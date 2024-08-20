use std::{iter::zip, ops::Add};
use typenum::{Integer, Unsigned};

use crate::{
    fields::BigGaloisField,
    parameter::{self, PARAM, PARAMOWF},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_key_schedule_has0, rijndael_shift_rows_1, sub_bytes,
        sub_bytes_nots, State,
    },
    universal_hashing::zkhash,
    vole::chaldec,
};

pub fn convert_to_bit<T>(input: &[u8]) -> Vec<T>
where
    T: BigGaloisField,
{
    let mut res: Vec<T> = Vec::with_capacity(8 * input.len());
    for i in input {
        for j in 0..8 {
            res.push(T::new(((i >> j) & 1) as u128, 0))
        }
    }
    res
}

pub fn aes_extendedwitness<P, O>(key: &[u8], pk: &[u8]) -> Vec<u8>
where
    P: PARAM,
    O: PARAMOWF,
{
    let beta = <P::BETA as Unsigned>::to_usize();
    let bc = 4;
    let r = <O::R as Unsigned>::to_u8();
    let kc = <O::NK as Unsigned>::to_usize();
    let mut input = [0u8; 32];
    //step 0
    input[..16 * beta].clone_from_slice(&pk[..16 * beta]);
    let mut w = Vec::with_capacity((<P::L as Unsigned>::to_usize() / 8).into());
    //step 3
    let kb = rijndael_key_schedule(key, bc, kc as u8, r, <O::SKE as Unsigned>::to_u8());
    //step 4
    w.append(
        &mut convert_from_batchblocks(inv_bitslice(&kb[..8]))[..4]
            .to_vec()
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<u8>>(),
    );
    w.append(
        &mut convert_from_batchblocks(inv_bitslice(&kb[8..16]))[..kc / 2 - (4 - (kc / 2))]
            .to_vec()
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<u8>>(),
    );
    for j in
        1 + (kc / 8)..1 + (kc / 8) + ((<O::SKE as Unsigned>::to_usize()) * ((2 - (kc % 4)) * 2 + (kc % 4) * 3)) / 16
    {
        let key = convert_from_batchblocks(inv_bitslice(&kb[8 * j..8 * (j + 1)]));
        if kc == 6 {
            if j % 3 == 1 {
                w.append(&mut key[2].to_le_bytes().to_vec());
            } else if j % 3 == 0 {
                w.append(&mut key[0].to_le_bytes().to_vec());
            }
        } else {
            w.append(&mut key[0].to_le_bytes().to_vec());
        }
    }
    //step 5
    for b in 0..beta {
        round_with_save(
            input[16 * b..16 * (b + 1)].try_into().unwrap(),
            [0; 16],
            &kb,
            r,
            &mut w,
        );
    }
    w
}

///This function allow to get the directs antecedents of subbyte when calling extendwitness to check quicly if the key is valid or not
pub fn aes_witness_has0<P, O>(k: &[u8], pk: &[u8]) -> Vec<u8>
where
    P: PARAM,
    O: PARAMOWF,
{
    let beta = <P::BETA as Unsigned>::to_usize();
    let bc = 4;
    let r = <O::R as Unsigned>::to_u8();
    let kc = <O::NK as Unsigned>::to_usize();
    let mut input = [0u8; 32];
    //step 0
    input[..16 * beta].clone_from_slice(&pk[..16 * beta]);
    let mut w: Vec<u8> = vec![];
    //step 3
    let kb = rijndael_key_schedule_has0(k, bc, kc as u8, r, <O::SKE as Unsigned>::to_u8(), &mut w);
    //step 4

    //step 5
    for b in 0..beta {
        round_with_save_has0(
            input[16 * b..16 * (b + 1)].try_into().unwrap(),
            [0; 16],
            &kb,
            r + 1,
            &mut w,
        );
    }
    w
}

#[allow(clippy::too_many_arguments)]
fn round_with_save(input1: [u8; 16], input2: [u8; 16], kb: &[u32], r: u8, w: &mut Vec<u8>) {
    let mut state = State::default();
    bitslice(&mut state, &input1, &input2);
    rijndael_add_round_key(&mut state, &kb[..8]);
    for j in 1..r as usize {
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);
        rijndael_shift_rows_1(&mut state, 4);
        w.append(
            &mut convert_from_batchblocks(inv_bitslice(&state))[..4][..4]
                .to_vec()
                .iter()
                .flat_map(|x| x.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        mix_columns_0(&mut state);
        rijndael_add_round_key(&mut state, &kb[8 * j..8 * (j + 1)]);
    }
}

#[allow(clippy::too_many_arguments)]
fn round_with_save_has0(input1: [u8; 16], input2: [u8; 16], kb: &[u32], r: u8, w: &mut Vec<u8>) {
    let mut state = State::default();
    bitslice(&mut state, &input1, &input2);
    rijndael_add_round_key(&mut state, &kb[..8]);
    for j in 1..r as usize {
        w.append(&mut inv_bitslice(&state)[0][..].to_vec());
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);
        rijndael_shift_rows_1(&mut state, 4);

        mix_columns_0(&mut state);
        rijndael_add_round_key(&mut state, &kb[8 * j..8 * (j + 1)]);
    }
}

///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///One of the first path to optimize the code could be to do the distinction
#[allow(clippy::ptr_arg)]
pub fn aes_key_exp_fwd<T>(x: &Vec<T>, r: u8, lambda: usize, kc: u8) -> Vec<T>
where
    T: BigGaloisField + std::ops::Add<Output = T>,
{
    //Step 1 is ok by construction
    let mut out = Vec::with_capacity(((r + 1) as u16 * 128).into());
    for i in x.iter().take(lambda).cloned() {
        out.push(i);
    }
    let mut index = lambda;
    for j in kc as u16..(4 * (r + 1)) as u16 {
        if (j % (kc as u16) == 0) || ((kc > 6) && (j % (kc as u16) == 4)) {
            out.append(&mut x[index..index + 32].to_vec());
            index += 32;
        } else {
            for i in 0..32 {
                out.push(
                    out[((32 * (j - kc as u16)) + i) as usize] + out[((32 * (j - 1)) + i) as usize],
                );
            }
        }
    }
    out
}

///Choice is made to treat bits as element of GFlambda(that is, m=lambda anyway, while in the paper we can have m = 1),
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///One of the first path to optimize the code could be to do the distinction
///Beware when calling it : if Mtag = 1 ∧ Mkey = 1 or Mkey = 1 ∧ ∆ = ⊥ return ⊥
#[allow(clippy::ptr_arg)]
pub fn aes_key_exp_bwd<T>(x: &[T], xk: &[T], mtag: bool, mkey: bool, delta: T, ske: u16) -> Vec<T>
where
    T: BigGaloisField + std::default::Default + std::marker::Sized + std::fmt::Debug,
    T: std::ops::Add<T>,
{
    let rcon_table = [
        1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53,
        106, 212, 179, 125, 250, 239, 197, 145,
    ];
    let mut out = Vec::with_capacity((8 * ske).into());
    let mut index = 0u16;
    let mut c = 0u8;
    let mut rmvrcon = true;
    let mut ircon = 0;
    //Step 6
    for j in 0..ske {
        //Step 7
        let mut x_tilde: Vec<T> = zip(
            x.iter().skip((8 * j).into()).take(8),
            xk.iter().skip((index + 8 * (c as u16)).into()).take(8),
        )
        .map(|(x, xk)| *x + *xk)
        .collect();

        //Step 8
        if !mtag && rmvrcon && (c == 0) {
            let rcon = rcon_table[ircon];
            ircon += 1;
            let mut r = [T::default(); 8];
            //Step 11
            for i in 0..8 {
                r[i] = if mkey {
                    delta * ((rcon >> i) & 1)
                } else {
                    T::ONE * ((rcon >> i) & 1)
                };
                x_tilde[i] += r[i];
            }
        }
        let mut y_tilde = [T::default(); 8];
        //Step 15
        for i in 0..8 {
            y_tilde[i] = x_tilde[(i + 7) % 8] + x_tilde[(i + 5) % 8] + x_tilde[(i + 2) % 8];
        }
        y_tilde[0] += if mtag {
            T::default()
        } else if mkey {
            delta
        } else {
            T::ONE
        };
        y_tilde[2] += if mtag {
            T::default()
        } else if mkey {
            delta
        } else {
            T::ONE
        };
        out.append(&mut y_tilde.to_vec());
        c += 1;
        //Step 21
        if c == 4 {
            c = 0;
            if T::LENGTH == 192 {
                index += 192;
            } else {
                index += 128;
                if T::LENGTH == 256 {
                    rmvrcon = !rmvrcon;
                }
            }
        }
    }
    out
}

///Make sure you have 8 element into input before calling this function
fn into_array<T>(input: &[T]) -> [T; 8]
where
    T: std::default::Default + std::marker::Copy,
{
    let mut res = [T::default(); 8];
    res.copy_from_slice(&input[..8]);
    res
}

///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///One of the first path to optimize the code could be to do the distinction
pub fn aes_key_exp_cstrnts<T, O>(
    w: &[u8],
    v: &[T],
    mkey: bool,
    q: &[T],
    delta: T,
) -> (Vec<T>, Vec<T>, Vec<T>, Vec<T>)
where
    T: BigGaloisField
        + std::default::Default
        + std::marker::Sized
        + std::fmt::Debug
        + std::ops::Add<T>,
    O: PARAMOWF,
{
    let lambda = T::LENGTH as usize;
    let kc = <O::NK as Unsigned>::to_u8();
    let ske = <O::SKE as Unsigned>::to_u16();
    let mut iwd: u16 = 32 * (kc - 1) as u16;
    let mut dorotword = true;
    if !mkey {
        let mut a = (
            Vec::<T>::with_capacity(ske.into()),
            Vec::<T>::with_capacity(ske.into()),
        );
        let k = aes_key_exp_fwd(&convert_to_bit(w), <O::R as Unsigned>::to_u8(), lambda, kc);
        let vk = aes_key_exp_fwd(&v.to_vec(), <O::R as Unsigned>::to_u8(), lambda, kc);
        let w_b = aes_key_exp_bwd::<T>(&convert_to_bit(w)[lambda..], &k, false, false, delta, ske);
        let v_w_b = aes_key_exp_bwd::<T>(&v[lambda..], &vk, true, false, delta, ske);
        for j in 0..ske / 4 {
            let mut k_hat = [T::default(); 4];
            let mut v_k_hat = [T::default(); 4];
            let mut w_hat = [T::default(); 4];
            let mut v_w_hat = [T::default(); 4];
            for r in 0..4 {
                let r_p = if dorotword { (r + 3) % 4 } else { r };
                k_hat[r_p] = T::byte_combine(into_array::<T>(
                    &k[(iwd as usize) + (8 * r)..(iwd as usize) + (8 * r) + 8],
                ));
                v_k_hat[r_p] = T::byte_combine(into_array::<T>(
                    &vk[(iwd as usize) + (8 * r)..(iwd as usize) + (8 * r) + 8],
                ));
                w_hat[r] = T::byte_combine(into_array::<T>(
                    &w_b[(32 * j as usize) + (8 * r)..(32 * j as usize) + (8 * r) + 8],
                ));
                v_w_hat[r] = T::byte_combine(into_array::<T>(
                    &v_w_b[(32 * j as usize) + (8 * r)..(32 * j as usize) + (8 * r) + 8],
                ));
            }
            for r in 0..4 {
                a.0.push(v_k_hat[r] * v_w_hat[r]);
                a.1.push(
                    ((k_hat[r] + v_k_hat[r]) * (w_hat[r] + v_w_hat[r]))
                        + T::ONE
                        + a.0[(4 * j as usize) + r],
                );
            }
            if lambda == 256 {
                dorotword = !dorotword;
                iwd += 128;
            } else if lambda == 192 {
                iwd += 192;
            } else {
                iwd += 128;
            }
        }
        (a.0, a.1, k, vk)
    } else {
        let mut b = Vec::<T>::with_capacity(ske.into());
        let q_k = aes_key_exp_fwd(&q.to_vec(), <O::R as Unsigned>::to_u8(), lambda, kc);
        let q_w_b = aes_key_exp_bwd::<T>(&q[lambda..], &q_k, false, true, delta, ske);
        for j in 0..ske / 4 {
            let mut q_h_k = [T::default(); 4];
            let mut q_h_w_b = [T::default(); 4];
            for r in 0..4 {
                let r_p = if dorotword { (r + 3) % 4 } else { r };
                q_h_k[r_p] = T::byte_combine(into_array::<T>(
                    &q_k[(iwd as usize) + (8 * r)..(iwd as usize) + (8 * r) + 8],
                ));
                q_h_w_b[r] = T::byte_combine(into_array::<T>(
                    &q_w_b[(32 * j as usize) + (8 * r)..(32 * j as usize) + (8 * r) + 8],
                ));
            }
            for r in 0..4 {
                b.push(q_h_k[r] * q_h_w_b[r] + delta * delta);
            }
            if lambda == 128 {
                iwd += 128;
            } else if lambda == 192 {
                iwd += 192;
            } else {
                iwd += 128;
                dorotword = !dorotword;
            }
        }
        (b, vec![T::default()], vec![T::default()], q_k)
    }
}

///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///One of the first path to optimize the code could be to do the distinction
pub fn aes_enc_fwd<T, O>(
    x: &[T],
    xk: &[T],
    mkey: bool,
    mtag: bool,
    input: [u8; 16],
    delta: T,
) -> Vec<T>
where
    T: BigGaloisField
        + std::default::Default
        + std::marker::Sized
        + std::fmt::Debug
        + std::ops::Add<T>,
    O: PARAMOWF,
{
    let mut res = Vec::with_capacity(<O::SENC as Unsigned>::to_usize().into());
    //Step 2-5
    for i in 0..16 {
        let mut xin = [T::default(); 8];
        for (j, xin_item) in xin.iter_mut().enumerate() {
            let bit = (input[i] >> j) & 1;
            let temp_xin = if mtag {
                T::default()
            } else if mkey {
                delta * bit
            } else {
                T::ONE * bit
            };
            *xin_item = temp_xin;
        }
        res.push(
            T::byte_combine(xin[0..8].try_into().unwrap())
                + T::byte_combine(xk[8 * i..(8 * i) + 8].try_into().unwrap()),
        );
    }
    //Step 6
    for j in 1..<O::R as Unsigned>::to_usize() {
        for c in 0..4 {
            let ix: usize = 128 * (j - 1) + 32 * c;
            let ik: usize = 128 * j + 32 * c;
            let mut x_hat: [T; 4] = [T::default(); 4];
            let mut x_hat_k: [T; 4] = [T::default(); 4];
            for r in 0..4 {
                x_hat[r] = T::byte_combine(x[ix + 8 * r..ix + 8 * r + 8].try_into().unwrap());
                x_hat_k[r] = T::byte_combine(xk[ik + 8 * r..ik + 8 * r + 8].try_into().unwrap());
            }
            let (a, b, c) = (
                T::ONE,
                T::byte_combine([
                    T::default(),
                    T::ONE,
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                ]),
                T::byte_combine([
                    T::ONE,
                    T::ONE,
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                ]),
            );
            //Step 16
            res.push(x_hat[0] * b + x_hat[1] * c + x_hat[2] * a + x_hat[3] * a + x_hat_k[0]);
            res.push(x_hat[0] * a + x_hat[1] * b + x_hat[2] * c + x_hat[3] * a + x_hat_k[1]);
            res.push(x_hat[0] * a + x_hat[1] * a + x_hat[2] * b + x_hat[3] * c + x_hat_k[2]);
            res.push(x_hat[0] * c + x_hat[1] * a + x_hat[2] * a + x_hat[3] * b + x_hat_k[3]);
        }
    }
    res
}

///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///One of the first path to optimize the code could be to do the distinction
pub fn aes_enc_bkwd<T, O>(
    x: &[T],
    xk: &[T],
    mkey: bool,
    mtag: bool,
    out: [u8; 16],
    delta: T,
) -> Vec<T>
where
    T: BigGaloisField
        + std::default::Default
        + std::marker::Sized
        + std::fmt::Debug
        + std::ops::Add<T>,
    O: PARAMOWF,
{
    let mut res = Vec::with_capacity(<O::SENC as Unsigned>::to_usize().into());
    let r = <O::R as Unsigned>::to_usize() as usize;
    let immut = if mtag {
        T::default()
    } else if mkey {
        delta
    } else {
        T::ONE
    };
    //Step 2
    for j in 0..r {
        for c in 0..4 {
            //Step 4
            for k in 0..4 {
                let ird = 128 * j + 32 * ((c + 4 - k) % 4) + 8 * k;
                let x_t: [T; 8];
                if j < r - 1 {
                    x_t = x[ird..ird + 8].try_into().unwrap();
                } else {
                    let mut x_out = [T::default(); 8];
                    for i in 0..8 {
                        x_out[i] = immut
                            * ((out[(ird - 128 * j + i) / 8] >> ((ird - 128 * j + i) % 8)) & 1);
                    }
                    x_t = zip(x_out, &xk[128 + ird..136 + ird])
                        .map(|(out, &k)| out + k)
                        .collect::<Vec<T>>()
                        .try_into()
                        .unwrap();
                }
                let mut y_t = [T::default(); 8];
                for i in 0..8 {
                    y_t[i] = x_t[(i + 7) % 8] + x_t[(i + 5) % 8] + x_t[(i + 2) % 8];
                }
                y_t[0] += immut;
                y_t[2] += immut;
                res.push(T::byte_combine(y_t));
            }
        }
    }
    res
}

#[allow(clippy::too_many_arguments)]
pub fn aes_enc_cstrnts<T, O>(
    input: [u8; 16],
    output: [u8; 16],
    w: &[u8],
    v: &[T],
    k: &[T],
    vk: &[T],
    mkey: bool,
    q: &[T],
    qk: &[T],
    delta: T,
) -> Vec<T>
where
    T: BigGaloisField
        + std::default::Default
        + std::marker::Sized
        + std::fmt::Debug
        + std::ops::Add<T>,
    O: PARAMOWF,
{
    let senc = <O::SENC as Unsigned>::to_usize();
    if !mkey {
        let field_w = &(w
            .iter()
            .flat_map(|w| convert_to_bit(&[*w]))
            .collect::<Vec<T>>())[..];
        let s = aes_enc_fwd::<T, O>(field_w, k, false, false, input, T::default());
        let vs = aes_enc_fwd::<T, O>(v, vk, false, true, input, T::default());
        let s_b = aes_enc_bkwd::<T, O>(field_w, k, false, false, output, T::default());
        let v_s_b = aes_enc_bkwd::<T, O>(v, vk, false, true, output, T::default());
        let mut a0 = Vec::with_capacity(2 * senc);
        let mut a1 = Vec::with_capacity(senc);
        for j in 0..senc {
            a0.push(vs[j] * v_s_b[j]);
            a1.push((s[j] + vs[j]) * (s_b[j] + v_s_b[j]) + T::ONE + a0[j]);
        }
        a0.append(&mut a1);
        a0
    } else {
        let qs = aes_enc_fwd::<T, O>(q, qk, true, false, input, delta);
        let q_s_b = aes_enc_bkwd::<T, O>(q, qk, true, false, output, delta);
        let mut b = Vec::with_capacity(senc);
        let delta_square = delta * delta;
        for j in 0..senc {
            b.push((qs[j] * q_s_b[j]) + delta_square);
        }
        b
    }
}

///Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
pub fn aes_prove<T, P, O>(
    w: &[u8],
    u: &[u8],
    gv: &[Vec<u8>],
    pk: &[u8],
    chall: &[u8],
) -> (Vec<u8>, Vec<u8>)
where
    T: BigGaloisField + std::default::Default + std::fmt::Debug,
    P: PARAM,
    O: PARAMOWF,
{
    let l = <O::L as Unsigned>::to_usize();
    let c = <O::C as Unsigned>::to_usize();
    let lke = <O::LKE as Unsigned>::to_usize();
    let lenc = <O::LENC as Unsigned>::to_usize();
    let senc = <O::SENC as Unsigned>::to_usize();
    let lambda = <P::LAMBDA as Unsigned>::to_usize();
    let new_w = &w[..l / 8];
    let mut temp_v = Vec::with_capacity((l + lambda) * lambda / 8);
    for i in 0..(l + lambda) / 8 {
        for k in 0..8 {
            for j in 0..lambda / 8 {
                let mut temp = 0;
                for l in 0..8 {
                    temp += ((gv[(j * 8) + l][i] >> k) & 1) << l;
                }
                temp_v.push(temp);
            }
        }
    }
    let new_v = T::to_field(&temp_v);
    let (input, output) = if lambda == 192 {
        (&pk[..256 / 8], &pk[256 / 8..])
    } else {
        (&pk[..lambda / 8], &pk[lambda / 8..])
    };
    let (mut a0, mut a1, k, vk) =
        aes_key_exp_cstrnts::<T, O>(&new_w[..lke / 8], &new_v[..lke], false, &[], T::default());
    let a_01 = aes_enc_cstrnts::<T, O>(
        input[..16].try_into().unwrap(),
        output[..16].try_into().unwrap(),
        &new_w[lke / 8..(lke + lenc) / 8],
        &new_v[lke..lke + lenc],
        &k,
        &vk,
        false,
        &[],
        &[],
        T::default(),
    );
    a0.append(&mut a_01[..senc].to_vec());
    a1.append(&mut a_01[senc..].to_vec());
    if lambda > 128 {
        let a_01 = aes_enc_cstrnts::<T, O>(
            input[16..].try_into().unwrap(),
            output[16..].try_into().unwrap(),
            &new_w[(lke + lenc) / 8..l / 8],
            &new_v[(lke + lenc)..l],
            &k,
            &vk,
            false,
            &[],
            &[],
            T::default(),
        );
        a0.append(&mut a_01[..senc].to_vec());
        a1.append(&mut a_01[senc..].to_vec());
    }
    let u_s: T = T::to_field(&u[l / 8..])[0];

    let mut v_s = new_v[l];
    let alpha = T::new(2, 0);
    let mut cur_alpha = alpha;
    for i in 1..lambda {
        v_s += new_v[l + i] * cur_alpha;
        cur_alpha *= alpha;
    }
    let a_t = zkhash::<T>(chall, &a1, u_s, c);
    let b_t = zkhash::<T>(chall, &a0, v_s, c);
    (a_t, b_t)
}

///Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
#[allow(clippy::too_many_arguments)]
pub fn aes_verify<T, P, O>(
    d: &[u8],
    mut gq: Vec<Vec<u8>>,
    a_t: &[u8],
    chall2: &[u8],
    chall3: &[u8],
    pk: &[u8],
) -> Vec<u8>
where
    T: BigGaloisField + std::default::Default + std::fmt::Debug,
    P: PARAM,
    O: PARAMOWF,
{
    let lambda = T::LENGTH as usize;
    let k0 = <P::K0 as Unsigned>::to_usize();
    let k1 = <P::K1 as Unsigned>::to_usize();
    let t0 = <P::TAU0 as Unsigned>::to_usize();
    let t1 = <P::TAU1 as Unsigned>::to_usize();
    let l = <P::L as Unsigned>::to_usize();
    let c = <O::C as Unsigned>::to_usize();
    let delta = T::to_field(chall3)[0];
    let lke = <O::LKE as Unsigned>::to_usize();
    let lenc = <O::LENC as Unsigned>::to_usize();
    let (input, output) = if lambda == 128 {
        (&pk[..16], &pk[16..])
    } else {
        (&pk[..32], &pk[32..])
    };
    for i in 0..t0 {
        let sdelta = chaldec(chall3, k0 as u16, t0 as u16, k1 as u16, t1 as u16, i as u16);
        for j in 0..k0 {
            if sdelta[j] != 0 {
                for (k, _) in d.iter().enumerate().take(l / 8) {
                    gq[k0 * i + j][k] ^= d[k];
                }
            }
        }
    }
    for i in 0..t1 {
        let sdelta = chaldec(
            chall3,
            k0 as u16,
            t0 as u16,
            k1 as u16,
            t1 as u16,
            (t0 + i) as u16,
        );
        for j in 0..k1 {
            if sdelta[j] != 0 {
                for (k, _) in d.iter().enumerate().take(l / 8) {
                    gq[t0 * k0 + k1 * i + j][k] ^= d[k];
                }
            }
        }
    }
    let mut temp_q = Vec::with_capacity((l + lambda) * lambda / 8);
    for i in 0..(l + lambda) / 8 {
        for k in 0..8 {
            for j in 0..lambda / 8 {
                let mut temp = 0;
                for l in 0..8_usize {
                    temp += ((gq[(j * 8) + l][i] >> k) & 1) << l;
                }
                temp_q.push(temp);
            }
        }
    }
    let new_q = T::to_field(&temp_q);
    let mut b = Vec::with_capacity(c);
    let (mut b1, _, _, qk) = aes_key_exp_cstrnts::<T, O>(&[], &[], true, &new_q[0..lke], delta);
    let mut b2 = aes_enc_cstrnts::<T, O>(
        input[..16].try_into().unwrap(),
        output[..16].try_into().unwrap(),
        &[],
        &[],
        &[],
        &[],
        true,
        &new_q[lke..lke + lenc],
        &qk[..],
        delta,
    );
    b.append(&mut b1);
    b.append(&mut b2);
    if lambda > 128 {
        let mut b3 = aes_enc_cstrnts::<T, O>(
            input[16..].try_into().unwrap(),
            output[16..].try_into().unwrap(),
            &[],
            &[],
            &[],
            &[],
            true,
            &new_q[lke + lenc..l],
            &qk[..],
            delta,
        );
        b.append(&mut b3);
    }
    let mut q_s = new_q[l];
    let alpha = T::new(2, 0);
    let mut cur_alpha = alpha;
    for i in 1..lambda {
        q_s += new_q[l + i] * cur_alpha;
        cur_alpha *= alpha;
    }

    T::to_bytes(T::to_field(&zkhash::<T>(chall2, &b, q_s, c))[0] + T::to_field(a_t)[0] * delta)
}
