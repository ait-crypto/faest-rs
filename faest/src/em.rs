
use std::iter::zip;

use cipher::Unsigned;
use generic_array::GenericArray;

use crate::{
    aes::convert_to_bit,
    fields::BigGaloisField,
    parameter::{PARAM, PARAMOWF},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, sub_bytes,
        sub_bytes_nots, State,
    },
    universal_hashing::zkhash,
    vole::chaldec
};

pub fn em_extendedwitness<P, O>(k: &GenericArray<u8, O::LAMBDABYTES>, pk: &GenericArray<u8, O::PK>) -> (GenericArray<u8, O::LBYTES>, bool)
where
    P: PARAM,
    O: PARAMOWF,
{
    let lambda = <P::LAMBDA as Unsigned>::to_usize() / 8;
    let nst = <O::NST as Unsigned>::to_usize();
    let r = <O::R as Unsigned>::to_usize();
    let kc = <O::NK as Unsigned>::to_u8();
    let mut res : GenericArray<u8, O::LBYTES> = GenericArray::default();
    let mut index = 0; 
    let x = rijndael_key_schedule(
        &pk[..lambda],
        nst as u8,
        kc,
        r as u8,
        (4 * (((r + 1) * nst) / kc as usize)) as u8,
    );
    for i in k.to_vec() {
        res[index] = i;
        index += 1;
    }
    let mut state = State::default();
    bitslice(
        &mut state,
        &k[..16],
        &[k[16..].to_vec(), vec![0u8; 32 - lambda]].concat(),
    );
    rijndael_add_round_key(&mut state, &x.0[..8]);
    for j in 1..r {
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);
        rijndael_shift_rows_1(&mut state, nst as u8);
        for i in convert_from_batchblocks(inv_bitslice(&state))[..kc as usize][..kc as usize]
        .to_vec()
        .iter()
        .flat_map(|x| x.to_le_bytes())
        .collect::<Vec<u8>>() {
            res[index] = i;
            index += 1;
        }
        mix_columns_0(&mut state);
        rijndael_add_round_key(&mut state, &x.0[8 * j..8 * (j + 1)]);
    }
    (res, x.1)
}

/* pub fn em_witness_has0<P, O>(k: &[u8], pk: &[u8]) -> Vec<u8>
where
    P: PARAM,
    O: PARAMOWF,
{
    let lambda = <P::LAMBDA as Unsigned>::to_usize()/ 8;
    let nst = <O::NST as Unsigned>::to_usize();
    let r = <O::R as Unsigned>::to_usize();
    let kc = <O::NK as Unsigned>::to_u8();
    let mut res: Vec<u8> = vec![];
    let x = rijndael_key_schedule_has0(
        &pk[..lambda],
        nst as u8,
        kc,
        r as u8,
        (4 * (((r + 1) * nst) / kc as usize)) as u8,
        &mut vec![0],
    );
    let mut state = State::default();
    bitslice(
        &mut state,
        &k[..16],
        &[k[16..].to_vec(), vec![0u8; 32 - lambda]].concat(),
    );
    rijndael_add_round_key(&mut state, &x[..8]);
    for j in 1..r + 1 {
        res.append(&mut inv_bitslice(&state)[0][..].to_vec());
        if nst == 6 {
            res.append(&mut inv_bitslice(&state)[1][..8].to_vec());
        } else if nst == 8 {
            res.append(&mut inv_bitslice(&state)[1][..].to_vec());
        }
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);
        rijndael_shift_rows_1(&mut state, nst as u8);
        mix_columns_0(&mut state);
        rijndael_add_round_key(&mut state, &x[8 * j..8 * (j + 1)]);
    }
    res
} */
///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///One of the first path to optimize the code could be to do the distinction
pub fn em_enc_fwd<T, O>(z: &GenericArray<T, O::L>, x: &GenericArray<T, O::LAMBDAR1>) -> GenericArray<T, O::SENC>
where
    T: BigGaloisField
        + std::default::Default
        + std::marker::Sized
        + std::fmt::Debug
        + std::ops::Add<T>,
    O: PARAMOWF, 

{
    let mut res : GenericArray<T, O::SENC> = GenericArray::default();
    let mut index = 0;
    let nst = <O::NST as Unsigned>::to_usize();
    //Step 2-3
    for j in 0..4 * nst {
        res[index] = T::byte_combine(z[8 * j..8 * (j + 1)].try_into().unwrap())
                + T::byte_combine(x[8 * j..8 * (j + 1)].try_into().unwrap());
        index += 1;
        }
    //Step 4
    for j in 1..<O::R as Unsigned>::to_usize() {
        for c in 0..nst {
            let i: usize = 32 * nst * j + 32 * c;
            let mut z_hat: [T; 4] = [T::default(); 4];
            let mut x_hat: [T; 4] = [T::default(); 4];
            for r in 0..4 {
                z_hat[r] = T::byte_combine(z[i + 8 * r..i + 8 * r + 8].try_into().unwrap());
                x_hat[r] = T::byte_combine(x[i + 8 * r..i + 8 * r + 8].try_into().unwrap());
            }
            let (a, b, c) = (
                T::ONE,
                T::byte_combine(&[
                    T::default(),
                    T::ONE,
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                ]),
                T::byte_combine(&[
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
            res[index] = z_hat[0] * b + z_hat[1] * c + z_hat[2] * a + z_hat[3] * a + x_hat[0];
            res[index + 1] = z_hat[0] * a + z_hat[1] * b + z_hat[2] * c + z_hat[3] * a + x_hat[1];
            res[index + 2] = z_hat[0] * a + z_hat[1] * a + z_hat[2] * b + z_hat[3] * c + x_hat[2];
            res[index + 3] = z_hat[0] * c + z_hat[1] * a + z_hat[2] * a + z_hat[3] * b + x_hat[3];
            index += 4;
        }
    }
    res
}

///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///One of the first path to optimize the code could be to do the distinction
#[allow(clippy::too_many_arguments)]
pub fn em_enc_bkwd<T, P, O>(
    x: &GenericArray<T, O::LAMBDAR1>,
    z: &GenericArray<T, O::L>,
    z_out: &GenericArray<T, O::LAMBDA>,
    mkey: bool,
    mtag: bool,
    delta: T,
) -> GenericArray<T, O::SENC>
where
    T: BigGaloisField
        + std::default::Default
        + std::marker::Sized
        + std::fmt::Debug
        + std::ops::Add<T>,
    P: PARAM,
    O: PARAMOWF, 
{
    let mut res :GenericArray<T, O::SENC> = GenericArray::default();
    let mut index = 0;
    let r = <O::R as Unsigned>::to_usize();
    let nst = <O::NST as Unsigned>::to_usize();
    let lambda = <P::LAMBDA as Unsigned>::to_usize();
    let immut = if !mtag {
        if mkey {
            delta
        } else {
            T::ONE
        }
    } else {
        T::default()
    };
    //Step 2
    for j in 0..r {
        for c in 0..nst {
            //Step 4
            for k in 0..4 {
                let mut icol = (c + nst - k) % nst;
                if nst == 8 && k >= 2 {
                    icol = (icol + nst - 1) % nst;
                }
                let ird = lambda + 32 * nst * j + 32 * icol + 8 * k;
                let z_t = if j < r - 1 {
                    z[ird..ird + 8].to_vec()
                } else {
                    let z_out_t = &z_out[ird - 32 * nst * (j + 1)..ird - 32 * nst * (j + 1) + 8];
                    zip(z_out_t, &x[ird..ird + 8])
                        .map(|(z, x)| *z + *x)
                        .collect::<Vec<T>>()
                };
                let mut y_t = [T::default(); 8];
                for i in 0..8 {
                    y_t[i] = z_t[(i + 7) % 8] + z_t[(i + 5) % 8] + z_t[(i + 2) % 8]
                }
                y_t[0] += immut;
                y_t[2] += immut;
                res[index] = T::byte_combine(&y_t);
                index += 1;
            }
        }
    }
    res
}

#[allow(clippy::too_many_arguments)]
pub fn em_enc_cstrnts<T, P, O>(
    output: &GenericArray<u8, O::LAMBDABYTES>,
    x: &GenericArray<u8, O::LAMBDAR1BYTE>,
    w: &GenericArray<u8, O::LBYTES>,
    v: &GenericArray<T, O::L>,
    q: &GenericArray<T, O::L>,
    mkey: bool,
    delta: T,
) -> (GenericArray<T, O::C>, GenericArray<T, O::C>)
where
    T: BigGaloisField
        + std::default::Default
        + std::marker::Sized
        + std::fmt::Debug
        + std::ops::Add<T>,
    P: PARAM,
    O: PARAMOWF, 

{
    let lambda = <P::LAMBDA as Unsigned>::to_usize();
    let senc = <O::SENC as Unsigned>::to_usize();
    let nst = <O::NST as Unsigned>::to_usize();
    let r = <O::R as Unsigned>::to_usize();
    if !mkey {
        let new_w = convert_to_bit::<T, O, O::L, O::LBYTES>(w);
        let new_x = convert_to_bit::<T, O, O::LAMBDAR1, O::LAMBDAR1BYTE>(GenericArray::from_slice(&x[..4 * nst * (r + 1)]));
        let mut w_out : GenericArray<T, O::LAMBDA> = GenericArray::default();
        let mut index = 0;
        for i in 0..lambda / 8 {
            for j in 0..8 {
                w_out[index] = T::ONE * ((output[i] >> j) & 1) + new_w[i * 8 + j];
                index += 1;
            }
        }
        let v_out = GenericArray::from_slice(&v[..lambda]);
        let s = em_enc_fwd::<T, O>(&new_w, &new_x);
        let vs = em_enc_fwd::<T, O>(v, &GenericArray::default());
        let s_b = em_enc_bkwd::<T, P, O>(&new_x, &new_w, &w_out, false, false, T::default());
        let v_s_b = em_enc_bkwd::<T, P, O>(
            &GenericArray::default(),
            v,
            v_out,
            false,
            true,
            T::default(),
        );
        let (mut a0, mut a1) : (GenericArray<T, O::C>, GenericArray<T, O::C>) = (GenericArray::default(), GenericArray::default());
        for j in 0..senc {
            a0[j] = v_s_b[j] * vs[j];
            a1[j] = ((s[j] + vs[j]) * (s_b[j] + v_s_b[j])) + T::ONE + a0[j];
        }
        (a0, a1)
    } else {
        let new_output = &convert_to_bit::<T, O, O::LAMBDA, O::LAMBDABYTES>(output);
        let mut new_x : GenericArray<T, O::LAMBDAR1> = GenericArray::default();
        let mut index = 0;
        for byte in x.iter().take(4 * nst * (r + 1)) {
            for j in 0..8 {
                new_x[index] = delta * ((byte >> j) & 1);
                index += 1;
            }
        }
        let mut q_out : GenericArray<T, O::LAMBDA> = GenericArray::default();
        for i in 0..lambda {
            q_out[i] = T::ONE * (&[new_output[i]])[0] * delta + q[i];
        }
        let qs = em_enc_fwd::<T, O>(q, &new_x);
        let qs_b = em_enc_bkwd::<T, P, O>(&new_x, q, &q_out, true, false, delta);
        let immut = delta * delta;
        let b = zip(qs, qs_b).map(|(q, qb)| (q * qb) + immut).collect();
        (b, GenericArray::default())
    }
}

///Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
pub fn em_prove<T, P, O>(
    w: &GenericArray<u8, O::L>,
    u: &GenericArray<u8, O::LAMBDALBYTES>,
    gv: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
    pk: &GenericArray<u8, O::PK>,
    chall: &GenericArray<u8, O::CHALL>,
) -> (GenericArray<u8, O::LAMBDABYTES>, GenericArray<u8, O::LAMBDABYTES>)
where
    T: BigGaloisField + std::default::Default + std::fmt::Debug,
    P: PARAM,
    O: PARAMOWF, 

{
    let nst = <O::NST as Unsigned>::to_u8();
    let nk = <O::NK as Unsigned>::to_u8();
    let r = <O::R as Unsigned>::to_u8( );
    let l = <O::L as Unsigned>::to_usize();
    let lambda = <P::LAMBDA as Unsigned>::to_usize();
    let new_w  = GenericArray::from_slice(&w[..l]);
    let mut temp_v : GenericArray<u8, O::LAMBDALBYTESLAMBDA> = GenericArray::default();
    for i in 0..(l + lambda) / 8 {
        for k in 0..8 {
            for j in 0..lambda / 8 {
                let mut temp = 0;
                for m in 0..8 {
                    temp += ((gv[(j * 8) + m][i] >> k) & 1) << m;
                }
                temp_v[j + k*lambda/8 + i * lambda] = temp;
            }
        }
    }
    let new_v : GenericArray<T, O::LAMBDAL> = (*GenericArray::from_slice(&T::to_field(&temp_v))).clone();
    let x = rijndael_key_schedule(
        &pk[..lambda / 8],
        nst,
        nk,
        r,
        4 * (((r + 1) * nst) / nk),
    );
    let (a0, a1) = em_enc_cstrnts::<T, P, O>(
        GenericArray::from_slice(&pk[lambda / 8..]),
        &x.0.chunks(8)
            .flat_map(|x| {
                convert_from_batchblocks(inv_bitslice(x))
                    .iter()
                    .flat_map(|x| u32::to_le_bytes(*x))
                    .take(lambda / 8)
                    .collect::<Vec<u8>>()
            })
            .collect::<GenericArray<u8,_>>(),
        new_w,
        GenericArray::from_slice(&new_v[..l]),
        &GenericArray::default(),
        false,
        T::default(),
    );
    let u_s: T = T::to_field(&u[l / 8..])[0];
    let mut v_s = new_v[l];
    let alpha = T::new(2, 0);
    let mut cur_alpha = alpha;
    for i in 1..lambda {
    v_s += new_v[l + i] * cur_alpha;
        cur_alpha *= alpha;
    }
    let a_t = zkhash::<T, O>(chall, &a1, u_s);
    let b_t = zkhash::<T, O>(chall, &a0, v_s);
    (a_t, b_t)
}

///Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
#[allow(clippy::too_many_arguments)]
pub fn em_verify<T, P, O>(
    d: &GenericArray<u8, O::LBYTES>,
    gq: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
    a_t: &GenericArray<u8, O::LAMBDABYTES>,
    chall2: &GenericArray<u8, O::CHALL>,
    chall3: &GenericArray<u8, P::LAMBDA>,
    pk: &GenericArray<u8, O::PK>,
) -> GenericArray<u8, O::LAMBDABYTES>
where
    T: BigGaloisField + std::default::Default + std::fmt::Debug,
    P: PARAM,
    O: PARAMOWF, 

{
    let lambda = <P::LAMBDA as Unsigned>::to_usize();
    let k0 = <P::K0 as Unsigned>::to_usize();
    let k1 = <P::K1 as Unsigned>::to_usize();
    let t0 = <P::TAU0 as Unsigned>::to_usize();
    let t1 = <P::TAU1 as Unsigned>::to_usize();
    let l = <O::L as Unsigned>::to_usize();
    let delta = T::to_field(chall3)[0];
    let nst = <O::NST as Unsigned>::to_u8();
    let nk = <O::NK as Unsigned>::to_u8();
    let r = <O::R as Unsigned>::to_u8();

    let mut new_gq : GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA> = gq.clone();
    for i in 0..t0 {
        let sdelta = chaldec::<P>(chall3, i as u16);
        for j in 0..k0 {
            if sdelta[j] != 0 {
                for (k, _) in d.iter().enumerate(){
                    new_gq[k0 * i + j][k] = gq[k0 * i + j][k] ^ d[k];
                }
            }
        }
    }
    for i in 0..t1 {
        let sdelta = chaldec::<P>(
            chall3,
            (t0 + i) as u16,
        );
        for j in 0..k1 {
            if sdelta[j] != 0 {
                for (k, _) in d.iter().enumerate().take(l / 8) {
                    new_gq[t0 * k0 + k1 * i + j][k] = gq[t0 * k0 + k1 * i + j][k] ^ d[k];
                }
            }
        }
    }
    let mut temp_q : GenericArray<u8, O::LAMBDALBYTESLAMBDA> = GenericArray::default();
    for i in 0..(l + lambda) / 8 {
        for k in 0..8 {
            for j in 0..lambda / 8 {
                let mut temp = 0;
                for l in 0..8_usize {
                    temp += ((new_gq[(j * 8) + l][i] >> k) & 1) << l;
                }
                temp_q[j + k*(lambda/8) + i*lambda] = temp;
            }
        }
    }
    let new_q = T::to_field(&temp_q);
    let x = rijndael_key_schedule(
        &pk[..lambda / 8],
        nst,
        nk,
        r,
        4 * (((r + 1) * nst) / nk),
    );
    let (b, _) = em_enc_cstrnts::<T, P, O>(
        GenericArray::from_slice(&pk[lambda / 8..]),
        &x.0.chunks(8)
            .flat_map(|x| {
                convert_from_batchblocks(inv_bitslice(x))
                    .iter()
                    .flat_map(|x| u32::to_le_bytes(*x))
                    .take(lambda / 8)
                    .collect::<Vec<u8>>()
            })
            .collect::<GenericArray<u8, _>>(),
        &GenericArray::default(),
        &GenericArray::default(),
        GenericArray::from_slice(&new_q),
        true,
        delta,
    );
    let mut q_s = new_q[l];
    let alpha = T::new(2, 0);
    let mut cur_alpha = alpha;
    for i in 1..lambda {
        q_s += new_q[l + i] * cur_alpha;
        cur_alpha *= alpha;
    }
    (*GenericArray::from_slice(&T::to_bytes(&(T::to_field(&zkhash::<T, O>(chall2, &b, q_s))[0] + T::to_field(a_t)[0] * delta)))).clone()
}
