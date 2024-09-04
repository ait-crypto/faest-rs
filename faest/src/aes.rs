
use std::{default, iter::zip};
use generic_array::{GenericArray};
use typenum::{Unsigned, U8};

use crate::{
    fields::{BigGaloisField, ByteCombine, Field, SumPoly},
    parameter::{self, PARAM, PARAMOWF},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, sub_bytes, sub_bytes_nots, State,
    },
    universal_hashing::{zkhash, ZKHasherInit, ZKHasherProcess},
    vole::chaldec,
};

pub fn convert_to_bit<O, S, I>(input: &GenericArray<u8, I>) -> Box<GenericArray<O::Field, S>>
where
    O: PARAMOWF,
    I: generic_array::ArrayLength,
    S: generic_array::ArrayLength,
{
    let mut res = GenericArray::default_boxed();
    for i in 0..res.len() / 8 {
        for j in 0..8 {
            res[i * 8 + j] = O::Field::new(((input[i] >> j) & 1) as u128, 0)
        }
    }
    res
}

//The first member of the tuples are the effectives witness while the second is the validity according Faest requiremenbt of the keypair at the origin of the operation
pub fn aes_extendedwitness<P, O>(
    key: &GenericArray<u8, O::LAMBDABYTES>,
    pk: &GenericArray<u8, O::PK>,
) -> (Box<GenericArray<u8, O::LBYTES>>, bool)
where
    P: PARAM,
    O: PARAMOWF,
    <O as parameter::PARAMOWF>::KBLENGTH: generic_array::ArrayLength,
{
    let mut valid = true;
    let beta = <P::BETA as Unsigned>::to_usize();
    let kblen = <O::KBLENGTH as Unsigned>::to_usize();
    let bc = 4;
    let r = <O::R as Unsigned>::to_u8();
    let nk = <O::NK as Unsigned>::to_usize();
    let mut input = [0u8; 32];
    //step 0
    input[..16 * beta].clone_from_slice(&pk[..16 * beta]);
    let mut w: Box<GenericArray<u8, O::LBYTES>> = GenericArray::default_boxed();
    let mut index = 0;
    //step 3
    let (temp_kb, temp_val) =
        rijndael_key_schedule(key, bc, nk as u8, r, <O::SKE as Unsigned>::to_u8()); //modify rijndael_key_schedule
    let (kb, _temp_val): (GenericArray<u32, O::KBLENGTH>, bool) = (
        (*GenericArray::from_slice(&temp_kb[..kblen])).clone(),
        temp_val & valid,
    );
    //step 4
    for i in convert_from_batchblocks(inv_bitslice(&kb[..8]))[..4]
        .to_vec()
        .iter()
        .flat_map(|x| x.to_le_bytes())
        .collect::<Vec<u8>>()
    {
        w[index] = i;
        index += 1;
    }
    for i in convert_from_batchblocks(inv_bitslice(&kb[8..16]))[..nk / 2 - (4 - (nk / 2))]
        .to_vec()
        .iter()
        .flat_map(|x| x.to_le_bytes())
        .collect::<Vec<u8>>()
    {
        w[index] = i;
        index += 1;
    }
    for j in 1 + (nk / 8)
        ..1 + (nk / 8)
            + ((<O::SKE as Unsigned>::to_usize()) * ((2 - (nk % 4)) * 2 + (nk % 4) * 3)) / 16
    {
        let key: GenericArray<u32, U8> = *GenericArray::from_slice(&convert_from_batchblocks(
            inv_bitslice(&kb[8 * j..8 * (j + 1)]),
        ));
        if nk == 6 {
            if j % 3 == 1 {
                for i in key[2].to_le_bytes().to_vec() {
                    w[index] = i;
                    index += 1;
                }
            } else if j % 3 == 0 {
                for i in key[0].to_le_bytes().to_vec() {
                    w[index] = i;
                    index += 1;
                }
            }
        } else {
            for i in key[0].to_le_bytes().to_vec() {
                w[index] = i;
                index += 1;
            }
        }
    }
    //step 5
    for b in 0..beta {
        round_with_save::<O>(
            input[16 * b..16 * (b + 1)].try_into().unwrap(),
            [0; 16],
            &kb,
            r,
            &mut w,
            &mut index,
            &mut valid,
        );
    }
    (w, valid)
}

///This function allow to get the directs antecedents of subbyte when calling extendwitness to check quicly if the key is valid or not
/*pub fn aes_witness_has0<P, O>(k: &[u8], pk: &[u8]) -> Vec<u8>
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
} */

#[allow(clippy::too_many_arguments)]
fn round_with_save<O>(
    input1: [u8; 16],
    input2: [u8; 16],
    kb: &[u32],
    r: u8,
    w: &mut GenericArray<u8, O::LBYTES>,
    index: &mut usize,
    valid: &mut bool,
) where
    O: PARAMOWF,
{
    let mut state = State::default();
    bitslice(&mut state, &input1, &input2);
    rijndael_add_round_key(&mut state, &kb[..8]);
    for j in 1..r as usize {
        for i in inv_bitslice(&state)[0][..].to_vec() {
            *valid &= i != 0
        }
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);
        rijndael_shift_rows_1(&mut state, 4);
        for i in convert_from_batchblocks(inv_bitslice(&state))[..4][..4]
            .to_vec()
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<u8>>()
        {
            w[*index] = i;
            *index += 1
        }
        mix_columns_0(&mut state);
        rijndael_add_round_key(&mut state, &kb[8 * j..8 * (j + 1)]);
    }
}

/* #[allow(clippy::too_many_arguments)]
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
 */

///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///One of the first path to optimize the code could be to do the distinction
#[allow(clippy::ptr_arg)]
pub fn aes_key_exp_fwd<O>(x: &GenericArray<O::Field, O::LKE>) -> Box<GenericArray<O::Field, O::PRODRUN128>>
where
    O: PARAMOWF,
{
    //Step 1 is ok by construction
    let r = <O::R as Unsigned>::to_usize();
    let nk = <O::NK as Unsigned>::to_usize();
    let mut out = GenericArray::default_boxed();
    let lambda = <O::LAMBDA as Unsigned>::to_usize();
    let mut index = 0;
    for i in x.iter().take(lambda).cloned() {
        out[index] = i;
        index += 1;
    }
    let mut indice = lambda;
    for j in nk as u16..(4 * (r + 1)) as u16 {
        if (j % (nk as u16) == 0) || ((nk > 6) && (j % (nk as u16) == 4)) {
            for i in x[indice..indice + 32].to_vec() {
                out[index] = i;
                index += 1;
            }
            indice += 32;
        } else {
            for i in 0..32 {
                out[index] =
                    out[((32 * (j - nk as u16)) + i) as usize] + out[((32 * (j - 1)) + i) as usize];
                index += 1;
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
pub fn aes_key_exp_bwd<O>(x: &GenericArray<O::Field, O::LKE>, xk: &GenericArray<O::Field, O::PRODRUN128>, mtag: bool, mkey: bool, delta: O::Field) -> Box<GenericArray<O::Field, O::PRODSKE8>>
where
    O: PARAMOWF,
{
    let rcon_table = [
        1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53,
        106, 212, 179, 125, 250, 239, 197, 145,
    ];
    let ske = <O::SKE as Unsigned>::to_usize();
    let mut out : Box<GenericArray<O::Field, O::PRODSKE8>> = GenericArray::default_boxed();
    let mut indice = 0u16;
    let mut index = 0u16;
    let mut c = 0u8;
    let mut rmvrcon = true;
    let mut ircon = 0;
    //Step 6
    for j in 0..ske {
        //Step 7
        let mut x_tilde: GenericArray<O::Field, U8> = *GenericArray::from_slice(
            &zip(
                x.iter().skip((8 * j).into()).take(8),
                xk.iter().skip((indice + (8 * (c as u16))).into()).take(8),
            )
            .map(|(x, xk)| *x + *xk)
            .collect::<GenericArray<O::Field, U8>>(),
        );
        //Step 8
        if !mtag && rmvrcon && (c == 0) {
            let rcon = rcon_table[ircon];
            ircon += 1;
            let mut r = [O::Field::default(); 8];
            //Step 11
            for i in 0..8 {
                r[i] = if mkey {
                    delta * ((rcon >> i) & 1)
                } else {
                    O::Field::ONE * ((rcon >> i) & 1)
                };
                x_tilde[i] += r[i];
            }
        }
        let mut y_tilde = [O::Field::default(); 8];
        //Step 15
        for i in 0..8 {
            y_tilde[i] = x_tilde[(i + 7) % 8] + x_tilde[(i + 5) % 8] + x_tilde[(i + 2) % 8];
        }
        y_tilde[0] += if mtag {
            O::Field::default()
        } else if mkey {
            delta
        } else {
            O::Field::ONE
        };
        y_tilde[2] += if mtag {
            O::Field::default()
        } else if mkey {
            delta
        } else {
            O::Field::ONE
        };
        for i in y_tilde.to_vec() {
            out[index as usize] = i;
            index += 1;
        }
        c += 1;
        //Step 21
        if c == 4 {
            c = 0;
            if O::Field::LENGTH == 192 {
                indice += 192;
            } else {
                indice += 128;
                if O::Field::LENGTH == 256 {
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
pub fn aes_key_exp_cstrnts<O>(
    w: &GenericArray<u8, O::LKE>,
    v: &GenericArray<O::Field, O::LKE>,
    mkey: bool,
    q: &GenericArray<O::Field, O::LKE>,
    delta: O::Field,
) -> (Box<GenericArray<O::Field, O::SKE>>, Box<GenericArray<O::Field, O::SKE>>, Box<GenericArray<O::Field, O::PRODRUN128>>, Box<GenericArray<O::Field, O::PRODRUN128>>)
where
    O: PARAMOWF,
{
    let lambda = O::Field::LENGTH as usize;
    let kc = <O::NK as Unsigned>::to_u8();
    let ske = <O::SKE as Unsigned>::to_u16();
    let lke = <O::LKE as Unsigned>::to_usize();
    let mut iwd: u16 = 32 * (kc - 1) as u16;
    let mut dorotword = true;
    if !mkey {
        let mut a : (Box<GenericArray<O::Field, O::SKE>>, Box<GenericArray<O::Field, O::SKE>>) = (
            GenericArray::default_boxed(),
            GenericArray::default_boxed(),
        );
        
        let bits_w = &convert_to_bit::<O, O::PRODRUN128, O::LKE>(w)[..lke];
        let k = aes_key_exp_fwd::<O>(GenericArray::from_slice(&w.iter().map(|x| match x { 0 => O::Field::default(), _ => O::Field::ONE }).collect::<Vec<O::Field>>()));
        let vk = aes_key_exp_fwd::<O>(&v);
        let w_b = aes_key_exp_bwd::<O>(GenericArray::from_slice(&[&w.iter().map(|x| match x { 0 => O::Field::default(), _ => O::Field::ONE }).collect::<Vec<O::Field>>()[lambda..], &vec![O::Field::default(); lambda]].concat()), GenericArray::from_slice(&k), false, false, delta);
        let v_w_b = aes_key_exp_bwd::<O>(GenericArray::from_slice(&[&v[lambda..], &vec![O::Field::default(); lambda]].concat()), GenericArray::from_slice(&vk), true, false, delta);
        for j in 0..ske / 4 {
            let mut k_hat = [O::Field::default(); 4];
            let mut v_k_hat = [O::Field::default(); 4];
            let mut w_hat = [O::Field::default(); 4];
            let mut v_w_hat = [O::Field::default(); 4];
            for r in 0..4 {
                let r_p = if dorotword { (r + 3) % 4 } else { r };
                k_hat[r_p] = O::Field::byte_combine(&into_array(
                    &k[(iwd as usize) + (8 * r)..(iwd as usize) + (8 * r) + 8],
                ));
                v_k_hat[r_p] = O::Field::byte_combine(&into_array(
                    &vk[(iwd as usize) + (8 * r)..(iwd as usize) + (8 * r) + 8],
                ));
                w_hat[r] = O::Field::byte_combine(&into_array(
                    &w_b[(32 * j as usize) + (8 * r)..(32 * j as usize) + (8 * r) + 8],
                ));
                v_w_hat[r] = O::Field::byte_combine(&into_array(
                    &v_w_b[(32 * j as usize) + (8 * r)..(32 * j as usize) + (8 * r) + 8],
                ));
            }
            for r in 0..4 {
                a.0[j as usize * 4 + r as usize] = v_k_hat[r] * v_w_hat[r];
                a.1[j as usize * 4 + r as usize] = ((k_hat[r] + v_k_hat[r])
                    * (w_hat[r] + v_w_hat[r]))
                    + O::Field::ONE
                    + a.0[(4 * j as usize) + r];
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
        let _kc = <O::SKE as Unsigned>::to_u8();
        let mut b : Box<GenericArray<O::Field , O::SKE>> = GenericArray::default_boxed();
        let q_k = aes_key_exp_fwd::<O>(q);
        let q_w_b = aes_key_exp_bwd::<O>(GenericArray::from_slice(&[&q[lambda..], &vec![O::Field::default(); lambda]].concat()), GenericArray::from_slice(&q_k), false, true, delta);
        for j in 0..ske / 4 {
            let mut q_h_k = [O::Field::default(); 4];
            let mut q_h_w_b = [O::Field::default(); 4];
            for r in 0..4 {
                let r_p = if dorotword { (r + 3) % 4 } else { r };
                q_h_k[r_p] = O::Field::byte_combine(&into_array(
                    &q_k[(iwd as usize) + (8 * r)..(iwd as usize) + (8 * r) + 8],
                ));
                q_h_w_b[r] = O::Field::byte_combine(&into_array(
                    &q_w_b[(32 * j as usize) + (8 * r)..(32 * j as usize) + (8 * r) + 8],
                ));
            }
            for r in 0..4 {
                b[j as usize * 4 + r as usize] = q_h_k[r] * q_h_w_b[r] + delta * delta;
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
        (
            b,
            GenericArray::default_boxed(),
            GenericArray::default_boxed(),
            q_k,
        )
    }
}

///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///One of the first path to optimize the code could be to do the distinction
pub fn aes_enc_fwd<O>(
    x: &GenericArray<O::Field, O::LENC>,
    xk: &GenericArray<O::Field, O::PRODRUN128>,
    mkey: bool,
    mtag: bool,
    input: [u8; 16],
    delta: O::Field,
) -> Box<GenericArray<O::Field, O::SENC>>
where
    O: PARAMOWF,
{
    let mut index = 0;
    let mut res = GenericArray::default_boxed();
    //Step 2-5
    for i in 0..16 {
        let mut xin = [O::Field::default(); 8];
        for (j, xin_item) in xin.iter_mut().enumerate() {
            let bit = (input[i] >> j) & 1;
            let temp_xin = if mtag {
                O::Field::default()
            } else if mkey {
                delta * bit
            } else {
                O::Field::ONE * bit
            };
            *xin_item = temp_xin;
        }
        res[index] = O::Field::byte_combine(xin[0..8].try_into().unwrap())
            + O::Field::byte_combine(xk[8 * i..(8 * i) + 8].try_into().unwrap());
        index += 1;
    }
    //Step 6
    for j in 1..<O::R as Unsigned>::to_usize() {
        for c in 0..4 {
            let ix: usize = 128 * (j - 1) + 32 * c;
            let ik: usize = 128 * j + 32 * c;
            let mut x_hat = [O::Field::default(); 4];
            let mut x_hat_k = [O::Field::default(); 4];
            for r in 0..4 {
                x_hat[r] =
                    O::Field::byte_combine(x[ix + 8 * r..ix + 8 * r + 8].try_into().unwrap());
                x_hat_k[r] =
                    O::Field::byte_combine(xk[ik + 8 * r..ik + 8 * r + 8].try_into().unwrap());
            }
            let (a, b, c) = (
                O::Field::ONE,
                O::Field::byte_combine(&[
                    O::Field::default(),
                    O::Field::ONE,
                    O::Field::default(),
                    O::Field::default(),
                    O::Field::default(),
                    O::Field::default(),
                    O::Field::default(),
                    O::Field::default(),
                ]),
                O::Field::byte_combine(&[
                    O::Field::ONE,
                    O::Field::ONE,
                    O::Field::default(),
                    O::Field::default(),
                    O::Field::default(),
                    O::Field::default(),
                    O::Field::default(),
                    O::Field::default(),
                ]),
            );
            //Step 16
            res[index] = x_hat[0] * b + x_hat[1] * c + x_hat[2] * a + x_hat[3] * a + x_hat_k[0];
            res[index + 1] = x_hat[0] * a + x_hat[1] * b + x_hat[2] * c + x_hat[3] * a + x_hat_k[1];
            res[index + 2] = x_hat[0] * a + x_hat[1] * a + x_hat[2] * b + x_hat[3] * c + x_hat_k[2];
            res[index + 3] = x_hat[0] * c + x_hat[1] * a + x_hat[2] * a + x_hat[3] * b + x_hat_k[3];
            index += 4;
        }
    }

    res
}

///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///One of the first path to optimize the code could be to do the distinction
pub fn aes_enc_bkwd<O>(
    x: &GenericArray<O::Field, O::LENC>,
    xk: &GenericArray<O::Field, O::PRODRUN128>,
    mkey: bool,
    mtag: bool,
    out: [u8; 16],
    delta: O::Field,
) -> Box<GenericArray<O::Field, O::SENC>>
where
    O: PARAMOWF,
{
    let mut res = GenericArray::default_boxed();
    let r = <O::R as Unsigned>::to_usize() as usize;
    let immut = if mtag {
        O::Field::default()
    } else if mkey {
        delta
    } else {
        O::Field::ONE
    };
    //Step 2
    for j in 0..r {
        for c in 0..4 {
            //Step 4
            for k in 0..4 {
                let ird = 128 * j + 32 * ((c + 4 - k) % 4) + 8 * k;
                let x_t: [O::Field; 8];
                if j < r - 1 {
                    x_t = x[ird..ird + 8].try_into().unwrap();
                } else {
                    let mut x_out = [O::Field::default(); 8];
                    for i in 0..8 {
                        x_out[i] = immut
                            * ((out[(ird - 128 * j + i) / 8] >> ((ird - 128 * j + i) % 8)) & 1);
                    }
                    x_t = zip(x_out, &xk[128 + ird..136 + ird])
                        .map(|(out, &k)| out + k)
                        .collect::<Vec<O::Field>>()
                        .try_into()
                        .unwrap();
                }
                let mut y_t = [O::Field::default(); 8];
                for i in 0..8 {
                    y_t[i] = x_t[(i + 7) % 8] + x_t[(i + 5) % 8] + x_t[(i + 2) % 8];
                }
                y_t[0] += immut;
                y_t[2] += immut;
                res[k + c * 4 + j * 16] = O::Field::byte_combine(&y_t);
            }
        }
    }
    res
}

#[allow(clippy::too_many_arguments)]
pub fn aes_enc_cstrnts<O>(
    input: [u8; 16],
    output: [u8; 16],
    w: &GenericArray<u8, O::QUOTLENC8>,
    v: &GenericArray<O::Field, O::LENC>,
    k: &GenericArray<O::Field, O::PRODRUN128>,
    vk: &GenericArray<O::Field, O::PRODRUN128>,
    mkey: bool,
    q: &GenericArray<O::Field, O::LENC>,
    qk: &GenericArray<O::Field, O::PRODRUN128>,
    delta: O::Field,
) -> Box<GenericArray<O::Field, O::SENC2>>
where
    O: PARAMOWF,
{
    let senc = <O::SENC as Unsigned>::to_usize();
    if !mkey {
        let mut field_w: Box<GenericArray<O::Field, O::LENC>> = GenericArray::default_boxed();
        for i in 0..w.len() {
            for j in 0..8 {
                field_w[i * 8 + j] = O::Field::new(((w[i] >> j) & 1) as u128, 0)
            }
        }
        let s = aes_enc_fwd::<O>(
            &field_w,
            k,
            false,
            false,
            input,
            O::Field::default(),
        );
        let vs = aes_enc_fwd::<O>(
            v,
            vk,
            false,
            true,
            input,
            O::Field::default(),
        );
        let s_b = aes_enc_bkwd::<O>(
            &field_w,
            k,
            false,
            false,
            output,
            O::Field::default(),
        );
        let v_s_b = aes_enc_bkwd::<O>(
            v,
            vk,
            false,
            true,
            output,
            O::Field::default(),
        );
        let mut a0 /* : GenericArray<O::Field, O::SENC2> */ = Box::< GenericArray<O::Field, O::SENC2>>::new(GenericArray::default());
        for j in 0..senc {
            a0[j] = vs[j] * v_s_b[j];
            a0[senc + j] = (s[j] + vs[j]) * (s_b[j] + v_s_b[j]) + O::Field::ONE + a0[j];
        }

        a0
    } else {
        let qs = aes_enc_fwd::<O>(
            q, qk, true, false, input, delta,
        );
        let q_s_b = aes_enc_bkwd::<O>(
            q, qk, true, false, output, delta,
        );
        let mut b: GenericArray<O::Field, O::SENC2> = GenericArray::default();
        let delta_square = delta * delta;
        for j in 0..senc {
            b[j] = (qs[j] * q_s_b[j]) + delta_square;
        }
        Box::new(b)
        
    }
}

fn bit_to_byte(input: &[u8]) -> u8 {
    let mut res = 0u8;
    for i in 0..8 {
        res += input[i] << i;
    }
    res
}

///Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
pub fn aes_prove<P, O>(
    w: &GenericArray<u8, O::L>,
    u: &GenericArray<u8, O::LAMBDALBYTES>,
    gv: Box<&GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>,
    pk: &GenericArray<u8, O::PK>,
    chall: &GenericArray<u8, O::CHALL>,
) -> (
    Box<GenericArray<u8, O::LAMBDABYTES>>,
    Box<GenericArray<u8, O::LAMBDABYTES>>,
)
where
    P: PARAM,
    O: PARAMOWF,
{
    let l = <O::L as Unsigned>::to_usize();
    let _c = <O::C as Unsigned>::to_usize();
    let lke = <O::LKE as Unsigned>::to_usize();
    let lenc = <O::LENC as Unsigned>::to_usize();
    let senc = <O::SENC as Unsigned>::to_usize();
    let lambda = <P::LAMBDA as Unsigned>::to_usize();
    let pk_val = <O::PK as Unsigned>::to_usize();
    let new_w: GenericArray<u8, O::LKE> = (*GenericArray::from_slice(&w[..lke])).clone();
    let mut temp_v: Box<GenericArray<u8, O::LAMBDALBYTESLAMBDA>> = GenericArray::default_boxed();
    for i in 0..(l + lambda) / 8 {
        for k in 0..8 {
            for j in 0..(lambda / 8) {
                let mut temp = 0;
                for l in 0..8 {
                    temp += ((gv[(j * 8) + l][i] >> k) & 1) << l;
                }
                temp_v[i * lambda + k * lambda / 8 + j] = temp;
            }
        }
    }
    let new_v: GenericArray<O::Field, O::LAMBDAL> =
        (*GenericArray::from_slice(&O::Field::to_field(&temp_v))).clone();

    let (input, output): (&GenericArray<u8, O::QUOTPK2>, &GenericArray<u8, O::QUOTPK2>) = (
        GenericArray::from_slice(&pk[..pk_val / 2]),
        GenericArray::from_slice(&pk[pk_val / 2..]),
    );

    let (a0, a1, k, vk) = aes_key_exp_cstrnts::<O>(
        GenericArray::from_slice(&new_w),
        GenericArray::from_slice(&new_v[..lke]),
        false,
        &GenericArray::default_boxed(),
        O::Field::default(),
    );
    
    let a_01 = aes_enc_cstrnts::<O>(
        input[..16].try_into().unwrap(),
        output[..16].try_into().unwrap(),
        //building a T out of w
        GenericArray::from_slice(
            &w[lke..(lke + lenc)]
                .chunks(8)
                .map(|x| bit_to_byte(x))
                .collect::<Vec<u8>>()[..],
        ),
        GenericArray::from_slice(&new_v[lke..lke + lenc]),
        GenericArray::from_slice(&k),
        GenericArray::from_slice(&vk),
        false,
        &GenericArray::default_boxed(),
        &GenericArray::default_boxed(),
        O::Field::default(),
    );
    
    
    let mut a_01_bis : Box<GenericArray<O::Field, O::SENC2>> = GenericArray::default_boxed();
    
    if lambda > 128 {
        a_01_bis = aes_enc_cstrnts::<O>(
            input[16..].try_into().unwrap(),
            output[16..].try_into().unwrap(),
            GenericArray::from_slice(
                &w[(lke + lenc)..l]
                    .chunks(8)
                    .map(|x| bit_to_byte(x))
                    .collect::<Vec<u8>>()[..],
            ),
            GenericArray::from_slice(&new_v[(lke + lenc)..l]),
            GenericArray::from_slice(&k),
            GenericArray::from_slice(&vk),
            false,
            &GenericArray::default_boxed(),
            &GenericArray::default_boxed(),
            O::Field::default(),
        );
    }
    let a0_array : GenericArray<O::Field, O::C> = if lambda == 128 {(GenericArray::from_slice(&[&a0[..], &a_01[..senc]].concat())).clone()} else {(GenericArray::from_slice(&[&a0[..], &a_01[..senc], &a_01_bis[..senc]].concat())).clone()};
    let a1_array: GenericArray<O::Field, O::C> = if lambda == 128 {(GenericArray::from_slice(&[&a1[..], &a_01[senc..]].concat())).clone()} else {(GenericArray::from_slice(&[&a1[..], &a_01[senc..], &a_01_bis[senc..]].concat())).clone()};
    let u_s = O::Field::to_field(&u[l / 8..])[0];
    

    let mut v_s = new_v[l];
    let alpha = O::Field::new(2, 0);
    let mut cur_alpha = alpha;
    for i in 1..lambda {
        v_s += new_v[l + i] * cur_alpha;
        cur_alpha *= alpha;
    }
    
    let mut a_t = O::ZKHasher::new_zk_hasher(chall);
    let mut b_t = O::ZKHasher::new_zk_hasher(chall);
    for i in 0..a1_array.len() {
        a_t.update(&a1_array[i]);
        b_t.update(&a0_array[i]);
    }
    (Box::new(GenericArray::from_slice(&(a_t.finalize(&u_s).to_bytes())[..]).clone()), Box::new(GenericArray::from_slice(&(b_t.finalize(&v_s).to_bytes())[..]).clone()))
}

///Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
#[allow(clippy::too_many_arguments)]
pub fn aes_verify<P, O>(
    d: &GenericArray<u8, O::LBYTES>,
    gq: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
    a_t: &GenericArray<u8, O::LAMBDABYTES>,
    chall2: &GenericArray<u8, O::CHALL>,
    chall3: &GenericArray<u8, P::LAMBDABYTES>,
    pk: &GenericArray<u8, O::PK>,
) -> GenericArray<u8, O::LAMBDABYTES>
where
    P: PARAM,
    O: PARAMOWF,
{
    let lambda = O::Field::LENGTH as usize;
    let k0 = <P::K0 as Unsigned>::to_usize();
    let k1 = <P::K1 as Unsigned>::to_usize();
    let t0 = <P::TAU0 as Unsigned>::to_usize();
    let t1 = <P::TAU1 as Unsigned>::to_usize();
    let l = <P::L as Unsigned>::to_usize();
    let _c = <O::C as Unsigned>::to_usize();
    let delta = O::Field::to_field(chall3)[0];
    let lke = <O::LKE as Unsigned>::to_usize();
    let lenc = <O::LENC as Unsigned>::to_usize();
    let senc = <O::SENC as Unsigned>::to_usize();
    let pk_len = <O::PK as Unsigned>::to_usize();
    let (input, output): (GenericArray<u8, O::QUOTPK2>, GenericArray<u8, O::QUOTPK2>) = (
        (*GenericArray::from_slice(&pk[..pk_len / 2])).clone(),
        (*GenericArray::from_slice(&pk[pk_len / 2..])).clone(),
    );
    let mut new_gq: GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA> = gq.clone();
    for i in 0..t0 {
        let sdelta = chaldec::<P>(GenericArray::from_slice(&chall3), i as u16);
        for j in 0..k0 {
            if sdelta[j] != 0 {
                for (k, _) in d.iter().enumerate().take(l / 8) {
                    new_gq[k0 * i + j][k] = gq[k0 * i + j][k] ^ d[k];
                }
            }
        }
    }
    for i in 0..t1 {
        let sdelta = chaldec::<P>(
            GenericArray::from_slice(&chall3),
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

    

    let mut temp_q : Box<GenericArray<u8, O::LAMBDALBYTESLAMBDA>> = GenericArray::default_boxed();
    for i in 0..(l + lambda) / 8 {
        for k in 0..8 {
            for j in 0..lambda / 8 {
                let mut temp = 0;
                for l in 0..8_usize {
                    temp += ((new_gq[(j * 8) + l][i] >> k) & 1) << l;
                }
                temp_q[i * lambda + k * lambda / 8 + j] = temp;
            }
        }
    }

    let mut zk_hasher = O::ZKHasher::new_zk_hasher(chall2);

    let new_q = O::Field::to_field(&temp_q);

    let (b1, _, _, qk) = aes_key_exp_cstrnts::<O>(
        &GenericArray::default_boxed(),
        &GenericArray::default_boxed(),
        true,
        GenericArray::from_slice(&new_q[0..lke]),
        delta,
    );
    b1.into_iter().for_each(|value| zk_hasher.update(&value));

    
    let b2 = aes_enc_cstrnts::<O>(
        input[..16].try_into().unwrap(),
        output[..16].try_into().unwrap(),
        &GenericArray::default_boxed(),
        &GenericArray::default_boxed(),
        &GenericArray::default_boxed(),
        &GenericArray::default_boxed(),
        true,
        GenericArray::from_slice(&new_q[lke..(lke + lenc)]),
        GenericArray::from_slice(&qk[..]),
        delta,
    );
    b2[..senc].into_iter().for_each(|value| zk_hasher.update(&value));
    if lambda > 128 {
        let b3 = aes_enc_cstrnts::<O>(
            input[16..].try_into().unwrap(),
            output[16..].try_into().unwrap(),
            &GenericArray::default_boxed(),
            &GenericArray::default_boxed(),
            &GenericArray::default_boxed(),
            &GenericArray::default_boxed(),
            true,
            GenericArray::from_slice(&new_q[lke + lenc..l]),
            GenericArray::from_slice(&qk[..]),
            delta,
        );
        b3.into_iter().for_each(|value| zk_hasher.update(&value));
    }

    let q_s = O::Field::sum_poly(&new_q[l..l + lambda]);

    
    (zk_hasher.finalize(&q_s) + O::Field::from(a_t) * delta).as_bytes()
}
