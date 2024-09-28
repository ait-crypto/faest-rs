use std::iter::zip;

use generic_array::{
    typenum::{Unsigned, U8},
    ArrayLength, GenericArray,
};

use crate::{
    fields::{BigGaloisField, ByteCombine, ByteCombineConstants, Field as _, SumPoly},
    parameter::{BaseParameters, OWFParameters},
    parameter::{QSProof, TauParameters},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, sub_bytes, sub_bytes_nots, State,
    },
    universal_hashing::{ZKHasherInit, ZKHasherProcess},
    utils::convert_gq,
};

type Field<O> = <<O as OWFParameters>::BaseParams as BaseParameters>::Field;

type KeyCstrnts<O> = (
    Box<GenericArray<Field<O>, <O as OWFParameters>::PRODRUN128>>,
    Box<GenericArray<Field<O>, <O as OWFParameters>::PRODRUN128>>,
);

type CstrntsVal<'a, O> = &'a GenericArray<
    GenericArray<u8, <O as OWFParameters>::LAMBDALBYTES>,
    <O as OWFParameters>::LAMBDA,
>;

pub(crate) fn byte_to_bit(input: u8) -> Vec<u8> {
    (0..8).map(|i| (input >> i) & 1).collect()
}

pub(crate) fn convert_to_bit<F, S>(input: &[u8]) -> Box<GenericArray<F, S>>
where
    F: BigGaloisField,
    S: ArrayLength,
{
    let mut res = GenericArray::default_boxed();
    for i in 0..res.len() / 8 {
        for j in 0..8 {
            // FIXME
            res[i * 8 + j] = F::ONE * ((input[i] >> j) & 1);
        }
    }
    res
}

//The first member of the tuples are the effectives witness while the second is the validity according Faest requiremenbt of the keypair at the origin of the operation
pub(crate) fn aes_extendedwitness<O>(
    owf_key: &GenericArray<u8, O::LAMBDABYTES>,
    owf_input: &GenericArray<u8, O::InputSize>,
) -> (Box<GenericArray<u8, O::LBYTES>>, bool)
where
    O: OWFParameters,
{
    let beta = <O::BETA as Unsigned>::to_usize();
    let kblen = <O::KBLENGTH as Unsigned>::to_usize();
    let bc = 4;
    let r = <O::R as Unsigned>::to_u8();
    let nk = <O::NK as Unsigned>::to_usize();
    let mut input = [0u8; 32];
    //step 0
    input[..16 * beta].clone_from_slice(&owf_input[..16 * beta]);
    let mut w: Box<GenericArray<u8, O::LBYTES>> = GenericArray::default_boxed();
    let mut index = 0;
    //step 3
    let (temp_kb, temp_val) =
        rijndael_key_schedule(owf_key, bc, nk as u8, r, <O::SKE as Unsigned>::to_u8());
    let (kb, mut valid): (&GenericArray<u32, O::KBLENGTH>, bool) =
        (GenericArray::from_slice(&temp_kb[..kblen]), temp_val);
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
        let inside = &convert_from_batchblocks(inv_bitslice(&kb[8 * j..8 * (j + 1)]));
        let key: &GenericArray<u32, U8> = GenericArray::from_slice(inside);
        if nk == 6 {
            if j % 3 == 1 {
                for i in key[2].to_le_bytes() {
                    w[index] = i;
                    index += 1;
                }
            } else if j % 3 == 0 {
                for i in key[0].to_le_bytes() {
                    w[index] = i;
                    index += 1;
                }
            }
        } else {
            for i in key[0].to_le_bytes() {
                w[index] = i;
                index += 1;
            }
        }
    }
    //step 5
    for b in 0..beta {
        round_with_save(
            input[16 * b..16 * (b + 1)].try_into().unwrap(),
            kb,
            r,
            &mut w,
            &mut index,
            &mut valid,
        );
    }
    (w, valid)
}

#[allow(clippy::too_many_arguments)]
fn round_with_save(
    input1: &[u8; 16],
    kb: &[u32],
    r: u8,
    w: &mut [u8],
    index: &mut usize,
    valid: &mut bool,
) {
    let mut state = State::default();
    bitslice(&mut state, input1, &[]);
    rijndael_add_round_key(&mut state, &kb[..8]);
    for j in 1..r as usize {
        for i in &inv_bitslice(&state)[0][..] {
            *valid &= *i != 0
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
    for i in &inv_bitslice(&state)[0][..] {
        *valid &= *i != 0
    }
}

///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///
///One of the first path to optimize the code could be to do the distinction
fn aes_key_exp_fwd<O>(
    x: &GenericArray<Field<O>, O::LKE>,
) -> Box<GenericArray<Field<O>, O::PRODRUN128>>
where
    O: OWFParameters,
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
            for i in &x[indice..indice + 32] {
                out[index] = *i;
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
///
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///
///One of the first path to optimize the code could be to do the distinction
///Beware when calling it : if Mtag = 1 ∧ Mkey = 1 or Mkey = 1 ∧ ∆ = ⊥ return ⊥
fn aes_key_exp_bwd_mtag0_mkey0<O>(
    x: &GenericArray<Field<O>, O::LKE>,
    xk: &GenericArray<Field<O>, O::PRODRUN128>,
) -> Box<GenericArray<Field<O>, O::PRODSKE8>>
where
    O: OWFParameters,
{
    let rcon_table = [
        1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53,
        106, 212, 179, 125, 250, 239, 197, 145,
    ];
    let ske = <O::SKE as Unsigned>::to_usize();
    let mut out: Box<GenericArray<Field<O>, O::PRODSKE8>> = GenericArray::default_boxed();
    let mut indice = 0u16;
    let mut index = 0u16;
    let mut c = 0u8;
    let mut rmvrcon = true;
    let mut ircon = 0;
    //Step 6
    for j in 0..ske {
        //Step 7
        let mut x_tilde: GenericArray<Field<O>, U8> = *GenericArray::from_slice(
            &zip(
                x.iter().skip(8 * j).take(8),
                xk.iter().skip((indice + (8 * (c as u16))).into()).take(8),
            )
            .map(|(x, xk)| *x + *xk)
            .collect::<GenericArray<Field<O>, U8>>(),
        );
        //Step 8
        if rmvrcon && (c == 0) {
            let rcon = rcon_table[ircon];
            ircon += 1;
            let mut r = [Field::<O>::default(); 8];
            //Step 11
            for i in 0..8 {
                r[i] = Field::<O>::ONE * ((rcon >> i) & 1);
                x_tilde[i] += r[i];
            }
        }
        let mut y_tilde = [Field::<O>::default(); 8];
        //Step 15
        for i in 0..8 {
            y_tilde[i] = x_tilde[(i + 7) % 8] + x_tilde[(i + 5) % 8] + x_tilde[(i + 2) % 8];
        }
        y_tilde[0] += Field::<O>::ONE;
        y_tilde[2] += Field::<O>::ONE;
        for i in &y_tilde {
            out[index as usize] = *i;
            index += 1;
        }
        c += 1;
        //Step 21
        if c == 4 {
            c = 0;
            if Field::<O>::LENGTH == 192 {
                indice += 192;
            } else {
                indice += 128;
                if Field::<O>::LENGTH == 256 {
                    rmvrcon = !rmvrcon;
                }
            }
        }
    }
    out
}

fn aes_key_exp_bwd_mtag1_mkey0<O>(
    x: &GenericArray<Field<O>, O::LKE>,
    xk: &GenericArray<Field<O>, O::PRODRUN128>,
) -> Box<GenericArray<Field<O>, O::PRODSKE8>>
where
    O: OWFParameters,
{
    let ske = <O::SKE as Unsigned>::to_usize();
    let mut out: Box<GenericArray<Field<O>, O::PRODSKE8>> = GenericArray::default_boxed();
    let mut indice = 0u16;
    let mut index = 0u16;
    let mut c = 0u8;
    let mut rmvrcon = true;
    //Step 6
    for j in 0..ske {
        //Step 7
        let x_tilde: GenericArray<Field<O>, U8> = *GenericArray::from_slice(
            &zip(
                x.iter().skip(8 * j).take(8),
                xk.iter().skip((indice + (8 * (c as u16))).into()).take(8),
            )
            .map(|(x, xk)| *x + *xk)
            .collect::<GenericArray<Field<O>, U8>>(),
        );
        //Step 8
        let mut y_tilde = [Field::<O>::default(); 8];
        //Step 15
        for i in 0..8 {
            y_tilde[i] = x_tilde[(i + 7) % 8] + x_tilde[(i + 5) % 8] + x_tilde[(i + 2) % 8];
        }
        for i in &y_tilde {
            out[index as usize] = *i;
            index += 1;
        }
        c += 1;
        //Step 21
        if c == 4 {
            c = 0;
            if Field::<O>::LENGTH == 192 {
                indice += 192;
            } else {
                indice += 128;
                if Field::<O>::LENGTH == 256 {
                    rmvrcon = !rmvrcon;
                }
            }
        }
    }
    out
}

fn aes_key_exp_bwd_mtag0_mkey1<O>(
    x: &GenericArray<Field<O>, O::LKE>,
    xk: &GenericArray<Field<O>, O::PRODRUN128>,
    delta: Field<O>,
) -> Box<GenericArray<Field<O>, O::PRODSKE8>>
where
    O: OWFParameters,
{
    let rcon_table = [
        1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53,
        106, 212, 179, 125, 250, 239, 197, 145,
    ];
    let ske = <O::SKE as Unsigned>::to_usize();
    let mut out: Box<GenericArray<Field<O>, O::PRODSKE8>> = GenericArray::default_boxed();
    let mut indice = 0u16;
    let mut index = 0u16;
    let mut c = 0u8;
    let mut rmvrcon = true;
    let mut ircon = 0;
    //Step 6
    for j in 0..ske {
        //Step 7
        let mut x_tilde: GenericArray<Field<O>, U8> = *GenericArray::from_slice(
            &zip(
                x.iter().skip(8 * j).take(8),
                xk.iter().skip((indice + (8 * (c as u16))).into()).take(8),
            )
            .map(|(x, xk)| *x + *xk)
            .collect::<GenericArray<Field<O>, U8>>(),
        );
        //Step 8
        if rmvrcon && (c == 0) {
            let rcon = rcon_table[ircon];
            ircon += 1;
            let mut r = [Field::<O>::default(); 8];
            //Step 11
            for i in 0..8 {
                r[i] = delta * ((rcon >> i) & 1);
                x_tilde[i] += r[i];
            }
        }
        let mut y_tilde = [Field::<O>::default(); 8];
        //Step 15
        for i in 0..8 {
            y_tilde[i] = x_tilde[(i + 7) % 8] + x_tilde[(i + 5) % 8] + x_tilde[(i + 2) % 8];
        }
        y_tilde[0] += delta;
        y_tilde[2] += delta;
        for i in &y_tilde {
            out[index as usize] = *i;
            index += 1;
        }
        c += 1;
        //Step 21
        if c == 4 {
            c = 0;
            if Field::<O>::LENGTH == 192 {
                indice += 192;
            } else {
                indice += 128;
                if Field::<O>::LENGTH == 256 {
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
///
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///
///One of the first path to optimize the code could be to do the distinction
fn aes_key_exp_cstrnts_mkey0<O>(
    a_t_hasher: &mut impl ZKHasherProcess<Field<O>>,
    b_t_hasher: &mut impl ZKHasherProcess<Field<O>>,
    w: &GenericArray<u8, O::LKE>,
    v: &GenericArray<Field<O>, O::LKE>,
) -> KeyCstrnts<O>
where
    O: OWFParameters,
{
    let lambda = Field::<O>::LENGTH;
    let kc = <O::NK as Unsigned>::to_u8();
    let ske = <O::SKE as Unsigned>::to_u16();
    let mut iwd: u16 = 32 * (kc - 1) as u16;
    let mut dorotword = true;
    let k = aes_key_exp_fwd::<O>(GenericArray::from_slice(
        &w.iter()
            .map(|x| match x {
                0 => Field::<O>::default(),
                _ => Field::<O>::ONE,
            })
            .collect::<Vec<Field<O>>>(),
    ));
    let vk = aes_key_exp_fwd::<O>(v);
    let w_b = aes_key_exp_bwd_mtag0_mkey0::<O>(
        GenericArray::from_slice(
            &[
                &w.iter()
                    .map(|x| match x {
                        0 => Field::<O>::default(),
                        _ => Field::<O>::ONE,
                    })
                    .collect::<Vec<Field<O>>>()[lambda..],
                &vec![Field::<O>::default(); lambda],
            ]
            .concat(),
        ),
        GenericArray::from_slice(&k),
    );
    let v_w_b = aes_key_exp_bwd_mtag1_mkey0::<O>(
        GenericArray::from_slice(&[&v[lambda..], &vec![Field::<O>::default(); lambda]].concat()),
        GenericArray::from_slice(&vk),
    );
    for j in 0..ske / 4 {
        let mut k_hat = [Field::<O>::default(); 4];
        let mut v_k_hat = [Field::<O>::default(); 4];
        let mut w_hat = [Field::<O>::default(); 4];
        let mut v_w_hat = [Field::<O>::default(); 4];
        for r in 0..4 {
            let r_p = if dorotword { (r + 3) % 4 } else { r };
            k_hat[r_p] = Field::<O>::byte_combine(&into_array(
                &k[(iwd as usize) + (8 * r)..(iwd as usize) + (8 * r) + 8],
            ));
            v_k_hat[r_p] = Field::<O>::byte_combine(&into_array(
                &vk[(iwd as usize) + (8 * r)..(iwd as usize) + (8 * r) + 8],
            ));
            w_hat[r] = Field::<O>::byte_combine(&into_array(
                &w_b[(32 * j as usize) + (8 * r)..(32 * j as usize) + (8 * r) + 8],
            ));
            v_w_hat[r] = Field::<O>::byte_combine(&into_array(
                &v_w_b[(32 * j as usize) + (8 * r)..(32 * j as usize) + (8 * r) + 8],
            ));
        }
        for r in 0..4 {
            let a0 = v_k_hat[r] * v_w_hat[r];
            let a1 = ((k_hat[r] + v_k_hat[r]) * (w_hat[r] + v_w_hat[r])) + Field::<O>::ONE + a0;
            a_t_hasher.update(&a1);
            b_t_hasher.update(&a0);
        }
        if O::LAMBDA::USIZE == 256 {
            dorotword = !dorotword;
            iwd += 128;
        } else if O::LAMBDA::USIZE == 192 {
            iwd += 192;
        } else {
            iwd += 128;
        }
    }
    (k, vk)
}

fn aes_key_exp_cstrnts_mkey1<O>(
    b_t_hasher: &mut impl ZKHasherProcess<Field<O>>,
    q: &GenericArray<Field<O>, O::LKE>,
    delta: Field<O>,
) -> Box<GenericArray<Field<O>, <O as OWFParameters>::PRODRUN128>>
where
    O: OWFParameters,
{
    let lambda = Field::<O>::LENGTH;
    let kc = <O::NK as Unsigned>::to_u8();
    let ske = <O::SKE as Unsigned>::to_u16();
    let mut iwd: u16 = 32 * (kc - 1) as u16;
    let mut dorotword = true;
    let q_k = aes_key_exp_fwd::<O>(q);
    let q_w_b = aes_key_exp_bwd_mtag0_mkey1::<O>(
        GenericArray::from_slice(&[&q[lambda..], &vec![Field::<O>::default(); lambda]].concat()),
        GenericArray::from_slice(&q_k),
        delta,
    );
    for j in 0..ske / 4 {
        let mut q_h_k = [Field::<O>::default(); 4];
        let mut q_h_w_b = [Field::<O>::default(); 4];
        for r in 0..4 {
            let r_p = if dorotword { (r + 3) % 4 } else { r };
            q_h_k[r_p] = Field::<O>::byte_combine(&into_array(
                &q_k[(iwd as usize) + (8 * r)..(iwd as usize) + (8 * r) + 8],
            ));
            q_h_w_b[r] = Field::<O>::byte_combine(&into_array(
                &q_w_b[(32 * j as usize) + (8 * r)..(32 * j as usize) + (8 * r) + 8],
            ));
        }
        for r in 0..4 {
            let b = q_h_k[r] * q_h_w_b[r] + delta * delta;
            b_t_hasher.update(&b);
        }
        if O::LAMBDA::USIZE == 128 {
            iwd += 128;
        } else if O::LAMBDA::USIZE == 192 {
            iwd += 192;
        } else {
            iwd += 128;
            dorotword = !dorotword;
        }
    }
    q_k
}

///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///
///One of the first path to optimize the code could be to do the distinction
fn aes_enc_fwd_mkey0_mtag0<O>(
    x: &GenericArray<Field<O>, O::LENC>,
    xk: &GenericArray<Field<O>, O::PRODRUN128>,
    input: &[u8; 16],
) -> Box<GenericArray<Field<O>, O::SENC>>
where
    O: OWFParameters,
{
    let mut index = 0;
    let mut res = GenericArray::default_boxed();
    //Step 2-5
    for i in 0..16 {
        res[index] = Field::<O>::byte_combine_bits(input[i])
            + Field::<O>::byte_combine(xk[8 * i..(8 * i) + 8].try_into().unwrap());
        index += 1;
    }
    //Step 6
    for j in 1..<O::R as Unsigned>::to_usize() {
        for c in 0..4 {
            let ix: usize = 128 * (j - 1) + 32 * c;
            let ik: usize = 128 * j + 32 * c;
            let mut x_hat = [Field::<O>::default(); 4];
            let mut x_hat_k = [Field::<O>::default(); 4];
            for r in 0..4 {
                x_hat[r] =
                    Field::<O>::byte_combine(x[ix + 8 * r..ix + 8 * r + 8].try_into().unwrap());
                x_hat_k[r] =
                    Field::<O>::byte_combine(xk[ik + 8 * r..ik + 8 * r + 8].try_into().unwrap());
            }

            //Step 16
            res[index] = x_hat[0] * Field::<O>::BYTE_COMBINE_2  + x_hat[1] * Field::<O>::BYTE_COMBINE_3  + x_hat[2] /* * a */  + x_hat[3] /* * a */ + x_hat_k[0];
            res[index + 1] = x_hat[0] /* * a */ + x_hat[1] * Field::<O>::BYTE_COMBINE_2  + x_hat[2] * Field::<O>::BYTE_COMBINE_3  + x_hat[3] /* * a */ + x_hat_k[1];
            res[index + 2] = x_hat[0] /* * a */ + x_hat[1] /* * a */ + x_hat[2] * Field::<O>::BYTE_COMBINE_2  + x_hat[3] * Field::<O>::BYTE_COMBINE_3  + x_hat_k[2];
            res[index + 3] = x_hat[0] * Field::<O>::BYTE_COMBINE_3  + x_hat[1] /* * a */ + x_hat[2] /* * a */ + x_hat[3] * Field::<O>::BYTE_COMBINE_2  + x_hat_k[3];
            index += 4;
        }
    }

    res
}

fn aes_enc_fwd_mkey1_mtag0<O>(
    x: &GenericArray<Field<O>, O::LENC>,
    xk: &GenericArray<Field<O>, O::PRODRUN128>,
    input: &[u8; 16],
    delta: Field<O>,
) -> Box<GenericArray<Field<O>, O::SENC>>
where
    O: OWFParameters,
{
    let mut index = 0;
    let mut res = GenericArray::default_boxed();
    //Step 2-5
    for i in 0..16 {
        let mut xin = [Field::<O>::default(); 8];
        for (j, xin_item) in xin.iter_mut().enumerate() {
            let bit = (input[i] >> j) & 1;
            *xin_item = delta * bit;
        }
        res[index] = Field::<O>::byte_combine(&xin)
            + Field::<O>::byte_combine(xk[8 * i..(8 * i) + 8].try_into().unwrap());
        index += 1;
    }
    //Step 6
    for j in 1..<O::R as Unsigned>::to_usize() {
        for c in 0..4 {
            let ix: usize = 128 * (j - 1) + 32 * c;
            let ik: usize = 128 * j + 32 * c;
            let mut x_hat = [Field::<O>::default(); 4];
            let mut x_hat_k = [Field::<O>::default(); 4];
            for r in 0..4 {
                x_hat[r] =
                    Field::<O>::byte_combine(x[ix + 8 * r..ix + 8 * r + 8].try_into().unwrap());
                x_hat_k[r] =
                    Field::<O>::byte_combine(xk[ik + 8 * r..ik + 8 * r + 8].try_into().unwrap());
            }

            //Step 16
            res[index] = x_hat[0] * Field::<O>::BYTE_COMBINE_2  + x_hat[1] * Field::<O>::BYTE_COMBINE_3  + x_hat[2] /* * a */  + x_hat[3] /* * a */ + x_hat_k[0];
            res[index + 1] = x_hat[0] /* * a */ + x_hat[1] * Field::<O>::BYTE_COMBINE_2  + x_hat[2] * Field::<O>::BYTE_COMBINE_3  + x_hat[3] /* * a */ + x_hat_k[1];
            res[index + 2] = x_hat[0] /* * a */ + x_hat[1] /* * a */ + x_hat[2] * Field::<O>::BYTE_COMBINE_2  + x_hat[3] * Field::<O>::BYTE_COMBINE_3  + x_hat_k[2];
            res[index + 3] = x_hat[0] * Field::<O>::BYTE_COMBINE_3  + x_hat[1] /* * a */ + x_hat[2] /* * a */ + x_hat[3] * Field::<O>::BYTE_COMBINE_2  + x_hat_k[3];
            index += 4;
        }
    }

    res
}

fn aes_enc_fwd_mkey0_mtag1<O>(
    x: &GenericArray<Field<O>, O::LENC>,
    xk: &GenericArray<Field<O>, O::PRODRUN128>,
) -> Box<GenericArray<Field<O>, O::SENC>>
where
    O: OWFParameters,
{
    let mut index = 0;
    let mut res = GenericArray::default_boxed();
    //Step 2-5
    for i in 0..16 {
        res[index] = Field::<O>::byte_combine(xk[8 * i..(8 * i) + 8].try_into().unwrap());
        index += 1;
    }
    //Step 6
    for j in 1..<O::R as Unsigned>::to_usize() {
        for c in 0..4 {
            let ix: usize = 128 * (j - 1) + 32 * c;
            let ik: usize = 128 * j + 32 * c;
            let mut x_hat = [Field::<O>::default(); 4];
            let mut x_hat_k = [Field::<O>::default(); 4];
            for r in 0..4 {
                x_hat[r] =
                    Field::<O>::byte_combine(x[ix + 8 * r..ix + 8 * r + 8].try_into().unwrap());
                x_hat_k[r] =
                    Field::<O>::byte_combine(xk[ik + 8 * r..ik + 8 * r + 8].try_into().unwrap());
            }

            //Step 16
            res[index] = x_hat[0] * Field::<O>::BYTE_COMBINE_2  + x_hat[1] * Field::<O>::BYTE_COMBINE_3  + x_hat[2] /* * a */  + x_hat[3] /* * a */ + x_hat_k[0];
            res[index + 1] = x_hat[0] /* * a */ + x_hat[1] * Field::<O>::BYTE_COMBINE_2  + x_hat[2] * Field::<O>::BYTE_COMBINE_3  + x_hat[3] /* * a */ + x_hat_k[1];
            res[index + 2] = x_hat[0] /* * a */ + x_hat[1] /* * a */ + x_hat[2] * Field::<O>::BYTE_COMBINE_2  + x_hat[3] * Field::<O>::BYTE_COMBINE_3  + x_hat_k[2];
            res[index + 3] = x_hat[0] * Field::<O>::BYTE_COMBINE_3  + x_hat[1] /* * a */ + x_hat[2] /* * a */ + x_hat[3] * Field::<O>::BYTE_COMBINE_2  + x_hat_k[3];
            index += 4;
        }
    }

    res
}

///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///
///One of the first path to optimize the code could be to do the distinction
fn aes_enc_bkwd_mkey0_mtag0<O>(
    x: &GenericArray<Field<O>, O::LENC>,
    xk: &GenericArray<Field<O>, O::PRODRUN128>,
    out: &[u8; 16],
) -> Box<GenericArray<Field<O>, O::SENC>>
where
    O: OWFParameters,
{
    let mut res = GenericArray::default_boxed();
    let r = <O::R as Unsigned>::to_usize();
    //Step 2
    for j in 0..r {
        for c in 0..4 {
            //Step 4
            for k in 0..4 {
                let ird = 128 * j + 32 * ((c + 4 - k) % 4) + 8 * k;
                let x_t: [Field<O>; 8];
                if j < r - 1 {
                    x_t = x[ird..ird + 8].try_into().unwrap();
                } else {
                    let mut x_out = [Field::<O>::default(); 8];
                    for i in 0..8 {
                        // FIXME
                        x_out[i] = Field::<O>::ONE
                            * ((out[(ird - 128 * j + i) / 8] >> ((ird - 128 * j + i) % 8)) & 1);
                    }
                    x_t = zip(x_out, &xk[128 + ird..136 + ird])
                        .map(|(out, &k)| out + k)
                        .collect::<Vec<Field<O>>>()
                        .try_into()
                        .unwrap();
                }
                let mut y_t = [Field::<O>::default(); 8];
                for i in 0..8 {
                    y_t[i] = x_t[(i + 7) % 8] + x_t[(i + 5) % 8] + x_t[(i + 2) % 8];
                }
                y_t[0] += Field::<O>::ONE;
                y_t[2] += Field::<O>::ONE;
                res[k + c * 4 + j * 16] = Field::<O>::byte_combine(&y_t);
            }
        }
    }
    res
}

fn aes_enc_bkwd_mkey1_mtag0<O>(
    x: &GenericArray<Field<O>, O::LENC>,
    xk: &GenericArray<Field<O>, O::PRODRUN128>,
    out: &[u8; 16],
    delta: Field<O>,
) -> Box<GenericArray<Field<O>, O::SENC>>
where
    O: OWFParameters,
{
    let mut res = GenericArray::default_boxed();
    let r = <O::R as Unsigned>::to_usize();
    let immut = delta;
    //Step 2
    for j in 0..r {
        for c in 0..4 {
            //Step 4
            for k in 0..4 {
                let ird = 128 * j + 32 * ((c + 4 - k) % 4) + 8 * k;
                let x_t: [Field<O>; 8];
                if j < r - 1 {
                    x_t = x[ird..ird + 8].try_into().unwrap();
                } else {
                    let mut x_out = [Field::<O>::default(); 8];
                    for i in 0..8 {
                        x_out[i] = immut
                            * ((out[(ird - 128 * j + i) / 8] >> ((ird - 128 * j + i) % 8)) & 1);
                    }
                    x_t = zip(x_out, &xk[128 + ird..136 + ird])
                        .map(|(out, &k)| out + k)
                        .collect::<Vec<Field<O>>>()
                        .try_into()
                        .unwrap();
                }
                let mut y_t = [Field::<O>::default(); 8];
                for i in 0..8 {
                    y_t[i] = x_t[(i + 7) % 8] + x_t[(i + 5) % 8] + x_t[(i + 2) % 8];
                }
                y_t[0] += immut;
                y_t[2] += immut;
                res[k + c * 4 + j * 16] = Field::<O>::byte_combine(&y_t);
            }
        }
    }
    res
}

fn aes_enc_bkwd_mkey0_mtag1<O>(
    x: &GenericArray<Field<O>, O::LENC>,
    xk: &GenericArray<Field<O>, O::PRODRUN128>,
) -> Box<GenericArray<Field<O>, O::SENC>>
where
    O: OWFParameters,
{
    let mut res = GenericArray::default_boxed();
    let r = <O::R as Unsigned>::to_usize();
    //Step 2
    for j in 0..r {
        for c in 0..4 {
            //Step 4
            for k in 0..4 {
                let ird = 128 * j + 32 * ((c + 4 - k) % 4) + 8 * k;
                let x_t = if j < r - 1 {
                    &x[ird..ird + 8]
                } else {
                    &xk[128 + ird..136 + ird]
                };
                let mut y_t = [Field::<O>::default(); 8];
                for i in 0..8 {
                    y_t[i] = x_t[(i + 7) % 8] + x_t[(i + 5) % 8] + x_t[(i + 2) % 8];
                }
                res[k + c * 4 + j * 16] = Field::<O>::byte_combine(&y_t);
            }
        }
    }
    res
}

fn aes_enc_cstrnts_mkey0<O>(
    a_t_hasher: &mut impl ZKHasherProcess<Field<O>>,
    b_t_hasher: &mut impl ZKHasherProcess<Field<O>>,
    input: &[u8; 16],
    output: &[u8; 16],
    w: &GenericArray<u8, O::QUOTLENC8>,
    v: &GenericArray<Field<O>, O::LENC>,
    k: &GenericArray<Field<O>, O::PRODRUN128>,
    vk: &GenericArray<Field<O>, O::PRODRUN128>,
) where
    O: OWFParameters,
{
    let senc = <O::SENC as Unsigned>::to_usize();
    let mut field_w: Box<GenericArray<Field<O>, O::LENC>> = GenericArray::default_boxed();
    for i in 0..w.len() {
        for j in 0..8 {
            // FIXME
            field_w[i * 8 + j] = Field::<O>::ONE * ((w[i] >> j) & 1);
        }
    }
    let s = aes_enc_fwd_mkey0_mtag0::<O>(&field_w, k, input);
    let vs = aes_enc_fwd_mkey0_mtag1::<O>(v, vk);
    let s_b = aes_enc_bkwd_mkey0_mtag0::<O>(&field_w, k, output);
    let v_s_b = aes_enc_bkwd_mkey0_mtag1::<O>(v, vk);
    for j in 0..senc {
        let a0 = vs[j] * v_s_b[j];
        let a1 = (s[j] + vs[j]) * (s_b[j] + v_s_b[j]) + Field::<O>::ONE + a0;
        a_t_hasher.update(&a1);
        b_t_hasher.update(&a0);
    }
}

fn aes_enc_cstrnts_mkey1<O>(
    b_t_hasher: &mut impl ZKHasherProcess<Field<O>>,
    input: &[u8; 16],
    output: &[u8; 16],
    q: &GenericArray<Field<O>, O::LENC>,
    qk: &GenericArray<Field<O>, O::PRODRUN128>,
    delta: Field<O>,
) where
    O: OWFParameters,
{
    let senc = <O::SENC as Unsigned>::to_usize();
    let qs = aes_enc_fwd_mkey1_mtag0::<O>(q, qk, input, delta);
    let q_s_b = aes_enc_bkwd_mkey1_mtag0::<O>(q, qk, output, delta);
    let delta_square = delta * delta;
    for j in 0..senc {
        let b = (qs[j] * q_s_b[j]) + delta_square;
        b_t_hasher.update(&b);
    }
}

fn bit_to_byte(input: &[u8]) -> u8 {
    let mut res = 0u8;
    for (i, item) in input.iter().enumerate().take(8) {
        res += item << i;
    }
    res
}

///Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
pub(crate) fn aes_prove<O>(
    w: &GenericArray<u8, O::LBYTES>,
    u: &GenericArray<u8, O::LAMBDALBYTES>,
    gv: CstrntsVal<O>,
    owf_input: &GenericArray<u8, O::InputSize>,
    owf_output: &GenericArray<u8, O::OutputSize>,
    chall: &GenericArray<u8, O::CHALL>,
) -> QSProof<O>
where
    O: OWFParameters,
{
    let l = <O::L as Unsigned>::to_usize();
    let lke = <O::LKE as Unsigned>::to_usize();
    let lenc = <O::LENC as Unsigned>::to_usize();
    let lambda = <O::LAMBDA as Unsigned>::to_usize();
    let new_w: GenericArray<u8, O::L> = w.iter().flat_map(|x| byte_to_bit(*x)).collect();
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
    let new_v = GenericArray::<Field<O>, O::LAMBDAL>::from_iter(
        temp_v.chunks(O::LAMBDABYTES::USIZE).map(Field::<O>::from),
    );
    let mut a_t_hasher =
        <<O as OWFParameters>::BaseParams as BaseParameters>::ZKHasher::new_zk_hasher(chall);
    let mut b_t_hasher =
        <<O as OWFParameters>::BaseParams as BaseParameters>::ZKHasher::new_zk_hasher(chall);

    let (k, vk) = aes_key_exp_cstrnts_mkey0::<O>(
        &mut a_t_hasher,
        &mut b_t_hasher,
        GenericArray::from_slice(&new_w[..lke]),
        GenericArray::from_slice(&new_v[..lke]),
    );

    aes_enc_cstrnts_mkey0::<O>(
        &mut a_t_hasher,
        &mut b_t_hasher,
        owf_input[..16].try_into().unwrap(),
        owf_output[..16].try_into().unwrap(),
        //building a T out of w
        GenericArray::from_slice(
            &new_w[lke..(lke + lenc)]
                .chunks(8)
                .map(bit_to_byte)
                .collect::<Vec<u8>>()[..],
        ),
        GenericArray::from_slice(&new_v[lke..lke + lenc]),
        &k,
        GenericArray::from_slice(&vk),
    );

    if O::LAMBDA::USIZE > 128 {
        aes_enc_cstrnts_mkey0::<O>(
            &mut a_t_hasher,
            &mut b_t_hasher,
            owf_input[16..].try_into().unwrap(),
            owf_output[16..].try_into().unwrap(),
            GenericArray::from_slice(
                &new_w[(lke + lenc)..l]
                    .chunks(8)
                    .map(bit_to_byte)
                    .collect::<Vec<u8>>()[..],
            ),
            GenericArray::from_slice(&new_v[(lke + lenc)..l]),
            &k,
            GenericArray::from_slice(&vk),
        );
    }

    let u_s = Field::<O>::from(&u[l / 8..]);
    let v_s = Field::<O>::sum_poly(&new_v[l..l + lambda]);
    let a_t = a_t_hasher.finalize(&u_s);
    let b_t = b_t_hasher.finalize(&v_s);

    (a_t.as_bytes(), b_t.as_bytes())
}

///Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
#[allow(clippy::too_many_arguments)]
pub(crate) fn aes_verify<O, Tau>(
    d: &GenericArray<u8, O::LBYTES>,
    gq: Box<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>,
    a_t: &GenericArray<u8, O::LAMBDABYTES>,
    chall2: &GenericArray<u8, O::CHALL>,
    chall3: &GenericArray<u8, O::LAMBDABYTES>,
    owf_input: &GenericArray<u8, O::InputSize>,
    owf_output: &GenericArray<u8, O::OutputSize>,
) -> GenericArray<u8, O::LAMBDABYTES>
where
    O: OWFParameters,
    Tau: TauParameters,
{
    let lambda = Field::<O>::LENGTH;
    let l = <O::L as Unsigned>::to_usize();
    let delta = Field::<O>::from(chall3);
    let lke = <O::LKE as Unsigned>::to_usize();
    let lenc = <O::LENC as Unsigned>::to_usize();

    let new_q = convert_gq::<O, Tau>(d, gq, chall3);
    let mut zk_hasher =
        <<O as OWFParameters>::BaseParams as BaseParameters>::ZKHasher::new_zk_hasher(chall2);

    let qk = aes_key_exp_cstrnts_mkey1::<O>(
        &mut zk_hasher,
        GenericArray::from_slice(&new_q[0..lke]),
        delta,
    );

    aes_enc_cstrnts_mkey1::<O>(
        &mut zk_hasher,
        owf_input[..16].try_into().unwrap(),
        owf_output[..16].try_into().unwrap(),
        GenericArray::from_slice(&new_q[lke..(lke + lenc)]),
        GenericArray::from_slice(&qk[..]),
        delta,
    );
    if O::LAMBDA::USIZE > 128 {
        aes_enc_cstrnts_mkey1::<O>(
            &mut zk_hasher,
            owf_input[16..].try_into().unwrap(),
            owf_output[16..].try_into().unwrap(),
            GenericArray::from_slice(&new_q[lke + lenc..l]),
            GenericArray::from_slice(&qk[..]),
            delta,
        );
    }

    let q_s = Field::<O>::sum_poly(&new_q[l..l + lambda]);
    (zk_hasher.finalize(&q_s) + Field::<O>::from(a_t) * delta).as_bytes()
}

#[cfg(test)]
mod test {
    #![allow(clippy::needless_range_loop)]

    use super::*;

    use crate::{
        fields::{large_fields::NewFromU128, BigGaloisField, GF128, GF192, GF256},
        parameter::{
            OWFParameters, OWF128, OWF192, OWF256, PARAM, PARAM128S, PARAM192S, PARAM256S,
        },
    };

    use generic_array::{typenum::U8, GenericArray};
    use serde::Deserialize;

    type ZkHash256 = GenericArray<u8, <OWF256 as OWFParameters>::LAMBDABYTES>;
    type ZkHash192 = GenericArray<u8, <OWF192 as OWFParameters>::LAMBDABYTES>;
    type ZkHash128 = GenericArray<u8, <OWF128 as OWFParameters>::LAMBDABYTES>;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesExtendedWitness {
        lambda: u16,
        key: Vec<u8>,
        input: Vec<u8>,
        w: Vec<u8>,
    }

    #[test]
    fn aes_extended_witness_test() {
        let database: Vec<AesExtendedWitness> =
            serde_json::from_str(include_str!("../tests/data/AesExtendedWitness.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let res = aes_extendedwitness::<OWF128>(
                    GenericArray::from_slice(&data.key),
                    GenericArray::from_slice(
                        &data.input[..<OWF128 as OWFParameters>::InputSize::USIZE],
                    ),
                );
                assert_eq!(res.0, Box::new(*GenericArray::from_slice(&data.w)));
            } else if data.lambda == 192 {
                let res = aes_extendedwitness::<OWF192>(
                    GenericArray::from_slice(&data.key),
                    GenericArray::from_slice(
                        &data.input[..<OWF192 as OWFParameters>::InputSize::USIZE],
                    ),
                );
                assert_eq!(res.0, Box::new(*GenericArray::from_slice(&data.w)));
            } else {
                let res = aes_extendedwitness::<OWF256>(
                    GenericArray::from_slice(&data.key),
                    GenericArray::from_slice(
                        &data.input[..<OWF256 as OWFParameters>::InputSize::USIZE],
                    ),
                );
                assert_eq!(res.0, Box::new(*GenericArray::from_slice(&data.w)));
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesKeyExpFwd {
        lambda: u16,
        x: Vec<[u128; 4]>,
        out: Vec<[u128; 4]>,
    }

    fn convtobit<T>(x: u8) -> Box<GenericArray<T, U8>>
    where
        T: BigGaloisField,
    {
        convert_to_bit(&[x])
    }

    #[test]
    fn aes_key_exp_fwd_test() {
        let database: Vec<AesKeyExpFwd> =
            serde_json::from_str(include_str!("../tests/data/AesKeyExpFwd.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let (out, input): (Vec<GF128>, Vec<GF128>) = if data.x.len() >= 448 {
                    (
                        data.out
                            .iter()
                            .map(|x| GF128::new((x[0]) + ((x[1]) << 64), 0))
                            .collect(),
                        data.x
                            .iter()
                            .map(|x| GF128::new((x[0]) + ((x[1]) << 64), 0))
                            .collect(),
                    )
                } else {
                    (
                        data.out
                            .iter()
                            .flat_map(|out| convtobit(out[0] as u8))
                            .collect(),
                        data.x
                            .iter()
                            .flat_map(|out| convtobit(out[0] as u8))
                            .collect(),
                    )
                };
                let res: GenericArray<GF128, <OWF128 as OWFParameters>::PRODRUN128> =
                    *aes_key_exp_fwd::<OWF128>(GenericArray::from_slice(&input));
                assert_eq!(res, *GenericArray::from_slice(&out));
            } else if data.lambda == 192 {
                let (out, input): (Vec<GF192>, Vec<GF192>) = if data.x.len() >= 448 {
                    (
                        data.out
                            .iter()
                            .map(|x| GF192::new((x[0]) + ((x[1]) << 64), x[2]))
                            .collect(),
                        data.x
                            .iter()
                            .map(|x| GF192::new((x[0]) + ((x[1]) << 64), x[2]))
                            .collect(),
                    )
                } else {
                    (
                        data.out
                            .iter()
                            .flat_map(|out| convtobit(out[0] as u8))
                            .collect(),
                        data.x.iter().flat_map(|x| convtobit(x[0] as u8)).collect(),
                    )
                };
                let res: GenericArray<GF192, <OWF192 as OWFParameters>::PRODRUN128> =
                    *aes_key_exp_fwd::<OWF192>(GenericArray::from_slice(&input));
                assert_eq!(res, *GenericArray::from_slice(&out));
            } else {
                let (out, input): (Vec<GF256>, Vec<GF256>) = if data.x.len() >= 448 {
                    (
                        data.out
                            .iter()
                            .map(|x| GF256::new((x[0]) + ((x[1]) << 64), (x[2]) + ((x[3]) << 64)))
                            .collect(),
                        data.x
                            .iter()
                            .map(|x| GF256::new((x[0]) + ((x[1]) << 64), (x[2]) + ((x[3]) << 64)))
                            .collect(),
                    )
                } else {
                    (
                        data.out
                            .iter()
                            .flat_map(|out| convtobit(out[0] as u8))
                            .collect(),
                        data.x.iter().flat_map(|x| convtobit(x[0] as u8)).collect(),
                    )
                };
                let res: GenericArray<GF256, <OWF256 as OWFParameters>::PRODRUN128> =
                    *aes_key_exp_fwd::<OWF256>(GenericArray::from_slice(&input));
                assert_eq!(res, *GenericArray::from_slice(&out));
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesKeyExpBwd {
        lambda: u16,
        mtag: u8,
        mkey: u8,
        delta: [u128; 4],
        x: Vec<[u128; 4]>,
        xk: Vec<[u128; 4]>,
        out: Vec<[u128; 4]>,
    }

    fn aes_key_exp_bwd<O>(
        x: &GenericArray<Field<O>, O::LKE>,
        xk: &GenericArray<Field<O>, O::PRODRUN128>,
        mtag: bool,
        mkey: bool,
        delta: Field<O>,
    ) -> Box<GenericArray<Field<O>, O::PRODSKE8>>
    where
        O: OWFParameters,
    {
        if !mkey && !mtag {
            aes_key_exp_bwd_mtag0_mkey0::<O>(x, xk)
        } else if mkey {
            aes_key_exp_bwd_mtag0_mkey1::<O>(x, xk, delta)
        } else if mtag {
            aes_key_exp_bwd_mtag1_mkey0::<O>(x, xk)
        } else {
            unreachable!()
        }
    }

    #[test]
    fn aes_key_exp_bwd_test() {
        let database: Vec<AesKeyExpBwd> =
            serde_json::from_str(include_str!("../tests/data/AesKeyExpBwd.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let mtag = data.mtag != 0;
                let mkey = data.mkey != 0;
                let delta = GF128::new(data.delta[0] + (data.delta[1] << 64), 0);
                let (x, xk, out): (Vec<GF128>, Vec<GF128>, Vec<GF128>) = if !mtag && !mkey {
                    (
                        data.x
                            .iter()
                            .flat_map(|x| convtobit(x[0].to_le_bytes()[0]))
                            .collect(),
                        data.xk
                            .iter()
                            .flat_map(|x| convtobit(x[0].to_le_bytes()[0]))
                            .collect(),
                        data.out
                            .iter()
                            .flat_map(|x| convtobit(x[0].to_le_bytes()[0]))
                            .collect(),
                    )
                } else {
                    (
                        data.x
                            .iter()
                            .map(|x| GF128::new(x[0] + (x[1] << 64), 0))
                            .collect(),
                        data.xk
                            .iter()
                            .map(|xk| GF128::new(xk[0] + (xk[1] << 64), 0))
                            .collect(),
                        data.out
                            .iter()
                            .map(|out| GF128::new(out[0] + (out[1] << 64), 0))
                            .collect(),
                    )
                };

                let res = aes_key_exp_bwd::<OWF128>(
                    GenericArray::from_slice(&x[..448]),
                    GenericArray::from_slice(
                        &[&xk[..], &vec![GF128::default(); 224][..]].concat()[..1408],
                    ),
                    mtag,
                    mkey,
                    delta,
                );
                for i in 0..res.len() {
                    assert_eq!(res[i], out[i]);
                }
            } else if data.lambda == 192 {
                let mtag = data.mtag != 0;
                let mkey = data.mkey != 0;
                let delta = GF192::new(data.delta[0] + (data.delta[1] << 64), data.delta[2]);
                let (x, xk, out): (Vec<GF192>, Vec<GF192>, Vec<GF192>) = if !mtag && !mkey {
                    (
                        data.x
                            .iter()
                            .flat_map(|x| convtobit(x[0].to_le_bytes()[0]))
                            .collect(),
                        data.xk
                            .iter()
                            .flat_map(|x| convtobit(x[0].to_le_bytes()[0]))
                            .collect(),
                        data.out
                            .iter()
                            .flat_map(|x| convtobit(x[0].to_le_bytes()[0]))
                            .collect(),
                    )
                } else {
                    (
                        data.x
                            .iter()
                            .map(|x| GF192::new(x[0] + (x[1] << 64), x[2]))
                            .collect(),
                        data.xk
                            .iter()
                            .map(|xk| GF192::new(xk[0] + (xk[1] << 64), xk[2]))
                            .collect(),
                        data.out
                            .iter()
                            .map(|out| GF192::new(out[0] + (out[1] << 64), out[2]))
                            .collect(),
                    )
                };
                let res = aes_key_exp_bwd::<OWF192>(
                    GenericArray::from_slice(&x[..448]),
                    GenericArray::from_slice(
                        &[&xk[..], &vec![GF192::default(); 288][..]].concat()[..1664],
                    ),
                    mtag,
                    mkey,
                    delta,
                );
                for i in 0..res.len() {
                    assert_eq!(res[i], out[i]);
                }
            } else {
                let mtag = data.mtag != 0;
                let mkey = data.mkey != 0;
                let delta = GF256::new(
                    data.delta[0] + (data.delta[1] << 64),
                    data.delta[2] + (data.delta[3] << 64),
                );
                let (x, xk, out): (Vec<GF256>, Vec<GF256>, Vec<GF256>) = if !mtag && !mkey {
                    (
                        data.x
                            .iter()
                            .flat_map(|x| convtobit(x[0].to_le_bytes()[0]))
                            .collect(),
                        data.xk
                            .iter()
                            .flat_map(|x| convtobit(x[0].to_le_bytes()[0]))
                            .collect(),
                        data.out
                            .iter()
                            .flat_map(|x| convtobit(x[0].to_le_bytes()[0]))
                            .collect(),
                    )
                } else {
                    (
                        data.x
                            .iter()
                            .map(|x| GF256::new(x[0] + (x[1] << 64), x[2] + (x[3] << 64)))
                            .collect(),
                        data.xk
                            .iter()
                            .map(|xk| GF256::new(xk[0] + (xk[1] << 64), xk[2] + (xk[3] << 64)))
                            .collect(),
                        data.out
                            .iter()
                            .map(|out| GF256::new(out[0] + (out[1] << 64), out[2] + (out[3] << 64)))
                            .collect(),
                    )
                };
                let res = aes_key_exp_bwd::<OWF256>(
                    GenericArray::from_slice(&x[..672]),
                    GenericArray::from_slice(
                        &[&xk[..], &vec![GF256::default(); 352][..]].concat()[..1920],
                    ),
                    mtag,
                    mkey,
                    delta,
                );
                for i in 0..res.len() {
                    assert_eq!(res[i], out[i]);
                }
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesEncFwd {
        lambda: u16,
        mkey: u8,
        mtag: u8,
        x: Vec<[u64; 4]>,
        xk: Vec<[u64; 4]>,
        input: [u8; 16],
        delta: [u64; 4],
        reslambda: Vec<[u64; 4]>,
    }

    fn aes_enc_fwd<O>(
        x: &GenericArray<Field<O>, O::LENC>,
        xk: &GenericArray<Field<O>, O::PRODRUN128>,
        mkey: bool,
        mtag: bool,
        input: &[u8; 16],
        delta: Field<O>,
    ) -> Box<GenericArray<Field<O>, O::SENC>>
    where
        O: OWFParameters,
    {
        if !mkey && !mtag {
            aes_enc_fwd_mkey0_mtag0::<O>(x, xk, input)
        } else if mkey {
            aes_enc_fwd_mkey1_mtag0::<O>(x, xk, input, delta)
        } else if mtag {
            aes_enc_fwd_mkey0_mtag1::<O>(x, xk)
        } else {
            unreachable!()
        }
    }

    #[test]
    fn aes_enc_fwd_test() {
        let database: Vec<AesEncFwd> =
            serde_json::from_str(include_str!("../tests/data/AesEncFwd.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let mtag = data.mtag != 0;
                let mkey = data.mkey != 0;
                let (x, xk) = if !(mkey || mtag) {
                    (
                        (data
                            .x
                            .iter()
                            .flat_map(|x| convtobit::<GF128>(x[0].to_le_bytes()[..1][0]))
                            .collect::<Vec<GF128>>()),
                        (data
                            .xk
                            .iter()
                            .flat_map(|x| convtobit::<GF128>(x[0].to_le_bytes()[..1][0]))
                            .collect::<Vec<GF128>>()),
                    )
                } else {
                    (
                        (data
                            .x
                            .iter()
                            .map(|v| GF128::new(v[0] as u128 + ((v[1] as u128) << 64), 0))
                            .collect::<Vec<GF128>>()),
                        (data
                            .xk
                            .iter()
                            .map(|v| GF128::new(v[0] as u128 + ((v[1] as u128) << 64), 0))
                            .collect::<Vec<GF128>>()),
                    )
                };
                let res = aes_enc_fwd::<OWF128>(
                    GenericArray::from_slice(&x[..]),
                    GenericArray::from_slice(&xk[..]),
                    data.mkey != 0,
                    data.mtag != 0,
                    &data.input,
                    GF128::new(data.delta[0] as u128 + ((data.delta[1] as u128) << 64), 0),
                );
                let out = data
                    .reslambda
                    .iter()
                    .map(|v| GF128::new(v[0] as u128 + ((v[1] as u128) << 64), 0))
                    .collect::<Vec<GF128>>();
                for i in 0..out.len() {
                    assert_eq!(out[i], res[i]);
                }
            } else if data.lambda == 192 {
                let mtag = data.mtag != 0;
                let mkey = data.mkey != 0;
                let (x, xk) = if !(mkey || mtag) {
                    (
                        (data
                            .x
                            .iter()
                            .flat_map(|x| convtobit::<GF192>(x[0].to_le_bytes()[..1][0]))
                            .collect::<Vec<GF192>>()),
                        (data
                            .xk
                            .iter()
                            .flat_map(|x| convtobit::<GF192>(x[0].to_le_bytes()[..1][0]))
                            .collect::<Vec<GF192>>()),
                    )
                } else {
                    (
                        (data
                            .x
                            .iter()
                            .map(|v| {
                                GF192::new(v[0] as u128 + ((v[1] as u128) << 64), v[2] as u128)
                            })
                            .collect::<Vec<GF192>>()),
                        (data
                            .xk
                            .iter()
                            .map(|v| {
                                GF192::new(v[0] as u128 + ((v[1] as u128) << 64), v[2] as u128)
                            })
                            .collect::<Vec<GF192>>()),
                    )
                };
                let res = aes_enc_fwd::<OWF192>(
                    GenericArray::from_slice(&x[..]),
                    GenericArray::from_slice(&xk[..]),
                    data.mkey != 0,
                    data.mtag != 0,
                    &data.input,
                    GF192::new(
                        data.delta[0] as u128 + ((data.delta[1] as u128) << 64),
                        data.delta[2] as u128,
                    ),
                );
                let out = data
                    .reslambda
                    .iter()
                    .map(|v| GF192::new(v[0] as u128 + ((v[1] as u128) << 64), v[2] as u128))
                    .collect::<Vec<GF192>>();
                for i in 0..out.len() {
                    assert_eq!(out[i], res[i]);
                }
            } else {
                let mtag = data.mtag != 0;
                let mkey = data.mkey != 0;
                let (x, xk) = if !(mkey || mtag) {
                    (
                        (data
                            .x
                            .iter()
                            .flat_map(|x| convtobit::<GF256>(x[0].to_le_bytes()[..1][0]))
                            .collect::<Vec<GF256>>()),
                        (data
                            .xk
                            .iter()
                            .flat_map(|x| convtobit::<GF256>(x[0].to_le_bytes()[..1][0]))
                            .collect::<Vec<GF256>>()),
                    )
                } else {
                    (
                        (data
                            .x
                            .iter()
                            .map(|v| {
                                GF256::new(
                                    v[0] as u128 + ((v[1] as u128) << 64),
                                    v[2] as u128 + ((v[3] as u128) << 64),
                                )
                            })
                            .collect::<Vec<GF256>>()),
                        (data
                            .xk
                            .iter()
                            .map(|v| {
                                GF256::new(
                                    v[0] as u128 + ((v[1] as u128) << 64),
                                    v[2] as u128 + ((v[3] as u128) << 64),
                                )
                            })
                            .collect::<Vec<GF256>>()),
                    )
                };
                let res = aes_enc_fwd::<OWF256>(
                    GenericArray::from_slice(&x[..]),
                    GenericArray::from_slice(&xk[..]),
                    data.mkey != 0,
                    data.mtag != 0,
                    &data.input,
                    GF256::new(
                        data.delta[0] as u128 + ((data.delta[1] as u128) << 64),
                        data.delta[2] as u128 + ((data.delta[3] as u128) << 64),
                    ),
                );
                let out = data
                    .reslambda
                    .iter()
                    .map(|v| {
                        GF256::new(
                            v[0] as u128 + ((v[1] as u128) << 64),
                            v[2] as u128 + ((v[3] as u128) << 64),
                        )
                    })
                    .collect::<Vec<GF256>>();
                for i in 0..out.len() {
                    assert_eq!(out[i], res[i]);
                }
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesEncBkwd {
        lambda: u16,
        mkey: u8,
        mtag: u8,
        x: Vec<[u128; 4]>,
        xk: Vec<[u128; 4]>,
        output: [u8; 16],
        delta: [u128; 4],
        reslambda: Vec<[u128; 4]>,
    }

    fn aes_enc_bkwd<O>(
        x: &GenericArray<Field<O>, O::LENC>,
        xk: &GenericArray<Field<O>, O::PRODRUN128>,
        mkey: bool,
        mtag: bool,
        out: &[u8; 16],
        delta: Field<O>,
    ) -> Box<GenericArray<Field<O>, O::SENC>>
    where
        O: OWFParameters,
    {
        if !mkey && !mtag {
            aes_enc_bkwd_mkey0_mtag0::<O>(x, xk, out)
        } else if mkey {
            aes_enc_bkwd_mkey1_mtag0::<O>(x, xk, out, delta)
        } else if mtag {
            aes_enc_bkwd_mkey0_mtag1::<O>(x, xk)
        } else {
            unreachable!()
        }
    }

    #[test]
    fn aes_enc_bkwd_test() {
        let database: Vec<AesEncBkwd> =
            serde_json::from_str(include_str!("../tests/data/AesEncBkwd.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let mtag = data.mtag != 0;
                let mkey = data.mkey != 0;
                let (x, xk) = if !(mkey || mtag) {
                    (
                        (data
                            .x
                            .iter()
                            .flat_map(|x| convtobit::<GF128>(x[0].to_le_bytes()[..1][0]))
                            .collect::<Vec<GF128>>()),
                        (data
                            .xk
                            .iter()
                            .flat_map(|x| convtobit::<GF128>(x[0].to_le_bytes()[..1][0]))
                            .collect::<Vec<GF128>>()),
                    )
                } else {
                    (
                        (data
                            .x
                            .iter()
                            .map(|v| GF128::new(v[0] + (v[1] << 64), 0))
                            .collect::<Vec<GF128>>()),
                        (data
                            .xk
                            .iter()
                            .map(|v| GF128::new(v[0] + (v[1] << 64), 0))
                            .collect::<Vec<GF128>>()),
                    )
                };
                let res = aes_enc_bkwd::<OWF128>(
                    GenericArray::from_slice(&x[..]),
                    GenericArray::from_slice(&xk[..]),
                    data.mkey != 0,
                    data.mtag != 0,
                    &data.output,
                    GF128::new(data.delta[0] + (data.delta[1] << 64), 0),
                );
                let out = data
                    .reslambda
                    .iter()
                    .map(|v| GF128::new(v[0] + (v[1] << 64), 0))
                    .collect::<Vec<GF128>>();
                for i in 0..out.len() {
                    assert_eq!(out[i], res[i]);
                }
            } else if data.lambda == 192 {
                let mtag = data.mtag != 0;
                let mkey = data.mkey != 0;
                let (x, xk) = if !(mkey || mtag) {
                    (
                        (data
                            .x
                            .iter()
                            .flat_map(|x| convtobit::<GF192>(x[0].to_le_bytes()[..1][0]))
                            .collect::<Vec<GF192>>()),
                        (data
                            .xk
                            .iter()
                            .flat_map(|x| convtobit::<GF192>(x[0].to_le_bytes()[..1][0]))
                            .collect::<Vec<GF192>>()),
                    )
                } else {
                    (
                        (data
                            .x
                            .iter()
                            .map(|v| GF192::new(v[0] + (v[1] << 64), v[2]))
                            .collect::<Vec<GF192>>()),
                        (data
                            .xk
                            .iter()
                            .map(|v| GF192::new(v[0] + (v[1] << 64), v[2]))
                            .collect::<Vec<GF192>>()),
                    )
                };
                let res = aes_enc_bkwd::<OWF192>(
                    GenericArray::from_slice(&x[..]),
                    GenericArray::from_slice(&xk[..]),
                    data.mkey != 0,
                    data.mtag != 0,
                    &data.output,
                    GF192::new(data.delta[0] + (data.delta[1] << 64), data.delta[2]),
                );
                let out = data
                    .reslambda
                    .iter()
                    .map(|v| GF192::new(v[0] + (v[1] << 64), v[2]))
                    .collect::<Vec<GF192>>();
                for i in 0..out.len() {
                    assert_eq!(out[i], res[i]);
                }
            } else {
                let mtag = data.mtag != 0;
                let mkey = data.mkey != 0;
                let (x, xk) = if !(mkey || mtag) {
                    (
                        (data
                            .x
                            .iter()
                            .flat_map(|x| convtobit::<GF256>(x[0].to_le_bytes()[..1][0]))
                            .collect::<Vec<GF256>>()),
                        (data
                            .xk
                            .iter()
                            .flat_map(|x| convtobit::<GF256>(x[0].to_le_bytes()[..1][0]))
                            .collect::<Vec<GF256>>()),
                    )
                } else {
                    (
                        (data
                            .x
                            .iter()
                            .map(|v| GF256::new(v[0] + (v[1] << 64), v[2] + (v[3] << 64)))
                            .collect::<Vec<GF256>>()),
                        (data
                            .xk
                            .iter()
                            .map(|v| GF256::new(v[0] + (v[1] << 64), v[2] + (v[3] << 64)))
                            .collect::<Vec<GF256>>()),
                    )
                };
                let res = aes_enc_bkwd::<OWF256>(
                    GenericArray::from_slice(&x[..]),
                    GenericArray::from_slice(&xk[..]),
                    data.mkey != 0,
                    data.mtag != 0,
                    &data.output,
                    GF256::new(
                        data.delta[0] + (data.delta[1] << 64),
                        data.delta[2] + (data.delta[3] << 64),
                    ),
                );
                let out = data
                    .reslambda
                    .iter()
                    .map(|v| GF256::new(v[0] + (v[1] << 64), v[2] + (v[3] << 64)))
                    .collect::<Vec<GF256>>();
                for i in 0..out.len() {
                    assert_eq!(out[i], res[i]);
                }
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesProve {
        lambda: u16,
        gv: Vec<Vec<u8>>,
        w: Vec<u8>,
        u: Vec<u8>,
        input: Vec<u8>,
        output: Vec<u8>,
        chall: Vec<u8>,
        at: Vec<u8>,
        bt: Vec<u8>,
    }

    #[test]
    fn aes_prove_test() {
        let database: Vec<AesProve> =
            serde_json::from_str(include_str!("../tests/data/AesProve.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let res: (ZkHash128, ZkHash128) = aes_prove::<OWF128>(
                    GenericArray::from_slice(&data.w),
                    GenericArray::from_slice(&data.u),
                    GenericArray::from_slice(
                        &data
                            .gv
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.input),
                    GenericArray::from_slice(&data.output),
                    GenericArray::from_slice(&data.chall),
                );

                assert_eq!((res).0, *GenericArray::from_slice(&data.at));
                assert_eq!((res).1, *GenericArray::from_slice(&data.bt));
            } else if data.lambda == 192 {
                let mut bitw: Vec<u8> = vec![0; 3264];
                for i in 0..data.w.len() {
                    for j in 0..8 {
                        bitw[8 * i + j] = (data.w[i] >> j) & 1;
                    }
                }
                let res: (ZkHash192, ZkHash192) = aes_prove::<OWF192>(
                    GenericArray::from_slice(&data.w),
                    GenericArray::from_slice(&data.u),
                    GenericArray::from_slice(
                        &data
                            .gv
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.input),
                    GenericArray::from_slice(&data.output),
                    GenericArray::from_slice(&data.chall),
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.at));
                assert_eq!(res.1, *GenericArray::from_slice(&data.bt));
            } else {
                let mut bitw: Vec<u8> = vec![0; 4000];
                for i in 0..data.w.len() {
                    for j in 0..8 {
                        bitw[8 * i + j] = (data.w[i] >> j) & 1;
                    }
                }
                let res: (ZkHash256, ZkHash256) = aes_prove::<OWF256>(
                    GenericArray::from_slice(&data.w),
                    GenericArray::from_slice(&data.u),
                    GenericArray::from_slice(
                        &data
                            .gv
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.input),
                    GenericArray::from_slice(&data.output),
                    GenericArray::from_slice(&data.chall),
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.at));
                assert_eq!(res.1, *GenericArray::from_slice(&data.bt));
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesVerify {
        lambda: u16,
        gq: Vec<Vec<u8>>,
        d: Vec<u8>,
        chall2: Vec<u8>,
        chall3: Vec<u8>,
        at: Vec<u8>,
        input: Vec<u8>,
        output: Vec<u8>,
        res: Vec<u64>,
    }

    fn aes_verify<O, Tau>(
        d: &GenericArray<u8, O::LBYTES>,
        gq: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        a_t: &GenericArray<u8, O::LAMBDABYTES>,
        chall2: &GenericArray<u8, O::CHALL>,
        chall3: &GenericArray<u8, O::LAMBDABYTES>,
        owf_input: &GenericArray<u8, O::InputSize>,
        owf_output: &GenericArray<u8, O::OutputSize>,
    ) -> GenericArray<u8, O::LAMBDABYTES>
    where
        O: OWFParameters,
        Tau: TauParameters,
    {
        super::aes_verify::<O, Tau>(
            d,
            Box::<GenericArray<_, _>>::from_iter(gq.iter().cloned()),
            a_t,
            chall2,
            chall3,
            owf_input,
            owf_output,
        )
    }

    #[test]
    fn aes_verify_test() {
        let database: Vec<AesVerify> =
            serde_json::from_str(include_str!("../tests/data/AesVerify.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let out = aes_verify::<OWF128, <PARAM128S as PARAM>::Tau>(
                    GenericArray::from_slice(&data.d[..]),
                    GenericArray::from_slice(
                        &data
                            .gq
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.at),
                    GenericArray::from_slice(&data.chall2[..]),
                    GenericArray::from_slice(&data.chall3[..]),
                    GenericArray::from_slice(&data.input),
                    GenericArray::from_slice(&data.output),
                );
                assert_eq!(
                    GF128::new(data.res[0] as u128 + ((data.res[1] as u128) << 64), 0),
                    GF128::from(&out[..])
                );
            } else if data.lambda == 192 {
                let out = aes_verify::<OWF192, <PARAM192S as PARAM>::Tau>(
                    GenericArray::from_slice(&data.d[..]),
                    GenericArray::from_slice(
                        &data
                            .gq
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.at),
                    GenericArray::from_slice(&data.chall2[..]),
                    GenericArray::from_slice(&data.chall3[..]),
                    GenericArray::from_slice(&data.input),
                    GenericArray::from_slice(&data.output),
                );
                assert_eq!(
                    GF192::new(
                        data.res[0] as u128 + ((data.res[1] as u128) << 64),
                        data.res[2] as u128
                    ),
                    GF192::from(&out[..])
                );
            } else {
                let out = aes_verify::<OWF256, <PARAM256S as PARAM>::Tau>(
                    GenericArray::from_slice(&data.d[..]),
                    GenericArray::from_slice(
                        &data
                            .gq
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.at),
                    GenericArray::from_slice(&data.chall2[..]),
                    GenericArray::from_slice(&data.chall3[..]),
                    GenericArray::from_slice(&data.input),
                    GenericArray::from_slice(&data.output),
                );
                assert_eq!(
                    GF256::new(
                        data.res[0] as u128 + ((data.res[1] as u128) << 64),
                        data.res[2] as u128 + ((data.res[3] as u128) << 64)
                    ),
                    GF256::from(&out[..])
                );
            }
        }
    }
}
