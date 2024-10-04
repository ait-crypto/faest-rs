use std::{array, iter::zip};

use either::Either;
use generic_array::{typenum::Unsigned, GenericArray};

use crate::{
    aes::convert_to_bit,
    fields::{ByteCombine, ByteCombineConstants, Field as _, SumPoly},
    parameter::{BaseParameters, OWFParameters, QSProof, TauParameters},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, sub_bytes, sub_bytes_nots, State,
    },
    universal_hashing::{ZKHasherInit, ZKHasherProcess},
    utils::convert_gq,
};

type Field<O> = <<O as OWFParameters>::BaseParams as BaseParameters>::Field;

pub(crate) fn em_extendedwitness<O>(
    owf_key: &GenericArray<u8, O::LAMBDABYTES>,
    owf_input: &GenericArray<u8, O::InputSize>,
) -> (Box<GenericArray<u8, O::LBYTES>>, bool)
where
    O: OWFParameters,
{
    let mut valid = true;
    let mut res: Box<GenericArray<u8, O::LBYTES>> = GenericArray::default_boxed();
    let mut index = O::LAMBDABYTES::USIZE;
    let (kb, _) = rijndael_key_schedule(
        owf_input,
        O::NST::USIZE,
        O::NK::USIZE,
        O::R::USIZE,
        4 * (((O::R::USIZE + 1) * O::NST::USIZE) / O::NK::USIZE),
    );
    res[..O::LAMBDABYTES::USIZE].copy_from_slice(owf_key);
    let mut state = State::default();
    bitslice(&mut state, &owf_key[..16], &owf_key[16..]);
    rijndael_add_round_key(&mut state, &kb[..8]);
    for j in 1..O::R::USIZE {
        for i in inv_bitslice(&state)[0][..].iter() {
            valid &= *i != 0;
        }
        if O::NST::USIZE == 6 {
            for i in inv_bitslice(&state)[1][..8].iter() {
                valid &= *i != 0;
            }
        } else if O::NST::USIZE == 8 {
            for i in inv_bitslice(&state)[1][..].iter() {
                valid &= *i != 0;
            }
        }
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);
        rijndael_shift_rows_1(&mut state, O::NST::USIZE);
        for i in
            convert_from_batchblocks(inv_bitslice(&state))[..O::NK::USIZE][..O::NK::USIZE].iter()
        {
            res[index..index + size_of::<u32>()].copy_from_slice(&i.to_le_bytes());
            index += size_of::<u32>();
        }
        mix_columns_0(&mut state);
        rijndael_add_round_key(&mut state, &kb[8 * j..8 * (j + 1)]);
    }
    for i in inv_bitslice(&state)[0][..].iter() {
        valid &= *i != 0;
    }
    if O::NST::USIZE == 6 {
        for i in inv_bitslice(&state)[1][..8].iter() {
            valid &= *i != 0;
        }
    } else if O::NST::USIZE == 8 {
        for i in inv_bitslice(&state)[1][..].iter() {
            valid &= *i != 0;
        }
    }
    (res, valid)
}

///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///
///One of the first path to optimize the code could be to do the distinction
fn em_enc_fwd<O>(
    z: Either<&[u8], &[Field<O>]>,
    x: Option<Either<&[u8], &[Field<O>]>>,
) -> Box<GenericArray<Field<O>, O::SENC>>
where
    O: OWFParameters,
{
    let mut res = GenericArray::default_boxed();
    let mut index = 0;
    //Step 2-3
    for j in 0..4 * O::NST::USIZE {
        res[index] = match z {
            Either::Left(z) => Field::<O>::byte_combine_bits(z[j]),
            Either::Right(z) => Field::<O>::byte_combine_slice(&z[8 * j..8 * (j + 1)]),
        } + match x {
            None => Field::<O>::ZERO,
            Some(Either::Left(x)) => Field::<O>::byte_combine_bits(x[j]),
            Some(Either::Right(x)) => Field::<O>::byte_combine_slice(&x[8 * j..8 * (j + 1)]),
        };
        index += 1;
    }
    //Step 4
    for j in 1..O::R::USIZE {
        for c in 0..O::NST::USIZE {
            let i: usize = 32 * O::NST::USIZE * j + 32 * c;
            let mut z_hat = [Field::<O>::default(); 4];
            let mut x_hat = [Field::<O>::default(); 4];
            for r in 0..4 {
                z_hat[r] = match z {
                    Either::Left(z) => Field::<O>::byte_combine_bits(z[i / 8 + r]),
                    Either::Right(z) => {
                        Field::<O>::byte_combine_slice(&z[i + 8 * r..i + 8 * r + 8])
                    }
                };
                x_hat[r] = match x {
                    None => Field::<O>::ZERO,
                    Some(Either::Left(x)) => Field::<O>::byte_combine_bits(x[i / 8 + r]),
                    Some(Either::Right(x)) => {
                        Field::<O>::byte_combine_slice(&x[i + 8 * r..i + 8 * r + 8])
                    }
                };
            }

            //Step 16
            res[index] = z_hat[0] * Field::<O>::BYTE_COMBINE_2  + z_hat[1] * Field::<O>::BYTE_COMBINE_3  + z_hat[2] /* * a */ + z_hat[3] /* * a */ + x_hat[0];
            res[index + 1] = z_hat[0] /* * a */ + z_hat[1] * Field::<O>::BYTE_COMBINE_2  + z_hat[2] * Field::<O>::BYTE_COMBINE_3  + z_hat[3] /* * a */ + x_hat[1];
            res[index + 2] = z_hat[0] /* * a */ + z_hat[1] /* * a */ + z_hat[2] * Field::<O>::BYTE_COMBINE_2  + z_hat[3] * Field::<O>::BYTE_COMBINE_3  + x_hat[2];
            res[index + 3] = z_hat[0] * Field::<O>::BYTE_COMBINE_3  + z_hat[1] /* * a */ + z_hat[2] /* * a */ + z_hat[3] * Field::<O>::BYTE_COMBINE_2  + x_hat[3];
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
fn em_enc_bkwd_mkey0_mtag0<O>(
    x: &GenericArray<Field<O>, O::LAMBDAR1>,
    z: &GenericArray<Field<O>, O::L>,
    z_out: &GenericArray<Field<O>, O::LAMBDA>,
) -> Box<GenericArray<Field<O>, O::SENC>>
where
    O: OWFParameters,
{
    let mut res: Box<GenericArray<Field<O>, O::SENC>> = GenericArray::default_boxed();
    let mut index = 0;

    //Step 2
    for j in 0..O::R::USIZE {
        for c in 0..O::NST::USIZE {
            //Step 4
            for k in 0..4 {
                let mut icol = (c + O::NST::USIZE - k) % O::NST::USIZE;
                if O::NST::USIZE == 8 && k >= 2 {
                    icol = (icol + O::NST::USIZE - 1) % O::NST::USIZE;
                }
                let ird = O::LAMBDA::USIZE + 32 * O::NST::USIZE * j + 32 * icol + 8 * k;
                let z_t: [_; 8] = if j < O::R::USIZE - 1 {
                    array::from_fn(|idx| z[ird + idx])
                } else {
                    let z_out_t = &z_out[ird - 32 * O::NST::USIZE * (j + 1)
                        ..ird - 32 * O::NST::USIZE * (j + 1) + 8];
                    array::from_fn(|idx| z_out_t[idx] + x[ird + idx])
                };
                let mut y_t =
                    array::from_fn(|i| z_t[(i + 7) % 8] + z_t[(i + 5) % 8] + z_t[(i + 2) % 8]);
                y_t[0] += Field::<O>::ONE;
                y_t[2] += Field::<O>::ONE;
                res[index] = Field::<O>::byte_combine(&y_t);
                index += 1;
            }
        }
    }
    res
}

fn em_enc_bkwd_mkey0_mtag1<O>(
    z: &GenericArray<Field<O>, O::L>,
    z_out: &GenericArray<Field<O>, O::LAMBDA>,
) -> Box<GenericArray<Field<O>, O::SENC>>
where
    O: OWFParameters,
{
    let mut res: Box<GenericArray<Field<O>, O::SENC>> = GenericArray::default_boxed();
    let mut index = 0;
    //Step 2
    for j in 0..O::R::USIZE {
        for c in 0..O::NST::USIZE {
            //Step 4
            for k in 0..4 {
                let mut icol = (c + O::NST::USIZE - k) % O::NST::USIZE;
                if O::NST::USIZE == 8 && k >= 2 {
                    icol = (icol + O::NST::USIZE - 1) % O::NST::USIZE;
                }
                let ird = O::LAMBDA::USIZE + 32 * O::NST::USIZE * j + 32 * icol + 8 * k;
                let z_t = if j < O::R::USIZE - 1 {
                    &z[ird..ird + 8]
                } else {
                    &z_out
                        [ird - 32 * O::NST::USIZE * (j + 1)..ird - 32 * O::NST::USIZE * (j + 1) + 8]
                };
                let y_t =
                    array::from_fn(|i| z_t[(i + 7) % 8] + z_t[(i + 5) % 8] + z_t[(i + 2) % 8]);
                res[index] = Field::<O>::byte_combine(&y_t);
                index += 1;
            }
        }
    }
    res
}

fn em_enc_bkwd_mkey1_mtag0<O>(
    x: &GenericArray<Field<O>, O::LAMBDAR1>,
    z: &GenericArray<Field<O>, O::L>,
    z_out: &GenericArray<Field<O>, O::LAMBDA>,
    delta: Field<O>,
) -> Box<GenericArray<Field<O>, O::SENC>>
where
    O: OWFParameters,
{
    let mut res: Box<GenericArray<Field<O>, O::SENC>> = GenericArray::default_boxed();
    let mut index = 0;
    //Step 2
    for j in 0..O::R::USIZE {
        for c in 0..O::NST::USIZE {
            //Step 4
            for k in 0..4 {
                let mut icol = (c + O::NST::USIZE - k) % O::NST::USIZE;
                if O::NST::USIZE == 8 && k >= 2 {
                    icol = (icol + O::NST::USIZE - 1) % O::NST::USIZE;
                }
                let ird = O::LAMBDA::USIZE + 32 * O::NST::USIZE * j + 32 * icol + 8 * k;
                let z_t: [_; 8] = if j < O::R::USIZE - 1 {
                    array::from_fn(|idx| z[ird + idx])
                } else {
                    let z_out_t = &z_out[ird - 32 * O::NST::USIZE * (j + 1)
                        ..ird - 32 * O::NST::USIZE * (j + 1) + 8];
                    array::from_fn(|idx| z_out_t[idx] + x[ird + idx])
                };
                let mut y_t =
                    array::from_fn(|i| z_t[(i + 7) % 8] + z_t[(i + 5) % 8] + z_t[(i + 2) % 8]);
                y_t[0] += delta;
                y_t[2] += delta;
                res[index] = Field::<O>::byte_combine(&y_t);
                index += 1;
            }
        }
    }
    res
}

fn em_enc_cstrnts_mkey0<O>(
    a_t_hasher: &mut impl ZKHasherProcess<Field<O>>,
    b_t_hasher: &mut impl ZKHasherProcess<Field<O>>,
    output: &GenericArray<u8, O::InputSize>,
    x: &GenericArray<u8, O::LAMBDAR1BYTE>,
    w: &GenericArray<u8, O::LBYTES>,
    v: &GenericArray<Field<O>, O::L>,
) where
    O: OWFParameters,
{
    let new_w = convert_to_bit::<Field<O>, O::L>(w);
    let new_x =
        convert_to_bit::<Field<O>, O::LAMBDAR1>(&x[..4 * O::NST::USIZE * (O::R::USIZE + 1)]);
    let mut w_out: Box<GenericArray<Field<O>, O::LAMBDA>> = GenericArray::default_boxed();
    let mut index = 0;
    for i in 0..O::LAMBDABYTES::USIZE {
        for j in 0..8 {
            w_out[index] = new_w[i * 8 + j] + ((output[i] >> j) & 1);
            index += 1;
        }
    }
    let v_out = GenericArray::from_slice(&v[..O::LAMBDA::USIZE]);
    let s = em_enc_fwd::<O>(
        Either::Left(w),
        Some(Either::Left(&x[..4 * O::NST::USIZE * (O::R::USIZE + 1)])),
    );
    let vs = em_enc_fwd::<O>(Either::Right(v), None);
    let s_b = em_enc_bkwd_mkey0_mtag0::<O>(&new_x, &new_w, &w_out);
    let v_s_b = em_enc_bkwd_mkey0_mtag1::<O>(v, v_out);
    for j in 0..O::SENC::USIZE {
        let a0 = v_s_b[j] * vs[j];
        let a1 = ((s[j] + vs[j]) * (s_b[j] + v_s_b[j])) + Field::<O>::ONE + a0;
        a_t_hasher.update(&a1);
        b_t_hasher.update(&a0);
    }
}

fn em_enc_cstrnts_mkey1<O>(
    b_t_hasher: &mut impl ZKHasherProcess<Field<O>>,
    output: &GenericArray<u8, O::InputSize>,
    x: &GenericArray<u8, O::LAMBDAR1BYTE>,
    q: &GenericArray<Field<O>, O::L>,
    delta: Field<O>,
) where
    O: OWFParameters,
{
    let new_x = Box::<GenericArray<Field<O>, O::LAMBDAR1>>::from_iter(
        (0..4 * O::NST::USIZE * (O::R::USIZE + 1) * 8)
            .map(|index| delta * ((x[index / 8] >> (index % 8)) & 1)),
    );

    let q_out = Box::<GenericArray<Field<O>, O::LAMBDA>>::from_iter(
        (0..O::LAMBDA::USIZE).map(|idx| delta * ((output[idx / 8] >> (idx % 8)) & 1) + q[idx]),
    );
    let qs = em_enc_fwd::<O>(Either::Right(q), Some(Either::Right(new_x.as_slice())));
    let qs_b = em_enc_bkwd_mkey1_mtag0::<O>(&new_x, q, &q_out, delta);
    let immut = delta * delta;

    zip(qs, qs_b).for_each(|(q, qb)| {
        let b = (q * qb) + immut;
        b_t_hasher.update(&b);
    });
}

///Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
pub(crate) fn em_prove<O>(
    w: &GenericArray<u8, O::LBYTES>,
    u: &GenericArray<u8, O::LAMBDALBYTES>,
    gv: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
    owf_input: &GenericArray<u8, O::InputSize>,
    owf_output: &GenericArray<u8, O::InputSize>,
    chall: &GenericArray<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>,
) -> QSProof<O>
where
    O: OWFParameters,
{
    let mut temp_v: Box<GenericArray<u8, O::LAMBDALBYTESLAMBDA>> = GenericArray::default_boxed();
    for i in 0..O::LBYTES::USIZE + O::LAMBDABYTES::USIZE {
        for k in 0..8 {
            for j in 0..O::LAMBDABYTES::USIZE {
                let mut temp = 0;
                for m in 0..8 {
                    temp += ((gv[(j * 8) + m][i] >> k) & 1) << m;
                }
                temp_v[j + k * O::LAMBDABYTES::USIZE + i * O::LAMBDA::USIZE] = temp;
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

    let x = rijndael_key_schedule(
        owf_input,
        O::NST::USIZE,
        O::NK::USIZE,
        O::R::USIZE,
        4 * (((O::R::USIZE + 1) * O::NST::USIZE) / O::NK::USIZE),
    );
    em_enc_cstrnts_mkey0::<O>(
        &mut a_t_hasher,
        &mut b_t_hasher,
        owf_output,
        &x.0.chunks(8)
            .flat_map(|x| {
                convert_from_batchblocks(inv_bitslice(x))
                    .iter()
                    .flat_map(|x| u32::to_le_bytes(*x))
                    .take(O::LAMBDABYTES::USIZE)
                    .collect::<Vec<u8>>()
            })
            .take(O::LAMBDABYTES::USIZE * (O::R::USIZE + 1))
            .collect::<GenericArray<u8, _>>(),
        w,
        GenericArray::from_slice(&new_v[..O::L::USIZE]),
    );
    let u_s = Field::<O>::from(&u[O::LBYTES::USIZE..]);
    let v_s = Field::<O>::sum_poly(&new_v[O::L::USIZE..O::L::USIZE + O::LAMBDA::USIZE]);
    let a_t = a_t_hasher.finalize(&u_s);
    let b_t = b_t_hasher.finalize(&v_s);

    (a_t.as_bytes(), b_t.as_bytes())
}

///Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
#[allow(clippy::too_many_arguments)]
pub(crate) fn em_verify<O, Tau>(
    d: &GenericArray<u8, O::LBYTES>,
    gq: Box<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>,
    a_t: &GenericArray<u8, O::LAMBDABYTES>,
    chall2: &GenericArray<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>,
    chall3: &GenericArray<u8, O::LAMBDABYTES>,
    owf_input: &GenericArray<u8, O::InputSize>,
    owf_output: &GenericArray<u8, O::InputSize>,
) -> GenericArray<u8, O::LAMBDABYTES>
where
    O: OWFParameters,
    Tau: TauParameters,
{
    let delta = Field::<O>::from(chall3);

    let new_q = convert_gq::<O, Tau>(d, gq, chall3);
    let mut zk_hasher =
        <<O as OWFParameters>::BaseParams as BaseParameters>::ZKHasher::new_zk_hasher(chall2);
    let x = rijndael_key_schedule(
        owf_input,
        O::NST::USIZE,
        O::NK::USIZE,
        O::R::USIZE,
        4 * (((O::R::USIZE + 1) * O::NST::USIZE) / O::NK::USIZE),
    );
    em_enc_cstrnts_mkey1::<O>(
        &mut zk_hasher,
        owf_output,
        &x.0.chunks(8)
            .flat_map(|x| {
                convert_from_batchblocks(inv_bitslice(x))
                    .iter()
                    .flat_map(|x| u32::to_le_bytes(*x))
                    .take(O::LAMBDABYTES::USIZE)
                    .collect::<Vec<_>>()
            })
            .take(O::LAMBDABYTES::USIZE * (O::R::USIZE + 1))
            .collect::<GenericArray<u8, _>>(),
        GenericArray::from_slice(&new_q[..O::L::USIZE]),
        delta,
    );

    let q_s = Field::<O>::sum_poly(&new_q[O::L::USIZE..O::L::USIZE + O::LAMBDA::USIZE]);
    (zk_hasher.finalize(&q_s) + Field::<O>::from(a_t) * delta).as_bytes()
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        aes::convert_to_bit,
        fields::{large_fields::NewFromU128, GF128, GF192, GF256},
        parameter::{
            FAESTEM128fParameters, FAESTEM128sParameters, FAESTEM192fParameters,
            FAESTEM192sParameters, FAESTEM256fParameters, FAESTEM256sParameters, FAESTParameters,
            OWF128EM, OWF192EM, OWF256EM,
        },
    };

    use generic_array::{typenum::U8, GenericArray};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EmExtendedWitness {
        lambda: u16,
        key: Vec<u8>,
        input: Vec<u8>,
        w: Vec<u8>,
    }

    #[test]
    fn em_extended_witness_test() {
        let database: Vec<EmExtendedWitness> =
            serde_json::from_str(include_str!("../tests/data/EM-ExtendedWitness.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let res = em_extendedwitness::<OWF128EM>(
                    GenericArray::from_slice(&data.key),
                    GenericArray::from_slice(
                        &data.input[..<OWF128EM as OWFParameters>::InputSize::USIZE],
                    ),
                );
                assert_eq!(res.0, Box::new(*GenericArray::from_slice(&data.w)));
            } else if data.lambda == 192 {
                let res = em_extendedwitness::<OWF192EM>(
                    GenericArray::from_slice(&data.key),
                    GenericArray::from_slice(
                        &data.input[..<OWF192EM as OWFParameters>::InputSize::USIZE],
                    ),
                );
                assert_eq!(res.0, Box::new(*GenericArray::from_slice(&data.w)));
            } else {
                let res = em_extendedwitness::<OWF256EM>(
                    GenericArray::from_slice(&data.key),
                    GenericArray::from_slice(
                        &data.input[..<OWF256EM as OWFParameters>::InputSize::USIZE],
                    ),
                );
                assert_eq!(res.0, Box::new(*GenericArray::from_slice(&data.w)));
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EmEncFwd {
        lambda: u16,
        m: u8,
        x: Vec<[u64; 4]>,
        z: Vec<[u64; 4]>,
        res: Vec<[u64; 4]>,
    }

    #[test]
    fn em_enc_fwd_test() {
        let database: Vec<EmEncFwd> =
            serde_json::from_str(include_str!("../tests/data/EmEncFwd.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let (input_x, input_z): (Vec<GF128>, Vec<GF128>) = if data.m == 1 {
                    (
                        data.x
                            .iter()
                            .flat_map(|x| convert_to_bit::<GF128, U8>(&x[0].to_le_bytes()[..1]))
                            .collect(),
                        data.z
                            .iter()
                            .flat_map(|z| convert_to_bit::<GF128, U8>(&z[0].to_le_bytes()[..1]))
                            .collect(),
                    )
                } else {
                    (
                        data.x
                            .iter()
                            .map(|x| GF128::new(x[0] as u128 + ((x[1] as u128) << 64), 0))
                            .collect(),
                        data.z
                            .iter()
                            .map(|z| GF128::new(z[0] as u128 + ((z[1] as u128) << 64), 0))
                            .collect(),
                    )
                };
                let res =
                    em_enc_fwd::<OWF128EM>(Either::Right(&input_z), Some(Either::Right(&input_x)));
                assert_eq!(
                    res,
                    Box::new(*GenericArray::from_slice(
                        &data
                            .res
                            .iter()
                            .map(|z| GF128::new(z[0] as u128 + ((z[1] as u128) << 64), 0))
                            .collect::<Vec<GF128>>()
                    ))
                )
            } else if data.lambda == 192 {
                let (input_x, input_z): (Vec<GF192>, Vec<GF192>) = if data.m == 1 {
                    (
                        data.x
                            .iter()
                            .flat_map(|x| convert_to_bit::<GF192, U8>(&x[0].to_le_bytes()[..1]))
                            .collect(),
                        data.z
                            .iter()
                            .flat_map(|z| convert_to_bit::<GF192, U8>(&z[0].to_le_bytes()[..1]))
                            .collect(),
                    )
                } else {
                    (
                        data.x
                            .iter()
                            .map(|x| {
                                GF192::new(x[0] as u128 + ((x[1] as u128) << 64), x[2] as u128)
                            })
                            .collect(),
                        data.z
                            .iter()
                            .map(|z| {
                                GF192::new(z[0] as u128 + ((z[1] as u128) << 64), z[2] as u128)
                            })
                            .collect(),
                    )
                };
                let res =
                    em_enc_fwd::<OWF192EM>(Either::Right(&input_z), Some(Either::Right(&input_x)));
                assert_eq!(
                    res,
                    Box::new(*GenericArray::from_slice(
                        &data
                            .res
                            .iter()
                            .map(|z| GF192::new(
                                z[0] as u128 + ((z[1] as u128) << 64),
                                z[2] as u128
                            ))
                            .collect::<Vec<GF192>>()
                    ))
                )
            } else {
                let (input_x, input_z): (Vec<GF256>, Vec<GF256>) = if data.m == 1 {
                    (
                        data.x
                            .iter()
                            .flat_map(|x| convert_to_bit::<GF256, U8>(&x[0].to_le_bytes()[..1]))
                            .collect(),
                        data.z
                            .iter()
                            .flat_map(|z| convert_to_bit::<GF256, U8>(&z[0].to_le_bytes()[..1]))
                            .collect(),
                    )
                } else {
                    (
                        data.x
                            .iter()
                            .map(|x| {
                                GF256::new(
                                    x[0] as u128 + ((x[1] as u128) << 64),
                                    x[2] as u128 + ((x[3] as u128) << 64),
                                )
                            })
                            .collect(),
                        data.z
                            .iter()
                            .map(|z| {
                                GF256::new(
                                    z[0] as u128 + ((z[1] as u128) << 64),
                                    z[2] as u128 + ((z[3] as u128) << 64),
                                )
                            })
                            .collect(),
                    )
                };
                let res =
                    em_enc_fwd::<OWF256EM>(Either::Right(&input_z), Some(Either::Right(&input_x)));
                assert_eq!(
                    res,
                    Box::new(*GenericArray::from_slice(
                        &data
                            .res
                            .iter()
                            .map(|z| GF256::new(
                                z[0] as u128 + ((z[1] as u128) << 64),
                                z[2] as u128 + ((z[3] as u128) << 64)
                            ))
                            .collect::<Vec<GF256>>()
                    ))
                )
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EmEncBkwd {
        lambda: u16,
        m: u8,
        x: Vec<[u64; 4]>,
        z: Vec<[u64; 4]>,
        zout: Vec<[u64; 4]>,
        mtag: u8,
        mkey: u8,
        delta: Vec<u8>,
        res: Vec<[u64; 4]>,
    }

    fn em_enc_bkwd<O>(
        x: &GenericArray<Field<O>, O::LAMBDAR1>,
        z: &GenericArray<Field<O>, O::L>,
        z_out: &GenericArray<Field<O>, O::LAMBDA>,
        mkey: bool,
        mtag: bool,
        delta: Field<O>,
    ) -> Box<GenericArray<Field<O>, O::SENC>>
    where
        O: OWFParameters,
    {
        match (mkey, mtag) {
            (false, false) => em_enc_bkwd_mkey0_mtag0::<O>(x, z, z_out),
            (true, false) => em_enc_bkwd_mkey1_mtag0::<O>(x, z, z_out, delta),
            (false, true) => em_enc_bkwd_mkey0_mtag1::<O>(z, z_out),
            _ => {
                unreachable!();
            }
        }
    }

    #[test]
    fn em_enc_bkwd_test() {
        let database: Vec<EmEncBkwd> =
            serde_json::from_str(include_str!("../tests/data/EmEncBkwd.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let (x_in, z_in, z_out_in) = if data.m == 1 {
                    (
                        data.x
                            .iter()
                            .flat_map(|x| convert_to_bit::<GF128, U8>(&x[0].to_le_bytes()[..1]))
                            .collect::<Vec<GF128>>(),
                        data.z
                            .iter()
                            .flat_map(|z| convert_to_bit::<GF128, U8>(&z[0].to_le_bytes()[..1]))
                            .collect::<Vec<GF128>>(),
                        data.zout
                            .iter()
                            .flat_map(|z| convert_to_bit::<GF128, U8>(&z[0].to_le_bytes()[..1]))
                            .collect::<Vec<GF128>>(),
                    )
                } else {
                    (
                        data.x
                            .iter()
                            .map(|x| GF128::new(x[0] as u128 + ((x[1] as u128) << 64), 0))
                            .collect::<Vec<GF128>>(),
                        data.z
                            .iter()
                            .map(|z| GF128::new(z[0] as u128 + ((z[1] as u128) << 64), 0))
                            .collect::<Vec<GF128>>(),
                        data.zout
                            .iter()
                            .map(|z| GF128::new(z[0] as u128 + ((z[1] as u128) << 64), 0))
                            .collect::<Vec<GF128>>(),
                    )
                };
                let res = em_enc_bkwd::<OWF128EM>(
                    GenericArray::from_slice(&x_in),
                    GenericArray::from_slice(&z_in),
                    GenericArray::from_slice(&z_out_in),
                    data.mkey != 0,
                    data.mtag != 0,
                    GF128::from(&data.delta[..]),
                );
                assert_eq!(
                    res,
                    Box::new(*GenericArray::from_slice(
                        &data
                            .res
                            .iter()
                            .map(|z| GF128::new(z[0] as u128 + ((z[1] as u128) << 64), 0))
                            .collect::<Vec<GF128>>()
                    ))
                )
            } else if data.lambda == 192 {
                let (x_in, z_in, z_out_in) = if data.m == 1 {
                    (
                        data.x
                            .iter()
                            .flat_map(|x| convert_to_bit::<GF192, U8>(&x[0].to_le_bytes()[..1]))
                            .collect::<Vec<GF192>>(),
                        data.z
                            .iter()
                            .flat_map(|z| convert_to_bit::<GF192, U8>(&z[0].to_le_bytes()[..1]))
                            .collect::<Vec<GF192>>(),
                        data.zout
                            .iter()
                            .flat_map(|z| convert_to_bit::<GF192, U8>(&z[0].to_le_bytes()[..1]))
                            .collect::<Vec<GF192>>(),
                    )
                } else {
                    (
                        data.x
                            .iter()
                            .map(|x| {
                                GF192::new(x[0] as u128 + ((x[1] as u128) << 64), x[2] as u128)
                            })
                            .collect(),
                        data.z
                            .iter()
                            .map(|z| {
                                GF192::new(z[0] as u128 + ((z[1] as u128) << 64), z[2] as u128)
                            })
                            .collect(),
                        data.zout
                            .iter()
                            .map(|z| {
                                GF192::new(z[0] as u128 + ((z[1] as u128) << 64), z[2] as u128)
                            })
                            .collect(),
                    )
                };
                let res = em_enc_bkwd::<OWF192EM>(
                    GenericArray::from_slice(&x_in),
                    GenericArray::from_slice(&z_in),
                    GenericArray::from_slice(&z_out_in),
                    data.mkey != 0,
                    data.mtag != 0,
                    GF192::from(&data.delta[..]),
                );
                assert_eq!(
                    res,
                    Box::new(*GenericArray::from_slice(
                        &data
                            .res
                            .iter()
                            .map(|z| GF192::new(
                                z[0] as u128 + ((z[1] as u128) << 64),
                                z[2] as u128
                            ))
                            .collect::<Vec<GF192>>()
                    ))
                )
            } else {
                let (x_in, z_in, z_out_in) = if data.m == 1 {
                    (
                        data.x
                            .iter()
                            .flat_map(|x| convert_to_bit::<GF256, U8>(&x[0].to_le_bytes()[..1]))
                            .collect::<Vec<GF256>>(),
                        data.z
                            .iter()
                            .flat_map(|z| convert_to_bit::<GF256, U8>(&z[0].to_le_bytes()[..1]))
                            .collect::<Vec<GF256>>(),
                        data.zout
                            .iter()
                            .flat_map(|z| convert_to_bit::<GF256, U8>(&z[0].to_le_bytes()[..1]))
                            .collect::<Vec<GF256>>(),
                    )
                } else {
                    (
                        data.x
                            .iter()
                            .map(|x| {
                                GF256::new(
                                    x[0] as u128 + ((x[1] as u128) << 64),
                                    x[2] as u128 + ((x[3] as u128) << 64),
                                )
                            })
                            .collect(),
                        data.z
                            .iter()
                            .map(|z| {
                                GF256::new(
                                    z[0] as u128 + ((z[1] as u128) << 64),
                                    z[2] as u128 + ((z[3] as u128) << 64),
                                )
                            })
                            .collect(),
                        data.zout
                            .iter()
                            .map(|z| {
                                GF256::new(
                                    z[0] as u128 + ((z[1] as u128) << 64),
                                    z[2] as u128 + ((z[3] as u128) << 64),
                                )
                            })
                            .collect(),
                    )
                };
                let res = em_enc_bkwd::<OWF256EM>(
                    GenericArray::from_slice(&x_in),
                    GenericArray::from_slice(&z_in),
                    GenericArray::from_slice(&z_out_in),
                    data.mkey != 0,
                    data.mtag != 0,
                    GF256::from(&data.delta[..]),
                );
                assert_eq!(
                    res,
                    Box::new(*GenericArray::from_slice(
                        &data
                            .res
                            .iter()
                            .map(|z| GF256::new(
                                z[0] as u128 + ((z[1] as u128) << 64),
                                z[2] as u128 + ((z[3] as u128) << 64)
                            ))
                            .collect::<Vec<GF256>>()
                    ))
                )
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EmProve {
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
    fn em_prove_test() {
        let database: Vec<EmProve> =
            serde_json::from_str(include_str!("../tests/data/EmProve.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let res = em_prove::<OWF128EM>(
                    GenericArray::from_slice(&data.w),
                    GenericArray::from_slice(&[[0u8; 160].to_vec(), data.u].concat()),
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
                assert_eq!(
                    (
                        *GenericArray::from_slice(&data.at),
                        *GenericArray::from_slice(&data.bt)
                    ),
                    res
                );
                break;
            } else if data.lambda == 192 {
                let res = em_prove::<OWF192EM>(
                    GenericArray::from_slice(&data.w),
                    GenericArray::from_slice(&[[0u8; 288].to_vec(), data.u].concat()),
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
                assert_eq!(
                    (
                        *GenericArray::from_slice(&data.at),
                        *GenericArray::from_slice(&data.bt)
                    ),
                    res
                );
            } else {
                let res = em_prove::<OWF256EM>(
                    GenericArray::from_slice(&data.w),
                    GenericArray::from_slice(&([[0u8; 448].to_vec(), data.u].concat()).to_vec()),
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
                assert_eq!(
                    (
                        *GenericArray::from_slice(&data.at),
                        *GenericArray::from_slice(&data.bt)
                    ),
                    res
                );
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EmVerify {
        lambda: u16,

        tau: u8,

        d: Vec<u8>,

        gq: Vec<Vec<u8>>,

        at: Vec<u8>,

        chall2: Vec<u8>,

        chall3: Vec<u8>,

        input: Vec<u8>,

        output: Vec<u8>,

        qt: Vec<u8>,
    }

    fn em_verify<O, Tau>(
        d: &GenericArray<u8, O::LBYTES>,
        gq: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        a_t: &GenericArray<u8, O::LAMBDABYTES>,
        chall2: &GenericArray<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>,
        chall3: &GenericArray<u8, O::LAMBDABYTES>,
        owf_input: &GenericArray<u8, O::InputSize>,
        owf_output: &GenericArray<u8, O::InputSize>,
    ) -> GenericArray<u8, O::LAMBDABYTES>
    where
        O: OWFParameters,
        Tau: TauParameters,
    {
        super::em_verify::<O, Tau>(
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
    fn em_verify_test() {
        let database: Vec<EmVerify> =
            serde_json::from_str(include_str!("../tests/data/EmVerify.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let res = if data.tau == 11 {
                    em_verify::<OWF128EM, <FAESTEM128sParameters as FAESTParameters>::Tau>(
                        GenericArray::from_slice(&data.d),
                        GenericArray::from_slice(
                            &data
                                .gq
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>(),
                        ),
                        GenericArray::from_slice(&data.at),
                        GenericArray::from_slice(&data.chall2),
                        GenericArray::from_slice(&data.chall3),
                        GenericArray::from_slice(&data.input),
                        GenericArray::from_slice(&data.output),
                    )
                } else {
                    em_verify::<OWF128EM, <FAESTEM128fParameters as FAESTParameters>::Tau>(
                        GenericArray::from_slice(&data.d),
                        GenericArray::from_slice(
                            &data
                                .gq
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>(),
                        ),
                        GenericArray::from_slice(&data.at),
                        GenericArray::from_slice(&data.chall2),
                        GenericArray::from_slice(&data.chall3),
                        GenericArray::from_slice(&data.input),
                        GenericArray::from_slice(&data.output),
                    )
                };
                assert_eq!(res, *GenericArray::from_slice(&data.qt));
            } else if data.lambda == 192 {
                let res = if data.tau == 16 {
                    em_verify::<OWF192EM, <FAESTEM192sParameters as FAESTParameters>::Tau>(
                        GenericArray::from_slice(&data.d),
                        GenericArray::from_slice(
                            &data
                                .gq
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>(),
                        ),
                        GenericArray::from_slice(&data.at),
                        GenericArray::from_slice(&data.chall2),
                        GenericArray::from_slice(&data.chall3),
                        GenericArray::from_slice(&data.input),
                        GenericArray::from_slice(&data.output),
                    )
                } else {
                    em_verify::<OWF192EM, <FAESTEM192fParameters as FAESTParameters>::Tau>(
                        GenericArray::from_slice(&data.d),
                        GenericArray::from_slice(
                            &data
                                .gq
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>(),
                        ),
                        GenericArray::from_slice(&data.at),
                        GenericArray::from_slice(&data.chall2),
                        GenericArray::from_slice(&data.chall3),
                        GenericArray::from_slice(&data.input),
                        GenericArray::from_slice(&data.output),
                    )
                };
                assert_eq!(res, *GenericArray::from_slice(&data.qt));
            } else {
                let res = if data.tau == 22 {
                    em_verify::<OWF256EM, <FAESTEM256sParameters as FAESTParameters>::Tau>(
                        GenericArray::from_slice(&data.d),
                        GenericArray::from_slice(
                            &data
                                .gq
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>(),
                        ),
                        GenericArray::from_slice(&data.at),
                        GenericArray::from_slice(&data.chall2),
                        GenericArray::from_slice(&data.chall3),
                        GenericArray::from_slice(&data.input),
                        GenericArray::from_slice(&data.output),
                    )
                } else {
                    em_verify::<OWF256EM, <FAESTEM256fParameters as FAESTParameters>::Tau>(
                        GenericArray::from_slice(&data.d),
                        GenericArray::from_slice(
                            &data
                                .gq
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>(),
                        ),
                        GenericArray::from_slice(&data.at),
                        GenericArray::from_slice(&data.chall2),
                        GenericArray::from_slice(&data.chall3),
                        GenericArray::from_slice(&data.input),
                        GenericArray::from_slice(&data.output),
                    )
                };
                assert_eq!(res, *GenericArray::from_slice(&data.qt));
            }
        }
    }
}
