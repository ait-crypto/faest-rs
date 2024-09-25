use std::iter::zip;

use generic_array::{typenum::Unsigned, GenericArray};

use crate::{
    aes::convert_to_bit,
    fields::{ByteCombine, ByteCombineConstants, Field, SumPoly},
    parameter::{BaseParameters, QSProof, TauParameters, PARAM, PARAMOWF},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, sub_bytes, sub_bytes_nots, State,
    },
    universal_hashing::{ZKHasherInit, ZKHasherProcess},
};

type Reveal<O> = (
    Box<GenericArray<<O as PARAMOWF>::Field, <O as PARAMOWF>::C>>,
    Box<GenericArray<<O as PARAMOWF>::Field, <O as PARAMOWF>::C>>,
);

pub(crate) fn em_extendedwitness<O>(
    owf_key: &GenericArray<u8, O::LAMBDABYTES>,
    owf_input: &GenericArray<u8, O::InputSize>,
) -> (Box<GenericArray<u8, O::LBYTES>>, bool)
where
    O: PARAMOWF,
{
    let mut valid = true;
    let lambda = <O::LAMBDA as Unsigned>::to_usize() / 8;
    let nst = <O::NST as Unsigned>::to_usize();
    let r = <O::R as Unsigned>::to_usize();
    let kc = <O::NK as Unsigned>::to_u8();
    let mut res: Box<GenericArray<u8, O::LBYTES>> = GenericArray::default_boxed();
    let mut index = 0;
    let x = rijndael_key_schedule(
        &owf_input[..lambda],
        nst as u8,
        kc,
        r as u8,
        (4 * (((r + 1) * nst) / kc as usize)) as u8,
    );
    for i in owf_key.iter() {
        res[index] = *i;
        index += 1;
    }
    let mut state = State::default();
    bitslice(
        &mut state,
        &owf_key[..16],
        &[owf_key[16..].to_vec(), vec![0u8; 32 - lambda]].concat(),
    );
    rijndael_add_round_key(&mut state, &x.0[..8]);
    for j in 1..r {
        for i in inv_bitslice(&state)[0][..].iter() {
            valid &= *i != 0;
        }
        if nst == 6 {
            for i in inv_bitslice(&state)[1][..8].iter() {
                valid &= *i != 0;
            }
        } else if nst == 8 {
            for i in inv_bitslice(&state)[1][..].iter() {
                valid &= *i != 0;
            }
        }
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);
        rijndael_shift_rows_1(&mut state, nst as u8);
        for i in convert_from_batchblocks(inv_bitslice(&state))[..kc as usize][..kc as usize]
            .to_vec()
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<u8>>()
        {
            res[index] = i;
            index += 1;
        }
        mix_columns_0(&mut state);
        rijndael_add_round_key(&mut state, &x.0[8 * j..8 * (j + 1)]);
    }
    for i in inv_bitslice(&state)[0][..].iter() {
        valid &= *i != 0;
    }
    if nst == 6 {
        for i in inv_bitslice(&state)[1][..8].iter() {
            valid &= *i != 0;
        }
    } else if nst == 8 {
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
    z: &GenericArray<O::Field, O::L>,
    x: &GenericArray<O::Field, O::LAMBDAR1>,
) -> Box<GenericArray<O::Field, O::SENC>>
where
    O: PARAMOWF,
{
    let mut res = GenericArray::default_boxed();
    let mut index = 0;
    let nst = <O::NST as Unsigned>::to_usize();
    //Step 2-3
    for j in 0..4 * nst {
        res[index] = O::Field::byte_combine(z[8 * j..8 * (j + 1)].try_into().unwrap())
            + O::Field::byte_combine(x[8 * j..8 * (j + 1)].try_into().unwrap());
        index += 1;
    }
    //Step 4
    for j in 1..<O::R as Unsigned>::to_usize() {
        for c in 0..nst {
            let i: usize = 32 * nst * j + 32 * c;
            let mut z_hat = [O::Field::default(); 4];
            let mut x_hat = [O::Field::default(); 4];
            for r in 0..4 {
                z_hat[r] = O::Field::byte_combine(z[i + 8 * r..i + 8 * r + 8].try_into().unwrap());
                x_hat[r] = O::Field::byte_combine(x[i + 8 * r..i + 8 * r + 8].try_into().unwrap());
            }

            //Step 16
            res[index] = z_hat[0] * O::Field::BYTE_COMBINE_2  + z_hat[1] * O::Field::BYTE_COMBINE_3  + z_hat[2] /* * a */ + z_hat[3] /* * a */ + x_hat[0];
            res[index + 1] = z_hat[0] /* * a */ + z_hat[1] * O::Field::BYTE_COMBINE_2  + z_hat[2] * O::Field::BYTE_COMBINE_3  + z_hat[3] /* * a */ + x_hat[1];
            res[index + 2] = z_hat[0] /* * a */ + z_hat[1] /* * a */ + z_hat[2] * O::Field::BYTE_COMBINE_2  + z_hat[3] * O::Field::BYTE_COMBINE_3  + x_hat[2];
            res[index + 3] = z_hat[0] * O::Field::BYTE_COMBINE_3  + z_hat[1] /* * a */ + z_hat[2] /* * a */ + z_hat[3] * O::Field::BYTE_COMBINE_2  + x_hat[3];
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
#[allow(clippy::too_many_arguments)]
fn em_enc_bkwd<P, O>(
    x: &GenericArray<O::Field, O::LAMBDAR1>,
    z: &GenericArray<O::Field, O::L>,
    z_out: &GenericArray<O::Field, O::LAMBDA>,
    mkey: bool,
    mtag: bool,
    delta: O::Field,
) -> Box<GenericArray<O::Field, O::SENC>>
where
    P: PARAM<OWF = O>,
    O: PARAMOWF,
{
    let mut res: Box<GenericArray<O::Field, O::SENC>> = GenericArray::default_boxed();
    let mut index = 0;
    let r = <O::R as Unsigned>::to_usize();
    let nst = <O::NST as Unsigned>::to_usize();
    let lambda = <P::LAMBDA as Unsigned>::to_usize();
    let immut = if !mtag {
        if mkey {
            delta
        } else {
            O::Field::ONE
        }
    } else {
        O::Field::default()
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
                        .collect::<Vec<_>>()
                };
                let mut y_t = [O::Field::default(); 8];
                for i in 0..8 {
                    y_t[i] = z_t[(i + 7) % 8] + z_t[(i + 5) % 8] + z_t[(i + 2) % 8]
                }
                y_t[0] += immut;
                y_t[2] += immut;
                res[index] = O::Field::byte_combine(&y_t);
                index += 1;
            }
        }
    }
    res
}

#[allow(clippy::too_many_arguments)]
fn em_enc_cstrnts<P, O>(
    output: &GenericArray<u8, O::OutputSize>,
    x: &GenericArray<u8, O::LAMBDAR1BYTE>,
    w: &GenericArray<u8, O::LBYTES>,
    v: &GenericArray<O::Field, O::L>,
    q: &GenericArray<O::Field, O::L>,
    mkey: bool,
    delta: O::Field,
) -> Reveal<O>
where
    P: PARAM<OWF = O>,
    O: PARAMOWF,
{
    let lambda = <P::LAMBDA as Unsigned>::to_usize();
    let senc = <O::SENC as Unsigned>::to_usize();
    let nst = <O::NST as Unsigned>::to_usize();
    let r = <O::R as Unsigned>::to_usize();
    if !mkey {
        let new_w = convert_to_bit::<O::Field, O::L>(w);
        let new_x = convert_to_bit::<O::Field, O::LAMBDAR1>(&x[..4 * nst * (r + 1)]);
        let mut w_out: Box<GenericArray<O::Field, O::LAMBDA>> = GenericArray::default_boxed();
        let mut index = 0;
        for i in 0..lambda / 8 {
            for j in 0..8 {
                w_out[index] = O::Field::ONE * ((output[i] >> j) & 1) + new_w[i * 8 + j];
                index += 1;
            }
        }
        let v_out = GenericArray::from_slice(&v[..lambda]);
        let s = em_enc_fwd::<O>(&new_w, &new_x);
        let vs = em_enc_fwd::<O>(v, &GenericArray::default());
        let s_b = em_enc_bkwd::<P, O>(&new_x, &new_w, &w_out, false, false, O::Field::default());
        let v_s_b = em_enc_bkwd::<P, O>(
            &GenericArray::default_boxed(),
            v,
            v_out,
            false,
            true,
            O::Field::default(),
        );
        let (mut a0, mut a1): Reveal<O> =
            (GenericArray::default_boxed(), GenericArray::default_boxed());
        for j in 0..senc {
            a0[j] = v_s_b[j] * vs[j];
            a1[j] = ((s[j] + vs[j]) * (s_b[j] + v_s_b[j])) + O::Field::ONE + a0[j];
        }
        (a0, a1)
    } else {
        let new_output = convert_to_bit::<O::Field, O::LAMBDA>(output);
        let mut new_x: Box<GenericArray<O::Field, O::LAMBDAR1>> = GenericArray::default_boxed();
        let mut index = 0;
        for byte in x.iter().take(4 * nst * (r + 1)) {
            for j in 0..8 {
                new_x[index] = delta * ((byte >> j) & 1);
                index += 1;
            }
        }
        let mut q_out: Box<GenericArray<O::Field, O::LAMBDA>> = GenericArray::default_boxed();
        for i in 0..lambda {
            q_out[i] = new_output[i] * delta + q[i];
        }
        let qs = em_enc_fwd::<O>(q, &new_x);
        let qs_b = em_enc_bkwd::<P, O>(&new_x, q, &q_out, true, false, delta);
        let immut = delta * delta;

        let b = zip(qs, qs_b).map(|(q, qb)| (q * qb) + immut).collect();
        (b, GenericArray::default_boxed())
    }
}

///Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
pub(crate) fn em_prove<P, O>(
    w: &GenericArray<u8, O::LBYTES>,
    u: &GenericArray<u8, O::LAMBDALBYTES>,
    gv: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
    owf_input: &GenericArray<u8, O::InputSize>,
    owf_output: &GenericArray<u8, O::OutputSize>,
    chall: &GenericArray<u8, O::CHALL>,
) -> QSProof<O>
where
    P: PARAM<OWF = O>,
    O: PARAMOWF,
{
    let nst = <O::NST as Unsigned>::to_u8();
    let nk = <O::NK as Unsigned>::to_u8();
    let r = <O::R as Unsigned>::to_u8();
    let l = <O::L as Unsigned>::to_usize();
    let lambda = <P::LAMBDA as Unsigned>::to_usize();
    let mut temp_v: Box<GenericArray<u8, O::LAMBDALBYTESLAMBDA>> = GenericArray::default_boxed();
    for i in 0..(l + lambda) / 8 {
        for k in 0..8 {
            for j in 0..lambda / 8 {
                let mut temp = 0;
                for m in 0..8 {
                    temp += ((gv[(j * 8) + m][i] >> k) & 1) << m;
                }
                temp_v[j + k * lambda / 8 + i * lambda] = temp;
            }
        }
    }
    let new_v = GenericArray::<O::Field, O::LAMBDAL>::from_iter(
        temp_v.chunks(O::LAMBDABYTES::USIZE).map(O::Field::from),
    );
    let x = rijndael_key_schedule(owf_input, nst, nk, r, 4 * (((r + 1) * nst) / nk));
    let (a0, a1) = em_enc_cstrnts::<P, O>(
        owf_output,
        &x.0.chunks(8)
            .flat_map(|x| {
                convert_from_batchblocks(inv_bitslice(x))
                    .iter()
                    .flat_map(|x| u32::to_le_bytes(*x))
                    .take(lambda / 8)
                    .collect::<Vec<u8>>()
            })
            .take((lambda / 8) * (r as usize + 1))
            .collect::<GenericArray<u8, _>>(),
        w,
        GenericArray::from_slice(&new_v[..l]),
        &GenericArray::default_boxed(),
        false,
        O::Field::default(),
    );
    let u_s = O::Field::from(&u[l / 8..]);
    let v_s = O::Field::sum_poly(&new_v[l..l + lambda]);

    let mut a_t_hasher =
        <<O as PARAMOWF>::BaseParams as BaseParameters>::ZKHasher::new_zk_hasher(chall);
    let mut b_t_hasher =
        <<O as PARAMOWF>::BaseParams as BaseParameters>::ZKHasher::new_zk_hasher(chall);

    a1.into_iter().for_each(|value| a_t_hasher.update(&value));
    a0.into_iter().for_each(|value| b_t_hasher.update(&value));

    let a_t = a_t_hasher.finalize(&u_s);
    let b_t = b_t_hasher.finalize(&v_s);

    (a_t.as_bytes(), b_t.as_bytes())
}

///Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
#[allow(clippy::too_many_arguments)]
pub(crate) fn em_verify<P, O>(
    d: &GenericArray<u8, O::LBYTES>,
    gq: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
    a_t: &GenericArray<u8, O::LAMBDABYTES>,
    chall2: &GenericArray<u8, O::CHALL>,
    chall3: &GenericArray<u8, P::LAMBDABYTES>,
    owf_input: &GenericArray<u8, O::InputSize>,
    owf_output: &GenericArray<u8, O::OutputSize>,
) -> GenericArray<u8, O::LAMBDABYTES>
where
    P: PARAM<OWF = O>,
    O: PARAMOWF,
{
    let lambda = <P::LAMBDA as Unsigned>::to_usize();
    let l = <O::L as Unsigned>::to_usize();
    let delta = O::Field::from(chall3);
    let nst = <O::NST as Unsigned>::to_u8();
    let nk = <O::NK as Unsigned>::to_u8();
    let r = <O::R as Unsigned>::to_u8();

    let mut new_gq: GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA> = gq.clone();
    for i in 0..<P::Tau as TauParameters>::Tau0::USIZE {
        let sdelta = P::Tau::decode_challenge(chall3, i);
        for j in 0..<P::Tau as TauParameters>::K0::USIZE {
            if sdelta[j] != 0 {
                for (k, _) in d.iter().enumerate() {
                    new_gq[<P::Tau as TauParameters>::K0::USIZE * i + j][k] =
                        gq[<P::Tau as TauParameters>::K0::USIZE * i + j][k] ^ d[k];
                }
            }
        }
    }
    for i in 0..<P::Tau as TauParameters>::Tau1::USIZE {
        let sdelta = P::Tau::decode_challenge(chall3, <P::Tau as TauParameters>::Tau0::USIZE + i);
        for j in 0..<P::Tau as TauParameters>::K1::USIZE {
            if sdelta[j] != 0 {
                for (k, _) in d.iter().enumerate().take(l / 8) {
                    new_gq[<P::Tau as TauParameters>::Tau0::USIZE
                        * <P::Tau as TauParameters>::K0::USIZE
                        + <P::Tau as TauParameters>::K1::USIZE * i
                        + j][k] = gq[<P::Tau as TauParameters>::Tau0::USIZE
                        * <P::Tau as TauParameters>::K0::USIZE
                        + <P::Tau as TauParameters>::K1::USIZE * i
                        + j][k]
                        ^ d[k];
                }
            }
        }
    }
    let mut temp_q: Box<GenericArray<u8, O::LAMBDALBYTESLAMBDA>> = GenericArray::default_boxed();
    for i in 0..(l + lambda) / 8 {
        for k in 0..8 {
            for j in 0..lambda / 8 {
                let mut temp = 0;
                for l in 0..8_usize {
                    temp += ((new_gq[(j * 8) + l][i] >> k) & 1) << l;
                }
                temp_q[j + k * (lambda / 8) + i * lambda] = temp;
            }
        }
    }
    let new_q = GenericArray::<O::Field, O::LAMBDAL>::from_iter(
        temp_q.chunks(O::LAMBDABYTES::USIZE).map(O::Field::from),
    );
    let x = rijndael_key_schedule(owf_input, nst, nk, r, 4 * (((r + 1) * nst) / nk));
    let (b, _) = em_enc_cstrnts::<P, O>(
        owf_output,
        &x.0.chunks(8)
            .flat_map(|x| {
                convert_from_batchblocks(inv_bitslice(x))
                    .iter()
                    .flat_map(|x| u32::to_le_bytes(*x))
                    .take(lambda / 8)
                    .collect::<Vec<u8>>()
            })
            .take((lambda / 8) * (r as usize + 1))
            .collect::<GenericArray<u8, _>>(),
        &GenericArray::default_boxed(),
        &GenericArray::default_boxed(),
        GenericArray::from_slice(&new_q[..l]),
        true,
        delta,
    );

    let mut zk_hasher =
        <<O as PARAMOWF>::BaseParams as BaseParameters>::ZKHasher::new_zk_hasher(chall2);
    b.into_iter().for_each(|value| zk_hasher.update(&value));

    let q_s = O::Field::sum_poly(&new_q[l..l + lambda]);
    (zk_hasher.finalize(&q_s) + O::Field::from(a_t) * delta).as_bytes()
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        aes::convert_to_bit,
        fields::{large_fields::NewFromU128, GF128, GF192, GF256},
        parameter::{
            PARAM128FEM, PARAM128SEM, PARAM192FEM, PARAM192SEM, PARAM256FEM, PARAM256SEM,
            PARAMOWF128, PARAMOWF128EM, PARAMOWF192EM, PARAMOWF256EM,
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
                let res = em_extendedwitness::<PARAMOWF128EM>(
                    GenericArray::from_slice(&data.key),
                    GenericArray::from_slice(
                        &data.input[..<PARAMOWF128EM as PARAMOWF>::InputSize::USIZE],
                    ),
                );
                assert_eq!(res.0, Box::new(*GenericArray::from_slice(&data.w)));
            } else if data.lambda == 192 {
                let res = em_extendedwitness::<PARAMOWF192EM>(
                    GenericArray::from_slice(&data.key),
                    GenericArray::from_slice(
                        &data.input[..<PARAMOWF192EM as PARAMOWF>::InputSize::USIZE],
                    ),
                );
                assert_eq!(res.0, Box::new(*GenericArray::from_slice(&data.w)));
            } else {
                let res = em_extendedwitness::<PARAMOWF256EM>(
                    GenericArray::from_slice(&data.key),
                    GenericArray::from_slice(
                        &data.input[..<PARAMOWF256EM as PARAMOWF>::InputSize::USIZE],
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
                            .flat_map(|x| {
                                convert_to_bit::<<PARAMOWF128 as PARAMOWF>::Field, U8>(
                                    &x[0].to_le_bytes()[..1],
                                )
                            })
                            .collect(),
                        data.z
                            .iter()
                            .flat_map(|z| {
                                convert_to_bit::<<PARAMOWF128 as PARAMOWF>::Field, U8>(
                                    &z[0].to_le_bytes()[..1],
                                )
                            })
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
                let res = em_enc_fwd::<PARAMOWF128EM>(
                    GenericArray::from_slice(&input_z),
                    GenericArray::from_slice(&input_x),
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
                let (input_x, input_z): (Vec<GF192>, Vec<GF192>) = if data.m == 1 {
                    (
                        data.x
                            .iter()
                            .flat_map(|x| {
                                convert_to_bit::<<PARAMOWF192EM as PARAMOWF>::Field, U8>(
                                    &x[0].to_le_bytes()[..1],
                                )
                            })
                            .collect(),
                        data.z
                            .iter()
                            .flat_map(|z| {
                                convert_to_bit::<<PARAMOWF192EM as PARAMOWF>::Field, U8>(
                                    &z[0].to_le_bytes()[..1],
                                )
                            })
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
                let res = em_enc_fwd::<PARAMOWF192EM>(
                    GenericArray::from_slice(&input_z),
                    GenericArray::from_slice(&input_x),
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
                let (input_x, input_z): (Vec<GF256>, Vec<GF256>) = if data.m == 1 {
                    (
                        data.x
                            .iter()
                            .flat_map(|x| {
                                convert_to_bit::<<PARAMOWF256EM as PARAMOWF>::Field, U8>(
                                    &x[0].to_le_bytes()[..1],
                                )
                            })
                            .collect(),
                        data.z
                            .iter()
                            .flat_map(|z| {
                                convert_to_bit::<<PARAMOWF256EM as PARAMOWF>::Field, U8>(
                                    &z[0].to_le_bytes()[..1],
                                )
                            })
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
                let res = em_enc_fwd::<PARAMOWF256EM>(
                    GenericArray::from_slice(&input_z),
                    GenericArray::from_slice(&input_x),
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

    #[test]
    fn em_enc_bkwd_test() {
        let database: Vec<EmEncBkwd> =
            serde_json::from_str(include_str!("../tests/data/EmEncBkwd.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let (x_in, z_in, z_out_in): (Vec<GF128>, Vec<GF128>, Vec<GF128>) = if data.m == 1 {
                    (
                        data.x
                            .iter()
                            .flat_map(|x| {
                                convert_to_bit::<<PARAMOWF128 as PARAMOWF>::Field, U8>(
                                    &x[0].to_le_bytes()[..1],
                                )
                            })
                            .collect::<Vec<GF128>>(),
                        data.z
                            .iter()
                            .flat_map(|z| {
                                convert_to_bit::<<PARAMOWF128 as PARAMOWF>::Field, U8>(
                                    &z[0].to_le_bytes()[..1],
                                )
                            })
                            .collect::<Vec<GF128>>(),
                        data.zout
                            .iter()
                            .flat_map(|z| {
                                convert_to_bit::<<PARAMOWF128 as PARAMOWF>::Field, U8>(
                                    &z[0].to_le_bytes()[..1],
                                )
                            })
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
                let res = em_enc_bkwd::<PARAM128SEM, PARAMOWF128EM>(
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
                            .flat_map(|x| {
                                convert_to_bit::<<PARAMOWF192EM as PARAMOWF>::Field, U8>(
                                    &x[0].to_le_bytes()[..1],
                                )
                            })
                            .collect::<Vec<GF192>>(),
                        data.z
                            .iter()
                            .flat_map(|z| {
                                convert_to_bit::<<PARAMOWF192EM as PARAMOWF>::Field, U8>(
                                    &z[0].to_le_bytes()[..1],
                                )
                            })
                            .collect::<Vec<GF192>>(),
                        data.zout
                            .iter()
                            .flat_map(|z| {
                                convert_to_bit::<<PARAMOWF192EM as PARAMOWF>::Field, U8>(
                                    &z[0].to_le_bytes()[..1],
                                )
                            })
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
                let res = em_enc_bkwd::<PARAM192SEM, PARAMOWF192EM>(
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
                            .flat_map(|x| {
                                convert_to_bit::<<PARAMOWF256EM as PARAMOWF>::Field, U8>(
                                    &x[0].to_le_bytes()[..1],
                                )
                            })
                            .collect::<Vec<GF256>>(),
                        data.z
                            .iter()
                            .flat_map(|z| {
                                convert_to_bit::<<PARAMOWF256EM as PARAMOWF>::Field, U8>(
                                    &z[0].to_le_bytes()[..1],
                                )
                            })
                            .collect::<Vec<GF256>>(),
                        data.zout
                            .iter()
                            .flat_map(|z| {
                                convert_to_bit::<<PARAMOWF256EM as PARAMOWF>::Field, U8>(
                                    &z[0].to_le_bytes()[..1],
                                )
                            })
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
                let res = em_enc_bkwd::<PARAM256SEM, PARAMOWF256EM>(
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
    struct EmEncCstrnts {
        lambda: u16,

        mkey: u8,

        x: Vec<u8>,

        w: Vec<u8>,

        out: Vec<u8>,

        delta: Vec<u8>,

        vq: Vec<[u64; 4]>,

        ab: Vec<[u64; 8]>,
    }

    #[test]
    fn em_enc_cstrnts_test() {
        let database: Vec<EmEncCstrnts> =
            serde_json::from_str(include_str!("../tests/data/EmEncCstrnts.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let vq = &data
                    .vq
                    .iter()
                    .map(|v| GF128::new(v[0] as u128 + ((v[1] as u128) << 64), 0))
                    .collect::<Vec<GF128>>()[..];
                let res = em_enc_cstrnts::<PARAM128SEM, PARAMOWF128EM>(
                    GenericArray::from_slice(&data.out),
                    GenericArray::from_slice(&data.x),
                    GenericArray::from_slice(&data.w),
                    GenericArray::from_slice(vq),
                    GenericArray::from_slice(vq),
                    data.mkey != 0,
                    GF128::from(data.delta.as_slice()),
                );
                let (mut a0, mut a1) = (vec![], vec![]);
                for i in 0..data.ab.len() {
                    a0.push(GF128::new(
                        data.ab[i][0] as u128 + ((data.ab[i][1] as u128) << 64),
                        0,
                    ));
                    a1.push(GF128::new(
                        data.ab[i][4] as u128 + ((data.ab[i][5] as u128) << 64),
                        0,
                    ));
                }
                for i in 0..a0.len() {
                    assert_eq!((res.0[i], res.1[i]), (a0[i], a1[i]));
                }
            } else if data.lambda == 192 {
                let vq = &data
                    .vq
                    .iter()
                    .map(|v| GF192::new(v[0] as u128 + ((v[1] as u128) << 64), v[2] as u128))
                    .collect::<Vec<GF192>>()[..];
                let res = em_enc_cstrnts::<PARAM192SEM, PARAMOWF192EM>(
                    GenericArray::from_slice(&data.out),
                    GenericArray::from_slice(&data.x),
                    GenericArray::from_slice(&data.w),
                    GenericArray::from_slice(vq),
                    GenericArray::from_slice(vq),
                    data.mkey != 0,
                    GF192::from(data.delta.as_slice()),
                );
                let (mut a0, mut a1) = (vec![], vec![]);
                for i in 0..data.ab.len() {
                    a0.push(GF192::new(
                        data.ab[i][0] as u128 + ((data.ab[i][1] as u128) << 64),
                        data.ab[i][2] as u128,
                    ));
                    a1.push(GF192::new(
                        data.ab[i][4] as u128 + ((data.ab[i][5] as u128) << 64),
                        data.ab[i][6] as u128,
                    ));
                }
                for i in 0..res.0.len() {
                    assert_eq!((res.0[i], res.1[i]), (a0[i], a1[i]));
                }
            } else {
                let vq = &data
                    .vq
                    .iter()
                    .map(|v| {
                        GF256::new(
                            v[0] as u128 + ((v[1] as u128) << 64),
                            v[2] as u128 + ((v[3] as u128) << 64),
                        )
                    })
                    .collect::<Vec<GF256>>()[..];
                let res = em_enc_cstrnts::<PARAM256SEM, PARAMOWF256EM>(
                    GenericArray::from_slice(&data.out),
                    GenericArray::from_slice(&data.x),
                    GenericArray::from_slice(&data.w),
                    GenericArray::from_slice(vq),
                    GenericArray::from_slice(vq),
                    data.mkey != 0,
                    GF256::from(data.delta.as_slice()),
                );
                let (mut a0, mut a1) = (vec![], vec![]);
                for i in 0..data.ab.len() {
                    a0.push(GF256::new(
                        data.ab[i][0] as u128 + ((data.ab[i][1] as u128) << 64),
                        data.ab[i][2] as u128 + ((data.ab[i][3] as u128) << 64),
                    ));
                    a1.push(GF256::new(
                        data.ab[i][4] as u128 + ((data.ab[i][5] as u128) << 64),
                        data.ab[i][6] as u128 + ((data.ab[i][7] as u128) << 64),
                    ));
                }
                for i in 0..res.0.len() {
                    assert_eq!((res.0[i], res.1[i]), (a0[i], a1[i]));
                }
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
                let res = em_prove::<PARAM128SEM, PARAMOWF128EM>(
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
                let res = em_prove::<PARAM192SEM, PARAMOWF192EM>(
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
                let res = em_prove::<PARAM256SEM, PARAMOWF256EM>(
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

    #[test]
    fn em_verify_test() {
        let database: Vec<EmVerify> =
            serde_json::from_str(include_str!("../tests/data/EmVerify.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambda == 128 {
                let res = if data.tau == 11 {
                    em_verify::<PARAM128SEM, PARAMOWF128EM>(
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
                    em_verify::<PARAM128FEM, PARAMOWF128EM>(
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
                    em_verify::<PARAM192SEM, PARAMOWF192EM>(
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
                    em_verify::<PARAM192FEM, PARAMOWF192EM>(
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
                    em_verify::<PARAM256SEM, PARAMOWF256EM>(
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
                    em_verify::<PARAM256FEM, PARAMOWF256EM>(
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
