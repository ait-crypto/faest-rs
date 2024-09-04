use crate::aes::{aes_enc_bkwd, aes_enc_cstrnts, aes_prove, aes_verify};
use crate::aes::{
    aes_enc_fwd, aes_extendedwitness, aes_key_exp_bwd, aes_key_exp_cstrnts, aes_key_exp_fwd,
    convert_to_bit,
};
use crate::fields::{self, BigGaloisField, GF128, GF192, GF256};

use crate::parameter::{
    self, PARAM128S, PARAM192S, PARAM256S, PARAMOWF128, PARAMOWF192, PARAMOWF256,
};
use cipher::Unsigned;
use generic_array::GenericArray;
#[cfg(test)]
use serde::Deserialize;
#[allow(unused_imports)]
use std::convert;
use std::default;
use std::fs::File;
use typenum::{U176, U208, U240, U8};

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
    let file = File::open("AesExtendedWitness.json").unwrap();
    let database: Vec<AesExtendedWitness> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let res = aes_extendedwitness::<PARAM128S, PARAMOWF128>(
                GenericArray::from_slice(&data.key),
                GenericArray::from_slice(&data.input),
            );
            assert_eq!(res.0, *GenericArray::from_slice(&data.w));
        } else if data.lambda == 192 {
            let res = aes_extendedwitness::<PARAM192S, PARAMOWF192>(
                GenericArray::from_slice(&data.key),
                GenericArray::from_slice(&data.input),
            );
            assert_eq!(res.0, *GenericArray::from_slice(&data.w));
        } else {
            let res = aes_extendedwitness::<PARAM256S, PARAMOWF256>(
                GenericArray::from_slice(&data.key),
                GenericArray::from_slice(&data.input),
            );
            assert_eq!(res.0, *GenericArray::from_slice(&data.w));
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesKeyExpFwd {
    lambda: u16,

    r: u8,

    nwd: u8,

    x: Vec<[u128; 4]>,

    out: Vec<[u128; 4]>,
}

fn convtobit<T> (x : u8) -> Box<GenericArray<T, U8>> where T : BigGaloisField + std::default::Default{
    let mut res : Box<GenericArray<T, U8>> = GenericArray::default_boxed();
    for j in 0..8 {
        res[j] = T::new(((x >> j) & 1) as u128, 0)
    }
    res
}

#[test]
fn aes_key_exp_fwd_test() {
    let file = File::open("AesKeyExpFwd.json").unwrap();
    let database: Vec<AesKeyExpFwd> =
        serde_json::from_reader(file).expect("error while reading or parsing");
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
            let res: GenericArray<
                GF128,
                <parameter::PARAMOWF128 as parameter::PARAMOWF>::PRODRUN128,
            > = aes_key_exp_fwd::<PARAMOWF128>(GenericArray::from_slice(&input));
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
            let res: GenericArray<
                GF192,
                <parameter::PARAMOWF192 as parameter::PARAMOWF>::PRODRUN128,
            > = aes_key_exp_fwd::<PARAMOWF192>(GenericArray::from_slice(&input));
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
            let res: GenericArray<
                GF256,
                <parameter::PARAMOWF256 as parameter::PARAMOWF>::PRODRUN128,
            > = aes_key_exp_fwd::<PARAMOWF256>(GenericArray::from_slice(&input));
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

    ske: u16,

    delta: [u128; 4],

    x: Vec<[u128; 4]>,

    xk: Vec<[u128; 4]>,

    out: Vec<[u128; 4]>,
}

#[test]
fn aes_key_exp_bwd_test() {
    let file = File::open("AesKeyExpBwd.json").unwrap();
    let database: Vec<AesKeyExpBwd> =
        serde_json::from_reader(file).expect("error while reading or parsing");
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

            let res = aes_key_exp_bwd::<PARAMOWF128>(
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
            let res = aes_key_exp_bwd::<PARAMOWF192>(
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
            let res = aes_key_exp_bwd::<PARAMOWF256>(
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
struct AesKeyExpCstrnts {
    lambda: u16,

    mkey: u8,

    w: Vec<u8>,

    v: Vec<[u128; 4]>,

    q: Vec<[u128; 4]>,

    delta: Vec<u8>,

    ab: Vec<[u128; 8]>,

    res1: Vec<u8>,

    res2: Vec<[u128; 4]>,
}

pub fn byte_to_bit(input : u8) -> Vec<u8> {
    let mut res = vec![0; 8];
    for i in 0..8 {
        res[i] = (input >> i) & 1;
    }
    res
}
#[test]
fn aes_key_exp_cstrnts_test() {
    let file = File::open("AesKeyExpCstrnts.json").unwrap();
    let database: Vec<AesKeyExpCstrnts> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let fields_v = &(data
                .v
                .iter()
                .map(|v| GF128::new(v[0] + ((v[1]) << 64), 0))
                .collect::<Vec<GF128>>())[..];
            let mkey = data.mkey != 0;
            let fields_q = &(data
                .q
                .iter()
                .map(|q| GF128::new(q[0] + ((q[1]) << 64), 0))
                .collect::<Vec<GF128>>())[..];
            let delta = GF128::new(
                data.delta
                    .iter()
                    .enumerate()
                    .map(|(i, x)| ((*x as u128) << (8 * i)))
                    .sum(),
                0,
            );
            let field_ab: Vec<(GF128, GF128)> = data
                .ab
                .iter()
                .map(|a| {
                    (
                        GF128::new(a[0] + ((a[1]) << 64), 0),
                        GF128::new(a[4] + ((a[5]) << 64), 0),
                    )
                })
                .collect();
            let fields_res_1: GenericArray<
                GF128,
                <parameter::PARAMOWF128 as parameter::PARAMOWF>::PRODRUN128,
            > = *GenericArray::from_slice(&convert_to_bit::<
                PARAMOWF128,
                <parameter::PARAMOWF128 as parameter::PARAMOWF>::PRODRUN128,
                U176,
            >(GenericArray::from_slice(
                &data.res1[..176],
            )));
            let fields_res_2: Vec<GF128> = data
                .res2
                .iter()
                .map(|res| GF128::new(res[0] + ((res[1]) << 64), 0))
                .collect();
            
            let mut res =
                aes_key_exp_cstrnts::<PARAMOWF128>(GenericArray::from_slice(&data.w.iter().flat_map(|x| byte_to_bit(*x)).collect::<Vec<u8>>()[..448]), GenericArray::from_slice(&fields_v), mkey, GenericArray::from_slice(&fields_q), delta);
            if res.1 == GenericArray::default_boxed() {
                for i in 0..field_ab.len() {
                    res.1[i] = GF128::default();
                }
            }
            if res.2 == GenericArray::default_boxed() {
                for i in 0..field_ab.len() {
                    res.2[i] = GF128::default();
                }
            }

            #[allow(clippy::needless_range_loop)]
            for i in 0..field_ab.len() {
                assert_eq!(field_ab[i].0, res.0[i]);
                assert_eq!(field_ab[i].1, res.1[i]);
            }
            assert_eq!(fields_res_1, *res.2);
            assert_eq!(*GenericArray::from_slice(&fields_res_2), *res.3);
        } else if data.lambda == 192 {
            let fields_v = &(data
                .v
                .iter()
                .map(|v| GF192::new(v[0] + ((v[1]) << 64), v[2]))
                .take(448)
                .collect::<Vec<GF192>>());
            let mkey = data.mkey != 0;
            let fields_q = &(data
                .q
                .iter()
                .map(|q| GF192::new(q[0] + ((q[1]) << 64), q[2]))
                .take(448)
                .collect::<Vec<GF192>>());
            let delta = GF192::new(
                data.delta
                    .iter()
                    .take(16)
                    .enumerate()
                    .map(|(i, x)| ((*x as u128) << (8 * i)))
                    .sum(),
                data.delta
                    .iter()
                    .skip(16)
                    .enumerate()
                    .map(|(i, x)| ((*x as u128) << (8 * i)))
                    .sum(),
            );
            let field_ab: Vec<(GF192, GF192)> = data
                .ab
                .iter()
                .map(|a| {
                    (
                        GF192::new(a[0] + ((a[1]) << 64), a[2]),
                        GF192::new(a[4] + ((a[5]) << 64), a[6]),
                    )
                })
                .collect();
            let fields_res_1: GenericArray<
                GF192,
                <parameter::PARAMOWF192 as parameter::PARAMOWF>::PRODRUN128,
            > = *GenericArray::from_slice(&convert_to_bit::<
                PARAMOWF192,
                <parameter::PARAMOWF192 as parameter::PARAMOWF>::PRODRUN128,
                U208,
            >(GenericArray::from_slice(
                &data.res1[..208],
            )));
            let fields_res_2: Vec<GF192> = data
                .res2
                .iter()
                .map(|w| GF192::new(w[0] + ((w[1]) << 64), w[2]))
                .collect();
            let mut res =
                aes_key_exp_cstrnts::<PARAMOWF192>(GenericArray::from_slice(&data.w.iter().flat_map(|x| byte_to_bit(*x)).collect::<Vec<u8>>()[..448]), GenericArray::from_slice(&fields_v), mkey, GenericArray::from_slice(&fields_q), delta);
            #[allow(clippy::needless_range_loop)]
            for i in 0..field_ab.len() {
                assert_eq!(field_ab[i].0, res.0[i]);
                assert_eq!(field_ab[i].1, res.1[i]);
            }
            assert_eq!(fields_res_1, *res.2);
            assert_eq!(*GenericArray::from_slice(&fields_res_2), *res.3);
        } else {
            let fields_v = &(data
                .v
                .iter()
                .map(|v| GF256::new(v[0] + ((v[1]) << 64), v[2] + ((v[3]) << 64)))
                .take(672).collect::<Vec<GF256>>())[..];
            let mkey = data.mkey != 0;
            let fields_q = &(data
                .q
                .iter()
                .map(|q| GF256::new(q[0] + ((q[1]) << 64), q[2] + ((q[3]) << 64)))
                .take(672).collect::<Vec<GF256>>())[..];
            let delta = GF256::new(
                data.delta
                    .iter()
                    .take(16)
                    .enumerate()
                    .map(|(i, x)| ((*x as u128) << (8 * i)))
                    .sum(),
                data.delta
                    .iter()
                    .skip(16)
                    .enumerate()
                    .map(|(i, x)| ((*x as u128) << (8 * i)))
                    .sum(),
            );
            let field_ab: Vec<(GF256, GF256)> = data
                .ab
                .iter()
                .map(|a| {
                    (
                        GF256::new(a[0] + ((a[1]) << 64), a[2] + ((a[3]) << 64)),
                        GF256::new(a[4] + ((a[5]) << 64), a[6] + ((a[7]) << 64)),
                    )
                })
                .collect();
            let fields_res_1: GenericArray<GF256, <parameter::PARAMOWF256 as parameter::PARAMOWF>::PRODRUN128> = *GenericArray::from_slice(&convert_to_bit::<fields::GF256, PARAMOWF256, <parameter::PARAMOWF256 as parameter::PARAMOWF>::PRODRUN128, U240>(GenericArray::from_slice(&data.res1[..240])));
            let fields_res_2: Vec<GF256> = data
                .res2
                .iter()
                .map(|w| GF256::new(w[0] + ((w[1]) << 64), w[2] + ((w[3]) << 64)))
                .collect();
            let mut res =
                aes_key_exp_cstrnts::<GF256, PARAMOWF256>(GenericArray::from_slice(&data.w.iter().flat_map(|x| byte_to_bit(*x)).collect::<Vec<u8>>()[..672]), GenericArray::from_slice(&fields_v), mkey, GenericArray::from_slice(&fields_q), delta);
            #[allow(clippy::needless_range_loop)]
            for i in 0..field_ab.len() {
                assert_eq!(field_ab[i].0, res.0[i]);
                assert_eq!(field_ab[i].1, res.1[i]);
            }
            assert_eq!(fields_res_1, *res.2);
            assert_eq!(*GenericArray::from_slice(&fields_res_2), *res.3);
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

#[test]
fn aes_enc_fwd_test() {
    let file = File::open("AesEncFwd.json").unwrap();
    let database: Vec<AesEncFwd> =
        serde_json::from_reader(file).expect("error while reading or parsing");
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
            let res = aes_enc_fwd::<PARAMOWF128>(
                GenericArray::from_slice(&x[..]),
                GenericArray::from_slice(&xk[..]),
                data.mkey != 0,
                data.mtag != 0,
                data.input,
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
                        .map(|v| GF192::new(v[0] as u128 + ((v[1] as u128) << 64), v[2] as u128))
                        .collect::<Vec<GF192>>()),
                    (data
                        .xk
                        .iter()
                        .map(|v| GF192::new(v[0] as u128 + ((v[1] as u128) << 64), v[2] as u128))
                        .collect::<Vec<GF192>>()),
                )
            };
            let res = aes_enc_fwd::<PARAMOWF192>(
                GenericArray::from_slice(&x[..]),
                GenericArray::from_slice(&xk[..]),
                data.mkey != 0,
                data.mtag != 0,
                data.input,
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
            let res = aes_enc_fwd::<PARAMOWF256>(
                GenericArray::from_slice(&x[..]),
                GenericArray::from_slice(&xk[..]),
                data.mkey != 0,
                data.mtag != 0,
                data.input,
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

#[test]
fn aes_enc_bkwd_test() {
    let file = File::open("AesEncBkwd.json").unwrap();
    let database: Vec<AesEncBkwd> =
        serde_json::from_reader(file).expect("error while reading or parsing");
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
            let res = aes_enc_bkwd::<PARAMOWF128>(
                GenericArray::from_slice(&x[..]),
                GenericArray::from_slice(&xk[..]),
                data.mkey != 0,
                data.mtag != 0,
                data.output,
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
            let res = aes_enc_bkwd::<PARAMOWF192>(
                GenericArray::from_slice(&x[..]),
                GenericArray::from_slice(&xk[..]),
                data.mkey != 0,
                data.mtag != 0,
                data.output,
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
            let res = aes_enc_bkwd::<PARAMOWF256>(
                GenericArray::from_slice(&x[..]),
                GenericArray::from_slice(&xk[..]),
                data.mkey != 0,
                data.mtag != 0,
                data.output,
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
struct AesEncCstrnts {
    lambda: u16,

    mkey: u8,

    w: Vec<u8>,

    k: Vec<u8>,

    vq: Vec<[u128; 4]>,

    vqk: Vec<[u128; 4]>,

    input: [u8; 16],

    output: [u8; 16],

    delta: Vec<u8>,

    senc: u8,

    ab: Vec<[u128; 8]>,
}

#[test]
fn aes_enc_cstrnts_test() {
    let file = File::open("AesEncCstrnts.json").unwrap();
    let database: Vec<AesEncCstrnts> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        /* if data.lambda == 128 {
            let senc = data.senc as usize;
            let mkey = data.mkey != 0;
            let w = data.w;
            let k: Vec<GF128> = data.k.iter().flat_map(|x| convtobit(*x)).collect();
            let vq: Vec<GF128> = data
                .vq
                .iter()
                .map(|x| GF128::new(x[0] + (x[1] << 64), 0))
                .collect();
            let vqk: Vec<GF128> = data
                .vqk
                .iter()
                .map(|x| GF128::new(x[0] + (x[1] << 64), 0))
                .collect();
            let delta = GF128::new(
                u64::from_le_bytes(data.delta[..8].try_into().unwrap()) as u128
                    + ((u64::from_le_bytes(data.delta[8..].try_into().unwrap()) as u128) << 64),
                0,
            );
            let ab: Vec<(GF128, GF128)> = data
                .ab
                .iter()
                .map(|x| {
                    (
                        GF128::new(x[0] + (x[1] << 64), 0),
                        GF128::new(x[4] + (x[5] << 64), 0),
                    )
                })
                .collect();
            let res = aes_enc_cstrnts::<PARAMOWF128>(
                data.input,
                data.output,
                GenericArray::from_slice(&w),
                GenericArray::from_slice(&vq),
                GenericArray::from_slice(&k),
                GenericArray::from_slice(&vqk),
                mkey,
                GenericArray::from_slice(&vq),
                GenericArray::from_slice(&vqk),
                delta,
            );
            if mkey == false {
                for i in 0..senc {
                    assert_eq!(res[i], ab[i].0);
                    assert_eq!(res[senc + i], ab[i].1);
                }
            } else {
                for i in 0..senc {
                    assert_eq!(res[i], ab[i].0);
                }
            }
        } else  */if data.lambda == 192 {
            let senc = data.senc as usize;
            let mkey = data.mkey != 0;
            let w = data.w;
            let k: Vec<GF192> = data.k.iter().flat_map(|x| convtobit(*x)).collect();
            let vq: Vec<GF192> = data
                .vq
                .iter()
                .map(|x| GF192::new(x[0] + (x[1] << 64), x[2]))
                .collect();
            let vqk: Vec<GF192> = data
                .vqk
                .iter()
                .map(|x| GF192::new(x[0] + (x[1] << 64), x[2]))
                .collect();
            let delta = GF192::new(
                u64::from_le_bytes(data.delta[..8].try_into().unwrap()) as u128
                    + ((u64::from_le_bytes(data.delta[8..16].try_into().unwrap()) as u128) << 64),
                u64::from_le_bytes(data.delta[16..].try_into().unwrap()) as u128,
            );
            let ab: Vec<(GF192, GF192)> = data
                .ab
                .iter()
                .map(|x| {
                    (
                        GF192::new(x[0] + (x[1] << 64), x[2]),
                        GF192::new(x[4] + (x[5] << 64), x[6]),
                    )
                })
                .collect();
            let res = aes_enc_cstrnts::<PARAMOWF192>(
                data.input,
                data.output,
                GenericArray::from_slice(&w),
                GenericArray::from_slice(&vq),
                GenericArray::from_slice(&k),
                GenericArray::from_slice(&vqk),
                mkey,
                GenericArray::from_slice(&vq),
                GenericArray::from_slice(&vqk),
                delta,
            );
            if res.len() == senc * 2 {
                for i in 0..senc {
                    assert_eq!(res[i], ab[i].0);
                    assert_eq!(res[senc + i], ab[i].1);
                }
            } else {
                for i in 0..senc {
                    assert_eq!(res[i], ab[i].0);
                }
            }
        } /* else {
            let senc = data.senc as usize;
            let mkey = data.mkey != 0;
            let w = data.w;
            let k: Vec<GF256> = data.k.iter().flat_map(|x| convtobit(*x)).collect();
            let vq: Vec<GF256> = data
                .vq
                .iter()
                .map(|x| GF256::new(x[0] + (x[1] << 64), x[2] + (x[3] << 64)))
                .collect();
            let vqk: Vec<GF256> = data
                .vqk
                .iter()
                .map(|x| GF256::new(x[0] + (x[1] << 64), x[2] + (x[3] << 64)))
                .collect();
            let delta = GF256::new(
                u64::from_le_bytes(data.delta[..8].try_into().unwrap()) as u128
                    + ((u64::from_le_bytes(data.delta[8..16].try_into().unwrap()) as u128) << 64),
                u64::from_le_bytes(data.delta[16..24].try_into().unwrap()) as u128
                    + ((u64::from_le_bytes(data.delta[24..].try_into().unwrap()) as u128) << 64),
            );
            let ab: Vec<(GF256, GF256)> = data
                .ab
                .iter()
                .map(|x| {
                    (
                        GF256::new(x[0] + (x[1] << 64), x[2] + (x[3] << 64)),
                        GF256::new(x[4] + (x[5] << 64), x[6] + (x[7] << 64)),
                    )
                })
                .collect();
            let res = aes_enc_cstrnts::<PARAMOWF256>(
                data.input,
                data.output,
                GenericArray::from_slice(&w),
                GenericArray::from_slice(&vq),
                GenericArray::from_slice(&k),
                GenericArray::from_slice(&vqk),
                mkey,
                GenericArray::from_slice(&vq),
                GenericArray::from_slice(&vqk),
                delta,
            );
            if res.len() == senc * 2 {
                for i in 0..senc {
                    assert_eq!(res[i], ab[i].0);
                    assert_eq!(res[senc + i], ab[i].1);
                }
            } else {
                for i in 0..senc {
                    assert_eq!(res[i], ab[i].0);
                }
            }
        }*/
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
    
    let file = File::open("AesProve.json").unwrap();
    let database: Vec<AesProve> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let mut pk = data.input.to_vec();
            let mut bitw: Vec<u8> = vec![0; 1600];
            for i in 0..data.w.len() {
                for j in 0..8 {
                    bitw[8 * i + j] = (data.w[i] >> j) & 1;
                }
            }
            
            pk.append(&mut data.output.to_vec());
            
            let res: (Box<GenericArray<u8, <parameter::PARAMOWF128 as parameter::PARAMOWF>::LAMBDABYTES>>, Box<GenericArray<u8, <parameter::PARAMOWF128 as parameter::PARAMOWF>::LAMBDABYTES>>) = aes_prove::<PARAM128S, PARAMOWF128>( 
                GenericArray::from_slice(&bitw),
                GenericArray::from_slice(&data.u),
                Box::new(GenericArray::from_slice(&data.gv.iter().map(|x| *GenericArray::from_slice(x)).collect::<Vec<GenericArray<u8, _>>>())),
                GenericArray::from_slice(&pk),
                GenericArray::from_slice(&data.chall),
            );
            
            assert_eq!((res).0, Box::new(*GenericArray::from_slice(&data.at)));
            assert_eq!((res).1, Box::new(*GenericArray::from_slice(&data.bt)));
         } else if data.lambda == 192 {
            let mut pk = data.input.to_vec();
            let mut bitw : Vec<u8> = vec![0; 3264];
            for i in 0..data.w.len(){
                for j in 0..8 {
                    bitw[8*i + j] = (data.w[i] >> j) & 1;
                }
            }

            let mut pk = data.input.to_vec();
            pk.append(&mut data.output.to_vec());
            let res: (Box<GenericArray<u8, <parameter::PARAMOWF192 as parameter::PARAMOWF>::LAMBDABYTES>>, Box<GenericArray<u8, <parameter::PARAMOWF192 as parameter::PARAMOWF>::LAMBDABYTES>>) = aes_prove::<GF192, PARAM192S, PARAMOWF192>(
                GenericArray::from_slice(&bitw),
                GenericArray::from_slice(&data.u),
                Box::new(GenericArray::from_slice(&data.gv.iter().map(|x| *GenericArray::from_slice(x)).collect::<Vec<GenericArray<u8, _>>>())),
                GenericArray::from_slice(&pk),
                GenericArray::from_slice(&data.chall),
            );
            assert_eq!(res.0, Box::new(*GenericArray::from_slice(&data.at)));
            assert_eq!(res.1, Box::new(*GenericArray::from_slice(&data.bt)));
        } else {
            let mut pk = data.input.to_vec();
            let mut bitw : Vec<u8> = vec![0; 4000];
            for i in 0..data.w.len(){
                for j in 0..8 {
                    bitw[8*i + j] = (data.w[i] >> j) & 1;
                }
            }

            let mut pk = data.input.to_vec();
            pk.append(&mut data.output.to_vec());
            let res: (Box<GenericArray<u8, <parameter::PARAMOWF256 as parameter::PARAMOWF>::LAMBDABYTES>>, Box<GenericArray<u8, <parameter::PARAMOWF256 as parameter::PARAMOWF>::LAMBDABYTES>>)= aes_prove::<GF256, PARAM256S, PARAMOWF256>(
                GenericArray::from_slice(&bitw),
                GenericArray::from_slice(&data.u),
                Box::new(GenericArray::from_slice(&data.gv.iter().map(|x| *GenericArray::from_slice(x)).collect::<Vec<GenericArray<u8, _>>>())),
                GenericArray::from_slice(&pk),
                GenericArray::from_slice(&data.chall),
            );
            assert_eq!(*res.0, *GenericArray::from_slice(&data.at));
            assert_eq!(*res.1, *GenericArray::from_slice(&data.bt));
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

#[test]
fn aes_verify_test() {
    let file = File::open("AesVerify.json").unwrap();
    let database: Vec<AesVerify> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let mut pk = data.input.to_vec();
            pk.append(&mut data.output.to_vec());
            let out = aes_verify::<PARAM128S, PARAMOWF128>(
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
                GenericArray::from_slice(&pk[..]),
            );
            assert_eq!(
                GF128::new(data.res[0] as u128 + ((data.res[1] as u128) << 64), 0),
                GF128::to_field(&out)[0]
            );
        } else if data.lambda == 192 {
            let mut pk = data.input.to_vec();
            pk.append(&mut data.output.to_vec());
            let out = aes_verify::<PARAM192S, PARAMOWF192>(
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
                GenericArray::from_slice(&pk[..]),
            );
            assert_eq!(
                GF192::new(
                    data.res[0] as u128 + ((data.res[1] as u128) << 64),
                    data.res[2] as u128
                ),
                GF192::to_field(&out)[0]
            );
        } else {
            let mut pk = data.input.to_vec();
            pk.append(&mut data.output.to_vec());
            let out = aes_verify::<PARAM256S, PARAMOWF256>(
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
                GenericArray::from_slice(&pk[..]),
            );
            assert_eq!(
                GF256::new(
                    data.res[0] as u128 + ((data.res[1] as u128) << 64),
                    data.res[2] as u128 + ((data.res[3] as u128) << 64)
                ),
                GF256::to_field(&out)[0]
            );
        }
    }
}
