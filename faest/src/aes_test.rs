use crate::aes::{aes_key_enc_bkwd, aes_key_enc_cstrnts, aes_prove, aes_verify};
use crate::aes::{
    aes_key_enc_fwd, aes_key_exp_bwd, aes_key_exp_cstrnts, aes_key_exp_fwd, convert_to_bit,
    aes_extendedwitness,
};
use crate::fields::{BigGaloisField, GF128, GF192, GF256};
use crate::parameter::{self};
use crate::parameter::Param;
#[cfg(test)]
use serde::Deserialize;
#[allow(unused_imports)]
use std::convert;
use std::fs::File;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesExtendedWitness {
    lambda: u16,

    l: u16,

    lke: u16,

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
            let param = Param::set_param(128, data.l, 11, 12, 11, 1, 1, 16, 1);
            let mut paramowf = parameter::PARAMOWF128;
            paramowf.set_lke(data.lke);
            paramowf.set_nst((data.input.len() / 4).try_into().unwrap());
            let res = aes_extendedwitness(&data.key, &data.input, &param, &paramowf);
            for (i, _) in res.iter().enumerate() {
                for j in 0..4 {
                    assert_eq!(res[i].to_le_bytes()[j], data.w[i * 4 + j]);
                }
            }
        } else if data.lambda == 192 {
            let param = Param::set_param(192, data.l, 16, 12, 12, 1, 1, 16, 2);
            let mut paramowf = parameter::PARAMOWF192;
            paramowf.set_lke(data.lke);
            paramowf.set_nst((data.input.len() / 4).try_into().unwrap());
            let res = aes_extendedwitness(&data.key, &data.input, &param, &paramowf);
            for (i, _) in res.iter().enumerate() {
                for j in 0..4 {
                    assert_eq!(res[i].to_le_bytes()[j], data.w[i * 4 + j]);
                }
            }
        } else {
            let param = Param::set_param(256, data.l, 22, 12, 11, 1, 1, 16, 2);
            let mut paramowf = parameter::PARAMOWF256;
            paramowf.set_lke(data.lke);
            paramowf.set_nst((data.input.len() / 4).try_into().unwrap());
            let res = aes_extendedwitness(&data.key, &data.input, &param, &paramowf);
            for (i, _) in res.iter().enumerate() {
                for j in 0..4 {
                    assert_eq!(res[i].to_le_bytes()[j], data.w[i * 4 + j]);
                }
            }
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
                        .flat_map(|out| convert_to_bit(&[(out[0] as u8)]))
                        .collect(),
                    data.x
                        .iter()
                        .flat_map(|x| convert_to_bit(&[(x[0] as u8)]))
                        .collect(),
                )
            };
            let res: Vec<GF128> = aes_key_exp_fwd(&input, data.r, data.lambda as usize, data.nwd);
            assert_eq!(res, out);
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
                        .flat_map(|out| convert_to_bit(&[(out[0] as u8)]))
                        .collect(),
                    data.x
                        .iter()
                        .flat_map(|x| convert_to_bit(&[(x[0] as u8)]))
                        .collect(),
                )
            };
            let res: Vec<GF192> = aes_key_exp_fwd(&input, data.r, data.lambda as usize, data.nwd);
            assert_eq!(res, out);
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
                        .flat_map(|out| convert_to_bit(&[(out[0] as u8)]))
                        .collect(),
                    data.x
                        .iter()
                        .flat_map(|x| convert_to_bit(&[(x[0] as u8)]))
                        .collect(),
                )
            };
            let res: Vec<GF256> = aes_key_exp_fwd(&input, data.r, data.lambda as usize, data.nwd);
            assert_eq!(res, out);
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
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1]))
                        .collect(),
                    data.xk
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1]))
                        .collect(),
                    data.out
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1]))
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
            let res = aes_key_exp_bwd::<GF128>(&x, &xk.clone(), mtag, mkey, delta, data.ske);
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
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1]))
                        .collect(),
                    data.xk
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1]))
                        .collect(),
                    data.out
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1]))
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
            let res = aes_key_exp_bwd::<GF192>(&x, &xk, mtag, mkey, delta, data.ske);
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
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1]))
                        .collect(),
                    data.xk
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1]))
                        .collect(),
                    data.out
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1]))
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
            let res = aes_key_exp_bwd::<GF256>(&x, &xk, mtag, mkey, delta, data.ske);
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
            let fields_res_1: Vec<GF128> = convert_to_bit(&data.res1);
            let fields_res_2: Vec<GF128> = data
                .res2
                .iter()
                .map(|res| GF128::new(res[0] + ((res[1]) << 64), 0))
                .collect();
            let paramowf = parameter::PARAMOWF128;
            let mut res = aes_key_exp_cstrnts(&data.w, fields_v, mkey, fields_q, delta, &paramowf);
            if res.1 == vec![GF128::default()] {
                for _i in 0..field_ab.len() {
                    res.1.push(GF128::default());
                }
            }
            if res.2 == vec![GF128::default()] {
                for _i in 0..fields_res_1.len() - 1 {
                    res.2.push(GF128::default());
                }
            }

            #[allow(clippy::needless_range_loop)]
            for i in 0..field_ab.len() {
                assert_eq!(field_ab[i].0, res.0[i]);
                assert_eq!(field_ab[i].1, res.1[i]);
            }
            assert_eq!(fields_res_1, res.2);
            assert_eq!(fields_res_2, res.3);
        } else if data.lambda == 192 {
            let fields_v = &(data
                .v
                .iter()
                .map(|v| GF192::new(v[0] + ((v[1]) << 64), v[2]))
                .collect::<Vec<GF192>>())[..];
            let mkey = data.mkey != 0;
            let fields_q = &(data
                .q
                .iter()
                .map(|q| GF192::new(q[0] + ((q[1]) << 64), q[2]))
                .collect::<Vec<GF192>>())[..];
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
            let fields_res_1: Vec<GF192> = convert_to_bit(&data.res1);
            let fields_res_2: Vec<GF192> = data
                .res2
                .iter()
                .map(|w| GF192::new(w[0] + ((w[1]) << 64), w[2]))
                .collect();
            let paramowf = parameter::PARAMOWF192;
            let mut res = aes_key_exp_cstrnts(&data.w, fields_v, mkey, fields_q, delta, &paramowf);
            if res.1 == vec![GF192::default()] {
                for _i in 0..field_ab.len() {
                    res.1.push(GF192::default());
                }
            }
            if res.2 == vec![GF192::default()] {
                for _i in 0..fields_res_1.len() - 1 {
                    res.2.push(GF192::default());
                }
            }
            #[allow(clippy::needless_range_loop)]
            for i in 0..field_ab.len() {
                assert_eq!(field_ab[i].0, res.0[i]);
                assert_eq!(field_ab[i].1, res.1[i]);
            }
            assert_eq!(fields_res_1, res.2);
            assert_eq!(fields_res_2, res.3);
        } else {
            let fields_v = &(data
                .v
                .iter()
                .map(|v| GF256::new(v[0] + ((v[1]) << 64), v[2] + ((v[3]) << 64)))
                .collect::<Vec<GF256>>())[..];
            let mkey = data.mkey != 0;
            let fields_q = &(data
                .q
                .iter()
                .map(|q| GF256::new(q[0] + ((q[1]) << 64), q[2] + ((q[3]) << 64)))
                .collect::<Vec<GF256>>())[..];
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
            let fields_res_1: Vec<GF256> = convert_to_bit(&data.res1);
            let fields_res_2: Vec<GF256> = data
                .res2
                .iter()
                .map(|w| GF256::new(w[0] + ((w[1]) << 64), w[2] + ((w[3]) << 64)))
                .collect();
            let paramowf = parameter::PARAMOWF256;
            let mut res = aes_key_exp_cstrnts(&data.w, fields_v, mkey, fields_q, delta, &paramowf);
            if res.1 == vec![GF256::default()] {
                for _i in 0..field_ab.len() {
                    res.1.push(GF256::default());
                }
            }
            if res.2 == vec![GF256::default()] {
                for _i in 0..fields_res_1.len() - 1 {
                    res.2.push(GF256::default());
                }
            }
            #[allow(clippy::needless_range_loop)]
            for i in 0..field_ab.len() {
                assert_eq!(field_ab[i].0, res.0[i]);
                assert_eq!(field_ab[i].1, res.1[i]);
            }
            assert_eq!(fields_res_1, res.2);
            assert_eq!(fields_res_2, res.3);
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesEncFwd {
    lambda: u16,

    mkey: u8,

    mtag: u8,

    x: Vec<[u128; 4]>,

    xk: Vec<[u128; 4]>,

    input: [u8; 16],

    delta: [u128; 4],

    reslambda: Vec<[u128; 4]>,
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
                        .flat_map(|x| convert_to_bit(&(x[0].to_le_bytes())[..1]))
                        .collect::<Vec<GF128>>()),
                    (data
                        .xk
                        .iter()
                        .flat_map(|x| convert_to_bit(&(x[0].to_le_bytes())[..1]))
                        .collect::<Vec<GF128>>()),
                )
            } else {
                (
                    (data
                        .x
                        .iter()
                        .map(|v| GF128::new(v[0] + ((v[1]) << 64), 0))
                        .collect::<Vec<GF128>>()),
                    (data
                        .xk
                        .iter()
                        .map(|v| GF128::new(v[0] + ((v[1]) << 64), 0))
                        .collect::<Vec<GF128>>()),
                )
            };
            let paramowf = parameter::PARAMOWF128;
            let res = aes_key_enc_fwd::<GF128>(
                &x[..],
                &xk[..],
                data.mkey != 0,
                data.mtag != 0,
                data.input,
                GF128::new(data.delta[0] + ((data.delta[1]) << 64), 0),
                &paramowf,
            );
            let out = data
                .reslambda
                .iter()
                .map(|v| GF128::new(v[0] + ((v[1]) << 64), 0))
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
                        .flat_map(|x| convert_to_bit(&(x[0].to_le_bytes())[..1]))
                        .collect::<Vec<GF192>>()),
                    (data
                        .xk
                        .iter()
                        .flat_map(|x| convert_to_bit(&(x[0].to_le_bytes())[..1]))
                        .collect::<Vec<GF192>>()),
                )
            } else {
                (
                    (data
                        .x
                        .iter()
                        .map(|v| GF192::new(v[0] + ((v[1]) << 64), v[2]))
                        .collect::<Vec<GF192>>()),
                    (data
                        .xk
                        .iter()
                        .map(|v| GF192::new(v[0] + ((v[1]) << 64), v[2]))
                        .collect::<Vec<GF192>>()),
                )
            };
            let paramowf = parameter::PARAMOWF192;
            let res = aes_key_enc_fwd::<GF192>(
                &x[..],
                &xk[..],
                data.mkey != 0,
                data.mtag != 0,
                data.input,
                GF192::new(data.delta[0] + ((data.delta[1]) << 64), data.delta[2]),
                &paramowf,
            );
            let out = data
                .reslambda
                .iter()
                .map(|v| GF192::new(v[0] + ((v[1]) << 64), v[2]))
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
                        .flat_map(|x| convert_to_bit(&(x[0].to_le_bytes())[..1]))
                        .collect::<Vec<GF256>>()),
                    (data
                        .xk
                        .iter()
                        .flat_map(|x| convert_to_bit(&(x[0].to_le_bytes())[..1]))
                        .collect::<Vec<GF256>>()),
                )
            } else {
                (
                    (data
                        .x
                        .iter()
                        .map(|v| GF256::new(v[0] + ((v[1]) << 64), v[2] + ((v[3]) << 64)))
                        .collect::<Vec<GF256>>()),
                    (data
                        .xk
                        .iter()
                        .map(|v| GF256::new(v[0] + ((v[1]) << 64), v[2] + ((v[3]) << 64)))
                        .collect::<Vec<GF256>>()),
                )
            };
            let paramowf = parameter::PARAMOWF256;
            let res = aes_key_enc_fwd::<GF256>(
                &x[..],
                &xk[..],
                data.mkey != 0,
                data.mtag != 0,
                data.input,
                GF256::new(
                    data.delta[0] + ((data.delta[1]) << 64),
                    data.delta[2] + (data.delta[3] << 64),
                ),
                &paramowf,
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
                        .flat_map(|x| convert_to_bit(&(x[0].to_le_bytes())[..1]))
                        .collect::<Vec<GF128>>()),
                    (data
                        .xk
                        .iter()
                        .flat_map(|x| convert_to_bit(&(x[0].to_le_bytes())[..1]))
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
            let paramowf = parameter::PARAMOWF128;
            let res = aes_key_enc_bkwd::<GF128>(
                &x[..],
                &xk[..],
                data.mkey != 0,
                data.mtag != 0,
                data.output,
                GF128::new(data.delta[0] + (data.delta[1] << 64), 0),
                &paramowf,
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
                        .flat_map(|x| convert_to_bit(&(x[0].to_le_bytes())[..1]))
                        .collect::<Vec<GF192>>()),
                    (data
                        .xk
                        .iter()
                        .flat_map(|x| convert_to_bit(&(x[0].to_le_bytes())[..1]))
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
            let paramowf = parameter::PARAMOWF192;
            let res = aes_key_enc_bkwd::<GF192>(
                &x[..],
                &xk[..],
                data.mkey != 0,
                data.mtag != 0,
                data.output,
                GF192::new(data.delta[0] + (data.delta[1] << 64), data.delta[2]),
                &paramowf,
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
                        .flat_map(|x| convert_to_bit(&(x[0].to_le_bytes())[..1]))
                        .collect::<Vec<GF256>>()),
                    (data
                        .xk
                        .iter()
                        .flat_map(|x| convert_to_bit(&(x[0].to_le_bytes())[..1]))
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
            let paramowf = parameter::PARAMOWF256;
            let res = aes_key_enc_bkwd::<GF256>(
                &x[..],
                &xk[..],
                data.mkey != 0,
                data.mtag != 0,
                data.output,
                GF256::new(
                    data.delta[0] + (data.delta[1] << 64),
                    data.delta[2] + (data.delta[3] << 64),
                ),
                &paramowf,
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
        if data.lambda == 128 {
            let senc = data.senc as usize;
            let mkey = data.mkey != 0;
            let w = data.w;
            let k: Vec<GF128> = data.k.iter().flat_map(|x| convert_to_bit(&[*x])).collect();
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
            let paramowf = parameter::PARAMOWF128;
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
            let res = aes_key_enc_cstrnts::<GF128>(
                data.input,
                data.output,
                &w,
                &vq,
                &k,
                &vqk,
                mkey,
                &vq,
                &vqk,
                delta,
                &paramowf,
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
        } else if data.lambda == 192 {
            let senc = data.senc as usize;
            let mkey = data.mkey != 0;
            let w = data.w;
            let k: Vec<GF192> = data.k.iter().flat_map(|x| convert_to_bit(&[*x])).collect();
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
            let paramowf = parameter::PARAMOWF192;
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
            let res = aes_key_enc_cstrnts::<GF192>(
                data.input,
                data.output,
                &w,
                &vq,
                &k,
                &vqk,
                mkey,
                &vq,
                &vqk,
                delta,
                &paramowf,
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
        } else {
            let senc = data.senc as usize;
            let mkey = data.mkey != 0;
            let w = data.w;
            let k: Vec<GF256> = data.k.iter().flat_map(|x| convert_to_bit(&[*x])).collect();
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
            let paramowf = parameter::PARAMOWF256;
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
            let res = aes_key_enc_cstrnts::<GF256>(
                data.input,
                data.output,
                &w,
                &vq,
                &k,
                &vqk,
                mkey,
                &vq,
                &vqk,
                delta,
                &paramowf,
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
    let file = File::open("AesProve.json").unwrap();
    let database: Vec<AesProve> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let paramowf = parameter::PARAMOWF128;
            let mut pk = data.input.to_vec();
            pk.append(&mut data.output.to_vec());
            let res: (Vec<u8>, Vec<u8>) =
                aes_prove::<GF128>(&data.w, &data.u, &data.gv, &pk, &data.chall, &paramowf);
            assert_eq!(res.0, data.at);
            assert_eq!(res.1, data.bt);
        } else if data.lambda == 192 {
            let paramowf = parameter::PARAMOWF192;
            let mut pk = data.input.to_vec();
            pk.append(&mut data.output.to_vec());
            let res: (Vec<u8>, Vec<u8>) =
                aes_prove::<GF192>(&data.w, &data.u, &data.gv, &pk, &data.chall, &paramowf);
            assert_eq!(res.0, data.at);
            assert_eq!(res.1, data.bt);
        } else {
            let paramowf = parameter::PARAMOWF256;
            let mut pk = data.input.to_vec();
            pk.append(&mut data.output.to_vec());
            let res: (Vec<u8>, Vec<u8>) =
                aes_prove::<GF256>(&data.w, &data.u, &data.gv, &pk, &data.chall, &paramowf);
            assert_eq!(res.0, data.at);
            assert_eq!(res.1, data.bt);
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

    tau: u8,

    t0: u8,

    k0: u8,

    t1: u8,

    k1: u8,

    res: Vec<u64>,
}

#[test]
fn aes_verify_test() {
    let file = File::open("AesVerify.json").unwrap();
    let database: Vec<AesVerify> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let param = Param::set_param(
                128, 1600, data.tau, data.k0, data.k1, data.t0, data.t1, 16, 1,
            );
            let paramowf = parameter::PARAMOWF128;
            let mut pk = data.input.to_vec();
            pk.append(&mut data.output.to_vec());
            let out = aes_verify::<GF128>(
                &data.d[..],
                data.gq,
                &data.chall2[..],
                &data.chall3[..],
                GF128::to_field(&data.at)[0],
                &pk[..],
                &paramowf,
                &param,
            );
            assert_eq!(
                GF128::new(data.res[0] as u128 + ((data.res[1] as u128) << 64), 0),
                GF128::to_field(&out)[0]
            );
        } else if data.lambda == 192 {
            let param = Param::set_param(
                192, 3264, data.tau, data.k0, data.k1, data.t0, data.t1, 16, 2,
            );
            let paramowf = parameter::PARAMOWF192;
            let mut pk = data.input.to_vec();
            pk.append(&mut data.output.to_vec());
            let out = aes_verify::<GF192>(
                &data.d[..],
                data.gq,
                &data.chall2[..],
                &data.chall3[..],
                GF192::to_field(&data.at)[0],
                &pk[..],
                &paramowf,
                &param,
            );
            assert_eq!(
                GF192::new(
                    data.res[0] as u128 + ((data.res[1] as u128) << 64),
                    data.res[2] as u128
                ),
                GF192::to_field(&out)[0]
            );
        } else {
            let param = Param::set_param(
                256, 4000, data.tau, data.k0, data.k1, data.t0, data.t1, 16, 2,
            );
            let paramowf = parameter::PARAMOWF256;
            let mut pk = data.input.to_vec();
            pk.append(&mut data.output.to_vec());
            let out = aes_verify::<GF256>(
                &data.d[..],
                data.gq,
                &data.chall2[..],
                &data.chall3[..],
                GF256::to_field(&data.at)[0],
                &pk[..],
                &paramowf,
                &param,
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
