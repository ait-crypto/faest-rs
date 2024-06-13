use crate::aes::{
    aes_key_exp_bwd, aes_key_exp_cstrnts, aes_key_exp_fwd, convert_to_bit, extendedwitness,
};
use crate::fields::{BigGaloisField, GF128, GF192, GF256};
use crate::parameter::{self};
use crate::parameter::{Param, ParamOWF};
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
            let res = extendedwitness(&data.key, &data.input, param, paramowf);
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
            let res = extendedwitness(&data.key, &data.input, param, paramowf);
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
            let res = extendedwitness(&data.key, &data.input, param, paramowf);
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

    x: Vec<[u64; 4]>,

    out: Vec<[u64; 4]>,
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
                        .map(|x| GF128::new((x[0] as u128) + ((x[1] as u128) << 64), 0))
                        .collect(),
                    data.x
                        .iter()
                        .map(|x| GF128::new((x[0] as u128) + ((x[1] as u128) << 64), 0))
                        .collect(),
                )
            } else {
                (
                    data.out
                        .iter()
                        .flat_map(|out| convert_to_bit(&vec![(out[0] as u8)]))
                        .collect(),
                    data.x
                        .iter()
                        .flat_map(|x| convert_to_bit(&vec![(x[0] as u8)]))
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
                        .map(|x| GF192::new((x[0] as u128) + ((x[1] as u128) << 64), x[2] as u128))
                        .collect(),
                    data.x
                        .iter()
                        .map(|x| GF192::new((x[0] as u128) + ((x[1] as u128) << 64), x[2] as u128))
                        .collect(),
                )
            } else {
                (
                    data.out
                        .iter()
                        .flat_map(|out| convert_to_bit(&vec![(out[0] as u8)]))
                        .collect(),
                    data.x
                        .iter()
                        .flat_map(|x| convert_to_bit(&vec![(x[0] as u8)]))
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
                        .map(|x| {
                            GF256::new(
                                (x[0] as u128) + ((x[1] as u128) << 64),
                                (x[2] as u128) + ((x[3] as u128) << 64),
                            )
                        })
                        .collect(),
                    data.x
                        .iter()
                        .map(|x| {
                            GF256::new(
                                (x[0] as u128) + ((x[1] as u128) << 64),
                                (x[2] as u128) + ((x[3] as u128) << 64),
                            )
                        })
                        .collect(),
                )
            } else {
                (
                    data.out
                        .iter()
                        .flat_map(|out| convert_to_bit(&vec![(out[0] as u8)]))
                        .collect(),
                    data.x
                        .iter()
                        .flat_map(|x| convert_to_bit(&vec![(x[0] as u8)]))
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
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1].to_vec()))
                        .collect(),
                    data.xk
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1].to_vec()))
                        .collect(),
                    data.out
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1].to_vec()))
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
            let res = aes_key_exp_bwd::<GF128>(x, &xk.clone(), mtag, mkey, delta, data.ske);
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
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1].to_vec()))
                        .collect(),
                    data.xk
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1].to_vec()))
                        .collect(),
                    data.out
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1].to_vec()))
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
            let res = aes_key_exp_bwd::<GF192>(x, &xk, mtag, mkey, delta, data.ske);
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
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1].to_vec()))
                        .collect(),
                    data.xk
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1].to_vec()))
                        .collect(),
                    data.out
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1].to_vec()))
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
            let res = aes_key_exp_bwd::<GF256>(x, &xk, mtag, mkey, delta, data.ske);
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

    v: Vec<[u64; 4]>,

    q: Vec<[u64; 4]>,

    delta: Vec<u8>,

    ske: u8,

    kc: u8,

    ab: Vec<[u64; 8]>,

    res1: Vec<u8>,

    res2: Vec<[u64; 4]>,
}

#[test]
fn aes_key_exp_cstrnts_test() {
    let file = File::open("AesKeyExpCstrnts.json").unwrap();
    let database: Vec<AesKeyExpCstrnts> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let fields_v = data
                .v
                .iter()
                .map(|v| GF128::new(v[0] as u128 + ((v[1] as u128) << 64), 0))
                .collect();
            let mkey = data.mkey != 0;
            let fields_q = data
                .q
                .iter()
                .map(|q| GF128::new(q[0] as u128 + ((q[1] as u128) << 64), 0))
                .collect();
            let delta = GF128::new(
                data.delta
                    .iter()
                    .enumerate()
                    .map(|(i, x)| (*x as u128) << (8 * i))
                    .sum(),
                0,
            );
            let field_ab: Vec<(GF128, GF128)> = data
                .ab
                .iter()
                .map(|a| {
                    (
                        GF128::new(a[0] as u128 + ((a[1] as u128) << 64), 0),
                        GF128::new(a[4] as u128 + ((a[5] as u128) << 64), 0),
                    )
                })
                .collect();
            let fields_res_1: Vec<GF128> = convert_to_bit(&data.res1);
            let fields_res_2: Vec<GF128> = data
                .res2
                .iter()
                .map(|res| GF128::new(res[0] as u128 + ((res[1] as u128) << 64), 0))
                .collect();
            let paramowf = ParamOWF::set_paramowf(data.kc, 10, data.ske, 0, 0, 0, 0, 0, 0, Some(0));
            let mut res = aes_key_exp_cstrnts(data.w, fields_v, mkey, fields_q, delta, paramowf);
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
            let fields_v = data
                .v
                .iter()
                .map(|v| GF192::new(v[0] as u128 + ((v[1] as u128) << 64), v[2] as u128))
                .collect();
            let mkey = data.mkey != 0;
            let fields_q = data
                .q
                .iter()
                .map(|q| GF192::new(q[0] as u128 + ((q[1] as u128) << 64), q[2] as u128))
                .collect();
            let delta = GF192::new(
                data.delta
                    .iter()
                    .take(16)
                    .enumerate()
                    .map(|(i, x)| (*x as u128) << (8 * i))
                    .sum(),
                data.delta
                    .iter()
                    .skip(16)
                    .enumerate()
                    .map(|(i, x)| (*x as u128) << (8 * i))
                    .sum(),
            );
            let field_ab: Vec<(GF192, GF192)> = data
                .ab
                .iter()
                .map(|a| {
                    (
                        GF192::new(a[0] as u128 + ((a[1] as u128) << 64), a[2] as u128),
                        GF192::new(a[4] as u128 + ((a[5] as u128) << 64), a[6] as u128),
                    )
                })
                .collect();
            let fields_res_1: Vec<GF192> = convert_to_bit(&data.res1);
            let fields_res_2: Vec<GF192> = data
                .res2
                .iter()
                .map(|w| GF192::new(w[0] as u128 + ((w[1] as u128) << 64), w[2] as u128))
                .collect();
            let paramowf = ParamOWF::set_paramowf(data.kc, 12, data.ske, 0, 0, 0, 0, 0, 0, Some(0));
            let mut res = aes_key_exp_cstrnts(data.w, fields_v, mkey, fields_q, delta, paramowf);
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
            let fields_v = data
                .v
                .iter()
                .map(|v| {
                    GF256::new(
                        v[0] as u128 + ((v[1] as u128) << 64),
                        v[2] as u128 + ((v[3] as u128) << 64),
                    )
                })
                .collect();
            let mkey = data.mkey != 0;
            let fields_q = data
                .q
                .iter()
                .map(|q| {
                    GF256::new(
                        q[0] as u128 + ((q[1] as u128) << 64),
                        q[2] as u128 + ((q[3] as u128) << 64),
                    )
                })
                .collect();
            let delta = GF256::new(
                data.delta
                    .iter()
                    .take(16)
                    .enumerate()
                    .map(|(i, x)| (*x as u128) << (8 * i))
                    .sum(),
                data.delta
                    .iter()
                    .skip(16)
                    .enumerate()
                    .map(|(i, x)| (*x as u128) << (8 * i))
                    .sum(),
            );
            let field_ab: Vec<(GF256, GF256)> = data
                .ab
                .iter()
                .map(|a| {
                    (
                        GF256::new(
                            a[0] as u128 + ((a[1] as u128) << 64),
                            a[2] as u128 + ((a[3] as u128) << 64),
                        ),
                        GF256::new(
                            a[4] as u128 + ((a[5] as u128) << 64),
                            a[6] as u128 + ((a[7] as u128) << 64),
                        ),
                    )
                })
                .collect();
            let fields_res_1: Vec<GF256> = convert_to_bit(&data.res1);
            let fields_res_2: Vec<GF256> = data
                .res2
                .iter()
                .map(|w| {
                    GF256::new(
                        w[0] as u128 + ((w[1] as u128) << 64),
                        w[2] as u128 + ((w[3] as u128) << 64),
                    )
                })
                .collect();
            let paramowf = ParamOWF::set_paramowf(data.kc, 14, data.ske, 0, 0, 0, 0, 0, 0, Some(0));
            let mut res = aes_key_exp_cstrnts(data.w, fields_v, mkey, fields_q, delta, paramowf);
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
