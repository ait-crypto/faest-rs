use std::fs::File;

use serde::Deserialize;

use crate::{
    aes::convert_to_bit,
    em::{em_enc_bkwd, em_enc_cstrnts, em_enc_fwd, em_prove, em_verify, em_extendedwitness},
    fields::{BigGaloisField, GF128, GF192, GF256},
    parameter::{
        self, Param, PARAM128F, PARAM128S, PARAM192F, PARAM192S, PARAM256F, PARAM256S, PARAMOWF128,
        PARAMOWF128EM, PARAMOWF192, PARAMOWF192EM, PARAMOWF256, PARAMOWF256EM,
    },
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmExtendedWitness {
    lambda: u16,

    l: u16,

    lke: u16,

    key: Vec<u8>,

    input: Vec<u8>,

    w: Vec<u8>,
}

#[test]
fn em_extended_witness_test() {
    let file = File::open("EM-ExtendedWitness.json").unwrap();
    let database: Vec<EmExtendedWitness> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let param = Param::set_param(128, data.l, 11, 12, 11, 1, 1, 16, 1);
            let mut paramowf = parameter::PARAMOWF128;
            paramowf.set_lke(data.lke);
            let res = em_extendedwitness(
                &data.key,
                &data.input,
                &param,
                &paramowf,
            );
            assert_eq!(res, data.w);
        } else if data.lambda == 192 {
            let param = Param::set_param(192, data.l, 16, 12, 12, 1, 1, 16, 2);
            let mut paramowf = parameter::PARAMOWF192;
            paramowf.set_lke(data.lke);
            let res = em_extendedwitness(
                &data.key,
                &data.input,
                &param,
                &paramowf,
            );
            assert_eq!(res, data.w);
        } else {
            let param = Param::set_param(256, data.l, 22, 12, 11, 1, 1, 16, 2);
            let mut paramowf = parameter::PARAMOWF256;
            paramowf.set_lke(data.lke);
            let res = em_extendedwitness(
                &data.key,
                &data.input,
                &param,
                &paramowf,
            );
            assert_eq!(res, data.w);
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
fn aes_enc_fwd_test() {
    let file = File::open("EmEncFwd.json").unwrap();
    let database: Vec<EmEncFwd> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let paramowf = PARAMOWF128;
            let (input_x, input_z): (Vec<GF128>, Vec<GF128>) = if data.m == 1 {
                (
                    data.x
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1]))
                        .collect(),
                    data.z
                        .iter()
                        .flat_map(|z| convert_to_bit(&z[0].to_le_bytes()[..1]))
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
            let res = em_enc_fwd(&input_z, &input_x, &paramowf);
            assert_eq!(
                res,
                data.res
                    .iter()
                    .map(|z| GF128::new(z[0] as u128 + ((z[1] as u128) << 64), 0))
                    .collect::<Vec<GF128>>()
            )
        } else if data.lambda == 192 {
            let paramowf = PARAMOWF192;
            let (input_x, input_z): (Vec<GF192>, Vec<GF192>) = if data.m == 1 {
                (
                    data.x
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1]))
                        .collect(),
                    data.z
                        .iter()
                        .flat_map(|z| convert_to_bit(&z[0].to_le_bytes()[..1]))
                        .collect(),
                )
            } else {
                (
                    data.x
                        .iter()
                        .map(|x| GF192::new(x[0] as u128 + ((x[1] as u128) << 64), x[2] as u128))
                        .collect(),
                    data.z
                        .iter()
                        .map(|z| GF192::new(z[0] as u128 + ((z[1] as u128) << 64), z[2] as u128))
                        .collect(),
                )
            };
            let res = em_enc_fwd(&input_z, &input_x, &paramowf);
            assert_eq!(
                res,
                data.res
                    .iter()
                    .map(|z| GF192::new(z[0] as u128 + ((z[1] as u128) << 64), z[2] as u128))
                    .collect::<Vec<GF192>>()
            )
        } else {
            let paramowf = PARAMOWF256;
            let (input_x, input_z): (Vec<GF256>, Vec<GF256>) = if data.m == 1 {
                (
                    data.x
                        .iter()
                        .flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1]))
                        .collect(),
                    data.z
                        .iter()
                        .flat_map(|z| convert_to_bit(&z[0].to_le_bytes()[..1]))
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
            let res = em_enc_fwd(&input_z, &input_x, &paramowf);
            assert_eq!(
                res,
                data.res
                    .iter()
                    .map(|z| GF256::new(
                        z[0] as u128 + ((z[1] as u128) << 64),
                        z[2] as u128 + ((z[3] as u128) << 64)
                    ))
                    .collect::<Vec<GF256>>()
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
fn aes_enc_bkwd_test() {
    let file = File::open("EmEncBkwd.json").unwrap();
    let database: Vec<EmEncBkwd> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let paramowf = PARAMOWF128EM;
            let param = PARAM128S;
            let (x_in, z_in, z_out_in) = if data.m == 1 {
                (
                    data.x
                        .iter()
                        .flat_map(|x| convert_to_bit::<GF128>(&x[0].to_le_bytes()[..1]))
                        .collect::<Vec<GF128>>(),
                    data.z
                        .iter()
                        .flat_map(|z| convert_to_bit::<GF128>(&z[0].to_le_bytes()[..1]))
                        .collect::<Vec<GF128>>(),
                    data.zout
                        .iter()
                        .flat_map(|z| convert_to_bit::<GF128>(&z[0].to_le_bytes()[..1]))
                        .collect::<Vec<GF128>>(),
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
                    data.zout
                        .iter()
                        .map(|z| GF128::new(z[0] as u128 + ((z[1] as u128) << 64), 0))
                        .collect(),
                )
            };
            let res = em_enc_bkwd::<GF128>(
                &x_in,
                &z_in,
                &z_out_in,
                data.mkey != 0,
                data.mtag != 0,
                GF128::from(&data.delta[..]),
                &paramowf,
                &param,
            );
            assert_eq!(
                res,
                data.res
                    .iter()
                    .map(|z| GF128::new(z[0] as u128 + ((z[1] as u128) << 64), 0))
                    .collect::<Vec<GF128>>()
            )
        } else if data.lambda == 192 {
            let paramowf = PARAMOWF192EM;
            let param = PARAM192S;
            let (x_in, z_in, z_out_in) = if data.m == 1 {
                (
                    data.x
                        .iter()
                        .flat_map(|x| convert_to_bit::<GF192>(&x[0].to_le_bytes()[..1]))
                        .collect::<Vec<GF192>>(),
                    data.z
                        .iter()
                        .flat_map(|z| convert_to_bit::<GF192>(&z[0].to_le_bytes()[..1]))
                        .collect::<Vec<GF192>>(),
                    data.zout
                        .iter()
                        .flat_map(|z| convert_to_bit::<GF192>(&z[0].to_le_bytes()[..1]))
                        .collect::<Vec<GF192>>(),
                )
            } else {
                (
                    data.x
                        .iter()
                        .map(|x| GF192::new(x[0] as u128 + ((x[1] as u128) << 64), x[2] as u128))
                        .collect(),
                    data.z
                        .iter()
                        .map(|z| GF192::new(z[0] as u128 + ((z[1] as u128) << 64), z[2] as u128))
                        .collect(),
                    data.zout
                        .iter()
                        .map(|z| GF192::new(z[0] as u128 + ((z[1] as u128) << 64), z[2] as u128))
                        .collect(),
                )
            };
            let res = em_enc_bkwd::<GF192>(
                &x_in,
                &z_in,
                &z_out_in,
                data.mkey != 0,
                data.mtag != 0,
                GF192::from(&data.delta[..]),
                &paramowf,
                &param,
            );
            assert_eq!(
                res,
                data.res
                    .iter()
                    .map(|z| GF192::new(z[0] as u128 + ((z[1] as u128) << 64), z[2] as u128))
                    .collect::<Vec<GF192>>()
            )
        } else {
            let paramowf = PARAMOWF256EM;
            let param = PARAM256S;
            let (x_in, z_in, z_out_in) = if data.m == 1 {
                (
                    data.x
                        .iter()
                        .flat_map(|x| convert_to_bit::<GF256>(&x[0].to_le_bytes()[..1]))
                        .collect::<Vec<GF256>>(),
                    data.z
                        .iter()
                        .flat_map(|z| convert_to_bit::<GF256>(&z[0].to_le_bytes()[..1]))
                        .collect::<Vec<GF256>>(),
                    data.zout
                        .iter()
                        .flat_map(|z| convert_to_bit::<GF256>(&z[0].to_le_bytes()[..1]))
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
            let res = em_enc_bkwd::<GF256>(
                &x_in,
                &z_in,
                &z_out_in,
                data.mkey != 0,
                data.mtag != 0,
                GF256::from(&data.delta[..]),
                &paramowf,
                &param,
            );
            assert_eq!(
                res,
                data.res
                    .iter()
                    .map(|z| GF256::new(
                        z[0] as u128 + ((z[1] as u128) << 64),
                        z[2] as u128 + ((z[3] as u128) << 64)
                    ))
                    .collect::<Vec<GF256>>()
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
    let file = File::open("EmEncCstrnts.json").unwrap();
    let database: Vec<EmEncCstrnts> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let vq = &data
                .vq
                .iter()
                .map(|v| GF128::new(v[0] as u128 + ((v[1] as u128) << 64), 0))
                .collect::<Vec<GF128>>()[..];
            let res = em_enc_cstrnts::<GF128>(
                &data.out,
                &data.x,
                &data.w,
                vq,
                vq,
                data.mkey != 0,
                GF128::to_field(&data.delta)[0],
                &PARAMOWF128EM,
                &PARAM128S,
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
            let res = em_enc_cstrnts::<GF192>(
                &data.out,
                &data.x,
                &data.w,
                vq,
                vq,
                data.mkey != 0,
                GF192::to_field(&data.delta)[0],
                &PARAMOWF192EM,
                &PARAM192S,
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
            let res = em_enc_cstrnts::<GF256>(
                &data.out,
                &data.x,
                &data.w,
                vq,
                vq,
                data.mkey != 0,
                GF256::to_field(&data.delta)[0],
                &PARAMOWF256EM,
                &PARAM256S,
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
    let file = File::open("EmProve.json").unwrap();
    let database: Vec<EmProve> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let res = em_prove::<GF128>(
                &data.w,
                &data.u,
                &data.gv,
                &[data.input, data.output].concat(),
                &data.chall,
                &PARAMOWF128EM,
                &PARAM128S,
            );
            assert_eq!((data.at, data.bt), res);
        } else if data.lambda == 192 {
            let res = em_prove::<GF192>(
                &data.w,
                &data.u,
                &data.gv,
                &[data.input, data.output].concat(),
                &data.chall,
                &PARAMOWF192EM,
                &PARAM192S,
            );
            assert_eq!((data.at, data.bt), res);
        } else {
            let res = em_prove::<GF256>(
                &data.w,
                &data.u,
                &data.gv,
                &[data.input, data.output].concat(),
                &data.chall,
                &PARAMOWF256EM,
                &PARAM256S,
            );
            assert_eq!((data.at, data.bt), res);
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
    let file = File::open("EmVerify.json").unwrap();
    let database: Vec<EmVerify> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let res = if data.tau == 11 {
                em_verify::<GF128>(
                    &data.d,
                    data.gq,
                    &data.at,
                    &data.chall2,
                    &data.chall3,
                    &[data.input, data.output].concat(),
                    &PARAMOWF128EM,
                    &PARAM128S,
                )
            } else {
                em_verify::<GF128>(
                    &data.d,
                    data.gq,
                    &data.at,
                    &data.chall2,
                    &data.chall3,
                    &[data.input, data.output].concat(),
                    &PARAMOWF128EM,
                    &PARAM128F,
                )
            };
            assert_eq!(res, data.qt);
        } else if data.lambda == 192 {
            let res = if data.tau == 16 {
                em_verify::<GF192>(
                    &data.d,
                    data.gq,
                    &data.at,
                    &data.chall2,
                    &data.chall3,
                    &[data.input, data.output].concat(),
                    &PARAMOWF192EM,
                    &PARAM192S,
                )
            } else {
                em_verify::<GF192>(
                    &data.d,
                    data.gq,
                    &data.at,
                    &data.chall2,
                    &data.chall3,
                    &[data.input, data.output].concat(),
                    &PARAMOWF192EM,
                    &PARAM192F,
                )
            };
            assert_eq!(res, data.qt);
        } else {
            let res = if data.tau == 22 {
                em_verify::<GF256>(
                    &data.d,
                    data.gq,
                    &data.at,
                    &data.chall2,
                    &data.chall3,
                    &[data.input, data.output].concat(),
                    &PARAMOWF256EM,
                    &PARAM256S,
                )
            } else {
                em_verify::<GF256>(
                    &data.d,
                    data.gq,
                    &data.at,
                    &data.chall2,
                    &data.chall3,
                    &[data.input, data.output].concat(),
                    &PARAMOWF256EM,
                    &PARAM256F,
                )
            };
            assert_eq!(res, data.qt);
        }
    }
}
