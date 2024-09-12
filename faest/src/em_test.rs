use std::fs::File;

use generic_array::GenericArray;
use serde::Deserialize;
use typenum::{U1, U8};

use crate::{
    aes::convert_to_bit,
    em::{em_enc_bkwd, em_enc_cstrnts, em_enc_fwd, em_extendedwitness, em_prove, em_verify},
    fields::{BigGaloisField, GF128, GF192, GF256},
    parameter::{
        PARAM128FEM, PARAM128SEM, PARAM192FEM, PARAM192SEM, PARAM256FEM, PARAM256SEM, PARAMOWF128,
        PARAMOWF128EM, PARAMOWF192EM, PARAMOWF256EM,
    },
};

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
    let file = File::open("EM-ExtendedWitness.json").unwrap();
    let database: Vec<EmExtendedWitness> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let res = em_extendedwitness::<PARAM128SEM, PARAMOWF128EM>(
                GenericArray::from_slice(&data.key),
                GenericArray::from_slice(&data.input),
            );
            assert_eq!(res.0, Box::new(*GenericArray::from_slice(&data.w)));
        } else if data.lambda == 192 {
            let res = em_extendedwitness::<PARAM192SEM, PARAMOWF192EM>(
                GenericArray::from_slice(&data.key),
                GenericArray::from_slice(&[data.input, vec![0u8; 16]].concat()),
            );
            assert_eq!(res.0, Box::new(*GenericArray::from_slice(&data.w)));
        } else {
            let res = em_extendedwitness::<PARAM256SEM, PARAMOWF256EM>(
                GenericArray::from_slice(&data.key),
                GenericArray::from_slice(&[data.input, vec![0u8; 32]].concat()),
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
    let file = File::open("EmEncFwd.json").unwrap();
    let database: Vec<EmEncFwd> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let (input_x, input_z): (Vec<GF128>, Vec<GF128>) = if data.m == 1 {
                (
                    data.x
                        .iter()
                        .flat_map(|x| {
                            convert_to_bit::<PARAMOWF128, U8, U1>(GenericArray::from_slice(
                                &x[0].to_le_bytes()[..1],
                            ))
                        })
                        .collect(),
                    data.z
                        .iter()
                        .flat_map(|z| {
                            convert_to_bit::<PARAMOWF128, U8, U1>(GenericArray::from_slice(
                                &z[0].to_le_bytes()[..1],
                            ))
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
                            convert_to_bit::<PARAMOWF192EM, U8, U1>(GenericArray::from_slice(
                                &x[0].to_le_bytes()[..1],
                            ))
                        })
                        .collect(),
                    data.z
                        .iter()
                        .flat_map(|z| {
                            convert_to_bit::<PARAMOWF192EM, U8, U1>(GenericArray::from_slice(
                                &z[0].to_le_bytes()[..1],
                            ))
                        })
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
                        .map(|z| GF192::new(z[0] as u128 + ((z[1] as u128) << 64), z[2] as u128))
                        .collect::<Vec<GF192>>()
                ))
            )
        } else {
            let (input_x, input_z): (Vec<GF256>, Vec<GF256>) = if data.m == 1 {
                (
                    data.x
                        .iter()
                        .flat_map(|x| {
                            convert_to_bit::<PARAMOWF256EM, U8, U1>(GenericArray::from_slice(
                                &x[0].to_le_bytes()[..1],
                            ))
                        })
                        .collect(),
                    data.z
                        .iter()
                        .flat_map(|z| {
                            convert_to_bit::<PARAMOWF256EM, U8, U1>(GenericArray::from_slice(
                                &z[0].to_le_bytes()[..1],
                            ))
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
    let file = File::open("EmEncBkwd.json").unwrap();
    let database: Vec<EmEncBkwd> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let (x_in, z_in, z_out_in): (Vec<GF128>, Vec<GF128>, Vec<GF128>) = if data.m == 1 {
                (
                    data.x
                        .iter()
                        .flat_map(|x| {
                            convert_to_bit::<PARAMOWF128, U8, U1>(GenericArray::from_slice(
                                &x[0].to_le_bytes()[..1],
                            ))
                        })
                        .collect::<Vec<GF128>>(),
                    data.z
                        .iter()
                        .flat_map(|z| {
                            convert_to_bit::<PARAMOWF128, U8, U1>(GenericArray::from_slice(
                                &z[0].to_le_bytes()[..1],
                            ))
                        })
                        .collect::<Vec<GF128>>(),
                    data.zout
                        .iter()
                        .flat_map(|z| {
                            convert_to_bit::<PARAMOWF128, U8, U1>(GenericArray::from_slice(
                                &z[0].to_le_bytes()[..1],
                            ))
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
                            convert_to_bit::<PARAMOWF192EM, U8, U1>(GenericArray::from_slice(
                                &x[0].to_le_bytes()[..1],
                            ))
                        })
                        .collect::<Vec<GF192>>(),
                    data.z
                        .iter()
                        .flat_map(|z| {
                            convert_to_bit::<PARAMOWF192EM, U8, U1>(GenericArray::from_slice(
                                &z[0].to_le_bytes()[..1],
                            ))
                        })
                        .collect::<Vec<GF192>>(),
                    data.zout
                        .iter()
                        .flat_map(|z| {
                            convert_to_bit::<PARAMOWF192EM, U8, U1>(GenericArray::from_slice(
                                &z[0].to_le_bytes()[..1],
                            ))
                        })
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
                        .map(|z| GF192::new(z[0] as u128 + ((z[1] as u128) << 64), z[2] as u128))
                        .collect::<Vec<GF192>>()
                ))
            )
        } else {
            let (x_in, z_in, z_out_in) = if data.m == 1 {
                (
                    data.x
                        .iter()
                        .flat_map(|x| {
                            convert_to_bit::<PARAMOWF256EM, U8, U1>(GenericArray::from_slice(
                                &x[0].to_le_bytes()[..1],
                            ))
                        })
                        .collect::<Vec<GF256>>(),
                    data.z
                        .iter()
                        .flat_map(|z| {
                            convert_to_bit::<PARAMOWF256EM, U8, U1>(GenericArray::from_slice(
                                &z[0].to_le_bytes()[..1],
                            ))
                        })
                        .collect::<Vec<GF256>>(),
                    data.zout
                        .iter()
                        .flat_map(|z| {
                            convert_to_bit::<PARAMOWF256EM, U8, U1>(GenericArray::from_slice(
                                &z[0].to_le_bytes()[..1],
                            ))
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
            let res = em_enc_cstrnts::<PARAM128SEM, PARAMOWF128EM>(
                GenericArray::from_slice(&data.out),
                GenericArray::from_slice(&data.x),
                GenericArray::from_slice(&data.w),
                GenericArray::from_slice(&vq),
                GenericArray::from_slice(&vq),
                data.mkey != 0,
                GF128::to_field(&data.delta)[0],
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
                GenericArray::from_slice(&vq),
                GenericArray::from_slice(&vq),
                data.mkey != 0,
                GF192::to_field(&data.delta)[0],
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
                GenericArray::from_slice(&vq),
                GenericArray::from_slice(&vq),
                data.mkey != 0,
                GF256::to_field(&data.delta)[0],
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
            let res = em_prove::<PARAM128SEM, PARAMOWF128EM>(
                GenericArray::from_slice(&data.w),
                &GenericArray::from_slice(&[[0u8; 160].to_vec(), data.u].concat()),
                GenericArray::from_slice(
                    &data
                        .gv
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec<GenericArray<u8, _>>>(),
                ),
                GenericArray::from_slice(&[data.input, data.output].concat()),
                GenericArray::from_slice(&data.chall),
            );
            assert_eq!(
                (
                    Box::new(*GenericArray::from_slice(&data.at)),
                    Box::new(*GenericArray::from_slice(&data.bt))
                ),
                res
            );
            break;
        } else if data.lambda == 192 {
            let res = em_prove::<PARAM192SEM, PARAMOWF192EM>(
                GenericArray::from_slice(&data.w),
                &GenericArray::from_slice(&[[0u8; 288].to_vec(), data.u].concat()),
                GenericArray::from_slice(
                    &data
                        .gv
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec<GenericArray<u8, _>>>(),
                ),
                GenericArray::from_slice(&[data.input, data.output].concat()),
                GenericArray::from_slice(&data.chall),
            );
            assert_eq!(
                (
                    Box::new(*GenericArray::from_slice(&data.at)),
                    Box::new(*GenericArray::from_slice(&data.bt))
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
                GenericArray::from_slice(&[data.input, data.output].concat()),
                GenericArray::from_slice(&data.chall),
            );
            assert_eq!(
                (
                    Box::new(*GenericArray::from_slice(&data.at)),
                    Box::new(*GenericArray::from_slice(&data.bt))
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
    let file = File::open("EmVerify.json").unwrap();
    let database: Vec<EmVerify> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambda == 128 {
            let res = if data.tau == 11 {
                em_verify::<PARAM128SEM, PARAMOWF128EM>(
                    GenericArray::from_slice(&data.d),
                    &mut GenericArray::from_slice(
                        &data
                            .gq
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.at),
                    GenericArray::from_slice(&data.chall2),
                    GenericArray::from_slice(&data.chall3),
                    GenericArray::from_slice(&[data.input, data.output].concat()),
                )
            } else {
                em_verify::<PARAM128FEM, PARAMOWF128EM>(
                    GenericArray::from_slice(&data.d),
                    &mut GenericArray::from_slice(
                        &data
                            .gq
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.at),
                    GenericArray::from_slice(&data.chall2),
                    GenericArray::from_slice(&data.chall3),
                    GenericArray::from_slice(&[data.input, data.output].concat()),
                )
            };
            assert_eq!(res, *GenericArray::from_slice(&data.qt));
        } else if data.lambda == 192 {
            let res = if data.tau == 16 {
                em_verify::<PARAM192SEM, PARAMOWF192EM>(
                    GenericArray::from_slice(&data.d),
                    &mut GenericArray::from_slice(
                        &data
                            .gq
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.at),
                    GenericArray::from_slice(&data.chall2),
                    GenericArray::from_slice(&data.chall3),
                    GenericArray::from_slice(&[data.input, data.output].concat()),
                )
            } else {
                em_verify::<PARAM192FEM, PARAMOWF192EM>(
                    GenericArray::from_slice(&data.d),
                    &mut GenericArray::from_slice(
                        &data
                            .gq
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.at),
                    GenericArray::from_slice(&data.chall2),
                    GenericArray::from_slice(&data.chall3),
                    GenericArray::from_slice(&[data.input, data.output].concat()),
                )
            };
            assert_eq!(res, *GenericArray::from_slice(&data.qt));
        } else {
            let res = if data.tau == 22 {
                em_verify::<PARAM256SEM, PARAMOWF256EM>(
                    GenericArray::from_slice(&data.d),
                    &mut GenericArray::from_slice(
                        &data
                            .gq
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.at),
                    GenericArray::from_slice(&data.chall2),
                    GenericArray::from_slice(&data.chall3),
                    GenericArray::from_slice(&[data.input, data.output].concat()),
                )
            } else {
                em_verify::<PARAM256FEM, PARAMOWF256EM>(
                    GenericArray::from_slice(&data.d),
                    &mut GenericArray::from_slice(
                        &data
                            .gq
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.at),
                    GenericArray::from_slice(&data.chall2),
                    GenericArray::from_slice(&data.chall3),
                    GenericArray::from_slice(&[data.input, data.output].concat()),
                )
            };
            assert_eq!(res, *GenericArray::from_slice(&data.qt));
        }
    }
}
