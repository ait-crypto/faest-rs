use std::fs::File;

use generic_array::{sequence::GenericSequence, GenericArray};
use serde::Deserialize;
use typenum::{U16, U234, U24, U32, U458, U566};

use crate::{
    parameter::{
        self, PARAM128F, PARAM128FEM, PARAM128S, PARAM128SEM, PARAM192F, PARAM192FEM, PARAM192S,
        PARAM192SEM, PARAM256F, PARAM256FEM, PARAM256S, PARAM256SEM,
    },
    random_oracles::{
        self, RandomOracle, RandomOracleShake128, RandomOracleShake192, RandomOracleShake256,
    },
    vole::{chaldec, to_vole_convert, volecommit, volereconstruct},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DataConvertToVole {
    sd: Vec<Vec<u8>>,

    iv: [u8; 16],

    lh: [usize; 1],

    lambdabytes: [u8; 1],

    sd0: [u8; 1],

    u: Vec<u8>,

    v: Vec<Vec<u8>>,
}

#[test]
fn convert_to_vole_test() {
    let data = include_str!("../DataConvertToVole.json");
    let database: Vec<DataConvertToVole> =
        serde_json::from_str(data).expect("error while reading or parsing");
    for data in database {
        if data.lambdabytes[0] == 16 {
            let mut opt_sd: Vec<Option<GenericArray<u8, U16>>> = data
                .sd
                .iter()
                .cloned()
                .map(|x| Some(*GenericArray::from_slice(&x)))
                .collect::<Vec<Option<GenericArray<u8, U16>>>>();
            if data.sd0[0] == 1 {
                opt_sd[0] = None;
            }
            type LH = U234;
            let res = to_vole_convert::<RandomOracleShake128, LH>(&opt_sd, &data.iv);
            assert_eq!(res.0, *GenericArray::from_slice(&data.u));
            assert_eq!(
                res.1,
                data.v
                    .iter()
                    .map(|x| *GenericArray::from_slice(&x))
                    .collect::<Vec<GenericArray<u8, LH>>>()
            );
        } else if data.lambdabytes[0] == 24 {
            let mut opt_sd: Vec<Option<GenericArray<u8, U24>>> = data
                .sd
                .iter()
                .cloned()
                .map(|x| Some(GenericArray::default()))
                .collect::<Vec<Option<GenericArray<u8, U24>>>>();
            if data.sd0[0] == 1 {
                opt_sd[0] = None;
            }
            type LH = U458;
            let res = to_vole_convert::<RandomOracleShake192, LH>(&opt_sd, &data.iv);
            assert_eq!(res.0, *GenericArray::from_slice(&data.u));
            assert_eq!(
                res.1,
                data.v
                    .iter()
                    .map(|x| *GenericArray::from_slice(&x))
                    .collect::<Vec<GenericArray<u8, LH>>>()
            );
        } else {
            let mut opt_sd: Vec<Option<GenericArray<u8, U32>>> = data
                .sd
                .iter()
                .cloned()
                .map(|x| Some(GenericArray::default()))
                .collect::<Vec<Option<GenericArray<u8, U32>>>>();
            if data.sd0[0] == 1 {
                opt_sd[0] = None;
            }
            type LH = U566;
            let res = to_vole_convert::<RandomOracleShake256, LH>(&opt_sd, &data.iv);
            assert_eq!(res.0, *GenericArray::from_slice(&data.u));
            assert_eq!(
                res.1,
                data.v
                    .iter()
                    .map(|x| *GenericArray::from_slice(&x))
                    .collect::<Vec<GenericArray<u8, LH>>>()
            );
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DataChalDec {
    chal: Vec<u8>,
    i: [u16; 1],
    k0: [u16; 1],
    t0: [u16; 1],
    k1: [u16; 1],
    t1: [u16; 1],
    res: Vec<u8>,
}

#[test]
fn chaldec_test() {
    let file = File::open("DataChalDec.json").unwrap();
    let database: Vec<DataChalDec> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.chal.len() == 16 {
            if data.k0[0] == 12 {
                let res =
                    chaldec::<PARAM128S>(GenericArray::<u8, _>::from_slice(&data.chal), data.i[0]);
                assert_eq!(res, data.res);
            } else {
                let res =
                    chaldec::<PARAM128F>(GenericArray::<u8, _>::from_slice(&data.chal), data.i[0]);
                assert_eq!(res, data.res);
            }
        } else if data.chal.len() == 24 {
            if data.k0[0] == 12 {
                let res =
                    chaldec::<PARAM192S>(GenericArray::<u8, _>::from_slice(&data.chal), data.i[0]);
                assert_eq!(res, data.res);
            } else {
                let res =
                    chaldec::<PARAM192F>(GenericArray::<u8, _>::from_slice(&data.chal), data.i[0]);
                assert_eq!(res, data.res);
            }
        } else if data.k0[0] == 12 {
            let res =
                chaldec::<PARAM256S>(GenericArray::<u8, _>::from_slice(&data.chal), data.i[0]);
            assert_eq!(res, data.res);
        } else {
            let res =
                chaldec::<PARAM256F>(GenericArray::<u8, _>::from_slice(&data.chal), data.i[0]);
            assert_eq!(res, data.res);
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DataVoleCommit {
    r: Vec<u8>,

    iv: [u8; 16],

    lh: [usize; 1],

    lambdabytes: [u16; 1],

    tau: [usize; 1],

    k0: [u8; 1],

    k1: [u8; 1],

    hcom: Vec<u8>,

    k: Vec<Vec<Vec<u8>>>,

    com: Vec<Vec<Vec<u8>>>,

    c: Vec<Vec<u8>>,

    u: Vec<u8>,

    v: Vec<Vec<Vec<u8>>>,
}

#[test]
fn volecommit_test() {
    let file = File::open("DataVoleCommit.json").unwrap();
    let database: Vec<DataVoleCommit> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambdabytes[0] == 16 {
            if data.u.len() == 234 {
                if data.k0[0] == 12 {
                    let res = volecommit::<PARAM128S, RandomOracleShake128>(
                        &GenericArray::from_slice(&data.r),
                        &data.iv,
                    );
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                    for i in 0..res.1.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    for i in 0..data.com.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    assert_eq!(
                        res.2,
                        data.c
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect()
                    );
                    assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                    assert_eq!(
                        res.4,
                        data.v
                            .iter()
                            .map(|x| x.iter().map(|y| *GenericArray::from_slice(&y)).collect())
                            .collect()
                    );
                } else {
                    let res = volecommit::<PARAM128F, RandomOracleShake128>(
                        &GenericArray::from_slice(&data.r),
                        &data.iv,
                    );
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                    for i in 0..res.1.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    for i in 0..data.com.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    assert_eq!(
                        res.2,
                        data.c
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect()
                    );
                    assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                    assert_eq!(
                        res.4,
                        data.v
                            .iter()
                            .map(|x| x.iter().map(|y| *GenericArray::from_slice(&y)).collect())
                            .collect()
                    );
                }
            } else if data.k0[0] == 12 {
                let res = volecommit::<PARAM128SEM, RandomOracleShake128>(
                    &GenericArray::from_slice(&data.r),
                    &data.iv,
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                for i in 0..data.com.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                assert_eq!(
                    res.2,
                    data.c
                        .iter()
                        .map(|x| *GenericArray::from_slice(&x))
                        .collect()
                );
                assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                assert_eq!(
                    res.4,
                    data.v
                        .iter()
                        .map(|x| x.iter().map(|y| *GenericArray::from_slice(&y)).collect())
                        .collect()
                );
            } else {
                let res = volecommit::<PARAM128FEM, RandomOracleShake128>(
                    &GenericArray::from_slice(&data.r),
                    &data.iv,
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                for i in 0..data.com.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                assert_eq!(
                    res.2,
                    data.c
                        .iter()
                        .map(|x| *GenericArray::from_slice(&x))
                        .collect()
                );
                assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                assert_eq!(
                    res.4,
                    data.v
                        .iter()
                        .map(|x| x.iter().map(|y| *GenericArray::from_slice(&y)).collect())
                        .collect()
                );
            }
        } else if data.lambdabytes[0] == 24 {
            if data.u.len() == 458 {
                if data.k0[0] == 12 {
                    let res = volecommit::<PARAM192S, RandomOracleShake192>(
                        &GenericArray::from_slice(&data.r),
                        &data.iv,
                    );
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                    for i in 0..res.1.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    for i in 0..data.com.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    assert_eq!(
                        res.2,
                        data.c
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect()
                    );
                    assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                    assert_eq!(
                        res.4,
                        data.v
                            .iter()
                            .map(|x| x.iter().map(|y| *GenericArray::from_slice(&y)).collect())
                            .collect()
                    );
                } else {
                    let res = volecommit::<PARAM192F, RandomOracleShake192>(
                        &GenericArray::from_slice(&data.r),
                        &data.iv,
                    );
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                    for i in 0..res.1.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    for i in 0..data.com.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(&x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    assert_eq!(
                        res.2,
                        data.c
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect()
                    );
                    assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                    assert_eq!(
                        res.4,
                        data.v
                            .iter()
                            .map(|x| x.iter().map(|y| *GenericArray::from_slice(&y)).collect())
                            .collect()
                    );
                }
            } else if data.k0[0] == 12 {
                let res = volecommit::<PARAM192SEM, RandomOracleShake192>(
                    &GenericArray::from_slice(&data.r),
                    &data.iv,
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                for i in 0..data.com.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                assert_eq!(
                    res.2,
                    data.c
                        .iter()
                        .map(|x| *GenericArray::from_slice(&x))
                        .collect()
                );
                assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                assert_eq!(
                    res.4,
                    data.v
                        .iter()
                        .map(|x| x.iter().map(|y| *GenericArray::from_slice(&y)).collect())
                        .collect()
                );
            } else {
                let res = volecommit::<PARAM192FEM, RandomOracleShake192>(
                    &GenericArray::from_slice(&data.r),
                    &data.iv,
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                for i in 0..data.com.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                assert_eq!(
                    res.2,
                    data.c
                        .iter()
                        .map(|x| *GenericArray::from_slice(&x))
                        .collect()
                );
                assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                assert_eq!(
                    res.4,
                    data.v
                        .iter()
                        .map(|x| x.iter().map(|y| *GenericArray::from_slice(&y)).collect())
                        .collect()
                );
            }
        } else if data.u.len() == 566 {
            if data.k0[0] == 12 {
                let res = volecommit::<PARAM256S, RandomOracleShake256>(
                    &GenericArray::from_slice(&data.r),
                    &data.iv,
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                for i in 0..data.com.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                assert_eq!(
                    res.2,
                    data.c
                        .iter()
                        .map(|x| *GenericArray::from_slice(&x))
                        .collect()
                );
                assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                assert_eq!(
                    res.4,
                    data.v
                        .iter()
                        .map(|x| x.iter().map(|y| *GenericArray::from_slice(&y)).collect())
                        .collect()
                );
            } else {
                let res = volecommit::<PARAM256F, RandomOracleShake256>(
                    &GenericArray::from_slice(&data.r),
                    &data.iv,
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                for i in 0..data.com.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(&x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                assert_eq!(
                    res.2,
                    data.c
                        .iter()
                        .map(|x| *GenericArray::from_slice(&x))
                        .collect()
                );
                assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                assert_eq!(
                    res.4,
                    data.v
                        .iter()
                        .map(|x| x.iter().map(|y| *GenericArray::from_slice(&y)).collect())
                        .collect()
                );
            }
        } else if data.k0[0] == 12 {
            let res = volecommit::<PARAM256SEM, RandomOracleShake256>(
                &GenericArray::from_slice(&data.r),
                &data.iv,
            );
            assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
            for i in 0..res.1.len() {
                assert_eq!(
                    res.1[i],
                    (
                        data.k[i]
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect::<Vec<GenericArray<u8, _>>>()
                            .clone(),
                        data.com[i]
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect::<Vec<GenericArray<u8, _>>>()
                            .clone()
                    )
                );
            }
            for i in 0..data.com.len() {
                assert_eq!(
                    res.1[i],
                    (
                        data.k[i]
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect::<Vec<GenericArray<u8, _>>>()
                            .clone(),
                        data.com[i]
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect::<Vec<GenericArray<u8, _>>>()
                            .clone()
                    )
                );
            }
            assert_eq!(
                res.2,
                data.c
                    .iter()
                    .map(|x| *GenericArray::from_slice(&x))
                    .collect()
            );
            assert_eq!(res.3, *GenericArray::from_slice(&data.u));
            assert_eq!(
                res.4,
                data.v
                    .iter()
                    .map(|x| x.iter().map(|y| *GenericArray::from_slice(&y)).collect())
                    .collect()
            );
        } else {
            let res = volecommit::<PARAM256FEM, RandomOracleShake256>(
                &GenericArray::from_slice(&data.r),
                &data.iv,
            );
            assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
            for i in 0..res.1.len() {
                assert_eq!(
                    res.1[i],
                    (
                        data.k[i]
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect::<Vec<GenericArray<u8, _>>>()
                            .clone(),
                        data.com[i]
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect::<Vec<GenericArray<u8, _>>>()
                            .clone()
                    )
                );
            }
            for i in 0..data.com.len() {
                assert_eq!(
                    res.1[i],
                    (
                        data.k[i]
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect::<Vec<GenericArray<u8, _>>>()
                            .clone(),
                        data.com[i]
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect::<Vec<GenericArray<u8, _>>>()
                            .clone()
                    )
                );
            }
            assert_eq!(
                res.2,
                data.c
                    .iter()
                    .map(|x| *GenericArray::from_slice(&x))
                    .collect()
            );
            assert_eq!(res.3, *GenericArray::from_slice(&data.u));
            assert_eq!(
                res.4,
                data.v
                    .iter()
                    .map(|x| x.iter().map(|y| *GenericArray::from_slice(&y)).collect())
                    .collect()
            );
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DataVoleReconstruct {
    chal: Vec<u8>,

    pdec: Vec<Vec<Vec<u8>>>,

    com: Vec<Vec<u8>>,

    iv: [u8; 16],

    hcom: Vec<u8>,

    q: Vec<Vec<Vec<u8>>>,
}

#[test]
fn volereconstruct_test() {
    let file = File::open("DataVoleReconstruct.json").unwrap();
    let database: Vec<DataVoleReconstruct> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.chal.len() == 16 {
            if data.q[0].len() == 8 {
                let mut pdecom : GenericArray<(Vec<GenericArray<u8, <random_oracles::RandomOracleShake128 as random_oracles::RandomOracle>::LAMBDA>>, GenericArray<u8, <random_oracles::RandomOracleShake128 as random_oracles::RandomOracle>::PRODLAMBDA2>), <parameter::PARAM128F as parameter::PARAM>::TAU> = GenericArray::default();
                for i in 0..data.pdec.len() {
                    pdecom[i] = (
                        data.pdec[i]
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect(),
                        *GenericArray::from_slice(&data.com[i]),
                    );
                }
                let res = volereconstruct::<RandomOracleShake128, PARAM128F>(
                    GenericArray::from_slice(&data.chal),
                    &pdecom,
                    data.iv,
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(res.1[i].len(), data.q[i].len());
                }
            } else {
                let mut pdecom : GenericArray<(Vec<GenericArray<u8, <random_oracles::RandomOracleShake128 as random_oracles::RandomOracle>::LAMBDA>>, GenericArray<u8, <random_oracles::RandomOracleShake128 as random_oracles::RandomOracle>::PRODLAMBDA2>), <parameter::PARAM128S as parameter::PARAM>::TAU> = GenericArray::default();
                for i in 0..data.pdec.len() {
                    pdecom[i] = (
                        data.pdec[i]
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect(),
                        *GenericArray::from_slice(&data.com[i]),
                    );
                }
                let res = volereconstruct::<RandomOracleShake128, PARAM128S>(
                    GenericArray::from_slice(&data.chal),
                    GenericArray::from_slice(
                        &pdecom
                            .iter()
                            .map(|x| {
                                (
                                    x.0.iter().map(|y| *GenericArray::from_slice(y)).collect(),
                                    *GenericArray::from_slice(&x.1),
                                )
                            })
                            .collect::<Vec<(
                                Vec<
                                    GenericArray<
                                        u8,
                                        <RandomOracleShake128 as RandomOracle>::LAMBDA,
                                    >,
                                >,
                                GenericArray<
                                    u8,
                                    <RandomOracleShake128 as RandomOracle>::PRODLAMBDA2,
                                >,
                            )>>(),
                    ),
                    data.iv,
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(res.1[i].len(), data.q[i].len());
                }
            }
        } else if data.chal.len() == 24 {
            if data.q[0].len() == 8 {
                let mut pdecom : GenericArray<(Vec<GenericArray<u8, <random_oracles::RandomOracleShake192 as random_oracles::RandomOracle>::LAMBDA>>, GenericArray<u8, <random_oracles::RandomOracleShake192 as random_oracles::RandomOracle>::PRODLAMBDA2>), <parameter::PARAM192F as parameter::PARAM>::TAU> = GenericArray::default();
                for i in 0..data.pdec.len() {
                    pdecom[i] = (
                        data.pdec[i]
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect(),
                        *GenericArray::from_slice(&data.com[i]),
                    );
                }
                let res = volereconstruct::<RandomOracleShake192, PARAM192F>(
                    GenericArray::from_slice(&data.chal),
                    &pdecom,
                    data.iv,
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(res.1[i].len(), data.q[i].len());
                }
            } else {
                let mut pdecom : GenericArray<(Vec<GenericArray<u8, <random_oracles::RandomOracleShake192 as random_oracles::RandomOracle>::LAMBDA>>, GenericArray<u8, <random_oracles::RandomOracleShake192 as random_oracles::RandomOracle>::PRODLAMBDA2>), <parameter::PARAM192S as parameter::PARAM>::TAU> = GenericArray::default();
                for i in 0..data.pdec.len() {
                    pdecom[i] = (
                        data.pdec[i]
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect(),
                        *GenericArray::from_slice(&data.com[i]),
                    );
                }
                let res = volereconstruct::<RandomOracleShake192, PARAM192S>(
                    GenericArray::from_slice(&data.chal),
                    GenericArray::from_slice(
                        &pdecom
                            .iter()
                            .map(|x| {
                                (
                                    x.0.iter().map(|y| *GenericArray::from_slice(y)).collect(),
                                    *GenericArray::from_slice(&x.1),
                                )
                            })
                            .collect::<Vec<(
                                Vec<
                                    GenericArray<
                                        u8,
                                        <RandomOracleShake192 as RandomOracle>::LAMBDA,
                                    >,
                                >,
                                GenericArray<
                                    u8,
                                    <RandomOracleShake192 as RandomOracle>::PRODLAMBDA2,
                                >,
                            )>>(),
                    ),
                    data.iv,
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(res.1[i].len(), data.q[i].len());
                }
            }
        } else if data.q[0].len() == 8 {
            let mut pdecom : GenericArray<(Vec<GenericArray<u8, <random_oracles::RandomOracleShake256 as random_oracles::RandomOracle>::LAMBDA>>, GenericArray<u8, <random_oracles::RandomOracleShake256 as random_oracles::RandomOracle>::PRODLAMBDA2>), <parameter::PARAM256F as parameter::PARAM>::TAU> = GenericArray::default();
            for i in 0..data.pdec.len() {
                pdecom[i] = (
                    data.pdec[i]
                        .iter()
                        .map(|x| *GenericArray::from_slice(&x))
                        .collect(),
                    *GenericArray::from_slice(&data.com[i]),
                );
            }
            let res = volereconstruct::<RandomOracleShake256, PARAM256F>(
                GenericArray::from_slice(&data.chal),
                &pdecom,
                data.iv,
            );
            assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
            for i in 0..res.1.len() {
                assert_eq!(res.1[i].len(), data.q[i].len());
            }
        } else {
            let mut pdecom : GenericArray<(Vec<GenericArray<u8, <random_oracles::RandomOracleShake256 as random_oracles::RandomOracle>::LAMBDA>>, GenericArray<u8, <random_oracles::RandomOracleShake256 as random_oracles::RandomOracle>::PRODLAMBDA2>), <parameter::PARAM256S as parameter::PARAM>::TAU> = GenericArray::default();
            for i in 0..data.pdec.len() {
                pdecom[i] = (
                    data.pdec[i]
                        .iter()
                        .map(|x| *GenericArray::from_slice(&x))
                        .collect(),
                    *GenericArray::from_slice(&data.com[i]),
                );
            }
            let res = volereconstruct::<RandomOracleShake256, PARAM256S>(
                GenericArray::from_slice(&data.chal),
                GenericArray::from_slice(
                    &pdecom
                        .iter()
                        .map(|x| {
                            (
                                x.0.iter().map(|y| *GenericArray::from_slice(y)).collect(),
                                *GenericArray::from_slice(&x.1),
                            )
                        })
                        .collect::<Vec<(
                            Vec<GenericArray<u8, <RandomOracleShake256 as RandomOracle>::LAMBDA>>,
                            GenericArray<u8, <RandomOracleShake256 as RandomOracle>::PRODLAMBDA2>,
                        )>>(),
                ),
                data.iv,
            );
            assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
            for i in 0..res.1.len() {
                assert_eq!(res.1[i].len(), data.q[i].len());
            }
        }
    }
}
