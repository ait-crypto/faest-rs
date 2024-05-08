#[cfg(test)]
use std::fs::File;

use serde::Deserialize;

use crate::{
    fields::{GF128, GF192, GF256},
    prg::{prg_128, prg_192, prg_256},
    random_oracles::{RandomOracleShake128, RandomOracleShake256},
    vole::{chaldec, convert_to_vole, volecommit},
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
    let file = File::open("DataConvertToVole.json").unwrap();
    let database: Vec<DataConvertToVole> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.lambdabytes[0] == 16 {
            let mut opt_sd: Vec<Option<Vec<u8>>> = data.sd.iter().cloned().map(Some).collect();
            if data.sd0[0] == 1 {
                opt_sd[0] = None;
            }
            let res = convert_to_vole(
                &opt_sd[..],
                u128::from_be_bytes(data.iv),
                data.lh[0],
                &prg_128,
            );
            assert_eq!(res.0, data.u);
            assert_eq!(res.1, data.v)
        } else if data.lambdabytes[0] == 24 {
            let mut opt_sd: Vec<Option<Vec<u8>>> = data.sd.iter().cloned().map(Some).collect();
            if data.sd0[0] == 1 {
                opt_sd[0] = None;
            }
            let res = convert_to_vole(
                &opt_sd[..],
                u128::from_be_bytes(data.iv),
                data.lh[0],
                &prg_192,
            );
            assert_eq!(res.0, data.u);
            assert_eq!(res.1, data.v)
        } else {
            let mut opt_sd: Vec<Option<Vec<u8>>> = data.sd.iter().cloned().map(Some).collect();
            if data.sd0[0] == 1 {
                opt_sd[0] = None;
            }
            let res = convert_to_vole(
                &opt_sd[..],
                u128::from_be_bytes(data.iv),
                data.lh[0],
                &prg_256,
            );
            assert_eq!(res.0, data.u);
            assert_eq!(res.1, data.v)
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
        let res = chaldec(
            data.chal, data.k0[0], data.t0[0], data.k1[0], data.t1[0], data.i[0],
        );
        assert_eq!(res, data.res);
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
            let res = volecommit::<GF128, RandomOracleShake128>(
                &data.r,
                u128::from_be_bytes(data.iv),
                data.lh[0],
                data.tau[0],
                &prg_128,
                data.k0[0],
                data.k1[0],
            );
            assert_eq!(res.0, data.hcom);
            for i in 0..res.1.len() {
                assert_eq!(res.1[i], (data.k[i].clone(), data.com[i].clone()));
            }
            for i in 0..data.com.len() {
                assert_eq!(res.1[i], (data.k[i].clone(), data.com[i].clone()));
            }
            assert_eq!(res.2, data.c);
            assert_eq!(res.3, data.u);
            assert_eq!(res.4, data.v);
        } else if data.lambdabytes[0] == 24 {
            let res = volecommit::<GF192, RandomOracleShake256>(
                &data.r,
                u128::from_be_bytes(data.iv),
                data.lh[0],
                data.tau[0],
                &prg_192,
                data.k0[0],
                data.k1[0],
            );
            assert_eq!(res.0, data.hcom);
            for i in 0..res.1.len() {
                assert_eq!(res.1[i], (data.k[i].clone(), data.com[i].clone()));
            }
            for i in 0..data.com.len() {
                assert_eq!(res.1[i], (data.k[i].clone(), data.com[i].clone()));
            }
            assert_eq!(res.2, data.c);
            assert_eq!(res.3, data.u);
            assert_eq!(res.4, data.v);
        } else {
            let res = volecommit::<GF256, RandomOracleShake256>(
                &data.r,
                u128::from_be_bytes(data.iv),
                data.lh[0],
                data.tau[0],
                &prg_256,
                data.k0[0],
                data.k1[0],
            );
            assert_eq!(res.0, data.hcom);
            for i in 0..res.1.len() {
                assert_eq!(res.1[i], (data.k[i].clone(), data.com[i].clone()));
            }
            for i in 0..data.com.len() {
                assert_eq!(res.1[i], (data.k[i].clone(), data.com[i].clone()));
            }
            assert_eq!(res.2, data.c);
            assert_eq!(res.3, data.u);
            assert_eq!(res.4, data.v);
        }
    }
}
