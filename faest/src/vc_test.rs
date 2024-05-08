#[cfg(test)]
use std::fs::File;

use serde::Deserialize;

use crate::{
    fields::{GF128, GF192, GF256},
    prg::{prg_128, prg_192, prg_256},
    random_oracles::{RandomOracleShake128, RandomOracleShake256},
    vc::{commit, open, reconstruct},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DataCommit {
    keyroot: Vec<u8>,

    iv: u128,

    depth: u8,

    h: Vec<u8>,

    k: Vec<Vec<u8>>,

    com: Vec<Vec<u8>>,

    sd: Vec<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DataOpen {
    k: Vec<Vec<u8>>,

    b: Vec<u8>,

    com: Vec<Vec<u8>>,

    cop: Vec<Vec<u8>>,

    com_j: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DataReconstruct {
    cop: Vec<Vec<u8>>,

    com_j: Vec<u8>,

    b: Vec<u8>,

    iv: [u8; 16],

    h: Vec<u8>,

    sd: Vec<Vec<u8>>,
}

#[test]
fn commit_test() {
    let file = File::open("DataVc.json").unwrap();
    let database: Vec<DataCommit> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for mut data in database {
        let lamdabytes = data.keyroot.len();
        if lamdabytes == 16 {
            data.keyroot.append(&mut vec![0; 16]);
            let res = commit::<GF128, RandomOracleShake128>(
                GF128::from(&data.keyroot[..]),
                data.iv,
                1 << data.depth,
                &prg_128,
            );
            let mut sd = Vec::new();
            for val in data.sd {
                sd.push(Some(val));
            }
            assert_eq!(res.0, data.h);
            assert_eq!(res.1 .0, data.k);
            assert_eq!(res.1 .1, data.com);
            assert_eq!(res.2, sd);
        } else if lamdabytes == 24 {
            data.keyroot.append(&mut vec![0; 8]);
            let res = commit::<GF192, RandomOracleShake256>(
                GF192::from(&data.keyroot[..]),
                data.iv,
                1 << data.depth,
                &prg_192,
            );
            let mut sd = Vec::new();
            for val in data.sd {
                sd.push(Some(val));
            }
            assert_eq!(res.0, data.h);
            assert_eq!(res.1 .0, data.k);
            assert_eq!(res.1 .1, data.com);
            assert_eq!(res.2, sd);
        } else {
            let res = commit::<GF256, RandomOracleShake256>(
                GF256::from(&data.keyroot[0..32]),
                data.iv,
                1 << data.depth,
                &prg_256,
            );
            let mut sd = Vec::new();
            for val in data.sd {
                sd.push(Some(val));
            }
            assert_eq!(res.0, data.h);
            assert_eq!(res.1 .0, data.k);
            assert_eq!(res.1 .1, data.com);
            assert_eq!(res.2, sd);
        }
    }
}

#[test]
fn open_test() {
    let file = File::open("Dataopen.json").unwrap();
    let database: Vec<DataOpen> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        let res = open((data.k, data.com), data.b);
        assert_eq!(res.0, data.cop);
        assert_eq!(res.1, data.com_j);
    }
}

#[test]
fn reconstruct_test() {
    let file = File::open("DataReconstruct.json").unwrap();
    let database: Vec<DataReconstruct> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        let lambdabyte = data.com_j.len();
        if lambdabyte == 32 {
            let res = reconstruct::<GF128, RandomOracleShake128>(
                (data.cop, data.com_j),
                data.b,
                u128::from_be_bytes(data.iv),
                &prg_128,
            );
            assert_eq!(res.0, data.h);
            assert_eq!(res.1, data.sd);
        } else if lambdabyte == 48 {
            let res = reconstruct::<GF192, RandomOracleShake256>(
                (data.cop, data.com_j),
                data.b,
                u128::from_be_bytes(data.iv),
                &prg_192,
            );
            assert_eq!(res.0, data.h);
            assert_eq!(res.1, data.sd);
        } else {
            let res = reconstruct::<GF256, RandomOracleShake256>(
                (data.cop, data.com_j),
                data.b,
                u128::from_be_bytes(data.iv),
                &prg_256,
            );
            assert_eq!(res.0, data.h);
            assert_eq!(res.1, data.sd);
        }
    }
}
