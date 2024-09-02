#[cfg(test)]
use std::fs::File;

use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
use serde::Deserialize;
use typenum::{U15, U16, U3, U31, U32, U4, U5, U63};

use crate::{
    fields::{GF128, GF192, GF256},
    random_oracles::{self, RandomOracleShake128, RandomOracleShake192, RandomOracleShake256},
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
            type D = U31;
            type N = U16;
            let res = commit::<GF128, RandomOracleShake128>(
                GF128::from(&data.keyroot[..]),
                data.iv,
                1 << data.depth,
            );
            let mut sd = Vec::new();
            for val in data.sd {
                sd.push(Some(val));
            }
            assert_eq!(res.0, *GenericArray::from_slice(&data.h));
            assert_eq!(res.1.0, data.k.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8,_>>>());
            assert_eq!(res.1.1, data.com.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8,_>>>());
            assert_eq!(res.2, sd.iter().map(|x| match x { Some(y) => Some(*GenericArray::from_slice(y)), None => None}).collect::<Vec::<Option::<GenericArray<u8,_>>>>());
        } else if lamdabytes == 24 {
            data.keyroot.append(&mut vec![0; 8]);
            type D = U31;
            type N = U16;
            let res = commit::<GF192, RandomOracleShake192>(
                GF192::from(&data.keyroot[..]),
                data.iv,
                1 << data.depth,
            );
            let mut sd = Vec::new();
            for val in data.sd {
                sd.push(Some(val));
            }
            assert_eq!(res.0, *GenericArray::from_slice(&data.h));
            assert_eq!(res.1.0, data.k.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8,_>>>());
            assert_eq!(res.1.1, data.com.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8,_>>>());
            assert_eq!(res.2, sd.iter().map(|x| match x { Some(y) => Some(*GenericArray::from_slice(y)), None => None}).collect::<Vec::<Option::<GenericArray<u8,_>>>>());
        } else {
            type D = U31;
            type N = U16;
            let res = commit::<GF256, RandomOracleShake256>(
                GF256::from(&data.keyroot[0..32]),
                data.iv,
                1 << data.depth,
                
            );
            let mut sd = Vec::new();
            for val in data.sd {
                sd.push(Some(val));
            }
            assert_eq!(res.0, *GenericArray::from_slice(&data.h));
            assert_eq!(res.1.0, data.k.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8,_>>>());
            assert_eq!(res.1.1, data.com.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8,_>>>());
            assert_eq!(res.2, sd.iter().map(|x| match x { Some(y) => Some(*GenericArray::from_slice(y)), None => None}).collect::<Vec::<Option::<GenericArray<u8,_>>>>());
        }
    }
}

#[test]
fn open_test() {
    let file = File::open("Dataopen.json").unwrap();
    let database: Vec<DataOpen> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        if data.k[0].len()==16 {
            type D = U4;
            type DPOW = U31;
            type N = U16;
            let res = open::<RandomOracleShake128, DPOW, D, N>(&(data.k.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, _>>>(), data.com.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, _>>>()), *GenericArray::from_slice(&data.b));
            assert_eq!(res.0.to_vec(), data.cop.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, <random_oracles::RandomOracleShake128 as random_oracles::RandomOracle>::LAMBDA>>>());
            assert_eq!(res.1, data.com_j);
        } else if data.k[0].len()==24 {
            type D = U4;
            type DPOW = U31;
            type N = U16;
            let res = open::<RandomOracleShake192, DPOW, D, N>(&(data.k.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, _>>>(), data.com.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, _>>>()), *GenericArray::from_slice(&data.b));
            assert_eq!(res.0.to_vec(), data.cop.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, <random_oracles::RandomOracleShake192 as random_oracles::RandomOracle>::LAMBDA>>>());
            assert_eq!(res.1, data.com_j);
        } else if data.b.len() == 4 {
            type D = U4;
            type DPOW = U31;
            type N = U16;
            let res = open::<RandomOracleShake256, DPOW, D, N>(&(data.k.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, _>>>(), data.com.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, _>>>()), *GenericArray::from_slice(&data.b));
            assert_eq!(res.0.to_vec(), data.cop.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, <random_oracles::RandomOracleShake256 as random_oracles::RandomOracle>::LAMBDA>>>());
            assert_eq!(res.1, data.com_j);
        } else {
            type D = U5;
            type DPOW = U63;
            type N = U32;
            let res = open::<RandomOracleShake256, DPOW, D, N>(&(data.k.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, _>>>(), data.com.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, _>>>()), *GenericArray::from_slice(&data.b));;
            assert_eq!(res.0.to_vec(), data.cop.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, <random_oracles::RandomOracleShake256 as random_oracles::RandomOracle>::LAMBDA>>>());
            assert_eq!(res.1, data.com_j);
        }
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
                &(data.cop.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, <random_oracles::RandomOracleShake128 as random_oracles::RandomOracle>::LAMBDA>>>(), *GenericArray::<u8, <random_oracles::RandomOracleShake128 as random_oracles::RandomOracle>::PRODLAMBDA2>::from_slice(&data.com_j)),
                data.b,
                u128::from_be_bytes(data.iv),
            );
            assert_eq!(res.0, *GenericArray::from_slice(&data.h));
            assert_eq!(res.1, data.sd.iter().map(|x| match x[..] { [] => GenericArray::default(), _ => *GenericArray::from_slice(&x)}).collect::<Vec::<GenericArray<u8, <random_oracles::RandomOracleShake128 as random_oracles::RandomOracle>::LAMBDA>>>());
        } else if lambdabyte == 48 {
            let res = reconstruct::<GF192, RandomOracleShake192>(
                &(data.cop.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, <random_oracles::RandomOracleShake192 as random_oracles::RandomOracle>::LAMBDA>>>(), *GenericArray::<u8, <random_oracles::RandomOracleShake192 as random_oracles::RandomOracle>::PRODLAMBDA2>::from_slice(&data.com_j)),
                data.b,
                u128::from_be_bytes(data.iv),
            );
            assert_eq!(res.0, *GenericArray::from_slice(&data.h));
            assert_eq!(res.1, data.sd.iter().map(|x| match x[..] { [] => GenericArray::default(), _ => *GenericArray::from_slice(&x)}).collect::<Vec::<GenericArray<u8, <random_oracles::RandomOracleShake192 as random_oracles::RandomOracle>::LAMBDA>>>());
        } else {
            let res = reconstruct::<GF256, RandomOracleShake256>(
                &(data.cop.iter().map(|x| *GenericArray::from_slice(&x)).collect::<Vec::<GenericArray<u8, <random_oracles::RandomOracleShake256 as random_oracles::RandomOracle>::LAMBDA>>>(), *GenericArray::<u8, <random_oracles::RandomOracleShake256 as random_oracles::RandomOracle>::PRODLAMBDA2>::from_slice(&data.com_j)),
                data.b,
                u128::from_be_bytes(data.iv),
            );
            assert_eq!(res.0, *GenericArray::from_slice(&data.h));
            assert_eq!(res.1, data.sd.iter().map(|x| match x[..] { [] => GenericArray::default(), _ => *GenericArray::from_slice(&x)}).collect::<Vec::<GenericArray<u8, <random_oracles::RandomOracleShake256 as random_oracles::RandomOracle>::LAMBDA>>>());
        }
    }
}
