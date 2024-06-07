use crate::aes::{aes_key_exp_bwd, aes_key_exp_fwd, extendedwitness};
use crate::fields::{BigGaloisField, GF128, GF192, GF256};
use crate::parameter::Param;
use crate::parameter::{self};
#[cfg(test)]
use serde::Deserialize;
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

    x: Vec<u8>,

    out: Vec<u8>,
}

#[test]
fn aes_key_exp_fwd_test() {
    let file = File::open("AesKeyExpFwd.json").unwrap();
    let database: Vec<AesKeyExpFwd> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        let res = aes_key_exp_fwd(data.x, data.r, data.lambda as usize, data.nwd);
        assert_eq!(res, data.out);
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
            let x: Vec<GF128> = data
                .x
                .iter()
                .map(|x| GF128::new(x[0] + (x[1] << 64), 0))
                .collect();
            let xk: Vec<GF128> = data
                .xk
                .iter()
                .map(|xk| GF128::new(xk[0] + (xk[1] << 64), 0))
                .collect();
            let out: Vec<GF128> = data
                .out
                .iter()
                .map(|out| GF128::new(out[0] + (out[1] << 64), 0))
                .collect();
            let res = aes_key_exp_bwd::<GF128>(x, xk.clone(), mtag, mkey, delta, data.ske);
            for i in 0..res.len() {
                assert_eq!(res[i], out[i]);
            }
        } else if data.lambda == 192 {
            let mtag = data.mtag != 0;
            let mkey = data.mkey != 0;
            let delta = GF192::new(data.delta[0] + (data.delta[1] << 64), data.delta[2]);
            let x: Vec<GF192> = data
                .x
                .iter()
                .map(|x| GF192::new(x[0] + (x[1] << 64), x[2]))
                .collect();
            let xk = data
                .xk
                .iter()
                .map(|xk| GF192::new(xk[0] + (xk[1] << 64), xk[2]))
                .collect();
            let out: Vec<GF192> = data
                .out
                .iter()
                .map(|out| GF192::new(out[0] + (out[1] << 64), out[2]))
                .collect();
            let res = aes_key_exp_bwd::<GF192>(x, xk, mtag, mkey, delta, data.ske);
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
            let x: Vec<GF256> = data
                .x
                .iter()
                .map(|x| GF256::new(x[0] + (x[1] << 64), x[2] + (x[3] << 64)))
                .collect();
            let xk = data
                .xk
                .iter()
                .map(|xk| GF256::new(xk[0] + (xk[1] << 64), xk[2] + (xk[3] << 64)))
                .collect();
            let out: Vec<GF256> = data
                .out
                .iter()
                .map(|out| GF256::new(out[0] + (out[1] << 64), out[2] + (out[3] << 64)))
                .collect();
            let res = aes_key_exp_bwd::<GF256>(x, xk, mtag, mkey, delta, data.ske);
            for i in 0..res.len() {
                assert_eq!(res[i], out[i]);
            }
        }
    }
}
