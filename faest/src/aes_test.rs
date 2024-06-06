use crate::aes::extendedwitness;
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
