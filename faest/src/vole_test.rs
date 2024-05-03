#[cfg(test)]
use std::fs::File;

use serde::Deserialize;

use crate::{
    prg::{prg_128, prg_192, prg_256},
    vole::convert_to_vole,
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
