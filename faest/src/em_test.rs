use std::fs::File;

use serde::Deserialize;

use crate::{
    em::extendedwitness,
    parameter::{self, Param},
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
            let res = extendedwitness(
                &data.key,
                (&data.input[..16], &data.input[16..]),
                param,
                paramowf,
            );
            assert_eq!(res, data.w);
        } else if data.lambda == 192 {
            let param = Param::set_param(192, data.l, 16, 12, 12, 1, 1, 16, 2);
            let mut paramowf = parameter::PARAMOWF192;
            paramowf.set_lke(data.lke);
            let res = extendedwitness(
                &data.key,
                (&data.input[..24], &data.input[24..]),
                param,
                paramowf,
            );
            assert_eq!(res, data.w);
        } else {
            let param = Param::set_param(256, data.l, 22, 12, 11, 1, 1, 16, 2);
            let mut paramowf = parameter::PARAMOWF256;
            paramowf.set_lke(data.lke);
            let res = extendedwitness(
                &data.key,
                (&data.input[..32], &data.input[32..]),
                param,
                paramowf,
            );
            assert_eq!(res, data.w);
        }
    }
}
