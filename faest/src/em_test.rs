use std::fs::File;

use serde::Deserialize;

use crate::{
    aes::convert_to_bit, em::{em_key_enc_fwd, extendedwitness}, fields::{BigGaloisField, GF128, GF192, GF256}, parameter::{self, Param, PARAMOWF128, PARAMOWF192, PARAMOWF256}
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
            let (input_x, input_z) : (Vec<GF128>, Vec<GF128>) = if data.m == 1 {(data.x.iter().flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1])).collect(), data.z.iter().flat_map(|z| convert_to_bit(&z[0].to_le_bytes()[..1])).collect())} else {(data.x.iter().map(|x| GF128::new(x[0] as u128 + ((x[1] as u128)<<64), 0)).collect(), data.z.iter().map(|z| GF128::new(z[0] as u128 + ((z[1] as u128)<<64), 0)).collect())};
            let res = em_key_enc_fwd(&input_z, &input_x, &paramowf);
            assert_eq!(res, data.res.iter().map(|z| GF128::new(z[0] as u128 + ((z[1] as u128)<<64), 0)).collect::<Vec<GF128>>())
        } else if data.lambda == 192 {
            let paramowf = PARAMOWF192;
            let (input_x, input_z) : (Vec<GF192>, Vec<GF192>) = if data.m == 1 {(data.x.iter().flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1])).collect(), data.z.iter().flat_map(|z| convert_to_bit(&z[0].to_le_bytes()[..1])).collect())} else {(data.x.iter().map(|x| GF192::new(x[0] as u128 + ((x[1] as u128)<<64), x[2] as u128 )).collect(), data.z.iter().map(|z| GF192::new(z[0] as u128 + ((z[1] as u128)<<64), z[2] as u128)).collect())};
            let res = em_key_enc_fwd(&input_z, &input_x, &paramowf);
            assert_eq!(res, data.res.iter().map(|z| GF192::new(z[0] as u128 + ((z[1] as u128)<<64), z[2] as u128)).collect::<Vec<GF192>>())
        } else {
            let paramowf = PARAMOWF256;
            let (input_x, input_z) : (Vec<GF256>, Vec<GF256>) = if data.m == 1 {(data.x.iter().flat_map(|x| convert_to_bit(&x[0].to_le_bytes()[..1])).collect(), data.z.iter().flat_map(|z| convert_to_bit(&z[0].to_le_bytes()[..1])).collect())} else {(data.x.iter().map(|x| GF256::new(x[0] as u128 + ((x[1] as u128)<<64), x[2] as u128 + ((x[3] as u128)<<64))).collect(), data.z.iter().map(|z| GF256::new(z[0] as u128 + ((z[1] as u128)<<64), z[2] as u128 + ((z[3] as u128)<<64))).collect())};
            let res = em_key_enc_fwd(&input_z, &input_x, &paramowf);
            assert_eq!(res, data.res.iter().map(|z| GF256::new(z[0] as u128 + ((z[1] as u128)<<64), z[2] as u128 + ((z[3] as u128)<<64))).collect::<Vec<GF256>>())
        }
    }
}