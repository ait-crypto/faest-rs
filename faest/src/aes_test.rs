use crate::aes::extendedwitness;
use crate::aes::{expand_key192, expand_key256};
use crate::parameter::{self, PARAMOWF128};
use crate::{aes::expand_key128, parameter::Param};
use aesf::soft::fixslice::hazmat::bitslice_block;
use aesf::soft::fixslice::{self, hazmat, shift_rows_1, sub_bytes, sub_bytes_nots};
use aesf::Block;
#[cfg(test)]
use serde::Deserialize;
use std::fs::File;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AesExtendedWitness {
    lambda: u16,

    l: u16,

    lke: u16,

    ske: u16,

    numrounds: u8,

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
            let res = extendedwitness(&data.key, &data.input, param, paramowf, &expand_key128);
            for i in 0..res.len() {
                for j in 0..4 {
                    assert_eq!(res[i].to_le_bytes()[j], data.w[i * 4 + j]);
                }
            }
        } else if data.lambda == 192 {
            let param = Param::set_param(192, data.l, 16, 12, 12, 1, 1, 16, 2);
            let mut paramowf = parameter::PARAMOWF192;
            paramowf.set_lke(data.lke);
            let res = extendedwitness(&data.key, &data.input, param, paramowf, &expand_key192);
            for i in 0..res.len() {
                //println!("{:?}", res[i].to_le_bytes());
                for j in 0..4 {
                    assert_eq!(res[i].to_le_bytes()[j], data.w[i * 4 + j]);
                }
            }
        } else {
            let param = Param::set_param(256, data.l, 22, 12, 11, 1, 1, 16, 2);
            let mut paramowf = parameter::PARAMOWF256;
            paramowf.set_lke(data.lke);
            let res = extendedwitness(&data.key, &data.input, param, paramowf, &expand_key256);
            for i in 0..res.len() {
                for j in 0..4 {
                    assert_eq!(res[i].to_le_bytes()[j], data.w[i * 4 + j]);
                }
            }
        }
    }
}

#[test]
fn test_sub_byte() {
    let mut input: [u8; 16] = [
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
        0xf0,
    ];
    //let st1 = u64::from_le_bytes([57, 115, 41, 167, 110, 250, 205, 22]);
    /*let st2 = u64::from_le_bytes([57, 115, 41, 167, 110, 250, 205, 22]); */
    let block = Block::from_slice(&input);
    let mut state = hazmat::bitslice_block(block);
    for st in state {
        print!("{:x}, ", st);
    }
    println!(" ");
    fixslice::sub_bytes(&mut state);
    //fixslice::sub_bytes_nots(&mut state);
    //fixslice::shift_rows_1(&mut state);
    for st in state {
        print!("{:x}, ", st);
    }
    println!(" ");
}

/* #[test]
fn test_round() {
    let mut input = Block::from_slice(&[0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0]);
    let res = &mut input.clone();
    let mut state = bitslice_block(res);
    sub_bytes(&mut state);
    sub_bytes_nots(&mut state);
    inv_bitslice_block(res, &state);

    let mut half_input = Block::from_slice(&[0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0,0,0,0,0,0,0,0]);
    let half_res = &mut input.clone();
    let mut state = bitslice_block(res);
    sub_bytes(&mut state);
    sub_bytes_nots(&mut state);
    inv_bitslice_block(half_res, &state);

    println!("{:?}", res);
    println!("{:?}", half_res);
} */
