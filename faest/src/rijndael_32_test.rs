#[cfg(test)]
use rand::Rng;
use serde::Deserialize;
use std::{cmp::max, fs::File};

use crate::rijndael_32::{
    bitslice, inv_bitslice, mix_columns_0, rijndael_decrypt, rijndael_encrypt,
    rijndael_key_schedule, rijndael_shift_rows_1, rijndael_shift_rows_2, rijndael_shift_rows_3,
    State,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShiftRows {
    bc: u8,
    rep: u8,
    input: Vec<u8>,
    output: Vec<u8>,
}

#[test]
fn shift_row_test() {
    let file = File::open("shift_row_data.json").unwrap();
    let database: Vec<ShiftRows> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for mut data in database {
        let mut input = [0u32; 8];
        let mut output = [0u32; 8];
        for i in 0..data.bc {
            for j in 0..4 {
                input[i as usize] += (data.input[(j * 4 + i) as usize] as u32) << (24 - (j) * 8);
                output[i as usize] += (data.output[(i * 4 + j) as usize] as u32) << (24 - (j) * 8);
            }
        }
        for _i in 0..32 - data.input.len() {
            data.input.push(0u8);
        }
        let mut bitsliced_input = [0u32; 8];
        bitslice(&mut bitsliced_input, &data.input[..16], &data.input[16..]);
        if data.rep == 1 {
            rijndael_shift_rows_1(&mut bitsliced_input, data.bc);
        } else if data.rep == 2 {
            rijndael_shift_rows_2(&mut bitsliced_input, data.bc);
        } else {
            rijndael_shift_rows_3(&mut bitsliced_input, data.bc);
        }
        let res = inv_bitslice(&bitsliced_input);
        let mut input = [0u32; 8];
        for i in 0..data.bc {
            for j in 0..4 {
                input[i as usize] +=
                    (res[(i / 4) as usize][(((i % 4) * 4) + j) as usize] as u32) << (24 - (j) * 8);
            }
        }
        assert_eq!(input, output);
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MixColumns {
    bc: u8,
    input: Vec<u8>,
    output: Vec<u8>,
}

#[test]
fn mix_column_test() {
    let file = File::open("mix_column_data.json").unwrap();
    let database: Vec<MixColumns> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for mut data in database {
        let mut input = [0u32; 8];
        let mut output = [0u32; 8];
        for i in 0..data.bc {
            for j in 0..4 {
                input[i as usize] += (data.input[(j * 4 + i) as usize] as u32) << (24 - (j) * 8);
                output[i as usize] += (data.output[(i * 4 + j) as usize] as u32) << (24 - (j) * 8);
            }
        }
        for _i in 0..32 - data.input.len() {
            data.input.push(0u8);
        }
        let mut bitsliced_input = [0u32; 8];
        bitslice(&mut bitsliced_input, &data.input[..16], &data.input[16..]);
        mix_columns_0(&mut bitsliced_input);

        let res = inv_bitslice(&bitsliced_input);
        let mut input = [0u32; 8];
        for i in 0..data.bc {
            for j in 0..4 {
                input[i as usize] +=
                    (res[(i / 4) as usize][(((i % 4) * 4) + j) as usize] as u32) << (24 - (j) * 8);
            }
        }
        assert_eq!(input, output);
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rijndael {
    kc: u8,
    bc: u8,
    key: Vec<u8>,
    text: Vec<u8>,
    output: Vec<u8>,
}

#[test]
fn rijndael_test() {
    let file = File::open("rijndael_data.json").unwrap();
    let database: Vec<Rijndael> =
        serde_json::from_reader(file).expect("error while reading or parsing");
    for data in database {
        let mut input = [0u8; 32];
        input[..data.text.len()].copy_from_slice(&data.text[..]);
        let r = max(data.bc, data.kc) + 6;
        let rkeys = rijndael_key_schedule(&data.key, data.bc, data.kc, r);
        let res = rijndael_encrypt(&rkeys, &input, data.bc, data.bc, r);
        let mut input = [0u32; 8];
        let mut output = [0u32; 8];
        for i in 0..data.bc {
            for j in 0..4 {
                input[i as usize] +=
                    (res[(i / 4) as usize][(((i % 4) * 4) + j) as usize] as u32) << (24 - (j) * 8);
                output[i as usize] += (data.output[(i * 4 + j) as usize] as u32) << (24 - (j) * 8);
            }
        }
        assert_eq!(input, output);
    }
}

#[test]
fn rijndael_decrypt_test() {
    for k in 2..5 {
        let kc = 2 * k;
        for b in 2..5 {
            let bc = 2 * b;
            for _i in 0..1000 {
                let key: Vec<u8> = (0..4 * kc).map(|_| rand::thread_rng().gen()).collect();
                let text: Vec<u8> = (0..4 * bc).map(|_| rand::thread_rng().gen()).collect();
                let mut padded_text = [0u8; 32];
                padded_text[..text.len()].copy_from_slice(&text[..]);
                let r = max(kc, bc) + 6;
                let mut state_text = State::default();
                let rkeys = rijndael_key_schedule(&key, bc, kc, r);
                let crypted = rijndael_encrypt(&rkeys, &padded_text, bc, bc, r);
                let res = rijndael_decrypt(&rkeys, &crypted, bc, r);
                bitslice(&mut state_text, &padded_text[..16], &padded_text[16..]);
                assert_eq!(res, inv_bitslice(&state_text));
            }
        }
    }
}
