use crate::{
    parameter::{Param, ParamOWF},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, sub_bytes, sub_bytes_nots, State,
    },
};

pub fn extendedwitness(k: &[u8], pk: &[u8], param: Param, paramowf: ParamOWF) -> Vec<u32> {
    let lke = paramowf.get_lke();
    //lke as a value only in classical aes use. testing on it give which is used between rijndael and aes
    let mut beta = 0;
    let bc;
    let mut key = k;
    if lke != 0 {
        beta = param.get_beta() as usize;
        bc = 4;
    } else {
        bc = paramowf.get_nst();
    }
    let r = paramowf.get_r();
    let bk = paramowf.get_nk() as usize;
    let mut input = vec![0u8; 32];
    if lke != 0 {
        input[..16 * beta].clone_from_slice(&pk[..16 * beta]);
    } else {
        input = k.to_vec();
        input.append(&mut vec![0; 32 - k.len()]);
        key = &pk[..4 * bc as usize];
    }
    let mut w = Vec::with_capacity((param.get_l() / 32).into());
    println!("bc = {:?}", bc);
    println!("bk = {:?}", bk);
    let kb = if lke != 0 {
        rijndael_key_schedule(key, bc, bk as u8, r)
    } else {
        rijndael_key_schedule(key, bk as u8, bk as u8, r)
    };
    if lke != 0 {
        w.append(&mut convert_from_batchblocks(inv_bitslice(&kb[..8]))[..4].to_vec());
        w.append(
            &mut convert_from_batchblocks(inv_bitslice(&kb[8..16]))[..bk / 2 - (4 - (bk / 2))]
                .to_vec(),
        );
        for j in 1 + (bk / 8)
            ..1 + (bk / 8)
                + ((paramowf.get_ske() as usize) * ((2 - (bk % 4)) * 2 + (bk % 4) * 3)) / 16
        {
            let key = convert_from_batchblocks(inv_bitslice(&kb[8 * j..8 * (j + 1)]));
            if bk == 6 {
                if j % 3 == 1 {
                    w.push(key[2]);
                } else if j % 3 == 0 {
                    w.push(key[0]);
                }
            } else {
                w.push(key[0]);
            }
        }
    } else {
        for i in 0..k.len() / 4 {
            w.push(u32::from_le_bytes(
                k[i * 4..(i + 1) * 4].try_into().unwrap(),
            ));
        }
    }
    if lke != 0 {
        for b in 0..beta {
            round_with_save(
                input[16 * b..16 * (b + 1)].try_into().unwrap(),
                [0; 16],
                &kb,
                r,
                &mut w,
                bk as u8,
                lke,
            );
        }
    } else {
        round_with_save(
            input[..16].try_into().unwrap(),
            input[16..].try_into().unwrap(),
            &kb,
            r,
            &mut w,
            bk as u8,
            lke,
        );
    }
    w
}

#[allow(clippy::too_many_arguments)]
fn round_with_save(
    input1: [u8; 16],
    input2: [u8; 16],
    kb: &[u32],
    r: u8,
    w: &mut Vec<u32>,
    bk: u8,
    lke: u16,
) {
    let bc_int = if lke != 0 { 4 } else { bk };
    let mut state = State::default();
    bitslice(&mut state, &input1, &input2);
    rijndael_add_round_key(&mut state, &kb[..8]);
    for j in 1..r as usize {
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);
        rijndael_shift_rows_1(&mut state, bc_int);
        w.append(
            &mut convert_from_batchblocks(inv_bitslice(&state))[..bc_int as usize]
                [..bc_int as usize]
                .to_vec(),
        );
        mix_columns_0(&mut state);
        rijndael_add_round_key(&mut state, &kb[8 * j..8 * (j + 1)]);
    }
}
