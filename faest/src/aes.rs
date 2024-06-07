use std::iter::zip;

use crate::{
    fields::BigGaloisField, parameter::{Param, ParamOWF}, rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, sub_bytes, sub_bytes_nots, State,
    }
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
    let kc = paramowf.get_nk() as usize;
    let mut input = vec![0u8; 32];
    //step 0
    if lke != 0 {
        input[..16 * beta].clone_from_slice(&pk[..16 * beta]);
    } else {
        input = k.to_vec();
        input.append(&mut vec![0; 32 - k.len()]);
        key = &pk[..4 * bc as usize];
    }
    let mut w = Vec::with_capacity((param.get_l() / 32).into());
    //step 3
    let kb = if lke != 0 {
        rijndael_key_schedule(key, bc, kc as u8, r)
    } else {
        rijndael_key_schedule(key, kc as u8, kc as u8, r)
    };
    //step 4
    if lke != 0 {
        w.append(&mut convert_from_batchblocks(inv_bitslice(&kb[..8]))[..4].to_vec());
        w.append(
            &mut convert_from_batchblocks(inv_bitslice(&kb[8..16]))[..kc / 2 - (4 - (kc / 2))]
                .to_vec(),
        );
        for j in 1 + (kc / 8)
            ..1 + (kc / 8)
                + ((paramowf.get_ske() as usize) * ((2 - (kc % 4)) * 2 + (kc % 4) * 3)) / 16
        {
            let key = convert_from_batchblocks(inv_bitslice(&kb[8 * j..8 * (j + 1)]));
            if kc == 6 {
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
    //step 5
    if lke != 0 {
        for b in 0..beta {
            round_with_save(
                input[16 * b..16 * (b + 1)].try_into().unwrap(),
                [0; 16],
                &kb,
                r,
                &mut w,
                kc as u8,
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
            kc as u8,
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
    kc: u8,
    lke: u16,
) {
    let bc_int = if lke != 0 { 4 } else { kc };
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

pub fn aes_key_exp_fwd(x: Vec<u8>, r: u8, lambda: usize, kc: u8) -> Vec<u8> {
    //Step 1 is ok by construction
    let mut out = Vec::with_capacity(((r + 1) as u16 * 128).into());
    for i in x.iter().take(lambda / 8).cloned() {
        out.push(i);
    }
    let mut index = lambda / 8;
    for j in kc..4 * (r + 1) {
        if (j % kc == 0) || ((kc > 6) && (j % kc == 4)) {
            out.append(&mut x[index..index + 4].to_vec());
            index += 4;
        } else {
            for i in 0..4 {
                out.push(out[((4 * (j - kc)) + i) as usize] ^ out[((4 * (j - 1)) + i) as usize]);
            }
        }
    }
    out
}

///Beware when calling it : if Mtag = 1 ∧ Mkey = 1 or Mkey = 1 ∧ ∆ = ⊥ return ⊥
pub fn aes_key_exp_bwd<T>(x : Vec<T>, xk : Vec<T>, mtag : bool, mkey : bool, delta : T, ske: u16) -> Vec<T> where
T: BigGaloisField + std::default::Default + std::marker::Sized + std::fmt::Debug, T: std::ops::Add<T>{
    let rcon_table = [
            1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151,
            53, 106, 212, 179, 125, 250, 239, 197, 145
        ];
    let mut out = Vec::with_capacity((8*ske).into());
    let mut index = 0u16;
    let mut c = 0u8;
    let mut rmvrcon = true;
    let mut ircon = 0;
    for j in 0..ske {
        let mut x_tilde : Vec<T> = zip(x.iter().skip((8*j).into()).take(8), xk.iter().skip((index + 8*(c as u16)).into()).take(8)).map(|(x, xk)| *x + *xk).collect();
        if !mtag && rmvrcon && (c == 0) {
            let rcon = rcon_table[ircon];
            ircon  += 1;
            let mut r = [T::default() ; 8];
            for i in 0..8 {
                r[i] = if mkey {delta * ((rcon>>i)&1)} else {T::ONE * ((rcon>>i)&1)};
                x_tilde[i] += r[i];  
            }
        }
        let mut y_tilde = [T::default() ; 8];
        for i in 0..8 {
            y_tilde[i] = x_tilde[(i + 7)%8] + x_tilde[(i + 5)%8] + x_tilde[(i + 2)%8];
        }
        y_tilde[0] += if mtag {T::default()} else if mkey {delta} else {T::ONE};
        y_tilde[2] += if mtag {T::default()} else if mkey {delta} else {T::ONE};
        out.append(&mut y_tilde.to_vec());
        c += 1;
        if c == 4 {
            c = 0;
            if T::LENGTH == 192 {
                index += 192;
            } else {
                index += 128;
                if T::LENGTH == 256 {
                rmvrcon = !rmvrcon;
                }
            }
        }   
    }
    out
}
