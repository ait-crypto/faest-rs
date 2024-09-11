//! Fixsliced implementations of Rijdael (32-bit)
//! adapted from the C implementation
//!
//! All implementations are fully bitsliced and do not rely on any
//! Look-Up Table (LUT).
//!
//! # Author (original C code)
//!
//! Alexandre Adomnicai, Nanyang Technological University, Singapore
//! <alexandre.adomnicai@ntu.edu.sg>
//!
//! Originally licensed MIT. Relicensed as Apache 2.0+MIT with permission.

#![allow(clippy::unreadable_literal)]

use aes::Block;
use cipher::{array::Array, consts::U2};

/// AES block batch size for this implementation
pub(crate) type FixsliceBlocks = U2;

pub(crate) type BatchBlocks = Array<Block, FixsliceBlocks>;

/// 256-bit internal state
pub(crate) type State = [u32; 8];

/// Fully bitsliced Rijndael key schedule to match the fully-fixsliced representation.
#[allow(dead_code)]
pub(crate) fn rijndael_key_schedule(
    key: &[u8],
    nst: u8,
    nk: u8,
    r: u8,
    ske: u8,
) -> (Vec<u32>, bool) {
    let mut valid = true;
    let mut rkeys = vec![0u32; (((nst.div_ceil(nk)) * 8 * (r + 1)) + 8).into()];
    let mut sd_part = [0u8; 16];
    for i in 0..(nk * 4) - 16 {
        sd_part[i as usize] = key[(16 + i) as usize];
    }
    bitslice(&mut rkeys[..8], &key[..16], &sd_part);

    let mut rk_off = 0;
    let mut count = 0;
    for i in 0..ske / 4 {
        if nk == 8 {
            if count < ske / 4 {
                for i in inv_bitslice(&rkeys[rk_off..(rk_off + 8)])[1][12..].iter() {
                    valid &= (0 != *i);
                }
                count += 1
            }
        } else if nk == 6 {
            for i in inv_bitslice(&rkeys[rk_off..(rk_off + 8)])[1][4..8].iter() {
                valid &= (0 != *i);
            }
        } else {
            for i in inv_bitslice(&rkeys[rk_off..(rk_off + 8)])[0][12..].iter() {
                valid &= (0 != *i);
            }
        }
        memshift32(&mut rkeys, rk_off);
        rk_off += 8;
        sub_bytes(&mut rkeys[rk_off..(rk_off + 8)]);
        sub_bytes_nots(&mut rkeys[rk_off..(rk_off + 8)]);

        let table = [
            1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151,
            53, 106, 212, 179, 125, 250, 239, 197, 145,
        ];
        let ind = nk * 4;
        let mut rcon_0 = [0u8; 16];
        let mut rcon_1 = [0u8; 16];
        rcon_0[13] = table[i as usize] * (1 - ind / 17);
        rcon_1[5] = (table[i as usize] as u16 * (((ind / 8) % 2) as u16)) as u8;
        rcon_1[13] = table[i as usize] * (ind / 32);
        let mut bitsliced_rcon = [0u32; 8];
        bitslice(&mut bitsliced_rcon, &rcon_0, &rcon_1);

        for j in 0..8 {
            rkeys[rk_off + j] ^= bitsliced_rcon[j];
        }

        let idx_ror: u32;

        if nk == 4 {
            idx_ror = 14;
        } else if nk == 6 {
            idx_ror = 11;
        } else {
            idx_ror = 15;
        }

        xor_columns(&mut rkeys, rk_off, 8, idx_ror, nk);
        if nk == 8 && count < ske/4 {
            for i in inv_bitslice(&rkeys[rk_off..(rk_off + 8)])[0][12..].iter() {
                valid &= (0 != *i);
            }
            count += 1
        }
    }

    if nk == 4 {
        let mut final_res: Vec<u8> = vec![];
        for i in 0..rkeys.len() / 8 {
            let res = inv_bitslice(&rkeys[i * 8..(i + 1) * 8]);
            if nst == 4 {
                for j in 0..16 {
                    final_res.push(res[0][j]);
                }
                for _j in 0..16 {
                    final_res.push(0);
                }
            } else if nst == 6 {
                if i % 3 == 0 {
                    for j in 0..16 {
                        final_res.push(res[0][j]);
                    }
                } else if i % 3 == 1 {
                    for j in 0..8 {
                        final_res.push(res[0][j]);
                    }
                    for _j in 0..8 {
                        final_res.push(0);
                    }
                    for j in 8..16 {
                        final_res.push(res[0][j]);
                    }
                } else {
                    for j in 0..16 {
                        final_res.push(res[0][j]);
                    }
                    for _j in 0..8 {
                        final_res.push(0);
                    }
                }
            } else {
                for j in 0..16 {
                    final_res.push(res[0][j]);
                }
            }
        }

        let mut final_bitsliced_res = vec![0u32; final_res.len() / 4];
        for i in 0..final_res.len() / 32 {
            bitslice(
                &mut final_bitsliced_res[i * 8..(i + 1) * 8],
                &final_res[32 * i..(32 * i) + 16],
                &final_res[(32 * i) + 16..32 * (i + 1)],
            );
        }
        (final_bitsliced_res, valid)
    } else if nk == 6 {
        let mut final_res: Vec<u8> = vec![];
        for i in 0..rkeys.len() / 8 {
            let res = inv_bitslice(&rkeys[i * 8..(i + 1) * 8]);
            if nst == 4 {
                if i % 2 == 0 {
                    for j in 0..16 {
                        final_res.push(res[0][j]);
                    }
                    for _j in 0..16 {
                        final_res.push(0);
                    }
                    for j in 0..8 {
                        final_res.push(res[1][j]);
                    }
                } else {
                    for j in 0..8 {
                        final_res.push(res[0][j]);
                    }
                    for _j in 0..16 {
                        final_res.push(0);
                    }
                    for j in 8..16 {
                        final_res.push(res[0][j]);
                    }
                    for j in 0..8 {
                        final_res.push(res[1][j]);
                    }
                    for _j in 0..16 {
                        final_res.push(0);
                    }
                }
            } else if nst == 6 {
                for j in 0..16 {
                    final_res.push(res[0][j]);
                }
                for j in 0..8 {
                    final_res.push(res[1][j]);
                }
                for _j in 0..8 {
                    final_res.push(0);
                }
            } else {
                for j in 0..16 {
                    final_res.push(res[0][j]);
                }
                for j in 0..8 {
                    final_res.push(res[1][j]);
                }
            }
        }
        let mut final_bitsliced_res = vec![0u32; final_res.len() / 4];
        for i in 0..final_res.len() / 32 {
            bitslice(
                &mut final_bitsliced_res[i * 8..(i + 1) * 8],
                &final_res[32 * i..(32 * i) + 16],
                &final_res[(32 * i) + 16..32 * (i + 1)],
            );
        }
        (final_bitsliced_res, valid)
    } else {
        let mut final_res: Vec<u8> = vec![];
        for i in 0..rkeys.len() / 8 {
            let res = inv_bitslice(&rkeys[i * 8..(i + 1) * 8]);
            if nst == 4 {
                for j in 0..16 {
                    final_res.push(res[0][j]);
                }
                for _j in 0..16 {
                    final_res.push(0);
                }
                for j in 0..16 {
                    final_res.push(res[1][j]);
                }
                for _j in 0..16 {
                    final_res.push(0);
                }
            } else if nst == 6 {
                if i % 3 == 0 {
                    for j in 0..16 {
                        final_res.push(res[0][j]);
                    }
                    for j in 0..8 {
                        final_res.push(res[1][j]);
                    }
                    for _j in 0..8 {
                        final_res.push(0);
                    }
                    for j in 8..16 {
                        final_res.push(res[1][j]);
                    }
                } else if i % 3 == 1 {
                    for j in 0..16 {
                        final_res.push(res[0][j]);
                    }
                    for _j in 0..8 {
                        final_res.push(0);
                    }
                    for j in 0..16 {
                        final_res.push(res[1][j]);
                    }
                } else {
                    for j in 0..8 {
                        final_res.push(res[0][j]);
                    }
                    for _j in 0..8 {
                        final_res.push(0);
                    }
                    for j in 8..16 {
                        final_res.push(res[0][j]);
                    }
                    for j in 0..16 {
                        final_res.push(res[1][j]);
                    }
                    for _j in 0..8 {
                        final_res.push(0);
                    }
                }
            } else {
                for j in 0..16 {
                    final_res.push(res[0][j]);
                }
                for j in 0..16 {
                    final_res.push(res[1][j]);
                }
            }
        }
        let mut final_bitsliced_res = vec![0u32; final_res.len() / 4];
        for i in 0..final_res.len() / 32 {
            bitslice(
                &mut final_bitsliced_res[i * 8..(i + 1) * 8],
                &final_res[32 * i..(32 * i) + 16],
                &final_res[(32 * i) + 16..32 * (i + 1)],
            );
        }
        (final_bitsliced_res, valid)
    }
}

/// Fully-fixsliced AES-128 decryption (the InvShiftRows is completely omitted).
///
/// Decrypts four blocks in-place and in parallel.
#[allow(dead_code)]
pub(crate) fn rijndael_decrypt(rkeys: &[u32], blocks: &BatchBlocks, bc: u8, r: u8) -> BatchBlocks {
    let mut state = State::default();
    bitslice(&mut state, &blocks[0], &blocks[1]);

    rijndael_add_round_key(&mut state, &rkeys[(r * 8) as usize..((r + 1) * 8) as usize]);
    rijndael_inv_shift_rows_1(&mut state, bc);
    sub_bytes_nots(&mut state);
    inv_sub_bytes(&mut state);

    let mut rk_off = (r - 1) * 8;
    loop {
        rijndael_add_round_key(&mut state, &rkeys[(rk_off) as usize..(rk_off + 8) as usize]);
        inv_mix_columns_0(&mut state);
        rijndael_inv_shift_rows_1(&mut state, bc);
        sub_bytes_nots(&mut state);
        inv_sub_bytes(&mut state);
        rk_off -= 8;

        if rk_off == 0 {
            break;
        }
    }

    rijndael_add_round_key(&mut state, &rkeys[..8]);

    inv_bitslice(&state)
}

/// Fully-fixsliced AES-128 encryption (the ShiftRows is completely omitted).
///
/// Encrypts four blocks in-place and in parallel.
#[allow(dead_code)]
pub(crate) fn rijndael_encrypt(
    rkeys: &[u32],
    input: &[u8],
    nst: u8,
    _bc: u8,
    r: u8,
) -> BatchBlocks {
    let mut state = State::default();
    bitslice(&mut state, &input[..16], &input[16..]);
    rijndael_add_round_key(&mut state, &rkeys[..8]);
    let mut rk_off = 8;
    loop {
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);
        rijndael_shift_rows_1(&mut state, nst);
        mix_columns_0(&mut state);
        rijndael_add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;

        if rk_off == 8 * r as usize {
            break;
        }
    }
    //not even Mansour
    //192f ok
    //192s ok
    //temp_display_state(state);
    sub_bytes(&mut state);
    sub_bytes_nots(&mut state);
    rijndael_shift_rows_1(&mut state, nst);
    rijndael_add_round_key(&mut state, &rkeys[(r * 8) as usize..((r * 8) + 8) as usize]);
    inv_bitslice(&state)
}

/// Note that the 4 bitwise NOT (^= 0xffffffff) are accounted for here so that it is a true
/// inverse of 'sub_bytes'.
#[allow(dead_code)]
fn inv_sub_bytes(state: &mut [u32]) {
    debug_assert_eq!(state.len(), 8);

    // Scheduled using https://github.com/Ko-/aes-armcortexm/tree/public/scheduler
    // Inline "stack" comments reflect suggested stores and loads (ARM Cortex-M3 and M4)

    let u7 = state[0];
    let u6 = state[1];
    let u5 = state[2];
    let u4 = state[3];
    let u3 = state[4];
    let u2 = state[5];
    let u1 = state[6];
    let u0 = state[7];

    let t23 = u0 ^ u3;
    let t8 = u1 ^ t23;
    let m2 = t23 & t8;
    let t4 = u4 ^ t8;
    let t22 = u1 ^ u3;
    let t2 = u0 ^ u1;
    let t1 = u3 ^ u4;
    // t23 -> stack
    let t9 = u7 ^ t1;
    // t8 -> stack
    let m7 = t22 & t9;
    // t9 -> stack
    let t24 = u4 ^ u7;
    // m7 -> stack
    let t10 = t2 ^ t24;
    // u4 -> stack
    let m14 = t2 & t10;
    let r5 = u6 ^ u7;
    // m2 -> stack
    let t3 = t1 ^ r5;
    // t2 -> stack
    let t13 = t2 ^ r5;
    let t19 = t22 ^ r5;
    // t3 -> stack
    let t17 = u2 ^ t19;
    // t4 -> stack
    let t25 = u2 ^ t1;
    let r13 = u1 ^ u6;
    // t25 -> stack
    let t20 = t24 ^ r13;
    // t17 -> stack
    let m9 = t20 & t17;
    // t20 -> stack
    let r17 = u2 ^ u5;
    // t22 -> stack
    let t6 = t22 ^ r17;
    // t13 -> stack
    let m1 = t13 & t6;
    let y5 = u0 ^ r17;
    let m4 = t19 & y5;
    let m5 = m4 ^ m1;
    let m17 = m5 ^ t24;
    let r18 = u5 ^ u6;
    let t27 = t1 ^ r18;
    let t15 = t10 ^ t27;
    // t6 -> stack
    let m11 = t1 & t15;
    let m15 = m14 ^ m11;
    let m21 = m17 ^ m15;
    // t1 -> stack
    // t4 <- stack
    let m12 = t4 & t27;
    let m13 = m12 ^ m11;
    let t14 = t10 ^ r18;
    let m3 = t14 ^ m1;
    // m2 <- stack
    let m16 = m3 ^ m2;
    let m20 = m16 ^ m13;
    // u4 <- stack
    let r19 = u2 ^ u4;
    let t16 = r13 ^ r19;
    // t3 <- stack
    let t26 = t3 ^ t16;
    let m6 = t3 & t16;
    let m8 = t26 ^ m6;
    // t10 -> stack
    // m7 <- stack
    let m18 = m8 ^ m7;
    let m22 = m18 ^ m13;
    let m25 = m22 & m20;
    let m26 = m21 ^ m25;
    let m10 = m9 ^ m6;
    let m19 = m10 ^ m15;
    // t25 <- stack
    let m23 = m19 ^ t25;
    let m28 = m23 ^ m25;
    let m24 = m22 ^ m23;
    let m30 = m26 & m24;
    let m39 = m23 ^ m30;
    let m48 = m39 & y5;
    let m57 = m39 & t19;
    // m48 -> stack
    let m36 = m24 ^ m25;
    let m31 = m20 & m23;
    let m27 = m20 ^ m21;
    let m32 = m27 & m31;
    let m29 = m28 & m27;
    let m37 = m21 ^ m29;
    // m39 -> stack
    let m42 = m37 ^ m39;
    let m52 = m42 & t15;
    // t27 -> stack
    // t1 <- stack
    let m61 = m42 & t1;
    let p0 = m52 ^ m61;
    let p16 = m57 ^ m61;
    // m57 -> stack
    // t20 <- stack
    let m60 = m37 & t20;
    // p16 -> stack
    // t17 <- stack
    let m51 = m37 & t17;
    let m33 = m27 ^ m25;
    let m38 = m32 ^ m33;
    let m43 = m37 ^ m38;
    let m49 = m43 & t16;
    let p6 = m49 ^ m60;
    let p13 = m49 ^ m51;
    let m58 = m43 & t3;
    // t9 <- stack
    let m50 = m38 & t9;
    // t22 <- stack
    let m59 = m38 & t22;
    // p6 -> stack
    let p1 = m58 ^ m59;
    let p7 = p0 ^ p1;
    let m34 = m21 & m22;
    let m35 = m24 & m34;
    let m40 = m35 ^ m36;
    let m41 = m38 ^ m40;
    let m45 = m42 ^ m41;
    // t27 <- stack
    let m53 = m45 & t27;
    let p8 = m50 ^ m53;
    let p23 = p7 ^ p8;
    // t4 <- stack
    let m62 = m45 & t4;
    let p14 = m49 ^ m62;
    let s6 = p14 ^ p23;
    // t10 <- stack
    let m54 = m41 & t10;
    let p2 = m54 ^ m62;
    let p22 = p2 ^ p7;
    let s0 = p13 ^ p22;
    let p17 = m58 ^ p2;
    let p15 = m54 ^ m59;
    // t2 <- stack
    let m63 = m41 & t2;
    // m39 <- stack
    let m44 = m39 ^ m40;
    // p17 -> stack
    // t6 <- stack
    let m46 = m44 & t6;
    let p5 = m46 ^ m51;
    // p23 -> stack
    let p18 = m63 ^ p5;
    let p24 = p5 ^ p7;
    // m48 <- stack
    let p12 = m46 ^ m48;
    let s3 = p12 ^ p22;
    // t13 <- stack
    let m55 = m44 & t13;
    let p9 = m55 ^ m63;
    // p16 <- stack
    let s7 = p9 ^ p16;
    // t8 <- stack
    let m47 = m40 & t8;
    let p3 = m47 ^ m50;
    let p19 = p2 ^ p3;
    let s5 = p19 ^ p24;
    let p11 = p0 ^ p3;
    let p26 = p9 ^ p11;
    // t23 <- stack
    let m56 = m40 & t23;
    let p4 = m48 ^ m56;
    // p6 <- stack
    let p20 = p4 ^ p6;
    let p29 = p15 ^ p20;
    let s1 = p26 ^ p29;
    // m57 <- stack
    let p10 = m57 ^ p4;
    let p27 = p10 ^ p18;
    // p23 <- stack
    let s4 = p23 ^ p27;
    let p25 = p6 ^ p10;
    let p28 = p11 ^ p25;
    // p17 <- stack
    let s2 = p17 ^ p28;

    state[0] = s7;
    state[1] = s6;
    state[2] = s5;
    state[3] = s4;
    state[4] = s3;
    state[5] = s2;
    state[6] = s1;
    state[7] = s0;
}

/// Bitsliced implementation of the AES Sbox based on Boyar, Peralta and Calik.
///
/// See: <http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt>
///
/// Note that the 4 bitwise NOT (^= 0xffffffff) are moved to the key schedule.
pub fn sub_bytes(state: &mut [u32]) {
    // Scheduled using https://github.com/Ko-/aes-armcortexm/tree/public/scheduler
    // Inline "stack" comments reflect suggested stores and loads (ARM Cortex-M3 and M4)

    let u7 = state[0];
    let u6 = state[1];
    let u5 = state[2];
    let u4 = state[3];
    let u3 = state[4];
    let u2 = state[5];
    let u1 = state[6];
    let u0 = state[7];

    let y14 = u3 ^ u5;
    let y13 = u0 ^ u6;
    let y12 = y13 ^ y14;
    let t1 = u4 ^ y12;
    let y15 = t1 ^ u5;
    let t2 = y12 & y15;
    let y6 = y15 ^ u7;
    let y20 = t1 ^ u1;
    // y12 -> stack
    let y9 = u0 ^ u3;
    // y20 -> stack
    let y11 = y20 ^ y9;
    // y9 -> stack
    let t12 = y9 & y11;
    // y6 -> stack
    let y7 = u7 ^ y11;
    let y8 = u0 ^ u5;
    let t0 = u1 ^ u2;
    let y10 = y15 ^ t0;
    // y15 -> stack
    let y17 = y10 ^ y11;
    // y14 -> stack
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    // y17 -> stack
    let y19 = y10 ^ y8;
    // y10 -> stack
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let y16 = t0 ^ y11;
    // y11 -> stack
    let y21 = y13 ^ y16;
    // y13 -> stack
    let t7 = y13 & y16;
    // y16 -> stack
    let y18 = u0 ^ y16;
    let y1 = t0 ^ u7;
    let y4 = y1 ^ u3;
    // u7 -> stack
    let t5 = y4 & u7;
    let t6 = t5 ^ t2;
    let t18 = t6 ^ t16;
    let t22 = t18 ^ y19;
    let y2 = y1 ^ u0;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t20 = t11 ^ t16;
    let t24 = t20 ^ y18;
    let y5 = y1 ^ u6;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t19 = t9 ^ t14;
    let t23 = t19 ^ y21;
    let y3 = y5 ^ y8;
    // y6 <- stack
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    // y20 <- stack
    let t17 = t4 ^ y20;
    let t21 = t17 ^ t14;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t31 = t22 ^ t26;
    let t25 = t21 ^ t22;
    // y4 -> stack
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let z14 = t29 & y2;
    let z5 = t29 & y7;
    let t30 = t23 ^ t24;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t43 = t29 ^ t40;
    // y16 <- stack
    let z3 = t43 & y16;
    let tc12 = z3 ^ z5;
    // tc12 -> stack
    // y13 <- stack
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z4 = t40 & y1;
    let tc6 = z3 ^ z4;
    let t34 = t23 ^ t33;
    let t37 = t36 ^ t34;
    let t41 = t40 ^ t37;
    // y10 <- stack
    let z8 = t41 & y10;
    let z17 = t41 & y8;
    let t44 = t33 ^ t37;
    // y15 <- stack
    let z0 = t44 & y15;
    // z17 -> stack
    // y12 <- stack
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z1 = t37 & y6;
    let tc5 = z1 ^ z0;
    let tc11 = tc6 ^ tc5;
    // y4 <- stack
    let z11 = t33 & y4;
    let t42 = t29 ^ t33;
    let t45 = t42 ^ t41;
    // y17 <- stack
    let z7 = t45 & y17;
    let tc8 = z7 ^ tc6;
    // y14 <- stack
    let z16 = t45 & y14;
    // y11 <- stack
    let z6 = t42 & y11;
    let tc16 = z6 ^ tc8;
    // z14 -> stack
    // y9 <- stack
    let z15 = t42 & y9;
    let tc20 = z15 ^ tc16;
    let tc1 = z15 ^ z16;
    let tc2 = z10 ^ tc1;
    let tc21 = tc2 ^ z11;
    let tc3 = z9 ^ tc2;
    let s0 = tc3 ^ tc16;
    let s3 = tc3 ^ tc11;
    let s1 = s3 ^ tc16;
    let tc13 = z13 ^ tc1;
    // u7 <- stack
    let z2 = t33 & u7;
    let tc4 = z0 ^ z2;
    let tc7 = z12 ^ tc4;
    let tc9 = z8 ^ tc7;
    let tc10 = tc8 ^ tc9;
    // z14 <- stack
    let tc17 = z14 ^ tc10;
    let s5 = tc21 ^ tc17;
    let tc26 = tc17 ^ tc20;
    // z17 <- stack
    let s2 = tc26 ^ z17;
    // tc12 <- stack
    let tc14 = tc4 ^ tc12;
    let tc18 = tc13 ^ tc14;
    let s6 = tc10 ^ tc18;
    let s7 = z12 ^ tc18;
    let s4 = tc14 ^ s3;

    state[0] = s7;
    state[1] = s6;
    state[2] = s5;
    state[3] = s4;
    state[4] = s3;
    state[5] = s2;
    state[6] = s1;
    state[7] = s0;
}

/// NOT operations that are omitted in S-box
#[inline]
pub fn sub_bytes_nots(state: &mut [u32]) {
    debug_assert_eq!(state.len(), 8);
    state[0] ^= 0xffffffff;
    state[1] ^= 0xffffffff;
    state[5] ^= 0xffffffff;
    state[6] ^= 0xffffffff;
}

/// Computation of the MixColumns transformation in the fixsliced representation, with different
/// rotations used according to the round number mod 4.
///
/// Based on Käsper-Schwabe, similar to https://github.com/Ko-/aes-armcortexm.
macro_rules! define_mix_columns {
    (
        $name:ident,
        $name_inv:ident,
        $first_rotate:path,
        $second_rotate:path
    ) => {
        #[rustfmt::skip]
        pub fn $name(state: &mut State) {
            let (a0, a1, a2, a3, a4, a5, a6, a7) = (
                state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]
            );
            let (b0, b1, b2, b3, b4, b5, b6, b7) = (
                $first_rotate(a0),
                $first_rotate(a1),
                $first_rotate(a2),
                $first_rotate(a3),
                $first_rotate(a4),
                $first_rotate(a5),
                $first_rotate(a6),
                $first_rotate(a7),
            );
            let (c0, c1, c2, c3, c4, c5, c6, c7) = (
                a0 ^ b0,
                a1 ^ b1,
                a2 ^ b2,
                a3 ^ b3,
                a4 ^ b4,
                a5 ^ b5,
                a6 ^ b6,
                a7 ^ b7,
            );
            state[0] = b0      ^ c7 ^ $second_rotate(c0);
            state[1] = b1 ^ c0 ^ c7 ^ $second_rotate(c1);
            state[2] = b2 ^ c1      ^ $second_rotate(c2);
            state[3] = b3 ^ c2 ^ c7 ^ $second_rotate(c3);
            state[4] = b4 ^ c3 ^ c7 ^ $second_rotate(c4);
            state[5] = b5 ^ c4      ^ $second_rotate(c5);
            state[6] = b6 ^ c5      ^ $second_rotate(c6);
            state[7] = b7 ^ c6      ^ $second_rotate(c7);
        }

        #[rustfmt::skip]
        fn $name_inv(state: &mut State) {
            let (a0, a1, a2, a3, a4, a5, a6, a7) = (
                state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]
            );
            let (b0, b1, b2, b3, b4, b5, b6, b7) = (
                $first_rotate(a0),
                $first_rotate(a1),
                $first_rotate(a2),
                $first_rotate(a3),
                $first_rotate(a4),
                $first_rotate(a5),
                $first_rotate(a6),
                $first_rotate(a7),
            );
            let (c0, c1, c2, c3, c4, c5, c6, c7) = (
                a0 ^ b0,
                a1 ^ b1,
                a2 ^ b2,
                a3 ^ b3,
                a4 ^ b4,
                a5 ^ b5,
                a6 ^ b6,
                a7 ^ b7,
            );
            let (d0, d1, d2, d3, d4, d5, d6, d7) = (
                a0      ^ c7,
                a1 ^ c0 ^ c7,
                a2 ^ c1,
                a3 ^ c2 ^ c7,
                a4 ^ c3 ^ c7,
                a5 ^ c4,
                a6 ^ c5,
                a7 ^ c6,
            );
            let (e0, e1, e2, e3, e4, e5, e6, e7) = (
                c0      ^ d6,
                c1      ^ d6 ^ d7,
                c2 ^ d0      ^ d7,
                c3 ^ d1 ^ d6,
                c4 ^ d2 ^ d6 ^ d7,
                c5 ^ d3      ^ d7,
                c6 ^ d4,
                c7 ^ d5,
            );
            state[0] = d0 ^ e0 ^ $second_rotate(e0);
            state[1] = d1 ^ e1 ^ $second_rotate(e1);
            state[2] = d2 ^ e2 ^ $second_rotate(e2);
            state[3] = d3 ^ e3 ^ $second_rotate(e3);
            state[4] = d4 ^ e4 ^ $second_rotate(e4);
            state[5] = d5 ^ e5 ^ $second_rotate(e5);
            state[6] = d6 ^ e6 ^ $second_rotate(e6);
            state[7] = d7 ^ e7 ^ $second_rotate(e7);
        }
    }
}

define_mix_columns!(
    mix_columns_0,
    inv_mix_columns_0,
    rotate_rows_1,
    rotate_rows_2
);

define_mix_columns!(
    mix_columns_1,
    _inv_mix_columns_1,
    rotate_rows_and_columns_1_1,
    rotate_rows_and_columns_2_2
);

#[inline]
fn delta_swap_1(a: &mut u32, shift: u32, mask: u32) {
    let t = (*a ^ ((*a) >> shift)) & mask;
    *a ^= t ^ (t << shift);
}

#[inline]
fn delta_swap_2(a: &mut u32, b: &mut u32, shift: u32, mask: u32) {
    let t = (*a ^ ((*b) >> shift)) & mask;
    *a ^= t;
    *b ^= t << shift;
}

/// Applies ShiftRows once on an AES state (or key).################################################################################### check first rotate
///
///
/// /// Applies ShiftRows once on an AES state (or key).
#[cfg(any(not(aes_compact), feature = "hazmat"))]
#[inline]
pub fn rijndael_shift_rows_1(state: &mut [u32], bc: u8) {
    debug_assert_eq!(state.len(), 8);
    for x in state.iter_mut() {
        if bc == 4 {
            delta_swap_1(x, 4, 0x0c0f0300);
            delta_swap_1(x, 2, 0x33003300);
        } else if bc == 6 {
            delta_swap_1(x, 6, 0x01000000);
            delta_swap_1(x, 3, 0x000a0200);
            delta_swap_1(x, 2, 0x00003300);
            delta_swap_1(x, 1, 0x0a050400);
        } else {
            delta_swap_1(x, 4, 0x000c0300);
            delta_swap_1(x, 2, 0x00333300);
            delta_swap_1(x, 1, 0x55544000);
        }
    }
}

/// Applies ShiftRows twice on an AES state (or key).
#[inline]
pub fn rijndael_shift_rows_2(state: &mut [u32], bc: u8) {
    debug_assert_eq!(state.len(), 8);
    for x in state.iter_mut() {
        if bc == 4 {
            delta_swap_1(x, 4, 0x0f000f00);
            delta_swap_1(x, 1, 0x00000000);
        } else if bc == 6 {
            delta_swap_1(x, 4, 0x00050000);
            delta_swap_1(x, 3, 0x00000a00);
            delta_swap_1(x, 1, 0x00050500);
        } else {
            delta_swap_1(x, 4, 0x000f0f00);
            delta_swap_1(x, 2, 0x00000000);
            delta_swap_1(x, 1, 0x00055000);
        }
    }
}

/// Applies ShiftRows three times on an AES state (or key).
#[inline]
pub fn rijndael_shift_rows_3(state: &mut [u32], bc: u8) {
    debug_assert_eq!(state.len(), 8);
    for x in state.iter_mut() {
        if bc == 4 {
            delta_swap_1(x, 4, 0x030f0c00);
            delta_swap_1(x, 2, 0x33003300);
        } else if bc == 6 {
            delta_swap_1(x, 6, 0x01000100);
            delta_swap_1(x, 1, 0x0a000a00);
        } else {
            delta_swap_1(x, 4, 0x00030c00);
            delta_swap_1(x, 2, 0x00333300);
            delta_swap_1(x, 1, 0x55405400);
        }
    }
}

#[inline(always)]
fn rijndael_inv_shift_rows_1(state: &mut [u32], bc: u8) {
    if bc == 4 {
        rijndael_shift_rows_3(state, bc);
    } else {
        for x in state.iter_mut() {
            if bc == 6 {
                delta_swap_1(x, 1, 0x0a050400);
                delta_swap_1(x, 2, 0x00003300);
                delta_swap_1(x, 3, 0x000a0200);
                delta_swap_1(x, 6, 0x01000000);
            } else {
                delta_swap_1(x, 1, 0x55544000);
                delta_swap_1(x, 2, 0x00333300);
                delta_swap_1(x, 4, 0x000c0300);
            }
        }
    }
}

/// XOR the columns after the S-box during the key schedule round function.
///
/// The `idx_xor` parameter refers to the index of the previous round key that is
/// involved in the XOR computation (should be 8 and 16 for AES-128 and AES-256,
/// respectively).
///
/// The `idx_ror` parameter refers to the rotation value, which varies between the
/// different key schedules.
fn xor_columns(rkeys: &mut [u32], offset: usize, idx_xor: usize, idx_ror: u32, nk: u8) {
    if nk == 4 {
        for i in 0..8 {
            let off_i: usize = offset + i;
            let rk = rkeys[off_i - idx_xor] ^ (0x03030303 & ror(rkeys[off_i], idx_ror));
            rkeys[off_i] =
                rk ^ (0xfcfcfcfc & (rk << 2)) ^ (0xf0f0f0f0 & (rk << 4)) ^ (0xc0c0c0c0 & (rk << 6));
        }
    } else if nk == 6 {
        for i in 0..8 {
            let off_i = offset + i;
            let rk = rkeys[off_i - idx_xor] ^ (0x01010101 & ror(rkeys[off_i], idx_ror));
            rkeys[off_i] = rk
                ^ (0x5c5c5c5c & (rk << 2))
                ^ (0x02020202 & (rk >> 5))
                ^ (0x50505050 & (rk << 4))
                ^ (0x0a0a0a0a & (rk >> 3))
                ^ (0x0a0a0a0a & (rk << 1))
                ^ (0x0a0a0a0a & (rk >> 1))
                ^ (0x08080808 & (rk << 3))
                ^ (0x40404040 & (rk << 6));
        }
    } else {
        let mut temp = [0u32; 8];
        #[allow(clippy::needless_range_loop)]
        for i in 0..8 {
            let off_i = offset + i;
            let rk = rkeys[off_i - idx_xor] ^ (0x01010101 & ror(rkeys[off_i], idx_ror));
            rkeys[off_i] =
                rk ^ (0x54545454 & (rk << 2)) ^ (0x50505050 & (rk << 4)) ^ (0x40404040 & (rk << 6));
            temp[i] = rkeys[off_i];
        }
        //Not even Mansour
        //0 pour 256
        //192s see nothing
        //temp_display_state(temp);
        sub_bytes(&mut temp);
        sub_bytes_nots(&mut temp);
        for i in 0..8 {
            let off_i = offset + i;
            let rk = rkeys[off_i] ^ (temp[off_i % 8] & 0x40404040) >> 5;
            rkeys[off_i] =
                rk ^ (0xa8a8a8a8 & (rk << 2)) ^ (0xa0a0a0a0 & (rk << 4)) ^ (0x80808080 & (rk << 6));
        }
    }
}

/// Bitslice two 128-bit input blocks input0, input1 into a 256-bit internal state.
pub fn bitslice(output: &mut [u32], input0: &[u8], input1: &[u8]) {
    debug_assert_eq!(output.len(), 8);
    debug_assert_eq!(input0.len(), 16);
    debug_assert_eq!(input1.len(), 16);

    // Bitslicing is a bit index manipulation. 256 bits of data means each bit is positioned at an
    // 8-bit index. AES data is 2 blocks, each one a 4x4 column-major matrix of bytes, so the
    // index is initially ([b]lock, [c]olumn, [r]ow, [p]osition):
    //     b0 c1 c0 r1 r0 p2 p1 p0
    //
    // The desired bitsliced data groups first by bit position, then row, column, block:
    //     p2 p1 p0 r1 r0 c1 c0 b0

    // Interleave the columns on input (note the order of input)
    //     b0 c1 c0 __ __ __ __ __ => c1 c0 b0 __ __ __ __ __
    let mut t0 = u32::from_le_bytes(input0[0x00..0x04].try_into().unwrap());
    let mut t2 = u32::from_le_bytes(input0[0x04..0x08].try_into().unwrap());
    let mut t4 = u32::from_le_bytes(input0[0x08..0x0c].try_into().unwrap());
    let mut t6 = u32::from_le_bytes(input0[0x0c..0x10].try_into().unwrap());
    let mut t1 = u32::from_le_bytes(input1[0x00..0x04].try_into().unwrap());
    let mut t3 = u32::from_le_bytes(input1[0x04..0x08].try_into().unwrap());
    let mut t5 = u32::from_le_bytes(input1[0x08..0x0c].try_into().unwrap());
    let mut t7 = u32::from_le_bytes(input1[0x0c..0x10].try_into().unwrap());

    // Bit Index Swap 5 <-> 0:
    //     __ __ b0 __ __ __ __ p0 => __ __ p0 __ __ __ __ b0
    let m0 = 0x55555555;
    delta_swap_2(&mut t1, &mut t0, 1, m0);
    delta_swap_2(&mut t3, &mut t2, 1, m0);
    delta_swap_2(&mut t5, &mut t4, 1, m0);
    delta_swap_2(&mut t7, &mut t6, 1, m0);

    // Bit Index Swap 6 <-> 1:
    //     __ c0 __ __ __ __ p1 __ => __ p1 __ __ __ __ c0 __
    let m1 = 0x33333333;
    delta_swap_2(&mut t2, &mut t0, 2, m1);
    delta_swap_2(&mut t3, &mut t1, 2, m1);
    delta_swap_2(&mut t6, &mut t4, 2, m1);
    delta_swap_2(&mut t7, &mut t5, 2, m1);

    // Bit Index Swap 7 <-> 2:
    //     c1 __ __ __ __ p2 __ __ => p2 __ __ __ __ c1 __ __
    let m2 = 0x0f0f0f0f;
    delta_swap_2(&mut t4, &mut t0, 4, m2);
    delta_swap_2(&mut t5, &mut t1, 4, m2);
    delta_swap_2(&mut t6, &mut t2, 4, m2);
    delta_swap_2(&mut t7, &mut t3, 4, m2);

    // Final bitsliced bit index, as desired:
    //     p2 p1 p0 r1 r0 c1 c0 b0
    output[0] = t0;
    output[1] = t1;
    output[2] = t2;
    output[3] = t3;
    output[4] = t4;
    output[5] = t5;
    output[6] = t6;
    output[7] = t7;
}

/// Un-bitslice a 256-bit internal state into two 128-bit blocks of output.
pub fn inv_bitslice(input: &[u32]) -> BatchBlocks {
    debug_assert_eq!(input.len(), 8);

    // Unbitslicing is a bit index manipulation. 256 bits of data means each bit is positioned at
    // an 8-bit index. AES data is 2 blocks, each one a 4x4 column-major matrix of bytes, so the
    // desired index for the output is ([b]lock, [c]olumn, [r]ow, [p]osition):
    //     b0 c1 c0 r1 r0 p2 p1 p0
    //
    // The initially bitsliced data groups first by bit position, then row, column, block:
    //     p2 p1 p0 r1 r0 c1 c0 b0

    let mut t0 = input[0];
    let mut t1 = input[1];
    let mut t2 = input[2];
    let mut t3 = input[3];
    let mut t4 = input[4];
    let mut t5 = input[5];
    let mut t6 = input[6];
    let mut t7 = input[7];

    // TODO: these bit index swaps are identical to those in 'packing'

    // Bit Index Swap 5 <-> 0:
    //     __ __ p0 __ __ __ __ b0 => __ __ b0 __ __ __ __ p0
    let m0 = 0x55555555;
    delta_swap_2(&mut t1, &mut t0, 1, m0);
    delta_swap_2(&mut t3, &mut t2, 1, m0);
    delta_swap_2(&mut t5, &mut t4, 1, m0);
    delta_swap_2(&mut t7, &mut t6, 1, m0);

    // Bit Index Swap 6 <-> 1:
    //     __ p1 __ __ __ __ c0 __ => __ c0 __ __ __ __ p1 __
    let m1 = 0x33333333;
    delta_swap_2(&mut t2, &mut t0, 2, m1);
    delta_swap_2(&mut t3, &mut t1, 2, m1);
    delta_swap_2(&mut t6, &mut t4, 2, m1);
    delta_swap_2(&mut t7, &mut t5, 2, m1);

    // Bit Index Swap 7 <-> 2:
    //     p2 __ __ __ __ c1 __ __ => c1 __ __ __ __ p2 __ __
    let m2 = 0x0f0f0f0f;
    delta_swap_2(&mut t4, &mut t0, 4, m2);
    delta_swap_2(&mut t5, &mut t1, 4, m2);
    delta_swap_2(&mut t6, &mut t2, 4, m2);
    delta_swap_2(&mut t7, &mut t3, 4, m2);

    let mut output = BatchBlocks::default();
    // De-interleave the columns on output (note the order of output)
    //     c1 c0 b0 __ __ __ __ __ => b0 c1 c0 __ __ __ __ __
    output[0][0x00..0x04].copy_from_slice(&t0.to_le_bytes());
    output[0][0x04..0x08].copy_from_slice(&t2.to_le_bytes());
    output[0][0x08..0x0c].copy_from_slice(&t4.to_le_bytes());
    output[0][0x0c..0x10].copy_from_slice(&t6.to_le_bytes());
    output[1][0x00..0x04].copy_from_slice(&t1.to_le_bytes());
    output[1][0x04..0x08].copy_from_slice(&t3.to_le_bytes());
    output[1][0x08..0x0c].copy_from_slice(&t5.to_le_bytes());
    output[1][0x0c..0x10].copy_from_slice(&t7.to_le_bytes());

    // Final AES bit index, as desired:
    //     b0 c1 c0 r1 r0 p2 p1 p0
    output
}

pub fn convert_from_batchblocks(input: BatchBlocks) -> Vec<u32> {
    let mut output = Vec::<u32>::new();
    for i in 0..2 {
        for j in 0..4 {
            output.push(u32::from_le_bytes(
                input[i][j * 4..(j + 1) * 4].try_into().unwrap(),
            ));
        }
    }
    output
}

/// Copy 32-bytes within the provided slice to an 8-byte offset
fn memshift32(buffer: &mut [u32], src_offset: usize) {
    debug_assert_eq!(src_offset % 8, 0);
    let dst_offset = src_offset + 8;
    debug_assert!(dst_offset + 8 <= buffer.len());

    for i in (0..8).rev() {
        buffer[dst_offset + i] = buffer[src_offset + i];
    }
}

/// XOR the round key to the internal state. The round keys are expected to be
/// pre-computed and to be packed in the fixsliced representation.
#[inline]
pub fn rijndael_add_round_key(state: &mut State, rkey: &[u32]) {
    debug_assert_eq!(rkey.len(), 8);
    for (a, b) in state.iter_mut().zip(rkey) {
        *a ^= b;
    }
}

#[inline(always)]
fn ror(x: u32, y: u32) -> u32 {
    x.rotate_right(y)
}

#[inline(always)]
fn ror_distance(rows: u32, cols: u32) -> u32 {
    (rows << 3) + (cols << 1)
}

#[inline(always)]
fn rotate_rows_1(x: u32) -> u32 {
    ror(x, ror_distance(1, 0))
}

#[inline(always)]
fn rotate_rows_2(x: u32) -> u32 {
    ror(x, ror_distance(2, 0))
}

#[inline(always)]
#[rustfmt::skip]
fn rotate_rows_and_columns_1_1(x: u32) -> u32 {
    (ror(x, ror_distance(1, 1)) & 0x3f3f3f3f) |
    (ror(x, ror_distance(0, 1)) & 0xc0c0c0c0)
}

#[inline(always)]
#[rustfmt::skip]
fn rotate_rows_and_columns_2_2(x: u32) -> u32 {
    (ror(x, ror_distance(2, 2)) & 0x0f0f0f0f) |
    (ror(x, ror_distance(1, 2)) & 0xf0f0f0f0)
}

#[cfg(test)]
mod test {
    use rand::Rng;
    use serde::Deserialize;
    use std::{cmp::max, fs::File};

    use super::*;

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
                    input[i as usize] +=
                        (data.input[(j * 4 + i) as usize] as u32) << (24 - (j) * 8);
                    output[i as usize] +=
                        (data.output[(i * 4 + j) as usize] as u32) << (24 - (j) * 8);
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
                    input[i as usize] += (res[(i / 4) as usize][(((i % 4) * 4) + j) as usize]
                        as u32)
                        << (24 - (j) * 8);
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
                    input[i as usize] +=
                        (data.input[(j * 4 + i) as usize] as u32) << (24 - (j) * 8);
                    output[i as usize] +=
                        (data.output[(i * 4 + j) as usize] as u32) << (24 - (j) * 8);
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
                    input[i as usize] += (res[(i / 4) as usize][(((i % 4) * 4) + j) as usize]
                        as u32)
                        << (24 - (j) * 8);
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
            let rkeys = rijndael_key_schedule(
                &data.key,
                data.bc,
                data.kc,
                r,
                4 * (((r + 1) * data.bc) / data.kc),
            );
            let res = rijndael_encrypt(&rkeys.0, &input, data.bc, data.bc, r);
            let mut input = [0u32; 8];
            let mut output = [0u32; 8];
            for i in 0..data.bc {
                for j in 0..4 {
                    input[i as usize] += (res[(i / 4) as usize][(((i % 4) * 4) + j) as usize]
                        as u32)
                        << (24 - (j) * 8);
                    output[i as usize] +=
                        (data.output[(i * 4 + j) as usize] as u32) << (24 - (j) * 8);
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
                    let (rkeys, valid) =
                        rijndael_key_schedule(&key, bc, kc, r, 4 * (((r + 1) * bc) / kc));
                    let crypted = rijndael_encrypt(&rkeys, &padded_text, bc, bc, r);
                    let res = rijndael_decrypt(&rkeys, &crypted, bc, r);
                    bitslice(&mut state_text, &padded_text[..16], &padded_text[16..]);
                    assert_eq!(res, inv_bitslice(&state_text));
                }
            }
        }
    }
}
