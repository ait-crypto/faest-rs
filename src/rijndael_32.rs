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

use aes::{
    cipher::{
        generic_array::typenum::{U24, U32},
        BlockEncrypt, BlockSizeUser, KeyInit, KeySizeUser,
    },
    Block,
};
use generic_array::{
    typenum::{Unsigned, U12, U14, U2, U6, U8},
    GenericArray,
};
#[cfg(feature = "zeroize")]
use zeroize::ZeroizeOnDrop;

/// AES block batch size for this implementation
pub(crate) type FixsliceBlocks = U2;

pub(crate) type BatchBlocks = GenericArray<Block, FixsliceBlocks>;

/// 256-bit internal state
pub(crate) type State = [u32; 8];

pub(crate) const RCON_TABLE: [u8; 30] = [
    1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53,
    106, 212, 179, 125, 250, 239, 197, 145,
];

/// Fully bitsliced Rijndael key schedule to match the fully-fixsliced representation.
pub(crate) fn rijndael_key_schedule<NST: Unsigned, NK: Unsigned, R: Unsigned>(
    key: &[u8],
    ske: usize,
) -> (Vec<u32>, bool) {
    let mut valid = true;
    let mut rkeys = vec![0u32; (NST::USIZE.div_ceil(NK::USIZE) * 8 * (R::USIZE + 1)) + 8];

    bitslice(&mut rkeys[..8], &key[..16], &key[16..]);

    let mut rk_off = 0;
    let mut count = 0;
    for rcon in RCON_TABLE.iter().take(ske / 4) {
        if NK::USIZE == 8 {
            if count < ske / 4 {
                for i in inv_bitslice(&rkeys[rk_off..(rk_off + 8)])[1][12..].iter() {
                    valid &= 0 != *i;
                }
                count += 1
            }
        } else if NK::USIZE == 6 {
            for i in inv_bitslice(&rkeys[rk_off..(rk_off + 8)])[1][4..8].iter() {
                valid &= 0 != *i;
            }
        } else {
            for i in inv_bitslice(&rkeys[rk_off..(rk_off + 8)])[0][12..].iter() {
                valid &= 0 != *i;
            }
        }
        memshift32(&mut rkeys, rk_off);
        rk_off += 8;
        sub_bytes(&mut rkeys[rk_off..(rk_off + 8)]);
        sub_bytes_nots(&mut rkeys[rk_off..(rk_off + 8)]);

        let ind = (NK::USIZE * 4) as u8;
        let mut rcon_0 = [0u8; 16];
        let mut rcon_1 = [0u8; 16];
        rcon_0[13] = rcon * (1 - ind / 17);
        rcon_1[5] = (*rcon as u16 * (((ind / 8) % 2) as u16)) as u8;
        rcon_1[13] = rcon * (ind / 32);
        let mut bitsliced_rcon = [0u32; 8];
        bitslice(&mut bitsliced_rcon, &rcon_0, &rcon_1);

        for j in 0..8 {
            rkeys[rk_off + j] ^= bitsliced_rcon[j];
        }

        xor_columns::<NK>(&mut rkeys, rk_off);
        if NK::USIZE == 8 && count < ske / 4 {
            for i in inv_bitslice(&rkeys[rk_off..(rk_off + 8)])[0][12..].iter() {
                valid &= 0 != *i;
            }
            count += 1
        }
    }

    let mut final_res: Vec<u8> = vec![];
    if NK::USIZE == 4 {
        for i in 0..rkeys.len() / 8 {
            let res = inv_bitslice(&rkeys[i * 8..(i + 1) * 8]);
            if NST::USIZE == 4 {
                final_res.extend_from_slice(&res[0][0..16]);
                final_res.resize(final_res.len() + 16, 0);
            } else if NST::USIZE == 6 {
                if i % 3 == 0 {
                    final_res.extend_from_slice(&res[0][0..16]);
                } else if i % 3 == 1 {
                    final_res.extend_from_slice(&res[0][0..8]);
                    final_res.resize(final_res.len() + 8, 0);
                    final_res.extend_from_slice(&res[0][8..16]);
                } else {
                    final_res.extend_from_slice(&res[0][0..16]);
                    final_res.resize(final_res.len() + 8, 0);
                }
            } else {
                final_res.extend_from_slice(&res[0][0..16]);
            }
        }
    } else if NK::USIZE == 6 {
        for i in 0..rkeys.len() / 8 {
            let res = inv_bitslice(&rkeys[i * 8..(i + 1) * 8]);
            if NST::USIZE == 4 {
                if i % 2 == 0 {
                    final_res.extend_from_slice(&res[0][0..16]);
                    final_res.resize(final_res.len() + 16, 0);
                    final_res.extend_from_slice(&res[1][0..8]);
                } else {
                    final_res.extend_from_slice(&res[0][0..8]);
                    final_res.resize(final_res.len() + 16, 0);
                    final_res.extend_from_slice(&res[0][8..16]);
                    final_res.extend_from_slice(&res[1][0..8]);
                    final_res.resize(final_res.len() + 16, 0);
                }
            } else if NST::USIZE == 6 {
                final_res.extend_from_slice(&res[0][0..16]);
                final_res.extend_from_slice(&res[1][0..8]);
                final_res.resize(final_res.len() + 8, 0);
            } else {
                final_res.extend_from_slice(&res[0][0..16]);
                final_res.extend_from_slice(&res[1][0..8]);
            }
        }
    } else {
        for i in 0..rkeys.len() / 8 {
            let res = inv_bitslice(&rkeys[i * 8..(i + 1) * 8]);
            if NST::USIZE == 4 {
                final_res.extend_from_slice(&res[0][0..16]);
                final_res.resize(final_res.len() + 16, 0);
                final_res.extend_from_slice(&res[1][0..16]);
                final_res.resize(final_res.len() + 16, 0);
            } else if NST::USIZE == 6 {
                if i % 3 == 0 {
                    final_res.extend_from_slice(&res[0][0..16]);
                    final_res.extend_from_slice(&res[1][0..8]);
                    final_res.resize(final_res.len() + 8, 0);
                    final_res.extend_from_slice(&res[1][8..16]);
                } else if i % 3 == 1 {
                    final_res.extend_from_slice(&res[0][0..16]);
                    final_res.resize(final_res.len() + 8, 0);
                    final_res.extend_from_slice(&res[1][0..16]);
                } else {
                    final_res.extend_from_slice(&res[0][0..8]);
                    final_res.resize(final_res.len() + 8, 0);
                    final_res.extend_from_slice(&res[0][8..16]);
                    final_res.extend_from_slice(&res[1][0..16]);
                    final_res.resize(final_res.len() + 8, 0);
                }
            } else {
                final_res.extend_from_slice(&res[0][0..16]);
                final_res.extend_from_slice(&res[1][0..16]);
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

/// Fully-fixsliced AES-128 encryption (the ShiftRows is completely omitted).
///
/// Encrypts four blocks in-place and in parallel.
fn rijndael_encrypt<NST: Unsigned, R: Unsigned>(rkeys: &[u32], input: &[u8]) -> BatchBlocks {
    let mut state = State::default();
    bitslice(&mut state, &input[..16], &input[16..]);
    rijndael_add_round_key(&mut state, &rkeys[..8]);
    let mut rk_off = 8;
    loop {
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);
        rijndael_shift_rows_1::<NST>(&mut state);
        mix_columns_0(&mut state);
        rijndael_add_round_key(&mut state, &rkeys[rk_off..(rk_off + 8)]);
        rk_off += 8;

        if rk_off == 8 * R::USIZE {
            break;
        }
    }

    sub_bytes(&mut state);
    sub_bytes_nots(&mut state);
    rijndael_shift_rows_1::<NST>(&mut state);
    rijndael_add_round_key(&mut state, &rkeys[R::USIZE * 8..(R::USIZE * 8) + 8]);
    inv_bitslice(&state)
}

/// Bitsliced implementation of the AES Sbox based on Boyar, Peralta and Calik.
///
/// See: <http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt>
///
/// Note that the 4 bitwise NOT (^= 0xffffffff) are moved to the key schedule.
pub(crate) fn sub_bytes(state: &mut [u32]) {
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
pub(crate) fn sub_bytes_nots(state: &mut [u32]) {
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
pub(crate) fn mix_columns_0(state: &mut State) {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );
    let (b0, b1, b2, b3, b4, b5, b6, b7) = (
        rotate_rows_1(a0),
        rotate_rows_1(a1),
        rotate_rows_1(a2),
        rotate_rows_1(a3),
        rotate_rows_1(a4),
        rotate_rows_1(a5),
        rotate_rows_1(a6),
        rotate_rows_1(a7),
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
    state[0] = b0 ^ c7 ^ rotate_rows_2(c0);
    state[1] = b1 ^ c0 ^ c7 ^ rotate_rows_2(c1);
    state[2] = b2 ^ c1 ^ rotate_rows_2(c2);
    state[3] = b3 ^ c2 ^ c7 ^ rotate_rows_2(c3);
    state[4] = b4 ^ c3 ^ c7 ^ rotate_rows_2(c4);
    state[5] = b5 ^ c4 ^ rotate_rows_2(c5);
    state[6] = b6 ^ c5 ^ rotate_rows_2(c6);
    state[7] = b7 ^ c6 ^ rotate_rows_2(c7);
}

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

/// Applies ShiftRows once on an AES state (or key).
#[inline]
pub(crate) fn rijndael_shift_rows_1<BC: Unsigned>(state: &mut [u32]) {
    debug_assert_eq!(state.len(), 8);
    for x in state.iter_mut() {
        if BC::USIZE == 4 {
            delta_swap_1(x, 4, 0x0c0f0300);
            delta_swap_1(x, 2, 0x33003300);
        } else if BC::USIZE == 6 {
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

/// XOR the columns after the S-box during the key schedule round function.
fn xor_columns<NK: Unsigned>(rkeys: &mut [u32], offset: usize) {
    if NK::USIZE == 4 {
        for i in 0..8 {
            let off_i: usize = offset + i;
            let rk = rkeys[off_i - 8] ^ (0x03030303 & ror(rkeys[off_i], 14));
            rkeys[off_i] =
                rk ^ (0xfcfcfcfc & (rk << 2)) ^ (0xf0f0f0f0 & (rk << 4)) ^ (0xc0c0c0c0 & (rk << 6));
        }
    } else if NK::USIZE == 6 {
        for i in 0..8 {
            let off_i = offset + i;
            let rk = rkeys[off_i - 8] ^ (0x01010101 & ror(rkeys[off_i], 11));
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
        let mut temp = State::default();
        for (i, t) in temp.iter_mut().enumerate() {
            let off_i = offset + i;
            let rk = rkeys[off_i - 8] ^ (0x01010101 & ror(rkeys[off_i], 15));
            rkeys[off_i] =
                rk ^ (0x54545454 & (rk << 2)) ^ (0x50505050 & (rk << 4)) ^ (0x40404040 & (rk << 6));
            *t = rkeys[off_i];
        }
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

const M0: u32 = 0x55555555;
const M1: u32 = 0x33333333;
const M2: u32 = 0x0f0f0f0f;

/// Bitslice two 128-bit input blocks input0, input1 into a 256-bit internal state.
pub(crate) fn bitslice(output: &mut [u32], input0: &[u8], input1: &[u8]) {
    debug_assert_eq!(output.len(), 8);
    debug_assert_eq!(input0.len(), 16);
    debug_assert!(input1.is_empty() || input1.len() == 16 || input1.len() == 8);

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
    let mut t1 = if !input1.is_empty() {
        u32::from_le_bytes(input1[0x00..0x04].try_into().unwrap())
    } else {
        0
    };
    let mut t3 = if !input1.is_empty() {
        u32::from_le_bytes(input1[0x04..0x08].try_into().unwrap())
    } else {
        0
    };
    let mut t5 = if input1.len() > 8 {
        u32::from_le_bytes(input1[0x08..0x0c].try_into().unwrap())
    } else {
        0
    };
    let mut t7 = if input1.len() > 8 {
        u32::from_le_bytes(input1[0x0c..0x10].try_into().unwrap())
    } else {
        0
    };

    // Bit Index Swap 5 <-> 0:
    //     __ __ b0 __ __ __ __ p0 => __ __ p0 __ __ __ __ b0
    delta_swap_2(&mut t1, &mut t0, 1, M0);
    delta_swap_2(&mut t3, &mut t2, 1, M0);
    delta_swap_2(&mut t5, &mut t4, 1, M0);
    delta_swap_2(&mut t7, &mut t6, 1, M0);

    // Bit Index Swap 6 <-> 1:
    //     __ c0 __ __ __ __ p1 __ => __ p1 __ __ __ __ c0 __
    delta_swap_2(&mut t2, &mut t0, 2, M1);
    delta_swap_2(&mut t3, &mut t1, 2, M1);
    delta_swap_2(&mut t6, &mut t4, 2, M1);
    delta_swap_2(&mut t7, &mut t5, 2, M1);

    // Bit Index Swap 7 <-> 2:
    //     c1 __ __ __ __ p2 __ __ => p2 __ __ __ __ c1 __ __
    delta_swap_2(&mut t4, &mut t0, 4, M2);
    delta_swap_2(&mut t5, &mut t1, 4, M2);
    delta_swap_2(&mut t6, &mut t2, 4, M2);
    delta_swap_2(&mut t7, &mut t3, 4, M2);

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
pub(crate) fn inv_bitslice(input: &[u32]) -> BatchBlocks {
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
    delta_swap_2(&mut t1, &mut t0, 1, M0);
    delta_swap_2(&mut t3, &mut t2, 1, M0);
    delta_swap_2(&mut t5, &mut t4, 1, M0);
    delta_swap_2(&mut t7, &mut t6, 1, M0);

    // Bit Index Swap 6 <-> 1:
    //     __ p1 __ __ __ __ c0 __ => __ c0 __ __ __ __ p1 __
    delta_swap_2(&mut t2, &mut t0, 2, M1);
    delta_swap_2(&mut t3, &mut t1, 2, M1);
    delta_swap_2(&mut t6, &mut t4, 2, M1);
    delta_swap_2(&mut t7, &mut t5, 2, M1);

    // Bit Index Swap 7 <-> 2:
    //     p2 __ __ __ __ c1 __ __ => c1 __ __ __ __ p2 __ __
    delta_swap_2(&mut t4, &mut t0, 4, M2);
    delta_swap_2(&mut t5, &mut t1, 4, M2);
    delta_swap_2(&mut t6, &mut t2, 4, M2);
    delta_swap_2(&mut t7, &mut t3, 4, M2);

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

pub(crate) fn convert_from_batchblocks(input: BatchBlocks) -> Vec<u32> {
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
pub(crate) fn rijndael_add_round_key(state: &mut State, rkey: &[u32]) {
    debug_assert_eq!(rkey.len(), 8);
    for (a, b) in state.iter_mut().zip(rkey) {
        *a ^= b;
    }
}

#[inline(always)]
const fn ror(x: u32, y: usize) -> u32 {
    x.rotate_right(y as u32)
}

#[inline(always)]
const fn ror_distance(rows: usize, cols: usize) -> usize {
    (rows << 3) + (cols << 1)
}

#[inline(always)]
const fn rotate_rows_1(x: u32) -> u32 {
    ror(x, ror_distance(1, 0))
}

#[inline(always)]
const fn rotate_rows_2(x: u32) -> u32 {
    ror(x, ror_distance(2, 0))
}

const fn ske(r: usize, nst: usize, nk: usize) -> usize {
    4 * (r + 1) * nst / nk
}

#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub(crate) struct Rijndael192(Vec<u32>);

impl KeySizeUser for Rijndael192 {
    type KeySize = U24;
}

impl KeyInit for Rijndael192 {
    fn new(key: &aes::cipher::Key<Self>) -> Self {
        Self(rijndael_key_schedule::<U6, U6, U12>(key.as_slice(), ske(12, 6, 6)).0)
    }
}

impl BlockSizeUser for Rijndael192 {
    type BlockSize = U24;
}

impl BlockEncrypt for Rijndael192 {
    fn encrypt_with_backend(
        &self,
        _f: impl aes::cipher::BlockClosure<BlockSize = Self::BlockSize>,
    ) {
        unimplemented!();
    }

    fn encrypt_block_b2b(
        &self,
        in_block: &aes::cipher::Block<Self>,
        out_block: &mut aes::cipher::Block<Self>,
    ) {
        let out = rijndael_encrypt::<U6, U12>(&self.0, in_block.as_slice());
        out_block[..16].copy_from_slice(&out[0]);
        out_block[16..].copy_from_slice(&out[1][..8]);
    }
}

#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub(crate) struct Rijndael256(Vec<u32>);

impl KeySizeUser for Rijndael256 {
    type KeySize = U32;
}

impl KeyInit for Rijndael256 {
    fn new(key: &aes::cipher::Key<Self>) -> Self {
        Self(rijndael_key_schedule::<U8, U8, U14>(key.as_slice(), ske(14, 8, 8)).0)
    }
}

impl BlockSizeUser for Rijndael256 {
    type BlockSize = U32;
}

impl BlockEncrypt for Rijndael256 {
    fn encrypt_with_backend(
        &self,
        _f: impl aes::cipher::BlockClosure<BlockSize = Self::BlockSize>,
    ) {
        unimplemented!();
    }

    fn encrypt_block_b2b(
        &self,
        in_block: &aes::cipher::Block<Self>,
        out_block: &mut aes::cipher::Block<Self>,
    ) {
        let out = rijndael_encrypt::<U8, U14>(&self.0, in_block.as_slice());
        out_block[..16].copy_from_slice(&out[0]);
        out_block[16..].copy_from_slice(&out[1]);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::cmp::max;

    use aes::cipher::generic_array::GenericArray;
    use generic_array::typenum::{U10, U12, U14, U4, U6, U8};
    use serde::Deserialize;

    use crate::utils::test::read_test_data;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Rijndael {
        kc: usize,
        bc: usize,
        key: Vec<u8>,
        text: Vec<u8>,
        output: Vec<u8>,
    }

    fn rijndael_key_schedule(key: &[u8], bc: usize, kc: usize, ske: usize) -> (Vec<u32>, bool) {
        match (bc, kc) {
            (4, 4) => super::rijndael_key_schedule::<U4, U4, U10>(key, ske),
            (6, 4) => super::rijndael_key_schedule::<U6, U4, U12>(key, ske),
            (8, 4) => super::rijndael_key_schedule::<U8, U4, U14>(key, ske),
            (4, 6) => super::rijndael_key_schedule::<U4, U6, U12>(key, ske),
            (6, 6) => super::rijndael_key_schedule::<U6, U6, U12>(key, ske),
            (8, 6) => super::rijndael_key_schedule::<U8, U6, U14>(key, ske),
            (4, 8) => super::rijndael_key_schedule::<U4, U8, U14>(key, ske),
            (6, 8) => super::rijndael_key_schedule::<U6, U8, U14>(key, ske),
            (8, 8) => super::rijndael_key_schedule::<U8, U8, U14>(key, ske),
            _ => unreachable!(),
        }
    }

    fn rijndael_encrypt(rkeys: &[u32], input: &[u8], nst: usize, r: usize) -> BatchBlocks {
        match (nst, r) {
            (4, 10) => super::rijndael_encrypt::<U4, U10>(rkeys, input),
            (6, 12) => super::rijndael_encrypt::<U6, U12>(rkeys, input),
            (8, 14) => super::rijndael_encrypt::<U8, U14>(rkeys, input),
            (4, 12) => super::rijndael_encrypt::<U4, U12>(rkeys, input),
            (8, 12) => super::rijndael_encrypt::<U8, U14>(rkeys, input),
            (4, 14) => super::rijndael_encrypt::<U4, U14>(rkeys, input),
            (6, 14) => super::rijndael_encrypt::<U6, U14>(rkeys, input),
            _ => unreachable!(),
        }
    }

    #[test]
    fn rijndael_test() {
        let database: Vec<Rijndael> = read_test_data("rijndael_data.json");
        for data in database {
            let mut input = [0u8; 32];
            input[..data.text.len()].copy_from_slice(&data.text[..]);
            let r = max(data.bc, data.kc) + 6;
            let rkeys = rijndael_key_schedule(
                &data.key,
                data.bc,
                data.kc,
                4 * (((r + 1) * data.bc) / data.kc),
            );
            let res = rijndael_encrypt(&rkeys.0, &input, data.bc, r);
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
    fn test_rijndael192() {
        let mut key = GenericArray::default();
        key[0] = 0x80;

        let expected = [
            0x56, 0x4d, 0x36, 0xfd, 0xeb, 0x8b, 0xf7, 0xe2, 0x75, 0xf0, 0x10, 0xb2, 0xf5, 0xee,
            0x69, 0xcf, 0xea, 0xe6, 0x7e, 0xa0, 0xe3, 0x7e, 0x32, 0x09,
        ];

        let rijndael = Rijndael192::new(&key);
        let plaintext = GenericArray::default();
        let mut ciphertext = GenericArray::default();

        rijndael.encrypt_block_b2b(&plaintext, &mut ciphertext);
        assert_eq!(ciphertext.as_slice(), &expected);
    }

    #[test]
    fn test_rijndael256() {
        let mut key = GenericArray::default();
        key[0] = 0x80;

        let expected = [
            0xE6, 0x2A, 0xBC, 0xE0, 0x69, 0x83, 0x7B, 0x65, 0x30, 0x9B, 0xE4, 0xED, 0xA2, 0xC0,
            0xE1, 0x49, 0xFE, 0x56, 0xC0, 0x7B, 0x70, 0x82, 0xD3, 0x28, 0x7F, 0x59, 0x2C, 0x4A,
            0x49, 0x27, 0xA2, 0x77,
        ];

        let rijndael = Rijndael256::new(&key);
        let plaintext = GenericArray::default();
        let mut ciphertext = GenericArray::default();

        rijndael.encrypt_block_b2b(&plaintext, &mut ciphertext);
        assert_eq!(ciphertext.as_slice(), &expected);
    }
}
