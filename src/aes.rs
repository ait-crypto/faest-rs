use std::{array, mem::size_of};

use generic_array::{
    typenum::{Unsigned, U3, U4},
    GenericArray,
};
use itertools::iproduct;

use crate::{
    fields::{small_fields::{GF8, GF8_INV_NORM}, ByteCombine, ByteCombineConstants, Field as _, SumPoly},
    // internal_keys::PublicKey,
    parameter::{BaseParameters, OWFParameters, QSProof, TauParameters},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, sub_bytes, sub_bytes_nots, State, RCON_TABLE,
    },
    universal_hashing::{ZKHasherInit, ZKProofHasher, ZKVerifyHasher},
    utils::contains_zeros,
};

// type KeyCstrnts<O> = (
//     Box<GenericArray<u8, <O as OWFParameters>::PRODRUN128Bytes>>,
//     Box<GenericArray<Field<O>, <O as OWFParameters>::PRODRUN128>>,
// );

// type CstrntsVal<'a, O> = &'a GenericArray<
//     GenericArray<u8, <O as OWFParameters>::LAMBDALBYTES>,
//     <O as OWFParameters>::LAMBDA,
// >;

const fn inverse_rotate_word(r: usize, rotate: bool) -> usize {
    if rotate {
        // equivalent to (r - 3) % 4
        (r + 1) % 4
    } else {
        r
    }
}

pub(crate) fn aes_extendedwitness<O>(
    owf_key: &GenericArray<u8, O::LAMBDABYTES>,
    owf_input: &GenericArray<u8, O::InputSize>,
) -> Option<Box<GenericArray<u8, O::LBYTES>>>
where
    O: OWFParameters,
{
    // Step 0
    let mut input: GenericArray<u8, O::InputSize> = GenericArray::default();
    input.copy_from_slice(owf_input);

    // Step 3
    let mut witness = GenericArray::default_boxed();
    let mut index = 0;

    // Step 6
    let (kb, _) = rijndael_key_schedule::<O::NST, O::NK, O::R>(owf_key, O::SKE::USIZE);

    // Step 7
    save_key_bits::<O>(&mut witness, &kb, &mut index);

    // Step 8
    save_non_lin_bits::<O>(&mut witness, &kb, &mut index);

    let _ = round_with_save::<O>(&input, &kb, &mut witness, &mut index);

    if O::LAMBDA::USIZE > 128 {
        input[0] ^= 1;
        let _ = round_with_save::<O>(&input, &kb, &mut witness, &mut index);
    }

    Some(witness)
}

#[allow(clippy::too_many_arguments)]
fn save_key_bits<O>(witness: &mut [u8], kb: &[u32], index: &mut usize)
where
    O: OWFParameters,
{
    //Step 7
    for i in convert_from_batchblocks(inv_bitslice(&kb[..8])).take(4) {
        witness[*index..*index + size_of::<u32>()].copy_from_slice(&i);
        *index += size_of::<u32>();
    }
    // Take 0 for lambda = 128, take 2 for lambda=198, take 4 for lambda=256
    for i in convert_from_batchblocks(inv_bitslice(&kb[8..16]))
        .take(O::NK::USIZE / 2 - (4 - (O::NK::USIZE / 2)))
    {
        witness[*index..*index + size_of::<u32>()].copy_from_slice(&i);
        *index += size_of::<u32>();
    }
}

fn save_non_lin_bits<O>(witness: &mut [u8], kb: &[u32], index: &mut usize)
where
    O: OWFParameters,
{
    let start_off = 1 + (O::NK::USIZE / 8);

    let non_lin_blocks = if O::NK::USIZE % 4 == 0 {O::SKE::USIZE / 4} else {O::SKE::USIZE * 3 / 8};
        // (O::SKE::USIZE * ((2 - (O::NK::USIZE % 4)) * 2 + (O::NK::USIZE % 4) * 3)) / 16;

    for j in start_off..start_off + non_lin_blocks {
        let inside = GenericArray::<_, U3>::from_iter(
            convert_from_batchblocks(inv_bitslice(&kb[8 * j..8 * (j + 1)])).take(3),
        );
        if O::NK::USIZE != 6 || j % 3 == 0 {
            witness[*index..*index + size_of::<u32>()].copy_from_slice(&inside[0]);
            *index += size_of::<u32>();
        } else if j % 3 == 1 {
            witness[*index..*index + size_of::<u32>()].copy_from_slice(&inside[2]);
            *index += size_of::<u32>();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn round_with_save<O>(
    input1: &[u8], // in
    kb: &[u32],    // k_bar
    witness: &mut [u8],
    index: &mut usize,
) -> bool
where
    O: OWFParameters,
{
    let mut zeros = false;
    let mut state = State::default();
    bitslice(&mut state, input1, &[]);
    rijndael_add_round_key(&mut state, &kb[..8]);

    for j in 0..O::R::USIZE - 1 {
        // Not needed?
        // zeros |= contains_zeros(&inv_bitslice(&state)[0]);

        let even_round = (j % 2) == 0;

        // Step 19
        if even_round {
            for i in convert_from_batchblocks(inv_bitslice(&state)).take(4) {
                witness[*index] = GF8_INV_NORM[i[0] as usize];
                witness[*index] |= GF8_INV_NORM[i[1] as usize] << 4;
                *index += 1;
                witness[*index] = GF8_INV_NORM[i[2] as usize];
                witness[*index] |= GF8_INV_NORM[i[3] as usize] << 4;
                *index += 1;
            }
        }

        // Step 23: Consider defining a function rijndael_sub_bytes that calls sub_bytes and sub_bytes_nots in sequence
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);

        // Step 24
        rijndael_shift_rows_1::<O::NST>(&mut state);

        // Step 25
        if !even_round {
            // Step 26
            for i in convert_from_batchblocks(inv_bitslice(&state)).take(4) {
                witness[*index..*index + size_of::<u32>()].copy_from_slice(&i);
                *index += size_of::<u32>();
            }
        }

        // Step 27
        mix_columns_0(&mut state);

        // Step 28
        rijndael_add_round_key(&mut state, &kb[8 * (j + 1)..8 * (j + 2)]);
    }
    // Not needed?
    // zeros | contains_zeros(&inv_bitslice(&state)[0])
    zeros
}

// fn aes_key_exp_fwd_1<O>(
//     x: &GenericArray<u8, O::LKEBytes>,
// ) -> Box<GenericArray<u8, O::PRODRUN128Bytes>>
// where
//     O: OWFParameters,
// {
//     let mut out = GenericArray::default_boxed();
//     out[..O::LAMBDABYTES::USIZE].copy_from_slice(&x[..O::LAMBDABYTES::USIZE]);
//     let mut index = O::LAMBDABYTES::USIZE;
//     let mut x_index = O::LAMBDABYTES::USIZE;
//     for j in O::NK::USIZE..(4 * (O::R::USIZE + 1)) {
//         if (j % O::NK::USIZE == 0) || ((O::NK::USIZE > 6) && (j % O::NK::USIZE == 4)) {
//             out[index..index + 32 / 8].copy_from_slice(&x[x_index..x_index + 32 / 8]);
//             index += 32 / 8;
//             x_index += 32 / 8;
//         } else {
//             for i in 0..4 {
//                 out[index] = out[(32 * (j - O::NK::USIZE)) / 8 + i] ^ out[(32 * (j - 1)) / 8 + i];
//                 index += 1;
//             }
//         }
//     }
//     out
// }

// fn aes_key_exp_fwd<O>(
//     x: &GenericArray<Field<O>, O::LKE>,
// ) -> Box<GenericArray<Field<O>, O::PRODRUN128>>
// where
//     O: OWFParameters,
// {
//     // Step 1 is ok by construction
//     let mut out = GenericArray::default_boxed();
//     out[..O::LAMBDA::USIZE].copy_from_slice(&x[..O::LAMBDA::USIZE]);
//     let mut index = O::LAMBDA::USIZE;
//     let mut x_index = O::LAMBDA::USIZE;
//     for j in O::NK::USIZE..(4 * (O::R::USIZE + 1)) {
//         if (j % O::NK::USIZE == 0) || ((O::NK::USIZE > 6) && (j % O::NK::USIZE == 4)) {
//             out[index..index + 32].copy_from_slice(&x[x_index..x_index + 32]);
//             index += 32;
//             x_index += 32;
//         } else {
//             for i in 0..32 {
//                 out[index] = out[(32 * (j - O::NK::USIZE)) + i] + out[(32 * (j - 1)) + i];
//                 index += 1;
//             }
//         }
//     }
//     out
// }

// fn aes_key_exp_bwd_mtag0_mkey0<'a, O>(
//     x: &'a GenericArray<u8, O::LKEBytes>,
//     xk: &'a GenericArray<u8, O::PRODRUN128Bytes>,
// ) -> impl Iterator<Item = Field<O>> + 'a
// where
//     O: OWFParameters,
// {
//     let mut indice = 0;
//     let mut c = 0;
//     let mut rmvrcon = true;
//     let mut ircon = 0;
//     // Step 6
//     (0..O::SKE::USIZE).map(move |j| {
//         // Step 7
//         let mut x_tilde = xk[indice + c] ^ x[j + O::LAMBDABYTES::USIZE];
//         // Step 8
//         if rmvrcon && (c == 0) {
//             let rcon = RCON_TABLE[ircon];
//             ircon += 1;
//             // Step 11
//             x_tilde ^= rcon;
//         }

//         c += 1;
//         // Step 21
//         if c == 4 {
//             c = 0;
//             if O::LAMBDA::USIZE == 192 {
//                 indice += 192 / 8;
//             } else {
//                 indice += 128 / 8;
//                 if O::LAMBDA::USIZE == 256 {
//                     rmvrcon = !rmvrcon;
//                 }
//             }
//         }

//         Field::<O>::byte_combine_bits(
//             x_tilde.rotate_right(7) ^ x_tilde.rotate_right(5) ^ x_tilde.rotate_right(2) ^ 0x5,
//         )
//     })
// }

// fn aes_key_exp_bwd_mtag1_mkey0<'a, O>(
//     x: &'a [Field<O>],
//     xk: &'a GenericArray<Field<O>, O::PRODRUN128>,
// ) -> impl Iterator<Item = Field<O>> + 'a
// where
//     O: OWFParameters,
// {
//     let mut indice = 0;
//     let mut c = 0;
//     let mut rmvrcon = true;
//     // Step 6
//     (0..O::SKE::USIZE).map(move |j| {
//         // Step 7
//         let x_tilde: [_; 8] = array::from_fn(|i| x[8 * j + i] + xk[indice + 8 * c + i]);
//         // Step 15
//         let y_tilde =
//             array::from_fn(|i| x_tilde[(i + 7) % 8] + x_tilde[(i + 5) % 8] + x_tilde[(i + 2) % 8]);
//         c += 1;
//         // Step 21
//         if c == 4 {
//             c = 0;
//             if O::LAMBDA::USIZE == 192 {
//                 indice += 192;
//             } else {
//                 indice += 128;
//                 if O::LAMBDA::USIZE == 256 {
//                     rmvrcon = !rmvrcon;
//                 }
//             }
//         }
//         Field::<O>::byte_combine(&y_tilde)
//     })
// }

// fn aes_key_exp_bwd_mtag0_mkey1<'a, O>(
//     x: &'a GenericArray<Field<O>, O::LKE>,
//     xk: &'a GenericArray<Field<O>, O::PRODRUN128>,
//     delta: &'a Field<O>,
// ) -> impl Iterator<Item = Field<O>> + 'a
// where
//     O: OWFParameters,
// {
//     let mut indice = 0;
//     let mut c = 0;
//     let mut rmvrcon = true;
//     let mut ircon = 0;
//     // Step 6
//     (0..O::SKE::USIZE).map(move |j| {
//         // Step 7
//         let mut x_tilde: [_; 8] =
//             array::from_fn(|i| x[8 * j + i + O::LAMBDA::USIZE] + xk[indice + 8 * c + i]);
//         // Step 8
//         if rmvrcon && (c == 0) {
//             let rcon = RCON_TABLE[ircon];
//             ircon += 1;
//             // Step 11
//             for (i, x) in x_tilde.iter_mut().enumerate() {
//                 *x += *delta * ((rcon >> i) & 1);
//             }
//         }
//         // Step 15
//         let mut y_tilde =
//             array::from_fn(|i| x_tilde[(i + 7) % 8] + x_tilde[(i + 5) % 8] + x_tilde[(i + 2) % 8]);
//         y_tilde[0] += delta;
//         y_tilde[2] += delta;
//         c += 1;
//         // Step 21
//         if c == 4 {
//             c = 0;
//             if O::LAMBDA::USIZE == 192 {
//                 indice += 192;
//             } else {
//                 indice += 128;
//                 if O::LAMBDA::USIZE == 256 {
//                     rmvrcon = !rmvrcon;
//                 }
//             }
//         }
//         Field::<O>::byte_combine(&y_tilde)
//     })
// }

// fn aes_key_exp_cstrnts_mkey0<O>(
//     zk_hasher: &mut ZKProofHasher<Field<O>>,
//     w: &GenericArray<u8, O::LKEBytes>,
//     v: &GenericArray<Field<O>, O::LKE>,
// ) -> KeyCstrnts<O>
// where
//     O: OWFParameters,
// {
//     let k = aes_key_exp_fwd_1::<O>(w);
//     let vk = aes_key_exp_fwd::<O>(v);
//     let w_b = aes_key_exp_bwd_mtag0_mkey0::<O>(w, &k);
//     let v_w_b = aes_key_exp_bwd_mtag1_mkey0::<O>(&v[O::LAMBDA::USIZE..], &vk);

//     zk_hasher.process(
//         iproduct!(0..O::SKE::USIZE / 4, 0..4).map(|(j, r)| {
//             let iwd = 32 * (O::NK::USIZE - 1) + j * if O::LAMBDA::USIZE == 192 { 192 } else { 128 };
//             let dorotword = !(O::LAMBDA::USIZE == 256 && j % 2 == 1);
//             Field::<O>::byte_combine_bits(k[iwd / 8 + inverse_rotate_word(r, dorotword)])
//         }),
//         iproduct!(0..O::SKE::USIZE / 4, 0..4).map(|(j, r)| {
//             let iwd = 32 * (O::NK::USIZE - 1) + j * if O::LAMBDA::USIZE == 192 { 192 } else { 128 };
//             let dorotword = !(O::LAMBDA::USIZE == 256 && j % 2 == 1);
//             let r = inverse_rotate_word(r, dorotword);
//             Field::<O>::byte_combine_slice(&vk[iwd + (8 * r)..iwd + (8 * r) + 8])
//         }),
//         w_b,
//         v_w_b,
//     );

//     (k, vk)
// }

// fn aes_key_exp_cstrnts_mkey1<O>(
//     zk_hasher: &mut ZKVerifyHasher<Field<O>>,
//     q: &GenericArray<Field<O>, O::LKE>,
//     delta: &Field<O>,
// ) -> Box<GenericArray<Field<O>, <O as OWFParameters>::PRODRUN128>>
// where
//     O: OWFParameters,
// {
//     let q_k = aes_key_exp_fwd::<O>(q);
//     let q_w_b = aes_key_exp_bwd_mtag0_mkey1::<O>(q, &q_k, delta);

//     zk_hasher.process(
//         q_w_b,
//         iproduct!(0..O::SKE::USIZE / 4, 0..4).map(|(j, r)| {
//             let iwd = 32 * (O::NK::USIZE - 1) + j * if O::LAMBDA::USIZE == 192 { 192 } else { 128 };
//             let dorotword = !(O::LAMBDA::USIZE == 256 && j % 2 == 1);
//             let rotated_r = inverse_rotate_word(r, dorotword);
//             Field::<O>::byte_combine_slice(&q_k[iwd + (8 * rotated_r)..iwd + (8 * rotated_r) + 8])
//         }),
//     );

//     q_k
// }

// fn aes_enc_fwd_mkey0_mtag0<'a, O>(
//     x: &'a GenericArray<u8, O::QUOTLENC8>,
//     xk: &'a GenericArray<u8, O::PRODRUN128Bytes>,
//     input: &'a [u8; 16],
// ) -> impl Iterator<Item = Field<O>> + 'a
// where
//     O: OWFParameters,
// {
//     (0..16)
//         .map(|i| {
//             // Step 2-5
//             Field::<O>::byte_combine_bits(input[i]) + Field::<O>::byte_combine_bits(xk[i])
//         })
//         .chain(
//             iproduct!(1..O::R::USIZE, 0..4)
//                 .map(move |(j, c)| {
//                     // Step 6
//                     let ix: usize = 128 * (j - 1) + 32 * c;
//                     let ik: usize = 128 * j + 32 * c;
//                     let x_hat: [_; 4] =
//                         array::from_fn(|r| Field::<O>::byte_combine_bits(x[ix / 8 + r]));
//                     let mut res: [_; 4] =
//                         array::from_fn(|r| Field::<O>::byte_combine_bits(xk[ik / 8 + r]));

//                     // Step 16
//                     res[0] += x_hat[0] * Field::<O>::BYTE_COMBINE_2
//                         + x_hat[1] * Field::<O>::BYTE_COMBINE_3
//                         + x_hat[2]
//                         + x_hat[3];
//                     res[1] += x_hat[0]
//                         + x_hat[1] * Field::<O>::BYTE_COMBINE_2
//                         + x_hat[2] * Field::<O>::BYTE_COMBINE_3
//                         + x_hat[3];
//                     res[2] += x_hat[0]
//                         + x_hat[1]
//                         + x_hat[2] * Field::<O>::BYTE_COMBINE_2
//                         + x_hat[3] * Field::<O>::BYTE_COMBINE_3;
//                     res[3] += x_hat[0] * Field::<O>::BYTE_COMBINE_3
//                         + x_hat[1]
//                         + x_hat[2]
//                         + x_hat[3] * Field::<O>::BYTE_COMBINE_2;
//                     res
//                 })
//                 .flatten(),
//         )
// }

// fn aes_enc_fwd_mkey1_mtag0<'a, O>(
//     x: &'a GenericArray<Field<O>, O::LENC>,
//     xk: &'a GenericArray<Field<O>, O::PRODRUN128>,
//     input: &'a [u8; 16],
//     delta: &'a Field<O>,
// ) -> impl Iterator<Item = Field<O>> + 'a
// where
//     O: OWFParameters,
// {
//     (0..16)
//         .map(|i| {
//             // Step 2-5
//             bit_combine_with_delta::<O>(input[i], delta)
//                 + Field::<O>::byte_combine_slice(&xk[8 * i..(8 * i) + 8])
//         })
//         .chain(
//             iproduct!(1..O::R::USIZE, 0..4)
//                 .map(move |(j, c)| {
//                     // Step 6
//                     let ix: usize = 128 * (j - 1) + 32 * c;
//                     let ik: usize = 128 * j + 32 * c;
//                     let x_hat: [_; 4] = array::from_fn(|r| {
//                         Field::<O>::byte_combine_slice(&x[ix + 8 * r..ix + 8 * r + 8])
//                     });
//                     let mut res: [_; 4] = array::from_fn(|r| {
//                         Field::<O>::byte_combine_slice(&xk[ik + 8 * r..ik + 8 * r + 8])
//                     });

//                     // Step 16
//                     res[0] += x_hat[0] * Field::<O>::BYTE_COMBINE_2
//                         + x_hat[1] * Field::<O>::BYTE_COMBINE_3
//                         + x_hat[2]
//                         + x_hat[3];
//                     res[1] += x_hat[0]
//                         + x_hat[1] * Field::<O>::BYTE_COMBINE_2
//                         + x_hat[2] * Field::<O>::BYTE_COMBINE_3
//                         + x_hat[3];
//                     res[2] += x_hat[0]
//                         + x_hat[1]
//                         + x_hat[2] * Field::<O>::BYTE_COMBINE_2
//                         + x_hat[3] * Field::<O>::BYTE_COMBINE_3;
//                     res[3] += x_hat[0] * Field::<O>::BYTE_COMBINE_3
//                         + x_hat[1]
//                         + x_hat[2]
//                         + x_hat[3] * Field::<O>::BYTE_COMBINE_2;
//                     res
//                 })
//                 .flatten(),
//         )
// }

// fn aes_enc_fwd_mkey0_mtag1<'a, O>(
//     x: &'a GenericArray<Field<O>, O::LENC>,
//     xk: &'a GenericArray<Field<O>, O::PRODRUN128>,
// ) -> impl Iterator<Item = Field<O>> + 'a
// where
//     O: OWFParameters,
// {
//     (0..16)
//         .map(|i| {
//             // Step 2-5
//             Field::<O>::byte_combine_slice(&xk[8 * i..(8 * i) + 8])
//         })
//         .chain(
//             iproduct!(1..O::R::USIZE, 0..4)
//                 .map(move |(j, c)| {
//                     // Step 6
//                     let ix: usize = 128 * (j - 1) + 32 * c;
//                     let ik: usize = 128 * j + 32 * c;
//                     let x_hat: [_; 4] = array::from_fn(|r| {
//                         Field::<O>::byte_combine_slice(&x[ix + 8 * r..ix + 8 * r + 8])
//                     });
//                     let mut res: [_; 4] = array::from_fn(|r| {
//                         Field::<O>::byte_combine_slice(&xk[ik + 8 * r..ik + 8 * r + 8])
//                     });

//                     // Step 16
//                     res[0] += x_hat[0] * Field::<O>::BYTE_COMBINE_2
//                         + x_hat[1] * Field::<O>::BYTE_COMBINE_3
//                         + x_hat[2]
//                         + x_hat[3];
//                     res[1] += x_hat[0]
//                         + x_hat[1] * Field::<O>::BYTE_COMBINE_2
//                         + x_hat[2] * Field::<O>::BYTE_COMBINE_3
//                         + x_hat[3];
//                     res[2] += x_hat[0]
//                         + x_hat[1]
//                         + x_hat[2] * Field::<O>::BYTE_COMBINE_2
//                         + x_hat[3] * Field::<O>::BYTE_COMBINE_3;
//                     res[3] += x_hat[0] * Field::<O>::BYTE_COMBINE_3
//                         + x_hat[1]
//                         + x_hat[2]
//                         + x_hat[3] * Field::<O>::BYTE_COMBINE_2;
//                     res
//                 })
//                 .flatten(),
//         )
// }

// fn aes_enc_bkwd_mkey0_mtag0<'a, O>(
//     x: &'a GenericArray<u8, O::QUOTLENC8>,
//     xk: &'a GenericArray<u8, O::PRODRUN128Bytes>,
//     out: &'a [u8; 16],
// ) -> impl Iterator<Item = Field<O>> + 'a
// where
//     O: OWFParameters,
// {
//     // Step 2
//     iproduct!(0..O::R::USIZE, 0..4, 0..4).map(move |(j, c, k)| {
//         // Step 4
//         let ird = 128 * j + 32 * ((c + 4 - k) % 4) + 8 * k;
//         let x_t = if j < O::R::USIZE - 1 {
//             x[ird / 8]
//         } else {
//             let x_out = out[(ird - 128 * j) / 8];
//             x_out ^ xk[(128 + ird) / 8]
//         };
//         let y_t = x_t.rotate_right(7) ^ x_t.rotate_right(5) ^ x_t.rotate_right(2) ^ 0x5;
//         Field::<O>::byte_combine_bits(y_t)
//     })
// }

// fn aes_enc_bkwd_mkey1_mtag0<'a, O>(
//     x: &'a GenericArray<Field<O>, O::LENC>,
//     xk: &'a GenericArray<Field<O>, O::PRODRUN128>,
//     out: &'a [u8; 16],
//     delta: &'a Field<O>,
// ) -> impl Iterator<Item = Field<O>> + 'a
// where
//     O: OWFParameters,
// {
//     // Step 2
//     iproduct!(0..O::R::USIZE, 0..4, 0..4).map(move |(j, c, k)| {
//         // Step 4
//         let ird = 128 * j + 32 * ((c + 4 - k) % 4) + 8 * k;
//         let x_t: [_; 8] = if j < O::R::USIZE - 1 {
//             array::from_fn(|i| x[ird + i])
//         } else {
//             array::from_fn(|i| {
//                 *delta * ((out[(ird - 128 * j + i) / 8] >> ((ird - 128 * j + i) % 8)) & 1)
//                     + xk[128 + ird + i]
//             })
//         };
//         let mut y_t = array::from_fn(|i| x_t[(i + 7) % 8] + x_t[(i + 5) % 8] + x_t[(i + 2) % 8]);
//         y_t[0] += delta;
//         y_t[2] += delta;
//         Field::<O>::byte_combine(&y_t)
//     })
// }

// fn aes_enc_bkwd_mkey0_mtag1<'a, O>(
//     x: &'a GenericArray<Field<O>, O::LENC>,
//     xk: &'a GenericArray<Field<O>, O::PRODRUN128>,
// ) -> impl Iterator<Item = Field<O>> + 'a
// where
//     O: OWFParameters,
// {
//     // Step 2
//     iproduct!(0..O::R::USIZE, 0..4, 0..4).map(move |(j, c, k)| {
//         // Step 4
//         let ird = 128 * j + 32 * ((c + 4 - k) % 4) + 8 * k;
//         let x_t = if j < O::R::USIZE - 1 {
//             &x[ird..ird + 8]
//         } else {
//             &xk[128 + ird..136 + ird]
//         };
//         let y_t = array::from_fn(|i| x_t[(i + 7) % 8] + x_t[(i + 5) % 8] + x_t[(i + 2) % 8]);
//         Field::<O>::byte_combine(&y_t)
//     })
// }

// fn aes_enc_cstrnts_mkey0<O>(
//     zk_hasher: &mut ZKProofHasher<Field<O>>,
//     input: &[u8; 16],
//     output: &[u8; 16],
//     w: &GenericArray<u8, O::QUOTLENC8>,
//     v: &GenericArray<Field<O>, O::LENC>,
//     k: &GenericArray<u8, O::PRODRUN128Bytes>,
//     vk: &GenericArray<Field<O>, O::PRODRUN128>,
// ) where
//     O: OWFParameters,
// {
//     let s = aes_enc_fwd_mkey0_mtag0::<O>(w, k, input);
//     let vs = aes_enc_fwd_mkey0_mtag1::<O>(v, vk);
//     let s_b = aes_enc_bkwd_mkey0_mtag0::<O>(w, k, output);
//     let v_s_b = aes_enc_bkwd_mkey0_mtag1::<O>(v, vk);
//     zk_hasher.process(s, vs, s_b, v_s_b);
// }

// fn aes_enc_cstrnts_mkey1<O>(
//     zk_hasher: &mut ZKVerifyHasher<Field<O>>,
//     input: &[u8; 16],
//     output: &[u8; 16],
//     q: &GenericArray<Field<O>, O::LENC>,
//     qk: &GenericArray<Field<O>, O::PRODRUN128>,
//     delta: &Field<O>,
// ) where
//     O: OWFParameters,
// {
//     let qs = aes_enc_fwd_mkey1_mtag0::<O>(q, qk, input, delta);
//     let q_s_b = aes_enc_bkwd_mkey1_mtag0::<O>(q, qk, output, delta);
//     zk_hasher.process(qs, q_s_b);
// }

// // Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
// pub(crate) fn aes_prove<O>(
//     w: &GenericArray<u8, O::LBYTES>,
//     u: &GenericArray<u8, O::LAMBDALBYTES>,
//     gv: CstrntsVal<O>,
//     pk: &PublicKey<O>,
//     chall: &GenericArray<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>,
// ) -> QSProof<O>
// where
//     O: OWFParameters,
// {
//     let new_v = transpose_and_into_field::<O>(gv);

//     let mut zk_hasher =
//         <<O as OWFParameters>::BaseParams as BaseParameters>::ZKHasher::new_zk_proof_hasher(chall);

//     let (k, vk) = aes_key_exp_cstrnts_mkey0::<O>(
//         &mut zk_hasher,
//         GenericArray::from_slice(&w[..O::LKE::USIZE / 8]),
//         GenericArray::from_slice(&new_v[..O::LKE::USIZE]),
//     );

//     aes_enc_cstrnts_mkey0::<O>(
//         &mut zk_hasher,
//         pk.owf_input[..16].try_into().unwrap(),
//         pk.owf_output[..16].try_into().unwrap(),
//         GenericArray::from_slice(&w[O::LKE::USIZE / 8..(O::LKE::USIZE + O::LENC::USIZE) / 8]),
//         GenericArray::from_slice(&new_v[O::LKE::USIZE..O::LKE::USIZE + O::LENC::USIZE]),
//         &k,
//         &vk,
//     );

//     if O::LAMBDA::USIZE > 128 {
//         aes_enc_cstrnts_mkey0::<O>(
//             &mut zk_hasher,
//             pk.owf_input[16..].try_into().unwrap(),
//             pk.owf_output[16..].try_into().unwrap(),
//             GenericArray::from_slice(&w[(O::LKE::USIZE + O::LENC::USIZE) / 8..O::LBYTES::USIZE]),
//             GenericArray::from_slice(&new_v[(O::LKE::USIZE + O::LENC::USIZE)..O::L::USIZE]),
//             &k,
//             &vk,
//         );
//     }

//     let u_s = Field::<O>::from(&u[O::LBYTES::USIZE..]);
//     let v_s = Field::<O>::sum_poly(&new_v[O::L::USIZE..O::L::USIZE + O::LAMBDA::USIZE]);
//     let (a_t, b_t) = zk_hasher.finalize(&u_s, &v_s);

//     (a_t.as_bytes(), b_t.as_bytes())
// }

// // Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
// #[allow(clippy::too_many_arguments)]
// pub(crate) fn aes_verify<O, Tau>(
//     d: &GenericArray<u8, O::LBYTES>,
//     gq: Box<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>,
//     a_t: &GenericArray<u8, O::LAMBDABYTES>,
//     chall2: &GenericArray<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>,
//     chall3: &GenericArray<u8, O::LAMBDABYTES>,
//     pk: &PublicKey<O>,
// ) -> GenericArray<u8, O::LAMBDABYTES>
// where
//     O: OWFParameters,
//     Tau: TauParameters,
// {
//     let delta = Field::<O>::from(chall3);
//     let new_q = convert_gq::<O, Tau>(d, gq, chall3);
//     let mut zk_hasher =
//         <<O as OWFParameters>::BaseParams as BaseParameters>::ZKHasher::new_zk_verify_hasher(
//             chall2, delta,
//         );

//     let qk = aes_key_exp_cstrnts_mkey1::<O>(
//         &mut zk_hasher,
//         GenericArray::from_slice(&new_q[..O::LKE::USIZE]),
//         &delta,
//     );

//     aes_enc_cstrnts_mkey1::<O>(
//         &mut zk_hasher,
//         pk.owf_input[..16].try_into().unwrap(),
//         pk.owf_output[..16].try_into().unwrap(),
//         GenericArray::from_slice(&new_q[O::LKE::USIZE..(O::LKE::USIZE + O::LENC::USIZE)]),
//         &qk,
//         &delta,
//     );
//     if O::LAMBDA::USIZE > 128 {
//         aes_enc_cstrnts_mkey1::<O>(
//             &mut zk_hasher,
//             pk.owf_input[16..].try_into().unwrap(),
//             pk.owf_output[16..].try_into().unwrap(),
//             GenericArray::from_slice(&new_q[O::LKE::USIZE + O::LENC::USIZE..O::L::USIZE]),
//             &qk,
//             &delta,
//         );
//     }

//     let q_s = Field::<O>::sum_poly(&new_q[O::L::USIZE..O::L::USIZE + O::LAMBDA::USIZE]);
//     (zk_hasher.finalize(&q_s) + Field::<O>::from(a_t) * delta).as_bytes()
// }

#[cfg(test)]
mod test {
    #![allow(clippy::needless_range_loop)]

    use super::*;

    use crate::{
        fields::{GF128, GF192, GF256},
        parameter::{OWFParameters, OWF128, OWF192, OWF256},
        utils::test::read_test_data,
    };

    use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesExtendedWitness {
        lambda: u16,
        key: Vec<u8>,
        input: Vec<u8>,
        w: Vec<u8>,
    }

    #[test]
    fn aes_extended_witness_test() {
        // let database: Vec<AesExtendedWitness> = read_test_data("AesExtendedWitness.json");


        let owf_key: GenericArray<u8, _> = GenericArray::from_array([
            0xc1, 0xa3, 0xc0, 0x22, 0xe7, 0x18, 0x93, 0x5f, 0x46, 0x63, 0x03, 0x86, 0xaf, 0xa3,
            0xd3, 0xf2, 0xc0, 0x72, 0x0b, 0x10, 0xbf, 0x26, 0x6c, 0x19, 0x24, 0x18, 0x87, 0x72,
            0xc5, 0x1f, 0xbe, 0x52,
        ]);

        let owf_input = GenericArray::from_array([
            0xc1, 0xa3, 0xc0, 0x22, 0xe7, 0x18, 0x93, 0x5f, 0x46, 0x63, 0x03, 0x86, 0xaf, 0xa3,
            0xd3, 0xf2, 0xe1, 0x57, 0x09, 0xfe, 0x67, 0xa8, 0xb5, 0x37, 0xb5, 0x35, 0x89, 0x15,
            0x52, 0x4e, 0xb6, 0xf0,
        ]);

        let exp_wit: GenericArray<u8, _> = GenericArray::from_array([
            0xc0, 0x72, 0x0b, 0x10, 0xbf, 0x26, 0x6c, 0x19, 0x24, 0x18, 0x87, 0x72, 0xc5, 0x1f,
            0xbe, 0x52, 0x01, 0xdc, 0x0b, 0xb6, 0x57, 0x84, 0x78, 0x79, 0xbc, 0xb6, 0x27, 0x08,
            0x22, 0x85, 0xf6, 0x6f, 0x43, 0x2d, 0x60, 0x56, 0x9f, 0xc5, 0x2e, 0xe4, 0x78, 0x1a,
            0x2b, 0x68, 0x7f, 0xe1, 0xea, 0x3d, 0x6a, 0x05, 0x3a, 0x77, 0x94, 0xa8, 0x8a, 0x86,
            0x81, 0x4d, 0xe7, 0x6b, 0x58, 0x35, 0xcd, 0xba, 0x3d, 0xd5, 0x16, 0x1c, 0x47, 0x99,
            0x22, 0xf2, 0x75, 0x6f, 0x09, 0xd6, 0xe7, 0x1d, 0xc7, 0x42, 0x22, 0xd7, 0x54, 0x35,
            0xc2, 0xa6, 0x73, 0x11, 0xaa, 0x32, 0x99, 0xc3, 0x3f, 0x42, 0x84, 0x1c, 0xfd, 0x5b,
            0xdf, 0xba, 0x0c, 0x93, 0x83, 0xe8, 0x4c, 0xce, 0xde, 0xa5, 0x84, 0x3f, 0x25, 0xc9,
            0x15, 0x5a, 0x7e, 0x0c, 0x7a, 0x29, 0xd6, 0xa0, 0x2a, 0x93, 0xb7, 0xf2, 0xeb, 0x6d,
            0xad, 0x50, 0x54, 0x32, 0x5a, 0x4d, 0xe9, 0xc9, 0xcb, 0xac, 0x5d, 0x90, 0x10, 0x0f,
            0x9a, 0x45, 0x54, 0xee, 0x84, 0x1a, 0xed, 0x05, 0x02, 0x96, 0x78, 0x82, 0x79, 0x22,
            0x57, 0x1a, 0xea, 0x65, 0x19, 0xce,
        ]);


        // println!("key: {:?}, input: {:?}, wit:{:?}\n\n", owf_key.as_slice(), owf_input.as_slice(), exp_wit.as_slice());
        
        // return;

        let wit = aes_extendedwitness::<OWF128>(
            GenericArray::from_slice(&owf_key[16..]),
            &GenericArray::from_slice(&owf_input[0..16]),
        )
        .unwrap();

        assert_eq!(*wit, exp_wit);

        let owf_key: GenericArray<u8, _> = GenericArray::from_array([
            0x59, 0x4c, 0xbc, 0x98, 0x5a, 0x23, 0x9f, 0x97, 0x85, 0x9c, 0x0f, 0x5d, 0xbc, 0x9c,
            0x65, 0xee, 0xbd, 0x3a, 0x87, 0x1f, 0xc9, 0x3c, 0x17, 0xe3,
        ]);

        let owf_input = GenericArray::from_array([
            0x71, 0x4f, 0x4c, 0x85, 0x5d, 0xc3, 0x4e, 0xaf, 0xba, 0xa6, 0xd0, 0xc9, 0xa6, 0xcb,
            0x67, 0xef, 0xbc, 0xc9, 0x22, 0x82, 0xfe, 0x26, 0xa4, 0xc1, 0x85, 0x25, 0xd1, 0xe6,
            0x07, 0x19, 0xcd, 0x3d, 0x10, 0xe5, 0xb7, 0x38, 0x4b, 0xc0, 0x14, 0xb4, 0x79, 0x2f,
            0x49, 0xf2, 0x2c, 0xe5, 0x2d, 0xf9,
        ]);

        let exp_wit: GenericArray<u8, _> = GenericArray::from_array([
            0x59, 0x4c, 0xbc, 0x98, 0x5a, 0x23, 0x9f, 0x97, 0x85, 0x9c, 0x0f, 0x5d, 0xbc, 0x9c,
            0x65, 0xee, 0xbd, 0x3a, 0x87, 0x1f, 0xc9, 0x3c, 0x17, 0xe3, 0xb3, 0xbc, 0xad, 0x45,
            0x5f, 0x54, 0xf3, 0x0c, 0x24, 0x39, 0x95, 0x22, 0x93, 0x25, 0xf6, 0xac, 0x6a, 0xf0,
            0x9b, 0x44, 0xe4, 0x51, 0x3c, 0xce, 0x00, 0x1f, 0x3d, 0xe7, 0xde, 0xaf, 0x1a, 0x1e,
            0x93, 0x1a, 0xe4, 0x48, 0xdb, 0xdf, 0xee, 0x1d, 0x76, 0x9e, 0xa7, 0x31, 0xca, 0x68,
            0xa1, 0x1c, 0x75, 0x62, 0xa1, 0x7d, 0xcc, 0xc9, 0xb3, 0x7b, 0xc4, 0x61, 0xc9, 0x86,
            0xcb, 0xc2, 0x34, 0xd8, 0x46, 0xe5, 0x46, 0xdf, 0x83, 0x86, 0x3e, 0xdb, 0xc5, 0xa8,
            0x7b, 0x16, 0x47, 0xb6, 0x78, 0x18, 0xa6, 0x42, 0x19, 0x7c, 0x52, 0x24, 0xad, 0xdd,
            0xe4, 0xe5, 0x3b, 0xdf, 0xf3, 0x1b, 0x0e, 0xb1, 0x32, 0x36, 0x70, 0x57, 0x26, 0xc7,
            0x7c, 0x2b, 0x47, 0xee, 0xb9, 0x4f, 0xc8, 0x27, 0xf2, 0x38, 0xdd, 0x84, 0x3c, 0x29,
            0x2b, 0x05, 0xb2, 0xad, 0xee, 0xe5, 0x97, 0x9b, 0xf0, 0x7f, 0x8a, 0xf7, 0x31, 0x83,
            0x7f, 0xd5, 0x4a, 0x5d, 0x1e, 0x4f, 0x12, 0xa0, 0x93, 0x42, 0xd5, 0x70, 0x2d, 0xfe,
            0x8b, 0xa7, 0xe8, 0x69, 0x37, 0xd5, 0x34, 0x25, 0x6c, 0x1a, 0x86, 0x68, 0x43, 0x8c,
            0x6d, 0x73, 0x94, 0x1a, 0xe4, 0x48, 0xdb, 0xdf, 0xee, 0x1d, 0x05, 0x9e, 0xa7, 0x31,
            0xca, 0x68, 0xa1, 0x50, 0x75, 0x62, 0xd0, 0x7d, 0xcc, 0xec, 0xb3, 0x7b, 0x63, 0x4b,
            0xf2, 0xd4, 0xdf, 0xb3, 0x99, 0x59, 0x1c, 0x9a, 0x39, 0xd8, 0xd5, 0x07, 0xa5, 0x43,
            0x21, 0x12, 0x47, 0x49, 0x9b, 0x75, 0xd0, 0x8e, 0xa7, 0x88, 0x45, 0x35, 0xcd, 0x58,
            0x13, 0x15, 0x86, 0xf2, 0xad, 0xd0, 0x75, 0x4e, 0x71, 0x96, 0x91, 0x40, 0x87, 0x81,
            0x56, 0xfe, 0x83, 0xaf, 0xf3, 0x8f, 0x29, 0x8e, 0x18, 0x45, 0x08, 0xfb, 0x54, 0xb7,
            0xbc, 0x07, 0x38, 0x11, 0x84, 0x2f, 0x5b, 0xf0, 0xaf, 0x87, 0xbf, 0x5d, 0x06, 0xe0,
            0xc8, 0xd6, 0x1a, 0x83, 0x78, 0x54, 0x61, 0x12, 0xa5, 0xc9, 0x89, 0x60, 0x3b, 0xe5,
            0x7a, 0xa7, 0xe8, 0xcb, 0xab, 0x95, 0x6d, 0x72, 0xc9, 0x01, 0xf5, 0x34, 0x91, 0xe9,
            0x51, 0xb2, 0x87, 0xca,
        ]);

        let message = GenericArray::from_slice(&owf_input[..16]);

        let wit = aes_extendedwitness::<OWF192>(&owf_key, &message).unwrap();

        assert_eq!(*wit, exp_wit);

        let owf_key: GenericArray<u8, _> = GenericArray::from_array([
            0x56, 0xbe, 0x29, 0xa6, 0x14, 0x66, 0x5b, 0x84, 0xab, 0xb8, 0x80, 0x85, 0x65, 0xca,
            0x30, 0x59, 0x8d, 0x14, 0x3b, 0x6e, 0x79, 0x37, 0x99, 0xfd, 0xe7, 0x61, 0x7b, 0x4a,
            0x73, 0x4f, 0x49, 0x73, 0xa4, 0x10, 0x82, 0x59, 0xc3, 0x6d, 0x33, 0x00, 0xa3, 0x45,
            0x2d, 0xe6, 0xcc, 0x68, 0x19, 0xac,
        ]);

        let owf_input = GenericArray::from_array([
            0x56, 0xbe, 0x29, 0xa6, 0x14, 0x66, 0x5b, 0x84, 0xab, 0xb8, 0x80, 0x85, 0x65, 0xca,
            0x30, 0x59, 0xb5, 0xec, 0x1e, 0x47, 0xcf, 0xb0, 0x84, 0x23, 0x4b, 0x57, 0x35, 0xcf,
            0x8b, 0x7d, 0xdb, 0xf5, 0x5c, 0x7e, 0x83, 0x9a, 0xbe, 0xec, 0x1f, 0xe3, 0x72, 0x61,
            0x7f, 0x24, 0x51, 0x92, 0xd7, 0xea,
        ]);

        let exp_wit: GenericArray<u8, _> = GenericArray::from_array([
            0x8d, 0x14, 0x3b, 0x6e, 0x79, 0x37, 0x99, 0xfd, 0xe7, 0x61, 0x7b, 0x4a, 0x73, 0x4f,
            0x49, 0x73, 0xa4, 0x10, 0x82, 0x59, 0xc3, 0x6d, 0x33, 0x00, 0xa3, 0x45, 0x2d, 0xe6,
            0xcc, 0x68, 0x19, 0xac, 0xc9, 0xc0, 0xaa, 0x25, 0x92, 0x25, 0xfe, 0xa1, 0x86, 0x59,
            0x43, 0x97, 0xfc, 0xdd, 0xec, 0x4a, 0xd6, 0x5e, 0xe3, 0x78, 0xe0, 0x78, 0xa3, 0xbc,
            0x1a, 0x7f, 0x86, 0xf7, 0xe8, 0xe7, 0xd2, 0x0c, 0x62, 0x3a, 0x1a, 0xeb, 0xa2, 0x39,
            0x8c, 0x58, 0xa8, 0x66, 0x12, 0x79, 0xd1, 0x43, 0x4b, 0xbc, 0xff, 0x70, 0x18, 0xb0,
            0x94, 0xe7, 0x6a, 0x31, 0x85, 0x7e, 0x22, 0x93, 0x84, 0xc9, 0xb9, 0x11, 0xf4, 0x79,
            0x27, 0x44, 0x71, 0xa7, 0xba, 0xfe, 0x77, 0x69, 0x9f, 0x8d, 0xf4, 0xed, 0x61, 0x5e,
            0xe9, 0xe1, 0x91, 0xb8, 0x95, 0x1d, 0x9e, 0x42, 0x7d, 0x5f, 0xb7, 0x75, 0xc8, 0x53,
            0x11, 0xf3, 0x31, 0x48, 0xd9, 0x7c, 0xa5, 0x49, 0xe1, 0x87, 0x6b, 0x7b, 0x59, 0x6a,
            0xb3, 0xd8, 0xa1, 0x1c, 0x17, 0x1d, 0x2a, 0x1f, 0xa4, 0x08, 0xa6, 0xd7, 0xe6, 0xe0,
            0xb2, 0x92, 0xf3, 0x25, 0xc6, 0x47, 0x94, 0x64, 0x91, 0xe6, 0xc4, 0x7e, 0xee, 0xb4,
            0xc8, 0x47, 0xa0, 0x3e, 0x04, 0x87, 0x84, 0x89, 0xb0, 0x69, 0x4e, 0xa2, 0xe6, 0x2e,
            0xf2, 0x9c, 0x57, 0x54, 0x43, 0x6d, 0x34, 0x3f, 0xce, 0x80, 0x0b, 0xa2, 0x6d, 0x3c,
            0x5a, 0xb9, 0x56, 0xa4, 0x7b, 0xaa, 0xdb, 0xed, 0xb3, 0x9a, 0xd7, 0xa4, 0xd2, 0x45,
            0xc3, 0x94, 0xdd, 0x5e, 0x04, 0x28, 0x7a, 0x93, 0x4d, 0xa7, 0xfa, 0x6e, 0x23, 0xed,
            0x7d, 0xdf, 0xfd, 0x7d, 0x98, 0x43, 0xcd, 0xef, 0xb1, 0x8a, 0xcb, 0x75, 0x9e, 0xe7,
            0x6a, 0x31, 0x85, 0x7e, 0x22, 0x93, 0xc4, 0xc9, 0xb9, 0x11, 0xf4, 0x79, 0x27, 0x79,
            0x71, 0xa7, 0x31, 0xfe, 0x77, 0x67, 0x9f, 0x8d, 0x53, 0xcb, 0x36, 0xf5, 0xa5, 0xa3,
            0xe9, 0xa7, 0x80, 0x09, 0x4c, 0x08, 0x87, 0xfe, 0x25, 0x78, 0x5b, 0x24, 0x64, 0x66,
            0x45, 0x97, 0x17, 0xa2, 0x71, 0xb1, 0x8f, 0x7d, 0x3b, 0xcc, 0x8c, 0x54, 0x5c, 0x12,
            0x0c, 0x78, 0xfb, 0x26, 0x07, 0xbd, 0x8b, 0x26, 0x82, 0xd7, 0xb5, 0x3a, 0xfa, 0xfb,
            0x15, 0xd8, 0x83, 0xcf, 0xa1, 0xd5, 0x6c, 0xbc, 0x83, 0x2b, 0x3f, 0xf7, 0x84, 0x09,
            0x27, 0x1e, 0xc8, 0x22, 0x77, 0xc4, 0xf9, 0x6b, 0x75, 0x78, 0xe3, 0x5a, 0x9d, 0xa3,
            0x6c, 0x44, 0xa9, 0xd6, 0x72, 0x21, 0xf4, 0x1b, 0x40, 0x33, 0x22, 0xa3, 0x1f, 0x99,
            0x3b, 0x16, 0xf4, 0xff, 0xdb, 0xd4, 0x28, 0xfc, 0x5d, 0x6d, 0xd1, 0x45, 0x16, 0xa5,
            0x56, 0x63, 0xeb, 0x46, 0x24, 0xe7, 0x53, 0xd4, 0x3b, 0x98, 0x4a, 0xcb, 0x72, 0xbc,
            0xa6, 0x5e, 0x6f, 0x6c, 0x94, 0x1a, 0x2c, 0xe3, 0x95, 0xf1,
        ]);

        let message = GenericArray::from_slice(&owf_input[..16]);
        let owf_key = GenericArray::from_slice(&owf_key[16..]);

        let wit = aes_extendedwitness::<OWF256>(&owf_key, message).unwrap();

        assert_eq!(*wit, exp_wit);

        
    }
}
//     #[derive(Debug, Deserialize)]
//     #[serde(rename_all = "camelCase")]
//     struct AesProve {
//         lambda: u16,
//         w: Vec<u8>,
//         input: Vec<u8>,
//         output: Vec<u8>,
//         at: Vec<u8>,
//         bt: Vec<u8>,
//     }

//     impl AesProve {
//         fn as_pk<O>(&self) -> PublicKey<O>
//         where
//             O: OWFParameters,
//         {
//             PublicKey {
//                 owf_input: GenericArray::from_slice(&self.input).clone(),
//                 owf_output: GenericArray::from_slice(&self.output).clone(),
//             }
//         }
//     }

//     #[test]
//     fn aes_prove_test() {
//         let database: Vec<AesProve> = read_test_data("AesProve.json");
//         for data in database {
//             if data.lambda == 128 {
//                 let res = aes_prove::<OWF128>(
//                     GenericArray::from_slice(&data.w),
//                     &GenericArray::generate(|_| 19),
//                     &GenericArray::generate(|_| GenericArray::generate(|_| 55)),
//                     &data.as_pk(),
//                     &GenericArray::generate(|_| 47),
//                 );
//                 assert_eq!(res.0.as_slice(), &data.at);
//                 assert_eq!(res.1.as_slice(), &data.bt);
//             } else if data.lambda == 192 {
//                 let res = aes_prove::<OWF192>(
//                     GenericArray::from_slice(&data.w),
//                     &GenericArray::generate(|_| 19),
//                     &GenericArray::generate(|_| GenericArray::generate(|_| 55)),
//                     &data.as_pk(),
//                     &GenericArray::generate(|_| 47),
//                 );
//                 assert_eq!(res.0.as_slice(), &data.at);
//                 assert_eq!(res.1.as_slice(), &data.bt);
//             } else {
//                 let res = aes_prove::<OWF256>(
//                     GenericArray::from_slice(&data.w),
//                     &GenericArray::generate(|_| 19),
//                     &GenericArray::generate(|_| GenericArray::generate(|_| 55)),
//                     &data.as_pk(),
//                     &GenericArray::generate(|_| 47),
//                 );
//                 assert_eq!(res.0.as_slice(), &data.at);
//                 assert_eq!(res.1.as_slice(), &data.bt);
//             }
//         }
//     }

//     #[derive(Debug, Deserialize)]
//     #[serde(rename_all = "camelCase")]
//     struct AesVerify {
//         lambda: u16,
//         gq: Vec<Vec<u8>>,
//         d: Vec<u8>,
//         chall2: Vec<u8>,
//         chall3: Vec<u8>,
//         at: Vec<u8>,
//         input: Vec<u8>,
//         output: Vec<u8>,
//         res: Vec<u64>,
//     }

//     impl AesVerify {
//         fn res_as_u8(&self) -> Vec<u8> {
//             self.res.iter().flat_map(|x| x.to_le_bytes()).collect()
//         }

//         fn as_pk<O>(&self) -> PublicKey<O>
//         where
//             O: OWFParameters,
//         {
//             PublicKey {
//                 owf_input: GenericArray::from_slice(&self.input).clone(),
//                 owf_output: GenericArray::from_slice(&self.output).clone(),
//             }
//         }

//         fn as_gq<LHI, LHO>(&self) -> GenericArray<GenericArray<u8, LHI>, LHO>
//         where
//             LHI: ArrayLength,
//             LHO: ArrayLength,
//         {
//             self.gq
//                 .iter()
//                 .map(|x| GenericArray::from_slice(x).clone())
//                 .collect()
//         }
//     }

//     fn aes_verify<O, Tau>(
//         d: &GenericArray<u8, O::LBYTES>,
//         gq: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
//         a_t: &GenericArray<u8, O::LAMBDABYTES>,
//         chall2: &GenericArray<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>,
//         chall3: &GenericArray<u8, O::LAMBDABYTES>,
//         pk: &PublicKey<O>,
//     ) -> GenericArray<u8, O::LAMBDABYTES>
//     where
//         O: OWFParameters,
//         Tau: TauParameters,
//     {
//         super::aes_verify::<O, Tau>(
//             d,
//             Box::<GenericArray<_, _>>::from_iter(gq.iter().cloned()),
//             a_t,
//             chall2,
//             chall3,
//             pk,
//         )
//     }

//     #[test]
//     fn aes_verify_test() {
//         let database: Vec<AesVerify> = read_test_data("AesVerify.json");
//         for data in database {
//             if data.lambda == 128 {
//                 let out = aes_verify::<OWF128, <FAEST128sParameters as FAESTParameters>::Tau>(
//                     GenericArray::from_slice(&data.d[..]),
//                     &data.as_gq(),
//                     GenericArray::from_slice(&data.at),
//                     GenericArray::from_slice(&data.chall2[..]),
//                     GenericArray::from_slice(&data.chall3[..]),
//                     &data.as_pk(),
//                 );
//                 assert_eq!(
//                     GF128::from(&data.res_as_u8()[..16]),
//                     GF128::from(out.as_slice())
//                 );
//             } else if data.lambda == 192 {
//                 let out = aes_verify::<OWF192, <FAEST192sParameters as FAESTParameters>::Tau>(
//                     GenericArray::from_slice(&data.d[..]),
//                     &data.as_gq(),
//                     GenericArray::from_slice(&data.at),
//                     GenericArray::from_slice(&data.chall2[..]),
//                     GenericArray::from_slice(&data.chall3[..]),
//                     &data.as_pk(),
//                 );
//                 assert_eq!(
//                     GF192::from(&data.res_as_u8()[..24]),
//                     GF192::from(out.as_slice())
//                 );
//             } else {
//                 let out = aes_verify::<OWF256, <FAEST256sParameters as FAESTParameters>::Tau>(
//                     GenericArray::from_slice(&data.d[..]),
//                     &data.as_gq(),
//                     GenericArray::from_slice(&data.at),
//                     GenericArray::from_slice(&data.chall2[..]),
//                     GenericArray::from_slice(&data.chall3[..]),
//                     &data.as_pk(),
//                 );
//                 assert_eq!(
//                     GF256::from(&data.res_as_u8()[..32]),
//                     GF256::from(out.as_slice())
//                 );
//             }
//         }
//     }
// }
