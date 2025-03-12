use std::{
    array,
    mem::size_of,
    ops::{Add, Mul, Sub},
};

use generic_array::{
    functional::FunctionalSequence,
    typenum::{Prod, Unsigned, B1, U1, U10, U3, U4, U8},
    ArrayLength, GenericArray,
};
use itertools::{iproduct, izip};

use crate::{
    fields::{
        small_fields::{GF8, GF8_INV_NORM},
        BigGaloisField, ByteCombine, ByteCombineConstants, Field, SumPoly,
    },
    // internal_keys::PublicKey,
    parameter::{BaseParameters, OWFParameters, QSProof, TauParameters},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, rijndael_sub_bytes, sub_bytes,
        sub_bytes_nots, State, RCON_TABLE,
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
    owf_secret: &GenericArray<u8, O::LAMBDABYTES>,
    owf_input: &GenericArray<u8, O::InputSize>,
) -> Box<GenericArray<u8, O::LBYTES>>
where
    O: OWFParameters,
{
    // Step 0
    let mut input: GenericArray<u8, O::InputSize> = GenericArray::default();
    input.copy_from_slice(owf_input);

    // Step 3
    let mut witness = GenericArray::default_boxed();

    // Step 6
    // Note: for FAEST-LAMBDA-EM, SKE is set to the actual number of S-Boxes in Rijndael-LAMBDA.KeyExpansion.
    // This slightly differs from FAEST Spec v2, where SKE is always set to 0 in EM mode.
    let (kb, _) = rijndael_key_schedule::<O::NST, O::NK, O::R>(owf_secret, O::SKE::USIZE);

    let mut index = 0;

    // Step 7
    if !O::is_em() {
        save_key_bits::<O>(&mut witness, owf_secret, &mut index);
        // Step 8
        save_non_lin_bits::<O>(&mut witness, &kb, &mut index);
    } else {
        // In EM mode, AES key is part of public input while pt is secret
        save_key_bits::<O>(&mut witness, owf_input, &mut index);
    }

    // Step 14
    for _ in 0..O::BETA::USIZE {
        round_with_save::<O>(&input, &kb, &mut witness, &mut index);
        input[0] ^= 1;
    }

    witness
}

#[allow(clippy::too_many_arguments)]
fn save_key_bits<O>(witness: &mut [u8], key: &[u8], index: &mut usize)
where
    O: OWFParameters,
{
    witness[..O::LAMBDABYTES::USIZE].copy_from_slice(key);
    *index += O::LAMBDABYTES::USIZE;
}

#[allow(clippy::too_many_arguments)]
fn save_non_lin_bits<O>(witness: &mut [u8], kb: &[u32], index: &mut usize)
where
    O: OWFParameters,
{
    let start_off = 1 + (O::NK::USIZE / 8);

    let non_lin_blocks = if O::NK::USIZE % 4 == 0 {
        O::SKE::USIZE / 4
    } else {
        O::SKE::USIZE * 3 / 8
    };

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

#[inline]
fn store_invnorm_state(dst: &mut u8, lo_idx: u8, hi_idx: u8) {
    *dst = GF8_INV_NORM[lo_idx as usize] | GF8_INV_NORM[hi_idx as usize] << 4;
}

#[allow(clippy::too_many_arguments)]
fn round_with_save<O>(
    input1: &[u8], // in
    kb: &[u32],    // k_bar
    witness: &mut [u8],
    index: &mut usize,
) where
    O: OWFParameters,
{
    let mut state = State::default();

    // Input1 is always empty except for FAEST-EM-192 and FAEST-EM-256
    let (input0, input1) = input1.split_at(16);
    bitslice(&mut state, input0, input1);

    rijndael_add_round_key(&mut state, &kb[..8]);

    for j in 0..O::R::USIZE - 1 {
        let even_round = (j % 2) == 0;

        // Step 19
        if even_round {
            let to_take = if !O::is_em() { 4 } else { O::NK::USIZE };
            for i in convert_from_batchblocks(inv_bitslice(&state)).take(to_take) {
                store_invnorm_state(&mut witness[*index], i[0], i[1]);
                *index += 1;
                store_invnorm_state(&mut witness[*index], i[2], i[3]);
                *index += 1;
            }
        }

        // Step 23
        rijndael_sub_bytes(&mut state);

        // Step 24
        rijndael_shift_rows_1::<O::NST>(&mut state);

        // Step 25
        if !even_round {
            // Step 26
            for i in convert_from_batchblocks(inv_bitslice(&state)).take(O::NST::USIZE) {
                witness[*index..*index + size_of::<u32>()].copy_from_slice(&i);
                *index += size_of::<u32>();
            }
        }

        // Step 27
        mix_columns_0(&mut state);

        // Step 28
        rijndael_add_round_key(&mut state, &kb[8 * (j + 1)..8 * (j + 2)]);
    }
}

type OWFField<O> = <<O as OWFParameters>::BaseParams as BaseParameters>::Field;

fn aes_key_exp_fwd<O>(
    w: &GenericArray<u8, O::LKEBytes>,
    w_0: &GenericArray<OWFField<O>, O::LKE>,
) -> (
    Box<GenericArray<u8, O::PRODRUN128Bytes>>,
    Box<GenericArray<OWFField<O>, O::PRODRUN128>>,
)
where
    O: OWFParameters,
{
    // Step 1
    let mut y = GenericArray::default_boxed();
    let mut y_0 = GenericArray::default_boxed();
    y[..O::LAMBDABYTES::USIZE].copy_from_slice(&w[..O::LAMBDABYTES::USIZE]);
    y_0[..O::LAMBDA::USIZE].copy_from_slice(&w_0[..O::LAMBDA::USIZE]);

    // Step 2
    let mut i_wd = O::LAMBDA::USIZE;

    for j in O::NK::USIZE..(4 * (O::R::USIZE + 1)) {
        // Step 5
        if (j % O::NK::USIZE == 0) || ((O::NK::USIZE > 6) && (j % O::NK::USIZE == 4)) {
            // Step 6
            y[4 * j..4 * j + 4].copy_from_slice(&w[i_wd / 8..i_wd / 8 + 4]);
            y_0[32 * j..32 * j + 32].copy_from_slice(&w_0[i_wd..i_wd + 32]);

            // Step 7
            i_wd += 32;
        } else {
            // Step 9-10
            for i in 0..4 {
                y[4 * j + i] = y[4 * (j - O::NK::USIZE) + i] ^ y[4 * (j - 1) + i];

                for i_0 in 8 * i..8 * i + 8 {
                    y_0[32 * j + i_0] =
                        y_0[32 * (j - O::NK::USIZE) + i_0] + y_0[32 * (j - 1) + i_0];
                }
            }
        }
    }

    (y, y_0)
}

fn aes_key_exp_bkwd<O>(
    x: &GenericArray<u8, O::DIFFLKELAMBDABytes>,
    x_0: &GenericArray<OWFField<O>, O::DIFFLKELAMBDA>,
    xk: &GenericArray<u8, O::PRODRUN128Bytes>,
    xk_0: &GenericArray<OWFField<O>, O::PRODRUN128>,
) -> (
    Box<GenericArray<u8, O::SKE>>,
    Box<GenericArray<OWFField<O>, Prod<O::SKE, U8>>>,
)
where
    O: OWFParameters,
{
    let mut y = GenericArray::default_boxed();
    let mut y_0 = GenericArray::default_boxed();

    let mut i_wd = 0;

    let rcon_evry = 4 * (O::LAMBDA::USIZE / 8);

    for j in 0..O::SKE::USIZE {
        // Step 7
        let mut xt = x[j] ^ xk[i_wd / 8 + (j % 4)];

        let xt_0: GenericArray<OWFField<O>, U8> = (0..8)
            .map(|i| x_0[8 * j + i] + xk_0[i_wd + 8 * (j % 4) + i])
            .collect();

        // Step 8
        if j % rcon_evry == 0 {
            xt ^= RCON_TABLE[j / rcon_evry];
        }

        inverse_affine_byte::<O>(xt, &xt_0, &mut y[j], &mut y_0[8 * j..8 * j + 8]);

        // Step 12
        if j % 4 == 3 {
            if O::LAMBDA::USIZE != 256 {
                i_wd += O::LAMBDA::USIZE;
            } else {
                i_wd += 128;
            }
        }
    }

    (y, y_0)
}

fn inverse_affine_byte<O>(
    x: u8,
    x_0: &GenericArray<OWFField<O>, U8>,
    y: &mut u8,
    y_0: &mut [OWFField<O>],
) where
    O: OWFParameters,
{
    *y = x.rotate_right(7) ^ x.rotate_right(5) ^ x.rotate_right(2) ^ 0x5;

    for i in 0..8 {
        y_0[i] = x_0[(i + 8 - 1) % 8] + x_0[(i + 8 - 3) % 8] + x_0[(i + 8 - 6) % 8];
    }
}

fn aes_key_exp_cstrnts_prover<O>(
    w: &GenericArray<u8, O::LKEBytes>,
    w_tag: &GenericArray<OWFField<O>, O::LKE>,
) -> (
    Box<GenericArray<u8, O::PRODRUN128Bytes>>,
    Box<GenericArray<OWFField<O>, O::PRODRUN128>>,
)
where
    O: OWFParameters,
    OWFField<O>: BigGaloisField + ByteCombine,
    <<O as OWFParameters>::BaseParams as BaseParameters>::Field: PartialEq,
{
    // Step 1-2
    let (k, k_tag) = aes_key_exp_fwd::<O>(w, w_tag);
    let (w_flat, w_flat_tag) = aes_key_exp_bkwd::<O>(
        GenericArray::from_slice(&w[O::LAMBDABYTES::USIZE..]),
        GenericArray::from_slice(&w_tag[O::LAMBDA::USIZE..]),
        &k,
        &k_tag,
    );

    let mut i_wd = 32 * (O::NK::USIZE - 1);

    let mut do_rot_word = true;

    // Step 7
    for j in 0..O::SKE::USIZE / 4 {
        // Step 8
        let (mut k_hat, mut k_hat_tag) = (
            GenericArray::<OWFField<O>, U4>::default(),
            GenericArray::<OWFField<O>, U4>::default(),
        );
        let (mut k_hat_sq, mut k_hat_tag_sq) = (
            GenericArray::<OWFField<O>, U4>::default(),
            GenericArray::<OWFField<O>, U4>::default(),
        );
        let (mut w_hat, mut w_hat_tag) = (
            GenericArray::<OWFField<O>, U4>::default(),
            GenericArray::<OWFField<O>, U4>::default(),
        );
        let (mut w_hat_sq, mut w_hat_tag_sq) = (
            GenericArray::<OWFField<O>, U4>::default(),
            GenericArray::<OWFField<O>, U4>::default(),
        );

        for r in 0..4 {
            let r_prime = if do_rot_word { (r + 3) % 4 } else { r };

            // Steps 12-15
            k_hat[r_prime] = OWFField::<O>::byte_combine_bits(k[i_wd / 8 + r]);
            k_hat_sq[r_prime] = square_and_combine_bits(k[i_wd / 8 + r]);
            
            
            w_hat[r] = OWFField::<O>::byte_combine_bits(w_flat[4 * j + r]);
            w_hat_sq[r] = square_and_combine_bits(w_flat[4 * j + r]);
            

            k_hat_tag[r_prime] = OWFField::<O>::byte_combine_slice(&k_tag[i_wd + 8 * r..i_wd + 8 * r + 8]);
            k_hat_tag_sq[r_prime] = square_and_combine(&k_tag[i_wd + 8 * r..i_wd + 8 * r + 8]);
            

            w_hat_tag[r] =
                OWFField::<O>::byte_combine_slice(&w_flat_tag[32 * j + 8 * r..32 * j + 8 * r + 8]);
            w_hat_tag_sq[r_prime] = square_and_combine(&w_flat_tag[32 * j + 8 * r..32 * j + 8 * r + 8]);
        }

        // Step 16
        if O::LAMBDA::USIZE == 256 {
            do_rot_word = !do_rot_word;
        }

        // Step 17
        for r in 0..4 {
            
            let z = k_hat_sq[r] * w_hat[r] - k_hat[r];
            println!("{:?}", z);  
            // assert_eq!(z, <OWFField<O> as Field>::ZERO);

            let z = k_hat[r] * w_hat_sq[r] - w_hat[r];
            println!("{:?}\n\n", z);  

            // assert_eq!(z, <OWFField<O> as Field>::ZERO);
        }

        if O::LAMBDA::USIZE == 192 {
            i_wd += 192;
        } else {
            i_wd += 128;
        }
    }

    (k, k_tag)
}

fn square_bits(x: u8) -> u8 {
    let bits = [
        x & 0b1,
        (x & 0b10) >> 1,
        (x & 0b100) >> 2,
        (x & 0b1000) >> 3,
        (x & 0b10000) >> 4,
        (x & 0b100000) >> 5,
        (x & 0b1000000) >> 6,
        (x & 0b10000000) >> 7,
    ];

    let mut sq_bits = bits[0] ^ bits[4] ^ bits[6];
    sq_bits |= (bits[4] ^ bits[6] ^ bits[7]) << 1;
    sq_bits |= (bits[1] ^ bits[5]) << 2;
    sq_bits |= (bits[4] ^ bits[5] ^ bits[6] ^ bits[7]) << 3;
    sq_bits |= (bits[2] ^ bits[4] ^ bits[7]) << 4;
    sq_bits |= (bits[5] ^ bits[6]) << 5;
    sq_bits |= (bits[3] ^ bits[5]) << 6;
    sq_bits |= (bits[6] ^ bits[7]) << 7;
    sq_bits
}

fn square_and_combine_bits<F>(x: u8) -> F
where
    F: BigGaloisField,
{
    let sq_bits = square_bits(x);
    F::byte_combine_bits(sq_bits)
}

fn square<F>(x: &[F]) -> [F; 8]
where
    F: BigGaloisField,
{
    let mut sq = [F::ZERO; 8];
    sq[0] = x[0] + x[4] + x[6];
    sq[1] = x[4] + x[6] + x[7];
    sq[2] = x[1] + x[5];
    sq[3] = x[4] + x[5] + x[6] + x[7];
    sq[4] = x[2] + x[4] + x[7];
    sq[5] = x[5] + x[6];
    sq[6] = x[3] + x[5];
    sq[7] = x[6] + x[7];
    sq
}

fn square_and_combine<F>(x: &[F]) -> F
where
    F: BigGaloisField,
{
    let sq = square(x);
    F::byte_combine(&sq)
}

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
        parameter::{Lambda, OWFParameters, OWF128, OWF128EM, OWF192, OWF192EM, OWF256, OWF256EM},
        utils::test::read_test_data,
    };

    use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesExtendedWitness {
        lambda: u16,
        em: bool,
        key: Vec<u8>,
        input: Vec<u8>,
        w: Vec<u8>,
    }
    impl AesExtendedWitness {
        fn test(&self) -> bool {
            match self.em {
                false => self.extend_witness_test(),
                true => self.extend_witness_test_em(),
            }
        }

        fn extend_witness_test(&self) -> bool {
            match self.lambda {
                128 => {
                    println!("AES-128 - testing witness extension..");
                    let wit = OWF128::extendwitness(
                        GenericArray::from_slice(&self.key),
                        GenericArray::from_slice(&self.input),
                    );
                    (*wit).as_slice() == self.w.as_slice()
                }
                192 => {
                    println!("AES-192 - testing witness extension..");
                    let wit = OWF192::extendwitness(
                        GenericArray::from_slice(&self.key),
                        GenericArray::from_slice(&self.input),
                    );
                    (*wit).as_slice() == self.w.as_slice()
                }
                _ => {
                    println!("AES-256 - testing witness extension..");
                    let wit = OWF256::extendwitness(
                        GenericArray::from_slice(&self.key),
                        GenericArray::from_slice(&self.input),
                    );
                    (*wit).as_slice() == self.w.as_slice()
                }
            }
        }

        fn extend_witness_test_em(&self) -> bool {
            match self.lambda {
                128 => {
                    println!("AES-EM-128 - testing witness extension..");
                    let wit = OWF128EM::extendwitness(
                        GenericArray::from_slice(&self.key),
                        GenericArray::from_slice(&self.input),
                    );
                    (*wit).as_slice() == self.w.as_slice()
                }
                192 => {
                    println!("AES-EM-192 - testing witness extension..");
                    let wit = OWF192EM::extendwitness(
                        GenericArray::from_slice(&self.key),
                        GenericArray::from_slice(&self.input),
                    );
                    (*wit).as_slice() == self.w.as_slice()
                }
                _ => {
                    println!("AES-EM-256 - testing witness extension..");
                    let wit = OWF256EM::extendwitness(
                        GenericArray::from_slice(&self.key),
                        GenericArray::from_slice(&self.input),
                    );
                    (*wit).as_slice() == self.w.as_slice()
                }
            }
        }
    }

    #[test]
    fn aes_extended_witness_test() {
        let database: Vec<AesExtendedWitness> = read_test_data("AesExtendedWitness.json");

        for data in database {
            assert!(data.test())
        }
    }

    #[test]
    fn aes_enc_fwd_prover_128_test() {
        let w: GenericArray<u8, _> = GenericArray::from_array([
            17, 114, 181, 111, 55, 1, 111, 109, 39, 0, 190, 122, 209, 86, 174, 250, 161, 150, 152,
            81, 219, 2, 253, 129, 241, 75, 93, 95, 57, 172, 5, 217, 225, 238, 21, 13, 45, 134, 80,
            97, 15, 126, 161, 50, 27, 253, 118, 137, 35, 0, 176, 94, 230, 199, 184, 147,
        ]);

        let exp_k: GenericArray<u8, _> = GenericArray::from_array([
            17, 114, 181, 111, 55, 1, 111, 109, 39, 0, 190, 122, 209, 86, 174, 250, 161, 150, 152,
            81, 150, 151, 247, 60, 177, 151, 73, 70, 96, 193, 231, 188, 219, 2, 253, 129, 77, 149,
            10, 189, 252, 2, 67, 251, 156, 195, 164, 71, 241, 75, 93, 95, 188, 222, 87, 226, 64,
            220, 20, 25, 220, 31, 176, 94, 57, 172, 5, 217, 133, 114, 82, 59, 197, 174, 70, 34, 25,
            177, 246, 124, 225, 238, 21, 13, 100, 156, 71, 54, 161, 50, 1, 20, 184, 131, 247, 104,
            45, 134, 80, 97, 73, 26, 23, 87, 232, 40, 22, 67, 80, 171, 225, 43, 15, 126, 161, 50,
            70, 100, 182, 101, 174, 76, 160, 38, 254, 231, 65, 13, 27, 253, 118, 137, 93, 153, 192,
            236, 243, 213, 96, 202, 13, 50, 33, 199, 35, 0, 176, 94, 126, 153, 112, 178, 141, 76,
            16, 120, 128, 126, 49, 191, 230, 199, 184, 147, 152, 94, 200, 33, 21, 18, 216, 89, 149,
            108, 233, 230,
        ]);

        let tags = GenericArray::default();

        let res = aes_key_exp_fwd::<OWF128>(&w, &tags);

        assert!(*res.0 == exp_k);
    }

    #[test]
    fn aes_enc_bkwd_prover_128_test() {
        let w: GenericArray<u8, _> = GenericArray::from_array([
            168, 233, 176, 51, 172, 6, 233, 110, 215, 248, 209, 67, 11, 234, 191, 117, 60, 3, 82,
            31, 53, 103, 128, 235, 3, 122, 147, 230, 113, 159, 193, 47, 11, 201, 121, 202, 159,
            209, 193, 112,
        ]);

        let k: GenericArray<u8, _> = GenericArray::from_array([
            188, 126, 253, 108, 122, 171, 208, 78, 219, 200, 132, 13, 132, 47, 133, 101, 168, 233,
            176, 51, 210, 66, 96, 125, 9, 138, 228, 112, 141, 165, 97, 21, 172, 6, 233, 110, 126,
            68, 137, 19, 119, 206, 109, 99, 250, 107, 12, 118, 215, 248, 209, 67, 169, 188, 88, 80,
            222, 114, 53, 51, 36, 25, 57, 69, 11, 234, 191, 117, 162, 86, 231, 37, 124, 36, 210,
            22, 88, 61, 235, 83, 60, 3, 82, 31, 158, 85, 181, 58, 226, 113, 103, 44, 186, 76, 140,
            127, 53, 103, 128, 235, 171, 50, 53, 209, 73, 67, 82, 253, 243, 15, 222, 130, 3, 122,
            147, 230, 168, 72, 166, 55, 225, 11, 244, 202, 18, 4, 42, 72, 113, 159, 193, 47, 217,
            215, 103, 24, 56, 220, 147, 210, 42, 216, 185, 154, 11, 201, 121, 202, 210, 30, 30,
            210, 234, 194, 141, 0, 192, 26, 52, 154, 159, 209, 193, 112, 77, 207, 223, 162, 167,
            13, 82, 162, 103, 23, 102, 56,
        ]);

        let w_tags = GenericArray::default();
        let k_tags = GenericArray::default();

        let res = aes_key_exp_bkwd::<OWF128>(&w, &w_tags, &k, &k_tags);

        println!("{:?}", res.0);
    }

    #[test]
    fn test_keycnstr() {
        let w = GenericArray::from_array([
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

        println!("{}", w.len());
        let lke = <OWF128 as OWFParameters>::LKEBytes::USIZE;
        aes_key_exp_cstrnts_prover::<OWF128>(
            GenericArray::from_slice(&w[..lke]),
            &GenericArray::default(),
        );
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

// fn mul_deg_1_commits<F, L>(
//     lhs: &GenericArray<F, L>,
//     lhs_tag: &GenericArray<F, L>,
//     rhs: &GenericArray<F, L>,
//     rhs_tag: &GenericArray<F, L>,
// ) -> (GenericArray<F, L>, GenericArray<F, L>, GenericArray<F, L>)
// where
//     F: crate::fields::Field,
//     for<'a> &'a F: Mul<&'a F, Output = F>,
//     L: ArrayLength,
// {
//     let mut res_tag0 = GenericArray::default();
//     let mut res_tag1 = GenericArray::default();
//     let mut res = GenericArray::default();

//     for (i, (l, ltag, r, rtag)) in izip!(lhs, lhs_tag, rhs, rhs_tag).enumerate() {
//         res_tag0[i] = ltag * rtag;
//         res_tag1[i] = ltag * r + rtag * l;
//         res[i] = l * r;
//     }

//     (res_tag0, res_tag1, res)
// }

// fn diff_deg_2_deg_1_commits<F, L>(
//     lhs: &GenericArray<F, L>,
//     lhs_tag1: &GenericArray<F, L>,
//     lhs_tag0: &GenericArray<F, L>,
//     rhs: &GenericArray<F, L>,
//     rhs_tag: &GenericArray<F, L>,
// ) -> (GenericArray<F, L>, GenericArray<F, L>, GenericArray<F, L>)
// where
//     F: Clone + crate::fields::Field,
//     for<'a> &'a F: Sub<&'a F, Output = F>,
//     L: ArrayLength,
// {
//     let res_tag0= (*lhs_tag0).clone();
//     let mut res_tag1 = GenericArray::default();
//     let mut res = GenericArray::default();

//     for (i, (l, ltag, r, rtag)) in izip!(lhs, lhs_tag1, rhs, rhs_tag).enumerate() {
//         res_tag1[i] = ltag - rtag;
//         res[i] = l-r;
//     }

//     (res_tag0, res_tag1, res)
// }
