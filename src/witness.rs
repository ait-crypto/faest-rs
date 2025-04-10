use aes::cipher::KeyInit;
use generic_array::{
    functional::FunctionalSequence,
    typenum::{Prod, Unsigned, B1, U1, U10, U3, U32, U4, U8},
    ArrayLength, GenericArray,
};
use itertools::multiunzip;
use itertools::{iproduct, izip};
use std::{
    array, default,
    mem::size_of,
    ops::{Add, Mul, Sub},
};

use crate::{
    fields::{
        large_fields::{Betas, ByteCombineSquared, SquareBytes},
        small_fields::{GF8, GF8_INV_NORM},
        BigGaloisField, ByteCombine, ByteCombineConstants, Field,
        SumPoly,
    },
    internal_keys::PublicKey,
    parameter::{BaseParameters, OWFParameters, QSProof, TauParameters},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, rijndael_sub_bytes, sub_bytes,
        sub_bytes_nots, State, RCON_TABLE,
    },
    universal_hashing::{ZKHasher, ZKHasherInit, ZKHasherProcess, ZKProofHasher, ZKVerifyHasher},
    utils::contains_zeros,
};

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
    let mut input: GenericArray<u8, O::InputSize> = owf_input.to_owned();

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

        // Tests witness extension both in EM and normal mode
        for data in database {
            assert!(data.test())
        }
    }
}
