use core::mem::size_of;

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box};

use hybrid_array::{
    Array,
    typenum::{U3, Unsigned},
};

use crate::{
    fields::{GF8, Square},
    parameter::OWFParameters,
    rijndael_32::{
        State, bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0,
        rijndael_add_round_key, rijndael_key_schedule, rijndael_shift_rows_1, rijndael_sub_bytes,
        ske,
    },
};

pub(crate) fn extend_witness<O: OWFParameters>(
    owf_key: &Array<u8, O::LambdaBytes>,
    owf_input: &Array<u8, O::InputSize>,
) -> Box<Array<u8, O::LBytes>> {
    let mut input = owf_input.to_owned();

    let mut witness = Box::<Array<u8, O::LBytes>>::default();

    let mut offset = 0;

    // lines 7 & 17
    // EM has no key schedule constraints (SKe = 0), but encryption still
    // needs the full public round key schedule
    let key_schedule_sboxes = ske(O::R::USIZE, O::NSt::USIZE, O::NK::USIZE);
    let k_bar = rijndael_key_schedule::<O::NSt, O::NK, O::R>(owf_key, key_schedule_sboxes);

    if !O::IS_EM {
        // line 8
        save_secret_bits::<O>(&mut witness, &owf_key, &mut offset);
        // line 9
        save_non_lin_bits::<O>(&mut witness, &k_bar, &mut offset);

    } else {
        // line 18
        // in EM mode, AES key is part of public input while pt is secret
        save_secret_bits::<O>(&mut witness, owf_input, &mut offset);
    };

    
    // line 21
    for _ in 0..O::Beta::USIZE {
        round_with_save::<O>(&input, &k_bar, &mut witness, &mut offset);
        input[0] ^= 1;
    }

    witness
}

fn save_secret_bits<O>(witness: &mut [u8], owf_secret: &[u8], offset: &mut usize)
where
    O: OWFParameters,
{
    witness[..O::LambdaBytes::USIZE].copy_from_slice(owf_secret);
    *offset += O::LambdaBytes::USIZE;
}

fn save_non_lin_bits<O>(witness: &mut [u8], kb: &[u32], offset: &mut usize)
where
    O: OWFParameters,
{
    let start_off = 1 + (O::NK::USIZE / 8);

    let non_lin_blocks = if O::NK::USIZE % 4 == 0 {
        O::SKe::USIZE / 4
    } else {
        O::SKe::USIZE * 3 / 8
    };

    for j in start_off..start_off + non_lin_blocks {
        let inside = Array::<_, U3>::from_iter(
            convert_from_batchblocks(inv_bitslice(&kb[8 * j..8 * (j + 1)])).take(3),
        );

        if O::NK::USIZE != 6 || j % 3 == 0 {
            witness[*offset..*offset + size_of::<u32>()].copy_from_slice(&inside[0]);
            *offset += size_of::<u32>();
        } else if j % 3 == 1 {
            witness[*offset..*offset + size_of::<u32>()].copy_from_slice(&inside[2]);
            *offset += size_of::<u32>();
        }
    }
}

fn round_with_save<O>(
    input1: &[u8], // in
    kb: &[u32],    // k_bar
    witness: &mut [u8],
    offset: &mut usize,
) where
    O: OWFParameters,
{
    let mut state = State::default();

    //  note: input1 is always empty except for FAEST-EM-192 and FAEST-EM-256
    let (input0, input1) = input1.split_at(16);
    bitslice(&mut state, input0, input1);

    // line 24
    rijndael_add_round_key(&mut state, &kb[..8]);

    for j in 1..O::R::USIZE - 1 {
        // line 23
        rijndael_sub_bytes(&mut state);

        // line 24
        rijndael_shift_rows_1::<O::NSt>(&mut state);

        // line 29-30
        if (j % 2) == 0 {
            for state_word in convert_from_batchblocks(inv_bitslice(&state)).take(O::NSt::USIZE) {
                witness[*offset..*offset + state_word.len()].copy_from_slice(&state_word);
                *offset += state_word.len();
            }
        }

        // line 31
        mix_columns_0(&mut state);

        // line 32
        rijndael_add_round_key(&mut state, &kb[8 * j..8 * (j + 1)]);
    }
}

#[cfg(test)]
#[path = "../tests/data/faest_tvs.rs"]
mod test_vectors;

#[cfg(test)]
mod test {
    #![allow(clippy::needless_range_loop)]

    use super::test_vectors::*;
    use crate::{
        fields::{GF128, GF192, GF256},
        parameter::{OWF128, OWF128EM, OWF192, OWF192EM, OWF256, OWF256EM, OWFParameters},
        utils::{array_ref, test::read_test_data},
    };
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

    use serde::Deserialize;

    macro_rules! witness_test {
        ($vectors:ident, $owf:ty, $input_size:literal) => {
            #[test]
            fn $vectors() {
                // Reference secret keys serialize the public input first.
                let input = array_ref(&$vectors::SK[..$input_size]);
                let key = array_ref(&$vectors::SK[$input_size..]);
                let wit = <$owf>::extendwitness(key, input);
                assert_eq!(wit.as_slice(), $vectors::WITNESS.as_slice());
            }
        };
    }

    witness_test!(faest_128s, OWF128, 16);
    witness_test!(faest_128f, OWF128, 16);
    witness_test!(faest_192s, OWF192, 16);
    witness_test!(faest_192f, OWF192, 16);
    witness_test!(faest_256s, OWF256, 16);
    witness_test!(faest_256f, OWF256, 16);
    witness_test!(faest_em_128s, OWF128EM, 16);
    witness_test!(faest_em_128f, OWF128EM, 16);
    witness_test!(faest_em_192s, OWF192EM, 24);
    witness_test!(faest_em_192f, OWF192EM, 24);
    witness_test!(faest_em_256s, OWF256EM, 32);
    witness_test!(faest_em_256f, OWF256EM, 32);
}
