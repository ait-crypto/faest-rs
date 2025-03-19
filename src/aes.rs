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
    ops::{Add, AddAssign, Mul, Sub},
};

use crate::{
    fields::{
        field_commitment::{
            BitCommits, BitCommitsRef, FieldCommitDegOne, FieldCommitDegThree, FieldCommitDegTwo,
        },
        large_fields::{Betas, ByteCombineSquared, ByteCombineSquaredConstants, SquareBytes},
        small_fields::{GF8, GF8_INV_NORM},
        BigGaloisField, ByteCombine, ByteCombineConstants, Field, SumPoly,
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
    zk_constraints::OWFField,
};

pub(crate) fn add_round_key<O>(
    input: &BitCommits<OWFField<O>, Prod<O::NST, U4>>,
    key: &BitCommits<OWFField<O>, Prod<O::NST, U4>>,
) -> BitCommits<OWFField<O>, Prod<O::NST, U4>>
where
    O: OWFParameters,
{
    BitCommits {
        keys: input
            .keys
            .iter()
            .zip(key.keys.iter())
            .map(|(x, k)| x ^ k)
            .collect(),
        tags: input
            .tags
            .iter()
            .zip(key.tags.iter())
            .map(|(x, k)| x.clone() + k)
            .collect(),
    }
}

pub(crate) type CommittedState<O> =
    Box<GenericArray<FieldCommitDegOne<OWFField<O>>, <O as OWFParameters>::NSTBytes>>;

pub(crate) type CommittedStateSquared<O> =
    Box<GenericArray<FieldCommitDegTwo<OWFField<O>>, <O as OWFParameters>::NSTBytes>>;

pub(crate) fn state_to_bytes<O>(state: &BitCommits<OWFField<O>, O::NSTBytes>) -> CommittedState<O>
where
    O: OWFParameters,
{
    (0..O::NSTBytes::USIZE)
        .map(|i| FieldCommitDegOne {
            key: OWFField::<O>::byte_combine_bits(state.keys[i]),
            tag: OWFField::<O>::byte_combine_slice(&state.tags[i * 8..i * 8 + 8]),
        })
        .collect()
}

pub(crate) fn shift_rows<O>(state: &mut CommittedStateSquared<O>)
where
    O: OWFParameters,
{
    // TODO: Copy row by row instead of entire state
    let mut tmp = state.clone();

    for r in 0..4 {
        for c in 0..O::NST::USIZE {
            let off = if O::NST::USIZE != 8 || r <= 1 { 0 } else { 1 };
            std::mem::swap(
                &mut state[4 * c + r],
                &mut tmp[4 * ((c + r + off) % O::NST::USIZE) + r],
            );
        }
    }
}

pub(crate) fn add_round_key_bytes<O, T>(
    state: &mut CommittedStateSquared<O>,
    key_bytes: &GenericArray<T, O::NSTBytes>,
) where
    O: OWFParameters,
    for<'a> FieldCommitDegTwo<OWFField<O>>: AddAssign<&'a T>,
{
    for (st, k) in izip!(state.iter_mut(), key_bytes) {
        (*st) += k;
    }
}

pub(crate) fn mix_columns<O>(state: &mut CommittedStateSquared<O>, sq: bool)
where
    O: OWFParameters,
{
    let v2 = if sq {
        OWFField::<O>::BYTE_COMBINE_SQ_2
    } else {
        OWFField::<O>::BYTE_COMBINE_2
    };
    let v3 = if sq {
        OWFField::<O>::BYTE_COMBINE_SQ_3
    } else {
        OWFField::<O>::BYTE_COMBINE_3
    };

    for c in 0..O::NST::USIZE {

        // Save the 4 state's columns that are modified in this round
        let tmp = GenericArray::<_,U4>::from_slice(&state[4*c..4*c+4]).to_owned();

        let i0 = 4 * c;
        let i1 = 4 * c + 1;
        let i2 = 4 * c + 2;
        let i3 = 4 * c + 3;

        // ::7
        state[i0] = tmp[0].clone() * &v2 + tmp[1].clone() * &v3 + &tmp[2] + &tmp[3]; 
        
        // ::8
        state[i1] = tmp[1].clone() * &v2 + tmp[2].clone() * &v3 + &tmp[1] + &tmp[3];

        // ::9
        state[i2] = tmp[2].clone() * &v2 + tmp[3].clone() * &v3 + &tmp[0] + &tmp[1]; 

        // ::10
        // SAFETY: tmp has length 4, hence unwrapping the first 4 elements is safe
        let mut tmp = tmp.into_iter();
        let tmp0 = tmp.next().unwrap();
        let tmp1 = tmp.next().unwrap();
        let tmp2 = tmp.next().unwrap();
        let tmp3 = tmp.next().unwrap();
        
        state[i3] = tmp0 * &v3 + tmp3 * &v2 + &tmp1 + &tmp2;
    }
}
