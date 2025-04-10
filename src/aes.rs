use aes::cipher::KeyInit;
use generic_array::{
    functional::FunctionalSequence,
    typenum::{Prod, Unsigned, Zero, B1, U1, U10, U3, U32, U4, U8},
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
        large_fields::{Betas, ByteCombineSquared, ByteCombineSquaredConstants, SquareBytes},
        small_fields::{GF8, GF8_INV_NORM},
        BigGaloisField, ByteCombine, ByteCombineConstants, Field, Sigmas, SumPoly,
    },
    internal_keys::PublicKey,
    parameter::{BaseParameters, OWFField, OWFParameters, QSProof, TauParameters},
    prover::{
        byte_commitments::{ByteCommits, ByteCommitsRef},
        field_commitment::{FieldCommitDegOne, FieldCommitDegThree, FieldCommitDegTwo},
    },
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, rijndael_sub_bytes, sub_bytes,
        sub_bytes_nots, State, RCON_TABLE,
    },
    universal_hashing::{ZKHasher, ZKHasherInit, ZKHasherProcess, ZKProofHasher, ZKVerifyHasher},
    utils::{contains_zeros, get_bits, xor_arrays},
};

/// Trait for adding a round key to the state, generating a new state
pub(crate) trait AddRoundKey<Rhs = Self> {
    type Output;

    fn add_round_key(&self, rhs: Rhs) -> Self::Output;
}

/// Trait for adding a round key to the state in-place
pub(crate) trait AddRoundKeyAssign<Rhs = Self> {
    fn add_round_key_assign(&mut self, rhs: Rhs);
}

/// Trait for combining commitments to the state bits into commitments to the state bytes
pub(crate) trait StateToBytes<O: OWFParameters> {
    type Output;

    fn state_to_bytes(&self) -> Self::Output;
}

/// Trait for applying the AES inverse shift rows transformation to the state, generating a new state
pub(crate) trait InverseShiftRows<O: OWFParameters> {
    type Output;
    fn inverse_shift_rows(&self) -> Self::Output;
}

/// Trait for applying the AES mix columns transformation to the state bytes, generating a new state
pub(crate) trait BytewiseMixColumns<O: OWFParameters> {
    type Output;
    fn bytewise_mix_columns(&self) -> Self::Output;
}

/// Trait for applying the AES S-box affine transformation to the state, generating a new state
pub(crate) trait SBoxAffine<O: OWFParameters> {
    type Output;
    fn s_box_affine(&self, sq: bool) -> Self::Output;
}

/// Trait for applying the AES shift rows transformation to the state in-place
pub(crate) trait ShiftRows {
    fn shift_rows<O: OWFParameters>(&mut self);
}

/// Trait for applying the AES S-box affine inverse transformation to the state in-place
pub(crate) trait InverseAffine {
    fn inverse_affine<O: OWFParameters>(&mut self);
}

/// Trait for applying the AES mix columns transformation to the state in-place
pub(crate) trait MixColumns<O: OWFParameters> {
    fn mix_columns(&mut self, sq: bool);
}

/// Trait for adding a round key to the state bytes in-place
pub(crate) trait AddRoundKeyBytes<Rhs = Self> {
    fn add_round_key_bytes(&mut self, rhs: Rhs, sq: bool);
}
