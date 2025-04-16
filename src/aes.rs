use crate::parameter::OWFParameters;

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
    fn shift_rows(&mut self);
}

/// Trait for applying the AES S-box affine inverse transformation to the state in-place
pub(crate) trait InverseAffine {
    fn inverse_affine(&mut self);
}

/// Trait for applying the AES mix columns transformation to the state in-place
pub(crate) trait MixColumns<O> {
    fn mix_columns(&mut self, sq: bool);
}

/// Trait for adding a round key to the state bytes in-place
pub(crate) trait AddRoundKeyBytes<Rhs = Self> {
    fn add_round_key_bytes(&mut self, rhs: Rhs, sq: bool);
}
