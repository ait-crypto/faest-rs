use crate::{
    aes::{AddRoundKey, AddRoundKeyAssign},
    fields::BigGaloisField,
};
use generic_array::{typenum::U8, ArrayLength, GenericArray};
use std::ops::{Add, Mul};

mod encryption;
mod key_expansion;
mod vole_commitments;
pub(crate) mod zk_constraints;
