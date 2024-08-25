pub(crate) mod large_fields;
pub(crate) mod small_fields;

use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

pub use large_fields::{BigGaloisField, GF128, GF192, GF256};
pub use small_fields::{GaloisField, GF64, GF8};

/// Trait covering the basic functionality of a field
pub trait Field:
    Sized
    + Default
    + Add<Self, Output = Self>
    + AddAssign
    + Sub<Self, Output = Self>
    + SubAssign
    + Mul<Self, Output = Self>
    + MulAssign
{
    /// Reppresentation of `0`
    const ZERO: Self;

    /// Reppresentation of `0`
    const ONE: Self;
}
