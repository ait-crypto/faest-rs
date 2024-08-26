pub(crate) mod large_fields;
pub(crate) mod small_fields;

use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

pub use large_fields::{BigGaloisField, ByteCombine, SumPoly, GF128, GF192, GF256};
pub use small_fields::{GaloisField, GF64, GF8};

/// Trait covering the basic functionality of a field
///
/// The implementation in general does not require field elements to be
/// inverted. As such, no function to invert elements is provided.
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
    /// Representation of `0`
    const ZERO: Self;

    /// Representation of `0`
    const ONE: Self;
}
