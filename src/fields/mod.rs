pub(crate) mod large_fields;
pub(crate) mod small_fields;

#[cfg(all(
    feature = "opt-simd",
    target_arch = "x86_64",
    target_feature = "avx2",
    target_feature = "pclmulqdq"
))]
pub(crate) mod x86_simd_large_fields;

use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use generic_array::{ArrayLength, GenericArray};

pub(crate) use large_fields::{
    Betas, BigGaloisField, ByteCombine, ByteCombineConstants, ByteCombineSquaredConstants, FromBit,
    Sigmas, SumPoly,
};
#[cfg(not(all(
    feature = "opt-simd",
    target_feature = "avx2",
    target_feature = "pclmulqdq"
)))]
pub(crate) use large_fields::{GF128, GF192, GF256, GF384, GF576, GF768};
pub(crate) use small_fields::{GF8, GF64};

#[cfg(all(
    feature = "opt-simd",
    target_feature = "avx2",
    target_feature = "pclmulqdq"
))]
pub(crate) use x86_simd_large_fields::{GF128, GF192, GF256, GF384, GF576, GF768};

/// Trait covering the basic functionality of a field
///
/// The implementation in general does not require field elements to be
/// inverted. As such, no function to invert elements is provided.
pub(crate) trait Field:
    Sized
    + Default
    + Add<Self, Output = Self>
    + AddAssign
    + Sub<Self, Output = Self>
    + SubAssign
    + Neg<Output = Self>
    + Mul<Self, Output = Self>
    + MulAssign
{
    /// Representation of `0`
    const ZERO: Self;

    /// Representation of `1`
    const ONE: Self;

    /// Length of the byte representation of the field
    type Length: ArrayLength;

    /// Obtain byte representation of the field element
    fn as_bytes(&self) -> GenericArray<u8, Self::Length>;

    /// Obtain a boxed byte representation of the field element
    #[allow(dead_code)]
    fn as_boxed_bytes(&self) -> Box<GenericArray<u8, Self::Length>>;
}

/// Double a field element
///
/// This operation is not equivalent to `self + self` but corresponds to a the
/// multiplication with the element representing `2`.
pub(crate) trait Double {
    /// Output type
    type Output;

    /// Double a field element
    fn double(self) -> Self::Output;
}

/// Square a field element
pub(crate) trait Square {
    /// Output type
    type Output;
    /// Square an element
    fn square(self) -> Self::Output;
}

/// Trait covering the basic functionality of an extension field
///
/// The implementation in general does not require field elements to be
/// inverted. As such, no function to invert elements is provided.
/// Furthermore, we only require extension field elements to support multiplication for base field elements.
pub(crate) trait ExtensionField:
    Sized
    + Default
    + Add<Self, Output = Self>
    + AddAssign
    + Sub<Self, Output = Self>
    + SubAssign
    + Neg<Output = Self>
    + Mul<Self::BaseField, Output = Self>
    + for<'a> Mul<&'a Self::BaseField, Output = Self>
{
    /// Representation of `0`
    const ZERO: Self;

    /// Representation of `1`
    const ONE: Self;

    /// Length of the byte representation of the field
    type Length: ArrayLength;

    /// Base field of the extension field
    type BaseField: Field;

    /// Obtain byte representation of the field element
    #[allow(dead_code)]
    fn as_bytes(&self) -> GenericArray<u8, Self::Length>;

    /// Obtain a boxed byte representation of the field element
    fn as_boxed_bytes(&self) -> Box<GenericArray<u8, Self::Length>>;
}
