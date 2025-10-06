#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use core::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use generic_array::{
    ArrayLength, GenericArray,
    typenum::{Prod, U3},
};

pub(crate) mod large_fields;
pub(crate) mod large_fields_constants;
pub(crate) mod small_fields;

#[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
#[allow(unused_unsafe)]
pub(crate) mod x86_simd_large_fields;

pub(crate) use large_fields::{
    BigGaloisField, ByteCombine, ByteCombineConstants, ByteCombineSquaredConstants, FromBit,
    Sigmas, SumPoly,
};
#[cfg(not(all(
    feature = "opt-simd",
    target_feature = "avx2",
    target_feature = "pclmulqdq"
)))]
pub(crate) use large_fields::{GF128, GF192, GF256};
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
    + PartialEq
    + Eq
{
    /// Representation of `0`
    const ZERO: Self;

    /// Representation of `1`
    const ONE: Self;

    /// Length of the byte representation of the field
    type Length: ArrayLength;

    /// Obtain byte representation of the field element
    fn as_bytes(&self) -> GenericArray<u8, Self::Length>;

    /*/
    /// Obtain a boxed byte representation of the field element
    fn as_boxed_bytes(&self) -> Box<GenericArray<u8, Self::Length>>;
    */
}

pub(crate) trait Base: Field<Length: Mul<U3, Output: ArrayLength>> {
    type Extension: ExtensionField<BaseField = Self, Length = Prod<Self::Length, U3>>;
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

// blanket implementation for GenericArray

impl<F, L> Square for GenericArray<F, L>
where
    F: Square,
    L: ArrayLength,
{
    type Output = GenericArray<F::Output, L>;

    fn square(self) -> Self::Output {
        self.into_iter().map(|x| x.square()).collect()
    }
}

impl<F, L> Square for &GenericArray<F, L>
where
    F: Square + Clone,
    L: ArrayLength,
{
    type Output = GenericArray<F::Output, L>;

    fn square(self) -> Self::Output {
        self.iter().cloned().map(|x| x.square()).collect()
    }
}

impl<F, L> Square for &Box<GenericArray<F, L>>
where
    F: Square + Clone,
    L: ArrayLength,
{
    type Output = Box<GenericArray<F::Output, L>>;

    fn square(self) -> Self::Output {
        self.iter().cloned().map(|x| x.square()).collect()
    }
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
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> From<&'a [u8]>
    + PartialEq
    + Eq
    + Debug
{
    /// Length of the byte representation of the field
    type Length: ArrayLength;

    /// Base field of the extension field
    type BaseField: Field;

    /// Obtain byte representation of the field element
    fn as_bytes(&self) -> GenericArray<u8, Self::Length>;
}
