use std::{
    array,
    fmt::Debug,
    mem,
    num::Wrapping,
    ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitXor, BitXorAssign, Mul, MulAssign, Neg,
        Shl, Shr, Sub, SubAssign,
    },
};

use generic_array::{
    GenericArray,
    typenum::{U16, U24, U32, U48, U72, U96},
};
#[cfg(test)]
use rand::{
    Rng,
    distributions::{Distribution, Standard},
};

use super::{Double, ExtensionField, Field, GF8, GF64, Square};

/// Helper trait that define "alphas" for calculating embedings as part of [`ByteCombine`]
pub(crate) trait Alphas: Sized {
    const ALPHA: [Self; 7];
}

/// Helper trait that define "betas" for calculating F2 conjugates
pub(crate) trait Betas: Sized {
    const BETA_SQUARES: [Self; 5];
    const BETA_CUBES: [Self; 4];
}

pub(crate) trait Sigmas: Sized {
    const SIGMA: [Self; 9];
    const SIGMA_SQUARES: [Self; 9];
}

/// "Marker" trait for the larger binary Galois fields, i.e., [GF128], [GF192] and [GF256].
///
/// This trait requires an implementation of [From] for a byte slice. This may
/// panic in principle, but the implementation ensures that this function is
/// only called with slices of the correct length.
pub(crate) trait BigGaloisField:
    Field
    + FromBit
    + Copy
    + Double<Output = Self>
    + Mul<u8, Output = Self>
    + Mul<GF64, Output = Self>
    + Square<Output = Self>
    + ByteCombine
    + ByteCombineConstants
    + SquareBytes
    + ByteCombineSquared
    + ByteCombineSquaredConstants
    + SumPoly
    + Betas
    + Sigmas
    + Debug
where
    Self: for<'a> From<&'a [u8]>,
    Self: for<'a> AddAssign<&'a Self>,
    Self: for<'a> Add<&'a Self, Output = Self>,
    Self: for<'a> SubAssign<&'a Self>,
    Self: for<'a> Sub<&'a Self, Output = Self>,
    Self: for<'a> MulAssign<&'a Self>,
    Self: for<'a> Mul<&'a Self, Output = Self>,
{
}

#[allow(dead_code)]
/// Trait providing methods for "byte combination"
pub trait ByteCombine: Field {
    /// "Combine" field elements
    fn byte_combine(x: &[Self; 8]) -> Self;

    /// "Combine" field elements
    ///
    /// This is the same as [`Self::byte_combine`] but takes a slice instead. It
    /// panics if the slice has less than `8` elements.
    fn byte_combine_slice(x: &[Self]) -> Self;

    /// "Combine" bits
    ///
    /// This is equivalient to calling the other functions with each bit
    /// expressed a `0` or `1` field elements.`
    fn byte_combine_bits(x: u8) -> Self;
}

/// Pre-computed values from [`ByteCombine`]
pub trait ByteCombineConstants: Field {
    /// Equivalent `ByteCombing::byte_combine_bits(2)`
    const BYTE_COMBINE_2: Self;
    /// Equivalent `ByteCombing::byte_combine_bits(3)`
    const BYTE_COMBINE_3: Self;
}

/// Trait providing a polynomial sum
pub trait SumPoly: Field {
    /// Compute polynomial sum
    fn sum_poly(v: &[Self]) -> Self;
    fn sum_poly_bits(v: &[u8]) -> Self;
}

// Trait providing methods for byte squaring, where each byte is represented by 8 field elements.
pub trait SquareBytes: Field {
    fn square_byte(x: &[Self]) -> [Self; 8];
    fn square_byte_inplace(x: &mut [Self]);
}

impl<T> SquareBytes for T
where
    T: BigGaloisField,
{
    fn square_byte(x: &[Self]) -> [Self; 8] {
        let mut sq = [<Self as Field>::ZERO; 8];
        sq[0] = x[0] + x[4] + x[6];
        sq[2] = x[1] + x[5];
        sq[4] = x[2] + x[4] + x[7];
        sq[5] = x[5] + x[6];
        sq[6] = x[3] + x[5];
        sq[7] = x[6] + x[7];

        sq[1] = x[4] + sq[7];
        sq[3] = x[5] + sq[1];

        sq
    }

    fn square_byte_inplace(x: &mut [Self]) {
        let (i2, i4, i5, i6) = (x[2], x[4], x[5], x[6]);

        // x0 = x0 + x4 + x6
        x[0] += x[4] + x[6];
        // x2 = x1 + x5
        x[2] = x[1] + x[5];
        // x4 = x4 + x2 + x7
        x[4] += i2 + x[7];
        // x5 = x5 + x6
        x[5] += x[6];
        // x6 = x3 + x5
        x[6] = x[3] + i5;
        // x7 = x6 + x7
        x[7] += i6;

        // x1 = x4 + (x6 + x7)
        x[1] = i4 + x[7];
        // x3 = x5 + (x4 + x6 + x7)
        x[3] = i5 + x[1];
    }
}

/// Trait providing methods for "squared byte combination"
#[allow(dead_code)]
pub trait ByteCombineSquared: Field {
    fn byte_combine_sq(x: &[Self; 8]) -> Self;
    fn byte_combine_sq_slice(x: &[Self]) -> Self;
    fn byte_combine_bits_sq(x: u8) -> Self;
}

// Trait providing for deriving a field element from a bit value
pub trait FromBit: Field {
    /// Takes the first bit from the input byte `x`, and returns the respective Field representation.
    fn from_bit(x: u8) -> Self;
}

/// Pre-computed values from [`ByteCombineSquared`]
pub trait ByteCombineSquaredConstants: Field {
    /// Equivalent `ByteCombing::byte_combine_bits_sq(2)`
    const BYTE_COMBINE_SQ_2: Self;
    /// Equivalent `ByteCombing::byte_combine_bits_sq(3)`
    const BYTE_COMBINE_SQ_3: Self;
}

impl<T> SumPoly for T
where
    T: Copy + Field + Double<Output = Self> + for<'a> Add<&'a Self, Output = Self> + FromBit,
{
    fn sum_poly(v: &[Self]) -> Self {
        v.iter()
            .rev()
            .skip(1)
            .fold(v[v.len() - 1], |sum, val| sum.double() + val)
    }

    fn sum_poly_bits(v: &[u8]) -> Self {
        let init = Self::from_bit(v[v.len() - 1] >> 7);
        (0..v.len() * 8).rev().skip(1).fold(init, |sum, i| {
            sum.double() + Self::from_bit(v[i / 8] >> (i % 8))
        })
    }
}

/// Binary galois field for larger sizes (e.g., 128 bits and above)
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct BigGF<T, const N: usize, const LENGTH: usize>(pub(crate) [T; N]);

impl<T, const N: usize, const LENGTH: usize> Default for BigGF<T, N, LENGTH>
where
    T: Default + Copy,
{
    fn default() -> Self {
        Self([Default::default(); N])
    }
}

// generic implementation of FromBit

impl<T, const N: usize, const LENGTH: usize> FromBit for BigGF<T, N, LENGTH>
where
    Self: Field + ApplyMask<T, Output = Self>,
    u8: ToMask<T>,
{
    fn from_bit(x: u8) -> Self {
        Self::ONE.apply_mask(x.to_mask_bit(0))
    }
}

// generic implementation of ByteCombine

impl<T, const N: usize, const LENGTH: usize> ByteCombine for BigGF<T, N, LENGTH>
where
    Self:
        Alphas + Field + Copy + ApplyMask<T, Output = Self> + for<'a> Mul<&'a Self, Output = Self>,
    u8: ToMask<T>,
{
    fn byte_combine(x: &[Self; 8]) -> Self {
        x.iter()
            .skip(1)
            .zip(Self::ALPHA)
            .fold(x[0], |sum, (xi, alphai)| sum + (alphai * xi))
    }

    fn byte_combine_slice(x: &[Self]) -> Self {
        debug_assert_eq!(x.len(), 8);
        let (x0, x) = x.split_at(1);
        x.iter()
            .zip(Self::ALPHA)
            .fold(x0[0], |sum, (xi, alphai)| sum + (alphai * xi))
    }

    fn byte_combine_bits(x: u8) -> Self {
        Self::ALPHA.iter().enumerate().fold(
            Self::ONE.apply_mask(x.to_mask_bit(0)),
            |sum, (index, alpha)| sum + alpha.apply_mask(x.to_mask_bit(index + 1)),
        )
    }
}

// generic implementation of byte combine squared

impl<T, const N: usize, const LENGTH: usize> ByteCombineSquared for BigGF<T, N, LENGTH>
where
    Self: Alphas
        + Field
        + Copy
        + ApplyMask<T, Output = Self>
        + for<'a> Mul<&'a Self, Output = Self>
        + SquareBytes,
    u8: ToMask<T>,
{
    /// "Square and Combine" field elements.
    ///
    /// Each input field element is associated to a bit. The function computes bitwise squaring of the input and combines the result.
    fn byte_combine_sq(x: &[Self; 8]) -> Self {
        let sq = Self::square_byte(x);
        Self::byte_combine(&sq)
    }

    /// "Square and Combine" field elements
    ///
    /// This is the same as [`Self::byte_combine_sq`] but takes a slice instead. It
    /// panics if the slice has less than `8` elements.
    fn byte_combine_sq_slice(x: &[Self]) -> Self {
        let sq = Self::square_byte(x);
        Self::byte_combine(&sq)
    }

    /// "Square and Combine" bits
    ///
    /// This is equivalient to calling the other functions with each bit
    /// expressed a `0` or `1` field elements.`
    fn byte_combine_bits_sq(x: u8) -> Self {
        let sq_bits = GF8::square_bits(x);
        Self::byte_combine_bits(sq_bits)
    }
}

// generic implementations of Add and AddAssign

impl<T, const N: usize, const LENGTH: usize> Add for BigGF<T, N, LENGTH>
where
    T: BitXor<Output = T> + Copy,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(array::from_fn(|idx| self.0[idx] ^ rhs.0[idx]))
    }
}

impl<T, const N: usize, const LENGTH: usize> Add<&Self> for BigGF<T, N, LENGTH>
where
    T: BitXor<Output = T> + Copy,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(array::from_fn(|idx| self.0[idx] ^ rhs.0[idx]))
    }
}

impl<T, const N: usize, const LENGTH: usize> Add<Self> for &BigGF<T, N, LENGTH>
where
    T: BitXor<Output = T> + Copy,
{
    type Output = BigGF<T, N, LENGTH>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        BigGF(array::from_fn(|idx| self.0[idx] ^ rhs.0[idx]))
    }
}

impl<T, const N: usize, const LENGTH: usize> AddAssign for BigGF<T, N, LENGTH>
where
    T: BitXorAssign<T> + Copy,
{
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        for idx in 0..N {
            self.0[idx] ^= rhs.0[idx];
        }
    }
}

impl<T, const N: usize, const LENGTH: usize> AddAssign<&Self> for BigGF<T, N, LENGTH>
where
    T: BitXorAssign<T> + Copy,
{
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: &Self) {
        for idx in 0..N {
            self.0[idx] ^= rhs.0[idx];
        }
    }
}

// generic implementations of Sub and SubAssign

impl<T, const N: usize, const LENGTH: usize> Sub for BigGF<T, N, LENGTH>
where
    Self: Add<Output = Self>,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl<T, const N: usize, const LENGTH: usize> Sub<&Self> for BigGF<T, N, LENGTH>
where
    Self: for<'a> Add<&'a Self, Output = Self>,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &Self) -> Self::Output {
        self + rhs
    }
}

impl<T, const N: usize, const LENGTH: usize> SubAssign for BigGF<T, N, LENGTH>
where
    Self: AddAssign,
{
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs;
    }
}

impl<T, const N: usize, const LENGTH: usize> SubAssign<&Self> for BigGF<T, N, LENGTH>
where
    Self: for<'a> AddAssign<&'a Self>,
{
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: &Self) {
        *self += rhs;
    }
}

// generic implementation of Neg

impl<T, const N: usize, const LENGTH: usize> Neg for BigGF<T, N, LENGTH> {
    type Output = Self;

    #[inline(always)]
    fn neg(self) -> Self::Output {
        self
    }
}

// generic implementations of Mul and MulAssign

/// Modulus of a binary Galois field
pub(crate) trait Modulus<T> {
    const MODULUS: T;
}

/// Convert a bit into a mask, that is a 0 bit is converted into an all-0 value
/// and 1 bit is converted into an all-1 value.
trait ToMask<T> {
    /// Turn the most signficant bit into a mask
    fn to_mask(&self) -> T;
    /// Turn the specified bit into a mask
    fn to_mask_bit(&self, bit: usize) -> T;
}

/// Apply mask generated by [`ToMask`] to a binary field
trait ApplyMask<T> {
    /// Output type of the masking operation
    type Output;

    /// Apply a mask to the current value
    fn apply_mask(self, mask: T) -> Self::Output;
    /// Apply a mask to the current value without modifying it
    fn copy_apply_mask(&self, mask: T) -> Self::Output;
}

impl<T, const N: usize, const LENGTH: usize> ApplyMask<T> for BigGF<T, N, LENGTH>
where
    T: BitAndAssign + BitAnd<Output = T> + Copy,
{
    type Output = Self;

    fn apply_mask(mut self, mask: T) -> Self::Output {
        for idx in 0..N {
            self.0[idx] &= mask;
        }
        self
    }

    fn copy_apply_mask(&self, mask: T) -> Self::Output {
        Self(array::from_fn(|idx| self.0[idx] & mask))
    }
}

/// Shift the element of binary field left by `1`
trait ShiftLeft1 {
    /// Output type of the shifting operation
    type Output;

    /// Shift to the left by `1`
    fn shift_left_1(self) -> Self::Output;
}

/// Clear bits that are larger than the field size
trait ClearHighBits: Sized {
    fn clear_high_bits(self) -> Self;
}

impl<T, const N: usize, const LENGTH: usize> ShiftLeft1 for BigGF<T, N, LENGTH>
where
    Self: ClearHighBits,
    T: Shl<usize, Output = T> + Shr<usize, Output = T> + BitOr<Output = T> + Copy,
{
    type Output = Self;

    fn shift_left_1(mut self) -> Self::Output {
        for idx in (1..N).rev() {
            self.0[idx] = (self.0[idx] << 1) | (self.0[idx - 1] >> (mem::size_of::<T>() * 8 - 1));
        }
        self.0[0] = self.0[0] << 1;
        self.clear_high_bits()
    }
}

impl<T, const N: usize, const LENGTH: usize> Mul for BigGF<T, N, LENGTH>
where
    Self: Modulus<T>,
    Self: ToMask<T>,
    Self: ApplyMask<T, Output = Self>,
    Self: AddAssign,
    Self: ShiftLeft1<Output = Self>,
    T: BitAnd<Output = T>,
    T: BitXorAssign,
{
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        let mut result = self.copy_apply_mask(rhs.to_mask_bit(0));
        for idx in 1..LENGTH {
            let mask = self.to_mask();
            self = self.shift_left_1();
            self.0[0] ^= mask & Self::MODULUS;

            result += self.copy_apply_mask(rhs.to_mask_bit(idx));
        }
        result
    }
}

impl<T, const N: usize, const LENGTH: usize> Mul<&Self> for BigGF<T, N, LENGTH>
where
    Self: Modulus<T>,
    Self: ToMask<T>,
    Self: ApplyMask<T, Output = Self>,
    Self: AddAssign,
    Self: ShiftLeft1<Output = Self>,
    T: BitAnd<Output = T>,
    T: BitXorAssign,
{
    type Output = Self;

    fn mul(mut self, rhs: &Self) -> Self::Output {
        let mut result = self.copy_apply_mask(rhs.to_mask_bit(0));
        for idx in 1..LENGTH {
            let mask = self.to_mask();
            self = self.shift_left_1();
            self.0[0] ^= mask & Self::MODULUS;

            result += self.copy_apply_mask(rhs.to_mask_bit(idx));
        }
        result
    }
}

impl<T, const N: usize, const LENGTH: usize> Mul<Self> for &BigGF<T, N, LENGTH>
where
    BigGF<T, N, LENGTH>: Mul<Self, Output = BigGF<T, N, LENGTH>>,
    BigGF<T, N, LENGTH>: Copy,
{
    type Output = BigGF<T, N, LENGTH>;

    fn mul(self, rhs: Self) -> Self::Output {
        *self * rhs
    }
}

impl<T, const N: usize, const LENGTH: usize> Mul<u8> for BigGF<T, N, LENGTH>
where
    Self: ApplyMask<T, Output = Self>,
    u8: ToMask<T>,
{
    type Output = Self;

    fn mul(self, rhs: u8) -> Self::Output {
        self.apply_mask(rhs.to_mask_bit(0))
    }
}

impl<T, const N: usize, const LENGTH: usize> Mul<GF64> for BigGF<T, N, LENGTH>
where
    Self: Modulus<T>,
    Self: ToMask<T>,
    Self: ApplyMask<T, Output = Self>,
    Self: AddAssign,
    Self: ShiftLeft1<Output = Self>,
    T: BitAnd<Output = T>,
    T: BitXorAssign,
    u64: ToMask<T>,
{
    type Output = Self;

    fn mul(mut self, rhs: GF64) -> Self::Output {
        let rhs = u64::from(rhs);
        let mut result = self.copy_apply_mask(rhs.to_mask_bit(0));
        for idx in 1..64 {
            let mask = self.to_mask();
            self = self.shift_left_1();
            self.0[0] ^= mask & Self::MODULUS;

            result += self.copy_apply_mask(rhs.to_mask_bit(idx));
        }
        result
    }
}

impl<T, const N: usize, const LENGTH: usize> Mul<GF64> for &BigGF<T, N, LENGTH>
where
    BigGF<T, N, LENGTH>: Mul<GF64, Output = BigGF<T, N, LENGTH>>,
    BigGF<T, N, LENGTH>: Copy,
{
    type Output = BigGF<T, N, LENGTH>;

    fn mul(self, rhs: GF64) -> Self::Output {
        *self * rhs
    }
}

impl<T, const N: usize, const LENGTH: usize> MulAssign for BigGF<T, N, LENGTH>
where
    Self: Copy,
    Self: Modulus<T>,
    Self: ToMask<T>,
    Self: ApplyMask<T, Output = Self>,
    Self: AddAssign,
    Self: ShiftLeft1<Output = Self>,
    T: BitAnd<Output = T>,
    T: BitXorAssign,
{
    fn mul_assign(&mut self, rhs: Self) {
        let mut lhs = *self;
        *self = self.copy_apply_mask(rhs.to_mask_bit(0));
        for idx in 1..LENGTH {
            let mask = lhs.to_mask();
            lhs = lhs.shift_left_1();
            lhs.0[0] ^= mask & Self::MODULUS;

            *self += lhs.copy_apply_mask(rhs.to_mask_bit(idx));
        }
    }
}

impl<T, const N: usize, const LENGTH: usize> MulAssign<&Self> for BigGF<T, N, LENGTH>
where
    Self: Copy,
    Self: Modulus<T>,
    Self: ToMask<T>,
    Self: ApplyMask<T, Output = Self>,
    Self: AddAssign,
    Self: ShiftLeft1<Output = Self>,
    T: BitAnd<Output = T>,
    T: BitXorAssign,
{
    fn mul_assign(&mut self, rhs: &Self) {
        let mut lhs = *self;
        *self = self.copy_apply_mask(rhs.to_mask_bit(0));
        for idx in 1..LENGTH {
            let mask = lhs.to_mask();
            lhs = lhs.shift_left_1();
            lhs.0[0] ^= mask & Self::MODULUS;

            *self += lhs.copy_apply_mask(rhs.to_mask_bit(idx));
        }
    }
}

impl<T, const N: usize, const LENGTH: usize> MulAssign<u64> for BigGF<T, N, LENGTH>
where
    Self: Copy,
    Self: Modulus<T>,
    Self: ToMask<T>,
    Self: ApplyMask<T, Output = Self>,
    Self: AddAssign,
    Self: ShiftLeft1<Output = Self>,
    T: BitAnd<Output = T>,
    T: BitXorAssign,
    u64: ToMask<T>,
{
    fn mul_assign(&mut self, rhs: u64) {
        let mut lhs = *self;
        *self = self.copy_apply_mask(rhs.to_mask_bit(0));
        for idx in 1..64 {
            let mask = lhs.to_mask();
            lhs = lhs.shift_left_1();
            lhs.0[0] ^= mask & Self::MODULUS;

            *self += lhs.copy_apply_mask(rhs.to_mask_bit(idx));
        }
    }
}

// generic implementation of Double

impl<T, const N: usize, const LENGTH: usize> Double for BigGF<T, N, LENGTH>
where
    Self: ToMask<T>,
    Self: Modulus<T>,
    Self: ShiftLeft1<Output = Self>,
    T: BitAnd<Output = T>,
    T: BitXorAssign,
{
    type Output = Self;

    fn double(mut self) -> Self::Output {
        let mask = self.to_mask();
        self = self.shift_left_1();
        self.0[0] ^= mask & Self::MODULUS;
        self
    }
}

// generic implementation of Square

impl<T, const N: usize, const LENGTH: usize> Square for BigGF<T, N, LENGTH>
where
    Self: Copy,
    Self: Modulus<T>,
    Self: ToMask<T>,
    Self: ApplyMask<T, Output = Self>,
    Self: AddAssign,
    Self: ShiftLeft1<Output = Self>,
    T: BitAnd<Output = T>,
    T: BitXorAssign,
{
    type Output = Self;

    fn square(self) -> Self::Output {
        let mut other = self;
        let mut result = other.copy_apply_mask(self.to_mask_bit(0));
        for idx in 1..LENGTH {
            let mask = other.to_mask();
            other = other.shift_left_1();
            other.0[0] ^= mask & Self::MODULUS;

            result += other.copy_apply_mask(self.to_mask_bit(idx));
        }
        result
    }
}

// implementations for u128 based field implementations

impl<const N: usize, const LENGTH: usize> ToMask<u128> for BigGF<u128, N, LENGTH> {
    fn to_mask(&self) -> u128 {
        let array_index = (LENGTH - 1) / (mem::size_of::<u128>() * 8);
        let value_index = (LENGTH - 1) % (mem::size_of::<u128>() * 8);

        (-Wrapping((self.0[array_index] >> value_index) & 1)).0
    }

    fn to_mask_bit(&self, bit: usize) -> u128 {
        let array_index = bit / (mem::size_of::<u128>() * 8);
        let value_index = bit % (mem::size_of::<u128>() * 8);

        (-Wrapping((self.0[array_index] >> value_index) & 1)).0
    }
}

impl ToMask<u128> for u64 {
    fn to_mask(&self) -> u128 {
        self.to_mask_bit(64 - 1)
    }

    fn to_mask_bit(&self, bit: usize) -> u128 {
        // let array_index = bit / 64;
        let value_index = bit % 64;

        (-Wrapping(((self >> value_index) & 1) as u128)).0
    }
}

impl ToMask<u128> for GF64 {
    fn to_mask(&self) -> u128 {
        self.to_mask_bit(64 - 1)
    }

    fn to_mask_bit(&self, bit: usize) -> u128 {
        let value: u64 = (*self).into();
        value.to_mask_bit(bit)
    }
}

impl ToMask<u128> for u8 {
    fn to_mask(&self) -> u128 {
        self.to_mask_bit(0)
    }

    fn to_mask_bit(&self, bit: usize) -> u128 {
        (-Wrapping(((*self >> bit) & 1) as u128)).0
    }
}

// u128-based GF128, GF192, and GF256

impl Modulus<u128> for BigGF<u128, 1, 128> {
    const MODULUS: u128 = 0b10000111u128;
}

impl ClearHighBits for BigGF<u128, 1, 128> {
    #[inline(always)]
    fn clear_high_bits(self) -> Self {
        self
    }
}

impl Field for BigGF<u128, 1, 128> {
    const ZERO: Self = Self([0]);
    const ONE: Self = Self([1]);

    type Length = U16;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        GenericArray::from(self.0[0].to_le_bytes())
    }

    fn as_boxed_bytes(&self) -> Box<GenericArray<u8, Self::Length>> {
        let mut arr = GenericArray::default_boxed();
        arr.copy_from_slice(&self.0[0].to_le_bytes());
        arr
    }
}

impl Alphas for BigGF<u128, 1, 128> {
    const ALPHA: [Self; 7] = [
        Self([0x053d8555a9979a1ca13fe8ac5560ce0du128]),
        Self([0x4cf4b7439cbfbb84ec7759ca3488aee1u128]),
        Self([0x35ad604f7d51d2c6bfcf02ae363946a8u128]),
        Self([0x0dcb364640a222fe6b8330483c2e9849u128]),
        Self([0x549810e11a88dea5252b49277b1b82b4u128]),
        Self([0xd681a5686c0c1f75c72bf2ef2521ff22u128]),
        Self([0x0950311a4fb78fe07a7a8e94e136f9bcu128]),
    ];
}

impl ByteCombineConstants for BigGF<u128, 1, 128> {
    const BYTE_COMBINE_2: Self = Self::ALPHA[0];
    const BYTE_COMBINE_3: Self = Self([Self::ALPHA[0].0[0] ^ Self::ONE.0[0]]);
}

impl From<&[u8]> for BigGF<u128, 1, 128> {
    fn from(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), 16);
        let mut array = [0u8; 16];
        array.copy_from_slice(&value[..16]);
        Self([u128::from_le_bytes(array)])
    }
}

impl Betas for GF128 {
    const BETA_SQUARES: [Self; 5] = [
        Self([0xdb4a932e2cae3d8baca8c2a7190f676bu128]),
        Self([0x500317bd159d73bb34d2f7fba603e341u128]),
        Self([0xf210539fd8dd2772cbc26e38bdbd6c62u128]),
        Self([0x7959d70ce1ee694253b85b6402b1e849u128]),
        Self([0xdb4a932e2cae3d8baca8c2a7190f676bu128]),
    ];

    const BETA_CUBES: [Self; 4] = [
        Self([0x7959d70ce1ee694253b85b6402b1e849u128]),
        Self([0xdb4a932e2cae3d8baca8c2a7190f676bu128]),
        Self([0x500317bd159d73bb34d2f7fba603e341u128]),
        Self([0xf210539fd8dd2772cbc26e38bdbd6c62u128]),
    ];
}

impl Sigmas for GF128 {
    const SIGMA: [Self; 9] = [
        Self([0x4cf4b7439cbfbb84ec7759ca3488aee0u128]),
        Self([0x35ad604f7d51d2c6bfcf02ae363946a9u128]),
        Self([0xb32fd29a04c0be084c3607bab51b5acau128]),
        Self([0x186ca7a286376521c95c10ed4f932c54u128]),
        Self([0xca760596e52ed74a1f8e5cdeb7aab282u128]),
        Self([0x00000000000000000000000000000001u128]),
        Self([0x1cf7a0fe8922c83fd8a5ae31928b4da1u128]),
        Self([0x7534634307ce7cbe88fd3d5cb6e7dff9u128]),
        Self([0x872430dcdf135bcc433f53640b5ab39au128]),
    ];

    const SIGMA_SQUARES: [Self; 9] = [
        Self([0x0dcb364640a222fe6b8330483c2e9848u128]),
        Self([0xd681a5686c0c1f75c72bf2ef2521ff23u128]),
        Self([0x49c93216352821984d48b16661e860edu128]),
        Self([0xf68b54c3d7c88a6cda3bd0e460a50d97u128]),
        Self([0x9283a13819861c13e1e073c178e70787u128]),
        Self([0x00000000000000000000000000000001u128]),
        Self([0xffdb65d9987f058ca0415e708193f42au128]),
        Self([0xa3b5c62b6bc263cb4fd6cfb393c620dbu128]),
        Self([0xdaec11278a2c0a891c6e94d79177c893u128]),
    ];
}

impl ByteCombineSquaredConstants for BigGF<u128, 1, 128> {
    const BYTE_COMBINE_SQ_2: Self = Self::ALPHA[1];
    const BYTE_COMBINE_SQ_3: Self = Self([Self::ALPHA[1].0[0] ^ Self::ONE.0[0]]);
}

impl BigGaloisField for BigGF<u128, 1, 128> {}

#[cfg(test)]
impl serde::Serialize for BigGF<u128, 1, 128> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0[0].to_le_bytes().serialize(serializer)
    }
}

#[cfg(test)]
impl<'de> serde::Deserialize<'de> for BigGF<u128, 1, 128> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <[u8; 16]>::deserialize(deserializer).map(|buffer| Self::from(buffer.as_slice()))
    }
}

/// Type representing binary Galois field of size `2^128`
pub type GF128 = BigGF<u128, 1, 128>;

#[cfg(test)]
impl Distribution<GF128> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GF128 {
        BigGF([rng.sample(self)])
    }
}

impl Modulus<u128> for BigGF<u128, 2, 192> {
    const MODULUS: u128 = 0b10000111u128;
}

impl ClearHighBits for BigGF<u128, 2, 192> {
    #[inline(always)]
    fn clear_high_bits(mut self) -> Self {
        self.0[1] &= u64::MAX as u128;
        self
    }
}

impl Field for BigGF<u128, 2, 192> {
    const ZERO: Self = Self([0, 0]);
    const ONE: Self = Self([1, 0]);

    type Length = U24;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        let mut ret = GenericArray::default();
        ret[..16].copy_from_slice(&self.0[0].to_le_bytes());
        ret[16..].copy_from_slice(&self.0[1].to_le_bytes()[..8]);
        ret
    }

    fn as_boxed_bytes(&self) -> Box<GenericArray<u8, Self::Length>> {
        let mut arr = GenericArray::default_boxed();
        arr[..16].copy_from_slice(&self.0[0].to_le_bytes());
        arr[16..].copy_from_slice(&self.0[1].to_le_bytes()[..8]);
        arr
    }
}

impl Alphas for BigGF<u128, 2, 192> {
    const ALPHA: [Self; 7] = [
        Self([
            0xe665d76c966ebdeaccc8a3d56f389763u128,
            0x310bc8140e6b3662u128,
        ]),
        Self([
            0x7bf61f19d5633f26b233619e7cf450bbu128,
            0xda933726d491db34u128,
        ]),
        Self([
            0x8232e37706328d199c6d2c13f5398a0du128,
            0x0c3b0d703c754ef6u128,
        ]),
        Self([
            0x7a5542ab0058d22edd20747cbd2bf75du128,
            0x45ec519c94bc1251u128,
        ]),
        Self([
            0x08168cb767debe84d8d50ce28ace2bf8u128,
            0xd67d146a4ba67045u128,
        ]),
        Self([
            0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
            0x29a6bd5f696cea43u128,
        ]),
        Self([
            0x6019fd623906e9d3f5945dc265068571u128,
            0xc77c56540f87c4b0u128,
        ]),
    ];
}

impl Betas for GF192 {
    const BETA_SQUARES: [Self; 5] = [
        Self([
            0x89bfb5055f8ff2664a2fe80a53fe16e7u128,
            0x6c4aecc3fdd0f812u128,
        ]),
        Self([
            0x125a337e5e808579f061255c52e359d4u128,
            0x54ed13a2d09da6a4u128,
        ]),
        Self([
            0x62217a15d25ec520941080db88d09584u128,
            0xee0fc537c5a9cb74u128,
        ]),
        Self([
            0xf9c4fc6ed351b23f2e5e4d8d89cddab6u128,
            0xd6a83a56e8e495c2u128,
        ]),
        Self([
            0x89bfb5055f8ff2664a2fe80a53fe16e7u128,
            0x6c4aecc3fdd0f812u128,
        ]),
    ];

    const BETA_CUBES: [Self; 4] = [
        Self([
            0xf9c4fc6ed351b23f2e5e4d8d89cddab6u128,
            0xd6a83a56e8e495c2u128,
        ]),
        Self([
            0x89bfb5055f8ff2664a2fe80a53fe16e7u128,
            0x6c4aecc3fdd0f812u128,
        ]),
        Self([
            0x125a337e5e808579f061255c52e359d4u128,
            0x54ed13a2d09da6a4u128,
        ]),
        Self([
            0x62217a15d25ec520941080db88d09584u128,
            0xee0fc537c5a9cb74u128,
        ]),
    ];
}

impl Sigmas for GF192 {
    const SIGMA: [Self; 9] = [
        Self([
            0x7bf61f19d5633f26b233619e7cf450bau128,
            0xda933726d491db34u128,
        ]),
        Self([
            0x8232e37706328d199c6d2c13f5398a0cu128,
            0x0c3b0d703c754ef6u128,
        ]),
        Self([
            0x638227a707652828fb039539490f3262u128,
            0x7170a38d85840211u128,
        ]),
        Self([
            0x73e093aeb2bd81a26ae66d7cf63a7b42u128,
            0x0cee234c9f37ab71u128,
        ]),
        Self([
            0x9a46dbc9d4349a17d55dd8b4c0c2e8d5u128,
            0xa7d899db6d6097d3u128,
        ]),
        Self([
            0x00000000000000000000000000000001u128,
            0x0000000000000000u128,
        ]),
        Self([
            0x69ac2c678be3ba5f425244c22e17096eu128,
            0x8e7e2484040c7d90u128,
        ]),
        Self([
            0x7fb8d6607c39e6061702b39a83f3c8a5u128,
            0x20dfa416e9086710u128,
        ]),
        Self([
            0x1d99ac75ae672326831233410b235d20u128,
            0xced061212ca1ac64u128,
        ]),
    ];
    const SIGMA_SQUARES: [Self; 9] = [
        Self([
            0x7a5542ab0058d22edd20747cbd2bf75cu128,
            0x45ec519c94bc1251u128,
        ]),
        Self([
            0xf3eaf7ae5fd72048970f9c76eed5e1bbu128,
            0x29a6bd5f696cea43u128,
        ]),
        Self([
            0x9d93c875430d82cc7efbc24b13ccc7d9u128,
            0xeb98ff32dafaed56u128,
        ]),
        Self([
            0x786dc5dceb00feddbca4a96550fde7a8u128,
            0x6c9fc2ff5e921d95u128,
        ]),
        Self([
            0x142c7d701c8270aa34d42a414032d13fu128,
            0x87d213f1272a1544u128,
        ]),
        Self([
            0x00000000000000000000000000000001u128,
            0x0000000000000000u128,
        ]),
        Self([
            0x187438bed206170e4930f4a735fb62d8u128,
            0xabe394ab5115d925u128,
        ]),
        Self([
            0x8c5221ce23eec64e800d2fec6d26291fu128,
            0x0979194980648d53u128,
        ]),
        Self([
            0x7596dda0f0bf7471ae536261e4ebf3a8u128,
            0xdfd1231f68801891u128,
        ]),
    ];
}

impl ByteCombineConstants for BigGF<u128, 2, 192> {
    const BYTE_COMBINE_2: Self = Self::ALPHA[0];
    const BYTE_COMBINE_3: Self = Self([
        Self::ALPHA[0].0[0] ^ Self::ONE.0[0],
        Self::ALPHA[0].0[1] ^ Self::ONE.0[1],
    ]);
}

impl ByteCombineSquaredConstants for BigGF<u128, 2, 192> {
    const BYTE_COMBINE_SQ_2: Self = Self::ALPHA[1];
    const BYTE_COMBINE_SQ_3: Self = Self([
        Self::ALPHA[1].0[0] ^ Self::ONE.0[0],
        Self::ALPHA[1].0[1] ^ Self::ONE.0[1],
    ]);
}

impl From<&[u8]> for BigGF<u128, 2, 192> {
    fn from(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), 24);
        let mut array_1 = [0u8; 16];
        array_1.copy_from_slice(&value[..16]);
        let mut array_2 = [0u8; 16];
        array_2[..8].copy_from_slice(&value[16..24]);
        Self([u128::from_le_bytes(array_1), u128::from_le_bytes(array_2)])
    }
}

impl BigGaloisField for BigGF<u128, 2, 192> {}

#[cfg(test)]
impl serde::Serialize for BigGF<u128, 2, 192> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut buffer = [0u8; 24];
        buffer[..16].copy_from_slice(&self.0[0].to_le_bytes());
        buffer[16..].copy_from_slice(&self.0[1].to_le_bytes()[..8]);
        buffer.serialize(serializer)
    }
}

#[cfg(test)]
impl<'de> serde::Deserialize<'de> for BigGF<u128, 2, 192> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <[u8; 24]>::deserialize(deserializer).map(|buffer| Self::from(buffer.as_slice()))
    }
}

/// Type representing binary Galois field of size `2^192`
pub type GF192 = BigGF<u128, 2, 192>;

#[cfg(test)]
impl Distribution<GF192> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GF192 {
        BigGF([rng.sample(self), {
            let v: u64 = rng.sample(self);
            v as u128
        }])
    }
}

impl Modulus<u128> for BigGF<u128, 2, 256> {
    const MODULUS: u128 = 0b10000100101u128;
}

impl ClearHighBits for BigGF<u128, 2, 256> {
    #[inline(always)]
    fn clear_high_bits(self) -> Self {
        self
    }
}

impl Field for BigGF<u128, 2, 256> {
    const ZERO: Self = Self([0, 0]);
    const ONE: Self = Self([1, 0]);

    type Length = U32;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        let mut ret = GenericArray::default();
        ret[..16].copy_from_slice(&self.0[0].to_le_bytes());
        ret[16..].copy_from_slice(&self.0[1].to_le_bytes());
        ret
    }

    fn as_boxed_bytes(&self) -> Box<GenericArray<u8, Self::Length>> {
        let mut arr = GenericArray::default_boxed();
        arr[..16].copy_from_slice(&self.0[0].to_le_bytes());
        arr[16..].copy_from_slice(&self.0[1].to_le_bytes());
        arr
    }
}

impl Alphas for BigGF<u128, 2, 256> {
    const ALPHA: [Self; 7] = [
        Self([
            0xbed68d38a0474e67969788420bdefee7u128,
            0x04c9a8cf20c95833df229845f8f1e16au128,
        ]),
        Self([
            0x2ba5c48d2c42072fa95af52ad52289c1u128,
            0x064e4d699c5b4af1d14a0d376c00b0eau128,
        ]),
        Self([
            0x1771831e533b0f5755dab3833f809d1du128,
            0x6195e3db7011f68dfb96573fad3fac10u128,
        ]),
        Self([
            0x752758911a30e3f6de010519b01bcdd5u128,
            0x56c24fd64f7688382a0778b6489ea03fu128,
        ]),
        Self([
            0x1bc4dbd440f1848298c2f529e98a30b6u128,
            0x22270b6d71574ffc2fbe09947d49a981u128,
        ]),
        Self([
            0xaced66c666f1afbc9e75afb9de44670bu128,
            0xc03d372fd1fa29f3f001253ff2991f7eu128,
        ]),
        Self([
            0x5237c4d625b86f0dba43b698b332e88bu128,
            0x133eea09d26b7bb82f652b2af4e81545u128,
        ]),
    ];
}

impl ByteCombineConstants for BigGF<u128, 2, 256> {
    const BYTE_COMBINE_2: Self = Self::ALPHA[0];
    const BYTE_COMBINE_3: Self = Self([
        Self::ALPHA[0].0[0] ^ Self::ONE.0[0],
        Self::ALPHA[0].0[1] ^ Self::ONE.0[1],
    ]);
}

impl ByteCombineSquaredConstants for BigGF<u128, 2, 256> {
    const BYTE_COMBINE_SQ_2: Self = Self::ALPHA[1];
    const BYTE_COMBINE_SQ_3: Self = Self([
        Self::ALPHA[1].0[0] ^ Self::ONE.0[0],
        Self::ALPHA[1].0[1] ^ Self::ONE.0[1],
    ]);
}

impl From<&[u8]> for BigGF<u128, 2, 256> {
    fn from(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), 32);
        Self(array::from_fn(|idx| {
            let mut array = [0u8; 16];
            array.copy_from_slice(&value[idx * 16..(idx + 1) * 16]);
            u128::from_le_bytes(array)
        }))
    }
}

impl BigGaloisField for BigGF<u128, 2, 256> {}

impl Betas for GF256 {
    const BETA_SQUARES: [Self; 5] = [
        Self([
            0xd9ca3e577cc14c4a4074aaa06e5faadeu128,
            0x96ff78f99e8ca1cbda065d89ba07bf41u128,
        ]),
        Self([
            0x3cd447937f790879fc8046a8eaa315e8u128,
            0x67dbaeb2ec4abc7c2adc5a08c13f1cfbu128,
        ]),
        Self([
            0xd9ca3e577cc14c4b4074aaa16e5eabebu128,
            0x96ff78f99e8ca1cbda065d89ba07bf40u128,
        ]),
        Self([
            0x3cd447937f790878fc8046a9eaa214dcu128,
            0x67dbaeb2ec4abc7c2adc5a08c13f1cfau128,
        ]),
        Self([
            0xd9ca3e577cc14c4a4074aaa06e5faadeu128,
            0x96ff78f99e8ca1cbda065d89ba07bf41u128,
        ]),
    ];
    const BETA_CUBES: [Self; 4] = [
        Self([
            0x3cd447937f790878fc8046a9eaa214dcu128,
            0x67dbaeb2ec4abc7c2adc5a08c13f1cfau128,
        ]),
        Self([
            0xd9ca3e577cc14c4a4074aaa06e5faadeu128,
            0x96ff78f99e8ca1cbda065d89ba07bf41u128,
        ]),
        Self([
            0x3cd447937f790879fc8046a8eaa315e8u128,
            0x67dbaeb2ec4abc7c2adc5a08c13f1cfbu128,
        ]),
        Self([
            0xd9ca3e577cc14c4b4074aaa16e5eabebu128,
            0x96ff78f99e8ca1cbda065d89ba07bf40u128,
        ]),
    ];
}

impl Sigmas for GF256 {
    const SIGMA: [Self; 9] = [
        Self([
            0x2ba5c48d2c42072fa95af52ad52289c0,
            0x064e4d699c5b4af1d14a0d376c00b0ea,
        ]),
        Self([
            0x1771831e533b0f5755dab3833f809d1c,
            0x6195e3db7011f68dfb96573fad3fac10,
        ]),
        Self([
            0x8748a24b4ab3a892372f5a920b67efff,
            0xc6737a464da16302214b28089e99af95,
        ]),
        Self([
            0x30611f596cb383ad319800033ca8b976,
            0x24694604ed0c050dfef404a31149196b,
        ]),
        Self([
            0xbb9ce5d835caa0eacbaf1c3be1c5fb22,
            0xa1a8d4f4a1ebdf7e0b9772005fa6b36f,
        ]),
        Self([
            0x00000000000000000000000000000001,
            0x00000000000000000000000000000000,
        ]),
        Self([
            0x1771831e533b0f5655dab3823f819c28,
            0x6195e3db7011f68dfb96573fad3fac11,
        ]),
        Self([
            0xd0350e7dfa862912d0547873524e02b1,
            0x702cec741ee89ff7da9be967cd26e8d5,
        ]),
        Self([
            0x09ff302a864765599020d2d23c10a95b,
            0xe6d3948d80643e3c009db4ee77215795,
        ]),
    ];
    const SIGMA_SQUARES: [Self; 9] = [
        Self([
            0x752758911a30e3f6de010519b01bcdd4,
            0x56c24fd64f7688382a0778b6489ea03f,
        ]),
        Self([
            0xaced66c666f1afbc9e75afb9de44670a,
            0xc03d372fd1fa29f3f001253ff2991f7e,
        ]),
        Self([
            0x957349b58c0549483fcd7d68defc7727,
            0x0287e5a6bc9212c20e68957294f15180,
        ]),
        Self([
            0xfedaa2104349c0b0243619206d778eb5,
            0xd303dd260391524bdf640e1506710a3a,
        ]),
        Self([
            0x4cb977e2f0c405027fb9d7c8b0a3ddf8,
            0x94789d5f221eb309d46ec8fb2ef6eec1,
        ]),
        Self([
            0x00000000000000000000000000000001,
            0x00000000000000000000000000000000,
        ]),
        Self([
            0xaced66c666f1afbd9e75afb8de45663f,
            0xc03d372fd1fa29f3f001253ff2991f7f,
        ]),
        Self([
            0x7cd868bb9c7786ae4e21d7ca8c0a65ba,
            0xb011db5bcf12b6042a9acc583fbff7ab,
        ]),
        Self([
            0x400c2f28e30e8ed6b2a1916366a87167,
            0xd7ca75e923580a7800469650fe80eb51,
        ]),
    ];
}

#[cfg(test)]
impl serde::Serialize for BigGF<u128, 2, 256> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut buffer = [0u8; 32];
        buffer[..16].copy_from_slice(&self.0[0].to_le_bytes());
        buffer[16..].copy_from_slice(&self.0[1].to_le_bytes());
        buffer.serialize(serializer)
    }
}

#[cfg(test)]
impl<'de> serde::Deserialize<'de> for BigGF<u128, 2, 256> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <[u8; 32]>::deserialize(deserializer).map(|buffer| Self::from(buffer.as_slice()))
    }
}

/// Type representing binary Galois field of size `2^256`
pub type GF256 = BigGF<u128, 2, 256>;

#[cfg(test)]
impl Distribution<GF256> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GF256 {
        BigGF([rng.sample(self), rng.sample(self)])
    }
}

/// Type representing binary Galois field of size `2^384`
pub type GF384 = BigGF<u128, 3, 384>;

impl Modulus<u128> for GF384 {
    const MODULUS: u128 = 0b1000000001101u128;
}

impl ClearHighBits for GF384 {
    #[inline(always)]
    fn clear_high_bits(self) -> Self {
        self
    }
}

impl ExtensionField for GF384 {
    const ZERO: Self = Self([0, 0, 0]);
    const ONE: Self = Self([1, 0, 0]);

    type Length = U48;

    type BaseField = GF128;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        let mut ret = GenericArray::default();
        ret[..16].copy_from_slice(&self.0[0].to_le_bytes());
        ret[16..32].copy_from_slice(&self.0[1].to_le_bytes());
        ret[32..].copy_from_slice(&self.0[2].to_le_bytes());
        ret
    }
}

impl From<&[u8]> for GF384 {
    fn from(value: &[u8]) -> Self {
        Self(array::from_fn(|idx| {
            let mut array = [0u8; 16];
            if idx * 16 < value.len() {
                array.copy_from_slice(&value[idx * 16..(idx + 1) * 16]);
            }
            u128::from_le_bytes(array)
        }))
    }
}

impl Mul<GF128> for GF384 {
    type Output = Self;
    fn mul(mut self, rhs: GF128) -> Self::Output {
        let mut result = self.copy_apply_mask(rhs.to_mask_bit(0));
        for idx in 1..128 {
            let mask = self.to_mask();
            self = self.shift_left_1();
            self.0[0] ^= mask & Self::MODULUS;
            result += self.copy_apply_mask(rhs.to_mask_bit(idx));
        }
        result
    }
}

impl Mul<&GF128> for GF384 {
    type Output = Self;
    fn mul(mut self, rhs: &GF128) -> Self::Output {
        let mut result = self.copy_apply_mask(rhs.to_mask_bit(0));
        for idx in 1..128 {
            let mask = self.to_mask();
            self = self.shift_left_1();
            self.0[0] ^= mask & Self::MODULUS;
            result += self.copy_apply_mask(rhs.to_mask_bit(idx));
        }
        result
    }
}

#[cfg(test)]
impl Distribution<GF384> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GF384 {
        BigGF([rng.sample(self), rng.sample(self), rng.sample(self)])
    }
}

/// Type representing binary Galois field of size `2^576`
pub type GF576 = BigGF<u128, 5, 576>;

impl Modulus<u128> for GF576 {
    const MODULUS: u128 = 0b10000000011001u128;
}

impl ClearHighBits for GF576 {
    #[inline(always)]
    fn clear_high_bits(mut self) -> Self {
        self.0[4] &= u64::MAX as u128;
        self
    }
}

impl ExtensionField for GF576 {
    const ZERO: Self = Self([0, 0, 0, 0, 0]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);

    type Length = U72;

    type BaseField = GF192;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        let mut ret = GenericArray::default();
        ret[..16].copy_from_slice(&self.0[0].to_le_bytes());
        ret[16..32].copy_from_slice(&self.0[1].to_le_bytes());
        ret[32..48].copy_from_slice(&self.0[2].to_le_bytes());
        ret[48..64].copy_from_slice(&self.0[3].to_le_bytes());
        ret[64..].copy_from_slice(&self.0[4].to_le_bytes()[..8]);
        ret
    }
}

impl Mul<GF192> for GF576 {
    type Output = Self;
    fn mul(mut self, rhs: GF192) -> Self::Output {
        let mut result = self.copy_apply_mask(rhs.to_mask_bit(0));
        for idx in 1..192 {
            let mask = self.to_mask();
            self = self.shift_left_1();
            self.0[0] ^= mask & Self::MODULUS;
            result += self.copy_apply_mask(rhs.to_mask_bit(idx));
        }
        result
    }
}

impl Mul<&GF192> for GF576 {
    type Output = Self;
    fn mul(mut self, rhs: &GF192) -> Self::Output {
        let mut result = self.copy_apply_mask(rhs.to_mask_bit(0));
        for idx in 1..192 {
            let mask = self.to_mask();
            self = self.shift_left_1();
            self.0[0] ^= mask & Self::MODULUS;
            result += self.copy_apply_mask(rhs.to_mask_bit(idx));
        }
        result
    }
}

impl From<&[u8]> for GF576 {
    fn from(value: &[u8]) -> Self {
        let full_blocks = value.len() / 16;
        let partial_block_size = value.len() % 16;
        Self(array::from_fn(|idx| {
            let mut array = [0u8; 16];
            if idx < full_blocks {
                array.copy_from_slice(&value[idx * 16..(idx + 1) * 16]);
            } else if partial_block_size > 0 {
                array[..partial_block_size].copy_from_slice(&value[idx * 16..]);
            }
            u128::from_le_bytes(array)
        }))
    }
}

#[cfg(test)]
impl Distribution<GF576> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GF576 {
        BigGF([
            rng.sample(self),
            rng.sample(self),
            rng.sample(self),
            rng.sample(self),
            rng.sample(self),
        ])
    }
}

/// Type representing binary Galois field of size `2^768`
pub type GF768 = BigGF<u128, 6, 768>;

impl Modulus<u128> for GF768 {
    const MODULUS: u128 = 0b10100000000000010001u128;
}

impl ClearHighBits for GF768 {
    #[inline(always)]
    fn clear_high_bits(self) -> Self {
        self
    }
}

impl ExtensionField for GF768 {
    const ZERO: Self = Self([0, 0, 0, 0, 0, 0]);
    const ONE: Self = Self([1, 0, 0, 0, 0, 0]);

    type Length = U96;

    type BaseField = GF256;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        let mut ret = GenericArray::default();
        (0..6).for_each(|idx| {
            ret[idx * 16..(idx + 1) * 16].copy_from_slice(&self.0[idx].to_le_bytes());
        });
        ret
    }
}

impl From<&[u8]> for GF768 {
    fn from(value: &[u8]) -> Self {
        Self(array::from_fn(|idx| {
            let mut array = [0u8; 16];
            array.copy_from_slice(&value[idx * 16..(idx + 1) * 16]);
            u128::from_le_bytes(array)
        }))
    }
}

impl Mul<GF256> for GF768 {
    type Output = Self;
    fn mul(mut self, rhs: GF256) -> Self::Output {
        let mut result = self.copy_apply_mask(rhs.to_mask_bit(0));
        for idx in 1..256 {
            let mask = self.to_mask();
            self = self.shift_left_1();
            self.0[0] ^= mask & Self::MODULUS;
            result += self.copy_apply_mask(rhs.to_mask_bit(idx));
        }
        result
    }
}

impl Mul<&GF256> for GF768 {
    type Output = Self;
    fn mul(mut self, rhs: &GF256) -> Self::Output {
        let mut result = self.copy_apply_mask(rhs.to_mask_bit(0));
        for idx in 1..256 {
            let mask = self.to_mask();
            self = self.shift_left_1();
            self.0[0] ^= mask & Self::MODULUS;
            result += self.copy_apply_mask(rhs.to_mask_bit(idx));
        }
        result
    }
}

#[cfg(test)]
impl Distribution<GF768> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GF768 {
        BigGF([
            rng.sample(self),
            rng.sample(self),
            rng.sample(self),
            rng.sample(self),
            rng.sample(self),
            rng.sample(self),
        ])
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::fmt::Debug;

    const RUNS: usize = 10;

    #[generic_tests::define]
    mod field_ops {
        use super::*;

        use std::iter::zip;

        use generic_array::typenum::Unsigned;
        use rand::{RngCore, SeedableRng, rngs::SmallRng};

        #[test]
        fn from_bit<F: BigGaloisField + Debug + Eq>() {
            assert_eq!(F::ONE, F::from_bit(1));
            assert_eq!(F::ZERO, F::from_bit(0));
            assert_eq!(F::ONE, F::from_bit(3));
            assert_eq!(F::ZERO, F::from_bit(2));
        }

        #[test]
        fn add<F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<F>,
        {
            let mut rng = SmallRng::from_entropy();

            for _ in 0..RUNS {
                let mut random_1: F = rng.r#gen();
                let random_2: F = rng.r#gen();
                let res = random_1 + random_2;

                let res_bytes = res.as_bytes();
                let random_1_bytes = random_1.as_bytes();
                let random_2_bytes = random_2.as_bytes();
                let expected = GenericArray::from_iter(
                    zip(random_1_bytes, random_2_bytes).map(|(a, b)| a ^ b),
                );
                assert_eq!(res_bytes, expected);
                assert_eq!(random_2 + random_1, res);

                let r_random_2 = &random_2;
                let ref_res = random_1 + r_random_2;
                assert_eq!(res, ref_res);

                random_1 += random_2;
                assert_eq!(random_1, res);
            }
        }

        #[test]
        fn mul_64<F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<F>,
        {
            let mut rng = SmallRng::from_entropy();

            for _ in 0..RUNS {
                let lhs: F = rng.r#gen();
                let mut rhs = GenericArray::<u8, F::Length>::default();
                rng.fill_bytes(&mut rhs[..8]);

                let rhs_f = F::from(&rhs);
                let rhs_64 = GF64::from(&rhs[..8]);

                assert_eq!(lhs * rhs_64, lhs * rhs_f);
            }
        }

        #[test]
        fn mul_bit<F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<F>,
        {
            let mut rng = SmallRng::from_entropy();

            for _ in 0..RUNS {
                let anything: F = rng.r#gen();
                #[allow(clippy::erasing_op)]
                let res = anything * 0u8;
                assert_eq!(res, F::ZERO);
                let res = anything * 1u8;
                assert_eq!(res, anything);

                let anything: F = rng.r#gen();
                let res = anything * F::ZERO;
                assert_eq!(res, F::ZERO);
                let res = anything * F::ONE;
                assert_eq!(res, anything);
            }
        }

        #[test]
        fn sum_poly<F: BigGaloisField + Debug + Eq>() {
            let all_zeroes = vec![F::ZERO; F::Length::USIZE * 8];
            assert_eq!(F::sum_poly(&all_zeroes), F::ZERO);

            let all_ones = vec![F::ONE; F::Length::USIZE * 8];
            assert_eq!(
                F::sum_poly(&all_ones),
                F::from(vec![0xff; F::Length::USIZE].as_slice())
            );
        }

        #[test]
        fn byte_combine_constants<F: BigGaloisField + Debug + Eq>() {
            assert_eq!(F::ZERO, F::byte_combine(&[F::ZERO; 8]));
            assert_eq!(
                F::BYTE_COMBINE_2,
                F::byte_combine(&[
                    F::ZERO,
                    F::ONE,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO
                ])
            );
            assert_eq!(
                F::BYTE_COMBINE_3,
                F::byte_combine(&[
                    F::ONE,
                    F::ONE,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO
                ])
            );

            assert_eq!(F::ZERO, F::byte_combine_bits(0));
        }

        #[test]
        fn byte_combine_slice<F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<F>,
        {
            let mut rng = SmallRng::from_entropy();

            let elements = array::from_fn(|_| rng.r#gen());
            assert_eq!(F::byte_combine(&elements), F::byte_combine_slice(&elements));
        }

        #[test]
        fn byte_conversions<F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<F>,
        {
            let mut rng = SmallRng::from_entropy();

            let element = rng.r#gen();
            let bytes = element.as_bytes();
            assert_eq!(element, F::from(&bytes));
            assert_eq!(element, F::from(bytes.as_slice()));
        }

        #[test]
        fn square<F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<F>,
        {
            let mut rng = SmallRng::from_entropy();

            let element = rng.r#gen();
            assert_eq!(element * element, element.square());
        }

        #[instantiate_tests(<GF128>)]
        mod gf128 {}

        #[instantiate_tests(<GF192>)]
        mod gf192 {}

        #[instantiate_tests(<GF256>)]
        mod gf256 {}
    }

    fn mul<F: BigGaloisField + Debug + Eq>(test_data: &[(&str, &str, &str)]) {
        for (lhs, rhs, expected) in test_data {
            let mut lhs = F::from(hex::decode(*lhs).unwrap().as_slice());
            let rhs = F::from(hex::decode(*rhs).unwrap().as_slice());
            let expected = F::from(hex::decode(*expected).unwrap().as_slice());
            assert_eq!(lhs * rhs, expected);
            assert_eq!(rhs * lhs, expected);
            lhs *= rhs;
            assert_eq!(lhs, expected);
        }
    }

    #[test]
    fn gf128_mul() {
        let database = [
            (
                "27ec1e89b0b5850162ffbb02a5ff1d26",
                "059feb9834e99d50dec63ed3ef4bfaa3",
                "150ac741911e13e9ea77141a1841dfe6",
            ),
            (
                "25eb38901e62e7fa75ecc365a5ef1033",
                "c428558a2d0fd83160c068527316c0f1",
                "acd7ed7097ccb7819a03678338e15a01",
            ),
            (
                "1d29dd6299a660502fd86cc95c5b418a",
                "679d3d12e03bd0e906993d0ecbfd8e90",
                "825275df2d791802e6d72a5600efbad6",
            ),
            (
                "ed68f7c9a621faf7beabf86bfb2ebc52",
                "77f498ddae22bc852e298f5d44dfc0b6",
                "f934a28e7d13fc89e40f0cb629ec9bbb",
            ),
            (
                "2750098402c56181576e74ba6d764764",
                "7c83159e9f3f60499300150879b5aa03",
                "2212f95b84ec8fddc46b1373d7badd33",
            ),
        ];
        mul::<GF128>(&database);
    }

    #[test]
    fn gf192_mul() {
        let database = [
            (
                "67669059b507187a2352e4056bd9612c5e5533a597cc9280",
                "7a65986fc4410b3950214bb622bef74ede5669de1f352600",
                "4204a19c90ddf5969197e140a3d28e926fa118bcd57b65df",
            ),
            (
                "a7500fd672632e78a148b6bcca55bf9ab851ebc6f98cd20c",
                "1f06b7fb7eaa4febfca3690aec9830104ba72cdd50ad4577",
                "bca1159014f0c0f10619bb32ea29a881219c7deeb829e11b",
            ),
            (
                "ec982502f5b5d0182525ed1384cee4db16d41fc99f1dc6e7",
                "c30f691b3800498049ae9fb7a0f0ebaea941409b4c206617",
                "bcf1bef999b7085d1cf6826e186a9de31b54eb0ba55bf268",
            ),
            (
                "97ff3a808ed72737fd55f6c19fcb376cccaf5b88d2bb201b",
                "fb46dfca7e6b2051dfaa0b0ef71cc59359276a82a467dd9f",
                "d02dd8595fd39d11f49f39de8f533b209c3e354000124890",
            ),
            (
                "cb448f65f634d5c69de8201f38202a62bc327f856df86eb7",
                "02b4176343f425bbba8e270c297081c06185de8260fd3648",
                "db68a51a539649fb5b183841d8effb21a35df7f15e2a74f0",
            ),
        ];
        mul::<GF192>(&database);
    }

    #[test]
    fn gf256_mul() {
        let database = [
            (
                "8a2a2fd1a69dd46353f9badc5b90aeb8c28c36c9d9b17efe844d3bc1fa49e36a",
                "7f13975ef2e4877731e671d8214041988e082ef1a0757917173a3a6079aff741",
                "79502482a1d215cd731ab67453148708de5c8a567d75fbd497b35ff77d65848f",
            ),
            (
                "c21ce5e3f6ca570603159c10736372a00642d8ef975d00820a225371ef487af0",
                "9b495ebc5f0189cde768f1776227e1c775ce93ee3e7c629de1b18827eeb7c67f",
                "4c4e76d784273d1ca5ce4d601d1f1c7c81f21e9c9fc7a348fa4374ba99193d51",
            ),
            (
                "dadf8c4cc33bde49690c2751d9ac39c566a925012dfac190e57f25cdcd377d81",
                "aa96ea13a62685394c3dce8c19bcb8f03e046523dc47f6dfab8131135dcc8796",
                "733a43e5587bb3c0f36a80d896dc1f4ad6806b4200f71fa6d93a7cbebc156ab3",
            ),
            (
                "aba9b03603ac8741bea87e7fbbd62579e126e34adbc85052deb9fca265a99280",
                "045d0bb80935bafbe1d6d43d9b530100f50d19f387e962a8b54feb5e6d255988",
                "5e58597debdca0923c5d9e370cdf2e531effd8f9f069aaccba84efa91f516a4a",
            ),
            (
                "7d3e3e134f80d8884334ac93c449155df5c326da691163f210158d0b7eb50f89",
                "99005059eaa1418c4bd68edc851667ec05b3b1d1a10f2c233240c899c7d3b0ec",
                "387f086fca73b66e39c0ee94bf5a394d1e9b4e0cfbc53ece53f7fbf175fa208f",
            ),
        ];
        mul::<GF256>(&database);
    }

    #[test]
    fn gf384_mul() {
        let database = [
            (
                "8bc36869535dc1e4459f471841d8e4720b5959e5d16da9a97ecce7309c764e66ce2ff02ee646bc6f27aa93d953fd1b48",
                "8bb881cb82ab7d5d36a475f559cbb58e22f6093694528c60e711f114abf53332ee96cf332b84871b00a5ffdc3795a965",
                "a08b1c65be1e5af36df08e961936a5b395f3127bb85a6c779b6be97202840d106d9673e8cae45b82c5d074c31eb57ab8",
            ),
            (
                "5f4d57279dd4a67f99f7f6558d0a3ec920a3511311e6bb49a4eb0492db61af332c004bcd73a459f0a8af5a6cdee992ae",
                "618dd5723aad16339ec6d007d93fc03611d95dd7a7d22020ddbc1952ee3a862c8a115179a7ef9d2f8ad25260134049ef",
                "5f8afefcd24460c805595374874ffde89f5f7e525a8ac94e082ab96766bbf7f2c7828f2c4b37b5a86d0e8d6e4f0e7a61",
            ),
            (
                "14e07338a12964adce31eeced329f5d60ded45bf7a26905bc6835b7c610cde174af2d7b9d01c4e2cf89609c19d0625fc",
                "b02287838374385690f33df07838f3952f8828cd2669dc3274bfbcb36089968c3195b7af1233a6898054b3cea1a31066",
                "da504788dc6fcb8ab47e38fbaf7978a6f216261d8345e3a9b627623dbe2c7c8df6b200f10ea5554b3317fd227ecf83ed",
            ),
            (
                "2e2f2432f9f7a852e815cbb84109a5b76efb39e111c9a312e33e6f80926fc07299681632a7ebdd23b0a10c6adbadf274",
                "fbba3a11375b4def60471e5bb63004ab584b5e5b1c1646759abb8b5cd33cc75264ec3fb3c13d4f22f73a2c5c29a5013b",
                "4820f64859d97ab6a4543d37b50c83eedf694920e8ffb5281546e4efec7cfe832423faa58dd7e2202231399aa7e1b0e8",
            ),
            (
                "708ecc2abc3db4581331221bd9fb6c5e20aa741c7d37e685d31041a3281f7d110dbc8dd1376f454c2b27693b1ac82e95",
                "87217ba77eec051f5f7cba31acdfc7dfc136722752dcdd543836fea47ae566708c10602238e9747ef0faba824ca7a88d",
                "f9312081b0773d5457b1a6359e3643473af6d9ee9dcd91655a4b58c04edfe79b4562eab928628c9a4037f94b254a52da",
            ),
        ];

        for (x, y, z) in database {
            let x = GF384::from(hex::decode(x).unwrap().as_slice());
            let y = GF384::from(hex::decode(y).unwrap().as_slice());
            let z = GF384::from(hex::decode(z).unwrap().as_slice());

            assert_eq!(x * y, z);
            assert_eq!(y * x, z);
        }
    }

    #[test]
    fn gf576_mul() {
        let database = [
            (
                "54a6c2c69b06b8b0694b794571683eeb5413c8b465da06bcdfc37e4807d1072722abefddb8d58c5140c9c7c77717c106baa3f4ae81903a40035d682bbe15504339c941fbb4fdbdb8",
                "a805b0090170d28ff11062b44e2c13ba6d07f5cd264c1bcd37b80b0f5facb2dd387619550167b75b81d2659b56d29b7a852c14d2cb0a3b64700cf74d4b1e7a9dfc8e57cfcb07db23",
                "45d69adbeab2cf4bc0da73f932b250f06097dddb71e2cc7a31db5efb502e0fe18496f1706c4bb7fec3603de9fc03b57817c0cfb7b908c6a223448cabf22f365c4dedbf45439d0cf6",
            ),
            (
                "103e10d7da92c942d286243373736c63473420980ef675a73975eb73b8f27a351b9eb1df691d8c34c4483414cda159a3a6f278fdac20528f16d4f1e5e4671a06733029f3d99ab1cc",
                "eb37d5c76143733e78221b0516537daba5819f8322ec6c10e22fbf129448850635c871d838cb102467b96a9e5a84efbbba99106ab96bc9f1771c9478246dff9e3ac3070facc152ec",
                "935704b1c84251002d136197d2acd29995c46c82f67c3a012dcf86deba1d3f227c24a65fc211bbee796572b0a05a97f9cd0f970218f1e5f82359ffc6adbf4b5f2b1f345e50fdab4e",
            ),
            (
                "b7104ed362a60f0378de88e68f0eaa4fc64643373aef5eff9f91cc02bcd9a6023181d79136d00540ac33c9f50068d59c9a39b2925d1ec4808b398d45ac6cd23a8ae91e0179e3ffd6",
                "9896cf92ff31c5bf96b495d54a42017353060cacadfe4c7606a87ed8b68ff0a2307a1b5278bfc303f67b874eb698ace6ef2953c1499504663b90e73fcfd25131761c30a4b3733f1e",
                "7941079d84692d18834e6639af77ac1d1ab207182e9c19360ed6ad134ce3e706a701849d3aaed9abdc3eb0dba4e2598b19230aab42bee2bee2fa80b7bcaacad9cfd861db4945f9aa",
            ),
            (
                "35000d536a13d9b3a7e89c4b0ded4d1ded48cff5312906abac051ffc627fbc98d4a681f051a643d290b0dfc3939ba372fd02f039bff23a798b48f107aaa3ab73da05856937b5c486",
                "948f26373610d74ac2260cbbeda6514621db803d2b0ce01d65b312eb84e20dd7b4c5bc6fd581cf2ebbbb903663b588ba92c0c3c73512a7078a2145f3d2a75293a747d2c870bcb17b",
                "1ad4663ba7260c79de00c10dc8cc97853987461e8acbad07cc8a69d2bdc804fa3dff2c38de2ba545acd6ee3b218a05c774f294f85b180966e913dabff521f85169ed37a29bd4a7a0",
            ),
            (
                "9374272e5613048b2e59da5a4a20e44f8b94b3754cfe31d63a6d482d5fe910b1c82663592935fba5837c39ed5928cabee7cbbeb37f9520cd4d6acabd41fc146062572b825d9e1ba5",
                "b3f0b8f10b242f41b7e2abbbc13ea7e6f85f5dd682e91e089d1a8b6963706db320b8b67948594d79d9e69ee8fd3583d3576aa6cf3eed0ce27218a24f0d3b97139607fa01f9025979",
                "66a6134efdce64b4ea3a2e957bacf2967adbf944ff9240d42c2afdbb169f4931eafc39167a6b7084844136f614a349f1419c634e10e31679262e0183698d35a1ecf3878b43a89bc8",
            ),
        ];
        for (x, y, z) in database {
            let x = GF576::from(hex::decode(x).unwrap().as_slice());
            let y = GF576::from(hex::decode(y).unwrap().as_slice());
            let z = GF576::from(hex::decode(z).unwrap().as_slice());

            assert_eq!(x * y, z);
            assert_eq!(y * x, z);
        }
    }

    #[test]
    fn gf768_mul() {
        let database = [
            (
                "07391d1e06f0174a7619bf8d8b1d6a21f00b8b8b42d24f491d2eb24e84bc73e3dc6f8930ff98ac2fb5f3a835115f3bdbaf85a79c5b15493af6b7221689394ccf22e5574ff9e475eb5b96544160a9f9e088ea8e1d813c92e39034de49ea9a93ec",
                "fb2dc09ec0b20da0d9d3fd0e38ea443bae0ee401b91aeb5ba13a91dca0161bc0606f1202c73470a1dafad38ac283368cbb2d667033f78b29c12ad80ab6003fcdf32233365868ca513a1d0717200b41a99211b0ee15ab451fd4d68237a7a150df",
                "97bd25456a588ff10153b95e41c088652e9a40eed80a41aa5756c9fcb361c3fbbc4a8ffc0b066b0fadd126e146e6201bd4b2d61bf0ac4a758ae66aa79a8dfc62fe5440d3c7292e789d6c758e8a3df9aa0abbd068f4ed79400ef37169dac33138",
            ),
            (
                "1efc5c4ccb67d817e7b966bf9486d24379c38eb96481e7089a455056ae94b7d39613cbf0b73812073cb18431947e5afdbab5e1d341f5d93f79ffe6e2ddf0751de8632eb36ae15e005a9c75155b5b809bebb0a6eef74fe265c45f2cdb1366748e",
                "f4808c409dd8975a724ba0fe9bc50d7d407d051394c3eec774758a12ae42d1b33fcaaf8c8d6fd2e5e192ddf3a163cb4b8c270ead0488ec0cac0c3eaf03915a3971bfd09586cbd407eff09702d555835e7b06f93afbdf9d3701f63537c2372259",
                "3f3572cb1035da03f2f34ec643ee3346469bc7c3cb8a010948b782ba3ea03cd7149a845059ad8873e5216f0a6963b59721bd7e614e764f6b60916723ecb6d2d1ef52bfdb765fd4899382cd7752f00531ffbb8eed00a4cec957750ec3bb43ca18",
            ),
            (
                "262ea85c390665c150543ddbe931dbeab03ab03c28a08410ee811a5f22da85ab7b70847882deec8f1446384e89277aa533e38b16dcd8a772023c51ff595e81c85e9e50503c9a2bf83e365afe98d919eda7aa5092c5ab9ab938e40c2a348a6906",
                "ab5d5bbbd2e8591db331953ead12f638af331083fb3bc40c18e634c7cb82d290e8aa65f9e96d8e67ef197d96b01bcae3568c55637ed81b76eece7782d113271546c035c8b368e856d9d9ec039beb764a2f0bef687b1a8b2b79e49bebd9c1df82",
                "d1a69edb339c5b6ef70366841d1946149a3b7df826d39ea602b45d8d130bd03a0af7bc4aeb60d5606c2d8bafa8b866db034a88812dd7d0670115653333ecd6c90419b1133610c2c899afc2cb98e2b10d45919790464b684840145002d0042c0f",
            ),
            (
                "eb7b42ef2203e1c158bed2a6ab09d8f065f85eb4036d1073afc98fcbff6dd2d8ed82a920a9e2d8c7ee715c26c1cccda3edd4e675d933a3e3308a193151f5c5c09a601442c8d2eff2041ff11066d4f486589b3df321fc26aa3e14a182611e8091",
                "57ece743145f1401fd11a813bde08e83f7c2b0dc799f7070e02a26c64f1eb9f6990174a1b0b0f095468f96e154d1dc912e26af8c0100459c461604bfa133deea56a21ee767c271ead9500266c2dff09b3030bbfaf047667ad3504941e6ff286a",
                "076f2f051d18c008ccf5c6ddc4fc4e7497961bb95e6f5e46e3e103638c9e62747b3795cb10de8194dd15e3ce768906e4d59638a678d81eddc1473ae6f390fc72e78276736ce68bf52a95524b329680891139bde172b12085496192d5b53e0a47",
            ),
            (
                "aded86c99c004d9bd850252b716d6b8b62a6fb8786f4d2b7ee43914158a2fe7d7c60879736dc1ad4e5d6b2d39de01d18358e8cf1e229bda961df49ef4221a9b2ef79918d5decc26dcc462c9f32928ef30655871c8637cc4f54550e55fae6108a",
                "a1540b67567bbd621022be49b04f1f43034c71d0195f905575141c0e1d902be92db81123ee6478b4c5056e0d14f29d396fef2597fa687ded94eb1f8758b73e117460b2f0d93e58ca0b2ee6ccd453852fc47c7ab5d4bbbaff27324ec4404af06b",
                "3faf6d2f7d3c15697143c95ff67dd534a666b9dbae767890c71d848f39f03e4e0269abfece50ce736095b09942eb8cb8a861d8b472d43f51b7461737e23bc3b5416f447b72af35bc35b7a5200284a563e5ccf58840e3c69776b9c2bab425ba12",
            ),
        ];

        for (x, y, z) in database {
            let x = GF768::from(hex::decode(x).unwrap().as_slice());
            let y = GF768::from(hex::decode(y).unwrap().as_slice());
            let z = GF768::from(hex::decode(z).unwrap().as_slice());

            assert_eq!(x * y, z);
            assert_eq!(y * x, z);
            assert_eq!((y * x).as_bytes(), z.as_bytes());
        }
    }
    fn byte_combine_bits<F: BigGaloisField + Debug + Eq>(test_data: &[(u8, &str)]) {
        for (x, data) in test_data {
            let result = F::from(hex::decode(*data).unwrap().as_slice());
            assert_eq!(F::byte_combine_bits(*x), result);
        }
    }

    #[test]
    fn gf128_byte_combine_bits() {
        let database = [
            (0xc1, "9f0617c47b7c51bd9590bb237294d1df"),
            (0xa3, "04b54dcf1f2f6efe59cba8fcaea4f558"),
            (0xc0, "9e0617c47b7c51bd9590bb237294d1df"),
        ];
        byte_combine_bits::<GF128>(&database);
    }

    #[test]
    fn gf192_byte_combine_bits() {
        let database = [
            (0xbf, "001416b404cbf712ac8abf1b7c18fb0d04051236e0e14eb3"),
            (0x26, "20ec0299a9ce2ea6483cd324c2448595139d5c9158ebe53d"),
            (0x52, "8481c63cdf4be7868c4fe1c96962da6f70cebbf3d724415d"),
        ];
        byte_combine_bits::<GF192>(&database);
    }

    #[test]
    fn gf256_test_byte_combine_bits() {
        let database = [
            (
                0x9b,
                "a546773740880fa7cbcdf4cc6192b78e00f8b8e9e69cd6213e5dc5cdcbeea020",
            ),
            (
                0x7e,
                "5370a9666291a1b2d78e0ee3282f0c4050eb80fe50964600780a5823e975cad7",
            ),
            (
                0x62,
                "5aa9103cd2d22090596547862a30ff0995572177eeb49d003c3e64808d94d3e6",
            ),
        ];
        byte_combine_bits::<GF256>(&database);
    }

    fn byte_combine<F: BigGaloisField + Debug + Eq>(
        test_data: &[(&str, &str, &str, &str, &str, &str, &str, &str, &str)],
    ) {
        for data in test_data {
            let tab = [
                F::from(hex::decode(data.0).unwrap().as_slice()),
                F::from(hex::decode(data.1).unwrap().as_slice()),
                F::from(hex::decode(data.2).unwrap().as_slice()),
                F::from(hex::decode(data.3).unwrap().as_slice()),
                F::from(hex::decode(data.4).unwrap().as_slice()),
                F::from(hex::decode(data.5).unwrap().as_slice()),
                F::from(hex::decode(data.6).unwrap().as_slice()),
                F::from(hex::decode(data.7).unwrap().as_slice()),
            ];
            let result = F::from(hex::decode(data.8).unwrap().as_slice());
            assert_eq!(F::byte_combine(&tab), result);
        }
    }

    #[test]
    fn gf128_byte_combine() {
        let database = [
            (
                "aa6a6f1713d27a71fe989e93dc79d27d",
                "714f4c855dc34eafbaa6d0c9a6cb67ef",
                "594cbc985a239f97859c0f5dbc9c65ee",
                "bd3a871fc93c17e3781cb120b89a5bc4",
                "edff635fd5c3a8e210534b6a29da7c4a",
                "d16d14e0cae7da06be1134a171555bb4",
                "56be29a614665b84abb8808565ca3059",
                "8d143b6e793799fde7617b4a734f4973",
                "334dbbe5004d3dbbe3ac3a2e86ddb72a",
            ),
            (
                "a4108259c36d3300a3452de6cc6819ac",
                "f74513a1922de3721a29e974d16a6d52",
                "1a313de17135292c281f35f36d642221",
                "66322955d8a653ed6397826ca1ef2d6c",
                "d3a414c6a1e83bdd37696aa0ecb9482e",
                "3f5c0f270b04733c065b8c2cb0ca8212",
                "0e96f9872bbc1a87ddeb27c7f189b826",
                "fb1b26d476b3f87607f4a9742a1a26e3",
                "4d38054fc9df94561220860e9ebf72a2",
            ),
            (
                "263e276e9d619c4fe6b9b40d1f5ae81b",
                "78ffd6d19573db9fa408e8cb29f82e27",
                "96e08f0df9f18a1d67d5ec2214923217",
                "a98663ac8a0578bed72c80910767ce11",
                "f17959de6a99bbdc75b204636f1dd25f",
                "270d3294a2a45d1dcc86c5fe76b41e56",
                "b3aa6455426c8f62c47bd85c3a96afa1",
                "7f456dad4831aa46f018ed4dd3a4d8cd",
                "7f088260d013e0b497e0bf44dea3b5bc",
            ),
        ];
        byte_combine::<GF128>(&database);
    }

    #[test]
    fn gf192_byte_combine() {
        let database = [
            (
                "97435430defb19efaf7e3a6e9fc365b419633d4221d07ea7",
                "6d4949bf79ddbbbd17c1a4761f2169e44bbcc6d998468635",
                "8a13ceeabe8aee808b1d39eba3da8313fa6080cff2f4df8c",
                "9b46eb3c67d416b5b466aeb667ccb8860b7bfb4a3f7bf875",
                "3b9a144eda2392d8c3ae8d871741e0b914b3036ca3f99e19",
                "d9ffc96ad4cb269ab3fdfc617afecd260fe5bef4d778ecc5",
                "c524bad21ff3c079745cf027bbf461cd823e8ec20b86838d",
                "104261f32b5213d7ad09c34d5042bfbec74d051430914b76",
                "3c3aeab72cb94f341f526028551479e4335a9e7e29c769ab",
            ),
            (
                "e90ba7d98495ec8f34ffc33cd4fec49900e86d7f5ded63d5",
                "a458f5c02b6cbf5884b1fc51568a4b6cace0914b113da05b",
                "80016f8597da72e83ab2af373bd406858f18293f7bf19fca",
                "d0b48d33172d01284a38c147688380f4a982de10b0129087",
                "d0675051d384f4a9bbadccefb788f56f3c49994f12cb4104",
                "f9af9b3008af0ebc2435b48424546aabcdd4fcd26028c015",
                "146ce9152843cc89b66f956b20f5c5ad4967b891f7797c84",
                "027f4a31fcf61149b791fe06744cd9c4a96990d393dbc729",
                "9247127d401126a9e217b3a3a6e9e02fa3094d1dc280777c",
            ),
            (
                "4f30c4b472dc4eaff3b409206897a65db6f0ac03dbb8e4a1",
                "85ee56ffce3aa7d81035717812eb918467823c44c27665e5",
                "96643a20b33012458f6bf54dd07b5e424a90213452f65471",
                "76c4019c31e2469471c507c5f73061107d31e01b8213a732",
                "d3e8adef5c7b5b33e06e868c6f38ce54175e481d598455df",
                "69a1d0189000168f3a8ba459525968def7989a837f56c9e7",
                "5b0843fe01ad4b62298fd67f12a606a43871626d2fa9866c",
                "5b02e930dc80f9bdc6f7fda2210bc46e7180f67a4f56e2a5",
                "8c5fc7d9e4aae7a23b4a60cfa972f1570383fac4850080ef",
            ),
        ];
        byte_combine::<GF192>(&database);
    }

    #[test]
    fn gf256_byte_combine() {
        let database = [
            (
                "c2f6c29d90d5f0aceafd8751f1880efc9ab70c2b8a2ae54976ac9e0efbc88cd6",
                "7d798407e8db5017aae4cbe8f249342f0c524ce4442b0af0cb903f64c8185778",
                "95315e58d485508458286b521c541fcdbb106f389275987da6e8936065954d3c",
                "a9456a8285167815b7577b06080cd879eedc7369fc29bef61fae73e322198451",
                "9ea4717819ecd1ead760f10ef380e965af2c06604c300216b14164fe85b380d9",
                "e4a60ad034cbfe80dcfbffd4b895f6d144ad5f191926ff483815ba551e6580c4",
                "71198fcb06a47c624ec560dc1235f2e0eec7f634e9680e6ffa22a3a41f57c263",
                "1586cb264022ce18b6793cfe01bed1187693b9537bd4e940c5b46b019dfd4971",
                "c56b311c313ee2d49000d298bc532e663c8170974ba202289662c032237a005c",
            ),
            (
                "4fb3716fa0d84561336cefb4840a371878e4cec3832744554694739703ab7a29",
                "0f429ca77f674b13c1bc7b9f87ba635e7939f9756b83c6c7f4db0e7f722c785f",
                "7aec71702cf0a8b08005f568daafccc3a95a3a3b121f1f966552b1a9fd9fe068",
                "1efb0c9b9464a89b5898f3b466d895b910b1fb4773cd56c01939ff10da7c8f97",
                "81b656b24ce53ba62391d51cd2a230672a3bc4a8a6dbe6b9871ba932bbf1fd82",
                "754a57aa984ff4cdf1c6f851ed66d98d3d2a62736c2af0e332f5885ae8cf8afa",
                "c9989982817be71fd981fe62c604e575eedda4cb98252a04f4e9a2d354d1b0cc",
                "b875a162992e5b51cd5b05a17c69a274054a92aedcc56f8d187afb0008302f46",
                "e732850e177e5f2dd3e8765ccd91a25438c3c6b841e0ab2e3da0dc648d9faca9",
            ),
            (
                "45f19ae41aed2508f08fe519f53c68ea4425e83f1f44c25a1e4d67c010ca2ca4",
                "4b2c6726f26fb5b8a37e3c697b9604e19960864152e74e0d8003ff07936ab1fc",
                "dfc86e485b1c0d4aa7236d7e2fcfbbb17969124934f5b295d85b6758cdcda4ba",
                "4ca4a35ae61fb0adacdd1775f6efb0236d08e76d6f2a10c44d039ff016eaa884",
                "38bd431d0381f6d842ca1b9465fe9fae3b692d3b88dfc517352988cf57d0bf1d",
                "ca414b24ae668f4dcaa3b0fefff191437b4f968d984a79fd0dd2b5bcdb663a48",
                "bc18c65f0a7902731ec09bb67b55a09cae445c5d5fd7167d1991ab98bf6830ae",
                "a10852ecf84c45ef352dd1af830c8bc64b70d16f6a92a0a7e2b781f3b683d004",
                "2f7d52efccba230fe92554d1c30bb9fbaaa4672f474b8c56141bdc6a80115d44",
            ),
        ];
        byte_combine::<GF256>(&database);
    }
}
