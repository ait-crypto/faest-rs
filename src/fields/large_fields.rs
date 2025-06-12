use std::{
    array,
    fmt::Debug,
    iter::zip,
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

/// U128_LOWER_MASK = 0xFFFFFFFFFFFFFFFF
const U128_LOWER_MASK: u128 = u64::MAX as u128;

/// Takes two 128-bit integers `x = x_l + 2^64 * x_h` and `y = y_l + 2^64 y_h`.
///
/// Returns `y_h + 2^64 x_l`.
#[inline]
const fn allignr_8bytes(x: u128, y: u128) -> u128 {
    x << 64 ^ y >> 64
}

#[inline]
const fn combine_poly128s_5(x: [u128; 5]) -> [u128; 3] {
    [
        x[0] ^ x[1] << 64,
        x[1] >> 64 ^ x[2] ^ x[3] << 64,
        x[3] >> 64 ^ x[4],
    ]
}

#[inline]
const fn combine_poly128s_7(x: [u128; 7]) -> [u128; 4] {
    [
        x[0] ^ x[1] << 64,
        x[2] ^ allignr_8bytes(x[3], x[1]),
        x[4] ^ allignr_8bytes(x[5], x[3]),
        x[5] >> 64 ^ x[6],
    ]
}

/// Perform a carry-less multiplication of two 64-bit polynomials over the finite field GF(2).
///
/// This function takes the lower halves of both lhs and rhs.
#[inline]
fn u128_clmul_ll(lhs: u128, rhs: u128) -> u128 {
    // Select lower 64 bits from lhs and rhs
    let (lhs, rhs) = (lhs & U128_LOWER_MASK, rhs & U128_LOWER_MASK);

    u128_clmul_64(lhs, rhs)
}

/// Perform a carry-less multiplication of two 64-bit polynomials over the finite field GF(2).
///
/// This function takes the upper halves of both lhs and rhs.
#[inline]
fn u128_clmul_hh(lhs: u128, rhs: u128) -> u128 {
    // Select upper 64 bits from lhs and rhs
    let (lhs, rhs) = (lhs >> 64, rhs >> 64);

    u128_clmul_64(lhs, rhs)
}

/// Perform a carry-less multiplication of two 64-bit polynomials over the finite field GF(2).
///
/// This function takes the upper half of lhs and the lower half of rhs.
#[inline]
fn u128_clmul_lh(lhs: u128, rhs: u128) -> u128 {
    // Select lower 64 bits from lhs and rhs
    let (lhs, rhs) = (lhs & U128_LOWER_MASK, rhs >> 64);

    u128_clmul_64(lhs, rhs)
}

#[inline]
fn u128_clmul_64(mut lhs: u128, mut rhs: u128) -> u128 {
    let mut res = lhs & (-Wrapping(rhs & 1)).0;
    for _ in 1..64 {
        lhs <<= 1;
        rhs >>= 1;
        res ^= lhs & (-Wrapping(rhs & 1)).0;
    }
    res
}

/// Splits `lhs` and `rhs` into four 64-bit polynomials over GF(2) and uses [`u128_clmul_64`] to perform karatsuba multiplication.
///
/// Returns the resulting 256-bit polynomial `res` in uncombined form (i.e., `lhs * rhs = res[0] + 2^64 * res[1] + 2^128 * res[2]`).
#[inline]
fn karatsuba_mul_128_uncombined(lhs: u128, rhs: u128) -> [u128; 3] {
    let lo = u128_clmul_ll(lhs, rhs);
    let hi = u128_clmul_hh(lhs, rhs);

    let lhs_sum = (lhs >> 64) ^ lhs & U128_LOWER_MASK;
    let rhs_sum = (rhs >> 64) ^ rhs & U128_LOWER_MASK;
    let mid = u128_clmul_ll(lhs_sum, rhs_sum) ^ lo ^ hi;

    [lo, mid, hi]
}

/// Splits `lhs` and `rhs` into four 64-bit polynomials over GF(2) and uses [`u128_clmul_64`] to perform karatsuba multiplication.
///
/// Returns the resulting 256-bit polynomial `res` (i.e., `lhs * rhs = res[0] + 2^128 * res[1]`).
#[inline]
fn karatsuba_mul_128(lhs: u128, rhs: u128) -> [u128; 2] {
    let lo = u128_clmul_ll(lhs, rhs);
    let hi = u128_clmul_hh(lhs, rhs);

    let lhs_sum = (lhs >> 64) ^ lhs & U128_LOWER_MASK;
    let rhs_sum = (rhs >> 64) ^ rhs & U128_LOWER_MASK;
    let mid = u128_clmul_ll(lhs_sum, rhs_sum) ^ lo ^ hi;

    [lo ^ mid << 64, hi ^ mid >> 64]
}

#[inline]
fn karatsuba_mul_128_uninterpolated_other_sum(
    x: u128,
    y: u128,
    x_for_sum: u128,
    y_for_sum: u128,
) -> [u128; 3] {
    let x0y0 = u128_clmul_ll(x, y);
    let x1y1 = u128_clmul_hh(x, y);
    let x1_cat_y0 = allignr_8bytes(y_for_sum, x_for_sum);
    let xsum = x_for_sum ^ x1_cat_y0; // Reult in low 64 bits
    let ysum = y_for_sum ^ x1_cat_y0; // Reult in high 64 bits
    let xsum_ysum = u128_clmul_lh(xsum, ysum);

    [x0y0, xsum_ysum, x1y1]
}

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
pub trait ByteCombineSquared: Field {
    /*
    /// "Square and Combine" field elements.
    ///
    /// Each input field element is associated to a bit. The function computes bitwise squaring of the input and combines the result.
    fn byte_combine_sq(x: &[Self; 8]) -> Self;
    */

    /// "Square and Combine" field elements
    ///
    /// This is the same as [`Self::byte_combine_sq`] but takes a slice instead. It
    /// panics if the slice has less than `8` elements.
    fn byte_combine_sq_slice(x: &[Self]) -> Self;

    /// "Square and Combine" bits
    ///
    /// This is equivalient to calling the other functions with each bit
    /// expressed a `0` or `1` field elements.`
    fn byte_combine_bits_sq(x: u8) -> Self;
}

// blanket implementation of byte combine squared

impl<F> ByteCombineSquared for F
where
    F: Field + SquareBytes + ByteCombine,
{
    fn byte_combine_sq_slice(x: &[Self]) -> Self {
        Self::byte_combine(&Self::square_byte(x))
    }

    fn byte_combine_bits_sq(x: u8) -> Self {
        Self::byte_combine_bits(GF8::square_bits(x))
    }
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
    Self: Alphas
        + Field
        + Copy
        + Debug
        + ApplyMask<T, Output = Self>
        + for<'a> Mul<&'a Self, Output = Self>,
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

// generic implementations of Add and AddAssign

impl<T, const N: usize, const LENGTH: usize> Add for BigGF<T, N, LENGTH>
where
    T: BitXor<Output = T> + Copy,
{
    type Output = Self;

    #[inline]
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

/// generic (unoptimized) implementation of GF multiplication
fn gf_mul<T, const N_L: usize, const N_R: usize, const LENGTH_L: usize, const LENGTH_R: usize>(
    mut lhs: BigGF<T, N_L, LENGTH_L>,
    rhs: &BigGF<T, N_R, LENGTH_R>,
) -> BigGF<T, N_L, LENGTH_L>
where
    T: BitAnd<Output = T>,
    T: BitXorAssign,
    BigGF<T, N_L, LENGTH_L>: Modulus<T>,
    BigGF<T, N_L, LENGTH_L>: ToMask<T>,
    BigGF<T, N_L, LENGTH_L>: ApplyMask<T, Output = BigGF<T, N_L, LENGTH_L>>,
    BigGF<T, N_L, LENGTH_L>: AddAssign,
    BigGF<T, N_L, LENGTH_L>: ShiftLeft1<Output = BigGF<T, N_L, LENGTH_L>>,
    BigGF<T, N_R, LENGTH_R>: ToMask<T>,
{
    let mut result = lhs.copy_apply_mask(rhs.to_mask_bit(0));
    for idx in 1..LENGTH_R {
        let mask = lhs.to_mask();
        lhs = lhs.shift_left_1();
        lhs.0[0] ^= mask & BigGF::<T, N_L, LENGTH_L>::MODULUS;

        result += lhs.copy_apply_mask(rhs.to_mask_bit(idx));
    }
    result
}

// generic implementation of Neg

impl<T, const N: usize, const LENGTH: usize> Neg for BigGF<T, N, LENGTH> {
    type Output = Self;

    #[inline]
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

impl<T, const N: usize, const LENGTH: usize> Mul<Self> for BigGF<T, N, LENGTH>
where
    Self: Modulus<T>,
    Self: ToMask<T>,
    Self: ApplyMask<T, Output = Self>,
    Self: AddAssign,
    Self: ShiftLeft1<Output = Self>,
    Self: ExtensionField,
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
    #[inline]
    fn clear_high_bits(self) -> Self {
        self
    }
}

/// Multiplies two 128-bit polynomials 'x', 'y' over the finite field GF(2). Stores the result in 'x'.
fn gf128_mul(x: &mut u128, y: u128) {
    // Carry-less multiplication of lhs by rhs
    let [lo, hi] = karatsuba_mul_128(*x, y);

    // Reduction modulo x^128 + x^7 + x^2 + x + 1 as by page 16/17
    // of <https://cdrdv2-public.intel.com/836172/clmul-wp-rev-2-02-2014-04-20.pdf>

    // Step 1
    let x2 = hi & U128_LOWER_MASK;
    let x3 = hi >> 64;

    let a = x3 >> 63;
    let b = x3 >> 62;
    let c = x3 >> 57;

    // Step 2
    let x3_d = (x3 << 64) ^ x2 ^ a ^ b ^ c;

    // Step 3
    let e1_e0 = x3_d << 1;
    let f1_f0 = x3_d << 2;
    let g1_g0 = x3_d << 7;

    // Step 4
    let h1_h0 = x3_d ^ e1_e0 ^ f1_f0 ^ g1_g0;

    *x = lo ^ h1_h0
}

impl Mul for GF128 {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl Mul<&Self> for GF128 {
    type Output = Self;

    fn mul(mut self, rhs: &Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl MulAssign for GF128 {
    fn mul_assign(&mut self, rhs: Self) {
        *self *= &rhs;
    }
}

impl MulAssign<&Self> for GF128 {
    fn mul_assign(&mut self, rhs: &Self) {
        gf128_mul(&mut self.0[0], rhs.0[0])
    }
}

impl Field for BigGF<u128, 1, 128> {
    const ZERO: Self = Self([0]);
    const ONE: Self = Self([1]);

    type Length = U16;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        GenericArray::from(self.0[0].to_le_bytes())
    }
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
    #[inline]
    fn clear_high_bits(mut self) -> Self {
        self.0[1] &= u64::MAX as u128;
        self
    }
}

/// Type representing binary Galois field of size `2^192`
pub type GF192 = BigGF<u128, 2, 192>;

/// Multiplies two 192-bit polynomials 'x', 'y' over the finite field GF(2). Stores the result in 'x'.
fn gf192_mul(x: &mut [u128; 2], y: &[u128; 2]) {
    // Carry-less multiplication of x times y
    let xlow_ylow = u128_clmul_ll(x[0], y[0]);
    let xhigh_yhigh = u128_clmul_ll(x[1], y[1]);

    let x1_cat_y0_plus_y2 = allignr_8bytes(y[0] ^ y[1], x[0]);
    let xsum = x[0] ^ x[1] ^ x1_cat_y0_plus_y2; // Result in low.
    let ysum = y[0] ^ x1_cat_y0_plus_y2; // Result in high.
    let xsum_ysum = u128_clmul_lh(xsum, ysum);

    let xa = x[0] ^ (x[1] ^ (x[1] & U128_LOWER_MASK) << 64);
    let ya = y[0] ^ (y[1] ^ (y[1] & U128_LOWER_MASK) << 64);

    let karatsuba_out = karatsuba_mul_128_uninterpolated_other_sum(xa, ya, x[0], y[0]);
    let xya0 = karatsuba_out[0] ^ karatsuba_out[2];
    let xya1 = karatsuba_out[0] ^ karatsuba_out[1];

    let xya0_plus_xsum_ysum = xya0 ^ xsum_ysum;
    let combined = combine_poly128s_5([
        xlow_ylow,
        xya0_plus_xsum_ysum ^ xhigh_yhigh,
        xya0_plus_xsum_ysum ^ xya1,
        xlow_ylow ^ xsum_ysum ^ xya1,
        xhigh_yhigh,
    ]);

    // Reduction modulo x^192 + x^7 + x^2 + x^1 + 1 adapted from page 16/17
    // of <https://cdrdv2-public.intel.com/836172/clmul-wp-rev-2-02-2014-04-20.pdf>

    // Step 1
    let x2 = combined[1] >> 64 ^ combined[2] << 64;
    let x3 = combined[2] >> 64;

    let a = x3 >> 63;
    let b = x3 >> 62;
    let c = x3 >> 57;

    // Step 2
    let d = x2 ^ a ^ b ^ c;

    // Step 3
    let e1_e0 = [d << 1, x3 << 1 ^ d >> 127];
    let f1_f0 = [d << 2, x3 << 2 ^ d >> 126];
    let g1_g0 = [d << 7, x3 << 7 ^ d >> 121];

    // Step 4
    let h1_h0 = [
        d ^ e1_e0[0] ^ f1_f0[0] ^ g1_g0[0],
        x3 ^ e1_e0[1] ^ f1_f0[1] ^ g1_g0[1],
    ];

    x[0] = combined[0] ^ h1_h0[0];
    x[1] = (combined[1] ^ h1_h0[1]) & U128_LOWER_MASK;
}

impl Mul for GF192 {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl Mul<&Self> for GF192 {
    type Output = Self;

    fn mul(mut self, rhs: &Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl MulAssign for GF192 {
    fn mul_assign(&mut self, rhs: Self) {
        *self *= &rhs;
    }
}

impl MulAssign<&Self> for GF192 {
    fn mul_assign(&mut self, rhs: &Self) {
        gf192_mul(&mut self.0, &rhs.0);
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
}

impl BigGaloisField for BigGF<u128, 2, 192> {}

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

/// Type representing binary Galois field of size `2^256`
pub type GF256 = BigGF<u128, 2, 256>;

#[cfg(test)]
impl Distribution<GF192> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GF192 {
        BigGF([rng.sample(self), {
            let v: u64 = rng.sample(self);
            v as u128
        }])
    }
}

/// Multiplies two polynomials 'x' and 'y' in the finite field GF256, storing the result in x.
fn gf256_mul(x: &mut [u128; 2], y: &[u128; 2]) {
    // Karatsuba multiplication of x * y
    let x0y0 = karatsuba_mul_128_uncombined(x[0], y[0]);
    let x1y1 = karatsuba_mul_128_uncombined(x[1], y[1]);
    let xsum_ysum = karatsuba_mul_128_uncombined(x[0] ^ x[1], y[0] ^ y[1]);

    // Combine the result into a single poly of degree 510
    let x0y0_2_plus_x1y1_0 = x0y0[2] ^ x1y1[0];
    let combined = combine_poly128s_7([
        x0y0[0],
        x0y0[1],
        xsum_ysum[0] ^ x0y0[0] ^ x0y0_2_plus_x1y1_0,
        xsum_ysum[1] ^ x0y0[1] ^ x1y1[1],
        xsum_ysum[2] ^ x1y1[2] ^ x0y0_2_plus_x1y1_0,
        x1y1[1],
        x1y1[2],
    ]);

    // Reduction modulo x^256 + x^10 + x^5 + x^2 + 1 adapted from page 16/17
    // of <https://cdrdv2-public.intel.com/836172/clmul-wp-rev-2-02-2014-04-20.pdf>

    // Step 1
    let x2 = combined[2];
    let x3 = combined[3];

    let a = x3 >> 126;
    let b = x3 >> 123;
    let c = x3 >> 118;

    // Step 2
    let d = x2 ^ a ^ b ^ c;

    // Step 3
    let e1_e0 = [d << 2, x3 << 2 ^ d >> 126];
    let f1_f0 = [d << 5, x3 << 5 ^ d >> 123];
    let g1_g0 = [d << 10, x3 << 10 ^ d >> 118];

    // Step 4
    let h1_h0 = [
        d ^ e1_e0[0] ^ f1_f0[0] ^ g1_g0[0],
        x3 ^ e1_e0[1] ^ f1_f0[1] ^ g1_g0[1],
    ];

    x[0] = combined[0] ^ h1_h0[0];
    x[1] = combined[1] ^ h1_h0[1];
}

impl Mul for GF256 {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl Mul<&Self> for GF256 {
    type Output = Self;

    fn mul(mut self, rhs: &Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl MulAssign for GF256 {
    fn mul_assign(&mut self, rhs: Self) {
        *self *= &rhs;
    }
}

impl MulAssign<&Self> for GF256 {
    fn mul_assign(&mut self, rhs: &Self) {
        gf256_mul(&mut self.0, &rhs.0);
    }
}

impl Modulus<u128> for BigGF<u128, 2, 256> {
    const MODULUS: u128 = 0b10000100101u128;
}

impl ClearHighBits for BigGF<u128, 2, 256> {
    #[inline]
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
    #[inline]
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
    fn mul(self, rhs: GF128) -> Self::Output {
        gf_mul(self, &rhs)
    }
}

impl Mul<&GF128> for GF384 {
    type Output = Self;
    fn mul(self, rhs: &GF128) -> Self::Output {
        gf_mul(self, rhs)
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
    #[inline]
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
    fn mul(self, rhs: GF192) -> Self::Output {
        gf_mul(self, &rhs)
    }
}

impl Mul<&GF192> for GF576 {
    type Output = Self;
    fn mul(self, rhs: &GF192) -> Self::Output {
        gf_mul(self, rhs)
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
            rng.sample::<u64, _>(self) as u128,
        ])
    }
}

/// Type representing binary Galois field of size `2^768`
pub type GF768 = BigGF<u128, 6, 768>;

impl Modulus<u128> for GF768 {
    const MODULUS: u128 = 0b10100000000000010001u128;
}

impl ClearHighBits for GF768 {
    #[inline]
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
        for (dst, src) in zip(ret.chunks_exact_mut(16), self.0.as_ref()) {
            dst.copy_from_slice(&src.to_le_bytes());
        }
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
    fn mul(self, rhs: GF256) -> Self::Output {
        gf_mul(self, &rhs)
    }
}

impl Mul<&GF256> for GF768 {
    type Output = Self;
    fn mul(self, rhs: &GF256) -> Self::Output {
        gf_mul(self, rhs)
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
    use crate::utils::test::read_test_data;
    use std::fmt::Debug;

    use serde::Deserialize;

    const RUNS: usize = 10;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataMul {
        lambda: usize,
        database: Vec<[String; 3]>,
    }

    #[generic_tests::define]
    mod field_ops {
        use super::*;

        use std::iter::zip;

        use generic_array::typenum::Unsigned;
        use rand::RngCore;

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
            let mut rng = rand::thread_rng();

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
            let mut rng = rand::thread_rng();

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
            let mut rng = rand::thread_rng();

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
            let mut rng = rand::thread_rng();

            let elements = array::from_fn(|_| rng.r#gen());
            assert_eq!(F::byte_combine(&elements), F::byte_combine_slice(&elements));
        }

        #[test]
        fn byte_conversions<F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<F>,
        {
            let mut rng = rand::thread_rng();

            let element = rng.r#gen();
            let bytes = element.as_bytes();
            assert_eq!(element, F::from(&bytes));
            assert_eq!(element, F::from(bytes.as_slice()));
        }

        #[test]
        fn mul<F: BigGaloisField + Debug + Eq>() {
            let test_data = read_test_data("LargeFieldMul.json")
                .into_iter()
                .find(|data: &DataMul| data.lambda == <F as Field>::Length::USIZE * 8)
                .expect(&format!(
                    "No test data for GF{}",
                    <F as Field>::Length::USIZE * 8
                ));

            for [lhs, rhs, expected] in test_data.database {
                let mut lhs = F::from(hex::decode(lhs.as_str()).unwrap().as_slice());
                let rhs = F::from(hex::decode(rhs.as_str()).unwrap().as_slice());
                let expected = F::from(hex::decode(expected.as_str()).unwrap().as_slice());
                assert_eq!(lhs * rhs, expected);
                assert_eq!(rhs * lhs, expected);
                lhs *= rhs;
                assert_eq!(lhs, expected);
            }
        }

        #[test]
        fn square<F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<F>,
        {
            let mut rng = rand::thread_rng();

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

    fn byte_combine<F: BigGaloisField + Debug + Eq>(test_data: &[[&str; 9]]) {
        for data in test_data {
            let tab = [
                F::from(hex::decode(data[0]).unwrap().as_slice()),
                F::from(hex::decode(data[1]).unwrap().as_slice()),
                F::from(hex::decode(data[2]).unwrap().as_slice()),
                F::from(hex::decode(data[3]).unwrap().as_slice()),
                F::from(hex::decode(data[4]).unwrap().as_slice()),
                F::from(hex::decode(data[5]).unwrap().as_slice()),
                F::from(hex::decode(data[6]).unwrap().as_slice()),
                F::from(hex::decode(data[7]).unwrap().as_slice()),
            ];
            let result = F::from(hex::decode(data[8]).unwrap().as_slice());
            assert_eq!(F::byte_combine(&tab), result);
        }
    }

    #[test]
    fn gf128_byte_combine() {
        let database = [
            [
                "aa6a6f1713d27a71fe989e93dc79d27d",
                "714f4c855dc34eafbaa6d0c9a6cb67ef",
                "594cbc985a239f97859c0f5dbc9c65ee",
                "bd3a871fc93c17e3781cb120b89a5bc4",
                "edff635fd5c3a8e210534b6a29da7c4a",
                "d16d14e0cae7da06be1134a171555bb4",
                "56be29a614665b84abb8808565ca3059",
                "8d143b6e793799fde7617b4a734f4973",
                "334dbbe5004d3dbbe3ac3a2e86ddb72a",
            ],
            [
                "a4108259c36d3300a3452de6cc6819ac",
                "f74513a1922de3721a29e974d16a6d52",
                "1a313de17135292c281f35f36d642221",
                "66322955d8a653ed6397826ca1ef2d6c",
                "d3a414c6a1e83bdd37696aa0ecb9482e",
                "3f5c0f270b04733c065b8c2cb0ca8212",
                "0e96f9872bbc1a87ddeb27c7f189b826",
                "fb1b26d476b3f87607f4a9742a1a26e3",
                "4d38054fc9df94561220860e9ebf72a2",
            ],
            [
                "263e276e9d619c4fe6b9b40d1f5ae81b",
                "78ffd6d19573db9fa408e8cb29f82e27",
                "96e08f0df9f18a1d67d5ec2214923217",
                "a98663ac8a0578bed72c80910767ce11",
                "f17959de6a99bbdc75b204636f1dd25f",
                "270d3294a2a45d1dcc86c5fe76b41e56",
                "b3aa6455426c8f62c47bd85c3a96afa1",
                "7f456dad4831aa46f018ed4dd3a4d8cd",
                "7f088260d013e0b497e0bf44dea3b5bc",
            ],
        ];
        byte_combine::<GF128>(&database);
    }

    #[test]
    fn gf192_byte_combine() {
        let database = [
            [
                "97435430defb19efaf7e3a6e9fc365b419633d4221d07ea7",
                "6d4949bf79ddbbbd17c1a4761f2169e44bbcc6d998468635",
                "8a13ceeabe8aee808b1d39eba3da8313fa6080cff2f4df8c",
                "9b46eb3c67d416b5b466aeb667ccb8860b7bfb4a3f7bf875",
                "3b9a144eda2392d8c3ae8d871741e0b914b3036ca3f99e19",
                "d9ffc96ad4cb269ab3fdfc617afecd260fe5bef4d778ecc5",
                "c524bad21ff3c079745cf027bbf461cd823e8ec20b86838d",
                "104261f32b5213d7ad09c34d5042bfbec74d051430914b76",
                "3c3aeab72cb94f341f526028551479e4335a9e7e29c769ab",
            ],
            [
                "e90ba7d98495ec8f34ffc33cd4fec49900e86d7f5ded63d5",
                "a458f5c02b6cbf5884b1fc51568a4b6cace0914b113da05b",
                "80016f8597da72e83ab2af373bd406858f18293f7bf19fca",
                "d0b48d33172d01284a38c147688380f4a982de10b0129087",
                "d0675051d384f4a9bbadccefb788f56f3c49994f12cb4104",
                "f9af9b3008af0ebc2435b48424546aabcdd4fcd26028c015",
                "146ce9152843cc89b66f956b20f5c5ad4967b891f7797c84",
                "027f4a31fcf61149b791fe06744cd9c4a96990d393dbc729",
                "9247127d401126a9e217b3a3a6e9e02fa3094d1dc280777c",
            ],
            [
                "4f30c4b472dc4eaff3b409206897a65db6f0ac03dbb8e4a1",
                "85ee56ffce3aa7d81035717812eb918467823c44c27665e5",
                "96643a20b33012458f6bf54dd07b5e424a90213452f65471",
                "76c4019c31e2469471c507c5f73061107d31e01b8213a732",
                "d3e8adef5c7b5b33e06e868c6f38ce54175e481d598455df",
                "69a1d0189000168f3a8ba459525968def7989a837f56c9e7",
                "5b0843fe01ad4b62298fd67f12a606a43871626d2fa9866c",
                "5b02e930dc80f9bdc6f7fda2210bc46e7180f67a4f56e2a5",
                "8c5fc7d9e4aae7a23b4a60cfa972f1570383fac4850080ef",
            ],
        ];
        byte_combine::<GF192>(&database);
    }

    #[test]
    fn gf256_byte_combine() {
        let database = [
            [
                "c2f6c29d90d5f0aceafd8751f1880efc9ab70c2b8a2ae54976ac9e0efbc88cd6",
                "7d798407e8db5017aae4cbe8f249342f0c524ce4442b0af0cb903f64c8185778",
                "95315e58d485508458286b521c541fcdbb106f389275987da6e8936065954d3c",
                "a9456a8285167815b7577b06080cd879eedc7369fc29bef61fae73e322198451",
                "9ea4717819ecd1ead760f10ef380e965af2c06604c300216b14164fe85b380d9",
                "e4a60ad034cbfe80dcfbffd4b895f6d144ad5f191926ff483815ba551e6580c4",
                "71198fcb06a47c624ec560dc1235f2e0eec7f634e9680e6ffa22a3a41f57c263",
                "1586cb264022ce18b6793cfe01bed1187693b9537bd4e940c5b46b019dfd4971",
                "c56b311c313ee2d49000d298bc532e663c8170974ba202289662c032237a005c",
            ],
            [
                "4fb3716fa0d84561336cefb4840a371878e4cec3832744554694739703ab7a29",
                "0f429ca77f674b13c1bc7b9f87ba635e7939f9756b83c6c7f4db0e7f722c785f",
                "7aec71702cf0a8b08005f568daafccc3a95a3a3b121f1f966552b1a9fd9fe068",
                "1efb0c9b9464a89b5898f3b466d895b910b1fb4773cd56c01939ff10da7c8f97",
                "81b656b24ce53ba62391d51cd2a230672a3bc4a8a6dbe6b9871ba932bbf1fd82",
                "754a57aa984ff4cdf1c6f851ed66d98d3d2a62736c2af0e332f5885ae8cf8afa",
                "c9989982817be71fd981fe62c604e575eedda4cb98252a04f4e9a2d354d1b0cc",
                "b875a162992e5b51cd5b05a17c69a274054a92aedcc56f8d187afb0008302f46",
                "e732850e177e5f2dd3e8765ccd91a25438c3c6b841e0ab2e3da0dc648d9faca9",
            ],
            [
                "45f19ae41aed2508f08fe519f53c68ea4425e83f1f44c25a1e4d67c010ca2ca4",
                "4b2c6726f26fb5b8a37e3c697b9604e19960864152e74e0d8003ff07936ab1fc",
                "dfc86e485b1c0d4aa7236d7e2fcfbbb17969124934f5b295d85b6758cdcda4ba",
                "4ca4a35ae61fb0adacdd1775f6efb0236d08e76d6f2a10c44d039ff016eaa884",
                "38bd431d0381f6d842ca1b9465fe9fae3b692d3b88dfc517352988cf57d0bf1d",
                "ca414b24ae668f4dcaa3b0fefff191437b4f968d984a79fd0dd2b5bcdb663a48",
                "bc18c65f0a7902731ec09bb67b55a09cae445c5d5fd7167d1991ab98bf6830ae",
                "a10852ecf84c45ef352dd1af830c8bc64b70d16f6a92a0a7e2b781f3b683d004",
                "2f7d52efccba230fe92554d1c30bb9fbaaa4672f474b8c56141bdc6a80115d44",
            ],
        ];
        byte_combine::<GF256>(&database);
    }

    #[generic_tests::define]
    mod extended_field_ops {
        use super::*;
        use crate::utils::test::read_test_data;

        #[test]
        fn mul<F, const LAMBDA: usize>()
        where
            F: ExtensionField<BaseField: for<'a> From<&'a [u8]>> + Copy + Debug + Eq,
        {
            let test_data: Vec<DataMul> = read_test_data("ExtendedFields.json");
            let test_data = test_data
                .into_iter()
                .find(|data| data.lambda == LAMBDA)
                .expect(&format!("No test data for GF{LAMBDA}"));

            for [lhs, rhs, res] in test_data.database {
                let lhs = F::from(hex::decode(lhs.as_str()).unwrap().as_slice());
                let rhs = <F::BaseField>::from(hex::decode(rhs.as_str()).unwrap().as_slice());
                let res = F::from(hex::decode(res.as_str()).unwrap().as_slice());
                assert_eq!(lhs * rhs, res);
            }
        }

        #[test]
        fn byte_conversions<F: ExtensionField + Debug + Eq, const LAMBDA: usize>()
        where
            Standard: Distribution<F>,
        {
            let mut rng = rand::thread_rng();

            let element = rng.r#gen();
            let bytes = element.as_bytes();
            assert_eq!(element, F::from(&bytes));
            assert_eq!(element, F::from(bytes.as_slice()));
        }

        #[instantiate_tests(<GF384, 384>)]
        mod gf384 {}

        #[instantiate_tests(<GF576, 576>)]
        mod gf576 {}

        #[instantiate_tests(<GF768, 768>)]
        mod gf768 {}
    }
}
