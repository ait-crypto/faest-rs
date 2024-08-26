use std::{
    array, mem,
    num::Wrapping,
    ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitXor, BitXorAssign, Mul, MulAssign, Neg,
        Shl, Shr, Sub, SubAssign,
    },
};

use super::{Field, GF64};

#[cfg(test)]
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use subtle::{Choice, ConditionallySelectable};

/// Helper trait to convert the least significant bit of `u8` values into a [Choice].
trait IntoChoice {
    fn into_choice(self) -> Choice;
}

impl IntoChoice for u8 {
    #[inline(always)]
    fn into_choice(self) -> Choice {
        (self & 1).into()
    }
}

/// Helper trait that define "alphas" for calculating embedings as part of [ByteCombine]
trait Alphas: Sized {
    const ALPHA: [Self; 7];
}

/// Create an instance of `0` or `1` in the field out of a bit representation
pub trait FromBit: Field + ConditionallySelectable {
    #[deprecated]
    fn from_bit(x: u8) -> Self {
        Self::conditional_select(&Self::ZERO, &Self::ONE, x.into_choice())
    }
}

//For GF192 and GF256, as u192 and u256 dont exist in rust, we will implement a new trait BigGaloisField, in wich we will also implement basis operations.

/// "Marker" trait for the larger binary Galois fields, i.e., [GF128], [GF192] and [GF256].
pub trait BigGaloisField: Field
where
    Self: Sized + Copy,
    Self: for<'a> From<&'a [u8]>,
    Self: Mul<u8, Output = Self>,
    Self: Mul<GF64, Output = Self>,
    Self: for<'a> MulAssign<&'a Self>,
    Self: for<'a> Mul<&'a Self, Output = Self>,
    Self: ConditionallySelectable,
    Self: ByteCombine,
    Self: SumPoly,
{
    const LENGTH: u32;

    const MODULUS: Self;

    const MAX: Self;

    fn new(first_value: u128, second_value: u128) -> Self;

    fn get_value(&self) -> (u128, u128);

    //return MAX if the input is different from 0
    fn all_bytes_heavyweight(self) -> Self {
        let (first_value, second_value) = self.get_value();
        let c_1 = (first_value & ((1u128 << 127).wrapping_shr(first_value.leading_zeros())))
            .wrapping_shl(first_value.leading_zeros())
            >> 127;
        let c_2 = (second_value & ((1u128 << 127).wrapping_shr(second_value.leading_zeros())))
            .wrapping_shl(second_value.leading_zeros())
            >> 127;
        let c = c_1 | c_2;
        Self::new(u128::MAX * c, u128::MAX * c)
    }

    fn switch_left_1(self) -> Self {
        let (first_value, second_value) = self.get_value();
        let carry = (first_value & (1u128 << 127)) >> 127;
        let first_res = first_value.wrapping_shl(1);
        let second_res = (second_value.wrapping_shl(1)) | carry;
        Self::new(first_res, second_res)
    }

    fn and(left: &Self, right: &Self) -> Self {
        let (l_first_value, l_second_value) = left.get_value();
        let (r_first_value, r_second_value) = right.get_value();
        Self::new(
            l_first_value & r_first_value,
            l_second_value & r_second_value,
        )
    }

    fn to_bytes(input: Self) -> Vec<u8>;

    fn to_field(x: &[u8]) -> Vec<Self> {
        let n = (8 * x.len()) / (Self::LENGTH as usize);
        let mut res = vec![];
        let padding_array = [0u8; 16];
        for i in 0..n {
            let padded_value = &mut x
                [(i * (Self::LENGTH as usize) / 8)..((i + 1) * (Self::LENGTH as usize) / 8)]
                .to_vec();
            padded_value.append(&mut padding_array[..(32 - (Self::LENGTH as usize) / 8)].to_vec());
            res.push(Self::from(padded_value));
        }
        res
    }
}

/// Trait provinding "byte combination"
pub trait ByteCombine: Field {
    /// "Combine" field elements
    fn byte_combine(x: &[Self; 8]) -> Self;

    /// "Combine" bits
    fn byte_combine_bits(x: u8) -> Self;
}

impl<T> ByteCombine for T
where
    T: Alphas + Field + ConditionallySelectable + for<'a> Mul<&'a Self, Output = Self>,
{
    fn byte_combine(x: &[Self; 8]) -> Self {
        x.iter()
            .skip(1)
            .zip(Self::ALPHA)
            .fold(x[0], |sum, (xi, alphai)| sum + (alphai * xi))
    }

    fn byte_combine_bits(x: u8) -> Self {
        Self::ALPHA.iter().enumerate().fold(
            Self::conditional_select(&Self::ZERO, &Self::ONE, x.into_choice()),
            |sum, (index, alpha)| {
                sum + Self::conditional_select(&Self::ZERO, alpha, (x >> (index + 1)).into_choice())
            },
        )
    }
}

/// Helper trait for blanket implementations of [SumPoly]
trait Double: Sized {
    fn double(self) -> Self;
}

/// Trait providing a polynomial sum
pub trait SumPoly: Field {
    /// Compute polynomial sum
    fn sum_poly(v: &[Self]) -> Self;
}

impl<T> SumPoly for T
where
    T: Copy + Field + Double + for<'a> Add<&'a Self, Output = Self>,
{
    fn sum_poly(v: &[Self]) -> Self {
        v.iter()
            .rev()
            .skip(1)
            .fold(v[v.len() - 1], |sum, val| sum.double() + val)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct BigGF<T, const N: usize, const LENGTH: usize>([T; N]);

impl<T, const N: usize, const LENGTH: usize> Default for BigGF<T, N, LENGTH>
where
    T: Default + Copy,
{
    fn default() -> Self {
        Self([Default::default(); N])
    }
}

impl<T, const N: usize, const LENGTH: usize> ConditionallySelectable for BigGF<T, N, LENGTH>
where
    T: ConditionallySelectable,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<[T; N]>::conditional_select(&a.0, &b.0, choice))
    }
}

// generic implementations of Add and AddASsign

impl<T, const N: usize, const LENGTH: usize> Add for BigGF<T, N, LENGTH>
where
    T: BitXorAssign + Copy,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(mut self, rhs: Self) -> Self::Output {
        for idx in 0..N {
            self.0[idx] ^= rhs.0[idx];
        }
        self
    }
}

impl<T, const N: usize, const LENGTH: usize> Add<&Self> for BigGF<T, N, LENGTH>
where
    T: BitXorAssign<T> + Copy,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(mut self, rhs: &Self) -> Self::Output {
        for idx in 0..N {
            self.0[idx] ^= rhs.0[idx];
        }
        self
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
    T: BitXorAssign + Copy,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(mut self, rhs: Self) -> Self::Output {
        for idx in 0..N {
            self.0[idx] ^= rhs.0[idx];
        }
        self
    }
}

impl<T, const N: usize, const LENGTH: usize> Sub<&Self> for BigGF<T, N, LENGTH>
where
    T: BitXorAssign<T> + Copy,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(mut self, rhs: &Self) -> Self::Output {
        for idx in 0..N {
            self.0[idx] ^= rhs.0[idx];
        }
        self
    }
}

impl<T, const N: usize, const LENGTH: usize> SubAssign for BigGF<T, N, LENGTH>
where
    T: BitXorAssign<T> + Copy,
{
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        for idx in 0..N {
            self.0[idx] ^= rhs.0[idx];
        }
    }
}

impl<T, const N: usize, const LENGTH: usize> SubAssign<&Self> for BigGF<T, N, LENGTH>
where
    T: BitXorAssign<T> + Copy,
{
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: &Self) {
        for idx in 0..N {
            self.0[idx] ^= rhs.0[idx];
        }
    }
}

// generic implementations of Mul and MulAssign

trait Modulus<T> {
    const MODULUS: T;
}

trait ToMask<T> {
    fn to_mask(&self) -> T;

    fn to_mask_bit(&self, bit: usize) -> T;
}

/* impl<T, const N: usize, const LENGTH: usize> ToMask<T> for BigGF<T, N, LENGTH>
where
    T: Copy + Shr<usize, Output = T>,
    Wrapping<T>: Neg<Output = Wrapping<T>>,
{
    fn to_mask(&self) -> T {
        let array_index = (LENGTH - 1) / (size_of::<T>() * 8);
        let value_index = (LENGTH - 1) % (size_of::<T>() * 8);

        (-Wrapping(self.0[array_index] >> value_index)).0
    }

    fn to_mask_bit(&self, bit: usize) -> T {
        let array_index = bit / (size_of::<T>() * 8);
        let value_index = bit % (size_of::<T>() * 8);

        (-Wrapping(self.0[array_index] >> value_index)).0
    }
} */

trait ApplyMask<T> {
    type Output;

    fn apply_mask(self, mask: T) -> Self::Output;

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

trait ShiftLeft1 {
    type Output;

    fn shift_left_1(self) -> Self::Output;
}

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

            result += self.copy_apply_mask(rhs.to_mask_bit(idx))
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

            result += self.copy_apply_mask(rhs.to_mask_bit(idx))
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

impl<T, const N: usize, const LENGTH: usize> Mul<u64> for BigGF<T, N, LENGTH>
where
    Self: Modulus<T>,
    Self: ToMask<T>,
    Self: ApplyMask<T, Output = Self>,
    Self: AddAssign,
    Self: ShiftLeft1<Output = Self>,
    T: BitAnd<Output = T>,
    T: BitXorAssign + std::fmt::Debug,
    u64: ToMask<T>,
{
    type Output = Self;

    fn mul(mut self, rhs: u64) -> Self::Output {
        let mut result = self.copy_apply_mask(rhs.to_mask_bit(0));
        for idx in 1..64 {
            let mask = self.to_mask();
            self = self.shift_left_1();
            self.0[0] ^= mask & Self::MODULUS;

            result += self.copy_apply_mask(rhs.to_mask_bit(idx))
        }
        result
    }
}

impl<T, const N: usize, const LENGTH: usize> Mul<u64> for &BigGF<T, N, LENGTH>
where
    BigGF<T, N, LENGTH>: Copy,
    BigGF<T, N, LENGTH>: Mul<u64, Output = BigGF<T, N, LENGTH>>,
{
    type Output = BigGF<T, N, LENGTH>;

    fn mul(self, rhs: u64) -> Self::Output {
        *self * rhs
    }
}

impl<T, const N: usize, const LENGTH: usize> Mul<GF64> for BigGF<T, N, LENGTH>
where
    Self: Mul<u64, Output = Self>,
{
    type Output = Self;

    #[inline]
    fn mul(self, rhs: GF64) -> Self::Output {
        self * (rhs.into())
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

            *self += lhs.copy_apply_mask(rhs.to_mask_bit(idx))
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

            *self += lhs.copy_apply_mask(rhs.to_mask_bit(idx))
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

            *self += lhs.copy_apply_mask(rhs.to_mask_bit(idx))
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
    fn double(mut self) -> Self {
        let mask = self.to_mask();
        self = self.shift_left_1();
        self.0[0] ^= mask & Self::MODULUS;
        self
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

// u128-based GF128, GF256

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

impl From<&[u8]> for BigGF<u128, 1, 128> {
    fn from(value: &[u8]) -> Self {
        // FIXME
        // assert_eq!(value.len(), 16);
        let mut array = [0u8; 16];
        array.copy_from_slice(&value[..16]);
        Self([u128::from_le_bytes(array)])
    }
}

impl BigGaloisField for BigGF<u128, 1, 128> {
    const LENGTH: u32 = 128;

    const MODULUS: Self = Self([<Self as Modulus<u128>>::MODULUS]);

    const MAX: Self = Self([u128::MAX]);

    fn new(first_value: u128, _second_value: u128) -> Self {
        Self([first_value])
    }

    fn get_value(&self) -> (u128, u128) {
        (self.0[0], 0)
    }

    fn to_bytes(input: Self) -> Vec<u8> {
        input.0[0].to_le_bytes().to_vec()
    }

    fn switch_left_1(self) -> Self {
        self.shift_left_1()
    }

    fn and(left: &Self, right: &Self) -> Self {
        todo!()
    }
}

#[cfg(test)]
impl FromBit for BigGF<u128, 1, 128> {}

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

impl From<&[u8]> for BigGF<u128, 2, 192> {
    fn from(value: &[u8]) -> Self {
        // FIXME
        // assert_eq!(value.len(), 16);
        let mut array_1 = [0u8; 16];
        array_1.copy_from_slice(&value[..16]);
        let mut array_2 = [0u8; 16];
        array_2.copy_from_slice(&value[16..]);
        Self([u128::from_le_bytes(array_1), u128::from_le_bytes(array_2)])
    }
}

impl BigGaloisField for BigGF<u128, 2, 192> {
    const LENGTH: u32 = 192;

    const MODULUS: Self = Self([<Self as Modulus<u128>>::MODULUS, 0]);

    const MAX: Self = Self([u128::MAX, u64::MAX as u128]);

    fn new(first_value: u128, second_value: u128) -> Self {
        Self([first_value, second_value]).clear_high_bits()
    }

    fn get_value(&self) -> (u128, u128) {
        (self.0[0], self.0[1])
    }

    fn to_bytes(input: Self) -> Vec<u8> {
        let mut res = Vec::with_capacity(Self::LENGTH as usize / 8);
        res.append(&mut input.0[0].to_le_bytes().to_vec());
        res.append(&mut input.0[1].to_le_bytes()[..8].to_vec());
        res
    }

    fn switch_left_1(self) -> Self {
        self.shift_left_1()
    }

    fn and(left: &Self, right: &Self) -> Self {
        todo!()
    }
}

#[cfg(test)]
impl FromBit for BigGF<u128, 2, 192> {}

/// Type representing binary Galois field of size `2^128`
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

impl From<&[u8]> for BigGF<u128, 2, 256> {
    fn from(value: &[u8]) -> Self {
        // FIXME
        // assert_eq!(value.len(), 16);
        let mut array = [0u8; 16];
        array.copy_from_slice(&value[..16]);
        Self(array::from_fn(|idx| {
            let mut array = [0u8; 16];
            array.copy_from_slice(&value[idx * 16..(idx + 1) * 16]);
            u128::from_le_bytes(array)
        }))
    }
}

impl BigGaloisField for BigGF<u128, 2, 256> {
    const LENGTH: u32 = 256;

    const MODULUS: Self = Self([<Self as Modulus<u128>>::MODULUS, 0]);

    const MAX: Self = Self([u128::MAX, u128::MAX]);

    fn new(first_value: u128, second_value: u128) -> Self {
        Self([first_value, second_value])
    }

    fn get_value(&self) -> (u128, u128) {
        (self.0[0], self.0[1])
    }

    fn to_bytes(input: Self) -> Vec<u8> {
        let mut bytes = input.0[0].to_le_bytes().to_vec();
        bytes.extend_from_slice(&input.0[1].to_le_bytes());
        bytes
    }

    fn switch_left_1(self) -> Self {
        self.shift_left_1()
    }

    fn and(left: &Self, right: &Self) -> Self {
        todo!()
    }
}

#[cfg(test)]
impl FromBit for BigGF<u128, 2, 256> {}

/// Type representing binary Galois field of size `2^128`
pub type GF256 = BigGF<u128, 2, 256>;

#[cfg(test)]
impl Distribution<GF256> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GF256 {
        BigGF([rng.sample(self), rng.sample(self)])
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use num_bigint::BigUint;

    //GF128
    #[test]
    //precondition : none
    //Postiditon : GF128 whose get value is as expected
    fn gf128_test_new_get_value() {
        let polynome = GF128::new(243806996201303833512771950610419307673u128, 0);
        let (first_value, second_value) = polynome.get_value();
        assert_eq!(first_value, 243806996201303833512771950610419307673u128);
        assert_eq!(second_value, 0u128);

        //if given a second value not null
        let polynome = GF128::new(243806996201303833512771950610419307673u128, 1u128);
        let (first_value, second_value) = polynome.get_value();
        assert_eq!(first_value, 243806996201303833512771950610419307673u128);
        assert_eq!(second_value, 0u128);
    }

    #[test]
    //precondition: a GF128
    //postcondition : return MAX if the input is different from 0
    fn gf128_test_all_bytes_heavyweight() {
        //input != 0
        let pol_1 = GF128::ONE;
        let pol_1_big = GF128::new(2730312856557028196081990424695764059u128 | 1u128, 0u128);
        let pol_2 = pol_1.all_bytes_heavyweight();
        let pol_2_big = pol_1_big.all_bytes_heavyweight();
        assert_eq!(pol_2, GF128::MAX);
        assert_eq!(pol_2_big, GF128::MAX);
        //input = 0
        let pol_0 = GF128::default();
        let pol_res = pol_0.all_bytes_heavyweight();
        assert_eq!(pol_res, pol_0);
        let pol_0_p = GF128::new(0u128, 63483453u128);
        let pol_res_p = pol_0_p.all_bytes_heavyweight();
        assert_eq!(pol_res_p, pol_0);
    }

    #[test]
    //precondition : a GF128
    //a GF128 that has switch to the left by one
    fn gf128_test_switch_left_1() {
        let mut rng = rand::thread_rng();

        for _i in 0..10000 {
            let random: u128 = rng.gen();
            let pol_1 = GF128::new(random, 0u128);
            let pol_1_res = pol_1.switch_left_1();
            let (first_value, second_value) = pol_1_res.get_value();
            assert_eq!(first_value, random.wrapping_shl(1));
            assert_eq!(second_value, 0u128);
        }
    }

    #[test]
    //input : two GF128
    //output : the product of the two according to the rules of Galois Fields arithmetic
    fn gf128_test_mul() {
        let mut rng = rand::thread_rng();

        //0 * anything = 0
        let pol_0 = GF128::default();
        for _i in 0..1000 {
            let anything: GF128 = rng.gen();
            let pol_res = pol_0 * anything;
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, 0u128);
            assert_eq!(second_value, 0u128);
            //1 * anything = anything
            let (first_value_anything, _second_value_anything) = anything.get_value();
            #[deny(clippy::op_ref)]
            let pol_res = GF128::ONE * anything;
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, first_value_anything);
            assert_eq!(second_value, 0u128);
            //anything * 0 = 0
            let pol_res_rev = anything * pol_0;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, 0u128);
            assert_eq!(second_value_rev, 0u128);
            //anything * 1 = anything
            let pol_res_rev = anything * GF128::ONE;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, first_value_anything);
            assert_eq!(second_value_rev, 0u128);
        }
        //to test with random values we use a database we get from the test cases of the reference implementation
        let database = [
            [
                0x000000000000000000000000000000ffu128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x000000000000000000000000000000ffu128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x000000000000000000000000000000ffu128,
                0x00000000000000000000000000000001u128,
                0x000000000000000000000000000000ffu128,
            ],
            [
                0x00000000000000000000000000000001u128,
                0x000000000000000000000000000000ffu128,
                0x000000000000000000000000000000ffu128,
            ],
            [
                0x261dffa502bbff620185b5b0891eec27u128,
                0xa3fa4befd33ec6de509de93498eb9f05u128,
                0xe6df41181a1477eae9131e9141c70a15u128,
            ],
            [
                0x3310efa565c3ec75fae7621e9038eb25u128,
                0xf1c016735268c06031d80f2d8a5528c4u128,
                0x015ae1388367039a81b7cc9770edd7acu128,
            ],
            [
                0x8a415b5cc96cd82f5060a69962dd291du128,
                0x908efdcb0e3d9906e9d03be0123d9d67u128,
                0xd6baef00562ad7e60218792ddf755282u128,
            ],
            [
                0x52bc2efb6bf8abbef7fa21a6c9f768edu128,
                0xb6c0df445d8f292e85bc22aedd98f477u128,
                0xbb9bec29b60c0fe489fc137d8ea234f9u128,
            ],
            [
                0x6447766dba746e578161c50284095027u128,
                0x03aab5790815009349603f9f9e15837cu128,
                0x33ddbad773136bc4dd8fec845bf91222u128,
            ],
            [
                0xaca84143380abfe2141ca4d014d88565u128,
                0x74c2def3e24e9270491af728cafd8219u128,
                0x99c893cdb801eadc7a866353d2d6ed77u128,
            ],
            [
                0x246da3dbf86fc9e98626343cff644b4du128,
                0x8d29c20e2c6478b8134ff1654432b7dau128,
                0xbe3c6019309964a4203f3f895affc8a5u128,
            ],
            [
                0x4bf61e7da8ba9765246fe554917d2826u128,
                0xff30130ad14cdade8f6e3fa6b2347fc9u128,
                0x41cb24a867b2ae87e2e5de624cd76a8au128,
            ],
            [
                0xb6b1d1b078ca096421918774641b3e12u128,
                0xb43d95cb15932720af1b2d138f6e12f2u128,
                0x01a1756ad8be3d54f2857bf05a16682eu128,
            ],
            [
                0x6b4801c2a2511b63ae633596bc8b56f4u128,
                0x55e80871667b75142663c289d8bd4a34u128,
                0x630e386febd8c721fdc7b789d57a5d97u128,
            ],
            [
                0xfd7b7df1b3a9a4527a052831c64f4ad3u128,
                0x36c7dae9965e3d90479ddc5875d85a14u128,
                0x69ae8258f34d344e8379f9719dba7ba8u128,
            ],
            [
                0x87ef9559c4a0fed2399b0277d065f2f4u128,
                0x8afd273b3806dd189f5364cd52c2cd92u128,
                0xf5ce45c10f1ac65c1eb3ba60f54464d6u128,
            ],
            [
                0xf16080ee19663d226be51d06a8338ab8u128,
                0x8c58749e0de8b49c6fa2a3db4a6960fdu128,
                0x870e2b18b70c2a909baa9af39dfafe60u128,
            ],
            [
                0x05b87cf7b901d0d5562a77d68ab1346fu128,
                0x54328931ca8a7dc1f3724124539f1bf0u128,
                0x7317e860537789e54320c0f76b6b9b8du128,
            ],
            [
                0xe46017fbc9b11d05ec8b7a660e9ca2b1u128,
                0x02f987458ea8b3ea3d36cbde6599cbd1u128,
                0xce29ac35c94dd7235010366a4a4d0d88u128,
            ],
            [
                0x86747fe8c081ce3976613f5b58fc852cu128,
                0xab839e0bb2803f139d00b847c0725999u128,
                0x49233482e1df8a897e25649207710b4cu128,
            ],
            [
                0xb890a6f5911464a9dc907c1517e2a782u128,
                0x0ff9f6a1e7001ac354da4eee39a4909eu128,
                0x9361d0fd0cb9bcc0f75262d3d1f8577eu128,
            ],
            [
                0x76471d30fe25e6ac8d91c2c41cb49d78u128,
                0x6d2464b763a029251b0dc8dd65082fadu128,
                0x42da705cbb85208119089a790a22c084u128,
            ],
            [
                0x4c98f93b2e475028c594c99028635d7au128,
                0xa1dfce81e6d8d748d50603f998f0b5cfu128,
                0x3d6734feb6ecdf54e220209eff4f9d1eu128,
            ],
            [
                0x481787abb09e367aef16e476fc6210ceu128,
                0xb2159f8cc6bdfb58c0d1646ef9c054aau128,
                0x5c96c4e7f7b1a46d44daaacf1dffb4c1u128,
            ],
            [
                0xf695d9c2913df89e4288a7ad6432c4c2u128,
                0xf838b8f0638d473501d2213bdf67dcf6u128,
                0x6e390d20ac3cefb9a5609f085b90c01fu128,
            ],
            [
                0x0a82d87309b8ed2fbf056e350b4650b7u128,
                0x541e9ff88dd5c376b7ea83566ea89f0du128,
                0x7ab020ac21c4bd8853163550307a7cf4u128,
            ],
            [
                0xf3144420d0676443ae0b4972a1117514u128,
                0x58cc81c2a6b5bc661d300b18c433703cu128,
                0xbc32c541ab68ca0046ca90fdc37e80bbu128,
            ],
            [
                0x56de78096702b90cf5b0393ccb02508fu128,
                0xcb9db395e16d3d3e686995f8d2b5cd84u128,
                0xfa2d6d558fc3b4561c02914b6384f31cu128,
            ],
            [
                0xd28702ef92046fcf8d093abadddda255u128,
                0x13b21d42b4284c94f8e2ffd02787cd56u128,
                0xe31dce0866f22df6cc4890a41f2a2fa4u128,
            ],
            [
                0xcfcc56967f32667613f79159356fd8b2u128,
                0xabe8bf0404c9293c133d9fafa7bee345u128,
                0xaf15c2a8058c4d820563818fbb28c805u128,
            ],
            [
                0xd8a3181ccf2f6447ca3c30840cf19122u128,
                0xf8279e2c880a9bd78d5aafefdb92ef57u128,
                0xee7242bd4de9e32fc24dc8f20c5a16c8u128,
            ],
            [
                0xe9de05d64daa617593078851f288d196u128,
                0x07f5a3ea76a669d792d04dbd2c7aaccfu128,
                0xc2618e86c0c1285fa9d1582d574bcbc3u128,
            ],
            [
                0xa3d91dd183717a18e2fa3b3f4003881eu128,
                0xb1c69527bf46d39ecec67298c4b971dau128,
                0x6bf8d376a31b7c10e7f2c18383eb4ca1u128,
            ],
            [
                0xa4e88859619431600e3547ce1cb9e51bu128,
                0x3bee6c47f67d58313ffffbcaf1aed22au128,
                0x1a394fc760ee4714ec2dd3e892713f76u128,
            ],
            [
                0x795e580113a8e3721b9594262bef2577u128,
                0xdfec2bdf171f746432353d6845652f08u128,
                0x6f776b1f64d2b30763284375f7938d82u128,
            ],
            [
                0x37e1d16107549a69cc9d14c497b8bd90u128,
                0xc3f2ebe29ca84c2e82462587a4c54c28u128,
                0x1f43595a109d91fabbbc4a466b8573ecu128,
            ],
            [
                0x8d22a7d46eb817eea8d77d98edc4e39cu128,
                0xb03784c1b3090a0a556fedcff6d286b3u128,
                0x0d514060fa1b53b16bac556c98849967u128,
            ],
            [
                0xeb20e0a5eaed11c60cd8cb5c46f6e91eu128,
                0x46879f3cef55a7ecc1bde942fcec23fbu128,
                0x357aac6c063fdc80945b0d0d63499745u128,
            ],
            [
                0xeaf60151fa71894a82ab50d45076f032u128,
                0xb433f5a1561c0d8c327e415675d5deabu128,
                0x920194073f4472186cd2cd42e754b864u128,
            ],
            [
                0xa0f169548fba6c892f5c2060c4a55b2cu128,
                0x111919ef036edf9001e62a523481c5f0u128,
                0x4781b70c969cea1909657af6e7b2b330u128,
            ],
            [
                0x570a8da8a9cefb1bab429ee25b78cb84u128,
                0xffc68b351146971e6ec5f89fc5b592f0u128,
                0xb165bdf06daba807f825ceaa6b508c91u128,
            ],
            [
                0xa5d9fdf9cc8c97d8bd10317e6231a1a0u128,
                0xa67f87e67c932887a4791ea7e757dbcdu128,
                0x2718dc8daa9b1ad3465ce57078188bd5u128,
            ],
            [
                0xb9559ccc13ac27790b3f734dc38d95a2u128,
                0x1c9ab7fc3ce8d57d5a6a87d1585fa6a9u128,
                0xe0e516bedd00460191f3a891ca3d10d6u128,
            ],
            [
                0x331ba17b640b10377b8daacb47b96f00u128,
                0x2dd0472d642b5dac1e035e1415b85e78u128,
                0xb16abfd757b94f87fe31890e549fcf2bu128,
            ],
            [
                0xa47e2572d009d69a2aeb570088c587acu128,
                0x627ee86896f0cf88f98cedf0932166e0u128,
                0xe653b402159545bce28eb4aa17f15b02u128,
            ],
            [
                0x22180eb716fff3816541636ffd45f952u128,
                0x7d4943c1988c2a51fcd231fe45d5203cu128,
                0xbcff209a45d70e3a070c9916d2fb6cbeu128,
            ],
            [
                0xf83ff1db38480f0f62e8a318edb70addu128,
                0xa742319e2c018a4561356d46dcef2951u128,
                0xac887e57f72fec8609ae361da827f2f5u128,
            ],
            [
                0x19eb0deb482cf1b3fc652ca0f7586ee5u128,
                0x534e7c1b847e7e1c767f042a293a7f65u128,
                0xda950eec97f6173e64ac3481d3289cadu128,
            ],
            [
                0x7158da967569ed2655bb5e4a557f38d3u128,
                0x5157a7d836046f91177040141d03540au128,
                0xd40003c5555e46608a0fc5ac6ea43670u128,
            ],
            [
                0xec53f9fb127fb662026e28bedd859d37u128,
                0x343cb18a754b9608c2f1f4240e9d813au128,
                0xd8f23728ba3130c92815136e67ce4398u128,
            ],
            [
                0xb36445f2cf0dc8f6f651df5560224244u128,
                0x8c7518ec10746401192f4860293d1531u128,
                0x09a3cb0fc2ed078bc3ca05c5a63fb026u128,
            ],
            [
                0xa65bcfbb29ad402eb95bb8eb2eab9a21u128,
                0x50944c68ba6a5a07a0e06946e68693f0u128,
                0xa98bc6e1eb8892c0a2654e0cb5d2e7eau128,
            ],
            [
                0x12d89444a804c6fb6b04cedefbc705fau128,
                0xe6620892bfb5b4547fb305e07441be49u128,
                0x11d949da38f8b28236b0bf3f01f3a7e3u128,
            ],
            [
                0x6602400cceb5f17660b598788c05879bu128,
                0x47e26917d25afbea583c9aaa81ef389du128,
                0xe9edd98d9bec1331fa505743a742855au128,
            ],
            [
                0xefcdab8967452301efcdab8967452301u128,
                0x0123456789abcdef0123456789abcdefu128,
                0x7bb4ed130ac59c43da154cb2ab643de2u128,
            ],
            [
                0xefcdab8967452301efcdab8967452301u128,
                0x00000000000000000123456789abcdefu128,
                0x40404040404040403bf4ad534a85dc22u128,
            ],
            [
                0xded6351ebc119016ded3e9b7f4305f7cu128,
                0x02d17072ee962ae22516f322af681e30u128,
                0x041012ceca0f0dcf450400f6623ad3f3u128,
            ],
            [
                0xcc8f7c7d14efaf53fc072396d275abf5u128,
                0x653ec081eded0551b6a67e5b0a5e8b91u128,
                0xe131b96212d21fe3e7415f47ada6a1e7u128,
            ],
            [
                0xd9f53cf39f528b7f802494fb0029c4ffu128,
                0xd2f5418bb53859982d8ac14f0e299525u128,
                0x7fa17adfd4cf081df7ca61878636dc44u128,
            ],
            [
                0x73b310fc304b08a5381cd5184f80ca5fu128,
                0xbe507887c8ab285e6802175acd2c0568u128,
                0x8e33ad4d691a60e1b71bf1e1d686e287u128,
            ],
            [
                0xf7efed5c1d00c15545822fb465dd284du128,
                0x4c69b5b9f28b019840560651c7feecf2u128,
                0x29fccdba597bc0edd576c5ef6eb2994eu128,
            ],
            [
                0x954446b2ddf6d114400ac48fb201e685u128,
                0x02927c526e2eb8d0905f7f498dc931aeu128,
                0x82be98684956c222d793822c4d916de9u128,
            ],
            [
                0xd181d6288cda33f653fd89964d06f342u128,
                0xc9f1b41a2b3d6b2dda31e5e4e33c0a26u128,
                0x92ae9047dc49a150a2a94ded26683582u128,
            ],
            [
                0x8d725291d3a8b7c983a882fe8f924f89u128,
                0x346275eebbf40ed96d2488ed9a4374e0u128,
                0xac24dbfa76090d388774ce5956cc186fu128,
            ],
            [
                0x8fd8b8a05147492e80063434bcff9df4u128,
                0x5072eda799ef0003cfa71e023a0f95c0u128,
                0xdccb08b426858892bc94978854ebdd1eu128,
            ],
            [
                0xdfe56bf10488b3c7fcc2e82b78c81577u128,
                0xa64ddef4606ae573287312bc21925122u128,
                0xebe547d1e89ed889104f44e2d0e50faeu128,
            ],
            [
                0x2fdc5b901cc24818020ac926e028aeeeu128,
                0x589e96e559704d28832411da5cbf3828u128,
                0xf4db638a5baf9cdf261e0c9133be0563u128,
            ],
            [
                0xa0769fe5ba1988629e61d42b03bdda72u128,
                0x973dfe5fdb499dc683c3d8d39115de23u128,
                0x01a76c47b9e56ba70fdb67b966c31931u128,
            ],
            [
                0xc13d3a4044faf641d78243f81218da2fu128,
                0x44e954f152dff897f9a3de788c9bb562u128,
                0xc56ebadfd4b55634b71aa90ad11df3b2u128,
            ],
            [
                0xe54254237b2dd6cbc3aabf8e93f96970u128,
                0x25589772cb41a8349b775b8fad1be4beu128,
                0xcec9699eb43d3d0745db2b0f6e369d35u128,
            ],
            [
                0x23ef4b5a50949bba2d55d8e55074e0dau128,
                0x5fd5ba3308d4bb723255dfaa632ded94u128,
                0x6467bd6eb682c1cd7b3363fb08aaa579u128,
            ],
            [
                0x7982da0716085826a4ee46193a7704dcu128,
                0xd0a79fb3e4f3bbe9b8b353c2f525b038u128,
                0x673c92cc6af78aa8a3f95eaa9c7fc6feu128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0xef67cba6c9d0a6baaf4ec35d854c4f71u128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0xb9ed9b3b48720bd5a5619f34b61c64e2u128,
            ],
            [
                0xee659cbc5d0f9c85979f235a98bc4c59u128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0xad7af31cc11f2c33850475df39c911f2u128,
            ],
            [
                0xc45b9ab820b11c78e3173cc91f873abdu128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0x3d48938113f75ad981ba3e62ea443ca4u128,
            ],
            [
                0x4a7cda296a4b5310e2a8c3d55f63ffedu128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0xa473ca6c086b9ab6d15322f640d77800u128,
            ],
            [
                0xb45b5571a13411be06dae7cae0146dd1u128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0xab1e2d6cf54a76b09f9463173b7e5d4au128,
            ],
            [
                0x5930ca658580b8ab845b6614a629be56u128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0x99f1961f2976da354aef89541706e15eu128,
            ],
            [
                0x73494f734a7b61e7fd9937796e3b148du128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0xe8262ee3f3697f116fb0832ffbeaaa39u128,
            ],
            [
                0x526d6ad174e9291a72e32d92a11345f7u128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0x59c1b079053b3a338ab5489b112828b7u128,
            ],
            [
                0x2122646df3351f282c293571e13d311au128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0xfdd62741f961ebf53939400f7660d6ceu128,
            ],
            [
                0x6c2defa16c829763ed53a6d855293266u128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0xcf5c42ef6e625fd37cfe1ff61c123f96u128,
            ],
            [
                0x2e48b9eca06a6937dd3be8a1c614a4d3u128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0x393e55ead179ca1b54ffb71a0d731a48u128,
            ],
            [
                0x1282cab02c8c5b063c73040b270f5c3fu128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0xd4469bb12a7d35315b6d45b3e62dec4du128,
            ],
            [
                0x26b889f1c727ebdd871abc2b87f9960eu128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0x65f6f63be9385504b79cd76149846ed5u128,
            ],
            [
                0xe3261a2a74a9f40776f8b376d4261bfbu128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0xedae3ae568af418a21db80a0cf0771d6u128,
            ],
            [
                0x272ef829cbe808a49fdb7395d1d6ff78u128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0x6f1f8b0b6debee91cdfe9377a2c2e5b8u128,
            ],
            [
                0x1732921422ecd5671d8af1f90d8fe096u128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0x926231cff2e773c42ac41854bfe6950du128,
            ],
            [
                0x11ce670791802cd7be78058aac6386a9u128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0x52500f5ba93f4a8bd4871e62674445aau128,
            ],
            [
                0x5fd21d6f6304b275dcbb996ade5979f1u128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0x8a432d04a0f64d5ff441ca2985835672u128,
            ],
            [
                0x561eb476fec586cc1d5da4a294320d27u128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0x8495a28b1063eb1d24097d8e955514a8u128,
            ],
            [
                0xa1af963a5cd87bc4628f6c425564aab3u128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0xd79d85d4ad64f08950b0ba38c3e2c6b2u128,
            ],
            [
                0xcdd8a4d34ded18f046aa3148ad6d457fu128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0xd13b460562c9d8644839ea93a7f1872eu128,
            ],
            [
                0x8fc1877f997be46d42904263ec9ff2f2u128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0x67a3d72f4606676cf5d9969e639d11e9u128,
            ],
            [
                0x9dd7171da4b75cb7944e8d0dbdd392f2u128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0x92bf895a89f8b28e99c4283b9817138cu128,
            ],
            [
                0xa8a807a31bafc8b6e420307e65f1ec6du128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0xdff217b7d274130d21f4bce69cfdd226u128,
            ],
            [
                0x1cb68f4a7c1bae2f893157d5d39b77a7u128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0xf0d219162e4858358ea1da465f2f7a2cu128,
            ],
            [
                0xa57e2d50397594633362359de24d7c15u128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0xacdcf928ed5f92131a5222e8dbe55007u128,
            ],
            [
                0x2c6702bd6ba4647fd0b5c23ccad033f7u128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0xa5454834da254dd7335be899940c6737u128,
            ],
            [
                0xd379138579386e23af46f05b73fb19edu128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0x322077c61a31c833ce523ba74c332d0au128,
            ],
            [
                0xa473fea7bcde85b4892089bcd1cac060u128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0x804dfc7e52b66cc3cc6faff103bca0adu128,
            ],
            [
                0x6e8b2e72dcc26a379477882061d1526au128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0x2cebb8db86cbf0b3a59e268d1b2dc19fu128,
            ],
            [
                0x43423d0e8108d2c6a05b55a842d24558u128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0xda021b4ca5e4c0e0f0ab7ba26f664ab6u128,
            ],
            [
                0x4036a6eaa832de6f0ee9adc915da8f5fu128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0xa5255da37647de8e0854814c0ac500acu128,
            ],
            [
                0x11549b692772a884893789d86979b752u128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0x3c02e486d182b7ad0a0dfe16e2ac2f0cu128,
            ],
            [
                0x56cb2b8624f9653b3192fa514ec98b3bu128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0x3abf145115549fae47bcadc21c0d509fu128,
            ],
            [
                0x2998fc1bbab3b20e80e80a623e7437b6u128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0x2e0ae54b94773b87e336b1b73b1c7eb1u128,
            ],
            [
                0x090d5f123f252617be95cd9ba5050d74u128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0x11276aa277838aa62cf2ff33616d4896u128,
            ],
            [
                0xf671ee7e1b54a20c09439339faf57f77u128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0x68918d358b22014b56ace45f39c88becu128,
            ],
            [
                0xb1258dcf0cc9eba5fdd7d1ee183aa156u128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0xe2e048ebdb9599da2be19660587c8163u128,
            ],
            [
                0x615fe5a0549851d0817b324b38062820u128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0x193294084437f5a054e92ca4665bf08eu128,
            ],
            [
                0xcbf7c5ce84d390a9c39d64fd13098a35u128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0xe31464b78d3ca770bc8bf3825c36c064u128,
            ],
            [
                0x1a8cfe729a96f8c1912e0aebe77e31bfu128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0xef08a7921198265e715ad8d59de1714cu128,
            ],
            [
                0xf76030a62e2394f42ed47a963783ef7eu128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0x16cda9c65ecc120bb5d22740a90a3cddu128,
            ],
            [
                0x8adc4392537c3dbae77ee22ccbe89a49u128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0xf9939fd6c5d0b372c63e2336bb941934u128,
            ],
            [
                0x8544956ca794ab2de55a4c01f0e6957eu128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0xd0fea3eadef76e9049aeb9c501a927bcu128,
            ],
            [
                0xfcaf80672fd69f27ccf820db89dca36au128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0x53fe1e652dde8971dbb0a6f4ee511248u128,
            ],
            [
                0x1b42fa44a824643d46dc2671ed59583au128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0x55a082b43977b33018198430298e1972u128,
            ],
            [
                0x35459c7223d2c85f8aeb9e8dcd1d752du128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0x52a6aecfa4105c4e0e074f396ff6a778u128,
            ],
            [
                0x32a5bc67c41f34b05ff3caa88f3c315fu128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0x754add502b4916302bd2184cbeb50c10u128,
            ],
            [
                0x852a53e186b5b1e57d03c7ef9c1a76cdu128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0xd22188714c019e1785f0a3b7951c70e1u128,
            ],
            [
                0xe92f9b8b70ff2056e404534792334e92u128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0x28be3b07e9586e3ee626af560690b1b8u128,
            ],
            [
                0x5f2218cf49d9b95fbc16dc6aba030c0au128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0xb5f86471e9aeca9d7ed4e0933a9b9840u128,
            ],
            [
                0x4d566b2969b1ec0d352a8310ca9a1189u128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0xe63c807a04353f398374f1f2d7526577u128,
            ],
            [
                0xadc63d0b9c9b5551cb7efcc20d8687b2u128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0x1fbc4afd0633619176f136e8c91530e2u128,
            ],
            [
                0x739514f6345b92e9b300bd25c4406e33u128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0xe574cb1e0fc0286999b4ba1bbb3a9490u128,
            ],
            [
                0xf6f97ff43bec1cfb19a5dcdc4300838eu128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0xc0599bc116755633656a811fa71f997fu128,
            ],
            [
                0x02f81c9491745b5841ee9f3b0d768cb9u128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0x175ba748b073d9f09927e415780b90efu128,
            ],
            [
                0x244d88e033d0f73b9aef79ffbe47b41du128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0x95fe9e8c8cfbb6687f9d57ddfad06518u128,
            ],
            [
                0x624427de97b2d7281133f3e7ce5af9a8u128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0x42a76dccbddc5bebcae80dc920af6a60u128,
            ],
            [
                0x51dc83003180f5dc9678e2d01e69a59bu128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0x3fbdcad41bd13e822f8c83e9ace1ab8cu128,
            ],
            [
                0x03232d0f21a1c3c3cba987e913622a09u128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0x44e74fdf6686cd3f985f10d8163f2617u128,
            ],
            [
                0x551f56fe1900a1e10c5a366ffc5ad678u128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0xcef87f08347dab412a3a27557dd5ac92u128,
            ],
            [
                0x79656fd874c0b6d6409ff160ba7b7843u128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0x77e5b302605e13350e2b8f360f52ca71u128,
            ],
            [
                0x59086a9cb5da7b9c852db9fa47872908u128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0xa813bbcbbc866d311301a50f9a0387d8u128,
            ],
            [
                0x72179449b2dcd76a8e45f3a8e6b72eb3u128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0xd909cab073f35b26546bbe76f44fd7dfu128,
            ],
            [
                0x491ea6265fb2b5ff72c5de9f3b2757f4u128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0xeeb3bf8a001c20129097bc4ac65a7765u128,
            ],
            [
                0xdd084fbb410e28e6f53e72ada8a40b7au128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0xbc832c19f876453a0d812cc5dfb9ab63u128,
            ],
            [
                0xdff1d4906182b5434089ae1e40ae79fdu128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0xadc4bfb66e372e6143e823898884251eu128,
            ],
            [
                0x7bc80231cf690a86196dec7447b3dd5bu128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0x9578d598c78e413dc6287f92412b456cu128,
            ],
            [
                0x12e5b269b09b03873444fbe53edbea51u128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0x8e19e6c79faef15b9fee9ba58a0ae1d6u128,
            ],
            [
                0xedf6f7dbc483b76f738a8e5fe2b2bc95u128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0xb8528c6c7e6282b2942dfd9bf07811d9u128,
            ],
            [
                0xb798f5c92d8dbc20601ed76f396c5e4au128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0xba786749233add3c3d8277700c8d6385u128,
            ],
            [
                0xfd69ea6dbe121663df70a8256656bd1eu128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0x2aba72c410239ac86ecd616f810e334cu128,
            ],
            [
                0x629268d68962665ffe292312e80fad04u128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0xf8de44d22d593b7b20868a3bf56d56d1u128,
            ],
            [
                0xcb33327feda04503830b0ad443a485b7u128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0xdda0b240eb6c2ca432ccf163d1c7c8deu128,
            ],
            [
                0xe04d2ff812d1c9513741d2bef13195eeu128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0xa6372830433f2f79c95341cf9ac1b5deu128,
            ],
            [
                0xc9fa0910ea222c2097d4e34cde3e959du128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0x3f1abbf621f4b11e1d3e099e28e71500u128,
            ],
            [
                0x8de8acdc59b3640ecfcb2485be91c613u128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0x1acc3ddc52085d0a48d54e73bac49eaeu128,
            ],
            [
                0xadd6460e269729a21d2bcb79961b83aau128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0x1cb776ea195cdd3210d3b2b66b4da387u128,
            ],
            [
                0xe84a7aa51a953f922153ad9c744a610fu128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0x525263e727b91c885d64f00a0b983946u128,
            ],
            [
                0x7bc88df64dadb4905d22fc5970b5dd39u128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0x8ad40fbec79b91c1042b6c5010ea97fcu128,
            ],
            [
                0x2b494239d391cf16772461b59b44f029u128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0x714ab57dd3fa4f1f6d90301af4ecf8a7u128,
            ],
            [
                0xe8a1cac79f50ea280643a6b806bf644cu128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0x694e7e4b29512448e22b970985bbb2f2u128,
            ],
            [
                0x9ddbb64aa0e9188cbbe112411eb188d1u128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0x69603c37fa07f6efd06995cbc03da76eu128,
            ],
            [
                0xbcdcdea83dc90cd314959b3a69601587u128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0x019ec8668e3b58a5ce4cbc86054b46feu128,
            ],
            [
                0x01f1195f7fad9478f6e7896ce01218d2u128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0x65d88e6e66773219f3f52c09c86e556bu128,
            ],
            [
                0x321c01bc9f5f291e55c9efecc2157e52u128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0xc9acfe47b27e8c8379e7a5ed0bf19407u128,
            ],
            [
                0xe7b674917da63678c21c69b11be279acu128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0x4df5bd8968f84efda37e334b510922e3u128,
            ],
            [
                0xd627ce568dd03027461c9e6be616d9f6u128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0x2a7a21de7034786d0b9eb494073eb4a1u128,
            ],
            [
                0x482b49d016b37e8ab42bb5dced6fca13u128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0x1458c00fd3cfb610bf476292e7dbf8e8u128,
            ],
            [
                0x0d68e305d507dc1e69a2ee069789aec2u128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0xc6da928ebb04e138ea9a5fa03b780027u128,
            ],
            [
                0x384f2ab88ebf9ba17932a6169896d742u128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0xb035dde1d83a8c0895fb8c72b0dfc398u128,
            ],
            [
                0xba8496972a94bcb80ed8675767f7bc69u128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0xf439e1fd20864b9a847fb91154f2c8d6u128,
            ],
            [
                0xc64cf639431153c91c35d51a7ef766abu128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0x6036f6a989315b3a98af9f3b9bddf848u128,
            ],
            [
                0x4f4b50b603c3c80275959f51c725fdacu128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0x788e77b2e337e278321fcbd2e66a70a9u128,
            ],
            [
                0xa70de02106713f67116cd5b3e383474bu128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0x90ca5e33173b47588eda3bd90c305f5cu128,
            ],
            [
                0x342e76c98c6e5378ba506717be3f7805u128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0xc23e4ac2c40dcace12ab376f1ecae6c2u128,
            ],
            [
                0x21c3008f5df958fa38a174e4907441a9u128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0x659c52059d2ce342abf194ad141f233au128,
            ],
            [
                0x4032c35a5e7aa9128edd138d31336fbdu128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0x2c070e85b54e870696dd8badfd1c0ce0u128,
            ],
            [
                0xd598419694b4743abd35f360803c408fu128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0x7981907f05d6a7f2894c120ef37ff11eu128,
            ],
            [
                0xf1b238281fff1fc038303c2a56e0c53du128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0x8796c00c8cc28f155d33aad2faa87b05u128,
            ],
            [
                0x7fdc8ca4400b84e893b785460aa054b6u128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0xff443df80e3c96661a0d3388c421f1a3u128,
            ],
            [
                0x098a838636aeb4c8ececc1bff3657900u128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0xf17f0668f187e7b000e63e0965bd8fe5u128,
            ],
            [
                0xbfa72807c798a35248ee295b2f82f695u128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0xeaf6f5e4f0000971aa77a1d2b9c6bd47u128,
            ],
            [
                0xa6d9c275acadf0f3f14290919f5eb6a1u128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0x764a8dd5948a9853d4b79200892284d6u128,
            ],
            [
                0x48cb54050bdf71dd0aeece0afdfabac3u128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0xcd0bcf36962f87c88b044026bd8864fbu128,
            ],
            [
                0xb1a8cbe0a417a3670124cf7836591174u128,
                0x053d8555a9979a1ca13fe8ac5560ce0du128,
                0xb1da789cd9eb6f1ab0f47bceef63a641u128,
            ],
            [
                0x9dc9c90544fc2d5f386c7b7f4de29d22u128,
                0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
                0x777ea6c5ed1818339434f153164bcd1au128,
            ],
            [
                0xcb89351078ec6a04be43174bacbf5cd2u128,
                0x35ad604f7d51d2c6bfcf02ae363946a8u128,
                0x57c7041c523ef4fc1c0a71f9700ed0d4u128,
            ],
            [
                0xe85a61997986c5fd988231c4ec16888eu128,
                0x0dcb364640a222fe6b8330483c2e9849u128,
                0x4dd635665d937c35e07f4781fe1e3242u128,
            ],
            [
                0x7b76efc842fcb221764bada7e28aa59au128,
                0x549810e11a88dea5252b49277b1b82b4u128,
                0x84054409e4bb8d380dc0ff21ad5df3efu128,
            ],
            [
                0xe101210e923d079443774cbafbeffc88u128,
                0xd681a5686c0c1f75c72bf2ef2521ff22u128,
                0xe80dd50e05fc33871932ab510399bd53u128,
            ],
            [
                0x64fd220b811d50fd4ffd9bdb0a8f82a4u128,
                0x0950311a4fb78fe07a7a8e94e136f9bcu128,
                0xe57c958200d10964ae1eddb8ea34f004u128,
            ],
        ];
        for data in database {
            let mut left = GF128::new(data[0], 0);
            let mut left_2 = GF128::new(data[0], 0);
            let right = GF128::new(data[1], 0);
            let result = GF128::new(data[2], 0);
            let res = left * right;
            let res_rev = right * left;
            let (first_value, second_value) = res.get_value();
            assert_eq!(first_value, result.get_value().0);
            assert_eq!(second_value, result.get_value().1);
            //to test commutativity
            assert_eq!(res, res_rev);
            //to test with ref
            #[allow(clippy::op_ref)]
            let res_rev = &left * &right;
            #[allow(clippy::op_ref)]
            let res = left * &right;
            assert_eq!(res, result);
            assert_eq!(res_rev, result);
            //to test mulassign
            left *= right;
            left_2 *= &right;
            assert_eq!(left, result);
            assert_eq!(left_2, result);
        }
    }

    #[test]
    //input : one GF128 and one GF128 restricted to 64 memory bits
    //output : the product of the two according to the rules of Galois Fields arithmetic
    #[allow(clippy::erasing_op)]
    fn gf128_test_mul_64() {
        let mut rng = rand::thread_rng();

        let pol_0 = GF128::default();
        for _i in 0..1000 {
            //0 * anything = 0
            let anything: u64 = rng.gen();
            let pol_res = pol_0 * anything;
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, 0u128);
            assert_eq!(second_value, 0u128);
            //1 * anything = anything
            let pol_res_1 = GF128::ONE * anything;
            let (first_value_1, second_value_1) = pol_res_1.get_value();
            assert_eq!(first_value_1, anything as u128);
            assert_eq!(second_value_1, 0u128);
            //anything * 0 = 0
            let anything: GF128 = rng.gen();
            let pol_res_rev = anything * 0u64;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, 0u128);
            assert_eq!(second_value_rev, 0u128);
            //anything * 1 = anything
            let (first_value_anything, _second_value_anything) = anything.get_value();
            let pol_res_rev = anything * 1u64;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, first_value_anything);
            assert_eq!(second_value_rev, 0u128);
        }
        //to test with complex values we use the tests values of the reference implementation
        let mut left = GF128::new(0xefcdab8967452301efcdab8967452301u128, 0);
        let mut left_2 = GF128::new(0xefcdab8967452301efcdab8967452301u128, 0);
        let right = 0x0123456789abcdefu64;
        let result = GF128::new(0x40404040404040403bf4ad534a85dc22u128, 0);
        let res = left * right;
        assert_eq!(res, result);
        //to test with ref
        #[allow(clippy::op_ref)]
        let res_rev = &left * right;
        #[allow(clippy::op_ref)]
        let res = left * right;
        assert_eq!(res, result);
        assert_eq!(res_rev, result);
        //to test mulassign
        left *= right;
        left_2 *= right;
        assert_eq!(left, result);
        assert_eq!(left_2, result);

        let (first_value, second_value) = res.get_value();
        assert_eq!(first_value, result.get_value().0);
        assert_eq!(second_value, result.get_value().1);
    }

    #[test]
    //input : one GF128 and one GF128 restricted to 1 memory bits
    #[allow(clippy::erasing_op)] //output : the product of the two according to the rules of Galois Fields arithmetic
    fn gf128_test_mul_bit() {
        let mut rng = rand::thread_rng();

        for _i in 0..1000 {
            //anything * 0 = 0
            let anything: GF128 = rng.gen();
            let pol_res_rev = anything * 0u8;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, 0u128);
            assert_eq!(second_value_rev, 0u128);
            //anything * 1 = anything
            let (first_value_anything, second_value_anything) = anything.get_value();
            let pol_res_rev = anything * 1u8;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, first_value_anything);
            assert_eq!(second_value_rev, 0u128);
            //anything_1 * anything_2 (odd) = anything_1
            let anything_2 = rng.gen::<u8>() | 1u8;
            let pol_res_2 = anything * anything_2;
            let (first_value_2, second_value_2) = pol_res_2.get_value();
            assert_eq!(first_value_2, first_value_anything);
            assert_eq!(second_value_2, second_value_anything);
            //anything_1 * anything_2 (even) = 0
            let anything_3 = rng.gen::<u8>() & u8::MAX << 1;
            let pol_res_3 = anything * anything_3;
            let (first_value_3, second_value_3) = pol_res_3.get_value();
            assert_eq!(first_value_3, 0u128);
            assert_eq!(second_value_3, 0u128);
        }
    }

    #[test]
    //input : two GF128
    //output : the result of the and bitwise operation on the two inputs
    fn gf128_test_and() {
        let mut rng = rand::thread_rng();

        for _i in 0..10000 {
            let random_1_1 = rng.gen();
            let random_2_1 = rng.gen();
            let pol_1 = GF128::new(random_1_1, 0u128);
            let pol_2 = GF128::new(random_2_1, 0u128);
            let pol_res = GF128::and(&pol_1, &pol_2);
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, random_1_1 & random_2_1);
            assert_eq!(second_value, 0u128);
        }
    }

    #[test]
    //input : two GF128
    //output : the result of the xor bitwise operation on the two inputs
    fn gf128_test_add() {
        let mut rng = rand::thread_rng();

        for _i in 0..10000 {
            let random_1_1 = rng.gen();
            let random_2_1 = rng.gen();
            let mut pol_1 = GF128::new(random_1_1, 0u128);
            let pol_2 = GF128::new(random_2_1, 0u128);
            #[allow(clippy::op_ref)]
            let pol_res = pol_1 + &pol_2;
            let pol_res_2 = pol_1 + pol_2;
            #[allow(clippy::op_ref)]
            let pol_res_3 = &pol_1 + &pol_2;
            let res = GF128::new(random_1_1 ^ random_2_1, 0u128);
            assert_eq!(pol_res, res);
            assert_eq!(pol_res_2, res);
            assert_eq!(pol_res_3, res);
            pol_1 += pol_2;
            assert_eq!(pol_1, res)
        }
    }

    #[test]
    //To dest those one we use the test dataset of the reference implementation
    fn gf128_test_byte_combine() {
        let database = [
            [
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x7dd279dc939e98fe717ad213176f6aaau128,
                0xef67cba6c9d0a6baaf4ec35d854c4f71u128,
                0xee659cbc5d0f9c85979f235a98bc4c59u128,
                0xc45b9ab820b11c78e3173cc91f873abdu128,
                0x4a7cda296a4b5310e2a8c3d55f63ffedu128,
                0xb45b5571a13411be06dae7cae0146dd1u128,
                0x5930ca658580b8ab845b6614a629be56u128,
                0x73494f734a7b61e7fd9937796e3b148du128,
                0x2ab7dd862e3aace3bb3d4d00e5bb4d33u128,
            ],
            [
                0xac1968cce62d45a300336dc3598210a4u128,
                0x526d6ad174e9291a72e32d92a11345f7u128,
                0x2122646df3351f282c293571e13d311au128,
                0x6c2defa16c829763ed53a6d855293266u128,
                0x2e48b9eca06a6937dd3be8a1c614a4d3u128,
                0x1282cab02c8c5b063c73040b270f5c3fu128,
                0x26b889f1c727ebdd871abc2b87f9960eu128,
                0xe3261a2a74a9f40776f8b376d4261bfbu128,
                0xa272bf9e0e8620125694dfc94f05384du128,
            ],
            [
                0x1be85a1f0db4b9e64f9c619d6e273e26u128,
                0x272ef829cbe808a49fdb7395d1d6ff78u128,
                0x1732921422ecd5671d8af1f90d8fe096u128,
                0x11ce670791802cd7be78058aac6386a9u128,
                0x5fd21d6f6304b275dcbb996ade5979f1u128,
                0x561eb476fec586cc1d5da4a294320d27u128,
                0xa1af963a5cd87bc4628f6c425564aab3u128,
                0xcdd8a4d34ded18f046aa3148ad6d457fu128,
                0xbcb5a3de44bfe097b4e013d06082087fu128,
            ],
            [
                0xfd9fe669622774ce35503d475e1530e1u128,
                0x8fc1877f997be46d42904263ec9ff2f2u128,
                0x9dd7171da4b75cb7944e8d0dbdd392f2u128,
                0xa8a807a31bafc8b6e420307e65f1ec6du128,
                0x1cb68f4a7c1bae2f893157d5d39b77a7u128,
                0xa57e2d50397594633362359de24d7c15u128,
                0x2c6702bd6ba4647fd0b5c23ccad033f7u128,
                0xd379138579386e23af46f05b73fb19edu128,
                0x1c1a70677caefde311431494659780b4u128,
            ],
            [
                0x00f7542fa4c6f755e3460fcb49191bbau128,
                0xa473fea7bcde85b4892089bcd1cac060u128,
                0x6e8b2e72dcc26a379477882061d1526au128,
                0x43423d0e8108d2c6a05b55a842d24558u128,
                0x4036a6eaa832de6f0ee9adc915da8f5fu128,
                0x11549b692772a884893789d86979b752u128,
                0x56cb2b8624f9653b3192fa514ec98b3bu128,
                0x2998fc1bbab3b20e80e80a623e7437b6u128,
                0xfbc143f9f3b966cfdccf9e3af19631b0u128,
            ],
            [
                0x7792a5963bbdcb8974b41c76339ed874u128,
                0x090d5f123f252617be95cd9ba5050d74u128,
                0xf671ee7e1b54a20c09439339faf57f77u128,
                0xb1258dcf0cc9eba5fdd7d1ee183aa156u128,
                0x615fe5a0549851d0817b324b38062820u128,
                0xcbf7c5ce84d390a9c39d64fd13098a35u128,
                0x1a8cfe729a96f8c1912e0aebe77e31bfu128,
                0xf76030a62e2394f42ed47a963783ef7eu128,
                0xef27f4019ad6bf3b09e1b1c93dc1e716u128,
            ],
            [
                0x77abf19b2c731f125bb34fe4ebf5cb98u128,
                0x8adc4392537c3dbae77ee22ccbe89a49u128,
                0x8544956ca794ab2de55a4c01f0e6957eu128,
                0xfcaf80672fd69f27ccf820db89dca36au128,
                0x1b42fa44a824643d46dc2671ed59583au128,
                0x35459c7223d2c85f8aeb9e8dcd1d752du128,
                0x32a5bc67c41f34b05ff3caa88f3c315fu128,
                0x852a53e186b5b1e57d03c7ef9c1a76cdu128,
                0xad55aa98e0a52cd8b7af0311d24825a3u128,
            ],
            [
                0xeb36bf7a86dad5a244c1511d9376ca31u128,
                0xe92f9b8b70ff2056e404534792334e92u128,
                0x5f2218cf49d9b95fbc16dc6aba030c0au128,
                0x4d566b2969b1ec0d352a8310ca9a1189u128,
                0xadc63d0b9c9b5551cb7efcc20d8687b2u128,
                0x739514f6345b92e9b300bd25c4406e33u128,
                0xf6f97ff43bec1cfb19a5dcdc4300838eu128,
                0x02f81c9491745b5841ee9f3b0d768cb9u128,
                0xbd86dd1c2dec88034c4f06d3d5142b5cu128,
            ],
            [
                0x4fe18e6caa7741d4609f393ec67ec464u128,
                0x244d88e033d0f73b9aef79ffbe47b41du128,
                0x624427de97b2d7281133f3e7ce5af9a8u128,
                0x51dc83003180f5dc9678e2d01e69a59bu128,
                0x03232d0f21a1c3c3cba987e913622a09u128,
                0x551f56fe1900a1e10c5a366ffc5ad678u128,
                0x79656fd874c0b6d6409ff160ba7b7843u128,
                0x59086a9cb5da7b9c852db9fa47872908u128,
                0xf2ec8fe60ea28aaf5529fd774e5ba7bcu128,
            ],
            [
                0x07edd0b090dd4747d0027e7022a2bf70u128,
                0x72179449b2dcd76a8e45f3a8e6b72eb3u128,
                0x491ea6265fb2b5ff72c5de9f3b2757f4u128,
                0xdd084fbb410e28e6f53e72ada8a40b7au128,
                0xdff1d4906182b5434089ae1e40ae79fdu128,
                0x7bc80231cf690a86196dec7447b3dd5bu128,
                0x12e5b269b09b03873444fbe53edbea51u128,
                0xedf6f7dbc483b76f738a8e5fe2b2bc95u128,
                0x82238916533165fc977c6aac7cd324d4u128,
            ],
            [
                0x75ff6228e4965e70f2ec37fd75d97c96u128,
                0xb798f5c92d8dbc20601ed76f396c5e4au128,
                0xfd69ea6dbe121663df70a8256656bd1eu128,
                0x629268d68962665ffe292312e80fad04u128,
                0xcb33327feda04503830b0ad443a485b7u128,
                0xe04d2ff812d1c9513741d2bef13195eeu128,
                0xc9fa0910ea222c2097d4e34cde3e959du128,
                0x8de8acdc59b3640ecfcb2485be91c613u128,
                0x43a22f2d2179cd362f515c98d4128c20u128,
            ],
            [
                0xd22f12adde4d533426bf022d88740a02u128,
                0xadd6460e269729a21d2bcb79961b83aau128,
                0xe84a7aa51a953f922153ad9c744a610fu128,
                0x7bc88df64dadb4905d22fc5970b5dd39u128,
                0x2b494239d391cf16772461b59b44f029u128,
                0xe8a1cac79f50ea280643a6b806bf644cu128,
                0x9ddbb64aa0e9188cbbe112411eb188d1u128,
                0xbcdcdea83dc90cd314959b3a69601587u128,
                0x66e43779a9a4c652febda29f4c6aacfau128,
            ],
            [
                0xc17b6c2bd1d59f62183d386ed85fcb10u128,
                0x01f1195f7fad9478f6e7896ce01218d2u128,
                0x321c01bc9f5f291e55c9efecc2157e52u128,
                0xe7b674917da63678c21c69b11be279acu128,
                0xd627ce568dd03027461c9e6be616d9f6u128,
                0x482b49d016b37e8ab42bb5dced6fca13u128,
                0x0d68e305d507dc1e69a2ee069789aec2u128,
                0x384f2ab88ebf9ba17932a6169896d742u128,
                0x68370f35ade1cc48fae98715218ba769u128,
            ],
            [
                0x95011ff4a6680587e77706b6492bd24au128,
                0xba8496972a94bcb80ed8675767f7bc69u128,
                0xc64cf639431153c91c35d51a7ef766abu128,
                0x4f4b50b603c3c80275959f51c725fdacu128,
                0xa70de02106713f67116cd5b3e383474bu128,
                0x342e76c98c6e5378ba506717be3f7805u128,
                0x21c3008f5df958fa38a174e4907441a9u128,
                0x4032c35a5e7aa9128edd138d31336fbdu128,
                0x62ef376317bc1e8d68e5f8f89b970439u128,
            ],
            [
                0xfe6f51fe71b06335f214e86f11ce5457u128,
                0xd598419694b4743abd35f360803c408fu128,
                0xf1b238281fff1fc038303c2a56e0c53du128,
                0x7fdc8ca4400b84e893b785460aa054b6u128,
                0x098a838636aeb4c8ececc1bff3657900u128,
                0xbfa72807c798a35248ee295b2f82f695u128,
                0xa6d9c275acadf0f3f14290919f5eb6a1u128,
                0x48cb54050bdf71dd0aeece0afdfabac3u128,
                0x5ff48d1af5ba2ceec9442ec634e9fd60u128,
            ],
            [
                0x40c4fcceb917eeeec2192ddb491475e2u128,
                0xb1a8cbe0a417a3670124cf7836591174u128,
                0x9dc9c90544fc2d5f386c7b7f4de29d22u128,
                0xcb89351078ec6a04be43174bacbf5cd2u128,
                0xe85a61997986c5fd988231c4ec16888eu128,
                0x7b76efc842fcb221764bada7e28aa59au128,
                0xe101210e923d079443774cbafbeffc88u128,
                0x64fd220b811d50fd4ffd9bdb0a8f82a4u128,
                0x1505176863dfa6d5a04018f67adc4297u128,
            ],
        ];
        for data in database {
            let mut tab = [GF128::default(); 8];
            for i in 0..8 {
                tab[i] = GF128::new(data[i], 0u128);
            }
            let result = GF128::new(data[8], 0);
            assert_eq!(GF128::byte_combine(&tab), result);
        }
    }

    #[test]
    //input : a bit (or a byte or many)
    //output : a GF128 whose light-weight bit is equal to the input bit (or the lightweight bit of the input value)
    fn gf128_test_from_bit() {
        //with bit = 0
        let bit_1 = 0u8;
        let res_1 = GF128::from_bit(bit_1);
        let (first_value_1, second_value_1) = res_1.get_value();
        assert_eq!(first_value_1, bit_1 as u128);
        assert_eq!(second_value_1, 0u128);
        //with bit = 1
        let bit_2 = 1u8;
        let res_2 = GF128::from_bit(bit_2);
        let (first_value_2, second_value_2) = res_2.get_value();
        assert_eq!(first_value_2, bit_2 as u128);
        assert_eq!(second_value_2, 0u128);
        //with byte whose lightweight bit =0
        let bit_3 = 76u8;
        let res_3 = GF128::from_bit(bit_3);
        let (first_value_3, second_value_3) = res_3.get_value();
        assert_eq!(first_value_3, 0u128);
        assert_eq!(second_value_3, 0u128);
        //with byte whose lightweight bit =0
        let bit_4 = 75u8;
        let res_4 = GF128::from_bit(bit_4);
        let (first_value_4, second_value_4) = res_4.get_value();
        assert_eq!(first_value_4, bit_4 as u128 & 1);
        assert_eq!(second_value_4, 0u128);
    }

    #[test]
    //To dest those one we use the test dataset of the reference implementation
    fn gf128_test_byte_combine_bits() {
        let database = [
            (0x0u8, 0x00000000000000000000000000000000u128),
            (0x1u8, 0x00000000000000000000000000000001u128),
            (0xc1u8, 0xdfd1947223bb9095bd517c7bc417069fu128),
            (0xa3u8, 0x58f5a4aefca8cb59fe6e2f1fcf4db504u128),
            (0xc0u8, 0xdfd1947223bb9095bd517c7bc417069eu128),
            (0x22u8, 0x51a595b4b31f44b98414a18b2e7b4cb9u128),
            (0xe7u8, 0xc280b6850c1b6fa8d532843adee4e4c7u128),
            (0x18u8, 0x386656093df3f038d44c32e60a17dee1u128),
            (0x93u8, 0x01a68209a6823702b0c656708878aff9u128),
            (0x5fu8, 0xa72ec17764d7ced55e2f716f4ede412eu128),
            (0x46u8, 0x9f48977e59243eed8a63438944c99fceu128),
            (0x63u8, 0x872430dcdf135bcc433f53640b5ab39au128),
            (0x3u8, 0x053d8555a9979a1ca13fe8ac5560ce0cu128),
            (0x86u8, 0x4099030c7a9fae7837323ff280de9950u128),
            (0xafu8, 0x21ac73a21d46a21badd6747bcdfc5d4du128),
            (0xa3u8, 0x58f5a4aefca8cb59fe6e2f1fcf4db504u128),
            (0xd3u8, 0xd7272761ca8e287777eda49fad5950dbu128),
            (0xf2u8, 0x83bf3780d006f6d252c6edb8d642d26eu128),
        ];
        for data in database {
            let x = data.0;
            let result = GF128::new(data.1, 0);
            assert_eq!(GF128::byte_combine_bits(x), result);
        }
    }

    #[test]
    //To dest those one we use the test dataset of the reference implementation
    fn gf128_test_sum_poly() {
        let all_zeroes = [GF128::ZERO; 128];
        assert_eq!(GF128::sum_poly(&all_zeroes), GF128::ZERO);

        let all_ones = [GF128::ONE; 128];
        assert_eq!(
            GF128::sum_poly(&all_ones),
            GF128::new(0xffffffffffffffffffffffffffffffffu128, 0u128)
        );
    }

    #[test]
    //We see if the to field function give the same result that what we could have with BigUint
    fn gf128_test_to_field() {
        let mut rng = rand::thread_rng();

        for _i in 0..1000 {
            let random: [u8; 16] = rng.gen();
            let pol = GF128::to_field(&random);
            let verif_big = BigUint::from_bytes_le(&random);
            let verif = verif_big.to_u64_digits()[0] as u128
                + ((verif_big.to_u64_digits()[1] as u128) << 64);
            assert_eq!(pol[0].get_value().0, verif)
        }
        //with many polynomes
        for _i in 0..1000 {
            let random: [u8; 32] = rng.gen();
            let pol = GF128::to_field(&random);
            let verif_big = BigUint::from_bytes_le(&random);
            let verif_0 = verif_big.to_u64_digits()[0] as u128
                + ((verif_big.to_u64_digits()[1] as u128) << 64);
            let verif_1 = verif_big.to_u64_digits()[2] as u128
                + ((verif_big.to_u64_digits()[3] as u128) << 64);
            assert_eq!(pol[0].get_value().0, verif_0);
            assert_eq!(pol[1].get_value().0, verif_1);
        }
    }

    //GF192
    #[test]
    //precondition : none
    //Postiditon : GF128 whose get value is as expected
    //if the value given as second value is greater than u64::MAX, the resulting second value will be truncated to hold in 64 bits
    fn gf192_test_new_get_value() {
        //when the input are correct
        let polynome = GF192::new(
            313773831264450545416201890967826687364u128,
            275646867658955913877178570363409381843u128 & u64::MAX as u128,
        );
        let (first_value, second_value) = polynome.get_value();
        assert_eq!(first_value, 313773831264450545416201890967826687364u128);
        assert_eq!(
            second_value,
            275646867658955913877178570363409381843u128 & u64::MAX as u128
        );
        //when the input is not bounded
        let other_polynome = GF192::new(
            313773831264450545416201890967826687364u128,
            275646867658955913877178570363409381843u128,
        );
        let (other_first_value, other_second_value) = other_polynome.get_value();
        assert_eq!(
            other_first_value,
            313773831264450545416201890967826687364u128
        );
        assert_eq!(
            other_second_value,
            275646867658955913877178570363409381843u128 & u64::MAX as u128
        );
    }

    #[test]
    //precondition: a GF192
    //postcondition : return MAX if the input is different from 0
    fn gf192_test_all_bytes_heavyweight() {
        //input != 1
        let pol_1 = GF192::new(1u128, 0u128);
        let pol_1_big = GF192::new(
            2730312856557028196081990424695764059u128 | 1u128,
            2730312856557028196081990424695764059u128,
        );
        let pol_2 = pol_1.all_bytes_heavyweight();
        let pol_2_big = pol_1_big.all_bytes_heavyweight();
        assert_eq!(pol_2, GF192::MAX);
        assert_eq!(pol_2_big, GF192::MAX);
        let pol_1_p = GF192::new(0u128, 63483453u128);
        let pol_2_p = pol_1_p.all_bytes_heavyweight();
        assert_eq!(pol_2_p, GF192::MAX);

        //input = 0
        let pol_3 = GF192::default();
        let pol_4 = pol_3.all_bytes_heavyweight();
        assert_eq!(pol_4, pol_3);
    }

    #[test]
    //precondition : a GF192
    //a GF192 that has switch to the left by one
    fn gf192_test_switch_left_1() {
        let mut rng = rand::thread_rng();

        for _i in 0..10000 {
            let random_1 = rng.gen();
            let random_2 = rng.gen();
            let pol_1 = GF192::new(random_1, random_2);
            let pol_1_res = pol_1.switch_left_1();
            let (first_value, second_value) = pol_1_res.get_value();
            assert_eq!(first_value, random_1.wrapping_shl(1));
            assert_eq!(
                second_value,
                ((random_2 & u64::MAX as u128).wrapping_shl(1)
                    | (random_1 & (1u128 << 127)) >> 127)
                    & u64::MAX as u128
            );
        }
    }

    #[test]
    //input : two GF192
    //output : the product of the two according to te rules of Galois Fields arithmetic
    fn gf192_test_mul() {
        let mut rng = rand::thread_rng();

        //0 * anything = 0
        let pol_0 = GF192::default();
        for _i in 0..1000 {
            let anything: GF192 = rng.gen();
            let pol_res = pol_0 * anything;
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, 0u128);
            assert_eq!(second_value, 0u128);
            //anything * 0 = 0
            let pol_res_rev = anything * pol_0;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, 0u128);
            assert_eq!(second_value_rev, 0u128);
            //1 * anything = anything
            let (first_value_anything, second_value_anything) = anything.get_value();
            let pol_res = GF192::ONE * anything;
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, first_value_anything);
            assert_eq!(second_value, second_value_anything);
            //anything * 1 = anything
            let pol_res_rev = anything * GF192::ONE;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, first_value_anything);
            assert_eq!(second_value_rev, second_value_anything);
        }
        //to test with random values we use a database we get from the test cases of the reference implementation
        let database = [
            [
                0x000000000000000000000000000000ffu128,
                0x0000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x000000000000000000000000000000ffu128,
                0x0000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
            ],
            [
                0x000000000000000000000000000000ffu128,
                0x0000000000000000u128,
                0x00000000000000000000000000000001u128,
                0x0000000000000000u128,
                0x000000000000000000000000000000ffu128,
                0x0000000000000000u128,
            ],
            [
                0x00000000000000000000000000000001u128,
                0x0000000000000000u128,
                0x000000000000000000000000000000ffu128,
                0x0000000000000000u128,
                0x000000000000000000000000000000ffu128,
                0x0000000000000000u128,
            ],
            [
                0xe235590a5d886aab7a4deef38c07d403u128,
                0x30b2c42ccbe391f4u128,
                0x3f68a60813a1d365d01542f5ff60a896u128,
                0xc58c2e08bb3c3d12u128,
                0x132819b4b6ae20118db25e7362b26c44u128,
                0xcee10c7ee4d2c2e8u128,
            ],
            [
                0x9bf8c089c1b20b530a9a8ae62070b16cu128,
                0xab89ea0248d9a527u128,
                0x54f2bc664cb5ea0b24e7615979699734u128,
                0x1536a3eedb3a3081u128,
                0x25f9db05eeac299b161658b781edd320u128,
                0x2d5827f452292782u128,
            ],
            [
                0x2c61d96b05e452237a1807b559906667u128,
                0x8092cc97a533555eu128,
                0x4ef7be22b64b2150390b41c46f98657au128,
                0x0026351fde6956deu128,
                0x928ed2a340e1979196f5dd909ca10442u128,
                0xdf657bd5bc18a16fu128,
            ],
            [
                0x9abf55cabcb648a1782e6372d60f50a7u128,
                0x0cd28cf9c6eb51b8u128,
                0x103098ec0a69a3fceb4faa7efbb7061fu128,
                0x7745ad50dd2ca74bu128,
                0x81a829ea32bb1906f1c0f0149015a1bcu128,
                0x1be129b8ee7d9c21u128,
            ],
            [
                0xdbe4ce8413ed252518d0b5f5022598ecu128,
                0xe7c61d9fc91fd416u128,
                0xaeebf0a0b79fae49804900381b690fc3u128,
                0x1766204c9b4041a9u128,
                0xe39d6a186e82f61c5d08b799f9bef1bcu128,
                0x68f25ba50beb541bu128,
            ],
            [
                0x6c37cb9fc1f655fd3727d78e803aff97u128,
                0x1b20bbd2885bafccu128,
                0x93c51cf70e0baadf51206b7ecadf46fbu128,
                0x9fdd67a4826a2759u128,
                0x203b538fde399ff4119dd35f59d82dd0u128,
                0x9048120040353e9cu128,
            ],
            [
                0x622a20381f20e89dc6d534f6658f44cbu128,
                0xb76ef86d857f32bcu128,
                0xc08170290c278ebabb25f4436317b402u128,
                0x4836fd6082de8561u128,
                0x21fbefd84138185bfb4996531aa568dbu128,
                0xf0742a5ef1f75da3u128,
            ],
            [
                0x4b3518dfd6a234b91411867109c34ca0u128,
                0x25b2fdf3c7eac392u128,
                0x5022f0c44ef73b2f4a290139f6fe838eu128,
                0x4c2da3fa1ca8d806u128,
                0xfa916af9ac3565d43ed988f72130661cu128,
                0x77af6414cb866f8eu128,
            ],
            [
                0xc3419bab762df0e80e61ae1d9c19281du128,
                0x5c5c08c1a6180479u128,
                0x5d651e375ef82ef463e82d58a530d5fbu128,
                0xaa54356495bbad53u128,
                0xb5e5de8ed7b1d2d8d622d2033a86a91bu128,
                0x0ae3d7071e7f8987u128,
            ],
            [
                0xd5f992ac2e1372c15bb613c4e0e35bcbu128,
                0xe0b282e136e43525u128,
                0x28645b29ad69dc4f5587e074b01f68bbu128,
                0x9488b7a9d4ea137fu128,
                0x11cfaa0450ff269006cf672925cffde4u128,
                0xa03798402b023d94u128,
            ],
            [
                0x9b0880f8a4f6f90cf7fc83013a2d7cc9u128,
                0xa7549ef27c81c606u128,
                0xd2b70019c91bdcbc330245e6b5695ad6u128,
                0x7da58a8ad61ff009u128,
                0xc45830f05719850a572a98424b58fba2u128,
                0x53b98afb5af3d2e3u128,
            ],
            [
                0x33acc5b9bf5e1a01ce029758b47e456cu128,
                0xce6951df574f94d3u128,
                0xc7a9eef53e3c9dfcdb403a333dddd5a3u128,
                0x13a9d229bf76c480u128,
                0xfc73233e0b8f703560f3ce4d1650da67u128,
                0x52b518e0ba65f2eeu128,
            ],
            [
                0xb5b7916c2db9778b98bd800671ef843du128,
                0xe76cd596825daaa8u128,
                0xb612a575158bf34b472a99450687bfa0u128,
                0x263196393dee5e3fu128,
                0x04c4d66ce7507ad4a4ca9fa8fee23eecu128,
                0x30ed84c27698df86u128,
            ],
            [
                0x7db8db3710b390d50d60ad300a79b639u128,
                0x6c7815ce74df6d4au128,
                0x146b4d4f85043dabfeafab0e305f4514u128,
                0x331cedb952814eefu128,
                0xeb3bb05a60118fced8d64f6bec554746u128,
                0x25b8b658d3544a2eu128,
            ],
            [
                0xd5b21378d08a5cdd2f945d7b1bae08d1u128,
                0x327e240ad6e719bfu128,
                0xdb8c065f726337920e3d39724aaf274du128,
                0x2aaef03d9035a003u128,
                0x329d78ad15c945e8207597019aa45f1au128,
                0x851ad34e4a7162a6u128,
            ],
            [
                0xcb7335069382eea5c353bfe848a75317u128,
                0xbbf37dafcde961afu128,
                0x0a253cfe42cd80da14ec672e5d60ef5bu128,
                0x4ce5fed139fa209bu128,
                0x936209e256ea1cbfff32794a389384cbu128,
                0x751fea3f00132be9u128,
            ],
            [
                0xc60f2251b1c9c55f3e011696aede6b36u128,
                0xce3fc0a75c38e60au128,
                0x321f77593e9589d4532cbdbe26042cefu128,
                0x82e49207d73f7b7cu128,
                0x0c1bb146dacb08294c35a60447754fadu128,
                0xab11b74e0f7d4392u128,
            ],
            [
                0x1b0cb3317908736a0e312a50caae968eu128,
                0xd579e554f44530d3u128,
                0xdf2c8c489a3d7ca99aba99829d87abc4u128,
                0x0513d870a125f414u128,
                0x0065b2d135f049495e8db7bf2dcb3485u128,
                0x2862318c6689520cu128,
            ],
            [
                0xd8e39c3592a1ddf434fbc8683225f15cu128,
                0x9a88bd20e6580e8fu128,
                0x253686a47b587bce0bbcb9770f4ab3e5u128,
                0x913c74ee536ea679u128,
                0x2677c9ab6e69101efef42687c0d17cb7u128,
                0x5e00e2b5b13c0a8eu128,
            ],
            [
                0x3820057aa1c8c1d4214f2e0f275c00fdu128,
                0x53e0e7154eb41d68u128,
                0x3a445770f72fbe6519c04952522ea472u128,
                0xd2796a210801fbcau128,
                0x18fcab03f29827d785996db37fc33052u128,
                0x2e2fd6bf74e85238u128,
            ],
            [
                0x79eff14bf4f27bff0767cf1e4a50afc3u128,
                0x2258cd4b365dc0b0u128,
                0xcb8a3d73363875a7c78f8354cd00e832u128,
                0xa61e6dc5630033acu128,
                0x316962ef45a1baaaab6a9cdba3b2bdc3u128,
                0xbfcd9a80665b071cu128,
            ],
            [
                0xff8ac5003b705a54c5650b0793d84836u128,
                0x51ea18b24f5d7b15u128,
                0xb3cfbb0dd47826fb86559a95a97d8db8u128,
                0x3d75c099304a62bdu128,
                0x97e19468e2a9c6a7a238e2bcfa7ca063u128,
                0xc976e77cd451da55u128,
            ],
            [
                0x4d987410f04f13ecb4bb3c8c01bb914au128,
                0x5f3fd58c2d37587au128,
                0x8057416f4627cc9a34faff02548b67f3u128,
                0x5cc490f95380096fu128,
                0xdd3a652b55fd13f7c3bcbca3b045e95cu128,
                0xaa2ca9e0db735e66u128,
            ],
            [
                0x26d5b159c2f24d7e7aae9b7d220285e6u128,
                0x42251974bcc396c9u128,
                0x8385ca389c3089a12fd7652974e4ef72u128,
                0x4b74b75f4f7c7ce8u128,
                0x014cea8f2efbb9c648ca5817015d023du128,
                0xe1513d1cb418c92du128,
            ],
            [
                0x6257fc430bc70c64e81a4aeec6c29f38u128,
                0x7ce56e8506bb6ed7u128,
                0x5e1ed2b9ac592c5dcde4a84f80c44bacu128,
                0x395f1e0ad5fb6bd5u128,
                0x19d56750930b22799fd7dddfd3e15eaeu128,
                0xb82806e433c3f60bu128,
            ],
            [
                0x1f2cebc321fc0d5c8de3b961a98e24f4u128,
                0xaf65bbe497fc98beu128,
                0xa965a98430aaa8ff42f179b6049343f4u128,
                0x1b23e76e58658cfau128,
                0xe49568cdc71482d11f1bcb362e8b597cu128,
                0x1ed24044112ff5c4u128,
            ],
            [
                0x866b379b50aebeaf98b680da94550747u128,
                0x835b87f13b847443u128,
                0x6baf320f334fa417c316c6ee11b2871cu128,
                0x16cf40a38543db49u128,
                0x7f4a90f26d0583f3ec5f57bbb64a4b23u128,
                0x6bcd080edae9ec17u128,
            ],
            [
                0xf8ef5d193cc3b6ef70cb159d8c68d801u128,
                0x2c41fb40369118e1u128,
                0xbe8db61f5ba54838a9fa8ef4ef92a867u128,
                0x446be2eb474ec0ecu128,
                0xdadbd3950b3f130929104ea048344cd2u128,
                0x97baa77a9cb49755u128,
            ],
            [
                0xdb9a4a0409527169ed705bd294b5553du128,
                0xf69854a701914afbu128,
                0x7e9eeab9fc1a8d39a76cbc2aadc7bfedu128,
                0x5adf5f2f76949f07u128,
                0x5ac693cd15e67c832e426e3dfbd127a2u128,
                0x6a545e83c14ae9c1u128,
            ],
            [
                0x37ed9bfb1e610936fac1fead2cb50ed0u128,
                0xae0d3c7be41eb85bu128,
                0x65c44eb7d838eec5d913553206db6c85u128,
                0x6d0fa583cb83cf98u128,
                0x215d51a8712738321f1c6af19aeb8dc4u128,
                0xd0f39058c495d3b2u128,
            ],
            [
                0x55f84a7130f4a6c5c13de9d5ecc077b0u128,
                0x4f5baacdc99198a7u128,
                0xe322d4b522a35f6bac22758cfcee982fu128,
                0xd728cdd211abbae4u128,
                0xcd21bf2c4c4f49d2d9e89775a42c7e86u128,
                0x74146078a53481dcu128,
            ],
            [
                0xe1916bda1edffe8afff611e109c30bfbu128,
                0x32ae4667d5a95d0eu128,
                0xf64d779d56eb5e4ae773f62b20ec1a10u128,
                0xbfbae3fa0b7420a8u128,
                0xb464096fed703ab7c78d3dc82e79d6c9u128,
                0x6336a79edc24f83du128,
            ],
            [
                0x92c9370ad58be1cc01f975919a33b5c5u128,
                0xabb22959e4cff78fu128,
                0x030e39cf6b09180f10a9ad1e1b4032f4u128,
                0x3fd35645cfe0f846u128,
                0x49949ecd19279620890de9722c03edcau128,
                0x127b74817301f94du128,
            ],
            [
                0xcae3bd8b589df55de201d425bec37594u128,
                0xa588f774af9b39bfu128,
                0xa8504c713e13393d3fbc5c32d26e371eu128,
                0x3b5a4162922d4caeu128,
                0xbf353c9bbbfcba44c634ffcb1144daf8u128,
                0xf2d6a5f5a21b4cefu128,
            ],
            [
                0xe7c7a0aae39f39262b196ffe63a8d2e1u128,
                0x7e77748a41d00d72u128,
                0x69addb19f6358380ca28e68f4895e908u128,
                0x2dc7bf7e53f2d8afu128,
                0x804c66157158a10bcfe29708c8e85a2fu128,
                0x1157747593885639u128,
            ],
            [
                0x494b7cb6a97c964f72018509fbb1123fu128,
                0xaf4765ec66d8dec4u128,
                0xa5997caae44399cd4d09b6efaf3917dcu128,
                0x56dd72cf564999b1u128,
                0x667e381cf89b3de1e48d544c3dd51004u128,
                0x5c7d31a3f60f0666u128,
            ],
            [
                0xad64140c0bfe2ac295810e2708c9dcaeu128,
                0xe44b423f8772bfe8u128,
                0x75756ca67c62436fbd2b2edc0b1a50dau128,
                0xa482428c05d43ae0u128,
                0x1570aa23fb4b9b781ba1a152c2ac1f87u128,
                0xcdc0baee477ea68bu128,
            ],
            [
                0x5742acb48c55624500189126cf88c737u128,
                0xbe30b08d86262705u128,
                0x69dbc053c40a1f234e5728b6e5a83d85u128,
                0x0285e9f102a1ef4au128,
                0xd2881cbfe346db235b87bbeedba83f9fu128,
                0x145d2c6c8d3e6a16u128,
            ],
            [
                0xf6d6f439840468f0bfdc8958e7d67308u128,
                0x868d0bc59fe863f1u128,
                0xca24b9582b244df2cd618acfad271ab8u128,
                0x320c4163fa23c4e8u128,
                0x55333dd3ca7bb2b717e041d4552f15bcu128,
                0x2b6becdf7ab1d6e8u128,
            ],
            [
                0x30b292068adba954ea676378afbe434eu128,
                0x2f58e1b68f49f27cu128,
                0x999248e00b64ab12bd89ea6e36057d49u128,
                0x008234374b02d8acu128,
                0x4f79cd48b781e243db56c5d0a16f333du128,
                0xfd4a05ddf673ab5cu128,
            ],
            [
                0xad0996daed941a116be06012f0b827f1u128,
                0xb3e7d84acab31751u128,
                0xf7ffc1231ae0a7fdf429342ddc53720bu128,
                0xad40083a64930199u128,
                0x47fbfe2f53b9b43c98cd56f3b6f5e0b7u128,
                0x76103d8f897b53a7u128,
            ],
            [
                0x2060ad5f2d719ad281b66bc69c89baaeu128,
                0x7a4ca21f282c4a8eu128,
                0xc3b47724073504f9e9c924e26ac60f83u128,
                0x02951991026e314eu128,
                0x7819c40451702a065921cab2a130c250u128,
                0x37fd3319315fd92fu128,
            ],
            [
                0x4ea3cee4e46a879008df8657594c1e62u128,
                0x29fd9fd348ab1f95u128,
                0x2240d2cbd7d89535c8a6b50abe475eb1u128,
                0xc9f3a34b4fb68273u128,
                0x02ae22ff63785fce824352a122f7288eu128,
                0x4814e96ee445394du128,
            ],
            [
                0xeb2fc9be977230a0c7676403033e2be1u128,
                0x2feac734c5b1fb84u128,
                0x4585bb8c88a964110235fda3bc15203bu128,
                0xfcdc76a9e5480608u128,
                0x36db67b2bdc264781286c1531a5fd121u128,
                0x8050f7f277597cfcu128,
            ],
            [
                0x17eb8473657e2bbd406dca9293e5313eu128,
                0x8338b21167e0a5a1u128,
                0x44fb84d6ecf556486dbc2eae33c596d8u128,
                0xe1e6654fab7bb9dfu128,
                0x5d581b88e5703fd8a88d2becfeb68e7fu128,
                0x9139d994930b4a80u128,
            ],
            [
                0x2f193e5e7d91031215840cb264a1c623u128,
                0x7fcf50e77bf6f5efu128,
                0xe269fec450313cfc683c48ebebae8c4au128,
                0x7696e158f2dc5477u128,
                0xb78d4e034c43b1e37e1694d0201d6fedu128,
                0x90d83a6543f569fau128,
            ],
            [
                0x4e2bcc00c28d1039e9e793445e79a7feu128,
                0xfe02ab6f2fd16e8cu128,
                0xb508b523a83cad5714e58b11ddd5b78bu128,
                0x844eb157782f988au128,
                0x09eab20a349ee561dde18dc81a0a9b19u128,
                0x7b747bbe7a4feec6u128,
            ],
            [
                0xe30bf864d1977ad051164071776bdcd1u128,
                0x2fdf187c20a188e6u128,
                0x063d2e810ae2aabdd192c2a2c22bf7e9u128,
                0xdc3088e2c378246fu128,
                0x83f6f3e86063e1a3083474935f7c034bu128,
                0x73df92a5e7fddda9u128,
            ],
            [
                0x2c768a8868b2f78c6e58d83ab6453383u128,
                0xdf1de6e7f1497844u128,
                0xc9662f3db8f62e944b1bb28daf8fe179u128,
                0x6357a0549fffeeadu128,
                0x862aee2298a671cdc1fa492bebdf816bu128,
                0x2263d9d9847adfc8u128,
            ],
            [
                0xb8d66e2f4f46e30461cb8a75ffc5960eu128,
                0xfd1a81107094c5cdu128,
                0x86cd33614981469b942717e87db00bf5u128,
                0x83c9d16ecc4403bfu128,
                0xbbd5cc1ec0810f9f89fa147390393cf0u128,
                0xc066ee9aed9687beu128,
            ],
            [
                0xefcdab8967452301efcdab8967452301u128,
                0xefcdab8967452301u128,
                0x0123456789abcdef0123456789abcdefu128,
                0x0123456789abcdefu128,
                0x9a550cf2eb247da23bf4ad534a85dc22u128,
                0x3bf4ad534a85dc03u128,
            ],
            [
                0xefcdab8967452301efcdab8967452301u128,
                0xefcdab8967452301u128,
                0x00000000000000000123456789abcdefu128,
                0x0000000000000000u128,
                0x40404040404040403bf4ad534a85dc22u128,
                0x4040404040404040u128,
            ],
            [
                0xd679d59f3f15cb8b1228d605c5c70bbbu128,
                0x41d0ae4a92d349f7u128,
                0xe194d005ee04a6de86d812ef7118d7bfu128,
                0x5badace1723a0f32u128,
                0x54a171b6ee07e24c167961ae046dd9a4u128,
                0x11d8c7b90eddad13u128,
            ],
            [
                0xb2b6e105b3d5e750f44612a22e0ce8a6u128,
                0x0679146d0db26722u128,
                0x71a07b6645352eaf66854f66fbd02b05u128,
                0xf8a9a324ad701436u128,
                0xfa459e41fa401365d9abbbaef7265a45u128,
                0xbd8d0ffa28ebf7b9u128,
            ],
            [
                0xbf3945012f4fce8d32c77e70d975195du128,
                0xe4bfd54ac1acb478u128,
                0xa553770ced39d61add545e26d7a7fdb5u128,
                0x13f590c10092b9e7u128,
                0xee8aa7ec0f325826eec9e9243dca7506u128,
                0x17f183fba20cdd8du128,
            ],
            [
                0x5179b5ac196354e2596800a390cf5d55u128,
                0xf71127cbfcae6ba0u128,
                0x286e823999f8fdd97f63903108eaaae2u128,
                0x9ef66486688a326du128,
                0xa1ae58d351a212ab8506f75a258b32ccu128,
                0x8faae59f69dccaadu128,
            ],
            [
                0xcba87dc7d42f238e9a81f39ec89a6350u128,
                0xe37ebaed58e9679au128,
                0x345a4ee570dd8a762d0822d711f5af3fu128,
                0x778db0a19bc4c5d1u128,
                0x0c2bdab07dd429b288748def7ce0e5fau128,
                0xd48f39f1f01e2694u128,
            ],
            [
                0x14b42573b8a48210c529c51873fbf642u128,
                0x22af17c6951bc1ceu128,
                0x67b5e9b13f2b50e7cc21f4de7a6cffacu128,
                0x9a5c7eb3db392aa9u128,
                0xaf922497abf5d8bcd63406902f2c9f2cu128,
                0x53c29c0dde4f9fe6u128,
            ],
            [
                0x8c6e1b2dccf63df0353a2c7499785a76u128,
                0x8cc9d319c8a1711fu128,
                0x18eed42a3452e98b8be5d0aacd24a64du128,
                0xb6b141a4a5ad4ecbu128,
                0x337b5ea6d214d836413891732f2db6cau128,
                0xdbeae0b5c42e2937u128,
            ],
            [
                0x314cf7514c44aa5f6ad5962d65528044u128,
                0x7184b8d37ac6ea8bu128,
                0xa95fe3db7e8059db3a95ae3cba3c78c0u128,
                0x0a2513c2825d3154u128,
                0x85e15233276cac3f7f4317ba24ba6cdeu128,
                0x8c807e605a78122cu128,
            ],
            [
                0x9fe796a0732ab9975ffbf6939f7868dcu128,
                0x324fe0b26fe7faf9u128,
                0xe0a1dceb414053842068cef16766868cu128,
                0x022e557d835cd54eu128,
                0x45bc431eb084ef0abf59a4b4f0f8c463u128,
                0x34ad9607a8e17c01u128,
            ],
            [
                0x5b2275410889a6181cd19cfaca4bee29u128,
                0x1241aad53872cabbu128,
                0xbab294156c972ab18431a24733ee6e6cu128,
                0xc6294e92ec2f7c8du128,
                0xff1500669dc01636625f790a4a2686d1u128,
                0x3f3f37c16a494c72u128,
            ],
            [
                0x92fb71c58ed56a6d220405fd97395adau128,
                0xc7de8aa9cc62052fu128,
                0x8043ef725e37f0ae3c11396fa9f9aa78u128,
                0x04fda0a7b6c6e8fdu128,
                0xedbfd04bbc7ffd417dd861d3668860ccu128,
                0xc97537a2c36f0b37u128,
            ],
            [
                0x589d71bf8d4a8d293611bd9e6d05cd59u128,
                0xdd912eb859c6a106u128,
                0x2c4d477733fe86ab494805762db29f94u128,
                0x46f13559e3b6c32cu128,
                0x0e3d26387f45e962d774ac8a9266fa57u128,
                0xf203ae20c32d73b5u128,
            ],
            [
                0x27d65868b1d83cc226ae540b355de6aeu128,
                0x5a8da1e5a8aa955fu128,
                0x29245c5b3bc057545b3225923e0f131cu128,
                0xbb865566896272dau128,
                0x14348b1da5a89ae215754e4210679804u128,
                0x5d63d89856f0d51au128,
            ],
            [
                0x6d50a32e6d8ec1bb8bc9927815cd0057u128,
                0x88645e9f3253c4b0u128,
                0xd7ab0dd75b90ca57b215d6b524ea7981u128,
                0xbd3ca3fdddc72e35u128,
                0x670d9b1426fa0e57c975f8ecc6415e7au128,
                0x94c966c505878094u128,
            ],
            [
                0x6cffdb17bc5a74f186fc6546211a9a41u128,
                0x821556f23350ea83u128,
                0xdeae63d40e8002918559f22df3e020bbu128,
                0x1e26865a7f45919fu128,
                0x1b09fc32529ae2b2348ac6b3e3e8aabdu128,
                0x07c20d9279054f79u128,
            ],
            [
                0x2208efeb91079f264c01f482bcf65422u128,
                0x6228ee2cb02e5b83u128,
                0xb895ac9842b87540d17284de5af8f356u128,
                0x6d3a91dcce3e9462u128,
                0xc002397c821fec8b6a5612be4c3c965eu128,
                0xb04b437bdc734a8du128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
            ],
            [
                0xe469211f76a4c117bdbbdd79bf49496du128,
                0x35864698d9c6bc4bu128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0xa5756403b13d5cb7e3a32108a5278511u128,
                0x9426d0ee916a6028u128,
            ],
            [
                0x1383daa3eb391d8b80ee8abeeace138au128,
                0x8cdff4f2cf8060fau128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0xf43f8c4edce5994be06cea63230f99b2u128,
                0x643ff34187e74d56u128,
            ],
            [
                0x86b8cc67b6ae66b4b516d4673ceb469bu128,
                0x75f87b3f4afb7b0bu128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0x3861f6682245b29397338d2db11b3b38u128,
                0x502cef15f51bd286u128,
            ],
            [
                0xb9e04117878daec3d89223da4e149a3bu128,
                0x199ef9a36c03b314u128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0x98ac3f06e555910bea7295ef250e6d7fu128,
                0x8cd5de2c6a519342u128,
            ],
            [
                0x26cdfe7a61fcfdb39a26cbd46ac9ffd9u128,
                0xc5ec78d7f4bee50fu128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0x5a1e392ed27502c0412b1e73290ac177u128,
                0x58d078ff820c2d2du128,
            ],
            [
                0xcd61f4bb27f05c7479c0f31fd2ba24c5u128,
                0x8d83860bc28e3e82u128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0x4e453bb0d4b1f6b02c902d359eacc7dcu128,
                0x06b364e2aff29b08u128,
            ],
            [
                0xbebf42504dc309add713522bf3614210u128,
                0x764b913014054dc7u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0xb5c0f477ea563ea4c863a21d222535e4u128,
                0x7e941983989ae3b5u128,
            ],
            [
                0x6c4b8a5651fcb18458bf6c2bc0f558a4u128,
                0x5ba03d114b91e0acu128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0x15e29793129389824894ce5f88c3f848u128,
                0xf48567f99ee6801eu128,
            ],
            [
                0x8506d43b37afb23ae872da97856f0180u128,
                0xca9ff17b3f29188fu128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0xe8c25335e50f9101c0a0d793c3d96b39u128,
                0x960f031591bebe38u128,
            ],
            [
                0xf480836847c1384a28012d17338db4d0u128,
                0x879012b010de82a9u128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0xeba41a2eb57be641020aa19859db3facu128,
                0x6976b2fbe2277109u128,
            ],
            [
                0x6ff588b7efccadbba9f484d3515067d0u128,
                0x0441cb124f99493cu128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0x15d288348bb164109dfb56d96f0167b6u128,
                0x3dc969e9333b23a9u128,
            ],
            [
                0xab6a542484b43524bc0eaf08309baff9u128,
                0x15c02860d2fcd4cdu128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0xa0312886666f5b3499b4e7cfb0992b28u128,
                0xbcefbc6736ded2d7u128,
            ],
            [
                0xadc5f5206b956fb689cc432815e96c14u128,
                0x847c79f791b86749u128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0x57de8633a9555fcdfa0b00bb3165c1eeu128,
                0x5c67d0b673161ee1u128,
            ],
            [
                0xc4d94c7406fe91b74911f6fc314a7f02u128,
                0x29c7db93d39069a9u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0x429def7b991c76fd52b08d3d58896dd6u128,
                0x7fa9beb0f9ac4113u128,
            ],
            [
                0x600b36d70f56fdb9c59e709e43007b95u128,
                0x25b7de41c661d6e1u128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0xc45843a8775b4f305a8776f675d23f62u128,
                0xf84f1c147bcd01f7u128,
            ],
            [
                0xd493e44edcab64ace6d9dee5417abce2u128,
                0x896174ce0b1b9ae1u128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0xb09ccae3da2083a3fb2fbc0f1c052ac1u128,
                0x39e04da59cb9f330u128,
            ],
            [
                0x6e2c23c4330238776f82a5dab159a2beu128,
                0x40656c878d804bdau128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0x1d8180b9eb57900e360347b1bcb3ad7fu128,
                0xd0de3cb2ab975210u128,
            ],
            [
                0x526be20dd427cae0b533e69fee013c17u128,
                0x5591e615fb4fe6ebu128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0xc423b7fbc112e09cd87b59bca2aa7c50u128,
                0xfe844f48f7acb177u128,
            ],
            [
                0x1a1961c9829c29049d8038cc9201a16eu128,
                0xccbfcb555da99fa3u128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0x863e306d99d4880497d39cf52729774bu128,
                0x869fd91ecce4379au128,
            ],
            [
                0xc0c5469929879334690a83ddecbbb1c0u128,
                0x60e120dfa44d440au128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0x29cb2358d40aa33be3fe8a4c388ddc21u128,
                0x019913d86397aac7u128,
            ],
            [
                0xa19b5da29c74ca83a7ba4a8d57b3fde0u128,
                0x2b02abe95dc41ae0u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0xe78e5232bbb34b060d91e6aa710286c5u128,
                0xe262e443993c07a4u128,
            ],
            [
                0x691c50de5ffc6ba5f9bca9fb7d928d05u128,
                0x09d734c0072225dfu128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0x5d3590ed198c13fc199bd623ab0bccb6u128,
                0xc28cc2d7f82d0390u128,
            ],
            [
                0xdc5d3225ff310afbabe666281fbee551u128,
                0x1450e118669e3774u128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0x23bc9b8e6047c5e1d238e582e858f140u128,
                0xfa3ea0c1f68a0cc5u128,
            ],
            [
                0x0e6c6e810e37f65dfee0e925a6d1e689u128,
                0xdda877e6748b0b62u128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0x95e0ae0f5cf5fd144d6f49cfff9f5a77u128,
                0x5f63ba5d8947ebd6u128,
            ],
            [
                0xce2050e1b1269fed64dc8682336cb647u128,
                0xaedd93e044a97aa8u128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0x9790cf928f939ddea67b43e91d7885feu128,
                0x7acce79a794e8c00u128,
            ],
            [
                0x1e6bf6271d3d4f360ee6a5f6a8d31bbcu128,
                0x4bb57e9e636464a6u128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0xaff77085c5e779b02e933271ef1572aeu128,
                0xe34917a787c19a2eu128,
            ],
            [
                0x168ea21246b6af6fdf50d642c51c0e9du128,
                0x719b460318d21c80u128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0x676513ead7ca65fde53158a75e0a5686u128,
                0x493b8ac0b51c5611u128,
            ],
            [
                0x93c239f8f72ba242e3ab0099dca7562eu128,
                0xc80da8c1734b7e08u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0xad0bdaec6bb0bb1670ac449b2dfbd40eu128,
                0x0b49474284bd8ce5u128,
            ],
            [
                0x43a281c6a3eb58288a02bda55994751cu128,
                0x5ffe963053c132d1u128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0x8edb9c2cfd74a00bab9ae1d6feff5dfau128,
                0x6d7e2f7ff349bb50u128,
            ],
            [
                0xbd3c1a5e237dc2c8bb87b8a3a6450ab3u128,
                0x41dd37b11c073166u128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0xf87a6dad79f142119acac61375944f36u128,
                0x6cece6dfbd71c19bu128,
            ],
            [
                0xf87b11c76c40dedd3eb95b685dd6e544u128,
                0xedd7078d3cfd6839u128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0xfaa3011b11510552c2e61f60d5a82dd1u128,
                0xe69dbf9088574836u128,
            ],
            [
                0x3683040f261afbd4b368cb4b4b972260u128,
                0x440671fedf6ea202u128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0xe03efc81f1a201057debf3f206ea44b5u128,
                0x994ae23f860513eau128,
            ],
            [
                0x41664a338f5041eee42182daf10a9dc8u128,
                0x6d8225b815133827u128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0x1ad643357df8476cdd68dae6da12a951u128,
                0x8bee87c53126d101u128,
            ],
            [
                0x7058b9fd238a428cc71061ccbd1dd129u128,
                0x5775a210b827cfb8u128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0x8addf0d42ed111f49b3790fd19a29dc0u128,
                0x462743d83f107d4du128,
            ],
            [
                0xd94cdba7848132b97498328c6b019979u128,
                0x7ed8937b3f39aa5cu128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0xb653b8a90279d1393412e2d95b889536u128,
                0x16ab4c3472f53242u128,
            ],
            [
                0x9caf5cf0d05131fd6ef1fcd1e8f23db5u128,
                0xfe32358ab268528fu128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0x8429e41a524f3172fbfbefda7ed82a0bu128,
                0xf03dbfb7648a9b56u128,
            ],
            [
                0x5e91050553ac3629367f32b5863c2fc4u128,
                0x348138f445f0601cu128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0x980d5592cc42ae6d2134ba1f8de84918u128,
                0x0476027a75198dceu128,
            ],
            [
                0xabea2fa2681cc14998fc916a1d00a47bu128,
                0xa848a97a420a3822u128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0xb0c5fabf90eb5bfe4ad09b785776775cu128,
                0x3806df4d53a38a07u128,
            ],
            [
                0xa94e70f8d855e4c0dde234a20abb34e1u128,
                0x3eba81996f17839bu128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0xd141cd482fface90b71ab6652cdcb6f9u128,
                0xae75a87bf1f971d6u128,
            ],
            [
                0x782842bc57c4168e16165e72f5667195u128,
                0xae548d42fa8486afu128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0x3874ece2b1eb677c2978351104107e7eu128,
                0x52b116774dc53082u128,
            ],
            [
                0xf5da48afd219d3bd61c30c94b8d436d4u128,
                0x11f79d98c77b889au128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0x5644a5ab264bafbafbee1bf7c08054f7u128,
                0xa52c65be63ad155bu128,
            ],
            [
                0xde28c095192f9e5b6ec5a447d038944bu128,
                0xe64c2d5c9604e6bcu128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0x68a448dae1d0e44d60c92816a295e62du128,
                0x5505510bb78f4e93u128,
            ],
            [
                0x2952c18f2372f337a207b8f4d65598d0u128,
                0x50b6f956b3218afdu128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0x4535e4d67e6d8877d95c54e1ac811b41u128,
                0x07f106f1786a9f51u128,
            ],
            [
                0x99a93b7996faa2d742b550a92af27dd8u128,
                0xb1ee6a5496efbda3u128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0xa660db0a2ba38f98bed5f505032a8a1fu128,
                0x03ad65a9d4c4e19eu128,
            ],
            [
                0x7acb595e759957e8944974e2b68e542fu128,
                0xade3ae46c8201ed8u128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0xe193e7476232c827facbf03579754d2du128,
                0x2700c57f51d15f2du128,
            ],
            [
                0x540f4bf688301c14294027aae5d4fdfau128,
                0x5d235afcb0904bdau128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0x1c8cff00d8db8855c63a2900cefde4cbu128,
                0x9a152def9f125c43u128,
            ],
            [
                0x11105b5bd26c0140b383cbc22b77dfa0u128,
                0x4a65e60a8b7c7370u128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0xc2bc3cfe41e5739330099194ef21a1b8u128,
                0xb315e74877c46f98u128,
            ],
            [
                0x4b0cb01578860e0bbb5e7fe9d1a634d6u128,
                0x0a8e746bdb3419d2u128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0xf2cbb34240cca53f676f999b83e1c416u128,
                0x305ae1ae0a0d66b0u128,
            ],
            [
                0xe28f4a21323a079d85ad97c10ab07a55u128,
                0xbd27fccf7f8f5e0fu128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0xb548a5451808d4d6f0fc89dd7148aa0au128,
                0x029a6f0e7c7d704cu128,
            ],
            [
                0x08edc57fd273688459cc00e2c24038ecu128,
                0x7dc39cb43f5a49f8u128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0x49c7be6c18f6e0b4a62b6b790a333192u128,
                0xb7a9ac25935c38fdu128,
            ],
            [
                0xad268f71d6d063e5137496553579f369u128,
                0x45e32138200997b7u128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0x049ab3876dca3ee7fcf05bc2c838bbecu128,
                0x56496a50fd64d148u128,
            ],
            [
                0x388becc301dbc7054bff372ed43a5234u128,
                0xc6704e0facdf08bbu128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0xf8fa1d0234e66ef270bde61471b3d44cu128,
                0x053240767d9e7520u128,
            ],
            [
                0x9817a77ff0c95654bf6c591fa21ca58fu128,
                0xe6f6cdff7de5fa9bu128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0x2f978c0083a07723430a6e98b447f36cu128,
                0x7280e1a0e731194cu128,
            ],
            [
                0xdf6e813fa14fd41e3759d3d2f95d544fu128,
                0xe4028d47a3f41c5au128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0x1f71574671e50b94b2e6aa60ed85e40au128,
                0xd24fa2494b7c8cc0u128,
            ],
            [
                0x7bd8c8285d6d2cf73fb8d8174f805d56u128,
                0xeb17827fa9e08b3bu128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0x9a291ffbc7c778956e30f30d502b833eu128,
                0x4cb5c177ccb3abaau128,
            ],
            [
                0x4fc9c2cb4cdd226f9993219dc50b6770u128,
                0xcdf2554c9e016452u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0x93f77a76ba071ade9c919f9a0b375697u128,
                0xff30e1784dc6dc02u128,
            ],
            [
                0x433e3160f07304b7ef12963e6c9d396au128,
                0x75ab197217777320u128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0x36eb014ec2128c1ea696eab6ad9e2dd6u128,
                0x8a50f4288f2e6ef4u128,
            ],
            [
                0x41c0fe25181855b6ede2198538e495d4u128,
                0xb2c2073bc9868e04u128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0x5ba9a8473faa3b2cb08e8790fd0f74a0u128,
                0x4df9c77cbb23fc7fu128,
            ],
            [
                0x2a10a4bbd0a13e88e7f442fbca467433u128,
                0x319300086bb2065fu128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0x665512712aca653d2f54414737f0769fu128,
                0x135167821c0027b7u128,
            ],
            [
                0x1276bf59e1dce88cdfa6f26de824dbbbu128,
                0x385c89ba90ba1144u128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0xf3922b0f7c07ff3a1261a7af89b42249u128,
                0x795dac00a2043712u128,
            ],
            [
                0x85412138acc1bd1e568239529f8f85d8u128,
                0xbf3ef00ec349ab4du128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0x8e9fbe9d9fae7bf13967da234a3dfb18u128,
                0xc92ff3f00bebb074u128,
            ],
            [
                0x001d831fb3881be715aa83189bed5dadu128,
                0xcf4bf2939beaf2b1u128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0xf6f48246b24a9d258903fa6e918ff9b6u128,
                0x91925d61a22cc6fbu128,
            ],
            [
                0xc691e37b884f4edfc8ccf1c8a8213304u128,
                0x85a1f65e6e7ce448u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0x46076f2a5513337c6b4c30491be18463u128,
                0x1fa278b916c6d5fbu128,
            ],
            [
                0x8491eb1278713510d8a73aceff56ee85u128,
                0xe56576c2443c8267u128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0xc1fda18b4bb0fdca234b5ca49c1927a0u128,
                0x52fb7e4da76da597u128,
            ],
            [
                0x425e7bd04df56b8f451230b3203a6496u128,
                0x7154f6523421904au128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0x3bcf1f6e75b53a2a3f458d98e0a3b162u128,
                0x57f1dc5ff6df064eu128,
            ],
            [
                0x106130f7c507c5719446e2319c01c476u128,
                0x32a713821be0317du128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0xf34948b7fbd05a4c9feea10fca291a07u128,
                0xcb51d41f23e50a09u128,
            ],
            [
                0x54ce386f8c866ee0335b7b5cefade8d3u128,
                0xdf5584591d485e17u128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0x0a480a6831b8f369830bbaf56d0e925du128,
                0x1c76ecb7afd5cdc4u128,
            ],
            [
                0xde68595259a48b3a8f16009018d0a169u128,
                0xe7c9567f839a98f7u128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0xa42919e1c0066e905ab71ca973d21142u128,
                0x3788703e23d7c9f4u128,
            ],
            [
                0xa406a6127fd68f29624bad01fe43085bu128,
                0x6c86a92f6d627138u128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0x7f6d26d9cadb7783e722d534c0fc9504u128,
                0xdaea230d1cbcc432u128,
            ],
            [
                0x6ec40b21a2fdf7c6bdf980dc30e9025bu128,
                0xa5e2564f7af68071u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0xd22026c311d9891eb0d775cd05b0f51du128,
                0x712b71d725bf1a67u128,
            ],
            [
                0xeecd35b69ac98faad2c2841d42b05666u128,
                0x86cee6f1c70be623u128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0xeb35e2c5a53579f7e502550292957d25u128,
                0xfc0734c3ce60f72bu128,
            ],
            [
                0x851bd0bc3d42fdceee1bd3aa4ce8b2b8u128,
                0x27263ac6e305a413u128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0x0f12bc991f403e21602576b2db4d07ecu128,
                0x7b5e782439f0f75au128,
            ],
            [
                0xb9c0809ddec43bd1a4a3395d368403a2u128,
                0x5c08dea24159857bu128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0x5b8c973d942ed4e306a0dad87b6d4d06u128,
                0xe07b3b9bf9f94c6eu128,
            ],
            [
                0xc879be1e2d19af21af0b00265eac41ddu128,
                0xb73cee99e7c4bb63u128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0xa420146b17975b1a6c4530f7a0acf36du128,
                0x90cf59765486766fu128,
            ],
            [
                0xed59b76bba45b058e2c675ee33c2457eu128,
                0x5090458767997af1u128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0x042d8a554b7b646e72bfaaa71cf5f781u128,
                0xd394a98597f8a963u128,
            ],
            [
                0x3134608b8ea60ec4e6f6b57244187a62u128,
                0xab821b1951aa37d6u128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0xaca25065551300d2f768bc85cc6fe3bfu128,
                0x246dd1933e0c8354u128,
            ],
            [
                0xce0f27d8e10997a0821ff14ad2c2a787u128,
                0xff47ca42d1012f69u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0xc87128c06cbaf5db7b10f78a18cda5c9u128,
                0x3b16f3369d08d483u128,
            ],
            [
                0xd08fd6349ba2d321979da1722c842f37u128,
                0xdc55b69205161b0bu128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0xafff94486cc736a4e9f2759a30db76b3u128,
                0x1d5586bb3d4ebb2cu128,
            ],
            [
                0x4be07c64bc1c92ca7e73cb2df01a2a5eu128,
                0x90267d5522334035u128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0x83409b97cb350d652f2432eb28abc250u128,
                0x650480e207c1c037u128,
            ],
            [
                0xa927e6b56467b1da9a266f87b5122adcu128,
                0x1088ccb1db59bda3u128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0x0997b300be33d018319d5eef394e6ba3u128,
                0xf3354515b0827f88u128,
            ],
            [
                0x17e1c49f5b402288bd72f9ea37c83127u128,
                0x41ccf3758933df67u128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0xa094321096b3931b1d0a582d2ae642e4u128,
                0xfe390179bf11e8a3u128,
            ],
            [
                0xd11272f1ed7b83c1692deead130682e5u128,
                0xd10e1914aa6694dbu128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0xbf93c4231e6d70b09a56b20c37f26d53u128,
                0xab237038ede984d8u128,
            ],
            [
                0x93e1fc26c0b6cf5c0a90fbeff2b64038u128,
                0x06af1540915a316bu128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0xb08fcb62e8bc05446b889086d13ba16fu128,
                0x441d91976ca48b75u128,
            ],
            [
                0x061d8dd66b20a148562b4a2d316db6ffu128,
                0x73f4e0f9815912b2u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0x90518721de41a1929fd809d0b1a2fb75u128,
                0x64a2f91d75bfa65bu128,
            ],
            [
                0x01a67333c0be62f0810eb4e8a37694e5u128,
                0x68b767ab68eeab06u128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0xd717b6506d39d6e58c0a4640a77bb015u128,
                0x9046c7e069fadaaeu128,
            ],
            [
                0x00394280228ce3e6b4a14a1672e8e932u128,
                0x1131bb5b85a2c731u128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0xfd244683f5631d9d98cb53c160749dc1u128,
                0xd1315390f1e601adu128,
            ],
            [
                0x235b7fcd66d61763567ebead963c82b7u128,
                0xbf4d54da9f3e0c93u128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0xd849bd3cf1f1df7751139afbbf9b3493u128,
                0x62b6893dfdb34a2cu128,
            ],
            [
                0x227398543e8af33414840e8c77bbbb3fu128,
                0x28e81d5e0aa0ce0cu128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0x844fb4aaac784745ec9c0270f3652104u128,
                0xc49351306c346089u128,
            ],
            [
                0x86b7d29a19fe85197bba1b892106cb51u128,
                0x81fbd6bbda432812u128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0x701f1b11b9c2c5950ebe4e333fc6280eu128,
                0xc7af5c31364ec456u128,
            ],
            [
                0xf149a8a2c6ba44302651286c01c9278bu128,
                0x2c8d5e9e460f43b1u128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0x7e5884349bc7a36c68c845f6534906f2u128,
                0x8ffe39dae6e2eff2u128,
            ],
            [
                0x5c8f8df30aa54caf978103b0f9398f1du128,
                0x94d38e3cda67e0e8u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0xcd478688d1771979f780462c8d9aa25cu128,
                0x985ad0f1acf9add3u128,
            ],
            [
                0x1692831be1ec3b1a89a5e0677150e0c5u128,
                0xb524659de5577ab4u128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0xa7f60f5d8f68c1794b82418ea67b4874u128,
                0x0acda5c6cb8058acu128,
            ],
            [
                0x367ffa2540fca390f133f8424db8b975u128,
                0x29360024c9dfa65au128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0xc0252cd06cdd91c77ecdaaaca380c0deu128,
                0x52651ba762f1ea05u128,
            ],
            [
                0x95d7049049b8aa52395d8de52d639d40u128,
                0xf3706a85c9e72611u128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0x1e1d3c03b97b28f61450c3b46386f17bu128,
                0xdccc3a4c4479db50u128,
            ],
            [
                0xb9490335f47cce0d2a2932bf12c7e852u128,
                0x6273d74fc777e9c1u128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0x294ac1113e18d64d4396d60921f9e297u128,
                0x102b1c26cf6a5c2au128,
            ],
            [
                0xa108e786362f43c4257fa34e1a108859u128,
                0x3f69a37526094ca4u128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0x4786f3c3c514bb73955d99e14de1781bu128,
                0x69c7a4bc4f8466deu128,
            ],
            [
                0x480aaad36f31fa946e1293b2a61401d7u128,
                0x9e4160e111266d0cu128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0xed40e9c2579a7c78ba1db28d7310a546u128,
                0x0f8494baf9c34eb8u128,
            ],
            [
                0xcd8c13dc0502170a42d74aed1ab84024u128,
                0xc3880294617700b1u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0x3d0f682857ff6dfadfe1ea91b793e68du128,
                0x10c56968984c3e60u128,
            ],
            [
                0x5fc8ae7c048d26886b29a0bd961e3c40u128,
                0x662496f52ffae967u128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0xf1c9fdcb7c741236391c5c0c4dedeaf7u128,
                0xe7cd5367ee7b0fd2u128,
            ],
            [
                0x9a0bcaba0e5e23875c24fc78d9c85d73u128,
                0x6c98b743baace4bau128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0x108a9945c3039d950ce9813b99769012u128,
                0x5349915c9f0f30edu128,
            ],
            [
                0xb4520cf9f0a82fa235cce77c150d12a3u128,
                0x6c4257b202c4ecdau128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0x5dead872752e11f8ef2734d9dad28d98u128,
                0xb0962cbe3aa14a45u128,
            ],
            [
                0x346e9323a755eed3152b3f60911b2e01u128,
                0x3fa5e0741d4a9624u128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0xa6fc042ec79c1c8717a24f75c8f24552u128,
                0x18d5746d369a38d6u128,
            ],
            [
                0x01e9ea20119e0003d167a381208e0235u128,
                0xc90696101fd17b41u128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0x101f2b432bf86c68b32d0d9594c615c8u128,
                0x4e9c41863a5a3c72u128,
            ],
            [
                0x736caec030cdc71b43fc38518bf4242au128,
                0x75a67086d934f8dbu128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0xb09462865d0f6f5cc9b9f9b828ad1fffu128,
                0xbfbf6a99f7a8f981u128,
            ],
            [
                0xf3472c0e03281698cb1f49597add7fc5u128,
                0xe96660dd350a70d7u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0xf00fcb2507aef8c0116b78429f97976eu128,
                0xf4696149b9a14d19u128,
            ],
            [
                0x47bc9c50192a3877c8683460c171174eu128,
                0xc017c9814c934910u128,
                0xe665d76c966ebdeaccc8a3d56f389763u128,
                0x310bc8140e6b3662u128,
                0x5bf4c8160507f68751c3a07831cbe510u128,
                0xb767483424d4d122u128,
            ],
            [
                0xb60589cd9d55f515d7899f18f9763fb5u128,
                0xb83b663d69b06fbbu128,
                0x7bf61f19d5633f26b233619e7cf450bbu128,
                0xda933726d491db34u128,
                0xcacd19309efa42cc20100f5a6b239e47u128,
                0x3df3d63dcb159702u128,
            ],
            [
                0x34816d74598b9bf239c434212f363838u128,
                0xbb1cc6d6df23e0b2u128,
                0x8232e37706328d199c6d2c13f5398a0du128,
                0x0c3b0d703c754ef6u128,
                0x77a22806b0090a1546269b644fdaaaedu128,
                0x8d4e5f5c3b40f311u128,
            ],
            [
                0xe22cbe4fcd1761669902aaff2860f57eu128,
                0xd3c8a7b93b360b75u128,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
                0x3b2481d1b2788238b31c8dec5ae34157u128,
                0xd2c975d695e8f007u128,
            ],
            [
                0x5505a4eb7fd3c89a8a4988e1e76298d5u128,
                0x90dbce524b64ab13u128,
                0x08168cb767debe84d8d50ce28ace2bf8u128,
                0xd67d146a4ba67045u128,
                0x0f04bab4bc084698e51fde2049c62b62u128,
                0x6fb6cbde9e325afdu128,
            ],
            [
                0x91446dd44a40fe73810e823a61aabc09u128,
                0xd9c07e1188c38ab0u128,
                0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
                0x29a6bd5f696cea43u128,
                0x3b1a43b1d95ea7fba69eba39e9844886u128,
                0x81a52189ab033b30u128,
            ],
            [
                0x640eedb69698deaa196f7f1b98910b50u128,
                0x0547425dd9157101u128,
                0x6019fd623906e9d3f5945dc265068571u128,
                0xc77c56540f87c4b0u128,
                0x046dcd726ebb38e43523f649993d74bdu128,
                0xa86c3b1cb6a53848u128,
            ],
        ];
        for data in database {
            let mut left = GF192::new(data[0], data[1]);
            let mut left_2 = GF192::new(data[0], data[1]);
            let right = GF192::new(data[2], data[3]);
            let result = GF192::new(data[4], data[5]);
            let res = left * right;
            #[allow(clippy::op_ref)]
            let res_rev = right * &left;
            let (first_value, second_value) = res.get_value();
            assert_eq!(first_value, result.get_value().0);
            assert_eq!(second_value, result.get_value().1);
            //to test commutativity
            assert_eq!(res, res_rev);
            //to test with ref
            #[allow(clippy::op_ref)]
            let res_rev = &left * &right;
            #[allow(clippy::op_ref)]
            let res = left * &right;
            assert_eq!(res, result);
            assert_eq!(res_rev, result);
            //to test mulassign
            left *= right;
            left_2 *= &right;
            assert_eq!(left, result);
            assert_eq!(left_2, result);
        }
    }

    #[test]
    //input : one GF192 and one GF192 restricted to 64 memory bits
    //output : the product of the two according to the rules of Galois Fields arithmetic
    #[allow(clippy::erasing_op)]
    fn gf192_test_mul_64() {
        let mut rng = rand::thread_rng();

        let pol_0 = GF192::default();
        for _i in 0..1000 {
            //0 * anything = 0
            let anything: u64 = rng.gen();
            let pol_res = pol_0 * anything;
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, 0u128);
            assert_eq!(second_value, 0u128);
            //1 * anything = anything
            let pol_res_1 = GF192::ONE * anything;
            let (first_value_1, second_value_1) = pol_res_1.get_value();
            assert_eq!(first_value_1, anything as u128);
            assert_eq!(second_value_1, 0u128);
            //anything * 0 = 0
            let anything: GF192 = rng.gen();
            let pol_res_rev = anything * 0u64;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, 0u128);
            assert_eq!(second_value_rev, 0u128);
            //anything * 1 = anything
            let (first_value_anything, second_value_anything) = anything.get_value();
            let pol_res_rev = anything * 1u64;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, first_value_anything);
            assert_eq!(second_value_rev, second_value_anything);
        }
        //to test with complex values we use the tests values of the reference implementation
        let mut left = GF192::new(
            0xefcdab8967452301efcdab8967452301u128,
            0xefcdab8967452301u128,
        );
        let mut left_2 = GF192::new(
            0xefcdab8967452301efcdab8967452301u128,
            0xefcdab8967452301u128,
        );
        let right = 0x0123456789abcdefu64;
        let result = GF192::new(
            0x40404040404040403bf4ad534a85dc22u128,
            0x4040404040404040u128,
        );
        let res = left * right;
        assert_eq!(res, result);
        //to test with ref
        #[allow(clippy::op_ref)]
        let res_rev = &left * right;
        #[allow(clippy::op_ref)]
        let res = left * right;
        assert_eq!(res, result);
        assert_eq!(res_rev, result);
        //to test mulassign
        left *= right;
        left_2 *= right;
        assert_eq!(left, result);
        assert_eq!(left_2, result);
    }

    #[test]
    //input : one GF192 and one GF192 restricted to 1 memory bits
    //output : the product of the two according to the rules of Galois Fields arithmetic
    #[allow(clippy::erasing_op)]
    fn gf192_test_mul_bit() {
        let mut rng = rand::thread_rng();

        for _i in 0..1000 {
            //anything * 0 = 0
            let anything: GF192 = rng.gen();
            let pol_res_rev = anything * 0u8;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, 0u128);
            assert_eq!(second_value_rev, 0u128);
            //anything * 1 = anything
            let (first_value_anything, second_value_anything) = anything.get_value();
            let pol_res_rev = anything * 1u8;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, first_value_anything);
            assert_eq!(second_value_rev, second_value_anything);
            //anything_1 * anything_2 (odd) = anything_1
            let anything_2 = rng.gen::<u8>() | 1u8;
            let pol_res_2 = anything * anything_2;
            let (first_value_2, second_value_2) = pol_res_2.get_value();
            assert_eq!(first_value_2, first_value_anything);
            assert_eq!(second_value_2, second_value_anything);
            //anything_1 * anything_2 (even) = 0
            let anything_3 = rng.gen::<u8>() & u8::MAX << 1;
            let pol_res_3 = anything * anything_3;
            let (first_value_3, second_value_3) = pol_res_3.get_value();
            assert_eq!(first_value_3, 0u128);
            assert_eq!(second_value_3, 0u128);
        }
    }

    #[test]
    //input : two GF192
    //output : the result of the and bitwise operation on the two inputs
    fn gf192_test_xor() {
        let mut rng = rand::thread_rng();

        for _i in 0..10000 {
            let random_1_1 = rng.gen();
            let random_1_2 = rng.gen::<u128>() & u64::MAX as u128;
            let random_2_1 = rng.gen();
            let random_2_2 = rng.gen::<u128>() & u64::MAX as u128;
            let pol_1 = GF192::new(random_1_1, random_1_2);
            let pol_2 = GF192::new(random_2_1, random_2_2);
            let pol_res = pol_1 + pol_2;
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, random_1_1 ^ random_2_1);
            assert_eq!(second_value, random_1_2 ^ random_2_2);
        }
    }

    #[test]
    //input : two GF192
    //output : the result of the xor bitwise operation on the two inputs
    fn gf192_test_and() {
        let mut rng = rand::thread_rng();

        for _i in 0..10000 {
            let random_1_1 = rng.gen();
            let random_1_2 = rng.gen::<u128>() & u64::MAX as u128;
            let random_2_1 = rng.gen();
            let random_2_2 = rng.gen::<u128>() & u64::MAX as u128;
            let pol_1 = GF192::new(random_1_1, random_1_2);
            let pol_2 = GF192::new(random_2_1, random_2_2);
            let pol_res = GF192::and(&pol_1, &pol_2);
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, random_1_1 & random_2_1);
            assert_eq!(second_value, random_1_2 & random_2_2);
        }
    }

    #[test]
    //To dest those one we use the test dataset of the reference implementation
    fn gf192_test_byte_combine() {
        let database = [
            [
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
            ],
            [
                0xb465c39f6e3a7eafef19fbde30544397u128,
                0xa77ed021423d6319u128,
                0xe469211f76a4c117bdbbdd79bf49496du128,
                0x35864698d9c6bc4bu128,
                0x1383daa3eb391d8b80ee8abeeace138au128,
                0x8cdff4f2cf8060fau128,
                0x86b8cc67b6ae66b4b516d4673ceb469bu128,
                0x75f87b3f4afb7b0bu128,
                0xb9e04117878daec3d89223da4e149a3bu128,
                0x199ef9a36c03b314u128,
                0x26cdfe7a61fcfdb39a26cbd46ac9ffd9u128,
                0xc5ec78d7f4bee50fu128,
                0xcd61f4bb27f05c7479c0f31fd2ba24c5u128,
                0x8d83860bc28e3e82u128,
                0xbebf42504dc309add713522bf3614210u128,
                0x764b913014054dc7u128,
                0xe47914552860521f344fb92cb7ea3a3cu128,
                0xab69c7297e9e5a33u128,
            ],
            [
                0x99c4fed43cc3ff348fec9584d9a70be9u128,
                0xd563ed5d7f6de800u128,
                0x6c4b8a5651fcb18458bf6c2bc0f558a4u128,
                0x5ba03d114b91e0acu128,
                0x8506d43b37afb23ae872da97856f0180u128,
                0xca9ff17b3f29188fu128,
                0xf480836847c1384a28012d17338db4d0u128,
                0x879012b010de82a9u128,
                0x6ff588b7efccadbba9f484d3515067d0u128,
                0x0441cb124f99493cu128,
                0xab6a542484b43524bc0eaf08309baff9u128,
                0x15c02860d2fcd4cdu128,
                0xadc5f5206b956fb689cc432815e96c14u128,
                0x847c79f791b86749u128,
                0xc4d94c7406fe91b74911f6fc314a7f02u128,
                0x29c7db93d39069a9u128,
                0x2fe0e9a6a3b317e2a92611407d124792u128,
                0x7c7780c21d4d09a3u128,
            ],
            [
                0x273aa480617422f57ec13b406c4badc5u128,
                0x95ecb9cf94b43e94u128,
                0x600b36d70f56fdb9c59e709e43007b95u128,
                0x25b7de41c661d6e1u128,
                0xd493e44edcab64ace6d9dee5417abce2u128,
                0x896174ce0b1b9ae1u128,
                0x6e2c23c4330238776f82a5dab159a2beu128,
                0x40656c878d804bdau128,
                0x526be20dd427cae0b533e69fee013c17u128,
                0x5591e615fb4fe6ebu128,
                0x1a1961c9829c29049d8038cc9201a16eu128,
                0xccbfcb555da99fa3u128,
                0xc0c5469929879334690a83ddecbbb1c0u128,
                0x60e120dfa44d440au128,
                0xa19b5da29c74ca83a7ba4a8d57b3fde0u128,
                0x2b02abe95dc41ae0u128,
                0xc2275b8e1027fecd48ad1fa7752344e6u128,
                0x1f7db50119b4b5cdu128,
            ],
            [
                0x36cec866e30c68d4068756e0de91793cu128,
                0xccbfeea5b162fb61u128,
                0x691c50de5ffc6ba5f9bca9fb7d928d05u128,
                0x09d734c0072225dfu128,
                0xdc5d3225ff310afbabe666281fbee551u128,
                0x1450e118669e3774u128,
                0x0e6c6e810e37f65dfee0e925a6d1e689u128,
                0xdda877e6748b0b62u128,
                0xce2050e1b1269fed64dc8682336cb647u128,
                0xaedd93e044a97aa8u128,
                0x1e6bf6271d3d4f360ee6a5f6a8d31bbcu128,
                0x4bb57e9e636464a6u128,
                0x168ea21246b6af6fdf50d642c51c0e9du128,
                0x719b460318d21c80u128,
                0x93c239f8f72ba242e3ab0099dca7562eu128,
                0xc80da8c1734b7e08u128,
                0x2fae1b1b303c79589d3e412ae3c16b65u128,
                0x70990b51f9acd338u128,
            ],
            [
                0x87c2cb71ab6ddb12255332ab0c0beac8u128,
                0xaf5fa19bcacfdd6bu128,
                0x43a281c6a3eb58288a02bda55994751cu128,
                0x5ffe963053c132d1u128,
                0xbd3c1a5e237dc2c8bb87b8a3a6450ab3u128,
                0x41dd37b11c073166u128,
                0xf87b11c76c40dedd3eb95b685dd6e544u128,
                0xedd7078d3cfd6839u128,
                0x3683040f261afbd4b368cb4b4b972260u128,
                0x440671fedf6ea202u128,
                0x41664a338f5041eee42182daf10a9dc8u128,
                0x6d8225b815133827u128,
                0x7058b9fd238a428cc71061ccbd1dd129u128,
                0x5775a210b827cfb8u128,
                0xd94cdba7848132b97498328c6b019979u128,
                0x7ed8937b3f39aa5cu128,
                0xcda6cc229e4bbafed943513ecc1a30c7u128,
                0x0a78bdbdf6666272u128,
            ],
            [
                0xca25e7c80b5575d31419f0569a6fa52cu128,
                0x23bd9607c0c40f3au128,
                0x9caf5cf0d05131fd6ef1fcd1e8f23db5u128,
                0xfe32358ab268528fu128,
                0x5e91050553ac3629367f32b5863c2fc4u128,
                0x348138f445f0601cu128,
                0xabea2fa2681cc14998fc916a1d00a47bu128,
                0xa848a97a420a3822u128,
                0xa94e70f8d855e4c0dde234a20abb34e1u128,
                0x3eba81996f17839bu128,
                0x782842bc57c4168e16165e72f5667195u128,
                0xae548d42fa8486afu128,
                0xf5da48afd219d3bd61c30c94b8d436d4u128,
                0x11f79d98c77b889au128,
                0xde28c095192f9e5b6ec5a447d038944bu128,
                0xe64c2d5c9604e6bcu128,
                0xb11160245c39532981438e7e74f0cb3eu128,
                0xe31d7e3eeaea8939u128,
            ],
            [
                0x9a95dd0ebf46f41e4bc7509ac07e4510u128,
                0x64d6a21ffe1b444bu128,
                0x2952c18f2372f337a207b8f4d65598d0u128,
                0x50b6f956b3218afdu128,
                0x99a93b7996faa2d742b550a92af27dd8u128,
                0xb1ee6a5496efbda3u128,
                0x7acb595e759957e8944974e2b68e542fu128,
                0xade3ae46c8201ed8u128,
                0x540f4bf688301c14294027aae5d4fdfau128,
                0x5d235afcb0904bdau128,
                0x11105b5bd26c0140b383cbc22b77dfa0u128,
                0x4a65e60a8b7c7370u128,
                0x4b0cb01578860e0bbb5e7fe9d1a634d6u128,
                0x0a8e746bdb3419d2u128,
                0xe28f4a21323a079d85ad97c10ab07a55u128,
                0xbd27fccf7f8f5e0fu128,
                0x01e0d06c4940b1f9b725a999c5d5b20cu128,
                0x5c4a403f9dc2408eu128,
            ],
            [
                0x30a72e13285485c4009de1a48f46061cu128,
                0xbc955d59228da254u128,
                0x08edc57fd273688459cc00e2c24038ecu128,
                0x7dc39cb43f5a49f8u128,
                0xad268f71d6d063e5137496553579f369u128,
                0x45e32138200997b7u128,
                0x388becc301dbc7054bff372ed43a5234u128,
                0xc6704e0facdf08bbu128,
                0x9817a77ff0c95654bf6c591fa21ca58fu128,
                0xe6f6cdff7de5fa9bu128,
                0xdf6e813fa14fd41e3759d3d2f95d544fu128,
                0xe4028d47a3f41c5au128,
                0x7bd8c8285d6d2cf73fb8d8174f805d56u128,
                0xeb17827fa9e08b3bu128,
                0x4fc9c2cb4cdd226f9993219dc50b6770u128,
                0xcdf2554c9e016452u128,
                0xbc388031e60b2b9929b69f643e209ae1u128,
                0x4b0db8bc1c13dce5u128,
            ],
            [
                0x27a67b6bd2e13228edf66e1e2e2ca983u128,
                0xbad184ada3855d19u128,
                0x433e3160f07304b7ef12963e6c9d396au128,
                0x75ab197217777320u128,
                0x41c0fe25181855b6ede2198538e495d4u128,
                0xb2c2073bc9868e04u128,
                0x2a10a4bbd0a13e88e7f442fbca467433u128,
                0x319300086bb2065fu128,
                0x1276bf59e1dce88cdfa6f26de824dbbbu128,
                0x385c89ba90ba1144u128,
                0x85412138acc1bd1e568239529f8f85d8u128,
                0xbf3ef00ec349ab4du128,
                0x001d831fb3881be715aa83189bed5dadu128,
                0xcf4bf2939beaf2b1u128,
                0xc691e37b884f4edfc8ccf1c8a8213304u128,
                0x85a1f65e6e7ce448u128,
                0xe14fb8ed0163cab51df3f5d400aa22eeu128,
                0x506baa53968d7c43u128,
            ],
            [
                0x5da697682009b4f3af4edc72b4c4304fu128,
                0xa1e4b8db03acf0b6u128,
                0x8491eb1278713510d8a73aceff56ee85u128,
                0xe56576c2443c8267u128,
                0x425e7bd04df56b8f451230b3203a6496u128,
                0x7154f6523421904au128,
                0x106130f7c507c5719446e2319c01c476u128,
                0x32a713821be0317du128,
                0x54ce386f8c866ee0335b7b5cefade8d3u128,
                0xdf5584591d485e17u128,
                0xde68595259a48b3a8f16009018d0a169u128,
                0xe7c9567f839a98f7u128,
                0xa406a6127fd68f29624bad01fe43085bu128,
                0x6c86a92f6d627138u128,
                0x6ec40b21a2fdf7c6bdf980dc30e9025bu128,
                0xa5e2564f7af68071u128,
                0x57f172a9cf604a3ba2e7aae4d9c75f8cu128,
                0xef800085c4fa8303u128,
            ],
            [
                0x3ef170b423b0290ca539c4b920a3dfe1u128,
                0x474ce0e818ed117bu128,
                0xeecd35b69ac98faad2c2841d42b05666u128,
                0x86cee6f1c70be623u128,
                0x851bd0bc3d42fdceee1bd3aa4ce8b2b8u128,
                0x27263ac6e305a413u128,
                0xb9c0809ddec43bd1a4a3395d368403a2u128,
                0x5c08dea24159857bu128,
                0xc879be1e2d19af21af0b00265eac41ddu128,
                0xb73cee99e7c4bb63u128,
                0xed59b76bba45b058e2c675ee33c2457eu128,
                0x5090458767997af1u128,
                0x3134608b8ea60ec4e6f6b57244187a62u128,
                0xab821b1951aa37d6u128,
                0xce0f27d8e10997a0821ff14ad2c2a787u128,
                0xff47ca42d1012f69u128,
                0x45845f4e68ae7044b43cec8e7aedaab4u128,
                0x7c4e45c276fed5bfu128,
            ],
            [
                0xa3b9dc4b616dce04c42688e316efc7d0u128,
                0x1941fa2e133f30c9u128,
                0xd08fd6349ba2d321979da1722c842f37u128,
                0xdc55b69205161b0bu128,
                0x4be07c64bc1c92ca7e73cb2df01a2a5eu128,
                0x90267d5522334035u128,
                0xa927e6b56467b1da9a266f87b5122adcu128,
                0x1088ccb1db59bda3u128,
                0x17e1c49f5b402288bd72f9ea37c83127u128,
                0x41ccf3758933df67u128,
                0xd11272f1ed7b83c1692deead130682e5u128,
                0xd10e1914aa6694dbu128,
                0x93e1fc26c0b6cf5c0a90fbeff2b64038u128,
                0x06af1540915a316bu128,
                0x061d8dd66b20a148562b4a2d316db6ffu128,
                0x73f4e0f9815912b2u128,
                0xb948dae4c68f62a04061e20a4a5c6d3du128,
                0xe780a0a9d2d1750fu128,
            ],
            [
                0xa8806bf7d43c9b3c392142f0d8b0c4ffu128,
                0xb0acc8e732ba5ed3u128,
                0x01a67333c0be62f0810eb4e8a37694e5u128,
                0x68b767ab68eeab06u128,
                0x00394280228ce3e6b4a14a1672e8e932u128,
                0x1131bb5b85a2c731u128,
                0x235b7fcd66d61763567ebead963c82b7u128,
                0xbf4d54da9f3e0c93u128,
                0x227398543e8af33414840e8c77bbbb3fu128,
                0x28e81d5e0aa0ce0cu128,
                0x86b7d29a19fe85197bba1b892106cb51u128,
                0x81fbd6bbda432812u128,
                0xf149a8a2c6ba44302651286c01c9278bu128,
                0x2c8d5e9e460f43b1u128,
                0x5c8f8df30aa54caf978103b0f9398f1du128,
                0x94d38e3cda67e0e8u128,
                0x1db58b1fe29db7f601998213b254701cu128,
                0x87f5318047742902u128,
            ],
            [
                0x513ce354af58c302766e50b43b80c79fu128,
                0x43e7a79d2b6dac61u128,
                0x1692831be1ec3b1a89a5e0677150e0c5u128,
                0xb524659de5577ab4u128,
                0x367ffa2540fca390f133f8424db8b975u128,
                0x29360024c9dfa65au128,
                0x95d7049049b8aa52395d8de52d639d40u128,
                0xf3706a85c9e72611u128,
                0xb9490335f47cce0d2a2932bf12c7e852u128,
                0x6273d74fc777e9c1u128,
                0xa108e786362f43c4257fa34e1a108859u128,
                0x3f69a37526094ca4u128,
                0x480aaad36f31fa946e1293b2a61401d7u128,
                0x9e4160e111266d0cu128,
                0xcd8c13dc0502170a42d74aed1ab84024u128,
                0xc3880294617700b1u128,
                0x96714fe20effc7f6e4466fd6f5666709u128,
                0xa12e66f827048fb4u128,
            ],
            [
                0x3eb74093d50da0856120d413ae8e2c4eu128,
                0xf49bba98f18804d6u128,
                0x5fc8ae7c048d26886b29a0bd961e3c40u128,
                0x662496f52ffae967u128,
                0x9a0bcaba0e5e23875c24fc78d9c85d73u128,
                0x6c98b743baace4bau128,
                0xb4520cf9f0a82fa235cce77c150d12a3u128,
                0x6c4257b202c4ecdau128,
                0x346e9323a755eed3152b3f60911b2e01u128,
                0x3fa5e0741d4a9624u128,
                0x01e9ea20119e0003d167a381208e0235u128,
                0xc90696101fd17b41u128,
                0x736caec030cdc71b43fc38518bf4242au128,
                0x75a67086d934f8dbu128,
                0xf3472c0e03281698cb1f49597add7fc5u128,
                0xe96660dd350a70d7u128,
                0x74667aa1a991d9adc7affee74bc90338u128,
                0xed166a26f894c190u128,
            ],
            [
                0x5eb86fd306c56ca4cfc7aadf2b3bae1fu128,
                0xc4e67809348b6912u128,
                0x47bc9c50192a3877c8683460c171174eu128,
                0xc017c9814c934910u128,
                0xb60589cd9d55f515d7899f18f9763fb5u128,
                0xb83b663d69b06fbbu128,
                0x34816d74598b9bf239c434212f363838u128,
                0xbb1cc6d6df23e0b2u128,
                0xe22cbe4fcd1761669902aaff2860f57eu128,
                0xd3c8a7b93b360b75u128,
                0x5505a4eb7fd3c89a8a4988e1e76298d5u128,
                0x90dbce524b64ab13u128,
                0x91446dd44a40fe73810e823a61aabc09u128,
                0xd9c07e1188c38ab0u128,
                0x640eedb69698deaa196f7f1b98910b50u128,
                0x0547425dd9157101u128,
                0xb374235594a489453d8c81255d9529abu128,
                0x578a1dc1f67675a1u128,
            ],
        ];
        for data in database {
            let mut tab = [GF192::default(); 8];
            for i in 0..8 {
                tab[i] = GF192::new(data[2 * i], data[(2 * i) + 1]);
            }
            let result = GF192::new(data[16], data[17]);
            assert_eq!(GF192::byte_combine(&tab), result);
        }
    }

    #[test]
    //input : a bit (or a byte or many)
    //output : a GF192 whose light-weight bit is equal to the input bit (or the lightweight bit of the input value)
    fn gf192_test_from_bit() {
        //with bit = 0
        let bit_1 = 0u8;
        let res_1 = GF192::from_bit(bit_1);
        let (first_value_1, second_value_1) = res_1.get_value();
        assert_eq!(first_value_1, bit_1 as u128);
        assert_eq!(second_value_1, 0u128);
        //with bit = 1
        let bit_2 = 1u8;
        let res_2 = GF192::from_bit(bit_2);
        let (first_value_2, second_value_2) = res_2.get_value();
        assert_eq!(first_value_2, bit_2 as u128);
        assert_eq!(second_value_2, 0u128);
        //with byte whose lightweight bit =0
        let bit_3 = 76u8;
        let res_3 = GF192::from_bit(bit_3);
        let (first_value_3, second_value_3) = res_3.get_value();
        assert_eq!(first_value_3, 0u128);
        assert_eq!(second_value_3, 0u128);
        //with byte whose lightweight bit =0
        let bit_4 = 75u8;
        let res_4 = GF192::from_bit(bit_4);
        let (first_value_4, second_value_4) = res_4.get_value();
        assert_eq!(first_value_4, bit_4 as u128 & 1);
        assert_eq!(second_value_4, 0u128);
    }

    #[test]
    //To dest those one we use the test dataset of the reference implementation
    fn gf192_test_byte_combine_bits() {
        let database = [
            (
                0x0u8,
                0x00000000000000000000000000000000u128,
                0x0000000000000000u128,
            ),
            (
                0x1u8,
                0x00000000000000000000000000000001u128,
                0x0000000000000000u128,
            ),
            (
                0xc0u8,
                0x93f30acc66d1c99b629bc1b48bd364cbu128,
                0xeedaeb0b66eb2ef3u128,
            ),
            (
                0x72u8,
                0x67cceedeae3ff1085e32473db608aa7cu128,
                0x8b3c30bdb81dbe35u128,
            ),
            (
                0xbu8,
                0x6457341b905c30f350a58fc69a011d6fu128,
                0x3d30c564321e7894u128,
            ),
            (
                0x10u8,
                0x7a5542ab0058d22edd20747cbd2bf75du128,
                0x45ec519c94bc1251u128,
            ),
            (
                0xbfu8,
                0x0dfb187c1bbf8aac12f7cb04b4161400u128,
                0xb34ee1e036120504u128,
            ),
            (
                0x26u8,
                0x958544c224d33c48a62ecea99902ec20u128,
                0x3de5eb58915c9d13u128,
            ),
            (
                0x6cu8,
                0x02388777eb582cf36184dd19edd610f4u128,
                0x29739363ca2e0fc4u128,
            ),
            (
                0x19u8,
                0xf867a1dc066a5f37414d586f48127d51u128,
                0x49d75ceca8c95ca7u128,
            ),
            (
                0x24u8,
                0x73e093aeb2bd81a26ae66d7cf63a7b43u128,
                0x0cee234c9f37ab71u128,
            ),
            (
                0x18u8,
                0xf867a1dc066a5f37414d586f48127d50u128,
                0x49d75ceca8c95ca7u128,
            ),
            (
                0x87u8,
                0xfd8a35177a0b6b1f8b6f9f8976ca42a8u128,
                0x2ce4a966d57d29e6u128,
            ),
            (
                0x72u8,
                0x67cceedeae3ff1085e32473db608aa7cu128,
                0x8b3c30bdb81dbe35u128,
            ),
            (
                0xc5u8,
                0xe80515d5b3b2f6bdd0a8a02af7273471u128,
                0x3449dc2db27af5c7u128,
            ),
            (
                0x1fu8,
                0x65f469a94567ddfb3fb69a245bdeba89u128,
                0xa24fa3de7233b1f1u128,
            ),
            (
                0xbeu8,
                0x0dfb187c1bbf8aac12f7cb04b4161401u128,
                0xb34ee1e036120504u128,
            ),
            (
                0x52u8,
                0x6fda6269c9e14f8c86e74bdf3cc68184u128,
                0x5d4124d7f3bbce70u128,
            ),
        ];
        for data in database {
            let x = data.0;
            let result = GF192::new(data.1, data.2);
            assert_eq!(GF192::byte_combine_bits(x), result);
        }
    }

    #[test]
    fn gf192_test_sum_poly() {
        let all_zeroes = [GF192::ZERO; 192];
        assert_eq!(GF192::sum_poly(&all_zeroes), GF192::ZERO);

        let all_ones = [GF192::ONE; 192];
        assert_eq!(
            GF192::sum_poly(&all_ones),
            GF192::new(
                0xffffffffffffffffffffffffffffffffu128,
                0xffffffffffffffffffffffffffffffffu128
            )
        );
    }

    #[test]
    //We see if the to field function give the same result that what we could have with BigUint
    fn gf192_test_to_field() {
        let mut rng = rand::thread_rng();

        for _i in 0..1000 {
            let random: [u8; 24] = rng.gen();
            let pol = GF192::to_field(&random);
            let verif_big = BigUint::from_bytes_le(&random);
            let verif_0_0 = verif_big.to_u64_digits()[0] as u128
                + ((verif_big.to_u64_digits()[1] as u128) << 64);
            let verif_0_1 = verif_big.to_u64_digits()[2] as u128;
            assert_eq!(pol[0].get_value().0, verif_0_0);
            assert_eq!(pol[0].get_value().1, verif_0_1);
        }
        //with many polynomes
        for _i in 0..1000 {
            let mut random_1 = rng.gen::<[u8; 24]>().to_vec();
            let mut random_2 = rng.gen::<[u8; 24]>().to_vec();
            random_1.append(&mut random_2);
            let pol = GF192::to_field(&random_1.clone());
            let verif_big = BigUint::from_bytes_le(&random_1);
            let verif_0_0 = verif_big.to_u64_digits()[0] as u128
                + ((verif_big.to_u64_digits()[1] as u128) << 64);
            let verif_0_1 = verif_big.to_u64_digits()[2] as u128;
            let verif_1_0 = verif_big.to_u64_digits()[3] as u128
                + ((verif_big.to_u64_digits()[4] as u128) << 64);
            let verif_1_1 = verif_big.to_u64_digits()[5] as u128;
            assert_eq!(pol[0].get_value().0, verif_0_0);
            assert_eq!(pol[0].get_value().1, verif_0_1);
            assert_eq!(pol[1].get_value().0, verif_1_0);
            assert_eq!(pol[1].get_value().1, verif_1_1);
        }
    }

    //GF256
    #[test]
    //precondition : none
    //Postiditon : GF128 whose get value is as expected
    fn gf256_test_new_get_value() {
        let polynome = GF256::new(
            164039018632738885083851012429149951352u128,
            259919711421018557325306649715233556854u128,
        );
        let (first_value, second_value) = polynome.get_value();
        assert_eq!(first_value, 164039018632738885083851012429149951352u128);
        assert_eq!(second_value, 259919711421018557325306649715233556854u128);
    }

    #[test]
    //precondition: a GF256
    //postcondition : return MAX if the input is different from 0
    fn gf256_test_all_bytes_heavyweight() {
        //input != 0
        let pol_1 = GF256::new(1u128, 0u128);
        let pol_1_big = GF256::new(
            2730312856557028196081990424695764059u128 | 1u128,
            2730312856557028196081990424695764059u128,
        );
        let pol_2 = pol_1.all_bytes_heavyweight();
        let pol_2_big = pol_1_big.all_bytes_heavyweight();
        assert_eq!(pol_2, GF256::MAX);
        assert_eq!(pol_2_big, GF256::MAX);
        let pol_1_p = GF256::new(0u128, 63483453u128);
        let pol_2_p = pol_1_p.all_bytes_heavyweight();
        assert_eq!(pol_2_p, GF256::MAX);

        //input = 0
        let pol_3 = GF256::default();
        let pol_4 = pol_3.all_bytes_heavyweight();
        assert_eq!(pol_4, pol_3);
    }

    #[test]
    //precondition : a GF256
    //a GF256 that has switch to the left by one
    fn gf256_test_switch_left_1() {
        let mut rng = rand::thread_rng();

        for _i in 0..10000 {
            let random_1 = rng.gen();
            let random_2 = rng.gen();
            let pol_1 = GF256::new(random_1, random_2);
            let pol_1_res = pol_1.switch_left_1();
            let (first_value, second_value) = pol_1_res.get_value();
            assert_eq!(first_value, random_1.wrapping_shl(1));
            assert_eq!(
                second_value,
                (random_2).wrapping_shl(1) | (random_1 & (1u128 << 127)) >> 127
            );
        }
    }

    #[test]
    //input : two GF256
    //output : the product of the two according to te rules of Galois Fields arithmetic
    fn gf256_test_mul() {
        let mut rng = rand::thread_rng();

        //0 * anything = 0
        let pol_0 = GF256::default();
        for _i in 0..1000 {
            let anything: GF256 = rng.gen();
            let pol_res = pol_0 * anything;
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, 0u128);
            assert_eq!(second_value, 0u128);
            //anything * 0 = 0
            let pol_res_rev = anything * pol_0;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, 0u128);
            assert_eq!(second_value_rev, 0u128);
            //1 * anything = anything
            let (first_value_anything, second_value_anything) = anything.get_value();
            let pol_res = GF256::ONE * anything;
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, first_value_anything);
            assert_eq!(second_value, second_value_anything);
            //anything * 1 = anything
            let pol_res_rev = anything * GF256::ONE;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, first_value_anything);
            assert_eq!(second_value_rev, second_value_anything);
        }
        //to test with random values we use a database we get from the test cases of the reference implementation
        let database = [
            [
                0x000000000000000000000000000000ffu128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x000000000000000000000000000000ffu128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x000000000000000000000000000000ffu128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000001u128,
                0x00000000000000000000000000000000u128,
                0x000000000000000000000000000000ffu128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000001u128,
                0x00000000000000000000000000000000u128,
                0x000000000000000000000000000000ffu128,
                0x00000000000000000000000000000000u128,
                0x000000000000000000000000000000ffu128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x873fb24d59dae7ee5d31c2e139527c02u128,
                0x5e5ca55d913916c652d20aa1ebf4b419u128,
                0x2b2c35d3017c1f6da365d1dc8c5051fau128,
                0x272a1d3a41883caeb9bb2f760a252248u128,
                0x72cceca5923780f8d1aa34a28482df66u128,
                0xe979ff0476479752edeb92b6737c4e0eu128,
            ],
            [
                0x286984ba8d51968436a58a5c60a9433du128,
                0x8e2d8ace0f035dd46db2c7d8e1fcae4cu128,
                0xe721277fe8daeecfaafcc7a586ce4194u128,
                0xbb920f6aa81fabe2e6de27c507316bd2u128,
                0x69f8b0a07eef9d9eaa6ca2d572d10e89u128,
                0xa9576b36b4c3c9f061eb158b6229c704u128,
            ],
            [
                0x6905a24d97b13051f438d4f8a05001fbu128,
                0x9bbde52a03149a7d886a79d746e2bfe8u128,
                0xfbea603573aff59d5052ea29192d3547u128,
                0x611031e7a03e356cfcc816f92538967fu128,
                0xe1c55c580ed71f5ed4ae9d287bdbb167u128,
                0x91879e6bc0c926cf3e2cd54a1673db72u128,
            ],
            [
                0xba9f7527fb2fbdf8ee72c53b74f7f5d9u128,
                0x503991bad4bf5a9067bfdc336a34fc58u128,
                0xb4758347b4dd0dd1d42cc1af03363098u128,
                0xa53a0465cb487545c2b1081062fcb067u128,
                0xde0ad198ae9ea25b602d5fad6f426e9du128,
                0x7dcf294880f0bf054720e26021281174u128,
            ],
            [
                0x455fdf8776ffe145b60adaddfca57f89u128,
                0xc424898a91f8ff13d48c01477b2012a2u128,
                0xacea29b4a111bf4cd973d95d633d8b07u128,
                0x44ad1b79a26ba6ccb3ea7cc9d7546509u128,
                0x528c6851ada10510376ac371c0e6f259u128,
                0xf2415ece0aa90fe06628108dd99ce98bu128,
            ],
            [
                0xb33bad6c3a26d49e167d6e203a7644b1u128,
                0x16cfde6e3aab819cf73e1ebe88b231cau128,
                0x5f6cff1be86895e2d0e6875dea748ba2u128,
                0x0295155f7c5ee9f3470df50b6b6bdcbdu128,
                0x1770368a1535ad58d005c1dccd3fd896u128,
                0x63ca1fc97d6aa786920db528f88ea97fu128,
            ],
            [
                0xb8ae905bdcbaf95363d49da6d12f2a8au128,
                0x6ae349fac13b4d84fe7eb1d9c9368cc2u128,
                0x98414021d871e6317787e4f25e97137fu128,
                0x41f7af79603a3a17177975a0f12e088eu128,
                0x0887145374b61a73cd15d2a182245079u128,
                0x8f84657df75fb397d4fb757d568a5cdeu128,
            ],
            [
                0xa0726373109c15030657caf6e3e51cc2u128,
                0xf07a48ef7153220a82005d97efd84206u128,
                0xc7e1276277f168e7cd89015fbc5e499bu128,
                0x7fc6b7ee2788b1e19d627c3eee93ce75u128,
                0x7c1c1f1d604dcea51c3d2784d7764e4cu128,
                0x513d1999ba7443fa48a3c79f9c1ef281u128,
            ],
            [
                0xc539acd951270c6949de3bc34c8cdfdau128,
                0x817d37cdcd257fe590c1fa2d0125a966u128,
                0xf0b8bc198cce3d4c398526a613ea96aau128,
                0x9687cc5d133181abdff647dc2365043eu128,
                0x4a1fdc96d8806af3c0b37b58e5433a73u128,
                0xb36a15bcbe7c3ad9a61ff700426b80d6u128,
            ],
            [
                0x7925d6bb7f7ea8be4187ac0336b0a9abu128,
                0x8092a965a2fcb9de5250c8db4ae326e1u128,
                0x0001539b3dd4d6e1fbba3509b80b5d04u128,
                0x8859256d5eeb4fb5a862e987f3190df5u128,
                0x532edf0c379e5d3c92a0dceb7d59585eu128,
                0x4a6a511fa9ef84baccaa69f0f9d8ff1eu128,
            ],
            [
                0x5d1549c493ac344388d8804f133e3e7du128,
                0x890fb57e0b8d1510f2631169da26c3f5u128,
                0xec671685dc8ed64b8c41a1ea59500099u128,
                0xecb0d3c799c84032232c0fa1d1b1b305u128,
                0x4d395abf94eec0396eb673ca6f087f38u128,
                0x8f20fa75f1fbf753ce3ec5fb0c4e9b1eu128,
            ],
            [
                0xb28bad5fdbf7debcb5262f0025560227u128,
                0x06128f73f5e9613db80dc48a0aaea178u128,
                0x271403bdbdf27067fa1a9c6e6fc0b426u128,
                0x2491234cee9fad810d066abdb7d7bafdu128,
                0xe834d9f372fbc3055126f04f79826384u128,
                0x4bd6f9f94634186f341a9c8dc0c333cfu128,
            ],
            [
                0x102e4fcc75a1c9bee04a535082ab1fd5u128,
                0xc66ff062b8d8c17ef11952416938fa4au128,
                0xc5bb609976355287c3f8a4dd3c4fe918u128,
                0x9cb72a7a68195ab82f88233e2d410f80u128,
                0x71771eef8ffae44d449e3f4551ed4eb2u128,
                0x203aa42c9f08f165d16e7f8e486c66d8u128,
            ],
            [
                0x8d057e10608e08c3ff42997fb7ea1558u128,
                0x1fd9a9199a39101afab4c040186034dfu128,
                0xea3bad6b46f35bb4c1acb345abe36821u128,
                0xf66182f00e4322c7c870db2a8b6d3d1du128,
                0x265a503af8093faedf2d443d8ecc703eu128,
                0x47e2a978d3085a861911fa326e867df6u128,
            ],
            [
                0x2e7cf06c728581f5a12f199abed5b16eu128,
                0xcde0f328ec1d6869f4bff53562fe163du128,
                0x1411f00005f5fa12459c5c72c753d3eau128,
                0x1528d12320e8c5194e3285507f745c22u128,
                0xf9dfe15f694148b9a33220202eeea695u128,
                0xfae935de714c10d75f0d06f2f2582346u128,
            ],
            [
                0x1ec3c97b7299085497d36d31cb2cd0d4u128,
                0x2fcfed79cc425b9c4af13df692809f30u128,
                0x9c40c8dc861476992ee49857052bcfe8u128,
                0x72d806d99cb81ed96ebb83eafe122293u128,
                0xb3bf00bbade5c225e71d53348d303667u128,
                0xdd8609792df6e06a86b1ebe5dbb57f51u128,
            ],
            [
                0xde43f830d7d2529a1d5f5ab59abb75c7u128,
                0xc0967d0cca9c687cd082e7d396b7166eu128,
                0xe6d508325d16bc5e0fe472ce029442c4u128,
                0xd40c720893787ff58b5de54cfdc43c29u128,
                0xa75ce945ca8743382a30365e9ac6a51du128,
                0x3db4c2128c50f21b481702500ee61bcdu128,
            ],
            [
                0xbb95fe627c84436194d27f8824add387u128,
                0x2d211698a818581ae7add7867a37ad80u128,
                0x0f022989babef318c682896d893c2970u128,
                0x7e7cb3f788c6ba0c3fbd55032116b2e8u128,
                0x460eaf8fd4b48b30f52e25842f1ea95bu128,
                0x16eb9a15ab32178ab41377900f9cade8u128,
            ],
            [
                0xef0cfe198d0d8fc1cba7162706a9f5aeu128,
                0x77c806c130e822ee076d6191f272e1e6u128,
                0x8c23661fd66d1966c870e8a767a3d2e6u128,
                0xa66ecb5f42b601025788024eb8357002u128,
                0xa28b61ced21ef6c39d04edef81998d89u128,
                0xd0a922b43de79557a1c8c571f4636d73u128,
            ],
            [
                0x5186546b79e38cdd5fe7430f9f52c776u128,
                0x68ce3eab931aeea8c9492f3b203d54d8u128,
                0xa1a5f6f1ccc2f71b7b9d1fd512f2e1b1u128,
                0xfac28933ff3a58f5b96bfb9a4875294cu128,
                0x3b99f44107db4372dd688736bd04f1edu128,
                0x2346159e3445efc034713baf8e8fcb91u128,
            ],
            [
                0x75dfe4680c2d0b1fb85d6a0c1124ce9bu128,
                0xf1403664ffed8c6042b8463e0812b960u128,
                0x9e32c108bc59840df66c3b2c8b9b239eu128,
                0xba421e57d6f2f110bc30677ed9838e47u128,
                0xb9ed196a8bca77f148823aa5e9029af3u128,
                0x32352dbc47c8bb00c8f56e5535cb5336u128,
            ],
            [
                0x14e5ac2cf9c876bf56999023b102a57fu128,
                0x1be4179dc185b05626a3c00fdcabe663u128,
                0xe3d90b2cdd9939745aab61d5491ad98eu128,
                0x8a73ad8e67dc42d4c1e8caabe80d7eccu128,
                0x27f408e32b1eb78d8b1f5108cd6a9320u128,
                0x161886dd64746ab250b2dce701139b2au128,
            ],
            [
                0xaed4fa2d0d139d31f7f483e05acb4de4u128,
                0x8d4fe3acf9d14106d8f81c309b95ea09u128,
                0x7dd3331d378c86484cf58bd83dc2da59u128,
                0xd9cc68f0dde74140653457cae0225ba9u128,
                0x38a892a57930531c88fe9fbc719689d6u128,
                0x463d7a29d1bbbc1605a908f64ebf7ad3u128,
            ],
            [
                0x668cd490b8ae9b920b52ebe3e747c11au128,
                0x35c55e3819381c67de3271c7ef61174bu128,
                0x2c928d9c0de566ec4c7ab8cde3af6941u128,
                0xe45da2a6411727fe22b952e8490fe8b4u128,
                0x0b0746066a4b598f4095b88c94d6e628u128,
                0xebe16bdffbc9a8fa5faef6427089a23du128,
            ],
            [
                0x980949978fe538cd51943337bf4e648fu128,
                0xdcd3f183a34162dd596c0be7f79ecbaau128,
                0xeb9956fba0a79ff0a8e1ff4ac0a8c46au128,
                0xc506aced55c834c6b611ab69fc43931au128,
                0xcb9af67949eddd566d09cef2869cee5du128,
                0x8e51855a02873d09c5c7a619eccb4ae8u128,
            ],
            [
                0xf4e1ad225bb2d5e2f1af784badafc3f5u128,
                0xcd20304156d9caefd3a52639156895d6u128,
                0x2fe97316937a376a9fdb3f2832996312u128,
                0x38f37950d66a7c9673f960e359cb7967u128,
                0x987e406565d1ce4c029de449f32c4e1fu128,
                0x1aac7d555b2cc05017b7086aa9c53bbeu128,
            ],
            [
                0x0397ee8de163ff064b660462c2b77807u128,
                0x10f3bf39a92f2f861464499d02867270u128,
                0x10406b457a09379b320aa889c3d48c22u128,
                0xc898954d895aa4d103ee455e30a303f0u128,
                0x20d75a2f0ce6b7ae6571f4ebd3af7c2fu128,
                0x5c34954f24c6f7426869e4da01d2acabu128,
            ],
            [
                0xbcf3afe02c5b33b41f85b51cf5d3286du128,
                0x9243825fe3c3a60c91f3871b5a506305u128,
                0x578025876c37990bb1ba5d952e2245bcu128,
                0x83ee506ed11bac0f8794aae173feefb8u128,
                0x7e2c32c2e6a2ffc9b7cf9fcd19e4dc6du128,
                0xad5cc772ad2e5892b0f9800b1cd22ba6u128,
            ],
            [
                0x646ed49ed1fdd7b39403cf25861d46e9u128,
                0x032ed6b58842087e14d750988ff7505du128,
                0x6550fdf198108c4db8f14545a11a77bdu128,
                0xbbdb56e04bfa134ab28d88f49b1ccdb2u128,
                0x9e85578518dcaf097a29ed120460b06eu128,
                0xaa98515b4f7a3f246fde3c11c3cbe483u128,
            ],
            [
                0x55f16f9abcaa875502404d559a481a81u128,
                0x3860ff04ff220c70c930672b9fbd7853u128,
                0x1c2226c2f93b65b2d01be12919e1aaabu128,
                0xebaa36ee4a2a064807bda4488dddfd70u128,
                0x6e3f4867e5f396df7fab6ef713410ac0u128,
                0x6c486bc4ba16fa64ba1dfd1105be9be0u128,
            ],
            [
                0x6bdbe4c421fb13510e2cb5616689d9ddu128,
                0x6655f71bcec551c6248da1233fbe3b24u128,
                0x21f5e3d9a2ef32b01b106551cd59614fu128,
                0x560d0ec3c0eca2dc6e35774bf49a90efu128,
                0x5a1b88fc6c6ad331ab0bb2667bae830bu128,
                0x972e00e7a35f81b36460ac5c7e00a39eu128,
            ],
            [
                0x47d4cce7acde12ec339ea80a955c20d5u128,
                0x7345e50d2124d2aa1c4477b0b9216aabu128,
                0x77ca48843bab75bddf381d77c740b7c4u128,
                0x593ca0f23ad07f7cfcc39d878798ffafu128,
                0x9c064d225aec0b0b8978f372b5525a1cu128,
                0x944db9b7676a8f90521a1533a4e13ee0u128,
            ],
            [
                0x39475c691057cc6398f752e215df0a8eu128,
                0x3f85dce8f1927bf05a31f6adea56d671u128,
                0x45447e1d952e8f9895c544ec1012c592u128,
                0xaf04f49f25d937f47074f0c4e4f56cd2u128,
                0x0326478c8d3cdf681dff33e38e9152eau128,
                0x2d1ebd6b90bd3ede77a148c31cb0a009u128,
            ],
            [
                0x910cd4740da36699479beee0e6469ddau128,
                0xdbeab308c763f6c2ca020bfdb9e29085u128,
                0x4a5e7dc5e69f15a1f508762fee4702e9u128,
                0x60c67acad0cf82a856c3b8bbc651e522u128,
                0xd6d3058f70c9ba5a9c8e4978fc45a8b7u128,
                0x29908967ff8890fec8a0843e947826a4u128,
            ],
            [
                0xb0307a5f138556b28697825ab334a755u128,
                0x3c853368ff04ae231a3e59692bb0bbb8u128,
                0x17f16c8fafa8288e639ef843ace01e4au128,
                0x09561eeac67616a8b6c78e1f9d86be5eu128,
                0xfc8424e1ff09507408ec6297e0a43392u128,
                0x447d801dd204c1b6b7bac3e986293473u128,
            ],
            [
                0xa5269697b90b2152a7469ce835d88203u128,
                0xafefc11cbd3735b368580f52b2e7727au128,
                0x189f2b67e18ad5f7f5a79f68dd72c6d6u128,
                0xd55a67482eaead31458a9783edfaa97au128,
                0xc7f20ade49a2d65ea37a39e39ce9d5acu128,
                0xcd1ff482f02599d9b140e63431052197u128,
            ],
            [
                0xdae2ac951978b79b9b896c0225f64150u128,
                0x21f2ec91393d38b86423c11be2002f28u128,
                0xdedbd920ef5b82ba678284b4e57105f6u128,
                0x00112af4ed8b06f5e49d72d255f7c90du128,
                0x6e99e887e2d9842c1e0941595a3039eeu128,
                0x366eb6a3e64d19ef50bd2aa3b94d92b7u128,
            ],
            [
                0xa92450d6efc9a037800964120cc1eba4u128,
                0x84ea815aae84c84d2159e6829e637b10u128,
                0x1a4a63b7314cea71e7f4f8fa666dd4f4u128,
                0xab2d035e72415bf03ed3e8cee6f7f0f5u128,
                0xc796c9fd384172078bdf1b8f1be869bbu128,
                0x60e524f00a0317e068f38c9bd8824b0fu128,
            ],
            [
                0xf53d34c397e9ffdbd51a0d1cd4381a74u128,
                0x83a1814e673b390996b1c0fa39b6b7fau128,
                0xbd63047c1349be2665ad4a8a56c9623cu128,
                0xbf436f54be624cfed7133b33e872f7f3u128,
                0x8a9c6fa5d0de0bb5ba28e9999dffcbddu128,
                0x56c47760c32614506d1cd1aff42541d2u128,
            ],
            [
                0x210d8f31fc4aeb0fc11d1d3aee97e4fcu128,
                0x4a609d77baf7d72362befb63a716d96du128,
                0x9651c85f4e2c829fa1afdba78a25867fu128,
                0xe76720ebf1f3143d6c1374ec28652b2au128,
                0xb95a3efeee1b607b1df7037fb1fcc717u128,
                0x70461e704eee89d0e13ab1718434a114u128,
            ],
            [
                0x1124f73e0cd0aadab89128bf7bac0c51u128,
                0x3411cf2faf04681e9804e1ad734d72a2u128,
                0x92ca37072128375d186c4223f366764au128,
                0x21c1c6e14df5dead46e9f5e57d5c0c04u128,
                0xba02d85152e7a98fa217f884d55fc6fbu128,
                0x2c58f09551c33b839de90ebf309ef044u128,
            ],
            [
                0xcbd8d3fcca3f89c088fbf8e83e86035du128,
                0xaccd5edee1d05749603d7b6229c7de07u128,
                0x881d4002c9adf3c92d8a1d5925c58c55u128,
                0xc43b47e5953cda26b90ec463c0037c57u128,
                0x1bce1d3467447617022c548999644ed2u128,
                0x56dccf49690625feaf72655956a182d0u128,
            ],
            [
                0xfd8ec38103e54cdc5730e7fbd77b89b3u128,
                0x01e6ba4f32ca9fd55f1fa3d61d4298a8u128,
                0x4cc8234137da6f2020e48faa53855f17u128,
                0xf291a4727c8abcb5b0ad39d72c7bcb05u128,
                0x045b24fc30c58db284314af4ef89f61fu128,
                0xb10d39f89325fdcbab2c281f9239c387u128,
            ],
            [
                0x1f4d9a623e9cff994e7648eeca4f63b1u128,
                0x633956f6b9879a01506a09d964ed20dcu128,
                0x022b61e0e3b7bff2c227ef07596ee504u128,
                0x9aceefaff73bef7dfc6fa1d38aaf3325u128,
                0xa9310d8fb5e2be1198e3e23b23810518u128,
                0xafa3fcf6ded8f3e1cf31f9ff00d3dc4eu128,
            ],
            [
                0xfe42dc69ad75387c188be0ea0174b013u128,
                0x8c4e99178d9cfa5237dc745bd3a9df24u128,
                0xb5c1facaad1bfb80d94cac1e0f5f6c36u128,
                0x4637dc863e05c2aef2801bb511cfad6bu128,
                0x5827691e8265066d9d55d850d85d443au128,
                0x1f9223c7450300bb9c93b925b43f70a8u128,
            ],
            [
                0x5dc1ac1cf800039fdd97ac349a875e73u128,
                0x350100b6c6b7a2096231f837e7574dfbu128,
                0xd910c1ea804434b12b1e58dd38605218u128,
                0x29e305db2444767203de0dd733db8e97u128,
                0xab30ef10b748d76d855d7d869e290f5eu128,
                0x7343b968c04b4e6c8753951b669b4b7bu128,
            ],
            [
                0x3e859aff1e615b571cf967151c55d656u128,
                0x61cbc1e2336941dc48de509cfe76d89eu128,
                0xbf2e00074b09037c80da6a06e83269e1u128,
                0x105dafd96228ea69a0ae3eb6cf892e36u128,
                0x7ec36870f479f005eb82bc5c83300a83u128,
                0x6463cd102ecd4281503f5e47ee332874u128,
            ],
            [
                0xdbadd89de15f78d83f6b5f2f52394058u128,
                0x00729ee8f88e9cddbf71eb81daaf389au128,
                0x40de2a410107d06dd7e3af28e91ba9e8u128,
                0xb6423c1671cfb7a903371a4a8056a7e4u128,
                0xcc69fc307cefae6c022128a2828734e4u128,
                0xd5107d181b65a98bf21da8f224d32117u128,
            ],
            [
                0x40d47cb2ba0629c4fab2649b7848d3dcu128,
                0x69b98ed82729e470a82e858fb37b6072u128,
                0xbb3c375b2f47c85416855a353d7bed17u128,
                0xf93166893d493a65c02e5ee712f5d2d1u128,
                0x4718a452a04db348349ce080d678208du128,
                0x7b3a5b8d05c3ea7e039ccf58971f5086u128,
            ],
            [
                0x7b8ca91f8dbc5958f63505eeda38f3c7u128,
                0xf3105d93ace8f920b6e51bdaa32b45aau128,
                0x1eb3b73ae51143a00aa74b59cafecc84u128,
                0xba0487fea44b5042f69eefe0b566a1f2u128,
                0x270871c4ec286b590cf1cae9bb4f30b2u128,
                0xcc5a295925310bd333f60dd9381d309cu128,
            ],
            [
                0xefcdab8967452301efcdab8967452301u128,
                0xefcdab8967452301efcdab8967452301u128,
                0x0123456789abcdef0123456789abcdefu128,
                0x0123456789abcdef0123456789abcdefu128,
                0xd1585753dd545a57d9505f5bd55c5e33u128,
                0xd1585753dd545a57d9505f5bd55c525fu128,
            ],
            [
                0xefcdab8967452301efcdab8967452301u128,
                0xefcdab8967452301efcdab8967452301u128,
                0x00000000000000000123456789abcdefu128,
                0x00000000000000000000000000000000u128,
                0x4040404040404043911817139d141b1cu128,
                0x40404040404040404040404040404040u128,
            ],
            [
                0xe13955f9aff8908e1a602bc65b84ad02u128,
                0xe806303a92e1556de785527d6df44dbdu128,
                0x01c14576c88bb9aaf1778e18c4f41c46u128,
                0x463b51426779b1e6a205f4d0ac91bfb9u128,
                0xab33ace82974d8c61d9766ae1eb79ff1u128,
                0xafce0b826a53a5fd467f5cc9c248f1bcu128,
            ],
            [
                0xd63eb11a5bed75606ef5c19d2c4594adu128,
                0xcc2a5df243116d787c552b3c9f20daecu128,
                0x42a3862adcf8930ea2a902aa4244ddb5u128,
                0x96d87ba8ed905c0ece3dc98aae719435u128,
                0x4b92d7e149a89a71c42ea8400f84470du128,
                0x016b1e77918973ae25e6e3981a8d5325u128,
            ],
            [
                0x33247e9d66676fccaabf2d1b5ef55dbau128,
                0x958100e36b4500a588e6dd72856581e0u128,
                0x1a3ef35af4a3f1ae0b60f07d1b6efcb0u128,
                0x4e773d099aa2dd1159a57792154818c1u128,
                0x9d1e71e5563f31a7207e973785ee1c50u128,
                0xe45f5c05526394bff4f24dc000ab5e11u128,
            ],
            [
                0x4c0c71249c15c691f85b2f771021ba56u128,
                0xd9718236d884e72f6007e59181619ee6u128,
                0x966effb1c5a985f00d0b423fb251e6c4u128,
                0xf6fa3f5067bc2394b192af172772c512u128,
                0x84d47f580b4391e19424ebb20f68a202u128,
                0x2713d95e027bb006d0f6cec679dc85dau128,
            ],
            [
                0x09652740f40b2ccac2ae171f9ee927c9u128,
                0xc0fb108da084e0d76cb7a844c166a0e8u128,
                0x0f88ba89a2acbd6e9cc42f8da2398239u128,
                0xafd33b72c081fa9e505aa1ac5a69679au128,
                0xc69c34a4e338851adae21158117895c9u128,
                0x969b50f708147fa814b364809dd51432u128,
            ],
            [
                0x47b5200ff4427f6813be68ebfc9b92b6u128,
                0x8ab26186c36f72e133f2a4fd18a799ebu128,
                0x1a3b516d27d9303a3cba2da4e092666eu128,
                0xf6fbb93fd6c9fbed93d0791c9a6cb1b1u128,
                0x68e2b920fa585210104659b13ffe0524u128,
                0x555ee1036d0aea10bb0104efd3007ec8u128,
            ],
            [
                0x328980161845efef4c8609d2e2f38111u128,
                0x801fff7f319f36c406cb9380d4ec2747u128,
                0x7222e3bbeee1bb7f4428fd8251b2b583u128,
                0x5beabf767098801f7b65ce3b0101fe33u128,
                0xa105ee30d99ea71475e17fd6ca013277u128,
                0xd22a7a4822c90beb8b4ed4dd1825314du128,
            ],
            [
                0x3d349a9b8711b8a93f4ecd0456180d97u128,
                0x16060b7c1bc51c942eed2ff5de06b978u128,
                0xe57d4eb5469acce9b78a0bc047b7c914u128,
                0x0a41ccc6ca0ed413190dde2781570771u128,
                0x595e9ed1fe868c860f820b44e5c555c5u128,
                0x57d46ba82ef3b63c482d4cae45a56d35u128,
            ],
            [
                0x66cde9249d4345af1bb2c50186e77fb4u128,
                0xe6acc32e3c29c7a8431f413a153935f6u128,
                0xcab283c94705e26c9d81fef6784c2924u128,
                0x3c166faaf69d9ec49a508fad51d6401fu128,
                0xe2c5c7eea4c95049270ea985487e0d13u128,
                0x93d5272acf6a07df8f40490a3e1d3e37u128,
            ],
            [
                0x315b545154236d54df2cefeefe89bc50u128,
                0x51ead2452726653e8ec87fa9dc3b751fu128,
                0x5939ec66be89df4491c2ea60a110c1e3u128,
                0x38e40aeaf150f99df7846deea23eb18cu128,
                0x8cb644a687a295acf206d31c36d9673du128,
                0x16eccd89e75d39dbb9e4e8cf65fe6148u128,
            ],
            [
                0x974e365c05f71650fa593f589b735a0cu128,
                0x91077f3b3234e112de69bb82e66b29f2u128,
                0xe415f3ad508848e449cb94ee42552057u128,
                0xa7546b67a5a3d2a55bfba11e067003afu128,
                0x6726bd4d5b2d018d5a2b349dd6c7d34eu128,
                0xe69918e370984c29dcb1ba6c972ab400u128,
            ],
            [
                0xf0340259dfbe7d131e6e311aace195e9u128,
                0x2ca8dbabc2dbf6d604a275993d801649u128,
                0x7b20029c1abdc4fad81b12f60543898cu128,
                0x08493327746fb24a0d53e3cb39420e70u128,
                0xcaa5d2452acd487da526b30512d338e8u128,
                0x854c1fb94828de51524b8dc2b0b8a31au128,
            ],
            [
                0xe83941cffe0410bb77ce1abaa1db5657u128,
                0x193cf1c2d60e7ec78c119ec82a3252a9u128,
                0x0e9ae6b5a752cedab1fd7ae252a04964u128,
                0x551a777459958f2182662135544bb9f3u128,
                0x346831d122db09b7808127b6f67c08f7u128,
                0xd868b4521a9e09680893eee26bcc7e49u128,
            ],
            [
                0xeb024ae6f61b317667ff36e062b85843u128,
                0x0800cf928d7ce61e19b0b66e5c8f0822u128,
                0x16c5417ecc63e63e8b42ded7b4fb6a6du128,
                0xbc808f61a9351bf298d3444913cdbdc8u128,
                0xd45164d48a1b3e0f9a2940d277f50c7au128,
                0x04723e707a21179b7db806f83477c09eu128,
            ],
            [
                0x1835a5dfac083e7c0959d62783a8a0e2u128,
                0x2e8ae067c3b5fc73fefa26bc780a89fdu128,
                0xa08f66a3d8e08394a4199e6faf5c0ea9u128,
                0x5e2cf158b95b9fae5d8b0926e94e2ea0u128,
                0x357bcd47152ea7e04a4ce74d21667487u128,
                0x3daf042a9d2a898bd39cf49d48ddeeffu128,
            ],
            [
                0x6e4fcbfe8b9ee525989e81ca3052059cu128,
                0x25149c43c8453c0f1ac62b0471ec72ceu128,
                0x97b0780fb819f51082402597b656bd22u128,
                0x7536b1f7a4751f392329d1c86660a1a3u128,
                0x167c27436ac4568babd403b2399efd08u128,
                0xb48b817fd971efe54364336b63f72e6fu128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0x2f3449f2e8cbe4aa1750dbe80784797du128,
                0x785718c8643f90cbf00a2b44e44c520cu128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0x6d5bc7bb4e40be4875340f82f245fb5bu128,
                0x9227ac266f020d4f83dfeb2048430fdau128,
            ],
            [
                0xcd1f541c526b2858845085d4585e3195u128,
                0x3c4d95656093e8a67d987592386f10bbu128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0xa1695eac3c2470049895b845b589a2efu128,
                0x39aa376a3dceb1f7450a4fc5bb6ca302u128,
            ],
            [
                0x79d80c08067b57b715781685826a45a9u128,
                0x51841922e373ae1ff6be29fc6973dceeu128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0xa2cd48dd526564d79d86d8234140cb85u128,
                0x0ec3a14550466f107bcb54cff1c36cd7u128,
            ],
            [
                0x65e980f30ef160d7ead1ec197871a49eu128,
                0xd980b385fe6441b11602304c60062cafu128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x3b915ceeb74e248f0980680d8113d5acu128,
                0x5b732d0095b7857cbce60608820a7931u128,
            ],
            [
                0xd1f695b8d4fffbdc80fecb34d00aa6e4u128,
                0xc480651e55ba153848ff2619195fad44u128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0xccc566a2272eaf79ec7a00a9bc92ef1eu128,
                0x453223c1218be71c0b2ffb70fd689605u128,
            ],
            [
                0xe0f23512dc60c54e627ca406cb8f1971u128,
                0x63c2571fa4a322fa6f0e68e934f6c7eeu128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0x45350297dd175a9e7a868f7e95de6378u128,
                0xaab0804e3d5a02878634d8f7b83b3818u128,
            ],
            [
                0x18d1be01fe3c79b618ce224026cb8615u128,
                0x7149fd9d016bb4c540e9d47b53b99376u128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0x46be325ca42386899749639f2f2056fcu128,
                0x9b33065eb7b27dafed045d6479c92185u128,
            ],
            [
                0x5e63ba879f7bbcc1134b677fa79c420fu128,
                0x5f782c727f0edbf4c7c6836b75f93979u128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0x175aca2a62f95aae9a3baa578e4cb0d5u128,
                0x228cf2c025e03dc5b12736154c25ef10u128,
            ],
            [
                0xc3ccafda68f50580b0a8f02c7071ec7au128,
                0x68e09ffda9b15265961f1f123b3a5aa9u128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0xd1dcb82b7bb1080b46d01f4bc7ad3595u128,
                0x998e23e9c72a810fee80fd9523fe607fu128,
            ],
            [
                0xb995d866b4f398589ba864949b0cfb1eu128,
                0x978f7cda10ff3919c056cd7347fbb110u128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0x34843c22798726eb36c2515f4e778714u128,
                0x8721379b5984743412955586aa381873u128,
            ],
            [
                0x6730a2d21cd59123a63be54cb256b681u128,
                0x82fdf1bb32a91b87b9e6dba6a8c43b2au128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x6e90ce7b0b7386f32b5d9c43e846c302u128,
                0x0ef530e4c4b58f8f4746c4ab4b58745du128,
            ],
            [
                0x8dd966ed51f8c6f1cdf44f98aa574a75u128,
                0xfa8acfe85a88f532e3f02a6c73622a3du128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0xcf24dcc5246f75fb45e3ef639d74b4d6u128,
                0x3ff113dbaeaead3327a1063a36d39dacu128,
            ],
            [
                0x75e504c662fe81d91fe77b81829998c9u128,
                0xccb0d154d3a2e9f4042a2598cba4ddeeu128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0xfa0ba7c43c3b88a285e3c8a55eee7163u128,
                0x3cde132530a3a5fe0e834d000142fea8u128,
            ],
            [
                0x74a2697ca1055bcd515b2e9962a175b8u128,
                0x462f300800fb7a188d6fc5dcae924a05u128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0xe52860109b718b044d6ef9714dbe854bu128,
                0xb12fe22612597bc758b9d655c222a705u128,
            ],
            [
                0xe104967b693c7ea3b8b56ff226672c4bu128,
                0xfcb16a9307ff03800d4ee75241866099u128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0x122f860f9155956328dcd64b34d051f5u128,
                0x2b5ca498cee6442ce790fc086d528338u128,
            ],
            [
                0xb1bbcf2f7e6d23a74a0d1c5b486ec8dfu128,
                0xbaa4cdcd58675bd895b2f53449126979u128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0xa93f85cedd7019c72cbc7ff964c47147u128,
                0xcbd663a3aa2a52fd872916fdc47368d7u128,
            ],
            [
                0x23b0eff67517ddacadb01fe65aa3a44cu128,
                0x84a8ea16f09f034dc4102a6f6de7086du128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0xade4c688d562c4df659b92095b620edfu128,
                0xddb8579b2bbef209d364de5a7a91a96cu128,
            ],
            [
                0xae9ffe65941bca42d8f681031d43bd38u128,
                0x1dbfd057cf88293517c5df883b2d693bu128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x26cec338a69eae381d60955d1a36cb05u128,
                0x72b84e32f8dcf22528a265b65f351d94u128,
            ],
            [
                0x4391f1fffeb0a3ca4d8f66ae244b41cau128,
                0x483a66dbbcb5d20dfd794a988d964f7bu128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0xbb883c79a5c5dac75a7d8707198c4a9cu128,
                0x6a845d7df3a1b76fda30584f3a574737u128,
            ],
            [
                0x9ca0557bb69bc01e7302790a5fc618bcu128,
                0xae3068bf98ab91197d16d75f5d5c44aeu128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0xa55c36dc73951304e296821b07de3daau128,
                0x7f4b59572a390aa0f61fa0faa423ebe7u128,
            ],
            [
                0xc68b0c83afd12d35ef454cf8ec5208a1u128,
                0x04d083b6f381b7e2a7a0926a6fd1704bu128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0x3f3f3be221388599c376fc2c04da1e34u128,
                0xba340128c48dfd38bb1ea6f4027e7229u128,
            ],
            [
                0x5a344f99c8a3db604192152c07330059u128,
                0x2b54d26bf8dca9ab357baa73d9066b6au128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0xecc7c4463b073e870d83dc435945b21bu128,
                0x5ae3de867ada2331f911f8e577abd222u128,
            ],
            [
                0x3dd861b61e0a8cc895411ceb598f9f5bu128,
                0xbaa05add572397089ded7f38b48bc122u128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0xfc9425594213c9a3259c8fd39f3a1580u128,
                0x6b41a68bff102c61c1c7768af5428fb9u128,
            ],
            [
                0xb0d21b849b77cafa85bc25acb9e97a29u128,
                0x66a86adea9063ae567a5bcfbfe518bb5u128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0x56d4283a9f00b110fcfb77d506dfb89du128,
                0xe6d13e161c77796788fb3d65507ac58du128,
            ],
            [
                0xddc211eefabd924e35fd04591dc19755u128,
                0xbf050e2f378d8f0333f42dcb03c65927u128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0xa9074706b07bcd68ab967433bf8648d5u128,
                0x1097ffca6367a43f158c182e187415d8u128,
            ],
            [
                0x90b1e3329e1e24c829596301211686cbu128,
                0x4de233ec1f709153d0b7d4e596961d58u128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0xbd8d860d8470fe9045b3cf48fc7659bfu128,
                0x126b1068228ece271dd90c8016a8cabcu128,
            ],
            [
                0xdabb2d457113e324d7a4f779881c4f16u128,
                0x40bc17e6c332b85b63cb533eec12c495u128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0xf13a53e9ded11705b4922f34ea9aeca4u128,
                0xa42f8f65f583af07254b264599173e44u128,
            ],
            [
                0xead5b92670e0089c41b969af0669b111u128,
                0x68a72d8b8c89c80a0d59681138775345u128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0x4f53e6c0e76ab55196d0bad1f5960984u128,
                0xe3a55e6e3d7b5447d8d30d6c11f3dac0u128,
            ],
            [
                0xa5bacecff26d2272fb474dac8ad13e2bu128,
                0x7938876502398c7dfc39b519f2e9913bu128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0xdb00887570cfc31d161c2197e3c9636bu128,
                0x87131dff927cc824a787e20b06b51666u128,
            ],
            [
                0x96eee2c2ec96c62aaaa4554fffb6c221u128,
                0x4f593dbee9887b149eb3c98659134279u128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0xc147162e3da5cfe9f6c165261e12d10cu128,
                0xb7d5c54297abcc7273f42d08d745acf5u128,
            ],
            [
                0x3f2924d6cb1d8440e500879bb409388bu128,
                0x7ecf8fb86310611b2b6ac9470269ffe2u128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0x8fd5e527a9cf7695ce028afca85965ceu128,
                0xd3c7e097971465f6faa07623a5758d5eu128,
            ],
            [
                0xeb5de4ea9c626c3177db69a17268541cu128,
                0xb4e8eb935d0bfab304ac26c2befb84bdu128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x20fcd128196c932654a3c24385eeeb6cu128,
                0xd4e0699d73bafece51aff1cb74c80591u128,
            ],
            [
                0xc6466496e5019d479655acf6201b4765u128,
                0x87a669bf4063057a71dd51461eefad78u128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0x46a3783ff17bfb155448d76c4342a99fu128,
                0x828244ffb4c9d20ad5eb734d59e592d3u128,
            ],
            [
                0xe197ceb3970a8c9ad45554df5f267039u128,
                0x78f54265b2616917ca49027901d86763u128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0x69bc421d77af66a8eefbe1874d29cfb2u128,
                0x0ab60849ea8802c387875b2dd750ac95u128,
            ],
            [
                0xe5ee4afa128f4836a8e9cd9bb17b5146u128,
                0x8616d77c581b4169003c03dd08f21e96u128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0x611cefa58a21ffa1cb0de946de8cc23bu128,
                0x3b6dda684327d4ae2bd52d0acc82ebceu128,
            ],
            [
                0x5b1e1515bb02a3aa65edf61c2d873b8cu128,
                0xe304414153f03970a2df936fc1ec26b1u128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0x8c62a2562eb9507e21f50f1081f57daeu128,
                0xcecdc9036de994d9411b0bfc70a2713du128,
            ],
            [
                0xbc91d3615d095d01b61c652e597cafd2u128,
                0x6e0b46fc2af34489328bc1f4c80a74f9u128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0xc1a511dc863f6f571d290e44256fdabfu128,
                0x5cb11e1adedba7c0c3d0cae2f3f28bd0u128,
            ],
            [
                0x9b585bb4485511efb12220fe2108d469u128,
                0x16368dd89be4ccc809089a46cfe00e33u128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0x9ba1e97d3ea17d3a81485ac1987b8c12u128,
                0x5fdd27fb098b33f6bc83e392b1a794f1u128,
            ],
            [
                0x3f237753eb749bd4e4cf305d8ffb43b9u128,
                0xc46fda57bff88f1bb1e113827f4a1108u128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x021194e496b70b2f063a554d9f6cbfcau128,
                0xcb9928a8e375c35714133f3767f0f9e0u128,
            ],
            [
                0x348e60ca936f3b84091b293f4e988763u128,
                0x7df441c28fae8dc189c3ecc74bc9c732u128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0x8681fcc8738f4fc1cc989080bda06700u128,
                0x229db0ba8857890707b9ba550b18ec6bu128,
            ],
            [
                0xd044f04ed8f329775d54254814606a4cu128,
                0x8a4fc235c37cc96473bb39cc2477a7efu128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0xb22109e8a4f80f22afdf06274c5e3a6bu128,
                0x1d5581f6d0059eba0deb24dc50bf90abu128,
            ],
            [
                0x7601024e05a48211ea19dd423820c4b0u128,
                0x1ec19a398fb926523c70b2aac88fa76au128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0xf3e8d205cdf8f75fbbea7f7fcb503e7eu128,
                0x78a53adf9615769770f8413b3f66238bu128,
            ],
            [
                0x9b8a45380e2f7fa8e447c44d621fab0cu128,
                0x60f328b428ce8929574a1208844ed712u128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0x8cb4cd4b0e4f74bfda2f167ad73c17c3u128,
                0x298f3e9fbd4c095babde1750506ab22fu128,
            ],
            [
                0xd4b7819e34ad051564e47f5df34ed658u128,
                0x56210debbf3b8a87f25000982eee8fd6u128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0x80901ceb0ad2440f9b2fdf16b155f121u128,
                0x5c531c195bd0b5d210497b535ac9896eu128,
            ],
            [
                0x717a9093e1a87f861c97e55142faba74u128,
                0xb6b4d6565b97fbc7ae16bd9431531eebu128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0xc8208fc7e343d8d5c32212f75a117d7au128,
                0xb9cc26b658e84aa1613607f672fa05c1u128,
            ],
            [
                0x70f1725234a3cd327a0762f13381ce62u128,
                0x8479a8c9017aac6712ff4b16ff774dceu128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x17577c1437cf4f8a26a745a3e5d2ac06u128,
                0xf628c4d0642b34cb427d22089ef76c98u128,
            ],
            [
                0xfce53188ccc6af6af625a13714ef6e0bu128,
                0xecd54a6586293382cae7de5da01890e5u128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0x18f83ad08a60e61670ccd08a319c9fb1u128,
                0xdaacfdbd236bb8803b49fc415618a152u128,
            ],
            [
                0x30e8786eafd6ec805f41620b4da53258u128,
                0x55bda99b786a0522ce5fede091c014c8u128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0x7a403ed509590f8d9547368c6f59bad1u128,
                0xfe2739799be97096e4aa10b368fe73a5u128,
            ],
            [
                0x331d3539537e450c0781963b12409807u128,
                0x33206e4afc5d1ebd80ddc9bfa6ab1de2u128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0xe6c73341c5a177f3edff172b8e325decu128,
                0x71c3aa7dd25a7919549917d3e821b100u128,
            ],
            [
                0xa4a2a0b51d158863d93dbf643818d4fbu128,
                0xfd6b1e341b9027c00e6c8bfd5e582823u128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0xe34e611777a06880597559343f26c19au128,
                0x9641b088ca921f9d8489dc5463eeedbeu128,
            ],
            [
                0x181dffbe7046a31a6f08c064500ffd5eu128,
                0x078def42ea6dfcc35151cbeed15c3273u128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0x9d46ef4861b64c10314341fb1126a828u128,
                0x461e1d85368384d58072b6b498b9255cu128,
            ],
            [
                0x31dd171f5450ecc1aa273ae50bc60be7u128,
                0x2da5f411e971644aab73f98bfac10ba1u128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0x1d8da13a9e284bb0a444c6a834d184e9u128,
                0xb51af2a92c8f5f09714b223b150c2045u128,
            ],
            [
                0x7f1c65924ea2f7f62c7b5621a34d5b3au128,
                0x71abeb74efd763a77326fe5e5fc6c918u128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x6739f92828f354bf914dd50d2009541fu128,
                0xf219d98937396b30fa52ea2f213560dcu128,
            ],
            [
                0x4fb7811b626631180d80f0b34d542a44u128,
                0x4a87d9297d7eab59874df70d7b62a3d5u128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0xa74c6401636676f72498f830303d1921u128,
                0xa6b0cfb3436b70030591bdd64a51e9bfu128,
            ],
            [
                0x43678091e71d905dac2291064ff8dfcbu128,
                0x5f71bec1c53d8610f6abd5bf9fe65078u128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0xb91612d6450d1b34c80d16d8a5b55203u128,
                0xbae54b36d24ce6840eaed7bbb2481071u128,
            ],
            [
                0x7458be8ee8a530b7c5e1097a8a10f013u128,
                0x5377bfede72abe8233e93ef3628dfe0cu128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0xa8176f79c1b61a3375b4cbe89f2c5287u128,
                0x6364fc9076f2851f0fccf8ccd2461867u128,
            ],
            [
                0x0edabba9e1c46070074f11baa77573cfu128,
                0xb1ea4ec3a0a39404e260a1df024169d7u128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0x05f6950a5bfeac38b5a246cf3e00bd7cu128,
                0xe4e18cedcf96c36f85af5aee5babcec5u128,
            ],
            [
                0x5b4d94a5438da60d7b67e390036a1188u128,
                0x6a4e4ed150f07b7afbade3bd7159974au128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0x53b1a315b81b89bf4657212e598947d3u128,
                0xc20521526c10f793e3c3f528e629c62eu128,
            ],
            [
                0xf9703ea34a14fb526b8ad2c21855bae8u128,
                0xbc9e8c04fe913d8f5b17b27b45e739b7u128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0xca099347426cfc5ad6de40b6051308ffu128,
                0xa0144304c8ac6a02a0cf6200d74344bdu128,
            ],
            [
                0xeb6ea118a1f4bc86f74e1162141c3022u128,
                0x948c29a8b94a95e22210f8759ff067ceu128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x5f1c4036b4aa44c6a2c49acdd5ddf22cu128,
                0x956bd1759c42b9d5e1ed7c28fd30b44du128,
            ],
            [
                0x5c93f531c6290ca2d9b3ac84a98ffa73u128,
                0x694404c4f041c383cf6f9d10195372d4u128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0x220f9bca8ff8097193a40d4891a686e9u128,
                0xb664456c14e53262a28c74ec64aa8cf4u128,
            ],
            [
                0x1e178e20804aff8ca9703c9cbb1d4136u128,
                0x4191e098f660b01cc04f951a42536537u128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0x8b3d10cdcc2c5ebf238624b215bcd424u128,
                0x35c298214fac894688deffa320c910ecu128,
            ],
            [
                0xadd8b562ddb80b47ac2f32f30a12b9cdu128,
                0xeb5e9c356a8ffbae2a4bfad71b390af2u128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0x1b61b508fa1cb6e051c1bf8489e91092u128,
                0x31c28e6d32018dbe0e07444ab12b51e4u128,
            ],
            [
                0x55ead9f863e9ba083496b091a7c226d0u128,
                0x070e54fdfc3f70c29a9783030a3d37dfu128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0xbe65f2ae2115d8133aec0b267901c684u128,
                0xce8036e71cda5b0ed93732a4a9abcdc3u128,
            ],
            [
                0x73ea60a037868aa0c5ebdbbe45988598u128,
                0x3b7108d3d3da80b1d1e1b5638371bfdfu128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0x7660d7740cdc3954dc11eaf5e5b071dau128,
                0xcb68995f74eab053797b9193c41c94e8u128,
            ],
            [
                0xd2e74903ca3894cef3a9c526b77975cfu128,
                0xd19aa399e238a7c0b5d4f1de948a84a3u128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0xcbece7ff66659c7e688e70c90594c0d7u128,
                0x9f3ffeed9d1df0e1f7aa0fb24c81a24bu128,
            ],
            [
                0x4110dded40a7a8a5f0d3e19b7d82b9ecu128,
                0x360cc898ba9692ed93c2803e92c62f9du128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0xcc87ec55b05b67bca18d7665034f8547u128,
                0x9c2816fd40006e3a5b12ca70003a7085u128,
            ],
            [
                0x0993c48c1893f634d00372dec0837d5du128,
                0xb07a77956b3ca5b3e4aca5b94ab352a1u128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0x7b362d58d33ce1b181e70ff4a38f3b29u128,
                0x3b064d758509024b1c1f1fbb2a311e47u128,
            ],
            [
                0x32129bdf43f3625dceec59fd79c3e09cu128,
                0x7637a9af2b5a1e12e3b359ef906b1064u128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0xf88040d23495761eb4f92c0d4df09428u128,
                0x7dd46e09f0055548b49e7fda702fd4f5u128,
            ],
            [
                0x7cb043e053124dc8702593ffbc5a18ceu128,
                0x493ea0b97c3f878027a54a3cb63d3625u128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0xf71504f227668b0f2fd4982e6ed48e7fu128,
                0xaa20177c06eff2a0a9778eb6708671acu128,
            ],
            [
                0x8bcbd22463109d913fa1c1c38300e649u128,
                0x642457ba7a5cce85bb94309129dcc565u128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0xef9388abf6cfb567749e8fcce50fda1du128,
                0xa395e3b69510dd089726b102cd886527u128,
            ],
            [
                0xb8f1a7196ad89702c428d23c958d4d81u128,
                0xa8073ca282df811f72b9fc0c5a6c895cu128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0xf028ed9c5d7c9eb5647f421634bb2d84u128,
                0xd21b3664d0d9ff0673b5e6e1e52190b5u128,
            ],
            [
                0xde38a73aca53b223d104a1bee44a9557u128,
                0x11c40c247bad1f0dd04f68ba94c41ef0u128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0xcaf9409b9162c95daa0a8f1a0b461e07u128,
                0xe13728feec3d670db4746b0fedca9da9u128,
            ],
            [
                0x05cfa11e0fbbc0bb145357482777c2bfu128,
                0x5787e7f4899a29fc1143a8ab8bc4b7f0u128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x2e6bbf95a122127d8d5f7487daf4d74au128,
                0xc404151ff76c76ba1740bccd435d9661u128,
            ],
            [
                0x80d0f583f0a0153e83cca75f31008576u128,
                0x9bf8638b29b200be8cddb44f41d2a208u128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0xd31b836eb8c532480e4a4a8553eee300u128,
                0x4fc0426e8798545b50443c654302f1d8u128,
            ],
            [
                0x9e283bd8984f964e95248af2f2033623u128,
                0x1fe62634c589c0a31406028c9ee1d9e7u128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0x2cb60b4ed932842f274b1ee8d0762cdcu128,
                0x742448f73db7170a25036462b1229f1eu128,
            ],
            [
                0x8093369a676352d9549ca8ae5a56d740u128,
                0x575386d73e5dd52674eea72a5add09a8u128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0x0a9ec2aa3308df2f4e03653542ff4dd2u128,
                0xd3ff00db5ab40005a46481c47d38c0e4u128,
            ],
            [
                0xae76d59811d68009b077f752b994b4c7u128,
                0xdd2d30438906b8e37e25f43aa9359cebu128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0x772684de1cd9d23490b3dda9eb029da5u128,
                0x558d19a4f19df110dd0b3bf99daccd81u128,
            ],
            [
                0x41856bf5baa48b2ef098affe9eed197du128,
                0x4314674a6f1bf6cf428089b52cbd2cdcu128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0x8e73749d7a8c84fd7198c340b50ac975u128,
                0x2988177b19de37498f568b0f939a05d8u128,
            ],
            [
                0x2e8ce6735331497b03fe14eb1ea22011u128,
                0x01ce82140a0f42e0bc976dc6ac4368dfu128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0xb30817ded8fa3b32bc321c58ea8ed586u128,
                0x7f87bc384a9e22bec57c96923f6a43efu128,
            ],
            [
                0x5230e71374daa2b1bbeb1ed5879cf005u128,
                0x92fef8be3827dcd53cf11dc8048c0badu128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x956d38dc315cfdef38eb789641b41f40u128,
                0x3c1ac2c057a4b35f480e99e4e964a6bdu128,
            ],
            [
                0xc0f334c2c5bf732102a79c57f8964c24u128,
                0x642eeee6d6679a561b906e5f64cb4f14u128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0xbf4f1da7eee7f30afeb7188002a9ff5bu128,
                0x4fde41a4865390563fa0ddfefe1f1491u128,
            ],
            [
                0x03b7af51244068f343a2b74461294a6du128,
                0x6745dcf60dfbbd4554b007cea003f679u128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0x6444d1b13f7190005df5eb7642fbd20au128,
                0xce9abcd94bc6058df2dc295859c5c6b8u128,
            ],
            [
                0x841a9d528756675731e4739cb9a39541u128,
                0x75eddd5593824c07cae6acf567e1b1c7u128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0x6b02dcea96a32ca0de96aa6a18da2628u128,
                0x16fb4027748d7c8fe90e850315f4c94fu128,
            ],
            [
                0xdddb02ecd3343dd4e1e93590b0c7b5eau128,
                0xedd7eae0411dda195dc312d83efb784eu128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0xf34b46ccce079301206232ea5c43d3e7u128,
                0xc2c2abd496da2c11d3f9a52a2c543910u128,
            ],
            [
                0x9f98256ac1b5a3333c0603c2eddc0f6cu128,
                0xf2382e0c1d0958a200a5316a6dcd3740u128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0x51608909a949628f675652d2b10be99cu128,
                0xa16e1a2c0ae7d6e510b3edf182185202u128,
            ],
            [
                0xe8471441607bb5d86196b3721a50bf0eu128,
                0x405df27cab88f2bf0476c62108bdab57u128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0x325e5442488b754638bbcb4b00974bc5u128,
                0xe8f2e307810ba59b8c4a9af29dc05fd6u128,
            ],
            [
                0xdba69ab5b0d8e3887b6f0b751b0811d9u128,
                0x478d2b7e5b4693a4e65c516e0e0f7f54u128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x7e744f7c3f45fdd6fb0e0181681bd444u128,
                0x6b71a5e33cff149d2ccbc904e2e593edu128,
            ],
            [
                0xbcdd2f14abbaa8aae5eb93cbf2333a03u128,
                0x7fb8c1b31c440ecafd071a8a7510eef0u128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0xb169439a43709302d4837aa9a46524fbu128,
                0x980d8d01bcea5ef95a1818009c772846u128,
            ],
            [
                0xabbf5486b38d806cd1d5265e6df965f7u128,
                0x5096daba2cf5b5025bc3175b1e462fe6u128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0x912ad2c9fac11c3b92e16392b86411f6u128,
                0x416d03c309c1b5407bc22f6bc0dfa9bau128,
            ],
            [
                0x1f5aea28e9b2d821b1562469020aa5e2u128,
                0x62fafa1de4f2ecc6f952c91e3853dafdu128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0x75e415b587c851ccad321899a7a7381fu128,
                0x4b2a04ad4c7cfae8945dcb7d53f1c0cdu128,
            ],
            [
                0x3d00dbb890125ed0ab1172963ab98adbu128,
                0x4135fcabd822651f7b17e7e5ec19c7b7u128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0x208b5981b0d9e3dcb9afed48fa62887bu128,
                0x57c2136ccd23db89919898d85290c787u128,
            ],
            [
                0x1c8afbebec63d5d89cb6ddf160abb1d4u128,
                0xc82a78d9f90eeaebddf9e586f66b209au128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0xa59138abc0ce94bb0bdde67607050586u128,
                0x611b3884a1d5b064b68563d77aee9ba9u128,
            ],
            [
                0x063aab9d00a8301ed0bfb769e02add7au128,
                0x002428a603ed9fe33c5030214ad0cb35u128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0xf239faf2475d7e96a70e943ef1d100a1u128,
                0xcabf7f0b9d6d5c72aebf773cd088db2au128,
            ],
            [
                0x2c99478182dcf52d7ac6490b85cc92e5u128,
                0xeae102bb259587b81605abad9ae518bcu128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x6dfd4fde37701ed08595b12a02d97a73u128,
                0xb7205df1f5b3df7d86b8ba8e6fbdf0fcu128,
            ],
            [
                0x6034772762b1749766700018f33fa596u128,
                0xa4f66d526054405435e655745135ec0eu128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0x78a42475ab17fce301ed0922b3abea12u128,
                0x9e43c19ab507b7cbe635b0eeb27dbbcdu128,
            ],
            [
                0x6eca6ec195e8c34e61592eb1241c84e3u128,
                0x4c13ea8c0637401b2f2fea8aafa37d45u128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0xe0e078977b8d46646ec1eeb83208a9e7u128,
                0xe44f5793bb4896b709917885959c1b47u128,
            ],
            [
                0xcad1caf8c67364095e4c07565e969614u128,
                0xc77ba50add9d1a50a0331f232b895443u128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0xc25c97ee8dfee67a45de0f80eb3b6962u128,
                0x15094a47b018951c9084048dd8b8d073u128,
            ],
            [
                0xf850a29dad557c0df64d6ba7c3078df9u128,
                0x7106004df44c7dd8437f7650e2131c3eu128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0x25fd015e366eb7df66f1f4a85c85d3acu128,
                0x236acb862badd6a4c76804f78f005d2cu128,
            ],
            [
                0xc80439997ab73ac1cb40d3871df1f59du128,
                0xe3edfd2162152a85aba6eb0a6fda044du128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0x0aae4a64a2cc4a67950bc26ab1a363e6u128,
                0xb430f0a8a6143431ef12bed4530278e2u128,
            ],
            [
                0xf58429be04c508d36c0772efe92d9c1cu128,
                0xa5847e33014947505780002564c577a9u128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0x8699e58d81948358afc7d3c0554f6b14u128,
                0x05f4e66f2d100bebf88811f58ef0f612u128,
            ],
            [
                0xaca0fd8c8d13f0bef9847cc7e0a6d7f7u128,
                0x7c30c6696f08bdb87be5498a09834d10u128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0x3f02803b9e441851baf905c93aaf1682u128,
                0xec942ccd086bbbace43dbc81189efe1fu128,
            ],
            [
                0xd982a70f17c3a63c572b866414f865fdu128,
                0x6b9716580dd05f835052f3c7e062b88du128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0x4327ab805b2736f5e357dc54dd2d1d37u128,
                0x0751eced0a11a2152d61988eca5f6d76u128,
            ],
            [
                0x4cdfcb88ce9f5356970aa14314258d26u128,
                0xdaa4baf30a03cc8808eace712a3ea9fdu128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0xe0773dd0fb2a1dfe02522f0bf082a1d1u128,
                0x4beac846d4a1f9639442b5582079c70cu128,
            ],
            [
                0xaf5b2f45b3684ba62c0146d1db136de3u128,
                0x4e135b26ea54299ac6d609c7cbe75680u128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0x53536afdcdb682984962122815dabafbu128,
                0x1982418bf1054e7ca97661c0e03e1163u128,
            ],
            [
                0x392129df172d96daf32f125a0f3c133bu128,
                0x591d813c2af80621d4438c72897947fcu128,
                0xbed68d38a0474e67969788420bdefee7u128,
                0x04c9a8cf20c95833df229845f8f1e16au128,
                0xba65bba62753e93a352c5212ccbe6ba4u128,
                0x5625ebfcc48bbd87d4fd643f3f5b85a7u128,
            ],
            [
                0x2b2686a0953af3739e6b97f7139ba8e6u128,
                0x5ba2333d9ebc236b10dbba58d84fe6d7u128,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
                0x8a682bf082b8905eb918b1761bbd2c8au128,
                0xe537dded5302d9146f627dc284408c74u128,
            ],
            [
                0x739ccf7f2a7deba7899084c806b121d6u128,
                0x75c9748768a864d1b7dab318d6a5e2e0u128,
                0x1771831e533b0f5755dab3833f809d1du128,
                0x6195e3db7011f68dfb96573fad3fac10u128,
                0xc964029862a6ee223dc8faf2b666616au128,
                0xe4203d4ee5fe020bcfec00d7a312d9c3u128,
            ],
            [
                0x4ad3c424c2529e7fa381cf7f05d21559u128,
                0x6aa149786b0bb6a42e18991345c58fc3u128,
                0x752758911a30e3f6de010519b01bcdd5u128,
                0x56c24fd64f7688382a0778b6489ea03fu128,
                0xfbd1f17321da739b0c9bc8a237df1a64u128,
                0x32858d8f3863f1b5ec89e56f460336d0u128,
            ],
            [
                0xdf812a2eaf8e465b25850fb55bb0639cu128,
                0xb2e22664fcde106e62c429babe1517ecu128,
                0x1bc4dbd440f1848298c2f529e98a30b6u128,
                0x22270b6d71574ffc2fbe09947d49a981u128,
                0x46b5be45188088778c88f6447082ce43u128,
                0x6d3302da1a09f7a91a9d0666039e8d64u128,
            ],
            [
                0x6ae6dc9128ec4756525f9b722188070bu128,
                0x8d5b0f528998d7e6fb40a04a90aedad7u128,
                0xaced66c666f1afbc9e75afb9de44670bu128,
                0xc03d372fd1fa29f3f001253ff2991f7eu128,
                0x31ceddb1b7a5c9716f4e091cd3a442a4u128,
                0x5da6b92eb44ad10ce13695ad7991a6c0u128,
            ],
            [
                0x13eb45f9bdc4e39d4dda743cfd91b382u128,
                0x3bfd6012a02f4e77d9ec829d0d81d317u128,
                0x5237c4d625b86f0dba43b698b332e88bu128,
                0x133eea09d26b7bb82f652b2af4e81545u128,
                0xf044db93deb3a514ab75669ffc7398c3u128,
                0x79a7843a59312b581b7e12e0a3b98dacu128,
            ],
        ];
        for data in database {
            let mut left = GF256::new(data[0], data[1]);
            let mut left_2 = GF256::new(data[0], data[1]);
            let right = GF256::new(data[2], data[3]);
            let result = GF256::new(data[4], data[5]);
            let res = left * right;
            let res_rev = right * left;
            let (first_value, second_value) = res.get_value();
            assert_eq!(first_value, result.get_value().0);
            assert_eq!(second_value, result.get_value().1);
            //to test commutativity
            assert_eq!(res, res_rev);
            //to test with ref
            #[allow(clippy::op_ref)]
            let res_rev = &left * &right;
            #[allow(clippy::op_ref)]
            let res = left * &right;
            assert_eq!(res, result);
            assert_eq!(res_rev, result);
            //to test mulassign
            left *= right;
            left_2 *= &right;
            assert_eq!(left, result);
            assert_eq!(left_2, result);
        }
    }

    #[test]
    //input : one GF256 and one GF256 restricted to 64 memory bits
    //output : the product of the two according to the rules of Galois Fields arithmetic
    #[allow(clippy::erasing_op)]
    fn gf256_test_mul_64() {
        let mut rng = rand::thread_rng();

        let pol_0 = GF256::default();
        for _i in 0..1000 {
            //0 * anything = 0
            let anything: u64 = rng.gen();
            let pol_res = pol_0 * anything;
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, 0u128);
            assert_eq!(second_value, 0u128);
            //1 * anything = anything
            let pol_res_1 = GF256::ONE * anything;
            let (first_value_1, second_value_1) = pol_res_1.get_value();
            assert_eq!(first_value_1, anything as u128);
            assert_eq!(second_value_1, 0u128);
            //anything * 0 = 0
            let anything: GF256 = rng.gen();
            let pol_res_rev = anything * 0u64;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, 0u128);
            assert_eq!(second_value_rev, 0u128);
            //anything * 1 = anything
            let (first_value_anything, second_value_anything) = anything.get_value();
            let pol_res_rev = anything * 1u64;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, first_value_anything);
            assert_eq!(second_value_rev, second_value_anything);
        }
        //to test with complex values we use the tests values of the reference implementation
        let mut left = GF256::new(
            0xefcdab8967452301efcdab8967452301u128,
            0xefcdab8967452301efcdab8967452301u128,
        );
        let mut left_2 = GF256::new(
            0xefcdab8967452301efcdab8967452301u128,
            0xefcdab8967452301efcdab8967452301u128,
        );
        let right = 0x0123456789abcdefu64;
        let result = GF256::new(
            0x4040404040404043911817139d141b1cu128,
            0x40404040404040404040404040404040u128,
        );
        let res = left * right;
        assert_eq!(res, result);
        //to test with ref
        #[allow(clippy::op_ref)]
        let res_rev = &left * right;
        #[allow(clippy::op_ref)]
        let res = left * right;
        assert_eq!(res, result);
        assert_eq!(res_rev, result);
        //to test mulassign
        left *= right;
        left_2 *= right;
        assert_eq!(left, result);
        assert_eq!(left_2, result);
    }

    #[test]
    //input : one GF256 and one GF256 restricted to 1 memory bits
    //output : the product of the two according to the rules of Galois Fields arithmetic
    #[allow(clippy::erasing_op)]
    fn gf256_test_mul_bit() {
        let mut rng = rand::thread_rng();

        for _i in 0..1000 {
            //anything * 0 = 0
            let anything: GF256 = rng.gen();
            let pol_res_rev = anything * 0u8;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, 0u128);
            assert_eq!(second_value_rev, 0u128);
            //anything * 1 = anything
            let (first_value_anything, second_value_anything) = anything.get_value();
            let pol_res_rev = anything * 1u8;
            let (first_value_rev, second_value_rev) = pol_res_rev.get_value();
            assert_eq!(first_value_rev, first_value_anything);
            assert_eq!(second_value_rev, second_value_anything);
            //anything_1 * anything_2 (odd) = anything_1
            let anything_2 = rng.gen::<u8>() | 1u8;
            let pol_res_2 = anything * anything_2;
            let (first_value_2, second_value_2) = pol_res_2.get_value();
            assert_eq!(first_value_2, first_value_anything);
            assert_eq!(second_value_2, second_value_anything);
            //anything_1 * anything_2 (even) = 0
            let anything_3 = rng.gen::<u8>() & u8::MAX << 1;
            let pol_res_3 = anything * anything_3;
            let (first_value_3, second_value_3) = pol_res_3.get_value();
            assert_eq!(first_value_3, 0u128);
            assert_eq!(second_value_3, 0u128);
        }
    }

    #[test]
    //input : two GF256
    //output : the result of the and bitwise operation on the two inputs
    fn gf256_test_and() {
        let mut rng = rand::thread_rng();

        for _i in 0..10000 {
            let random_1_1 = rng.gen();
            let random_1_2 = rng.gen();
            let random_2_1 = rng.gen();
            let random_2_2 = rng.gen();
            let pol_1 = GF256::new(random_1_1, random_1_2);
            let pol_2 = GF256::new(random_2_1, random_2_2);
            let pol_res = GF256::and(&pol_1, &pol_2);
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, random_1_1 & random_2_1);
            assert_eq!(second_value, random_1_2 & random_2_2);
        }
    }

    #[test]
    //input : two GF256
    //output : the result of the xor bitwise operation on the two inputs
    fn gf256_test_xor() {
        let mut rng = rand::thread_rng();

        for _i in 0..10000 {
            let random_1_1 = rng.gen();
            let random_1_2 = rng.gen();
            let random_2_1 = rng.gen();
            let random_2_2 = rng.gen();
            let pol_1 = GF256::new(random_1_1, random_1_2);
            let pol_2 = GF256::new(random_2_1, random_2_2);
            let pol_res = pol_1 + pol_2;
            let (first_value, second_value) = pol_res.get_value();
            assert_eq!(first_value, random_1_1 ^ random_2_1);
            assert_eq!(second_value, random_1_2 ^ random_2_2);
        }
    }

    #[test]
    //To dest those one we use the test dataset of the reference implementation
    fn gf256_test_byte_combine() {
        let database = [
            [
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
            ],
            [
                0xfc0e88f15187fdeaacf0d5909dc2f6c2u128,
                0xd68cc8fb0e9eac7649e52a8a2b0cb79au128,
                0x2f3449f2e8cbe4aa1750dbe80784797du128,
                0x785718c8643f90cbf00a2b44e44c520cu128,
                0xcd1f541c526b2858845085d4585e3195u128,
                0x3c4d95656093e8a67d987592386f10bbu128,
                0x79d80c08067b57b715781685826a45a9u128,
                0x51841922e373ae1ff6be29fc6973dceeu128,
                0x65e980f30ef160d7ead1ec197871a49eu128,
                0xd980b385fe6441b11602304c60062cafu128,
                0xd1f695b8d4fffbdc80fecb34d00aa6e4u128,
                0xc480651e55ba153848ff2619195fad44u128,
                0xe0f23512dc60c54e627ca406cb8f1971u128,
                0x63c2571fa4a322fa6f0e68e934f6c7eeu128,
                0x18d1be01fe3c79b618ce224026cb8615u128,
                0x7149fd9d016bb4c540e9d47b53b99376u128,
                0x662e53bc98d20090d4e23e311c316bc5u128,
                0x5c007a2332c062962802a24b9770813cu128,
            ],
            [
                0x18370a84b4ef6c336145d8a06f71b34fu128,
                0x297aab039773944655442783c3cee478u128,
                0x5e63ba879f7bbcc1134b677fa79c420fu128,
                0x5f782c727f0edbf4c7c6836b75f93979u128,
                0xc3ccafda68f50580b0a8f02c7071ec7au128,
                0x68e09ffda9b15265961f1f123b3a5aa9u128,
                0xb995d866b4f398589ba864949b0cfb1eu128,
                0x978f7cda10ff3919c056cd7347fbb110u128,
                0x6730a2d21cd59123a63be54cb256b681u128,
                0x82fdf1bb32a91b87b9e6dba6a8c43b2au128,
                0x8dd966ed51f8c6f1cdf44f98aa574a75u128,
                0xfa8acfe85a88f532e3f02a6c73622a3du128,
                0x75e504c662fe81d91fe77b81829998c9u128,
                0xccb0d154d3a2e9f4042a2598cba4ddeeu128,
                0x74a2697ca1055bcd515b2e9962a175b8u128,
                0x462f300800fb7a188d6fc5dcae924a05u128,
                0x54a291cd5c76e8d32d5f7e170e8532e7u128,
                0xa9ac9f8d64dca03d2eabe041b8c6c338u128,
            ],
            [
                0xea683cf519e58ff00825ed1ae49af145u128,
                0xa42cca10c0674d1e5ac2441f3fe82544u128,
                0xe104967b693c7ea3b8b56ff226672c4bu128,
                0xfcb16a9307ff03800d4ee75241866099u128,
                0xb1bbcf2f7e6d23a74a0d1c5b486ec8dfu128,
                0xbaa4cdcd58675bd895b2f53449126979u128,
                0x23b0eff67517ddacadb01fe65aa3a44cu128,
                0x84a8ea16f09f034dc4102a6f6de7086du128,
                0xae9ffe65941bca42d8f681031d43bd38u128,
                0x1dbfd057cf88293517c5df883b2d693bu128,
                0x4391f1fffeb0a3ca4d8f66ae244b41cau128,
                0x483a66dbbcb5d20dfd794a988d964f7bu128,
                0x9ca0557bb69bc01e7302790a5fc618bcu128,
                0xae3068bf98ab91197d16d75f5d5c44aeu128,
                0xc68b0c83afd12d35ef454cf8ec5208a1u128,
                0x04d083b6f381b7e2a7a0926a6fd1704bu128,
                0xfbb90bc3d15425e90f23baccef527d2fu128,
                0x445d11806adc1b14568c4b472f67a4aau128,
            ],
            [
                0xa3de04078ee1758ad6210405be3a17a5u128,
                0x2a0310d7f31fa7d3e80c83741f98defau128,
                0x5a344f99c8a3db604192152c07330059u128,
                0x2b54d26bf8dca9ab357baa73d9066b6au128,
                0x3dd861b61e0a8cc895411ceb598f9f5bu128,
                0xbaa05add572397089ded7f38b48bc122u128,
                0xb0d21b849b77cafa85bc25acb9e97a29u128,
                0x66a86adea9063ae567a5bcfbfe518bb5u128,
                0xddc211eefabd924e35fd04591dc19755u128,
                0xbf050e2f378d8f0333f42dcb03c65927u128,
                0x90b1e3329e1e24c829596301211686cbu128,
                0x4de233ec1f709153d0b7d4e596961d58u128,
                0xdabb2d457113e324d7a4f779881c4f16u128,
                0x40bc17e6c332b85b63cb533eec12c495u128,
                0xead5b92670e0089c41b969af0669b111u128,
                0x68a72d8b8c89c80a0d59681138775345u128,
                0x4fbab9006545a212cea20ede2266fce9u128,
                0xb8066865e3b340bcadec0ff94b337d0cu128,
            ],
            [
                0x9f0e704f9edb0cffa9f4ca19bbb54d9fu128,
                0x93cb40e58dd0b132c13443a5ce44622cu128,
                0xa5bacecff26d2272fb474dac8ad13e2bu128,
                0x7938876502398c7dfc39b519f2e9913bu128,
                0x96eee2c2ec96c62aaaa4554fffb6c221u128,
                0x4f593dbee9887b149eb3c98659134279u128,
                0x3f2924d6cb1d8440e500879bb409388bu128,
                0x7ecf8fb86310611b2b6ac9470269ffe2u128,
                0xeb5de4ea9c626c3177db69a17268541cu128,
                0xb4e8eb935d0bfab304ac26c2befb84bdu128,
                0xc6466496e5019d479655acf6201b4765u128,
                0x87a669bf4063057a71dd51461eefad78u128,
                0xe197ceb3970a8c9ad45554df5f267039u128,
                0x78f54265b2616917ca49027901d86763u128,
                0xe5ee4afa128f4836a8e9cd9bb17b5146u128,
                0x8616d77c581b4169003c03dd08f21e96u128,
                0x64630f9c6fe787a4a23619babb3ed54cu128,
                0x1773878c71cf2a3bc7f10e248c3e85f8u128,
            ],
            [
                0x2b517f82c35902e30754a4bea615989du128,
                0xfee209ba50c955d747db57a2905a3ce3u128,
                0x5b1e1515bb02a3aa65edf61c2d873b8cu128,
                0xe304414153f03970a2df936fc1ec26b1u128,
                0xbc91d3615d095d01b61c652e597cafd2u128,
                0x6e0b46fc2af34489328bc1f4c80a74f9u128,
                0x9b585bb4485511efb12220fe2108d469u128,
                0x16368dd89be4ccc809089a46cfe00e33u128,
                0x3f237753eb749bd4e4cf305d8ffb43b9u128,
                0xc46fda57bff88f1bb1e113827f4a1108u128,
                0x348e60ca936f3b84091b293f4e988763u128,
                0x7df441c28fae8dc189c3ecc74bc9c732u128,
                0xd044f04ed8f329775d54254814606a4cu128,
                0x8a4fc235c37cc96473bb39cc2477a7efu128,
                0x7601024e05a48211ea19dd423820c4b0u128,
                0x1ec19a398fb926523c70b2aac88fa76au128,
                0x386e96b4d946fc63645743be3f366f41u128,
                0xbfb7da63c742f745172a95aba19cf454u128,
            ],
            [
                0xadf0a092ddfaa8a3c15d0d82254ac934u128,
                0x51b8c1fb72cdd386ab4ff5c2324f0cc6u128,
                0x9b8a45380e2f7fa8e447c44d621fab0cu128,
                0x60f328b428ce8929574a1208844ed712u128,
                0xd4b7819e34ad051564e47f5df34ed658u128,
                0x56210debbf3b8a87f25000982eee8fd6u128,
                0x717a9093e1a87f861c97e55142faba74u128,
                0xb6b4d6565b97fbc7ae16bd9431531eebu128,
                0x70f1725234a3cd327a0762f13381ce62u128,
                0x8479a8c9017aac6712ff4b16ff774dceu128,
                0xfce53188ccc6af6af625a13714ef6e0bu128,
                0xecd54a6586293382cae7de5da01890e5u128,
                0x30e8786eafd6ec805f41620b4da53258u128,
                0x55bda99b786a0522ce5fede091c014c8u128,
                0x331d3539537e450c0781963b12409807u128,
                0x33206e4afc5d1ebd80ddc9bfa6ab1de2u128,
                0xfadcb5a54b7391246dac62972c178626u128,
                0x3ec86fa2c24aa06ab8e9471e02263d29u128,
            ],
            [
                0x2e6a448d09334fabf4e927307f869be2u128,
                0xa598165421377ec08b53ac0ca6a1eaa3u128,
                0xa4a2a0b51d158863d93dbf643818d4fbu128,
                0xfd6b1e341b9027c00e6c8bfd5e582823u128,
                0x181dffbe7046a31a6f08c064500ffd5eu128,
                0x078def42ea6dfcc35151cbeed15c3273u128,
                0x31dd171f5450ecc1aa273ae50bc60be7u128,
                0x2da5f411e971644aab73f98bfac10ba1u128,
                0x7f1c65924ea2f7f62c7b5621a34d5b3au128,
                0x71abeb74efd763a77326fe5e5fc6c918u128,
                0x4fb7811b626631180d80f0b34d542a44u128,
                0x4a87d9297d7eab59874df70d7b62a3d5u128,
                0x43678091e71d905dac2291064ff8dfcbu128,
                0x5f71bec1c53d8610f6abd5bf9fe65078u128,
                0x7458be8ee8a530b7c5e1097a8a10f013u128,
                0x5377bfede72abe8233e93ef3628dfe0cu128,
                0x9c9b8b6e4e2303c430f7095a4ffa3b03u128,
                0x4df5e86c2145c22900429c5943908371u128,
            ],
            [
                0x1b5498db4fe9cf8575eddfb43493f091u128,
                0xf1d841b85703382ea79e10ce0244fb4du128,
                0x0edabba9e1c46070074f11baa77573cfu128,
                0xb1ea4ec3a0a39404e260a1df024169d7u128,
                0x5b4d94a5438da60d7b67e390036a1188u128,
                0x6a4e4ed150f07b7afbade3bd7159974au128,
                0xf9703ea34a14fb526b8ad2c21855bae8u128,
                0xbc9e8c04fe913d8f5b17b27b45e739b7u128,
                0xeb6ea118a1f4bc86f74e1162141c3022u128,
                0x948c29a8b94a95e22210f8759ff067ceu128,
                0x5c93f531c6290ca2d9b3ac84a98ffa73u128,
                0x694404c4f041c383cf6f9d10195372d4u128,
                0x1e178e20804aff8ca9703c9cbb1d4136u128,
                0x4191e098f660b01cc04f951a42536537u128,
                0xadd8b562ddb80b47ac2f32f30a12b9cdu128,
                0xeb5e9c356a8ffbae2a4bfad71b390af2u128,
                0x6a5543bae302b3b013e1f4508e27b2b2u128,
                0x50272d56c923e99fa4856e2560fdceaau128,
            ],
            [
                0xaefe32e5ce767a606c5d208158d8e8eau128,
                0x4ce27a1a355b60d9967c1ec14d5ffed5u128,
                0x55ead9f863e9ba083496b091a7c226d0u128,
                0x070e54fdfc3f70c29a9783030a3d37dfu128,
                0x73ea60a037868aa0c5ebdbbe45988598u128,
                0x3b7108d3d3da80b1d1e1b5638371bfdfu128,
                0xd2e74903ca3894cef3a9c526b77975cfu128,
                0xd19aa399e238a7c0b5d4f1de948a84a3u128,
                0x4110dded40a7a8a5f0d3e19b7d82b9ecu128,
                0x360cc898ba9692ed93c2803e92c62f9du128,
                0x0993c48c1893f634d00372dec0837d5du128,
                0xb07a77956b3ca5b3e4aca5b94ab352a1u128,
                0x32129bdf43f3625dceec59fd79c3e09cu128,
                0x7637a9af2b5a1e12e3b359ef906b1064u128,
                0x7cb043e053124dc8702593ffbc5a18ceu128,
                0x493ea0b97c3f878027a54a3cb63d3625u128,
                0x153375edf54e7c4559697c2942193b5au128,
                0xa6ef09b2f395b0fc9b7e96e346cbce2eu128,
            ],
            [
                0x31be02b2f37d8a85af33deb61638f773u128,
                0x410d525a36bda6f3fc6498c1362a1084u128,
                0x8bcbd22463109d913fa1c1c38300e649u128,
                0x642457ba7a5cce85bb94309129dcc565u128,
                0xb8f1a7196ad89702c428d23c958d4d81u128,
                0xa8073ca282df811f72b9fc0c5a6c895cu128,
                0xde38a73aca53b223d104a1bee44a9557u128,
                0x11c40c247bad1f0dd04f68ba94c41ef0u128,
                0x05cfa11e0fbbc0bb145357482777c2bfu128,
                0x5787e7f4899a29fc1143a8ab8bc4b7f0u128,
                0x80d0f583f0a0153e83cca75f31008576u128,
                0x9bf8638b29b200be8cddb44f41d2a208u128,
                0x9e283bd8984f964e95248af2f2033623u128,
                0x1fe62634c589c0a31406028c9ee1d9e7u128,
                0x8093369a676352d9549ca8ae5a56d740u128,
                0x575386d73e5dd52674eea72a5add09a8u128,
                0x3fa4d2013a71133fff85d9a9d7594ba9u128,
                0xfdabb02b88bed61e6ae0c1233f0c40fcu128,
            ],
            [
                0xda108a432b96849032743cf726af9645u128,
                0x1d96fe4ece11c4af786e1b9703b29f40u128,
                0xae76d59811d68009b077f752b994b4c7u128,
                0xdd2d30438906b8e37e25f43aa9359cebu128,
                0x41856bf5baa48b2ef098affe9eed197du128,
                0x4314674a6f1bf6cf428089b52cbd2cdcu128,
                0x2e8ce6735331497b03fe14eb1ea22011u128,
                0x01ce82140a0f42e0bc976dc6ac4368dfu128,
                0x5230e71374daa2b1bbeb1ed5879cf005u128,
                0x92fef8be3827dcd53cf11dc8048c0badu128,
                0xc0f334c2c5bf732102a79c57f8964c24u128,
                0x642eeee6d6679a561b906e5f64cb4f14u128,
                0x03b7af51244068f343a2b74461294a6du128,
                0x6745dcf60dfbbd4554b007cea003f679u128,
                0x841a9d528756675731e4739cb9a39541u128,
                0x75eddd5593824c07cae6acf567e1b1c7u128,
                0xb52945fee3505b2e2a521f4c8b15032au128,
                0xb5b1333382707a438333d5b269a4a92du128,
            ],
            [
                0x96a357d962e25ebb34a0ed44d40cecb0u128,
                0xbfd3143bc376fb2bd85e963b902ac1c2u128,
                0xdddb02ecd3343dd4e1e93590b0c7b5eau128,
                0xedd7eae0411dda195dc312d83efb784eu128,
                0x9f98256ac1b5a3333c0603c2eddc0f6cu128,
                0xf2382e0c1d0958a200a5316a6dcd3740u128,
                0xe8471441607bb5d86196b3721a50bf0eu128,
                0x405df27cab88f2bf0476c62108bdab57u128,
                0xdba69ab5b0d8e3887b6f0b751b0811d9u128,
                0x478d2b7e5b4693a4e65c516e0e0f7f54u128,
                0xbcdd2f14abbaa8aae5eb93cbf2333a03u128,
                0x7fb8c1b31c440ecafd071a8a7510eef0u128,
                0xabbf5486b38d806cd1d5265e6df965f7u128,
                0x5096daba2cf5b5025bc3175b1e462fe6u128,
                0x1f5aea28e9b2d821b1562469020aa5e2u128,
                0x62fafa1de4f2ecc6f952c91e3853dafdu128,
                0x2d0507c44c1bf9505b714614ea6e4458u128,
                0xcdb669481be8a1880e1271004e1a27dau128,
            ],
            [
                0xf9c9780fadc6aaa32a77e5e9376001dcu128,
                0x096102928667f1848392fd5d8588b5a7u128,
                0x3d00dbb890125ed0ab1172963ab98adbu128,
                0x4135fcabd822651f7b17e7e5ec19c7b7u128,
                0x1c8afbebec63d5d89cb6ddf160abb1d4u128,
                0xc82a78d9f90eeaebddf9e586f66b209au128,
                0x063aab9d00a8301ed0bfb769e02add7au128,
                0x002428a603ed9fe33c5030214ad0cb35u128,
                0x2c99478182dcf52d7ac6490b85cc92e5u128,
                0xeae102bb259587b81605abad9ae518bcu128,
                0x6034772762b1749766700018f33fa596u128,
                0xa4f66d526054405435e655745135ec0eu128,
                0x6eca6ec195e8c34e61592eb1241c84e3u128,
                0x4c13ea8c0637401b2f2fea8aafa37d45u128,
                0xcad1caf8c67364095e4c07565e969614u128,
                0xc77ba50add9d1a50a0331f232b895443u128,
                0xb90f6705f098e17f906c23d95397dc64u128,
                0x2d22d7ce3c18ad06f3a80706ed9ab2a6u128,
            ],
            [
                0x550dd3f99a9aff23ec6d8cfe7696ecb9u128,
                0x74a4d0cb79285fe20c351622c0ff05cfu128,
                0xf850a29dad557c0df64d6ba7c3078df9u128,
                0x7106004df44c7dd8437f7650e2131c3eu128,
                0xc80439997ab73ac1cb40d3871df1f59du128,
                0xe3edfd2162152a85aba6eb0a6fda044du128,
                0xf58429be04c508d36c0772efe92d9c1cu128,
                0xa5847e33014947505780002564c577a9u128,
                0xaca0fd8c8d13f0bef9847cc7e0a6d7f7u128,
                0x7c30c6696f08bdb87be5498a09834d10u128,
                0xd982a70f17c3a63c572b866414f865fdu128,
                0x6b9716580dd05f835052f3c7e062b88du128,
                0x4cdfcb88ce9f5356970aa14314258d26u128,
                0xdaa4baf30a03cc8808eace712a3ea9fdu128,
                0xaf5b2f45b3684ba62c0146d1db136de3u128,
                0x4e135b26ea54299ac6d609c7cbe75680u128,
                0x33c601d87c533001a2ce8d42cc252778u128,
                0x5fa74467fe5f183a28af4d63808b9315u128,
            ],
            [
                0x90febb86e2d05502194fe76eebe109abu128,
                0xe556103ebfa7286af9cd61b5d7ce544au128,
                0x392129df172d96daf32f125a0f3c133bu128,
                0x591d813c2af80621d4438c72897947fcu128,
                0x2b2686a0953af3739e6b97f7139ba8e6u128,
                0x5ba2333d9ebc236b10dbba58d84fe6d7u128,
                0x739ccf7f2a7deba7899084c806b121d6u128,
                0x75c9748768a864d1b7dab318d6a5e2e0u128,
                0x4ad3c424c2529e7fa381cf7f05d21559u128,
                0x6aa149786b0bb6a42e18991345c58fc3u128,
                0xdf812a2eaf8e465b25850fb55bb0639cu128,
                0xb2e22664fcde106e62c429babe1517ecu128,
                0x6ae6dc9128ec4756525f9b722188070bu128,
                0x8d5b0f528998d7e6fb40a04a90aedad7u128,
                0x13eb45f9bdc4e39d4dda743cfd91b382u128,
                0x3bfd6012a02f4e77d9ec829d0d81d317u128,
                0x1579605c75d155cdec9baf9de20e21afu128,
                0xc9d3a92002c1b2ba81e21cdb50721482u128,
            ],
        ];
        for data in database {
            let mut tab = [GF256::default(); 8];
            for i in 0..8 {
                tab[i] = GF256::new(data[2 * i], data[(2 * i) + 1]);
            }
            let result = GF256::new(data[16], data[17]);
            assert_eq!(GF256::byte_combine(&tab), result);
        }
    }

    #[test]
    //input : a bit (or a byte or many)
    //output : a GF256 whose light-weight bit is equal to the input bit (or the lightweight bit of the input value)
    fn gf256_test_from_bit() {
        //with bit = 0
        let bit_1 = 0u8;
        let res_1 = GF256::from_bit(bit_1);
        let (first_value_1, second_value_1) = res_1.get_value();
        assert_eq!(first_value_1, bit_1 as u128);
        assert_eq!(second_value_1, 0u128);
        //with bit = 1
        let bit_2 = 1u8;
        let res_2 = GF256::from_bit(bit_2);
        let (first_value_2, second_value_2) = res_2.get_value();
        assert_eq!(first_value_2, bit_2 as u128);
        assert_eq!(second_value_2, 0u128);
        //with byte whose lightweight bit =0
        let bit_3 = 76u8;
        let res_3 = GF256::from_bit(bit_3);
        let (first_value_3, second_value_3) = res_3.get_value();
        assert_eq!(first_value_3, 0u128);
        assert_eq!(second_value_3, 0u128);
        //with byte whose lightweight bit =0
        let bit_4 = 75u8;
        let res_4 = GF256::from_bit(bit_4);
        let (first_value_4, second_value_4) = res_4.get_value();
        assert_eq!(first_value_4, bit_4 as u128 & 1);
        assert_eq!(second_value_4, 0u128);
    }

    #[test]
    //To dest those one we use the test dataset of the reference implementation
    fn gf256_test_byte_combine_bits() {
        let database = [
            (
                0x0u8,
                0x00000000000000000000000000000000u128,
                0x00000000000000000000000000000000u128,
            ),
            (
                0x1u8,
                0x00000000000000000000000000000001u128,
                0x00000000000000000000000000000000u128,
            ),
            (
                0xc0u8,
                0xfedaa2104349c0b1243619216d768f80u128,
                0xd303dd260391524bdf640e1506710a3bu128,
            ),
            (
                0xcdu8,
                0xc20ee5833c30c8c9d8b65f8887d49b5du128,
                0xb4d87394efdbee37f5b8541dc74e16c1u128,
            ),
            (
                0xbu8,
                0xa9a70e26f37c4130c34d3bc1345e63fbu128,
                0x655c4b1450d8aebe24b4cf7a55ce4d7au128,
            ),
            (
                0xedu8,
                0xd9ca3e577cc14c4b4074aaa16e5eabebu128,
                0x96ff78f99e8ca1cbda065d89ba07bf40u128,
            ),
            (
                0xbeu8,
                0xbed68d38a0474e66969788430bdfffd3u128,
                0x04c9a8cf20c95833df229845f8f1e16bu128,
            ),
            (
                0x6au8,
                0x1e8eb334d57c6a0ec5fa615103903447u128,
                0x87467756f075c8b1fb0be3d1da1efb85u128,
            ),
            (
                0x4cu8,
                0x903921551988a7c462f5e91034e673d7u128,
                0xa7e6999d3db0958fdadd7f3733a60384u128,
            ),
            (
                0x4u8,
                0x2ba5c48d2c42072fa95af52ad52289c1u128,
                0x064e4d699c5b4af1d14a0d376c00b0eau128,
            ),
            (
                0xb3u8,
                0x8202caabdf3e461e6a17ceeae17deb0eu128,
                0x6312067dcc83e44ff5fec24d39cefd91u128,
            ),
            (
                0x75u8,
                0xe9ab210e1072cfe771ecaaa352f713a8u128,
                0xb2963efd7380a4c624f2592aab4ea62au128,
            ),
            (
                0x89u8,
                0x454647c87683605aef99051b8cb27597u128,
                0x72ab09d2a27a8d35d4f37c1559d7b955u128,
            ),
            (
                0x7du8,
                0xfedaa2104349c0b0243619206d778eb5u128,
                0xd303dd260391524bdf640e1506710a3au128,
            ),
            (
                0x36u8,
                0xfb90caf0d6c42e3c790e8d58876d8a45u128,
                0x7662a11d82b3d5060bd1e450a126583eu128,
            ),
            (
                0x9bu8,
                0x8eb79261ccf4cdcba70f8840377746a5u128,
                0x20a0eecbcdc55d3e21d69ce6e9b8f800u128,
            ),
            (
                0x7eu8,
                0x400c2f28e30e8ed7b2a1916266a97053u128,
                0xd7ca75e923580a7800469650fe80eb50u128,
            ),
            (
                0x62u8,
                0x09ff302a864765599020d2d23c10a95au128,
                0xe6d3948d80643e3c009db4ee77215795u128,
            ),
        ];
        for data in database {
            let x = data.0;
            let result = GF256::new(data.1, data.2);
            assert_eq!(GF256::byte_combine_bits(x), result);
        }
    }

    #[test]
    fn gf256_test_sum_poly() {
        let all_zeroes = [GF256::ZERO; 256];
        assert_eq!(GF256::sum_poly(&all_zeroes), GF256::ZERO);

        let all_ones = [GF256::ONE; 256];
        assert_eq!(
            GF256::sum_poly(&all_ones),
            GF256::new(
                0xffffffffffffffffffffffffffffffffu128,
                0xffffffffffffffffffffffffffffffffu128
            )
        );
    }

    #[test]
    //We see if the to field function give the same result that what we could have with BigUint
    fn gf256_test_to_field() {
        let mut rng = rand::thread_rng();

        for _i in 0..1000 {
            let random: [u8; 32] = rng.gen();
            let pol = GF256::to_field(&random);
            let verif_big = BigUint::from_bytes_le(&random);
            let verif_0_0 = verif_big.to_u64_digits()[0] as u128
                + ((verif_big.to_u64_digits()[1] as u128) << 64);
            let verif_0_1 = verif_big.to_u64_digits()[2] as u128
                + ((verif_big.to_u64_digits()[3] as u128) << 64);
            assert_eq!(pol[0].get_value().0, verif_0_0);
            assert_eq!(pol[0].get_value().1, verif_0_1);
        }
        //with many polynomes
        for _i in 0..1000 {
            let mut random_1 = rng.gen::<[u8; 32]>().to_vec();
            let mut random_2 = rng.gen::<[u8; 32]>().to_vec();
            random_1.append(&mut random_2);
            let pol = GF256::to_field(&random_1.clone());
            let verif_big = BigUint::from_bytes_le(&random_1);
            let verif_0_0 = verif_big.to_u64_digits()[0] as u128
                + ((verif_big.to_u64_digits()[1] as u128) << 64);
            let verif_0_1 = verif_big.to_u64_digits()[2] as u128
                + ((verif_big.to_u64_digits()[3] as u128) << 64);
            let verif_1_0 = verif_big.to_u64_digits()[4] as u128
                + ((verif_big.to_u64_digits()[5] as u128) << 64);
            let verif_1_1 = verif_big.to_u64_digits()[6] as u128
                + ((verif_big.to_u64_digits()[7] as u128) << 64);
            assert_eq!(pol[0].get_value().0, verif_0_0);
            assert_eq!(pol[0].get_value().1, verif_0_1);
            assert_eq!(pol[1].get_value().0, verif_1_0);
            assert_eq!(pol[1].get_value().1, verif_1_1);
        }
    }
}
