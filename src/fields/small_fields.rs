use std::{
    num::Wrapping,
    ops::{
        Add, AddAssign, BitAnd, BitXor, BitXorAssign, Mul, MulAssign, Neg, Shl, Shr, Sub, SubAssign,
    },
};

use generic_array::{GenericArray, typenum::U8};

use super::{Field, Square};

trait GaloisFieldHelper<T>
where
    T: Sized + Copy,
    Wrapping<T>: BitAnd<Output = Wrapping<T>>
        + BitXor<Output = Wrapping<T>>
        + BitXorAssign
        + Neg<Output = Wrapping<T>>
        + Shl<usize, Output = Wrapping<T>>
        + Shr<usize, Output = Wrapping<T>>,
{
    const MODULUS: Wrapping<T>;

    const ONE: Wrapping<T>;

    const BITS: usize;

    fn mul_helper(mut left: Wrapping<T>, right: Wrapping<T>) -> Wrapping<T> {
        let mut result_value = (-(right & Self::ONE)) & left;
        for i in 1..Self::BITS {
            let mask = -((left >> (Self::BITS - 1)) & Self::ONE);
            left = (left << 1) ^ (mask & Self::MODULUS);
            result_value ^= (-((right >> i) & Self::ONE)) & left;
        }
        result_value
    }
}

/// Small binary fields to a size up to 64 bits
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
pub struct SmallGF<T>(Wrapping<T>);

impl<T> From<T> for SmallGF<T> {
    #[inline]
    fn from(value: T) -> Self {
        Self(Wrapping(value))
    }
}

impl From<SmallGF<Self>> for u8 {
    #[inline]
    fn from(value: SmallGF<Self>) -> Self {
        value.0.0
    }
}

impl From<SmallGF<Self>> for u64 {
    #[inline]
    fn from(value: SmallGF<Self>) -> Self {
        value.0.0
    }
}

impl<T> Default for SmallGF<T>
where
    T: Default,
{
    #[inline]
    fn default() -> Self {
        Self(Wrapping::default())
    }
}

impl<T> PartialEq<T> for SmallGF<T>
where
    T: PartialEq<T>,
{
    fn eq(&self, other: &T) -> bool {
        self.0.0 == *other
    }
}

impl<T> Add for SmallGF<T>
where
    Wrapping<T>: BitXor<Output = Wrapping<T>>,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl<T> AddAssign for SmallGF<T>
where
    Wrapping<T>: BitXorAssign,
{
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl<T> Sub for SmallGF<T>
where
    Wrapping<T>: BitXor<Output = Wrapping<T>>,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl<T> SubAssign for SmallGF<T>
where
    Wrapping<T>: BitXorAssign,
{
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl<T> Neg for SmallGF<T> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        self
    }
}

impl GaloisFieldHelper<u64> for SmallGF<u64> {
    const BITS: usize = u64::BITS as usize;
    const MODULUS: Wrapping<u64> = Wrapping(0b00011011u64);
    const ONE: Wrapping<u64> = Wrapping(1u64);
}

impl GaloisFieldHelper<u8> for SmallGF<u8> {
    const BITS: usize = u8::BITS as usize;
    const MODULUS: Wrapping<u8> = Wrapping(0b00011011);
    const ONE: Wrapping<u8> = Wrapping(1u8);
}

impl<T> Mul for SmallGF<T>
where
    Self: GaloisFieldHelper<T>,
    T: Sized + Copy,
    Wrapping<T>: BitAnd<Output = Wrapping<T>>
        + BitXor<Output = Wrapping<T>>
        + BitXorAssign
        + Neg<Output = Wrapping<T>>
        + Shl<usize, Output = Wrapping<T>>
        + Shr<usize, Output = Wrapping<T>>,
{
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(Self::mul_helper(self.0, rhs.0))
    }
}

impl<T> MulAssign for SmallGF<T>
where
    Self: GaloisFieldHelper<T>,
    T: Sized + Copy,
    Wrapping<T>: BitAnd<Output = Wrapping<T>>
        + BitXor<Output = Wrapping<T>>
        + BitXorAssign
        + Neg<Output = Wrapping<T>>
        + Shl<usize, Output = Wrapping<T>>
        + Shr<usize, Output = Wrapping<T>>,
{
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = Self::mul_helper(self.0, rhs.0);
    }
}

impl<T> Square for SmallGF<T>
where
    Self: GaloisFieldHelper<T>,
    T: Sized + Copy,
    Wrapping<T>: BitAnd<Output = Wrapping<T>>
        + BitXor<Output = Wrapping<T>>
        + BitXorAssign
        + Neg<Output = Wrapping<T>>
        + Shl<usize, Output = Wrapping<T>>
        + Shr<usize, Output = Wrapping<T>>,
{
    type Output = Self;

    #[inline]
    fn square(self) -> Self::Output {
        Self(Self::mul_helper(self.0, self.0))
    }
}

/// Binary field `2^8`
pub type GF8 = SmallGF<u8>;

impl GF8 {
    pub fn square_bits(x: u8) -> u8 {
        let mut res = (x ^ (x >> 4) ^ (x >> 6)) & 0x1;
        res |= ((x >> 3) ^ (x >> 5) ^ (x >> 6)) & 0x2;
        res |= ((x << 1) ^ (x >> 3)) & 0x4;
        res |= ((x >> 1) ^ (x >> 2) ^ (x >> 3) ^ (x >> 4)) & 0x8;
        res |= ((x << 2) ^ x ^ (x >> 3)) & 0x10;
        res |= (x ^ (x >> 1)) & 0x20;
        res |= ((x << 3) ^ (x << 1)) & 0x40;
        res |= ((x << 1) ^ x) & 0x80;
        res
    }
}

/// Binary field `2^64`
pub type GF64 = SmallGF<u64>;

impl Field for GF64 {
    const ZERO: Self = Self(Wrapping(0));
    const ONE: Self = Self(Wrapping(1));

    type Length = U8;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        GenericArray::from(self.0.0.to_le_bytes())
    }

    /*
    fn as_boxed_bytes(&self) -> Box<GenericArray<u8, Self::Length>> {
        let mut arr = GenericArray::default_boxed();
        arr.copy_from_slice(&self.0.0.to_le_bytes());
        arr
    }
    */
}

impl From<&[u8]> for GF64 {
    fn from(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), 8);
        let mut array = [0u8; 8];
        array.copy_from_slice(&value[..8]);
        Self::from(u64::from_le_bytes(array))
    }
}

#[cfg(test)]
mod test {
    use rand::{Rng, SeedableRng, rngs::SmallRng};

    use super::*;

    #[test]
    fn gf64_test_mul() {
        let mut rng = SmallRng::from_entropy();

        let anything: u64 = rng.r#gen();
        let pol_anything = GF64::from(anything);
        let pol_0 = GF64::from(0u64);
        let pol_1 = GF64::from(1u64);
        assert_eq!(pol_1 * pol_1, pol_1);
        assert_eq!(pol_0 * pol_anything, pol_0);
        assert_eq!(pol_anything * pol_0, pol_0);
        assert_eq!(pol_1 * pol_anything, pol_anything);
        assert_eq!(pol_anything * pol_1, pol_anything);
        let database = [
            (
                0xa2ec1d865e0dd535u64,
                0xa3aeb1ae21bc560cu64,
                0x889625a8702c4ffcu64,
            ),
            (
                0xdcf2a94bb4bafbb3u64,
                0xcbd8cbb7a2c06c81u64,
                0x3c426dbda1238ff1u64,
            ),
            (
                0x4b0644be8ca3b665u64,
                0xaa4f89d1033a083fu64,
                0xa92f63fd9f51f55du64,
            ),
            (
                0x31b401a1782f33fcu64,
                0x3ba4277db9907c90u64,
                0xe5b0ffdbf3a84b02u64,
            ),
            (
                0x67a633bebb389af2u64,
                0x6cc0f83c0233c8b1u64,
                0x8fb487e6ae0925d0u64,
            ),
        ];
        for (left, right, result) in database {
            let left = GF64::from(left);
            let right = GF64::from(right);
            let result = GF64::from(result);
            let res = left * right;
            let res_rev = right * left;
            assert_eq!(res, result);
            //to test commutativity
            assert_eq!(res, res_rev);
        }
    }
}
