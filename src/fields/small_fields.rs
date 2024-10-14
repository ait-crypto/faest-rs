use std::{
    num::Wrapping,
    ops::{
        Add, AddAssign, BitAnd, BitXor, BitXorAssign, Mul, MulAssign, Neg, Shl, Shr, Sub, SubAssign,
    },
};

use generic_array::{
    typenum::{U1, U8},
    GenericArray,
};

use super::Field;

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
#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(transparent)]
pub struct SmallGF<T>(Wrapping<T>);

impl<T> From<T> for SmallGF<T> {
    #[inline(always)]
    fn from(value: T) -> Self {
        Self(Wrapping(value))
    }
}

impl From<SmallGF<u8>> for u8 {
    #[inline(always)]
    fn from(value: SmallGF<u8>) -> Self {
        value.0 .0
    }
}

impl From<SmallGF<u64>> for u64 {
    #[inline(always)]
    fn from(value: SmallGF<u64>) -> Self {
        value.0 .0
    }
}

impl<T> Default for SmallGF<T>
where
    T: Default,
{
    #[inline(always)]
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<T> PartialEq<T> for SmallGF<T>
where
    T: PartialEq<T>,
{
    fn eq(&self, other: &T) -> bool {
        self.0 .0 == *other
    }
}

impl<T> Add for SmallGF<T>
where
    Wrapping<T>: BitXor<Output = Wrapping<T>>,
{
    type Output = Self;

    #[inline(always)]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl<T> AddAssign for SmallGF<T>
where
    Wrapping<T>: BitXorAssign,
{
    #[inline(always)]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0
    }
}

impl<T> Sub for SmallGF<T>
where
    Wrapping<T>: BitXor<Output = Wrapping<T>>,
{
    type Output = Self;

    #[inline(always)]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl<T> SubAssign for SmallGF<T>
where
    Wrapping<T>: BitXorAssign,
{
    #[inline(always)]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0
    }
}

impl<T> Neg for SmallGF<T> {
    type Output = Self;

    #[inline(always)]
    fn neg(self) -> Self::Output {
        self
    }
}

impl GaloisFieldHelper<u8> for SmallGF<u8> {
    const BITS: usize = u8::BITS as usize;
    const ONE: Wrapping<u8> = Wrapping(1u8);
    const MODULUS: Wrapping<u8> = Wrapping(0b11011u8);
}

impl GaloisFieldHelper<u64> for SmallGF<u64> {
    const BITS: usize = u64::BITS as usize;
    const MODULUS: Wrapping<u64> = Wrapping(0b00011011u64);
    const ONE: Wrapping<u64> = Wrapping(1u64);
}

impl Mul for SmallGF<u8> {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(Self::mul_helper(self.0, rhs.0))
    }
}

impl MulAssign for SmallGF<u8> {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = Self::mul_helper(self.0, rhs.0);
    }
}

impl Mul for SmallGF<u64> {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(Self::mul_helper(self.0, rhs.0))
    }
}

impl MulAssign for SmallGF<u64> {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = Self::mul_helper(self.0, rhs.0);
    }
}

/// Binary field `2^8`
pub type GF8 = SmallGF<u8>;
/// Binary field `2^64`
pub type GF64 = SmallGF<u64>;

impl Field for GF8 {
    const ZERO: Self = Self(Wrapping(0));
    const ONE: Self = Self(Wrapping(1));

    type Length = U1;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        GenericArray::from([self.0 .0])
    }
}

impl Field for GF64 {
    const ZERO: Self = Self(Wrapping(0));
    const ONE: Self = Self(Wrapping(1));

    type Length = U8;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        GenericArray::from(self.0 .0.to_le_bytes())
    }
}

impl GF8 {
    //---------------------------------------------------------------------------check this
    #[allow(dead_code)]
    pub fn inv(self) -> Self {
        let t2 = self * self;
        let t3 = self * t2;
        let t5 = t3 * t2;
        let t7 = t5 * t2;
        let t14 = t7 * t7;
        let t28 = t14 * t14;
        let t56 = t28 * t28;
        let t63 = t56 * t7;
        let t126 = t63 * t63;
        let t252 = t126 * t126;
        t252 * t2
    }
}

impl From<&[u8]> for GF64 {
    fn from(value: &[u8]) -> Self {
        let mut array = [0u8; 8];
        array.copy_from_slice(&value[..8]);
        Self::from(u64::from_le_bytes(array))
    }
}

#[cfg(test)]
mod test {
    use rand::{rngs::SmallRng, Rng, SeedableRng};

    use super::*;

    const RUNS: usize = 10;

    #[test]
    fn gf8_test_mul() {
        let mut rng = SmallRng::from_entropy();

        let pol_2 = GF8::from(2u8);
        let pol_135 = GF8::from(135u8);
        let pol_21 = GF8::from(21u8);
        let anything: u8 = rng.gen();
        let pol_anything = GF8::from(anything);
        let pol_0 = GF8::from(0u8);
        let pol_1 = GF8::from(1u8);
        assert_eq!(pol_2 * pol_135, pol_21);
        assert_eq!(pol_135 * pol_2, pol_21);
        assert_eq!(pol_0 * pol_anything, pol_0);
        assert_eq!(pol_anything * pol_0, pol_0);
        assert_eq!(pol_1 * pol_anything, pol_anything);
        assert_eq!(pol_anything * pol_1, pol_anything);
        //Some datas obtained from the refrence implementation :
        let database = [
            (0xc5u8, 0xa0u8, 0xb2u8),
            (0x4bu8, 0xb2u8, 0x53u8),
            (0xfcu8, 0xa0u8, 0x4cu8),
            (0x2cu8, 0x4cu8, 0x3eu8),
            (0xa1u8, 0xf7u8, 0x37u8),
        ];
        for (left, right, result) in database {
            let left = GF8::from(left);
            let right = GF8::from(right);
            let result = GF8::from(result);
            let res = left * right;
            let res_rev = right * left;
            assert_eq!(res, result);
            assert_eq!(res, res_rev);
        }
    }

    #[test]
    //anything * inv(anything) should be equal to 1
    //anything * inv(0) should be equal to 0
    fn gf8_test_inv() {
        let mut rng = SmallRng::from_entropy();

        let pol_1 = GF8::from(1u8);
        let pol_0 = GF8::from(0u8);
        let anything = {
            let mut r = 0;
            while r == 0 {
                r = rng.gen();
            }
            r
        };
        let pol_anything = GF8::from(anything);
        assert_eq!(pol_anything * GF8::inv(GF8::from(anything)), pol_1);
        assert_eq!(pol_anything * GF8::inv(GF8::from(0u8)), pol_0);
        let database = [
            (0xccu8, 0x1bu8),
            (0xb1u8, 0xe0u8),
            (0x78u8, 0xb6u8),
            (0x81u8, 0x7eu8),
            (0xb1u8, 0xe0u8),
        ];
        for (input, result) in database {
            let input = GF8::from(input);
            let result = GF8::from(result);
            let res = input.inv();
            assert_eq!(res, result);
        }
    }

    #[test]
    fn gf64_test_mul() {
        let mut rng = SmallRng::from_entropy();

        let anything: u64 = rng.gen();
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
