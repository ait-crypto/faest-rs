use std::{
    default,
    num::Wrapping,
    ops::{
        Add, AddAssign, BitAnd, BitXor, BitXorAssign, Mul, MulAssign, Neg, Shl, Shr, Sub, SubAssign,
    },
};

use generic_array::{
    typenum::{U1, U3, U8},
    GenericArray,
};

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
    #[inline(always)]
    fn from(value: T) -> Self {
        Self(Wrapping(value))
    }
}

impl From<SmallGF<Self>> for u64 {
    #[inline(always)]
    fn from(value: SmallGF<Self>) -> Self {
        value.0 .0
    }
}

impl<T> Default for SmallGF<T>
where
    T: Default,
{
    #[inline(always)]
    fn default() -> Self {
        Self(Wrapping::default())
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
        self.0 ^= rhs.0;
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
        self.0 ^= rhs.0;
    }
}

impl<T> Neg for SmallGF<T> {
    type Output = Self;

    #[inline(always)]
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

    #[inline(always)]
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
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = Self::mul_helper(self.0, rhs.0);
    }
}

/// Binary field `2^3`
pub(crate) type GF8 = SmallGF<u8>;
impl Square for GF8 {
    type Output = GF8;

    fn square(mut self) -> Self::Output {
        let mut result_value = -(self.0 & GF8::ONE) & self.0;
        let right = self.0;

        for i in 1..GF8::BITS {
            let mask = -((self.0 >> (GF8::BITS - 1)) & GF8::ONE);
            self.0 = (self.0 << 1) ^ (mask & GF8::MODULUS);
            result_value ^= -((right >> i) & GF8::ONE) & self.0;
        }

        SmallGF(result_value)
    }
}

impl GF8 {
    pub(crate) fn invnorm(x: u8) -> u8 {
        let inv = GF8::exp_238(GF8::from(x));

        let mut res = inv & 1; // Take bit 0 in pos 0

        res |= (inv & 0b11000000u8) >> 5; // Take bit 6,7 in pos 1,2

        res | ((inv & 0b100) << 1) // Take bit 2 in pos 3
    }

    fn exp_238(mut x: GF8) -> u8 {
        // 238 == 0b11101110
        let mut y = x.square(); // x^2
        x = y.square(); // x^4
        y = x * y;
        x = x.square(); // x^8
        y = x * y;
        x = x.square(); // x^16
        x = x.square(); // x^32
        y = x * y;
        x = x.square(); // x^64
        y = x * y;
        x = x.square(); // x^128
        (x * y).0 .0
    }

    pub(crate) fn square_bits_inplace(x: &mut u8) {
        let bits = [
            *x & 0b1,
            (*x & 0b10) >> 1,
            (*x & 0b100) >> 2,
            (*x & 0b1000) >> 3,
            (*x & 0b10000) >> 4,
            (*x & 0b100000) >> 5,
            (*x & 0b1000000) >> 6,
            (*x & 0b10000000) >> 7,
        ];

        *x = bits[0] ^ bits[4] ^ bits[6];
        *x |= (bits[4] ^ bits[6] ^ bits[7]) << 1;
        *x |= (bits[1] ^ bits[5]) << 2;
        *x |= (bits[4] ^ bits[5] ^ bits[6] ^ bits[7]) << 3;
        *x |= (bits[2] ^ bits[4] ^ bits[7]) << 4;
        *x |= (bits[5] ^ bits[6]) << 5;
        *x |= (bits[3] ^ bits[5]) << 6;
        *x |= (bits[6] ^ bits[7]) << 7;
    }

    pub(crate) fn square_bits(x: u8) -> u8 {
        let mut x = x;
        Self::square_bits_inplace(&mut x);
        x
    }
}

pub const GF8_INV_NORM: [u8; 256] = [
    0, 1, 13, 9, 12, 3, 6, 4, 1, 5, 8, 7, 15, 10, 10, 4, 13, 5, 7, 7, 11, 15, 2, 7, 9, 14, 14, 12,
    14, 1, 10, 10, 12, 7, 7, 9, 2, 12, 2, 9, 3, 4, 9, 2, 5, 15, 2, 1, 6, 3, 4, 12, 4, 1, 1, 15, 4,
    1, 13, 2, 14, 8, 14, 11, 1, 14, 2, 2, 2, 10, 6, 10, 5, 3, 1, 9, 5, 13, 6, 6, 8, 6, 10, 4, 6,
    15, 5, 14, 7, 11, 9, 3, 5, 9, 13, 9, 15, 12, 8, 1, 10, 3, 1, 15, 10, 3, 13, 2, 13, 10, 9, 15,
    10, 9, 13, 15, 12, 2, 5, 11, 4, 3, 11, 5, 4, 13, 3, 8, 13, 10, 4, 12, 5, 2, 5, 6, 5, 2, 14, 4,
    15, 12, 14, 11, 7, 12, 8, 3, 13, 11, 6, 12, 7, 14, 12, 6, 15, 5, 15, 13, 11, 8, 15, 15, 14, 9,
    10, 6, 15, 11, 9, 1, 7, 10, 4, 4, 2, 11, 3, 1, 6, 15, 8, 7, 7, 11, 6, 4, 12, 13, 6, 11, 9, 10,
    1, 2, 11, 13, 13, 8, 14, 7, 8, 13, 13, 4, 9, 7, 14, 8, 8, 1, 12, 8, 5, 6, 12, 8, 14, 4, 6, 3,
    9, 15, 14, 3, 6, 11, 12, 3, 9, 3, 1, 5, 5, 14, 7, 4, 3, 1, 10, 7, 8, 8, 3, 5, 7, 2, 10, 2, 12,
    14, 8, 11, 11, 11,
];

/// Binary field `2^64`
pub type GF64 = SmallGF<u64>;

impl Field for GF64 {
    const ZERO: Self = Self(Wrapping(0));
    const ONE: Self = Self(Wrapping(1));

    type Length = U8;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        GenericArray::from(self.0 .0.to_le_bytes())
    }

    fn as_boxed_bytes(&self) -> Box<GenericArray<u8, Self::Length>> {
        let mut arr = GenericArray::default_boxed();
        arr.copy_from_slice(&self.0 .0.to_le_bytes());
        arr
    }
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
    use rand::{rngs::SmallRng, Rng, SeedableRng};

    use super::*;

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

    #[test]
    fn gf8_test_invnorm() {
        assert_eq!(GF8::invnorm(0), 0);
        assert_eq!(GF8::invnorm(1), 1);
        assert_eq!(GF8::invnorm(2), 1 << 3 | 1 << 2 | 1);
        assert_eq!(GF8::invnorm(0x80), 1 << 3 | 1 << 2 | 1);
        assert_eq!(GF8::invnorm(0x88), 1 << 2 | 1);
    }
}
