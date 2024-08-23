use std::{
    num::Wrapping,
    ops::{
        Add, AddAssign, BitAnd, BitXor, BitXorAssign, Mul, MulAssign, Neg, Shl, Shr, Sub, SubAssign,
    },
};

use super::Field;

/// Trait for binary Galois fields up to a size of `2^64`
pub trait GaloisField<T>: Field
where
    Self: From<T> + Copy,
    T: From<Self>,
{
    /// Representation of `0`
    const ZERO: Self;

    /// Representation of `1`
    const ONE: Self;
}

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
pub struct SmallGF<T>(Wrapping<T>)
where
    T: Copy;

impl<T> From<T> for SmallGF<T>
where
    T: Copy,
{
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
    T: Copy + Default,
{
    #[inline(always)]
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<T> PartialEq<T> for SmallGF<T>
where
    T: Copy,
    T: PartialEq,
{
    fn eq(&self, other: &T) -> bool {
        self.0 .0 == *other
    }
}

impl<T> Add for SmallGF<T>
where
    Wrapping<T>: BitXor<Output = Wrapping<T>>,
    T: Copy,
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
    T: Copy,
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
    T: Copy,
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
    T: Copy,
{
    #[inline(always)]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0
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

impl Field for SmallGF<u8> {}
impl Field for SmallGF<u64> {}

/// Binary field `2^8`
pub type GF8 = SmallGF<u8>;
/// Binary field `2^64`
pub type GF64 = SmallGF<u64>;

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

impl GaloisField<u8> for GF8 {
    const ZERO: Self = Self(Wrapping(0));
    const ONE: Self = Self(Wrapping(1));
}

impl From<&[u8]> for GF64 {
    fn from(value: &[u8]) -> Self {
        let mut array = [0u8; 8];
        array.copy_from_slice(&value[..8]);
        Self::from(u64::from_le_bytes(array))
    }
}

impl GF64 {
    #[allow(dead_code)]
    pub fn to_field(x: &[u8]) -> Vec<GF64> {
        let mut res = vec![];
        for i in 0..x.len() / 8 {
            res.push(GF64::from(&x[(i * 8)..((i + 1) * 8)]))
        }
        res
    }
}

impl GaloisField<u64> for GF64 {
    const ZERO: Self = Self(Wrapping(0));
    const ONE: Self = Self(Wrapping(1));
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::random;

    //GF8
    #[test]
    //Precondition = None
    //Post contidtion = GF8 whose get_value is as expected
    fn gf8_test_from_and_get_value() {
        let x: u8 = random();
        let polynome = GF8::from(x);
        assert_eq!(polynome, x);
    }

    #[test]
    //Should be equal to 8
    fn gf8_test_get_bit() {
        assert_eq!(GF8::BITS, 8usize);
    }

    #[test]
    //135 * 2 should be equal to 21
    //2 * 135 should be equal to 21
    //0 * anything should be equal to 0
    //anything * 0 should be equal to 0
    //1 * anything should be equal to anything
    //anything * 1 should be equal to anything
    fn gf8_test_mul() {
        let pol_2 = GF8::from(2u8);
        let pol_135 = GF8::from(135u8);
        let pol_21 = GF8::from(21u8);
        let anything: u8 = random();
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
            [0xffu8, 0x0u8, 0x0u8],
            [0x0u8, 0xffu8, 0x0u8],
            [0xffu8, 0x1u8, 0xffu8],
            [0x1u8, 0xffu8, 0xffu8],
            [0x1u8, 0x1u8, 0x1u8],
            [0x1u8, 0x1u8, 0x1u8],
            [0x1u8, 0x1u8, 0x1u8],
            [0x1u8, 0x1u8, 0x1u8],
            [0x1u8, 0x1u8, 0x1u8],
            [0xffu8, 0x1u8, 0xffu8],
            [0x69u8, 0xeau8, 0x37u8],
            [0x65u8, 0x86u8, 0x15u8],
            [0x5bu8, 0x9fu8, 0xd1u8],
            [0xau8, 0x4du8, 0xc4u8],
            [0xceu8, 0xau8, 0xadu8],
            [0xfau8, 0xf8u8, 0xedu8],
            [0xaau8, 0xb3u8, 0x71u8],
            [0x94u8, 0x93u8, 0x50u8],
            [0x12u8, 0xcu8, 0xd8u8],
            [0xf8u8, 0x8u8, 0x81u8],
            [0x23u8, 0xaau8, 0x79u8],
            [0xd2u8, 0x4eu8, 0x1au8],
            [0x4du8, 0x97u8, 0xd3u8],
            [0x88u8, 0xe2u8, 0x36u8],
            [0x8eu8, 0x4du8, 0x7cu8],
            [0xddu8, 0x14u8, 0x26u8],
            [0x57u8, 0xe6u8, 0xc3u8],
            [0x1eu8, 0x68u8, 0xdcu8],
            [0x38u8, 0x2du8, 0x42u8],
            [0xe5u8, 0x4u8, 0xb9u8],
            [0x28u8, 0xedu8, 0x8du8],
            [0x67u8, 0x5cu8, 0x10u8],
            [0x22u8, 0xe7u8, 0x2au8],
            [0x1au8, 0x61u8, 0xadu8],
            [0xafu8, 0x6au8, 0xeu8],
            [0xadu8, 0x57u8, 0xa8u8],
            [0x22u8, 0x22u8, 0x68u8],
            [0x7u8, 0x65u8, 0x20u8],
            [0x9au8, 0x7u8, 0xebu8],
            [0x4u8, 0x8au8, 0x1eu8],
            [0x97u8, 0x99u8, 0x1fu8],
            [0xfu8, 0xfcu8, 0x63u8],
            [0xc3u8, 0x62u8, 0xa8u8],
            [0x45u8, 0x60u8, 0x88u8],
            [0x51u8, 0x24u8, 0x91u8],
            [0xfau8, 0xf2u8, 0x93u8],
            [0xabu8, 0x9u8, 0x84u8],
            [0xaeu8, 0xa6u8, 0xa5u8],
            [0xd8u8, 0x44u8, 0xf1u8],
            [0x80u8, 0x95u8, 0xf4u8],
            [0xadu8, 0x9au8, 0x8bu8],
            [0xa8u8, 0x2au8, 0xa0u8],
            [0xa7u8, 0x91u8, 0xa5u8],
            [0xcau8, 0x91u8, 0x7eu8],
            [0x79u8, 0xb6u8, 0xb7u8],
            [0x55u8, 0x63u8, 0x2du8],
            [0x32u8, 0x18u8, 0x86u8],
            [0x84u8, 0x16u8, 0xadu8],
            [0x8bu8, 0x26u8, 0xc7u8],
            [0xb2u8, 0x8cu8, 0xebu8],
            [0x64u8, 0xd7u8, 0x85u8],
            [0x85u8, 0xd7u8, 0x4u8],
            [0x4u8, 0xd7u8, 0x71u8],
            [0x99u8, 0x71u8, 0x3bu8],
            [0x73u8, 0xd7u8, 0x49u8],
            [0xe6u8, 0x49u8, 0x32u8],
            [0x43u8, 0xaeu8, 0xd1u8],
            [0xd1u8, 0xaeu8, 0xe8u8],
            [0xe8u8, 0xaeu8, 0x53u8],
            [0x16u8, 0x53u8, 0xb6u8],
            [0x7u8, 0xaeu8, 0x67u8],
            [0xa8u8, 0x67u8, 0xau8],
            [0x3bu8, 0x32u8, 0xcau8],
            [0xcau8, 0x32u8, 0xb3u8],
            [0xb3u8, 0x32u8, 0x29u8],
            [0x26u8, 0x29u8, 0xa1u8],
            [0x53u8, 0x32u8, 0x6fu8],
            [0xf1u8, 0x6fu8, 0x33u8],
            [0x72u8, 0xd8u8, 0x66u8],
            [0x66u8, 0xd8u8, 0x4u8],
            [0x4u8, 0xd8u8, 0x4du8],
            [0x4u8, 0x4du8, 0x2fu8],
            [0x36u8, 0xd8u8, 0x97u8],
            [0xcbu8, 0x97u8, 0x63u8],
            [0x54u8, 0xa0u8, 0xcdu8],
            [0xcdu8, 0xa0u8, 0xc5u8],
            [0xc5u8, 0xa0u8, 0xb2u8],
            [0x4bu8, 0xb2u8, 0x53u8],
            [0xfcu8, 0xa0u8, 0x4cu8],
            [0x2cu8, 0x4cu8, 0x3eu8],
            [0xa1u8, 0xf7u8, 0x37u8],
            [0x37u8, 0xf7u8, 0xd3u8],
            [0xd3u8, 0xf7u8, 0x6bu8],
            [0xd5u8, 0x6bu8, 0xa2u8],
            [0x42u8, 0xf7u8, 0x7cu8],
            [0x61u8, 0x7cu8, 0x57u8],
            [0xdcu8, 0x7au8, 0xfu8],
            [0xfu8, 0x7au8, 0x80u8],
            [0x80u8, 0x7au8, 0x49u8],
            [0x5au8, 0x49u8, 0xcdu8],
            [0xc7u8, 0x7au8, 0x9du8],
            [0x4fu8, 0x9du8, 0x36u8],
            [0xd2u8, 0x2eu8, 0x15u8],
            [0x15u8, 0x2eu8, 0x40u8],
            [0x40u8, 0x2eu8, 0x75u8],
            [0xc7u8, 0x75u8, 0x9cu8],
            [0x2bu8, 0x2eu8, 0xaeu8],
            [0xccu8, 0xaeu8, 0xc1u8],
            [0x63u8, 0xc2u8, 0x8u8],
            [0x8u8, 0xc2u8, 0x4au8],
            [0x4au8, 0xc2u8, 0xb3u8],
            [0x4au8, 0xb3u8, 0xabu8],
            [0xe8u8, 0xc2u8, 0xd3u8],
            [0x2u8, 0xd3u8, 0xbdu8],
            [0xb0u8, 0xedu8, 0x50u8],
            [0x50u8, 0xedu8, 0x1u8],
            [0x1u8, 0xedu8, 0xedu8],
            [0xb0u8, 0xedu8, 0x50u8],
            [0xedu8, 0xedu8, 0xcu8],
            [0x68u8, 0xcu8, 0xd6u8],
            [0x93u8, 0x84u8, 0xa3u8],
            [0xa3u8, 0x84u8, 0x10u8],
            [0x10u8, 0x84u8, 0x98u8],
            [0x77u8, 0x98u8, 0x37u8],
            [0xc3u8, 0x84u8, 0x6du8],
            [0x17u8, 0x6du8, 0x92u8],
            [0xbu8, 0x45u8, 0xd1u8],
            [0xd1u8, 0x45u8, 0x72u8],
            [0x72u8, 0x45u8, 0x3eu8],
            [0x86u8, 0x3eu8, 0xb6u8],
            [0x7u8, 0x45u8, 0xc0u8],
            [0xaau8, 0xc0u8, 0x65u8],
            [0x19u8, 0x5au8, 0x6bu8],
            [0x6bu8, 0x5au8, 0xccu8],
            [0xccu8, 0x5au8, 0x6u8],
            [0x45u8, 0x6u8, 0x85u8],
            [0xdfu8, 0x5au8, 0x3fu8],
            [0x6bu8, 0x3fu8, 0x5au8],
            [0x50u8, 0xb0u8, 0xcu8],
            [0xcu8, 0xb0u8, 0x1u8],
            [0x1u8, 0xb0u8, 0xb0u8],
            [0x50u8, 0xb0u8, 0xcu8],
            [0xb0u8, 0xb0u8, 0xedu8],
            [0xbfu8, 0xedu8, 0xccu8],
            [0x79u8, 0x9du8, 0x60u8],
            [0x60u8, 0x9du8, 0x6au8],
            [0x6au8, 0x9du8, 0xcfu8],
            [0x3fu8, 0xcfu8, 0xb5u8],
            [0x16u8, 0x9du8, 0x70u8],
            [0xd9u8, 0x70u8, 0xbdu8],
            [0x62u8, 0xc3u8, 0xa8u8],
            [0xa8u8, 0xc3u8, 0x1du8],
            [0x1du8, 0xc3u8, 0x24u8],
            [0xcau8, 0x24u8, 0x2du8],
            [0x26u8, 0xc3u8, 0xafu8],
            [0x73u8, 0xafu8, 0xb0u8],
            [0x74u8, 0xccu8, 0x4au8],
            [0x4au8, 0xccu8, 0x72u8],
            [0x72u8, 0xccu8, 0xd4u8],
            [0x72u8, 0xd4u8, 0x8u8],
            [0xabu8, 0xccu8, 0x10u8],
            [0x35u8, 0x10u8, 0x7du8],
            [0x90u8, 0x81u8, 0xd2u8],
            [0xd2u8, 0x81u8, 0xc6u8],
            [0xc6u8, 0x81u8, 0x3cu8],
            [0x9du8, 0x3cu8, 0xf3u8],
            [0xaeu8, 0x81u8, 0xdeu8],
            [0x92u8, 0xdeu8, 0xa6u8],
            [0x5fu8, 0xe5u8, 0x53u8],
            [0x53u8, 0xe5u8, 0x83u8],
            [0x83u8, 0xe5u8, 0xfeu8],
            [0x4eu8, 0xfeu8, 0x7cu8],
            [0xcau8, 0xe5u8, 0x17u8],
            [0x13u8, 0x17u8, 0x52u8],
            [0xedu8, 0xcu8, 0xb0u8],
            [0xb0u8, 0xcu8, 0x1u8],
            [0x1u8, 0xcu8, 0xcu8],
            [0xedu8, 0xcu8, 0xb0u8],
            [0xcu8, 0xcu8, 0x50u8],
            [0xafu8, 0x50u8, 0x66u8],
            [0x4au8, 0xefu8, 0x2fu8],
            [0x2fu8, 0xefu8, 0x66u8],
            [0x66u8, 0xefu8, 0x63u8],
            [0x66u8, 0x63u8, 0x36u8],
            [0xc2u8, 0xefu8, 0xabu8],
            [0xdu8, 0xabu8, 0x1eu8],
            [0xcbu8, 0x74u8, 0x1du8],
            [0x1du8, 0x74u8, 0x33u8],
            [0x33u8, 0x74u8, 0x9fu8],
            [0x33u8, 0x9fu8, 0xefu8],
            [0x40u8, 0x74u8, 0x4u8],
            [0x65u8, 0x4u8, 0x8fu8],
            [0x6cu8, 0x97u8, 0x39u8],
            [0x39u8, 0x97u8, 0x8du8],
            [0x8du8, 0x97u8, 0xc6u8],
            [0x8du8, 0xc6u8, 0x63u8],
            [0x35u8, 0x97u8, 0x33u8],
            [0xc5u8, 0x33u8, 0x63u8],
            [0xdeu8, 0x7eu8, 0xaeu8],
            [0xaeu8, 0x7eu8, 0xe4u8],
            [0xe4u8, 0x7eu8, 0x77u8],
            [0xdcu8, 0x77u8, 0x34u8],
            [0xd2u8, 0x7eu8, 0x90u8],
            [0x25u8, 0x90u8, 0x7bu8],
            [0x4eu8, 0xffu8, 0x32u8],
            [0x32u8, 0xffu8, 0x5eu8],
            [0x5eu8, 0xffu8, 0x5bu8],
            [0xa5u8, 0x5bu8, 0xdbu8],
            [0x92u8, 0xffu8, 0xe9u8],
            [0x21u8, 0xe9u8, 0xcdu8],
            [0xd5u8, 0x3bu8, 0x8cu8],
            [0x8cu8, 0x3bu8, 0xabu8],
            [0xabu8, 0x3bu8, 0x2bu8],
            [0x3du8, 0x2bu8, 0x55u8],
            [0xf7u8, 0x3bu8, 0xdbu8],
            [0x68u8, 0xdbu8, 0xc0u8],
            [0x47u8, 0xbeu8, 0x43u8],
            [0x43u8, 0xbeu8, 0x8du8],
            [0x8du8, 0xbeu8, 0x5fu8],
            [0xfbu8, 0x5fu8, 0xc3u8],
            [0x67u8, 0xbeu8, 0x69u8],
            [0xe9u8, 0x69u8, 0x8cu8],
            [0x4u8, 0x10u8, 0x40u8],
            [0x40u8, 0x10u8, 0x6cu8],
            [0x6cu8, 0x10u8, 0x9au8],
            [0x6cu8, 0x9au8, 0xb3u8],
            [0x1du8, 0x10u8, 0xcbu8],
            [0xc7u8, 0xcbu8, 0x77u8],
            [0x63u8, 0xc2u8, 0x8u8],
            [0x8u8, 0xc2u8, 0x4au8],
            [0x4au8, 0xc2u8, 0xb3u8],
            [0x4au8, 0xb3u8, 0xabu8],
            [0xe8u8, 0xc2u8, 0xd3u8],
            [0xa3u8, 0xd3u8, 0xdfu8],
            [0x15u8, 0xau8, 0x82u8],
            [0x82u8, 0xau8, 0x63u8],
            [0x63u8, 0xau8, 0xf3u8],
            [0xa2u8, 0xf3u8, 0x8bu8],
            [0x7fu8, 0xau8, 0x2bu8],
            [0x98u8, 0x2bu8, 0x99u8],
            [0xebu8, 0x18u8, 0x2bu8],
            [0x2bu8, 0x18u8, 0xc5u8],
            [0xc5u8, 0x18u8, 0x96u8],
            [0x81u8, 0x96u8, 0xf9u8],
            [0x15u8, 0x18u8, 0xe3u8],
            [0xbu8, 0xe3u8, 0x67u8],
            [0x6u8, 0x14u8, 0x78u8],
            [0x78u8, 0x14u8, 0x3au8],
            [0x3au8, 0x14u8, 0x65u8],
            [0x23u8, 0x65u8, 0xbbu8],
            [0xb6u8, 0x14u8, 0x7bu8],
            [0xbu8, 0x7bu8, 0x78u8],
            [0xa4u8, 0xe6u8, 0x3bu8],
            [0x3bu8, 0xe6u8, 0x7du8],
            [0x7du8, 0xe6u8, 0xbau8],
            [0xf8u8, 0xbau8, 0x89u8],
            [0x6fu8, 0xe6u8, 0x8fu8],
            [0xdcu8, 0x8fu8, 0xcdu8],
            [0x28u8, 0x2cu8, 0x8cu8],
            [0x8cu8, 0x2cu8, 0x3au8],
            [0x3au8, 0x2cu8, 0x22u8],
            [0x8fu8, 0x22u8, 0x55u8],
            [0xf7u8, 0x2cu8, 0xc1u8],
            [0x15u8, 0xc1u8, 0x4cu8],
            [0xb2u8, 0xe9u8, 0x6fu8],
            [0x6fu8, 0xe9u8, 0xccu8],
            [0xccu8, 0xe9u8, 0x58u8],
            [0xbfu8, 0x58u8, 0x9eu8],
            [0x3bu8, 0xe9u8, 0x1fu8],
            [0x46u8, 0x1fu8, 0xc3u8],
            [0x54u8, 0xa0u8, 0xcdu8],
            [0xcdu8, 0xa0u8, 0xc5u8],
            [0xc5u8, 0xa0u8, 0xb2u8],
            [0x4bu8, 0xb2u8, 0x53u8],
            [0xfcu8, 0xa0u8, 0x4cu8],
            [0x4au8, 0x4cu8, 0x48u8],
            [0x9cu8, 0xd1u8, 0x8bu8],
            [0x8bu8, 0xd1u8, 0x35u8],
            [0x35u8, 0xd1u8, 0x62u8],
            [0x67u8, 0x62u8, 0x32u8],
            [0xd9u8, 0xd1u8, 0xf9u8],
            [0x4bu8, 0xf9u8, 0xbdu8],
            [0xdu8, 0x51u8, 0xb0u8],
            [0xb0u8, 0x51u8, 0xbcu8],
            [0xbcu8, 0x51u8, 0x5du8],
            [0xe0u8, 0x5du8, 0xb0u8],
            [0xcu8, 0x51u8, 0xe1u8],
            [0x63u8, 0xe1u8, 0x79u8],
            [0xb3u8, 0xe8u8, 0x35u8],
            [0x35u8, 0xe8u8, 0x63u8],
            [0x63u8, 0xe8u8, 0x2fu8],
            [0x63u8, 0x2fu8, 0xd3u8],
            [0x39u8, 0xe8u8, 0xefu8],
            [0xa7u8, 0xefu8, 0xe2u8],
            [0x20u8, 0x6cu8, 0x2fu8],
            [0x2fu8, 0x6cu8, 0x7du8],
            [0x7du8, 0x6cu8, 0x61u8],
            [0x7du8, 0x61u8, 0x36u8],
            [0xc2u8, 0x6cu8, 0x3au8],
            [0xe1u8, 0x3au8, 0x3du8],
            [0x11u8, 0x1au8, 0xa1u8],
            [0xa1u8, 0x1au8, 0xd8u8],
            [0xd8u8, 0x1au8, 0x1eu8],
            [0x12u8, 0x1eu8, 0xc7u8],
            [0x7cu8, 0x1au8, 0xb4u8],
            [0x7cu8, 0xb4u8, 0x17u8],
            [0x92u8, 0x85u8, 0xb5u8],
            [0xb5u8, 0x85u8, 0x8u8],
            [0x8u8, 0x85u8, 0x44u8],
            [0xb6u8, 0x44u8, 0x8cu8],
            [0x75u8, 0x85u8, 0x32u8],
            [0xb4u8, 0x32u8, 0xb7u8],
            [0xeu8, 0x54u8, 0x75u8],
            [0x75u8, 0x54u8, 0x9au8],
            [0x9au8, 0x54u8, 0xaau8],
            [0x1cu8, 0xaau8, 0xf7u8],
            [0xb5u8, 0x54u8, 0xe5u8],
            [0x4cu8, 0xe5u8, 0xb5u8],
            [0x1du8, 0x4au8, 0xd3u8],
            [0xd3u8, 0x4au8, 0x35u8],
            [0x35u8, 0x4au8, 0x36u8],
            [0x35u8, 0x36u8, 0x39u8],
            [0x63u8, 0x4au8, 0x40u8],
            [0x75u8, 0x40u8, 0x44u8],
            [0xd0u8, 0x2au8, 0x24u8],
            [0x24u8, 0x2au8, 0x9fu8],
            [0x9fu8, 0x2au8, 0xd7u8],
            [0x68u8, 0xd7u8, 0x16u8],
            [0x55u8, 0x2au8, 0x7au8],
            [0x36u8, 0x7au8, 0x3fu8],
            [0x74u8, 0xccu8, 0x4au8],
            [0x4au8, 0xccu8, 0x72u8],
            [0x72u8, 0xccu8, 0xd4u8],
            [0x72u8, 0xd4u8, 0x8u8],
            [0xabu8, 0xccu8, 0x10u8],
            [0xdfu8, 0x10u8, 0x5fu8],
            [0xb5u8, 0xfcu8, 0x34u8],
            [0x34u8, 0xfcu8, 0x36u8],
            [0x36u8, 0xfcu8, 0xd5u8],
            [0x73u8, 0xd5u8, 0xafu8],
            [0xf3u8, 0xfcu8, 0x75u8],
            [0xf1u8, 0x75u8, 0x8au8],
            [0xf5u8, 0x57u8, 0x3du8],
            [0x3du8, 0x57u8, 0x97u8],
            [0x97u8, 0x57u8, 0x81u8],
            [0x21u8, 0x81u8, 0xau8],
            [0xbbu8, 0x57u8, 0x46u8],
            [0x9au8, 0x46u8, 0xe6u8],
            [0x59u8, 0xf1u8, 0xa3u8],
            [0xa3u8, 0xf1u8, 0x25u8],
            [0x25u8, 0xf1u8, 0x11u8],
            [0xe5u8, 0x11u8, 0x37u8],
            [0xc3u8, 0xf1u8, 0x3eu8],
            [0x3fu8, 0x3eu8, 0x1du8],
            [0x57u8, 0xa5u8, 0x26u8],
            [0x26u8, 0xa5u8, 0x94u8],
            [0x94u8, 0xa5u8, 0x9bu8],
            [0x6du8, 0x9bu8, 0x44u8],
            [0xa8u8, 0xa5u8, 0xbfu8],
            [0xf3u8, 0xbfu8, 0xe9u8],
        ];
        for data in database {
            let left = GF8::from(data[0]);
            let right = GF8::from(data[1]);
            let result = GF8::from(data[2]);
            let res = left * right;
            let res_rev = right * left;
            assert_eq!(res, result);
            //to test commutativity
            assert_eq!(res, res_rev);
        }
    }

    #[test]
    //anything * inv(anything) should be equal to 1
    //anything * inv(0) should be equal to 0
    fn gf8_test_inv() {
        let pol_1 = GF8::from(1u8);
        let pol_0 = GF8::from(0u8);
        let anything: u8 = random();
        let pol_anything = GF8::from(anything);
        assert_eq!(pol_anything * GF8::inv(GF8::from(anything)), pol_1);
        assert_eq!(pol_anything * GF8::inv(GF8::from(0u8)), pol_0);
        let database = [
            [0x1u8, 0x1u8],
            [0xb9u8, 0x8eu8],
            [0xd0u8, 0x7au8],
            [0xe3u8, 0xebu8],
            [0x47u8, 0x69u8],
            [0xdu8, 0xe1u8],
            [0xe4u8, 0xc6u8],
            [0x8cu8, 0xf7u8],
            [0xd0u8, 0x7au8],
            [0x72u8, 0x97u8],
            [0x79u8, 0x70u8],
            [0x31u8, 0x45u8],
            [0xf3u8, 0x34u8],
            [0xc4u8, 0xdau8],
            [0x30u8, 0x2cu8],
            [0x40u8, 0x1du8],
            [0x2u8, 0x8du8],
            [0x98u8, 0x2au8],
            [0x1eu8, 0xeeu8],
            [0x41u8, 0xfeu8],
            [0xc5u8, 0xd4u8],
            [0x48u8, 0xa7u8],
            [0x9du8, 0xdcu8],
            [0xa8u8, 0x26u8],
            [0xd8u8, 0x94u8],
            [0xccu8, 0x1bu8],
            [0xb1u8, 0xe0u8],
            [0x78u8, 0xb6u8],
            [0x81u8, 0x7eu8],
            [0xb1u8, 0xe0u8],
            [0x38u8, 0xf2u8],
            [0xd7u8, 0xeau8],
            [0xa6u8, 0x65u8],
            [0x76u8, 0xbau8],
            [0x70u8, 0x79u8],
            [0x73u8, 0x85u8],
            [0xfeu8, 0x41u8],
            [0xc7u8, 0xfu8],
            [0xffu8, 0x1cu8],
            [0xc9u8, 0x27u8],
            [0x84u8, 0x96u8],
            [0x2cu8, 0x30u8],
            [0xacu8, 0xceu8],
            [0x35u8, 0x39u8],
            [0xa2u8, 0x2eu8],
            [0x9eu8, 0x89u8],
            [0xcdu8, 0xfcu8],
            [0xe7u8, 0xadu8],
            [0x75u8, 0xb5u8],
            [0x9fu8, 0x9au8],
            [0xb9u8, 0x8eu8],
        ];
        for data in database {
            let input = GF8::from(data[0]);
            let result = GF8::from(data[1]);
            let res = input.inv();
            assert_eq!(res, result);
        }
    }

    //GF64

    #[test]
    //Precondition = None
    //Post contidtion = GF64 whose get_value is as expected
    fn gf64_test_from_and_get_value() {
        let x: u64 = random();
        let polynome = GF64::from(x);
        assert_eq!(polynome, x);
    }

    #[test]
    //Should be equal to 64
    fn gf64_test_get_bit() {
        assert_eq!(GF64::BITS, 64usize);
    }

    #[test]
    //-----------------------------------
    //0 * anything should be equal to 0
    //anything * 0 should be equal to 0
    //1 * anything should be equal to anything
    //anything * 1 should be equal to anything
    fn gf64_test_mul() {
        let anything: u64 = random();
        let pol_anything = GF64::from(anything);
        let pol_0 = GF64::from(0u64);
        let pol_1 = GF64::from(1u64);
        assert_eq!(pol_1 * pol_1, pol_1);
        assert_eq!(pol_0 * pol_anything, pol_0);
        assert_eq!(pol_anything * pol_0, pol_0);
        assert_eq!(pol_1 * pol_anything, pol_anything);
        assert_eq!(pol_anything * pol_1, pol_anything);
        let database = [
            [0xffu64, 0x0u64, 0x0u64],
            [0x0u64, 0xffu64, 0x0u64],
            [0xffu64, 0x1u64, 0xffu64],
            [0x1u64, 0xffu64, 0xffu64],
            [
                0x7008a4d0cc8df4eu64,
                0x2426e635b07c8599u64,
                0x3af833412ea0030cu64,
            ],
            [
                0x53bd078f19d0e96u64,
                0x87e034859b8eb2c8u64,
                0x5c6805e162e884b2u64,
            ],
            [
                0xb0dba2c463c8500u64,
                0xe4ecd40354d7f013u64,
                0x9a367e998360d486u64,
            ],
            [
                0x5eba58bc758958c0u64,
                0xf3b02bdba9c3820du64,
                0xf20ed64f34d580feu64,
            ],
            [
                0xa2ec1d865e0dd535u64,
                0xa3aeb1ae21bc560cu64,
                0x889625a8702c4ffcu64,
            ],
            [
                0xdcf2a94bb4bafbb3u64,
                0xcbd8cbb7a2c06c81u64,
                0x3c426dbda1238ff1u64,
            ],
            [
                0x4b0644be8ca3b665u64,
                0xaa4f89d1033a083fu64,
                0xa92f63fd9f51f55du64,
            ],
            [
                0x31b401a1782f33fcu64,
                0x3ba4277db9907c90u64,
                0xe5b0ffdbf3a84b02u64,
            ],
            [
                0x67a633bebb389af2u64,
                0x6cc0f83c0233c8b1u64,
                0x8fb487e6ae0925d0u64,
            ],
            [
                0x3d61c987289f4c69u64,
                0xeb3b27408e29aa8au64,
                0x3fdbd8d462010463u64,
            ],
            [
                0x88a33697c1ed7da5u64,
                0x71d2b645a86d8109u64,
                0xc577879c5af745bdu64,
            ],
            [
                0x5658e401df8547du64,
                0xa3de80249ff11bu64,
                0x9c4970bfc55dbeb5u64,
            ],
            [
                0x50677a506539f871u64,
                0x82bcbc6b4543d67eu64,
                0x79c847601f570efdu64,
            ],
            [
                0x4e5e42401cb1552u64,
                0x7e0bcec249b0e3f0u64,
                0x7151dc81d70a57f5u64,
            ],
            [
                0xa6c0e6d8b56262f8u64,
                0x98c6c2439da26c54u64,
                0x56e1ea7b0aa4b000u64,
            ],
            [
                0x451fd1fe9e4131fcu64,
                0xf9ffe9b0dbccf8b7u64,
                0xd6d15321f86d8b9fu64,
            ],
            [
                0xca35ca1ccea59e32u64,
                0x4f7041eb7b9148cbu64,
                0xefb2428b3b42ecc8u64,
            ],
            [
                0x5499d23265feecebu64,
                0xd4aa931c691ede1bu64,
                0xf4f3fedd9373e93fu64,
            ],
            [
                0x7cae49ff32f97cd0u64,
                0x2e9e29bd787a2b7eu64,
                0xf7759ebabcd15c2u64,
            ],
            [
                0x7dda3d33fb7b9dc6u64,
                0x6601e09319beea8fu64,
                0x6d7eaa39526ef9e6u64,
            ],
            [
                0x290cd51c5edcefc6u64,
                0x6295ff10057ae155u64,
                0x57714677a01d8661u64,
            ],
            [
                0x53442095e3ae03cdu64,
                0xd584fca327b7163du64,
                0x1d9ba1bb06dd9576u64,
            ],
            [
                0x67da99f5a094d308u64,
                0xe317c506f72e4bd5u64,
                0xcc955883953a020cu64,
            ],
            [
                0x882b06de91da92e1u64,
                0x9467d2d56764eb8fu64,
                0x11b7b850acd548e8u64,
            ],
            [
                0x3cfcafbd66a4e5ecu64,
                0x2d31ae41ff450330u64,
                0xd18ba962867fbc64u64,
            ],
            [
                0x51002ce189648c2fu64,
                0x7487ede9f15bdee7u64,
                0x603d922f131eab8eu64,
            ],
            [
                0xeba5a27652f8c344u64,
                0xa885e44ef0bbefb0u64,
                0x6433a8053a64a309u64,
            ],
            [
                0x2d7cee8ac801b89eu64,
                0x1c968b62930b7fb7u64,
                0xbf80adfdabe8fe02u64,
            ],
            [
                0x54b9a3e1f7a25578u64,
                0x64b9afaf91cb864bu64,
                0xe46bc7f880153b7eu64,
            ],
            [
                0x3d71e7db056d38c5u64,
                0x85ca0e3ca109b691u64,
                0x7874ab798364092u64,
            ],
            [
                0x3e75ab4ef8cbb1c7u64,
                0x44ba99a4581f9244u64,
                0x9987b676a873de32u64,
            ],
            [
                0x42a4ad7e32d38b91u64,
                0xda84ec68db625c6u64,
                0xe70311a760e49b34u64,
            ],
            [
                0xb7b2a244cc6e86e3u64,
                0xecf2503e5e8a10f3u64,
                0x1d2fad10e2849632u64,
            ],
            [
                0x8d4aa7f1ec1078edu64,
                0xb7bfa3ceead11142u64,
                0x53de475d250b45e5u64,
            ],
            [
                0x119a2ab66b27cdfbu64,
                0x6dd557b0ad15a1du64,
                0xbd4934f2ad17aa94u64,
            ],
            [
                0xc5cb51bf0a982b4au64,
                0xfb22bc03b27b60e0u64,
                0x7b09a06d9c9f1595u64,
            ],
            [
                0xc7b43baa99485b1au64,
                0x12f55b9aec427b34u64,
                0xa5464668f7d9d77fu64,
            ],
            [
                0xc6ca52e89fecb0b8u64,
                0x138b3ef39809a88cu64,
                0x2a7dfa24e36cd724u64,
            ],
            [
                0x930e0ef875cf73ffu64,
                0x3a488907dfc68e64u64,
                0xd8d7c571d28c15f4u64,
            ],
            [
                0x6d009c48f403b9c0u64,
                0xe04e44c0b80f815au64,
                0x58ba73941becd613u64,
            ],
            [
                0xb99772dce11ee7c1u64,
                0xeef9473f2b0a7c56u64,
                0x7b92bf0747bb6a92u64,
            ],
            [
                0x7aba159254da89a9u64,
                0x7188a6fb7cdf8d44u64,
                0xeafedf516645dafdu64,
            ],
            [
                0x325cdb2494b41c6u64,
                0x4cf7876f74b2b2afu64,
                0xf952eeed78d14fe5u64,
            ],
            [
                0x6a79060d4e3e1c4eu64,
                0xd5b679b9ca324102u64,
                0x2efc9722b4d5662cu64,
            ],
            [
                0x360c1cfdcc7e5862u64,
                0x408bfce3a8ccbebdu64,
                0xc472478a68846f8bu64,
            ],
            [
                0x70c5f3083e98c33au64,
                0x2d26506efa5979b6u64,
                0xdd2e0d867a1d4f7eu64,
            ],
            [
                0xc678b2edfd146168u64,
                0x46594ffb356d4879u64,
                0x34dd04b3f1067423u64,
            ],
            [
                0x45d574c90cbb6a7du64,
                0x59ba7b8a4091261bu64,
                0x658324634fb9f4aeu64,
            ],
            [
                0xd0c8a33dee7e8530u64,
                0xed0ceed83d156ae9u64,
                0xf81a1ef2a40119a8u64,
            ],
            [
                0x558245733719beb8u64,
                0xb7fc2efd06c902deu64,
                0x43c5b7775bd8d749u64,
            ],
            [
                0xefcdab8967452301u64,
                0x123456789abcdefu64,
                0x490c13538cc9d696u64,
            ],
            [
                0x5bad5b7b15087e3cu64,
                0xbd47da595dfca610u64,
                0xcfe43e8b2c23752eu64,
            ],
            [
                0x1111173521c03bc8u64,
                0x36def786c2538920u64,
                0x80b097d6a59a51d2u64,
            ],
            [
                0x35459a042ed75b8u64,
                0xd0a007b5343f566cu64,
                0x58b739cbbef85b49u64,
            ],
            [
                0x6380e5c3b813b48eu64,
                0xbd316443abed23a9u64,
                0x50c9a06d3ce7b7eau64,
            ],
            [
                0xe133bc1035e9a36u64,
                0xfb0413bb9b4fa71cu64,
                0x471ab29e323cabf7u64,
            ],
            [
                0x3f5b3dc64fbe7a7cu64,
                0x2392569842a17469u64,
                0x74a0d0576f51498du64,
            ],
            [
                0x57d3278cf79c66d0u64,
                0x7868e4a80fbc7614u64,
                0x977dd0972cb0eeb3u64,
            ],
            [
                0x1f0832b18e78be5cu64,
                0xd7ad0219b7b37b04u64,
                0xd09162868b66f9u64,
            ],
            [
                0x29c79a2d8c132c1u64,
                0x2407e2a7cd18449bu64,
                0x15cc0d30bdd9b41cu64,
            ],
            [
                0x90178c8c56b53a32u64,
                0x479cf30f107e6895u64,
                0xdbdb1b06870c955bu64,
            ],
            [
                0xd4eac207516ae3a7u64,
                0x7038fb1b66fce29cu64,
                0xa5cda8baf441ebb5u64,
            ],
            [
                0x9ed59c0f3752405du64,
                0xd1ac7eb118bd7eeau64,
                0x890d217cfe7b9d10u64,
            ],
            [
                0x9c650d40248108aeu64,
                0x2021eef96fca6f50u64,
                0x7fff2674603d145fu64,
            ],
            [
                0x86245a30e6cac27eu64,
                0x86b418cb7927e379u64,
                0xb561a0f57cd2847eu64,
            ],
            [
                0x8b0bc202c71030a0u64,
                0x9c8aa18deb9889b9u64,
                0xfdcc538e97404843u64,
            ],
            [
                0xa4145e6e326aacbfu64,
                0x7a443a08a228fb64u64,
                0x9504e2602ee81757u64,
            ],
        ];
        for data in database {
            let left = GF64::from(data[0]);
            let right = GF64::from(data[1]);
            let result = GF64::from(data[2]);
            let res = left * right;
            let res_rev = right * left;
            assert_eq!(res, result);
            //to test commutativity
            assert_eq!(res, res_rev);
        }
    }

    #[test]
    fn gf64_test_to_field() {
        for _i in 0..1000 {
            let random = random::<[u8; 8]>();
            let res = GF64::to_field(&random);
            let verif = u64::from_le_bytes(random);
            assert_eq!(res[0], verif);
        }
        //with many
        for _i in 0..1000 {
            let random = random::<[u8; 16]>();
            let res = GF64::to_field(&random);
            let verif_1 = u64::from_le_bytes(random[0..8].try_into().expect("REASON"));
            let verif_2 = u64::from_le_bytes(random[8..16].try_into().expect("REASON"));
            assert_eq!(res[0], verif_1);
            assert_eq!(res[1], verif_2);
        }
    }
}
