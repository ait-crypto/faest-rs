use std::{
    fmt::Debug,
    ops::{Add, AddAssign, BitAnd, BitXor, BitXorAssign, Mul, MulAssign, Shl, Shr, Sub, SubAssign},
    u128,
};

use rand::{
    distributions::{Distribution, Standard},
    random,
};

pub trait GaloisField<T>
where
    T: Sized
        + std::ops::BitAnd<Output = T>
        + std::ops::Sub
        + std::ops::Shl<i32>
        + std::ops::Mul<<T as std::ops::BitAnd>::Output, Output = T>
        + std::ops::Shr<<T as std::ops::Sub>::Output, Output = T>
        + std::ops::Sub<Output = T>
        + std::ops::Shl<i32>
        + std::ops::Mul
        + std::ops::BitXorAssign
        + Clone
        + std::ops::Shr
        + std::ops::Add<Output = T>
        + std::ops::AddAssign
        + std::fmt::Debug,
{
    const MODULUS: T;

    const ONE: T;

    fn new(value: T) -> Self;

    fn get_value(&self) -> T;

    fn get_max() -> T;

    fn get_bit_usize() -> usize;

    fn get_bit_int() -> T;

    fn set_value(&mut self, value: T);

    fn rand_polynome() -> Self
    where
        Self: Sized,
        Standard: Distribution<T>,
    {
        let ret: T = rand::random();

        Self::new(ret)
    }

    fn mul(lhs: &Self, rhs: &Self) -> Self
    where
        Self: Sized,
        <T as Shl<i32>>::Output: BitXor<<T as BitAnd>::Output, Output = T>,
        <T as Mul<<T as BitAnd>::Output>>::Output: BitAnd<T>,
        <T as Shr<<T as Sub>::Output>>::Output: BitAnd<T>,
        <T as BitAnd>::Output: BitXorAssign,
        <T as Shl<i32>>::Output:
            BitXor<T> + std::ops::Mul + std::ops::Add<Output = T> + std::fmt::Debug,
    {
        let mut left = lhs.get_value();
        let right = rhs.get_value();
        let mut result_value = (Self::get_max() * (right.clone() & Self::ONE)) & left.clone();
        let mut count = Self::ONE;
        for _i in 1..Self::get_bit_usize() {
            let mask: T =
                Self::get_max() * ((left.clone() >> (Self::get_bit_int() - Self::ONE)) & Self::ONE);
            left = (left.clone() << 1) ^ (mask & Self::MODULUS);
            result_value ^=
                (Self::get_max() * ((right.clone() >> count.clone()) & Self::ONE)) & left.clone();
            count += Self::ONE;
        }
        Self::new(result_value)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct GF8 {
    value: u8,
}

impl GF8 {
    //---------------------------------------------------------------------------check this
    #[allow(dead_code)]
    pub fn inv(self) -> Self {
        let t2 = GF8::mul(&self, &self);
        let t3 = GF8::mul(&self, &t2);
        let t5 = GF8::mul(&t3, &t2);
        let t7 = GF8::mul(&t5, &t2);
        let t14 = GF8::mul(&t7, &t7);
        let t28 = GF8::mul(&t14, &t14);
        let t56 = GF8::mul(&t28, &t28);
        let t63 = GF8::mul(&t56, &t7);
        let t126 = GF8::mul(&t63, &t63);
        let t252 = GF8::mul(&t126, &t126);
        GF8::mul(&t252, &t2)
    }
}

impl GaloisField<u8> for GF8 {
    fn get_value(&self) -> u8 {
        self.value
    }

    fn get_max() -> u8 {
        u8::MAX
    }

    fn set_value(&mut self, value: u8) {
        self.value = value;
    }

    const ONE: u8 = 1u8;

    const MODULUS: u8 = 0b11011u8;

    fn new(value: u8) -> Self {
        GF8 { value }
    }

    fn get_bit_usize() -> usize {
        u8::BITS as usize
    }

    fn get_bit_int() -> u8 {
        u8::BITS as u8
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct GF64 {
    value: u64,
}

impl From<&[u8]> for GF64 {
    fn from(value: &[u8]) -> Self {
        let mut array = [0u8; 8];
        array.copy_from_slice(&value[..8]);
        GF64::new(u64::from_le_bytes(array))
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
    const MODULUS: u64 = 0b00011011u64;

    fn new(value: u64) -> Self {
        GF64 { value }
    }

    fn get_value(&self) -> u64 {
        self.value
    }

    fn get_max() -> u64 {
        u64::MAX
    }

    fn set_value(&mut self, value: u64) {
        self.value = value;
    }

    const ONE: u64 = 1u64;

    fn get_bit_usize() -> usize {
        u64::BITS as usize
    }

    fn get_bit_int() -> u64 {
        u64::BITS as u64
    }
}

//For GF192 and GF256, as u192 and u256 dont exist in rust, we will implement a new trait BigGaloisField, in wich we will also implement basis operations.

pub trait BigGaloisField: Clone
where
    Self: Sized + Copy,
    Self: for<'a> From<&'a [u8]>,
    Self: std::ops::Mul<Output = Self>,
    Self: std::ops::Add<Output = Self>,
    Self: std::ops::AddAssign,
    Self: std::ops::Mul<u8, Output = Self>,
    Self: std::ops::MulAssign<Self>,
    Self: for<'a> std::ops::MulAssign<&'a Self>,
{
    const LENGTH: u32;

    const MODULUS: Self;

    const ONE: Self;

    const MAX: Self;

    const ALPHA: [Self; 7];

    fn new(first_value: u128, second_value: u128) -> Self;

    fn get_value(&self) -> (u128, u128);

    fn rand() -> Self;

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

    fn switch_right(self, int: u32) -> Self {
        //the int  & 64 is for GF192, in wich the bit worthing 64 would not have been taken into account otherwise.
        let lim_int = (int & (Self::LENGTH - 1)) | (int & 64);
        let (first_value, second_value) = self.get_value();
        let carry = second_value & (u128::MAX.wrapping_shr(128 - lim_int));
        Self::new(
            (first_value.wrapping_shr(lim_int)) | (carry.wrapping_shl(128 - lim_int)),
            second_value.wrapping_shr(lim_int),
        )
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

    fn byte_combine(x: [Self; 8]) -> Self {
        let mut out = x[0];
        for (i, _) in x.iter().enumerate().skip(1) {
            out += x[i] * Self::ALPHA[i - 1];
        }
        out
    }

    fn from_bit(x: u8) -> Self {
        Self::new((x & 1) as u128, 0u128)
    }

    fn byte_combine_bits(x: u8) -> Self {
        let mut out = Self::from_bit(x);
        for i in 1..8 {
            out += Self::ALPHA[i - 1] * (x >> i);
        }
        out
    }

    fn sum_poly(v: [Self; 256]) -> Self {
        let mut res = v[0];
        let mut alpha = Self::MODULUS;
        for (i, _) in v.iter().enumerate().skip(1) {
            res += v[i] * alpha;
            alpha = alpha * alpha;
        }
        res
    }

    fn to_field(x: &[u8]) -> Vec<Self> {
        let n = 8 * x.len() / (Self::LENGTH as usize);
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

macro_rules! impl_Default {
    (for $($t:ty),+) => {
        $(impl Default for $t {
            fn default() -> Self {
                return Self::new(0u128, 0u128);
            }
        })*
    }
}

impl_Default!(for GF128, GF192, GF256);

macro_rules! impl_From {
    (for $($t:ty),+) => {
        $(impl From<&[u8]> for $t {
            fn from(value: &[u8]) -> Self {
                let mut array_1 = [0u8; 16];
                let mut array_2 = [0u8; 16];
                let mut data = value.to_vec();
                data.append(&mut vec![0u8; 32 - value.len()]);
                array_1.copy_from_slice(&data[..16]);
                array_2.copy_from_slice(&data[16..]);
                Self::new(u128::from_le_bytes(array_1), u128::from_le_bytes(array_2))
            }
        })*
    }
}

impl_From!(for GF128, GF192, GF256);

macro_rules! impl_Add {
    (for $($t:ty),+) => {
        $(impl Add for $t {
            type Output = Self;
            fn add(self, other: Self) -> Self::Output{
                let (l_first_value, l_second_value) = self.get_value();
                let (r_first_value, r_second_value) = other.get_value();
                Self::new(
                    l_first_value ^ r_first_value,
                    l_second_value ^ r_second_value,
                )
            }
        })*
    }
}

impl_Add!(for GF128, GF192, GF256);

macro_rules! impl_AddRef {
    (for $($t:ty),+) => {
        $(impl Add<&Self> for $t {
            type Output = Self;
            fn add(self, other: &Self) -> Self::Output{
                let (l_first_value, l_second_value) = self.get_value();
                let (r_first_value, r_second_value) = other.get_value();
                Self::new(
                    l_first_value ^ r_first_value,
                    l_second_value ^ r_second_value,
                )
            }
        })*
    }
}

impl_AddRef!(for GF128, GF192, GF256);

macro_rules! impl_RefAdd {
    (for $($t:ty),+) => {
        $(impl<'a, 'b> Add<&'b $t> for &'a $t {
            type Output = $t;
            fn add(self, other: &'b $t) -> $t{
                let (l_first_value, l_second_value) = self.get_value();
                let (r_first_value, r_second_value) = other.get_value();
                return (<$t>::new(l_first_value ^ r_first_value,
                    l_second_value ^ r_second_value)
                );
            }
        })*
    }
}

impl_RefAdd!(for GF128, GF192, GF256);

macro_rules! impl_Sub {
    (for $($t:ty),+) => {
        $(impl Sub for $t {
            type Output = Self;
            fn sub(self, other: Self) -> Self::Output{
                let (l_first_value, l_second_value) = self.get_value();
                let (r_first_value, r_second_value) = other.get_value();
                Self::new(
                    l_first_value ^ r_first_value,
                    l_second_value ^ r_second_value,
                )
            }
        })*
    }
}

impl_Sub!(for GF128, GF192, GF256);

macro_rules! impl_SubRef {
    (for $($t:ty),+) => {
        $(impl Sub<&Self> for $t {
            type Output = Self;
            fn sub(self, other: &Self) -> Self::Output{
                let (l_first_value, l_second_value) = self.get_value();
                let (r_first_value, r_second_value) = other.get_value();
                Self::new(
                    l_first_value ^ r_first_value,
                    l_second_value ^ r_second_value,
                )
            }
        })*
    }
}

impl_SubRef!(for GF128, GF192, GF256);

macro_rules! impl_RefSub {
    (for $($t:ty),+) => {
        $(impl<'a, 'b> Sub<&'b $t> for &'a $t {
            type Output = $t;
            fn sub(self, other: &'b $t) -> $t{
                let (l_first_value, l_second_value) = self.get_value();
                let (r_first_value, r_second_value) = other.get_value();
                return (<$t>::new(l_first_value ^ r_first_value,
                    l_second_value ^ r_second_value)
                );
            }
        })*
    }
}

impl_RefSub!(for GF128, GF192, GF256);

macro_rules! impl_Mul {
    (for $($t:ty),+) => {
        $(impl Mul for $t {
            type Output = Self;
            fn mul(self, right: Self) -> Self::Output where Self : BigGaloisField{
                let mut leftc = self; //to avoid side effect
                let mut result = Self::and(
                    &Self::and(&right, &Self::ONE).all_bytes_heavyweight(),
                    &leftc,
                );
                for i in 1..Self::LENGTH {
                    let mask = Self::and(
                        &leftc,
                        &Self::new(
                            (1_u128 - ((Self::LENGTH - 1) / 128) as u128)
                                * (1_u128 << ((Self::LENGTH - 1) % 128)),
                            ((Self::LENGTH - 1) as u128 / 128) * (1_u128 << ((Self::LENGTH - 1) % 128)),
                        ),
                    )
                    .all_bytes_heavyweight();
                    leftc = leftc.switch_left_1() + Self::and(&mask, &Self::MODULUS);
                    result =
                        Self::and(
                            &Self::and(
                                &right,
                                &Self::new(
                                    (1_u128 - (i as u128 / 128)) * (1_u128 << (i as u128 % 128)),
                                    (i as u128 / 128) * (1_u128 << (i as u128 % 128)),
                                ),
                            )
                            .all_bytes_heavyweight(),
                            &leftc,
                        ) +
                        result
                    ;
                }
                result
            }
        })*
    }
}

impl_Mul!(for GF128, GF192, GF256);

macro_rules! impl_Mul64 {
    (for $($t:ty),+) => {
        $(impl Mul<u64> for $t {
            type Output = Self;
            fn mul(self, right: u64) -> Self::Output {
                let right = <$t>::new(right as u128, 0u128);
                return self * right
            }
        })*
    }
}

impl_Mul64!(for GF128, GF192, GF256);

macro_rules! impl_Mul64Ref {
    (for $($t:ty),+) => {
        $(impl Mul<&u64> for $t {
            type Output = Self;
            fn mul(self, right: &u64) -> Self::Output {
                let right = <$t>::new(*right as u128, 0u128);
                return self * right
            }
        })*
    }
}

impl_Mul64Ref!(for GF128, GF192, GF256);

macro_rules! impl_RefMul64 {
    (for $($t:ty),+) => {
        $(impl<'a, 'b> Mul<&'b u64> for &'a $t {
            type Output = $t;
            fn mul(self, other: &u64) -> $t{
                let right = <$t>::new(*other as u128, 0u128);
                return *self * right
            }
        })*
    }
}

impl_RefMul64!(for GF128, GF192, GF256);

macro_rules! impl_Mul8 {
    (for $($t:ty),+) => {
        $(impl Mul<u8> for $t {
            type Output = Self;
            fn mul(self, right: u8) -> Self::Output {
                let right = <$t>::new(right as u128 & 1, 0u128);
                return self * right
            }
        })*
    }
}

impl_Mul8!(for GF128, GF192, GF256);

macro_rules! impl_Mul8Ref {
    (for $($t:ty),+) => {
        $(impl Mul<&u8> for $t {
            type Output = Self;
            fn mul(self, right: &u8) -> Self::Output {
                let right = <$t>::new(*right as u128 & 1, 0u128);
                return self * right
            }
        })*
    }
}

impl_Mul8Ref!(for GF128, GF192, GF256);

macro_rules! impl_RefMul8 {
    (for $($t:ty),+) => {
        $(impl<'a, 'b> Mul<&'a u8> for &'b $t {
            type Output = $t;
            fn mul(self, other: &u8) -> $t{
                let right = <$t>::new(*other as u128 & 1, 0u128);
                return *self * right
            }
        })*
    }
}

impl_RefMul8!(for GF128, GF192, GF256);

macro_rules! impl_MulRef {
    (for $($t:ty),+) => {
        $(impl Mul<&Self> for $t {
            type Output = Self;
            fn mul(self, right: &Self) -> Self::Output {
                self * *right
            }
        })*
    }
}

impl_MulRef!(for GF128, GF192, GF256);

macro_rules! impl_RefMul {
    (for $($t:ty),+) => {
        $(impl<'a, 'b> Mul<&'b $t> for &'a $t {
            type Output = $t;
            fn mul(self, right: &'b $t) -> $t where $t : BigGaloisField{
                *self * *right
            }
        })*
    }
}

impl_RefMul!(for GF128, GF192, GF256);

macro_rules! impl_AddAssign {
    (for $($t:ty),+) => {
        $(impl AddAssign for $t {
            fn add_assign(&mut self, other: Self) {
                *self = (*self + other);
            }
        })*
    }
}

impl_AddAssign!(for GF128, GF192, GF256);

macro_rules! impl_AddAssignRef {
    (for $($t:ty),+) => {
        $(impl AddAssign<&Self> for $t {
            fn add_assign(&mut self, other: &Self) {
                let res = *self + *other;
                *self = res;
            }
        })*
    }
}

impl_AddAssignRef!(for GF128, GF192, GF256);

macro_rules! impl_SubAssign {
    (for $($t:ty),+) => {
        $(impl SubAssign for $t {
            #[allow(clippy::suspicious_op_assign_impl)]
            fn sub_assign(&mut self, other: Self) {
                *self += other;
            }
        })*
    }
}

impl_SubAssign!(for GF128, GF192, GF256);

macro_rules! impl_SubAssignRef {
    (for $($t:ty),+) => {
        $(impl SubAssign<&Self> for $t {
            #[allow(clippy::suspicious_op_assign_impl)]
            fn sub_assign(&mut self, other: &Self) {
                *self += *other;
            }
        })*
    }
}

impl_SubAssignRef!(for GF128, GF192, GF256);

macro_rules! impl_MulAssign {
    (for $($t:ty),+) => {
        $(impl MulAssign for $t {
            fn mul_assign(&mut self, other: Self) {
                *self = *self * other;
            }
        })*
    }
}

impl_MulAssign!(for GF128, GF192, GF256);

macro_rules! impl_MulAssignRef {
    (for $($t:ty),+) => {
        $(impl MulAssign<&Self> for $t {
            fn mul_assign(&mut self, other: &Self) {
                *self = *self * *other;
            }
        })*
    }
}

impl_MulAssignRef!(for GF128, GF192, GF256);

macro_rules! impl_MulAssign64 {
    (for $($t:ty),+) => {
        $(impl MulAssign<u64> for $t {
            fn mul_assign(&mut self, other: u64) {
                *self = *self * other;
            }
        })*
    }
}

impl_MulAssign64!(for GF128, GF192, GF256);

macro_rules! impl_MulAssign64Ref {
    (for $($t:ty),+) => {
        $(impl MulAssign<&u64> for $t {
            fn mul_assign(&mut self, other: &u64) {
                *self = *self * *other;
            }
        })*
    }
}

impl_MulAssign64Ref!(for GF128, GF192, GF256);

macro_rules! impl_MulAssign8 {
    (for $($t:ty),+) => {
        $(impl MulAssign<u8> for $t {
            fn mul_assign(&mut self, other: u8) {
                *self = *self * other;
            }
        })*
    }
}

impl_MulAssign8!(for GF128, GF192, GF256);

macro_rules! impl_MulAssign8Ref {
    (for $($t:ty),+) => {
        $(impl MulAssign<&u8> for $t {
            fn mul_assign(&mut self, other: &u8) {
                *self = *self * *other;
            }
        })*
    }
}

impl_MulAssign8Ref!(for GF128, GF192, GF256);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GF128 {
    first_value: u128,
    second_value: u128,
}

impl BigGaloisField for GF128 {
    const LENGTH: u32 = 128u32;

    const MODULUS: Self = GF128 {
        first_value: 0b10000111u128,
        second_value: 0u128,
    };

    const ONE: Self = GF128 {
        first_value: 1u128,
        second_value: 0u128,
    };

    const MAX: Self = GF128 {
        first_value: u128::MAX,
        second_value: 0u128,
    };

    const ALPHA: [Self; 7] = [
        GF128 {
            first_value: 0x053d8555a9979a1ca13fe8ac5560ce0du128,
            second_value: 0u128,
        },
        GF128 {
            first_value: 0x4cf4b7439cbfbb84ec7759ca3488aee1u128,
            second_value: 0u128,
        },
        GF128 {
            first_value: 0x35ad604f7d51d2c6bfcf02ae363946a8u128,
            second_value: 0u128,
        },
        GF128 {
            first_value: 0x0dcb364640a222fe6b8330483c2e9849u128,
            second_value: 0u128,
        },
        GF128 {
            first_value: 0x549810e11a88dea5252b49277b1b82b4u128,
            second_value: 0u128,
        },
        GF128 {
            first_value: 0xd681a5686c0c1f75c72bf2ef2521ff22u128,
            second_value: 0u128,
        },
        GF128 {
            first_value: 0x0950311a4fb78fe07a7a8e94e136f9bcu128,
            second_value: 0u128,
        },
    ];

    fn new(first_value: u128, _second_value: u128) -> Self {
        GF128 {
            first_value,
            second_value: 0u128,
        }
    }

    fn get_value(&self) -> (u128, u128) {
        (self.first_value, self.second_value)
    }

    fn rand() -> Self {
        Self::new(random(), 0u128)
    }

    fn and(left: &Self, right: &Self) -> Self {
        Self::new(
            left.first_value & right.first_value,
            left.second_value & right.second_value,
        )
    }

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

    fn switch_right(self, int: u32) -> Self {
        //the int  & 64 is for GF192, in wich the bit worthing 64 would not have been taken into account otherwise.
        let lim_int = (int & (Self::LENGTH - 1)) | (int & 64);
        let (first_value, second_value) = self.get_value();
        let carry = second_value & (u128::MAX.wrapping_shr(128 - lim_int));
        Self::new(
            (first_value.wrapping_shr(lim_int)) | (carry.wrapping_shl(128 - lim_int)),
            second_value.wrapping_shr(lim_int),
        )
    }

    fn switch_left_1(self) -> Self {
        let (first_value, second_value) = self.get_value();
        let carry = (first_value & (1u128 << 127)) >> 127;
        let first_res = first_value.wrapping_shl(1);
        let second_res = (second_value.wrapping_shl(1)) | carry;
        Self::new(first_res, second_res)
    }

    fn byte_combine(x: [Self; 8]) -> Self {
        let mut out = x[0];
        for (i, _) in x.iter().enumerate().skip(1) {
            out += x[i] * Self::ALPHA[i - 1];
        }
        out
    }

    fn from_bit(x: u8) -> Self {
        Self::new((x & 1) as u128, 0u128)
    }

    fn byte_combine_bits(x: u8) -> Self {
        let mut out = Self::from_bit(x);
        for i in 1..8 {
            out += Self::ALPHA[i - 1] * (x >> i);
        }
        out
    }

    fn sum_poly(v: [Self; 256]) -> Self {
        let mut res = v[0];
        let mut alpha = Self::MODULUS;
        for (i, _) in v.iter().enumerate().skip(1) {
            res += v[i] * alpha;
            alpha = alpha * alpha;
        }
        res
    }

    fn to_field(x: &[u8]) -> Vec<Self> {
        let n = 8 * x.len() / (Self::LENGTH as usize);
        let mut res = vec![];
        let padding_array = [0u8; 16];
        for i in 0..n {
            let padded_value = &mut x
                [(i * (Self::LENGTH as usize) / 8)..((i + 1) * (Self::LENGTH as usize) / 8)]
                .to_vec();
            padded_value.append(&mut padding_array[..(32 - (Self::LENGTH as usize) / 8)].to_vec());
            res.push(Self::from(&padded_value[..]));
        }
        res
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GF192 {
    first_value: u128,
    second_value: u128,
}

impl BigGaloisField for GF192 {
    const MODULUS: Self = GF192 {
        first_value: 0b10000111u128,
        second_value: 0u128,
    };

    const ONE: Self = GF192 {
        first_value: 1u128,
        second_value: 0u128,
    };

    const LENGTH: u32 = 192u32;

    const MAX: Self = GF192 {
        first_value: u128::MAX,
        second_value: u64::MAX as u128,
    };

    const ALPHA: [Self; 7] = [
        GF192 {
            first_value: 0xe665d76c966ebdeaccc8a3d56f389763u128,
            second_value: 0x310bc8140e6b3662u128,
        },
        GF192 {
            first_value: 0x7bf61f19d5633f26b233619e7cf450bbu128,
            second_value: 0xda933726d491db34u128,
        },
        GF192 {
            first_value: 0x8232e37706328d199c6d2c13f5398a0du128,
            second_value: 0x0c3b0d703c754ef6u128,
        },
        GF192 {
            first_value: 0x7a5542ab0058d22edd20747cbd2bf75du128,
            second_value: 0x45ec519c94bc1251u128,
        },
        GF192 {
            first_value: 0x08168cb767debe84d8d50ce28ace2bf8u128,
            second_value: 0xd67d146a4ba67045u128,
        },
        GF192 {
            first_value: 0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
            second_value: 0x29a6bd5f696cea43u128,
        },
        GF192 {
            first_value: 0x6019fd623906e9d3f5945dc265068571u128,
            second_value: 0xc77c56540f87c4b0u128,
        },
    ];

    fn new(first_value: u128, second_value: u128) -> Self {
        GF192 {
            first_value,
            second_value: second_value & u64::MAX as u128,
        }
    }

    fn get_value(&self) -> (u128, u128) {
        (self.first_value, self.second_value)
    }

    fn rand() -> Self {
        GF192 {
            first_value: random(),
            second_value: random::<u128>() & (u64::MAX as u128),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GF256 {
    first_value: u128,
    second_value: u128,
}

impl BigGaloisField for GF256 {
    const LENGTH: u32 = 256u32;

    const MODULUS: Self = GF256 {
        first_value: 0b10000100101u128,
        second_value: 0u128,
    };

    const ONE: Self = GF256 {
        first_value: 1u128,
        second_value: 0u128,
    };

    const MAX: Self = GF256 {
        first_value: u128::MAX,
        second_value: u128::MAX,
    };

    const ALPHA: [Self; 7] = [
        GF256 {
            first_value: 0xbed68d38a0474e67969788420bdefee7u128,
            second_value: 0x04c9a8cf20c95833df229845f8f1e16au128,
        },
        GF256 {
            first_value: 0x2ba5c48d2c42072fa95af52ad52289c1u128,
            second_value: 0x064e4d699c5b4af1d14a0d376c00b0eau128,
        },
        GF256 {
            first_value: 0x1771831e533b0f5755dab3833f809d1du128,
            second_value: 0x6195e3db7011f68dfb96573fad3fac10u128,
        },
        GF256 {
            first_value: 0x752758911a30e3f6de010519b01bcdd5u128,
            second_value: 0x56c24fd64f7688382a0778b6489ea03fu128,
        },
        GF256 {
            first_value: 0x1bc4dbd440f1848298c2f529e98a30b6u128,
            second_value: 0x22270b6d71574ffc2fbe09947d49a981u128,
        },
        GF256 {
            first_value: 0xaced66c666f1afbc9e75afb9de44670bu128,
            second_value: 0xc03d372fd1fa29f3f001253ff2991f7eu128,
        },
        GF256 {
            first_value: 0x5237c4d625b86f0dba43b698b332e88bu128,
            second_value: 0x133eea09d26b7bb82f652b2af4e81545u128,
        },
    ];

    fn new(first_value: u128, second_value: u128) -> Self {
        GF256 {
            first_value,
            second_value,
        }
    }

    fn get_value(&self) -> (u128, u128) {
        (self.first_value, self.second_value)
    }

    fn rand() -> Self {
        Self::new(random(), random())
    }
}
