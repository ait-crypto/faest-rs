use std::{ops::{BitAnd, BitXor, BitXorAssign, Mul, Shl, Shr, Sub}, u128};

use rand::{distributions::{Distribution, Standard}, random};

pub trait GalloisField<T> where T: Sized 
                                + std::ops::BitAnd<Output = T> 
                                + std::ops::Sub + std::ops::Shl<i32> 
                                + std::ops::Mul<<T as std::ops::BitAnd>::Output, Output = T> 
                                + std::ops::Shr<<T as std::ops::Sub>::Output, Output = T>
                                + std::ops::Sub<Output = T> + std::ops::Shl<i32> 
                                + std::ops::Mul
                                + std::ops::BitXorAssign
                                + Clone
                                + std::ops::Shr
                                + std::ops::Add<Output = T>
                                + std::ops::AddAssign
                                + std::fmt::Debug{

    const MODULUS : T;

    const ONE : T;

    fn new(value: T) -> Self;

    fn get_value(&self) -> T;

    fn get_max() -> T;

    fn get_bit_usize() -> usize;

    fn get_bit_int() -> T;

    fn set_value(&mut self, value: T);

    fn rand_polynome() -> Self where Self: Sized, Standard: Distribution<T> {
        let ret : T = rand::random();
        let res = Self::new(ret);
        return res;
    }

    fn mul(lhs : &Self, rhs : &Self) -> Self where Self: Sized,
                                                     <T as Shl<i32>>::Output: BitXor<<T as BitAnd>::Output, Output = T>, 
                                                     <T as Mul<<T as BitAnd>::Output>>::Output: BitAnd<T>, 
                                                     <T as Shr<<T as Sub>::Output>>::Output: BitAnd<T>, 
                                                     <T as BitAnd>::Output: BitXorAssign, 
                                                     <T as Shl<i32>>::Output: BitXor<T> 
                                                     + std::ops::Mul
                                                     + std::ops::Add<Output = T>
                                                     + std::fmt::Debug{
        let mut left = lhs.get_value();
        let right = rhs.get_value();
        let mut result_value = (Self::get_max() * (right.clone() & Self::ONE)) & left.clone();
        let mut count = Self::ONE;
        for _i in 1..Self::get_bit_usize() {
            let mask : T = Self::get_max() * ((left.clone() >> (Self::get_bit_int() - Self::ONE)) & Self::ONE);
            left  = (left.clone() << 1) ^ (mask & Self::MODULUS);
            result_value ^= (Self::get_max() * ((right.clone()>> count.clone()) & Self::ONE)) & left.clone();
            count += Self::ONE;
        }
        return Self::new(result_value);
    }
}


#[derive(Debug, PartialEq)]
pub struct GF8 {
    value : u8
}

impl GF8 {
    pub fn inv(self) -> Self {
        let t2 = GF8::mul(&self, &self);
        let t3 = GF8::mul(&self, &t2);
        let t5 = GF8::mul( &t3, &t2);
        let t7 = GF8::mul( &t5, &t2);
        let t14 = GF8::mul( &t7, &t7);
        let t28 = GF8::mul(&t14, &t14);
        let t56 = GF8::mul( &t28, &t28);
        let t63 = GF8::mul( &t56, &t7);
        let t126 = GF8::mul( &t63, &t63);
        let t252 = GF8::mul( &t126, &t126);
        return GF8::mul(&t252, &t2);
    }
}

impl GalloisField<u8> for GF8 {

    fn get_value(&self) -> u8 {
        return self.value;
    }

    fn get_max() -> u8 {
        return u8::MAX;
    }

    fn set_value(&mut self, value: u8) {
        self.value = value;
     }
        
    const ONE : u8 = 1u8;
    
    const MODULUS : u8 = 0b11011u8;
    
    fn new(value: u8) -> Self {
        return GF8 { value : value }
    }
    
    fn get_bit_usize() -> usize {
        return u8::BITS as usize;
    }
    
    fn get_bit_int() -> u8 {
        return u8::BITS as u8;
    }
}


#[derive(Debug, PartialEq)]
pub struct GF64 {
    value : u64
}

impl GalloisField<u64> for GF64 {
    const MODULUS : u64 = 0b00011011u64;

    fn new(value: u64) -> Self {
        return GF64 { value : value};
    }

    fn get_value(&self) -> u64 {
        return self.value;
    }

    fn get_max() -> u64 {
        return u64::MAX;
    }

    fn set_value(&mut self, value: u64) {
        self.value = value;
    }
    
    const ONE : u64 = 1u64;
    
    fn get_bit_usize() -> usize {
        return u64::BITS as usize;
    }
    
    fn get_bit_int() -> u64 {
        return u64::BITS as u64;
    }
}

//For GF192 and GF256, as u192 and u256 dont exist in rust, we will implement a new trait BigGalloisField, in wich we will also implement basis operations. 

pub trait BigGalloisField: Clone where Self : Sized + Copy{

    const LENGTH : u32;

    const MODULUS : Self;

    const ONE : Self;

    const MAX : Self;

    const ALPHA : [Self; 7];

    fn new(first_value: u128, second_value: u128) -> Self;

    fn get_value(&self) -> (u128, u128);

    fn rand() -> Self;

    fn add(left: &Self, right : &Self) -> Self;

    fn complement_to_0(self) -> Self {
        return Self::add(&Self::xor(&self, &Self::MAX), &Self::ONE);
    }

    fn switch_right(self, int : u32) -> Self {
        let (first_value, second_value) = self.get_value();
        let carry = second_value & (u128::MAX >> (128 - int));
        return Self::new((first_value >> int) | (carry <<(128 - int)), second_value >> int)
    }

    fn switch_left(self, int : u32) -> Self;

    fn mul(left: &Self, right: &Self) -> Self {
        let mut leftc = left.clone(); //to avoid side effect
        let mut result = Self::and(&Self::and(&right, &Self::ONE).complement_to_0(), &leftc);
        for i in 1..Self::LENGTH{
            let mask = Self::and(&leftc.switch_right(Self::LENGTH -1), &Self::ONE).complement_to_0();
            leftc = Self::xor(&leftc.switch_left(1), &Self::and(&mask, &Self::MODULUS));
            result = Self::xor(&Self::and(&Self::and(&(right.switch_right(i)), &Self::ONE).complement_to_0(), &leftc), &result)
        }
        return result
    }

    fn mul_64 (self, right : u64) -> Self {
        let self_right = Self::new(right as u128, 0u128);
        return Self::mul(&self, &self_right);
    }

    fn mul_bit (self, right : u8) -> Self {
        let self_right = Self::new(right as u128, 0u128);
        return Self::mul(&self, &self_right);
    }

    fn and(left: &Self, right: &Self) -> Self {
        let (l_first_value, l_second_value) = left.get_value();
        let (r_first_value, r_second_value) = right.get_value();
        return Self::new(l_first_value & r_first_value, l_second_value & r_second_value);
    }

    fn xor(left: &Self, right: &Self) -> Self
    {
        let (l_first_value, l_second_value) = left.get_value();
        let (r_first_value, r_second_value) = right.get_value();
        return Self::new(l_first_value ^ r_first_value, l_second_value ^ r_second_value);
    }

    fn byte_combine (x : [Self; 8] ) -> Self {
        let mut out = x[0].clone();
        for i in 1..8 {
            out  =  Self::add(&out, &Self::mul(&x[i], &Self::ALPHA[i - 1]));
        }
        return out;
    }

    fn from_bit(x: u8) -> Self {
        return Self::new((x&1) as u128, 0u128);
    }

    fn byte_combine_bits (x : u8) -> Self {
        let mut out = Self::from_bit(x);
        for i in 1..8 {
            out = Self::add(&out, &Self::ALPHA[i-1].mul_bit(x >> i));
        } 
        return out
    }

    #[allow(arithmetic_overflow)]
    fn and_64 (left: Self, right: u64) -> Self {
        let mut res = Self::and(&left, &Self::new(right as u128, 0u128));
        res = Self::and(&res, &Self::new((right << 64) as u128, 0u128));
        res = Self::and(&res, &Self::new(0u128,  right as u128));
        res = Self::and(&res, &Self::new(0u128, (right << 64) as u128));
        return res;
    }

    fn sum_poly(v : [Self; 256]) -> Self {
        let mut res = v[0].clone();
        let mut alpha = Self::MODULUS;
        for i in 1..Self::LENGTH as usize{
            res = Self::add(&res, &Self::mul(&v[i], &alpha));
            alpha = Self::mul(&alpha, &alpha);
        }
        return res

    }


} 

#[derive(Clone, Copy, Debug, PartialEq)]
struct GF128{
    first_value : u128,
    second_value : u128
}

impl BigGalloisField for GF128 {

    const LENGTH : u32 = 128u32;

    const MODULUS : Self = GF128 { first_value : 0b10000111u128, second_value : 0u128 };
    
    const ONE : Self = GF128 { first_value : 1u128, second_value : 0u128 };

    const MAX : Self = GF128 { first_value : u128::MAX, second_value : 0u128};
    
    const ALPHA : [Self; 7] =  [GF128 { first_value : 0x053d8555a9979a1ca13fe8ac5560ce0du128, second_value : 0u128 },
                                GF128 { first_value : 0x4cf4b7439cbfbb84ec7759ca3488aee1u128, second_value : 0u128 },
                                GF128 { first_value : 0x35ad604f7d51d2c6bfcf02ae363946a8u128, second_value : 0u128 },
                                GF128 { first_value : 0x0dcb364640a222fe6b8330483c2e9849u128, second_value : 0u128 },
                                GF128 { first_value : 0x549810e11a88dea5252b49277b1b82b4u128, second_value : 0u128 },
                                GF128 { first_value : 0xd681a5686c0c1f75c72bf2ef2521ff22u128, second_value : 0u128 },
                                GF128 { first_value : 0x0950311a4fb78fe07a7a8e94e136f9bcu128, second_value : 0u128 }];

    fn new(first_value: u128, second_value: u128) -> Self {
        return GF128 {first_value : first_value, second_value : second_value};
    }

    fn get_value(&self) -> (u128, u128) {
        return (self.first_value, self.second_value);
    }

    fn rand() -> Self {
        return Self::new(random(), 0u128);
    }

    fn add(left: &Self, right : &Self) -> Self {
        return GF128 { first_value : left.first_value + right.first_value, second_value : 0u128};
    }
    
    fn switch_left(self, int : u32) -> Self {
        return Self::new(self.first_value << int, 0u128);
    }
    
    fn complement_to_0(self) -> Self {
        return Self::add(&Self::xor(&self, &Self::MAX), &Self::ONE);
    }
    
    fn switch_right(self, int : u32) -> Self {
        let (first_value, second_value) = self.get_value();
        let carry = second_value & (u128::MAX >> (128 - int));
        return Self::new((first_value >> int) | (carry <<(128 - int)), second_value >> int)
    }
    
    fn byte_combine (x : [Self; 8] ) -> Self {
        let mut out = x[0].clone();
        for i in 1..8 {
            out  = Self::add(&out, &Self::mul(&x[i], &Self::ALPHA[i - 1]));
        }
        return out;
    }
    
    #[allow(arithmetic_overflow)]
    fn and_64 (left: Self, right: u64) -> Self {
        let mut res = Self::and(&left, &Self::new(right as u128, 0u128));
        res = Self::and(&res, &Self::new((right << 64) as u128, 0u128));
        res = Self::and(&res, &Self::new(0u128 , right as u128));
        res = Self::and(&res, &Self::new(0u128 , (right << 64) as u128));
        return res;
    }
    
    fn and(left: &Self, right: &Self) -> Self {
        return Self::new(left.first_value & right.first_value, left.second_value & right.second_value);
    }
    
    fn xor(left: &Self, right: &Self) -> Self
    {
        return Self::new(left.first_value ^ right.first_value, left.second_value ^ right.second_value);
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct GF192 {
    first_value : u128,
    second_value : u128
}

impl BigGalloisField for GF192 {
    
    const MODULUS : Self = GF192 {first_value : 0b10000111u128, second_value : 0u128};

    const ONE : Self = GF192 {first_value : 1u128, second_value : 0u128};

    const LENGTH : u32 = 192u32;

    const MAX : Self = GF192 { first_value : u128::MAX, second_value : u64::MAX as u128};
    
    const ALPHA : [Self; 7] =  [GF192 {first_value : 0xe665d76c966ebdeaccc8a3d56f389763u128, second_value : 0x310bc8140e6b3662u128},
                                GF192 {first_value : 0x7bf61f19d5633f26b233619e7cf450bbu128, second_value : 0xda933726d491db34u128},
                                GF192 {first_value : 0x8232e37706328d199c6d2c13f5398a0du128, second_value : 0x0c3b0d703c754ef6u128},
                                GF192 {first_value : 0x7a5542ab0058d22edd20747cbd2bf75du128, second_value : 0x45ec519c94bc1251u128},
                                GF192 {first_value : 0x08168cb767debe84d8d50ce28ace2bf8u128, second_value : 0xd67d146a4ba67045u128},
                                GF192 {first_value : 0xf3eaf7ae5fd72048970f9c76eed5e1bau128, second_value : 0x29a6bd5f696cea43u128},
                                GF192 {first_value : 0x6019fd623906e9d3f5945dc265068571u128, second_value : 0xc77c56540f87c4b0u128},];
    
    fn add(left: &Self, right : &Self) -> Self {
        //How to do the carry without side-attack friendly if-statement
        let a = left.first_value;
        let b = right.first_value;
        let la = a & (1u128 << 127);
        let lb = b & (1u128 << 127);
        let c = la & lb;
        let ct = la | lb;
        let pre_res = (a & (u128::MAX >> 1))+(b & (u128::MAX >> 1));
        let cp = ((1 - c) * ct) * (pre_res & (1u128 << 127));
        let res_first = c*pre_res + ((1u128 - c) * cp) * (pre_res & (u128::MAX >> 1)) + ((1u128 - c) * (1u128 - cp)) * pre_res;
        let res_second = (left.second_value + right.second_value + (c|cp)) & (u64::MAX as u128);
        return Self::new(res_first, res_second);
    }

    fn new(first_value: u128, second_value: u128) -> Self {
        return GF192 {first_value : first_value, second_value : second_value};
    }

    fn get_value(&self) -> (u128, u128) {
        return (self.first_value, self.second_value);
    }

    fn rand() -> Self {
        return GF192 {first_value : random(), second_value : random::<u128>() & (u64::MAX as u128)};
    }

    fn switch_left(self, int : u32) -> Self {
        let (first_value, second_value) = self.get_value();
        let carry = self.first_value & (u128::MAX << (128 - int));
        return Self::new(first_value << int, ((second_value << int) | carry) & u64::MAX as u128);
    }

}


#[derive(Clone, Copy, Debug, PartialEq)]
struct GF256{
    first_value : u128,
    second_value : u128
}

impl BigGalloisField for GF256 {
    
    const LENGTH : u32 = 256u32;

    const MODULUS : Self = GF256{ first_value : 0b10000100101u128, second_value : 0u128};
    
    const ONE : Self = GF256{ first_value : 1u128, second_value : 0u128};

    const MAX : Self = GF256{ first_value : u128::MAX, second_value : u128::MAX};

    const ALPHA : [Self; 7] =  [GF256{ first_value : 0xbed68d38a0474e67969788420bdefee7u128, second_value : 0x04c9a8cf20c95833df229845f8f1e16au128},
                                GF256{ first_value : 0x2ba5c48d2c42072fa95af52ad52289c1u128, second_value : 0x064e4d699c5b4af1d14a0d376c00b0eau128},
                                GF256{ first_value : 0x1771831e533b0f5755dab3833f809d1du128, second_value : 0x6195e3db7011f68dfb96573fad3fac10u128},
                                GF256{ first_value : 0x752758911a30e3f6de010519b01bcdd5u128, second_value : 0x56c24fd64f7688382a0778b6489ea03fu128},
                                GF256{ first_value : 0x1bc4dbd440f1848298c2f529e98a30b6u128, second_value : 0x22270b6d71574ffc2fbe09947d49a981u128},
                                GF256{ first_value : 0xaced66c666f1afbc9e75afb9de44670bu128, second_value : 0xc03d372fd1fa29f3f001253ff2991f7eu128},
                                GF256{ first_value : 0x5237c4d625b86f0dba43b698b332e88bu128, second_value : 0x133eea09d26b7bb82f652b2af4e81545u128}];
                               
    fn new(first_value: u128, second_value: u128) -> Self {
        return GF256 {first_value : first_value, second_value : second_value};
    }

    fn get_value(&self) -> (u128, u128) {
       return (self.first_value, self.second_value);
    }

    fn rand() -> Self {
        return Self::new(random(), random());
    }

    fn add(left: &Self, right : &Self) -> Self {
        //How to do the carry without side-attack friendly if-statement
        let a = left.first_value;
        let b = right.first_value;
        let la = a & (1u128 << 127);
        let lb = b & (1u128 << 127);
        let c = la & lb;
        let ct = la | lb;
        let pre_res = (a & (u128::MAX >> 1))+(b & (u128::MAX >> 1));
        let cp = ((1 - c) * ct) * (pre_res & (1u128 << 127));
        let res_first = c*pre_res + ((1u128 - c) * cp) * (pre_res & (u128::MAX >> 1)) + ((1u128 - c) * (1u128 - cp)) * pre_res;
        let res_second = left.second_value + right.second_value + (c|cp);
        return Self::new(res_first, res_second);
    }
    
    fn switch_left(self, int : u32) -> Self {
        let (first_value, second_value) = self.get_value();
        let carry = self.first_value & (u128::MAX << (128 - int));
        return Self::new(first_value << int, (second_value << int) | carry);
    }
  

}