/// Implementation of the binary fields with 128, 192 and 256 bit based on SSE2/AVX2 and the clmul instruction

#[cfg(target_arch = "x86")]
use std::arch::x86 as x86_64;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use x86_64::{
    __m128i, __m256i, _mm256_and_si256, _mm256_blend_epi32, _mm256_blendv_epi8,
    _mm256_castsi128_si256, _mm256_extracti128_si256, _mm256_inserti128_si256, _mm256_loadu_si256,
    _mm256_maskload_epi64, _mm256_maskstore_epi64, _mm256_or_si256, _mm256_permute4x64_epi64,
    _mm256_permutevar8x32_epi32, _mm256_set1_epi32, _mm256_set1_epi64x, _mm256_setr_epi64x,
    _mm256_setzero_si256, _mm256_slli_epi64, _mm256_srai_epi32, _mm256_srli_epi64,
    _mm256_storeu_si256, _mm256_testz_si256, _mm256_xor_si256, _mm_alignr_epi8, _mm_and_si128,
    _mm_andnot_si128, _mm_bslli_si128, _mm_clmulepi64_si128, _mm_loadu_si128, _mm_or_si128,
    _mm_set1_epi8, _mm_set_epi64x, _mm_set_epi8, _mm_setr_epi32, _mm_setr_epi8, _mm_setzero_si128,
    _mm_shuffle_epi32, _mm_shuffle_epi8, _mm_slli_epi32, _mm_slli_epi64, _mm_slli_si128,
    _mm_srli_epi32, _mm_srli_epi64, _mm_srli_si128, _mm_storeu_si128, _mm_test_all_zeros,
    _mm_xor_si128,
};

use generic_array::{
    typenum::{Unsigned, U16, U24, U32},
    GenericArray,
};

use super::{
    large_fields::{
        Alphas, Modulus, GF128 as UnoptimizedGF128, GF192 as UnoptimizedGF192,
        GF256 as UnoptimizedGF256,
    },
    BigGaloisField, ByteCombine, ByteCombineConstants, Double, Field, Square, GF64,
};

#[allow(non_snake_case)]
const fn _MM_SHUFFLE(z: u32, y: u32, x: u32, w: u32) -> i32 {
    ((z << 6) | (y << 4) | (x << 2) | w) as i32
}

#[inline(always)]
unsafe fn m128_clmul_ll(x: __m128i, y: __m128i) -> __m128i {
    _mm_clmulepi64_si128(x, y, 0x00)
}

#[inline(always)]
unsafe fn m128_clmul_lh(x: __m128i, y: __m128i) -> __m128i {
    _mm_clmulepi64_si128(x, y, 0x10)
}

#[inline(always)]
unsafe fn m128_clmul_hh(x: __m128i, y: __m128i) -> __m128i {
    _mm_clmulepi64_si128(x, y, 0x11)
}

#[inline(always)]
unsafe fn m256_shift_left_1(x: __m256i) -> __m256i {
    _mm256_or_si256(
        _mm256_slli_epi64(x, 1),
        _mm256_blend_epi32(
            _mm256_setzero_si256(),
            _mm256_permute4x64_epi64(_mm256_srli_epi64(x, 63), _MM_SHUFFLE(2, 1, 0, 0)),
            _MM_SHUFFLE(3, 3, 3, 0),
        ),
    )
}

// Karatsuba multiplication, but end right after the multiplications
unsafe fn karatsuba_mul_128_uninterpolated_other_sum(
    x: __m128i,
    y: __m128i,
    x_for_sum: __m128i,
    y_for_sum: __m128i,
) -> [__m128i; 3] {
    let x0y0 = m128_clmul_ll(x, y);
    let x1y1 = m128_clmul_hh(x, y);
    let x1_cat_y0 = _mm_alignr_epi8(y_for_sum, x_for_sum, 8);
    let xsum = _mm_xor_si128(x_for_sum, x1_cat_y0); // Result in low.
    let ysum = _mm_xor_si128(y_for_sum, x1_cat_y0); // Result in high.
    let xsum_ysum = m128_clmul_lh(xsum, ysum);

    [x0y0, xsum_ysum, x1y1]
}

unsafe fn karatsuba_mul_128_uninterpolated(x: __m128i, y: __m128i) -> [__m128i; 3] {
    let x0y0 = m128_clmul_ll(x, y);
    let x1y1 = m128_clmul_hh(x, y);
    let x1_cat_y0 = _mm_alignr_epi8(y, x, 8);
    let xsum = _mm_xor_si128(x, x1_cat_y0); // Result in low.
    let ysum = _mm_xor_si128(y, x1_cat_y0); // Result in high.
    let xsum_ysum = m128_clmul_lh(xsum, ysum);

    [x0y0, xsum_ysum, x1y1]
}

// Karatsuba multiplication, but don't combine the 3 128-bit polynomials into a 256-bit polynomial.
#[inline(always)]
unsafe fn karatsuba_mul_128_uncombined(x: __m128i, y: __m128i) -> [__m128i; 3] {
    let mut out = karatsuba_mul_128_uninterpolated(x, y);
    out[1] = _mm_xor_si128(_mm_xor_si128(out[0], out[2]), out[1]);
    out
}

unsafe fn karatsuba_square_128_uninterpolated_other_sum(
    x: __m128i,
    x_for_sum: __m128i,
) -> [__m128i; 3] {
    let x0y0 = m128_clmul_ll(x, x);
    let x1y1 = m128_clmul_hh(x, x);
    let x1_cat_y0 = _mm_alignr_epi8(x_for_sum, x_for_sum, 8);
    let xsum = _mm_xor_si128(x_for_sum, x1_cat_y0); // Result in low.
    let xsum_ysum = m128_clmul_lh(xsum, xsum);

    [x0y0, xsum_ysum, x1y1]
}

unsafe fn karatsuba_square_128_uninterpolated(x: __m128i) -> [__m128i; 3] {
    let x0y0 = m128_clmul_ll(x, x);
    let x1y1 = m128_clmul_hh(x, x);
    let x1_cat_y0 = _mm_alignr_epi8(x, x, 8);
    let xsum = _mm_xor_si128(x, x1_cat_y0); // Result in low.
    let xsum_ysum = m128_clmul_lh(xsum, xsum);

    [x0y0, xsum_ysum, x1y1]
}

#[inline(always)]
unsafe fn karatsuba_square_128_uncombined(x: __m128i) -> [__m128i; 3] {
    let mut out = karatsuba_square_128_uninterpolated(x);
    out[1] = _mm_xor_si128(_mm_xor_si128(out[0], out[2]), out[1]);
    out
}

#[inline]
unsafe fn combine_poly128s_3(v: [__m128i; 3]) -> [__m128i; 2] {
    [
        _mm_xor_si128(v[0], _mm_slli_si128(v[1], 8)),
        _mm_xor_si128(v[2], _mm_srli_si128(v[1], 8)),
    ]
}

#[inline]
unsafe fn combine_poly128s_5(v: [__m128i; 5]) -> [__m128i; 3] {
    [
        _mm_xor_si128(v[0], _mm_slli_si128(v[1], 8)),
        _mm_xor_si128(v[2], _mm_alignr_epi8(v[3], v[1], 8)),
        _mm_xor_si128(v[4], _mm_srli_si128(v[3], 8)),
    ]
}

#[inline]
unsafe fn combine_poly128s_7(v: [__m128i; 7]) -> [__m128i; 4] {
    [
        _mm_xor_si128(v[0], _mm_slli_si128(v[1], 8)),
        _mm_xor_si128(v[2], _mm_alignr_epi8(v[3], v[1], 8)),
        _mm_xor_si128(v[4], _mm_alignr_epi8(v[5], v[3], 8)),
        _mm_xor_si128(v[6], _mm_srli_si128(v[5], 8)),
    ]
}

#[inline]
unsafe fn combine_poly128s_4(v: [__m128i; 4]) -> [__m128i; 3] {
    [
        _mm_xor_si128(v[0], _mm_slli_si128(v[1], 8)),
        _mm_xor_si128(v[2], _mm_alignr_epi8(v[3], v[1], 8)),
        _mm_srli_si128(v[3], 8),
    ]
}

/// Helper to convert values to `__m128i`
union GF128ConstHelper {
    a: __m128i,
    b: u128,
    c: [u64; 2],
}

const fn u64_as_m128(v: u64) -> __m128i {
    unsafe { GF128ConstHelper { c: [v, 0] }.a }
}

const fn u128_as_m128(v: u128) -> __m128i {
    unsafe { GF128ConstHelper { b: v }.a }
}

const fn gfu128_as_m128(v: UnoptimizedGF128) -> __m128i {
    u128_as_m128(v.0[0])
}

/// Helper to convert values to `__m256i`
union GF256ConstHelper {
    a: __m256i,
    b: [u128; 2],
    c: [u64; 4],
}

const fn u64_as_m256(v: u64) -> __m256i {
    unsafe { GF256ConstHelper { c: [v, 0, 0, 0] }.a }
}

const fn u128_as_m256(v: [u128; 2]) -> __m256i {
    unsafe { GF256ConstHelper { b: v }.a }
}

const fn gfu192_as_m256(v: UnoptimizedGF192) -> __m256i {
    u128_as_m256(v.0)
}

const fn gfu256_as_m256(v: UnoptimizedGF256) -> __m256i {
    u128_as_m256(v.0)
}

/// Optimized implementation of the 128 bit Galois field
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub(crate) struct GF128(__m128i);

impl Default for GF128 {
    fn default() -> Self {
        Self(unsafe { _mm_setzero_si128() })
    }
}

impl PartialEq for GF128 {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            let tmp = _mm_xor_si128(self.0, other.0);
            _mm_test_all_zeros(tmp, tmp) == 1
        }
    }
}

impl Eq for GF128 {}

// implementations of Add and AddAssign

impl Add for GF128 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm_xor_si128(self.0, rhs.0) })
    }
}

impl Add<&Self> for GF128 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(unsafe { _mm_xor_si128(self.0, rhs.0) })
    }
}

impl Add<GF128> for &GF128 {
    type Output = GF128;

    #[inline(always)]
    fn add(self, rhs: GF128) -> Self::Output {
        GF128(unsafe { _mm_xor_si128(self.0, rhs.0) })
    }
}

impl AddAssign for GF128 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 = unsafe { _mm_xor_si128(self.0, rhs.0) };
    }
}

impl AddAssign<&Self> for GF128 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: &Self) {
        self.0 = unsafe { _mm_xor_si128(self.0, rhs.0) };
    }
}

// implementations of Sub and SubAssign

impl Sub for GF128 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm_xor_si128(self.0, rhs.0) })
    }
}

impl Sub<&Self> for GF128 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(unsafe { _mm_xor_si128(self.0, rhs.0) })
    }
}

impl Sub<GF128> for &GF128 {
    type Output = GF128;

    #[inline(always)]
    fn sub(self, rhs: GF128) -> Self::Output {
        GF128(unsafe { _mm_xor_si128(self.0, rhs.0) })
    }
}

impl SubAssign for GF128 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = unsafe { _mm_xor_si128(self.0, rhs.0) };
    }
}

impl SubAssign<&Self> for GF128 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 = unsafe { _mm_xor_si128(self.0, rhs.0) };
    }
}

// implementation of Neg

impl Neg for GF128 {
    type Output = Self;

    #[inline(always)]
    fn neg(self) -> Self::Output {
        self
    }
}

// implementation of Mul and MulAssign

fn mul_gf128(lhs: __m128i, rhs: __m128i) -> __m128i {
    unsafe {
        let mask = _mm_setr_epi32(-1, 0x0, 0x0, 0x0);
        let tmp3 = m128_clmul_ll(lhs, rhs);
        let tmp6 = m128_clmul_hh(lhs, rhs);
        let tmp4 = _mm_shuffle_epi32(lhs, 78);
        let tmp5 = _mm_shuffle_epi32(rhs, 78);
        let tmp4 = _mm_xor_si128(tmp4, lhs);
        let tmp5 = _mm_xor_si128(tmp5, rhs);
        let tmp4 = m128_clmul_ll(tmp4, tmp5);
        let tmp4 = _mm_xor_si128(tmp4, tmp3);
        let tmp4 = _mm_xor_si128(tmp4, tmp6);
        let tmp5 = _mm_slli_si128(tmp4, 8);
        let tmp4 = _mm_srli_si128(tmp4, 8);
        let tmp3 = _mm_xor_si128(tmp3, tmp5);
        let tmp6 = _mm_xor_si128(tmp6, tmp4);
        let tmp7 = _mm_srli_epi32(tmp6, 31);
        let tmp8 = _mm_srli_epi32(tmp6, 30);
        let tmp9 = _mm_srli_epi32(tmp6, 25);
        let tmp7 = _mm_xor_si128(tmp7, tmp8);
        let tmp7 = _mm_xor_si128(tmp7, tmp9);
        let tmp8 = _mm_shuffle_epi32(tmp7, 147);
        let tmp7 = _mm_and_si128(mask, tmp8);
        let tmp8 = _mm_andnot_si128(mask, tmp8);
        let tmp3 = _mm_xor_si128(tmp3, tmp8);
        let tmp6 = _mm_xor_si128(tmp6, tmp7);
        let tmp10 = _mm_slli_epi32(tmp6, 1);
        let tmp3 = _mm_xor_si128(tmp3, tmp10);
        let tmp11 = _mm_slli_epi32(tmp6, 2);
        let tmp3 = _mm_xor_si128(tmp3, tmp11);
        let tmp12 = _mm_slli_epi32(tmp6, 7);
        let tmp3 = _mm_xor_si128(tmp3, tmp12);
        _mm_xor_si128(tmp3, tmp6)
    }
}

fn mul_gf128_u64(lhs: __m128i, rhs: u64) -> __m128i {
    unsafe {
        let mask = _mm_setr_epi32(-1, 0x0, 0x0, 0x0);
        let rhs = _mm_set_epi64x(0, rhs as i64);
        let tmp3 = m128_clmul_ll(lhs, rhs);
        let tmp4 = _mm_shuffle_epi32(lhs, 78);
        let tmp5 = _mm_shuffle_epi32(rhs, 78);
        let tmp4 = _mm_xor_si128(tmp4, lhs);
        let tmp5 = _mm_xor_si128(tmp5, rhs);
        let tmp4 = m128_clmul_ll(tmp4, tmp5);
        let tmp4 = _mm_xor_si128(tmp4, tmp3);
        let tmp5 = _mm_slli_si128(tmp4, 8);
        let tmp4 = _mm_srli_si128(tmp4, 8);
        let tmp3 = _mm_xor_si128(tmp3, tmp5);
        let tmp7 = _mm_srli_epi32(tmp4, 31);
        let tmp8 = _mm_srli_epi32(tmp4, 30);
        let tmp9 = _mm_srli_epi32(tmp4, 25);
        let tmp7 = _mm_xor_si128(tmp7, tmp8);
        let tmp7 = _mm_xor_si128(tmp7, tmp9);
        let tmp8 = _mm_shuffle_epi32(tmp7, 147);
        let tmp7 = _mm_and_si128(mask, tmp8);
        let tmp8 = _mm_andnot_si128(mask, tmp8);
        let tmp3 = _mm_xor_si128(tmp3, tmp8);
        let tmp6 = _mm_xor_si128(tmp4, tmp7);
        let tmp10 = _mm_slli_epi32(tmp6, 1);
        let tmp3 = _mm_xor_si128(tmp3, tmp10);
        let tmp11 = _mm_slli_epi32(tmp6, 2);
        let tmp3 = _mm_xor_si128(tmp3, tmp11);
        let tmp12 = _mm_slli_epi32(tmp6, 7);
        let tmp3 = _mm_xor_si128(tmp3, tmp12);
        _mm_xor_si128(tmp3, tmp6)
    }
}

impl Mul for GF128 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(mul_gf128(self.0, rhs.0))
    }
}

impl Mul<&Self> for GF128 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(mul_gf128(self.0, rhs.0))
    }
}

impl Mul<GF128> for &GF128 {
    type Output = GF128;

    #[inline(always)]
    fn mul(self, rhs: GF128) -> Self::Output {
        GF128(mul_gf128(self.0, rhs.0))
    }
}

impl Mul<GF64> for GF128 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: GF64) -> Self::Output {
        Self(mul_gf128_u64(self.0, rhs.into()))
    }
}

impl Mul<u8> for GF128 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: u8) -> Self::Output {
        let mask = -((rhs & 1) as i64);
        Self(unsafe {
            let mask = _mm_set_epi64x(mask, mask);
            _mm_and_si128(self.0, mask)
        })
    }
}

impl MulAssign for GF128 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = mul_gf128(self.0, rhs.0);
    }
}

impl MulAssign<&Self> for GF128 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: &Self) {
        self.0 = mul_gf128(self.0, rhs.0);
    }
}

unsafe fn mm128_apply_mask_msb(v: __m128i, m: __m128i) -> __m128i {
    // extract MSB
    let mask = _mm_setr_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i8::MIN);
    let m = _mm_and_si128(m, mask);
    // move MSB to each 1-byte lane
    let m = _mm_shuffle_epi8(m, _mm_set1_epi8(15));
    // if MSB is set, produce index, otherwise keep MSB set to zero result
    let m = _mm_andnot_si128(
        m,
        _mm_set_epi8(
            15 | i8::MIN,
            14 | i8::MIN,
            13 | i8::MIN,
            12 | i8::MIN,
            11 | i8::MIN,
            10 | i8::MIN,
            9 | i8::MIN,
            8 | i8::MIN,
            7 | i8::MIN,
            6 | i8::MIN,
            5 | i8::MIN,
            4 | i8::MIN,
            3 | i8::MIN,
            2 | i8::MIN,
            1 | i8::MIN,
            i8::MIN,
        ),
    );
    _mm_shuffle_epi8(v, m)
}

// implementation of Double

const GF128_MODULUS: __m128i = u128_as_m128(UnoptimizedGF128::MODULUS);

impl Double for GF128 {
    type Output = Self;

    #[inline]
    fn double(self) -> Self::Output {
        Self(unsafe {
            let shifted = _mm_or_si128(
                _mm_slli_epi64(self.0, 1),
                _mm_srli_epi64(_mm_bslli_si128(self.0, 8), 63),
            );
            _mm_xor_si128(shifted, mm128_apply_mask_msb(GF128_MODULUS, self.0))
        })
    }
}

// implementation of Square

impl Square for GF128 {
    type Output = Self;

    #[inline]
    fn square(self) -> Self::Output {
        Self(mul_gf128(self.0, self.0))
    }
}

impl Field for GF128 {
    const ZERO: Self = Self(u64_as_m128(0));
    const ONE: Self = Self(u64_as_m128(1));

    type Length = U16;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        let mut ret = GenericArray::<u8, Self::Length>::default();
        unsafe { _mm_storeu_si128(ret.as_mut_ptr().cast(), self.0) };
        ret
    }
}

impl From<&[u8]> for GF128 {
    fn from(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), <Self as Field>::Length::USIZE);
        Self(unsafe { _mm_loadu_si128(value.as_ptr().cast()) })
    }
}

// implementation of ByteCombine

impl Alphas for GF128 {
    const ALPHA: [Self; 7] = [
        Self(gfu128_as_m128(UnoptimizedGF128::ALPHA[0])),
        Self(gfu128_as_m128(UnoptimizedGF128::ALPHA[1])),
        Self(gfu128_as_m128(UnoptimizedGF128::ALPHA[2])),
        Self(gfu128_as_m128(UnoptimizedGF128::ALPHA[3])),
        Self(gfu128_as_m128(UnoptimizedGF128::ALPHA[4])),
        Self(gfu128_as_m128(UnoptimizedGF128::ALPHA[5])),
        Self(gfu128_as_m128(UnoptimizedGF128::ALPHA[6])),
    ];
}

impl ByteCombineConstants for GF128 {
    const BYTE_COMBINE_2: Self = Self(gfu128_as_m128(UnoptimizedGF128::BYTE_COMBINE_2));
    const BYTE_COMBINE_3: Self = Self(gfu128_as_m128(UnoptimizedGF128::BYTE_COMBINE_3));
}

impl ByteCombine for GF128 {
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
        Self::ALPHA
            .iter()
            .enumerate()
            .fold(Self::ONE * x, |sum, (index, alpha)| {
                sum + (*alpha * (x >> (index + 1)))
            })
    }
}

impl BigGaloisField for GF128 {}

#[cfg(test)]
impl serde::Serialize for GF128 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_bytes().serialize(serializer)
    }
}

#[cfg(test)]
impl<'de> serde::Deserialize<'de> for GF128 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <[u8; <Self as Field>::Length::USIZE]>::deserialize(deserializer)
            .map(|buffer| Self::from(buffer.as_slice()))
    }
}

/// Optimized implementation of the 192 bit Galois field
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub(crate) struct GF192(__m256i);

impl Default for GF192 {
    fn default() -> Self {
        Self(unsafe { _mm256_setzero_si256() })
    }
}

impl PartialEq for GF192 {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            let tmp = _mm256_xor_si256(self.0, other.0);
            _mm256_testz_si256(tmp, tmp) == 1
        }
    }
}

impl Eq for GF192 {}

// implementations of Add and AddAssign

impl Add for GF192 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl Add<&Self> for GF192 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl Add<GF192> for &GF192 {
    type Output = GF192;

    #[inline(always)]
    fn add(self, rhs: GF192) -> Self::Output {
        GF192(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl AddAssign for GF192 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
    }
}

impl AddAssign<&Self> for GF192 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: &Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
    }
}

// implementations of Sub and SubAssign

impl Sub for GF192 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl Sub<&Self> for GF192 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl Sub<GF192> for &GF192 {
    type Output = GF192;

    #[inline(always)]
    fn sub(self, rhs: GF192) -> Self::Output {
        GF192(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl SubAssign for GF192 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
    }
}

impl SubAssign<&Self> for GF192 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
    }
}

// implementation of Neg

impl Neg for GF192 {
    type Output = Self;

    #[inline(always)]
    fn neg(self) -> Self::Output {
        self
    }
}

// implementation of Mul and MulAssign

const GF192_MOD_M128: __m128i = u128_as_m128(UnoptimizedGF192::MODULUS);

unsafe fn poly384_reduce192(x: [__m128i; 3]) -> __m256i {
    let reduced_320 = m128_clmul_lh(GF192_MOD_M128, x[2]);
    let reduced_256 = m128_clmul_ll(GF192_MOD_M128, x[2]);

    let mut combined = [
        _mm_xor_si128(x[0], _mm_slli_si128(reduced_256, 8)),
        _mm_xor_si128(x[1], reduced_320),
    ];
    combined[0] = _mm_xor_si128(combined[0], m128_clmul_lh(GF192_MOD_M128, combined[1]));
    combined[1] = _mm_xor_si128(combined[1], _mm_srli_si128(reduced_256, 8));

    _mm256_inserti128_si256(
        _mm256_castsi128_si256(combined[0]),
        _mm_and_si128(combined[1], _mm_set_epi64x(0, -1)),
        1,
    )
}

unsafe fn poly256_reduce192(x: [__m128i; 2]) -> __m256i {
    let low = _mm_xor_si128(x[0], m128_clmul_lh(GF192_MOD_M128, x[1]));
    _mm256_inserti128_si256(
        _mm256_castsi128_si256(low),
        _mm_and_si128(x[1], _mm_set_epi64x(0, -1)),
        1,
    )
}

unsafe fn m128_broadcast_low(v: __m128i) -> __m128i {
    _mm_xor_si128(v, _mm_bslli_si128(v, 8))
}

fn mul_gf192(lhs: __m256i, rhs: __m256i) -> __m256i {
    unsafe {
        let x0 = _mm256_extracti128_si256(lhs, 0);
        let x1 = _mm256_extracti128_si256(lhs, 1);
        let y0 = _mm256_extracti128_si256(rhs, 0);
        let y1 = _mm256_extracti128_si256(rhs, 1);

        let xlow_ylow = m128_clmul_ll(x0, y0);
        let xhigh_yhigh = m128_clmul_ll(x1, y1);

        let x1_cat_y0_plus_y2 = _mm_alignr_epi8(_mm_xor_si128(y0, y1), x0, 8);
        let xsum = _mm_xor_si128(_mm_xor_si128(x0, x1), x1_cat_y0_plus_y2); // Result in low.
        let ysum = _mm_xor_si128(y0, x1_cat_y0_plus_y2); // Result in high.
        let xsum_ysum = m128_clmul_lh(xsum, ysum);

        let m = _mm_set_epi64x(0, -1);
        let xa = _mm_xor_si128(x0, m128_broadcast_low(_mm_and_si128(x1, m)));
        let ya = _mm_xor_si128(y0, m128_broadcast_low(_mm_and_si128(y1, m)));
        // Karatsuba multiplication of two degree 1 polynomials (with deg <64 polynomial coefficients).
        let karatsuba_out = karatsuba_mul_128_uninterpolated_other_sum(xa, ya, x0, y0);
        let xya0 = _mm_xor_si128(karatsuba_out[0], karatsuba_out[2]);
        let xya1 = _mm_xor_si128(karatsuba_out[0], karatsuba_out[1]);

        let xya0_plus_xsum_ysum = _mm_xor_si128(xya0, xsum_ysum);
        let combined = [
            xlow_ylow,
            _mm_xor_si128(xya0_plus_xsum_ysum, xhigh_yhigh),
            _mm_xor_si128(xya0_plus_xsum_ysum, xya1),
            _mm_xor_si128(_mm_xor_si128(xlow_ylow, xsum_ysum), xya1),
            xhigh_yhigh,
        ];
        poly384_reduce192(combine_poly128s_5(combined))
    }
}

fn square_gf192(lhs: __m256i) -> __m256i {
    unsafe {
        let x0 = _mm256_extracti128_si256(lhs, 0);
        let x1 = _mm256_extracti128_si256(lhs, 1);

        let xlow_ylow = m128_clmul_ll(x0, x0);
        let xhigh_yhigh = m128_clmul_ll(x1, x1);

        let x0x1 = _mm_xor_si128(x0, x1);
        let x1_cat_y0_plus_y2 = _mm_alignr_epi8(x0x1, x0, 8);
        let xsum = _mm_xor_si128(x0x1, x1_cat_y0_plus_y2); // Result in low.
        let ysum = _mm_xor_si128(x0, x1_cat_y0_plus_y2); // Result in high.
        let xsum_ysum = m128_clmul_lh(xsum, ysum);

        let m = _mm_set_epi64x(0, -1);
        let xa = _mm_xor_si128(x0, m128_broadcast_low(_mm_and_si128(x1, m)));
        // Karatsuba multiplication of two degree 1 polynomials (with deg <64 polynomial coefficients).
        let karatsuba_out = karatsuba_square_128_uninterpolated_other_sum(xa, x0);
        let xya0 = _mm_xor_si128(karatsuba_out[0], karatsuba_out[2]);
        let xya1 = _mm_xor_si128(karatsuba_out[0], karatsuba_out[1]);

        let xya0_plus_xsum_ysum = _mm_xor_si128(xya0, xsum_ysum);
        let combined = [
            xlow_ylow,
            _mm_xor_si128(xya0_plus_xsum_ysum, xhigh_yhigh),
            _mm_xor_si128(xya0_plus_xsum_ysum, xya1),
            _mm_xor_si128(_mm_xor_si128(xlow_ylow, xsum_ysum), xya1),
            xhigh_yhigh,
        ];
        poly384_reduce192(combine_poly128s_5(combined))
    }
}

fn mul_gf192_u64(lhs: __m256i, rhs: u64) -> __m256i {
    unsafe {
        let rhs = _mm_set_epi64x(0, rhs as i64);
        let x0 = _mm256_extracti128_si256(lhs, 0);
        let x1 = _mm256_extracti128_si256(lhs, 1);
        let xy = [
            m128_clmul_ll(rhs, x0),
            m128_clmul_lh(rhs, x0),
            m128_clmul_ll(rhs, x1),
        ];
        poly256_reduce192(combine_poly128s_3(xy))
    }
}

impl Mul for GF192 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(mul_gf192(self.0, rhs.0))
    }
}

impl Mul<&Self> for GF192 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(mul_gf192(self.0, rhs.0))
    }
}

impl Mul<GF192> for &GF192 {
    type Output = GF192;

    #[inline(always)]
    fn mul(self, rhs: GF192) -> Self::Output {
        GF192(mul_gf192(self.0, rhs.0))
    }
}

impl Mul<GF64> for GF192 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: GF64) -> Self::Output {
        Self(mul_gf192_u64(self.0, rhs.into()))
    }
}

impl Mul<u8> for GF192 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: u8) -> Self::Output {
        let mask = -((rhs & 1) as i64);
        Self(unsafe {
            let mask = _mm256_set1_epi64x(mask);
            _mm256_and_si256(self.0, mask)
        })
    }
}

impl MulAssign for GF192 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = mul_gf192(self.0, rhs.0);
    }
}

impl MulAssign<&Self> for GF192 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: &Self) {
        self.0 = mul_gf192(self.0, rhs.0);
    }
}

// implementation of Double

unsafe fn mm192_apply_mask_msb(v: __m256i, m: __m256i) -> __m256i {
    let mask = _mm256_setr_epi64x(0, 0, i64::MIN, 0);
    let m = _mm256_and_si256(m, mask);
    let m = _mm256_srai_epi32(m, 32);
    let m = _mm256_permutevar8x32_epi32(m, _mm256_set1_epi32(5));
    _mm256_blendv_epi8(_mm256_setzero_si256(), v, m)
}

const GF192_MODULUS: __m256i = u128_as_m256([UnoptimizedGF192::MODULUS, 0]);

impl Double for GF192 {
    type Output = Self;

    #[inline]
    fn double(self) -> Self::Output {
        Self(unsafe {
            let shifted = m256_shift_left_1(self.0);
            _mm256_and_si256(
                _mm256_xor_si256(shifted, mm192_apply_mask_msb(GF192_MODULUS, self.0)),
                _mm256_setr_epi64x(-1, -1, -1, 0),
            )
        })
    }
}

// implementation of Square

impl Square for GF192 {
    type Output = Self;

    #[inline]
    fn square(self) -> Self::Output {
        Self(square_gf192(self.0))
    }
}

impl Field for GF192 {
    const ZERO: Self = Self(u64_as_m256(0));
    const ONE: Self = Self(u64_as_m256(1));

    type Length = U24;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        let mut ret = GenericArray::<u8, Self::Length>::default();
        unsafe {
            _mm256_maskstore_epi64(
                ret.as_mut_ptr().cast(),
                _mm256_setr_epi64x(i64::MIN, i64::MIN, i64::MIN, 0),
                self.0,
            )
        };
        ret
    }
}

impl From<&[u8]> for GF192 {
    fn from(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), <Self as Field>::Length::USIZE);
        Self(unsafe {
            _mm256_maskload_epi64(
                value.as_ptr().cast(),
                _mm256_setr_epi64x(i64::MIN, i64::MIN, i64::MIN, 0),
            )
        })
    }
}

// implementation of ByteCombine

impl Alphas for GF192 {
    const ALPHA: [Self; 7] = [
        Self(gfu192_as_m256(UnoptimizedGF192::ALPHA[0])),
        Self(gfu192_as_m256(UnoptimizedGF192::ALPHA[1])),
        Self(gfu192_as_m256(UnoptimizedGF192::ALPHA[2])),
        Self(gfu192_as_m256(UnoptimizedGF192::ALPHA[3])),
        Self(gfu192_as_m256(UnoptimizedGF192::ALPHA[4])),
        Self(gfu192_as_m256(UnoptimizedGF192::ALPHA[5])),
        Self(gfu192_as_m256(UnoptimizedGF192::ALPHA[6])),
    ];
}

impl ByteCombineConstants for GF192 {
    const BYTE_COMBINE_2: Self = Self(gfu192_as_m256(UnoptimizedGF192::BYTE_COMBINE_2));
    const BYTE_COMBINE_3: Self = Self(gfu192_as_m256(UnoptimizedGF192::BYTE_COMBINE_3));
}

impl ByteCombine for GF192 {
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
        Self::ALPHA
            .iter()
            .enumerate()
            .fold(Self::ONE * x, |sum, (index, alpha)| {
                sum + (*alpha * (x >> (index + 1)))
            })
    }
}

impl BigGaloisField for GF192 {}

#[cfg(test)]
impl serde::Serialize for GF192 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_bytes().serialize(serializer)
    }
}

#[cfg(test)]
impl<'de> serde::Deserialize<'de> for GF192 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <[u8; <Self as Field>::Length::USIZE]>::deserialize(deserializer)
            .map(|buffer| Self::from(buffer.as_slice()))
    }
}

/// Optimized implementation of the 256 bit Galois field
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub(crate) struct GF256(__m256i);

impl Default for GF256 {
    fn default() -> Self {
        Self(unsafe { _mm256_setzero_si256() })
    }
}

impl PartialEq for GF256 {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            let tmp = _mm256_xor_si256(self.0, other.0);
            _mm256_testz_si256(tmp, tmp) == 1
        }
    }
}

impl Eq for GF256 {}

// implementations of Add and AddAssign

impl Add for GF256 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl Add<&Self> for GF256 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl Add<GF256> for &GF256 {
    type Output = GF256;

    #[inline(always)]
    fn add(self, rhs: GF256) -> Self::Output {
        GF256(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl AddAssign for GF256 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
    }
}

impl AddAssign<&Self> for GF256 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: &Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
    }
}

// implementations of Sub and SubAssign

impl Sub for GF256 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl Sub<&Self> for GF256 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl Sub<GF256> for &GF256 {
    type Output = GF256;

    #[inline(always)]
    fn sub(self, rhs: GF256) -> Self::Output {
        GF256(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl SubAssign for GF256 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
    }
}

impl SubAssign<&Self> for GF256 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
    }
}

// implementation of Neg

impl Neg for GF256 {
    type Output = Self;

    #[inline(always)]
    fn neg(self) -> Self::Output {
        self
    }
}

// implementation of Mul and MulAssign

const GF256_MOD_M128: __m128i = u128_as_m128(UnoptimizedGF256::MODULUS);

#[inline]
unsafe fn poly512_reduce256(x: [__m128i; 4]) -> __m256i {
    let xmod = [
        _mm_setzero_si128(),
        m128_clmul_lh(GF256_MOD_M128, x[2]),
        m128_clmul_ll(GF256_MOD_M128, x[3]),
        m128_clmul_lh(GF256_MOD_M128, x[3]),
    ];
    let mut xmod_combined = combine_poly128s_4(xmod);
    xmod_combined[0] = _mm_xor_si128(xmod_combined[0], x[0]);
    xmod_combined[1] = _mm_xor_si128(xmod_combined[1], x[1]);
    xmod_combined[2] = _mm_xor_si128(xmod_combined[2], x[2]);
    xmod_combined[0] = _mm_xor_si128(
        xmod_combined[0],
        m128_clmul_ll(GF256_MOD_M128, xmod_combined[2]),
    );

    _mm256_inserti128_si256(
        _mm256_castsi128_si256(xmod_combined[0]),
        xmod_combined[1],
        1,
    )
}

#[inline]
unsafe fn poly320_reduce256(x: [__m128i; 3]) -> __m256i {
    let tmp = _mm_xor_si128(x[0], m128_clmul_ll(GF256_MOD_M128, x[2]));
    _mm256_inserti128_si256(_mm256_castsi128_si256(tmp), x[1], 1)
}

fn mul_gf256(lhs: __m256i, rhs: __m256i) -> __m256i {
    unsafe {
        let x0 = _mm256_extracti128_si256(lhs, 0);
        let x1 = _mm256_extracti128_si256(lhs, 1);
        let y0 = _mm256_extracti128_si256(rhs, 0);
        let y1 = _mm256_extracti128_si256(rhs, 1);
        let x0y0 = karatsuba_mul_128_uncombined(x0, y0);
        let x1y1 = karatsuba_mul_128_uncombined(x1, y1);
        let xsum_ysum = karatsuba_mul_128_uncombined(_mm_xor_si128(x0, x1), _mm_xor_si128(y0, y1));
        let x0y0_2_plus_x1y1_0 = _mm_xor_si128(x0y0[2], x1y1[0]);
        let combined = [
            x0y0[0],
            x0y0[1],
            _mm_xor_si128(xsum_ysum[0], _mm_xor_si128(x0y0[0], x0y0_2_plus_x1y1_0)),
            _mm_xor_si128(xsum_ysum[1], _mm_xor_si128(x0y0[1], x1y1[1])),
            _mm_xor_si128(xsum_ysum[2], _mm_xor_si128(x1y1[2], x0y0_2_plus_x1y1_0)),
            x1y1[1],
            x1y1[2],
        ];
        poly512_reduce256(combine_poly128s_7(combined))
    }
}

fn square_gf256(lhs: __m256i) -> __m256i {
    unsafe {
        let x0 = _mm256_extracti128_si256(lhs, 0);
        let x1 = _mm256_extracti128_si256(lhs, 1);
        let x0y0 = karatsuba_square_128_uncombined(x0);
        let x1y1 = karatsuba_square_128_uncombined(x1);
        let xsum_ysum = karatsuba_square_128_uncombined(_mm_xor_si128(x0, x1));
        let x0y0_2_plus_x1y1_0 = _mm_xor_si128(x0y0[2], x1y1[0]);
        let combined = [
            x0y0[0],
            x0y0[1],
            _mm_xor_si128(xsum_ysum[0], _mm_xor_si128(x0y0[0], x0y0_2_plus_x1y1_0)),
            _mm_xor_si128(xsum_ysum[1], _mm_xor_si128(x0y0[1], x1y1[1])),
            _mm_xor_si128(xsum_ysum[2], _mm_xor_si128(x1y1[2], x0y0_2_plus_x1y1_0)),
            x1y1[1],
            x1y1[2],
        ];
        poly512_reduce256(combine_poly128s_7(combined))
    }
}

fn mul_gf256_u64(lhs: __m256i, rhs: u64) -> __m256i {
    unsafe {
        let rhs = _mm_set_epi64x(0, rhs as i64);
        let x0 = _mm256_extracti128_si256(lhs, 0);
        let x1 = _mm256_extracti128_si256(lhs, 1);
        let xy = [
            m128_clmul_ll(rhs, x0),
            m128_clmul_lh(rhs, x0),
            m128_clmul_ll(rhs, x1),
            m128_clmul_lh(rhs, x1),
        ];
        poly320_reduce256(combine_poly128s_4(xy))
    }
}

impl Mul for GF256 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(mul_gf256(self.0, rhs.0))
    }
}

impl Mul<&Self> for GF256 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self(mul_gf256(self.0, rhs.0))
    }
}

impl Mul<GF256> for &GF256 {
    type Output = GF256;

    #[inline(always)]
    fn mul(self, rhs: GF256) -> Self::Output {
        GF256(mul_gf256(self.0, rhs.0))
    }
}

impl Mul<GF64> for GF256 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: GF64) -> Self::Output {
        Self(mul_gf256_u64(self.0, rhs.into()))
    }
}

impl Mul<u8> for GF256 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: u8) -> Self::Output {
        let mask = -((rhs & 1) as i64);
        Self(unsafe {
            let mask = _mm256_set1_epi64x(mask);
            _mm256_and_si256(self.0, mask)
        })
    }
}

impl MulAssign for GF256 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = mul_gf256(self.0, rhs.0);
    }
}

impl MulAssign<&Self> for GF256 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: &Self) {
        self.0 = mul_gf256(self.0, rhs.0);
    }
}

// implementation of Double

unsafe fn mm256_apply_mask_msb(v: __m256i, m: __m256i) -> __m256i {
    let mask = _mm256_setr_epi64x(0, 0, 0, i64::MIN);
    let m = _mm256_and_si256(m, mask);
    let m = _mm256_srai_epi32(m, 32);
    let m = _mm256_permutevar8x32_epi32(m, _mm256_set1_epi32(7));
    _mm256_blendv_epi8(_mm256_setzero_si256(), v, m)
}

const GF256_MODULUS: __m256i = u128_as_m256([UnoptimizedGF256::MODULUS, 0]);

impl Double for GF256 {
    type Output = Self;

    #[inline]
    fn double(self) -> Self::Output {
        Self(unsafe {
            let shifted = m256_shift_left_1(self.0);
            _mm256_xor_si256(shifted, mm256_apply_mask_msb(GF256_MODULUS, self.0))
        })
    }
}

// implementation of Square

impl Square for GF256 {
    type Output = Self;

    #[inline]
    fn square(self) -> Self::Output {
        Self(square_gf256(self.0))
    }
}

impl Field for GF256 {
    const ZERO: Self = Self(u64_as_m256(0));
    const ONE: Self = Self(u64_as_m256(1));

    type Length = U32;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        let mut ret = GenericArray::<u8, Self::Length>::default();
        unsafe { _mm256_storeu_si256(ret.as_mut_ptr().cast(), self.0) };
        ret
    }
}

impl From<&[u8]> for GF256 {
    fn from(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), <Self as Field>::Length::USIZE);
        Self(unsafe { _mm256_loadu_si256(value.as_ptr().cast()) })
    }
}

// implementation of ByteCombine

impl Alphas for GF256 {
    const ALPHA: [Self; 7] = [
        Self(gfu256_as_m256(UnoptimizedGF256::ALPHA[0])),
        Self(gfu256_as_m256(UnoptimizedGF256::ALPHA[1])),
        Self(gfu256_as_m256(UnoptimizedGF256::ALPHA[2])),
        Self(gfu256_as_m256(UnoptimizedGF256::ALPHA[3])),
        Self(gfu256_as_m256(UnoptimizedGF256::ALPHA[4])),
        Self(gfu256_as_m256(UnoptimizedGF256::ALPHA[5])),
        Self(gfu256_as_m256(UnoptimizedGF256::ALPHA[6])),
    ];
}

impl ByteCombineConstants for GF256 {
    const BYTE_COMBINE_2: Self = Self(gfu256_as_m256(UnoptimizedGF256::BYTE_COMBINE_2));
    const BYTE_COMBINE_3: Self = Self(gfu256_as_m256(UnoptimizedGF256::BYTE_COMBINE_3));
}

impl ByteCombine for GF256 {
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
        Self::ALPHA
            .iter()
            .enumerate()
            .fold(Self::ONE * x, |sum, (index, alpha)| {
                sum + (*alpha * (x >> (index + 1)))
            })
    }
}

impl BigGaloisField for GF256 {}

#[cfg(test)]
impl serde::Serialize for GF256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_bytes().serialize(serializer)
    }
}

#[cfg(test)]
impl<'de> serde::Deserialize<'de> for GF256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <[u8; <Self as Field>::Length::USIZE]>::deserialize(deserializer)
            .map(|buffer| Self::from(buffer.as_slice()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const RUNS: usize = 100;

    #[generic_tests::define]
    mod field_ops {
        use super::*;

        use std::fmt::Debug;

        use rand::{
            distributions::{Distribution, Standard},
            rngs::SmallRng,
            Rng, RngCore, SeedableRng,
        };

        #[test]
        fn add<Fu, F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<Fu>,
            Fu: BigGaloisField<Length = F::Length> + Debug + Eq,
        {
            let mut rng = SmallRng::from_entropy();

            for _ in 0..RUNS {
                let r1: Fu = rng.gen();
                let r2: Fu = rng.gen();
                let r3 = r1 + r2;

                let v1 = F::from(r1.as_bytes().as_slice());
                let v2 = F::from(r2.as_bytes().as_slice());
                let check_v3 = F::from(r3.as_bytes().as_slice());
                let v3 = v1 + v2;

                assert_eq!(check_v3, v3);
                assert_eq!(v3.as_bytes(), r3.as_bytes());
                assert_eq!(v3 + F::ZERO, v3);

                let mut v1 = v1;
                v1 += v2;
                assert_eq!(v1, v3);
            }
        }

        #[test]
        fn mul<Fu, F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<Fu>,
            Fu: BigGaloisField<Length = F::Length> + Debug + Eq,
        {
            let mut rng = SmallRng::from_entropy();

            for _ in 0..RUNS {
                let r1: Fu = rng.gen();
                let r2: Fu = rng.gen();
                let r3 = r1 * r2;

                let v1 = F::from(r1.as_bytes().as_slice());
                let v2 = F::from(r2.as_bytes().as_slice());
                let check_v3 = F::from(r3.as_bytes().as_slice());
                let v3 = v1 * v2;

                assert_eq!(check_v3, v3);
                assert_eq!(v3.as_bytes(), r3.as_bytes());
                assert_eq!(v3 * F::ZERO, F::ZERO);
                assert_eq!(v3 * F::ONE, v3);

                let mut v1 = v1;
                v1 *= v2;
                assert_eq!(v1, v3);

                assert_eq!(v1 * v1, v1.square());
            }
        }

        #[test]
        fn mul_u64<Fu, F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<Fu>,
            Fu: BigGaloisField<Length = F::Length> + Debug + Eq,
        {
            let mut rng = SmallRng::from_entropy();

            let v: Fu = rng.gen();
            let v = F::from(v.as_bytes().as_slice());
            assert_eq!(v * GF64::ONE, v);

            for _ in 0..RUNS {
                let r1: Fu = rng.gen();
                let r2 = GF64::from(rng.next_u64());
                let r3 = r1 * r2;

                let v1 = F::from(r1.as_bytes().as_slice());
                let check_v3 = F::from(r3.as_bytes().as_slice());
                let v3 = v1 * r2;

                assert_eq!(check_v3, v3);
                assert_eq!(v3.as_bytes(), r3.as_bytes());
            }
        }

        #[test]
        fn mul_u8<Fu, F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<Fu>,
            Fu: BigGaloisField<Length = F::Length> + Debug + Eq,
        {
            let mut rng = SmallRng::from_entropy();

            for _ in 0..RUNS {
                let r1: Fu = rng.gen();
                let r2 = rng.gen::<u8>() & 1;
                let r3 = r1 * r2;

                let v1 = F::from(r1.as_bytes().as_slice());
                let check_v3 = F::from(r3.as_bytes().as_slice());
                let v3 = v1 * r2;

                assert_eq!(check_v3, v3);
                assert_eq!(v3.as_bytes(), r3.as_bytes());
            }
        }

        #[test]
        fn double<Fu, F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<Fu>,
            Fu: BigGaloisField<Length = F::Length> + Debug + Eq,
        {
            let mut rng = SmallRng::from_entropy();

            for _ in 0..RUNS {
                let r1: Fu = rng.gen();
                let r3 = r1.double();

                let v1 = F::from(r1.as_bytes().as_slice());
                let check_v3 = F::from(r3.as_bytes().as_slice());
                let v3 = v1.double();

                assert_eq!(check_v3, v3);
                assert_eq!(v3.as_bytes(), r3.as_bytes());
            }
        }

        #[instantiate_tests(<UnoptimizedGF128, GF128>)]
        mod gf128 {}

        #[instantiate_tests(<UnoptimizedGF192, GF192>)]
        mod gf192 {}

        #[instantiate_tests(<UnoptimizedGF256, GF256>)]
        mod gf256 {}
    }
}
