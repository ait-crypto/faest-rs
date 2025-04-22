/// Implementation of the binary fields with 128, 192 and 256 bit based on SSE2/AVX2 and the clmul instruction

#[cfg(target_arch = "x86")]
use std::arch::x86 as x86_64;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64;
use std::{
    arch::x86_64::{_mm256_set_m128i, _mm_xor_pd},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use x86_64::{
    __m128i, __m256i, _mm256_and_si256, _mm256_blend_epi32, _mm256_blendv_epi8, _mm256_cmpeq_epi32,
    _mm256_extracti128_si256, _mm256_loadu_si256, _mm256_maskload_epi64, _mm256_maskstore_epi64,
    _mm256_or_si256, _mm256_permute4x64_epi64, _mm256_permutevar8x32_epi32, _mm256_set1_epi64x,
    _mm256_setr_epi64x, _mm256_setr_m128i, _mm256_setzero_si256, _mm256_slli_epi32,
    _mm256_slli_epi64, _mm256_srai_epi32, _mm256_srli_epi32, _mm256_srli_epi64,
    _mm256_storeu_si256, _mm256_testz_si256, _mm256_xor_si256, _mm_alignr_epi8, _mm_and_si128,
    _mm_andnot_si128, _mm_bslli_si128, _mm_clmulepi64_si128, _mm_cmpeq_epi32, _mm_loadu_si128,
    _mm_or_si128, _mm_set_epi64x, _mm_set_epi8, _mm_setr_epi32, _mm_setzero_si128,
    _mm_shuffle_epi32, _mm_shuffle_epi8, _mm_slli_epi32, _mm_slli_epi64, _mm_slli_si128,
    _mm_srli_epi32, _mm_srli_epi64, _mm_srli_si128, _mm_storeu_si128, _mm_test_all_zeros,
    _mm_xor_si128,
};

use generic_array::{
    typenum::{Unsigned, U16, U24, U32, U48, U64, U72},
    GenericArray,
};

use super::{
    large_fields::{
        Alphas, Betas, Modulus, SquareBytes, GF128 as UnoptimizedGF128, GF192 as UnoptimizedGF192,
        GF256 as UnoptimizedGF256, GF384 as UnoptimizedGF384, GF576 as UnoptimizedGF576,
        GF768 as UnoptimizedGF768,
    },
    BigGaloisField, ByteCombine, ByteCombineConstants, ByteCombineSquared,
    ByteCombineSquaredConstants, Double, ExtensionField, Field, FromBit, Sigmas, Square, GF64, GF8,
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

#[inline(always)]
unsafe fn m128_setones() -> __m128i {
    let zero = _mm_setzero_si128();
    _mm_cmpeq_epi32(zero, zero)
}

#[inline(always)]
unsafe fn m128_set_epi32_15() -> __m128i {
    _mm_srli_epi32(m128_setones(), 28)
}

#[inline(always)]
unsafe fn m128_set_msb() -> __m128i {
    let all_ones = m128_setones();
    let one = _mm_slli_epi64(all_ones, 63);
    _mm_slli_si128(one, 64 / 8)
}

#[inline(always)]
unsafe fn m256_setones() -> __m256i {
    let zero = _mm256_setzero_si256();
    _mm256_cmpeq_epi32(zero, zero)
}

#[inline(always)]
unsafe fn m256_set_epi32_7() -> __m256i {
    _mm256_srli_epi32(m256_setones(), 29)
}

#[inline(always)]
unsafe fn m256_set_epi32_5() -> __m256i {
    let one = _mm256_srli_epi32(m256_setones(), 31);
    _mm256_xor_si256(one, _mm256_slli_epi32(one, 2))
}

#[inline(always)]
unsafe fn m256_set_msb_192() -> __m256i {
    _mm256_blend_epi32(
        _mm256_setzero_si256(),
        _mm256_slli_epi64(m256_setones(), 63),
        _MM_SHUFFLE(0, 3, 0, 0),
    )
}

#[inline(always)]
unsafe fn m256_set_msb() -> __m256i {
    _mm256_blend_epi32(
        _mm256_setzero_si256(),
        _mm256_slli_epi64(m256_setones(), 63),
        _MM_SHUFFLE(3, 0, 0, 0),
    )
}

// Karatsuba multiplication, but end right after the multiplications
#[inline]
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

#[inline]
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
#[inline]
unsafe fn karatsuba_mul_128_uncombined(x: __m128i, y: __m128i) -> [__m128i; 3] {
    let mut out = karatsuba_mul_128_uninterpolated(x, y);
    out[1] = _mm_xor_si128(_mm_xor_si128(out[0], out[2]), out[1]);
    out
}

#[inline]
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

#[inline]
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
    #[inline(always)]
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

fn square_gf128(lhs: __m128i) -> __m128i {
    unsafe {
        let mask = _mm_setr_epi32(-1, 0x0, 0x0, 0x0);
        let tmp3 = m128_clmul_ll(lhs, lhs);
        let tmp6 = m128_clmul_hh(lhs, lhs);
        let tmp4 = _mm_shuffle_epi32(lhs, 78);
        let tmp4 = _mm_xor_si128(tmp4, lhs);
        let tmp4 = m128_clmul_ll(tmp4, tmp4);
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

#[inline]
unsafe fn m128_apply_mask_msb(v: __m128i, m: __m128i) -> __m128i {
    // extract MSB
    let m = _mm_and_si128(m, m128_set_msb());
    // move MSB to each 1-byte lane
    let m = _mm_shuffle_epi8(m, m128_set_epi32_15());
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
            _mm_xor_si128(shifted, m128_apply_mask_msb(GF128_MODULUS, self.0))
        })
    }
}

// implementation of Square

impl Square for GF128 {
    type Output = Self;

    #[inline]
    fn square(self) -> Self::Output {
        Self(square_gf128(self.0))
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

    fn as_boxed_bytes(&self) -> Box<GenericArray<u8, Self::Length>> {
        let mut ret = GenericArray::<u8, Self::Length>::default_boxed();
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

// Implementation of SquareBytes

impl SquareBytes for GF128 {
    // TODO: Should we define a generic implementation for F: Field in large fields instead?

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

// Implementation of ByteCombineSquared

impl ByteCombineSquaredConstants for GF128 {
    const BYTE_COMBINE_SQ_2: Self = Self(gfu128_as_m128(UnoptimizedGF128::BYTE_COMBINE_SQ_2));
    const BYTE_COMBINE_SQ_3: Self = Self(gfu128_as_m128(UnoptimizedGF128::BYTE_COMBINE_SQ_3));
}

impl ByteCombineSquared for GF128 {
    fn byte_combine_sq(x: &[Self; 8]) -> Self {
        let sq = Self::square_byte(x);
        Self::byte_combine(&sq)
    }

    fn byte_combine_sq_slice(x: &[Self]) -> Self {
        let sq = Self::square_byte(x);
        Self::byte_combine(&sq)
    }

    fn byte_combine_bits_sq(x: u8) -> Self {
        // TODO: define optimized implementation for GF8
        let sq_bits = GF8::square_bits(x);
        Self::byte_combine_bits(sq_bits)
    }
}

impl Betas for GF128 {
    const BETA_SQUARES: [Self; 5] = [
        Self(gfu128_as_m128(UnoptimizedGF128::BETA_SQUARES[0])),
        Self(gfu128_as_m128(UnoptimizedGF128::BETA_SQUARES[1])),
        Self(gfu128_as_m128(UnoptimizedGF128::BETA_SQUARES[2])),
        Self(gfu128_as_m128(UnoptimizedGF128::BETA_SQUARES[3])),
        Self(gfu128_as_m128(UnoptimizedGF128::BETA_SQUARES[4])),
    ];

    const BETA_CUBES: [Self; 4] = [
        Self(gfu128_as_m128(UnoptimizedGF128::BETA_CUBES[0])),
        Self(gfu128_as_m128(UnoptimizedGF128::BETA_CUBES[1])),
        Self(gfu128_as_m128(UnoptimizedGF128::BETA_CUBES[2])),
        Self(gfu128_as_m128(UnoptimizedGF128::BETA_CUBES[3])),
    ];
}

impl Sigmas for GF128 {
    const SIGMA: [Self; 9] = [
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA[0])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA[1])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA[2])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA[3])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA[4])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA[5])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA[6])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA[7])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA[8])),
    ];

    const SIGMA_SQUARES: [Self; 9] = [
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA_SQUARES[0])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA_SQUARES[1])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA_SQUARES[2])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA_SQUARES[3])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA_SQUARES[4])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA_SQUARES[5])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA_SQUARES[6])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA_SQUARES[7])),
        Self(gfu128_as_m128(UnoptimizedGF128::SIGMA_SQUARES[8])),
    ];
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
    #[inline]
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

    _mm256_setr_m128i(
        combined[0],
        _mm_and_si128(combined[1], _mm_set_epi64x(0, -1)),
    )
}

unsafe fn poly256_reduce192(x: [__m128i; 2]) -> __m256i {
    let low = _mm_xor_si128(x[0], m128_clmul_lh(GF192_MOD_M128, x[1]));
    _mm256_setr_m128i(low, _mm_and_si128(x[1], _mm_set_epi64x(0, -1)))
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

#[inline]
unsafe fn m192_apply_mask_msb(v: __m256i, m: __m256i) -> __m256i {
    let m = _mm256_and_si256(m, m256_set_msb_192());
    let m = _mm256_srai_epi32(m, 32);
    let m = _mm256_permutevar8x32_epi32(m, m256_set_epi32_5());
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
                _mm256_xor_si256(shifted, m192_apply_mask_msb(GF192_MODULUS, self.0)),
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

    fn as_boxed_bytes(&self) -> Box<GenericArray<u8, Self::Length>> {
        let mut ret = GenericArray::<u8, Self::Length>::default_boxed();
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

// Implementation of SquareBytes

impl SquareBytes for GF192 {
    // TODO: Should we define a generic implementation for F: Field in large fields instead?

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

// Implementation of ByteCombineSquared

impl ByteCombineSquaredConstants for GF192 {
    const BYTE_COMBINE_SQ_2: Self = Self(gfu192_as_m256(UnoptimizedGF192::BYTE_COMBINE_SQ_2));
    const BYTE_COMBINE_SQ_3: Self = Self(gfu192_as_m256(UnoptimizedGF192::BYTE_COMBINE_SQ_3));
}

impl ByteCombineSquared for GF192 {
    fn byte_combine_sq(x: &[Self; 8]) -> Self {
        let sq = Self::square_byte(x);
        Self::byte_combine(&sq)
    }

    fn byte_combine_sq_slice(x: &[Self]) -> Self {
        let sq = Self::square_byte(x);
        Self::byte_combine(&sq)
    }

    fn byte_combine_bits_sq(x: u8) -> Self {
        // TODO: define optimized implementation for GF8
        let sq_bits = GF8::square_bits(x);
        Self::byte_combine_bits(sq_bits)
    }
}

impl Betas for GF192 {
    const BETA_SQUARES: [Self; 5] = [
        Self(gfu192_as_m256(UnoptimizedGF192::BETA_SQUARES[0])),
        Self(gfu192_as_m256(UnoptimizedGF192::BETA_SQUARES[1])),
        Self(gfu192_as_m256(UnoptimizedGF192::BETA_SQUARES[2])),
        Self(gfu192_as_m256(UnoptimizedGF192::BETA_SQUARES[3])),
        Self(gfu192_as_m256(UnoptimizedGF192::BETA_SQUARES[4])),
    ];

    const BETA_CUBES: [Self; 4] = [
        Self(gfu192_as_m256(UnoptimizedGF192::BETA_CUBES[0])),
        Self(gfu192_as_m256(UnoptimizedGF192::BETA_CUBES[1])),
        Self(gfu192_as_m256(UnoptimizedGF192::BETA_CUBES[2])),
        Self(gfu192_as_m256(UnoptimizedGF192::BETA_CUBES[3])),
    ];
}

impl Sigmas for GF192 {
    const SIGMA: [Self; 9] = [
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA[0])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA[1])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA[2])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA[3])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA[4])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA[5])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA[6])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA[7])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA[8])),
    ];

    const SIGMA_SQUARES: [Self; 9] = [
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA_SQUARES[0])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA_SQUARES[1])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA_SQUARES[2])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA_SQUARES[3])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA_SQUARES[4])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA_SQUARES[5])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA_SQUARES[6])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA_SQUARES[7])),
        Self(gfu192_as_m256(UnoptimizedGF192::SIGMA_SQUARES[8])),
    ];
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
    #[inline]
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

    _mm256_setr_m128i(xmod_combined[0], xmod_combined[1])
}

#[inline]
unsafe fn poly320_reduce256(x: [__m128i; 3]) -> __m256i {
    let tmp = _mm_xor_si128(x[0], m128_clmul_ll(GF256_MOD_M128, x[2]));
    _mm256_setr_m128i(tmp, x[1])
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

#[inline]
unsafe fn m256_apply_mask_msb(v: __m256i, m: __m256i) -> __m256i {
    let mask = m256_set_msb();
    let m = _mm256_and_si256(m, mask);
    let m = _mm256_srai_epi32(m, 32);
    let m = _mm256_permutevar8x32_epi32(m, m256_set_epi32_7());
    _mm256_blendv_epi8(_mm256_setzero_si256(), v, m)
}

const GF256_MODULUS: __m256i = u128_as_m256([UnoptimizedGF256::MODULUS, 0]);

impl Double for GF256 {
    type Output = Self;

    #[inline]
    fn double(self) -> Self::Output {
        Self(unsafe {
            let shifted = m256_shift_left_1(self.0);
            _mm256_xor_si256(shifted, m256_apply_mask_msb(GF256_MODULUS, self.0))
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

    fn as_boxed_bytes(&self) -> Box<GenericArray<u8, Self::Length>> {
        let mut ret = GenericArray::<u8, Self::Length>::default_boxed();
        unsafe { _mm256_storeu_si256(ret.as_mut_ptr().cast(), self.0) };
        ret
    }
}

// Implementation of SquareBytes

impl SquareBytes for GF256 {
    // TODO: Should we define a generic implementation for F: Field in large fields instead?

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

// Implementation of ByteCombineSquared

impl ByteCombineSquaredConstants for GF256 {
    const BYTE_COMBINE_SQ_2: Self = Self(gfu256_as_m256(UnoptimizedGF256::BYTE_COMBINE_SQ_2));
    const BYTE_COMBINE_SQ_3: Self = Self(gfu256_as_m256(UnoptimizedGF256::BYTE_COMBINE_SQ_3));
}

impl ByteCombineSquared for GF256 {
    fn byte_combine_sq(x: &[Self; 8]) -> Self {
        let sq = Self::square_byte(x);
        Self::byte_combine(&sq)
    }

    fn byte_combine_sq_slice(x: &[Self]) -> Self {
        let sq = Self::square_byte(x);
        Self::byte_combine(&sq)
    }

    fn byte_combine_bits_sq(x: u8) -> Self {
        // TODO: define optimized implementation for GF8
        let sq_bits = GF8::square_bits(x);
        Self::byte_combine_bits(sq_bits)
    }
}

impl Betas for GF256 {
    const BETA_SQUARES: [Self; 5] = [
        Self(gfu256_as_m256(UnoptimizedGF256::BETA_SQUARES[0])),
        Self(gfu256_as_m256(UnoptimizedGF256::BETA_SQUARES[1])),
        Self(gfu256_as_m256(UnoptimizedGF256::BETA_SQUARES[2])),
        Self(gfu256_as_m256(UnoptimizedGF256::BETA_SQUARES[3])),
        Self(gfu256_as_m256(UnoptimizedGF256::BETA_SQUARES[4])),
    ];

    const BETA_CUBES: [Self; 4] = [
        Self(gfu256_as_m256(UnoptimizedGF256::BETA_CUBES[0])),
        Self(gfu256_as_m256(UnoptimizedGF256::BETA_CUBES[1])),
        Self(gfu256_as_m256(UnoptimizedGF256::BETA_CUBES[2])),
        Self(gfu256_as_m256(UnoptimizedGF256::BETA_CUBES[3])),
    ];
}

impl Sigmas for GF256 {
    const SIGMA: [Self; 9] = [
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA[0])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA[1])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA[2])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA[3])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA[4])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA[5])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA[6])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA[7])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA[8])),
    ];

    const SIGMA_SQUARES: [Self; 9] = [
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA_SQUARES[0])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA_SQUARES[1])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA_SQUARES[2])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA_SQUARES[3])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA_SQUARES[4])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA_SQUARES[5])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA_SQUARES[6])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA_SQUARES[7])),
        Self(gfu256_as_m256(UnoptimizedGF256::SIGMA_SQUARES[8])),
    ];
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

/// Optimized implementation of the 384 bit Galois field
#[derive(Debug, Clone, Copy)]
pub(crate) struct GF384(__m256i, __m256i);

impl Default for GF384 {
    #[inline(always)]
    fn default() -> Self {
        Self(unsafe { _mm256_setzero_si256() }, unsafe {
            _mm256_setzero_si256()
        })
    }
}

impl PartialEq for GF384 {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            let tmp = _mm256_xor_si256(self.0, other.0);

            if _mm256_testz_si256(tmp, tmp) != 1 {
                return false;
            }

            let tmp = _mm256_xor_si256(self.1, other.1);

            _mm256_testz_si256(tmp, tmp) == 1
        }
    }
}

impl Eq for GF384 {}

// implementations of Add and AddAssign

impl Add for GF384 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) }, unsafe {
            _mm256_xor_si256(self.1, rhs.1)
        })
    }
}

impl Add<&Self> for GF384 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) }, unsafe {
            _mm256_xor_si256(self.1, rhs.1)
        })
    }
}

impl Add<GF384> for &GF384 {
    type Output = GF384;

    #[inline(always)]
    fn add(self, rhs: GF384) -> Self::Output {
        GF384(unsafe { _mm256_xor_si256(self.0, rhs.0) }, unsafe {
            _mm256_xor_si256(self.1, rhs.1)
        })
    }
}

impl AddAssign for GF384 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
        self.1 = unsafe { _mm256_xor_si256(self.1, rhs.1) };
    }
}

impl AddAssign<&Self> for GF384 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: &Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
        self.1 = unsafe { _mm256_xor_si256(self.1, rhs.1) };
    }
}

// implementations of Sub and SubAssign

impl Sub for GF384 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) }, unsafe {
            _mm256_xor_si256(self.1, rhs.1)
        })
    }
}

impl Sub<&Self> for GF384 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) }, unsafe {
            _mm256_xor_si256(self.1, rhs.1)
        })
    }
}

impl Sub<GF384> for &GF384 {
    type Output = GF384;

    #[inline(always)]
    fn sub(self, rhs: GF384) -> Self::Output {
        GF384(unsafe { _mm256_xor_si256(self.0, rhs.0) }, unsafe {
            _mm256_xor_si256(self.1, rhs.1)
        })
    }
}

impl SubAssign for GF384 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
        self.1 = unsafe { _mm256_xor_si256(self.1, rhs.1) };
    }
}

impl SubAssign<&Self> for GF384 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
        self.1 = unsafe { _mm256_xor_si256(self.1, rhs.1) };
    }
}

// implementations of Neg

impl Neg for GF384 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl From<&[u8]> for GF384 {
    fn from(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), 48);
        Self(
            unsafe { _mm256_loadu_si256(value.as_ptr().cast()) },
            unsafe {
                _mm256_maskload_epi64(
                    value[32..].as_ptr().cast(),
                    _mm256_setr_epi64x(i64::MIN, i64::MIN, 0, 0),
                )
            },
        )
    }
}

impl From<(__m256i, __m256i)> for GF384 {
    fn from(value: (__m256i, __m256i)) -> Self {
        Self(value.0, value.1)
    }
}

impl Into<(__m256i, __m256i)> for GF384 {
    fn into(self) -> (__m256i, __m256i) {
        (self.0, self.1)
    }
}

const GF384_MOD_M128: __m128i = u128_as_m128(UnoptimizedGF384::MODULUS);

unsafe fn poly512_reduce384(mut x: [__m128i; 4]) -> (__m256i, __m256i) {
    let xmod = [
        m128_clmul_ll(GF384_MOD_M128, x[3]),
        m128_clmul_lh(GF384_MOD_M128, x[3]),
    ];

    let xmod_combined = [
        _mm_xor_si128(xmod[0], _mm_slli_si128(xmod[1], 8)),
        _mm_srli_si128(xmod[1], 8),
    ];

    x[0] = _mm_xor_si128(x[0], xmod_combined[0]);
    x[1] = _mm_xor_si128(x[1], xmod_combined[1]);

    (
        _mm256_setr_m128i(x[0], x[1]),
        _mm256_setr_m128i(x[2], _mm_setzero_si128()),
    )
}

fn mul_gf384_gf128(lhs: (__m256i, __m256i), y0: __m128i) -> (__m256i, __m256i) {
    unsafe {
        let x0 = _mm256_extracti128_si256(lhs.0, 0);
        let x1 = _mm256_extracti128_si256(lhs.0, 1);
        let x2 = _mm256_extracti128_si256(lhs.1, 0);

        let x0y0 = karatsuba_mul_128_uncombined(x0, y0);
        let x1y0 = karatsuba_mul_128_uncombined(x1, y0);
        let x2y0 = karatsuba_mul_128_uncombined(x2, y0);

        let tmp1 = _mm_xor_si128(x0y0[2], _mm_alignr_epi8(x1y0[1], x0y0[1], 8));
        let tmp2 = _mm_xor_si128(x1y0[2], _mm_alignr_epi8(x2y0[1], x1y0[1], 8));

        let combined = [
            _mm_xor_si128(x0y0[0], _mm_slli_si128(x0y0[1], 8)),
            _mm_xor_si128(x1y0[0], tmp1),
            _mm_xor_si128(x2y0[0], tmp2),
            _mm_xor_si128(x2y0[2], _mm_srli_si128(x2y0[1], 8)),
        ];

        poly512_reduce384(combined)
    }
}

impl Mul<GF128> for GF384 {
    type Output = GF384;

    #[inline(always)]
    fn mul(self, rhs: GF128) -> Self::Output {
        Self::from(mul_gf384_gf128(self.into(), rhs.0))
    }
}

impl Mul<&GF128> for GF384 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: &GF128) -> Self::Output {
        Self::from(mul_gf384_gf128(self.into(), rhs.0))
    }
}

impl ExtensionField for GF384 {
    const ZERO: Self = Self(u64_as_m256(0), u64_as_m256(0));
    const ONE: Self = Self(u64_as_m256(1), u64_as_m256(0));

    type Length = U48;

    type BaseField = GF128;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        let mut ret = GenericArray::<u8, Self::Length>::default();
        unsafe { _mm256_storeu_si256(ret.as_mut_ptr().cast(), self.0) };
        unsafe { _mm256_storeu_si256(ret[32..].as_mut_ptr().cast(), self.1) };
        ret
    }

    fn as_boxed_bytes(&self) -> Box<GenericArray<u8, Self::Length>> {
        let mut ret = GenericArray::<u8, Self::Length>::default_boxed();
        unsafe { _mm256_storeu_si256(ret.as_mut_ptr().cast(), self.0) };
        unsafe { _mm256_storeu_si256(ret[32..].as_mut_ptr().cast(), self.1) };
        ret
    }
}

/// Optimized implementation of the 576 bit Galois field
#[derive(Debug, Clone, Copy)]
pub(crate) struct GF576(__m256i, __m256i, u64);

impl Default for GF576 {
    #[inline(always)]
    fn default() -> Self {
        Self(
            unsafe { _mm256_setzero_si256() },
            unsafe { _mm256_setzero_si256() },
            0,
        )
    }
}

impl PartialEq for GF576 {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            let tmp = _mm256_xor_si256(self.0, other.0);

            let mut eq = true;

            eq &= _mm256_testz_si256(tmp, tmp) == 1;

            let tmp = _mm256_xor_si256(self.1, other.1);

            eq &= _mm256_testz_si256(tmp, tmp) == 1;

            eq & (self.2 == other.2)
        }
    }
}

impl Eq for GF576 {}

// implementations of Add and AddAssign

impl Add for GF576 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(
            unsafe { _mm256_xor_si256(self.0, rhs.0) },
            unsafe { _mm256_xor_si256(self.1, rhs.1) },
            self.2 ^ rhs.2,
        )
    }
}

impl Add<&Self> for GF576 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(
            unsafe { _mm256_xor_si256(self.0, rhs.0) },
            unsafe { _mm256_xor_si256(self.1, rhs.1) },
            self.2 ^ rhs.2,
        )
    }
}

impl Add<GF576> for &GF576 {
    type Output = GF576;

    #[inline(always)]
    fn add(self, rhs: GF576) -> Self::Output {
        GF576(
            unsafe { _mm256_xor_si256(self.0, rhs.0) },
            unsafe { _mm256_xor_si256(self.1, rhs.1) },
            self.2 ^ rhs.2,
        )
    }
}

impl AddAssign for GF576 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
        self.1 = unsafe { _mm256_xor_si256(self.1, rhs.1) };
        self.2 ^= rhs.2;
    }
}

impl AddAssign<&Self> for GF576 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: &Self) {
        self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
        self.1 = unsafe { _mm256_xor_si256(self.1, rhs.1) };
        self.2 ^= rhs.2;
    }
}

// implementations of Sub and SubAssign

impl Sub for GF576 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl Sub<&Self> for GF576 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: &Self) -> Self::Output {
        self.add(rhs)
    }
}

impl Sub<GF576> for &GF576 {
    type Output = GF576;

    #[inline(always)]
    fn sub(self, rhs: GF576) -> Self::Output {
        self.add(rhs)
    }
}

impl SubAssign for GF576 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs;
    }
}

impl SubAssign<&Self> for GF576 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &Self) {
        *self += rhs;
    }
}

// implementations of Neg

impl Neg for GF576 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl From<&[u8]> for GF576 {
    fn from(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), <Self as ExtensionField>::Length::USIZE);
        Self(
            unsafe { _mm256_loadu_si256(value.as_ptr().cast()) },
            unsafe { _mm256_loadu_si256(value.as_ptr().add(32).cast()) },
            u64::from_le_bytes(value[64..].try_into().unwrap()),
        )
    }
}

const GF576_MOD_M128: __m128i = u128_as_m128(UnoptimizedGF576::MODULUS);

unsafe fn poly896_reduce576(x: [__m128i; 6]) -> (__m256i, __m256i, u64) {
    let xmod = [
        m128_clmul_lh(GF576_MOD_M128, x[4]),
        m128_clmul_ll(GF576_MOD_M128, x[5]), //2^64
        m128_clmul_lh(GF576_MOD_M128, x[5]), //2^128
    ];

    let xmod_combined = [
        _mm_xor_si128(xmod[0], _mm_slli_si128(xmod[1], 8)),
        _mm_xor_si128(xmod[2], _mm_srli_si128(xmod[1], 8)),
    ];

    (
        _mm256_set_m128i(
            _mm_xor_si128(x[1], xmod_combined[1]),
            _mm_xor_si128(x[0], xmod_combined[0]),
        ),
        _mm256_set_m128i(x[3], x[2]),
        GF128ConstHelper { a: x[4] }.c[0],
    )
}

fn mul_gf576_gf192(lhs: (__m256i, __m256i, u64), rhs: __m256i) -> (__m256i, __m256i, u64) {
    unsafe {
        let x0 = _mm256_extracti128_si256(lhs.0, 0);
        let x1 = _mm256_extracti128_si256(lhs.0, 1);
        let x2 = _mm256_extracti128_si256(lhs.1, 0);
        let x3 = _mm256_extracti128_si256(lhs.1, 1);
        let x4 = _mm_set_epi64x(0, lhs.2 as i64);

        let y0 = _mm256_extracti128_si256(rhs, 0);
        let y1 = _mm256_extracti128_si256(rhs, 1);
        let ysum = _mm_xor_si128(y0, y1);

        let x0y0 = karatsuba_mul_128_uncombined(x0, y0);
        let xsum_low_ysum = karatsuba_mul_128_uncombined(_mm_xor_si128(x0, x1), ysum);
        let x1y1 = [m128_clmul_ll(y1, x1), m128_clmul_lh(y1, x1)];
        let x0y0_2_plus_x1y1_0 = _mm_xor_si128(x0y0[2], x1y1[0]);

        let x2y0 = karatsuba_mul_128_uncombined(x2, y0);
        let xsum_high_ysum = karatsuba_mul_128_uncombined(_mm_xor_si128(x2, x3), ysum);
        let x3y1 = [m128_clmul_ll(y1, x3), m128_clmul_lh(y1, x3)];
        let x2y0_2_plus_x3y1_0 = _mm_xor_si128(x2y0[2], x3y1[0]);

        let tmp = m128_clmul_lh(x4, y0);
        let x4y0 = [
            _mm_xor_si128(m128_clmul_ll(x4, y0), _mm_slli_si128(tmp, 8)),
            _mm_srli_si128(tmp, 8),
        ];

        let x4y1 = m128_clmul_ll(x4, y1);

        let tmp = [
            //128
            _mm_xor_si128(xsum_low_ysum[0], _mm_xor_si128(x0y0[0], x0y0_2_plus_x1y1_0)),
            _mm_xor_si128(xsum_low_ysum[1], _mm_xor_si128(x0y0[1], x1y1[1])),
            //256
            _mm_xor_si128(_mm_xor_si128(xsum_low_ysum[2], x2y0[0]), x0y0_2_plus_x1y1_0),
            _mm_xor_si128(x1y1[1], x2y0[1]),
            //384
            _mm_xor_si128(
                xsum_high_ysum[0],
                _mm_xor_si128(x2y0[0], x2y0_2_plus_x3y1_0),
            ),
            _mm_xor_si128(xsum_high_ysum[1], _mm_xor_si128(x2y0[1], x3y1[1])),
            //512
            _mm_xor_si128(xsum_high_ysum[2], x2y0_2_plus_x3y1_0),
        ];

        let combined = [
            _mm_xor_si128(x0y0[0], _mm_slli_si128(x0y0[1], 8)),
            _mm_xor_si128(tmp[0], _mm_alignr_epi8(tmp[1], x0y0[1], 8)),
            _mm_xor_si128(tmp[2], _mm_alignr_epi8(tmp[3], tmp[1], 8)),
            _mm_xor_si128(tmp[4], _mm_alignr_epi8(tmp[5], tmp[3], 8)),
            _mm_xor_si128(
                _mm_xor_si128(tmp[6], x4y0[0]),
                _mm_alignr_epi8(x3y1[1], tmp[5], 8),
            ),
            _mm_xor_si128(x4y0[1], _mm_xor_si128(_mm_srli_si128(x3y1[1], 8), x4y1)),
        ];

        poly896_reduce576(combined)
    }
}

impl Mul<GF192> for GF576 {
    type Output = GF576;

    #[inline(always)]
    fn mul(self, rhs: GF192) -> Self::Output {
        let res = mul_gf576_gf192((self.0, self.1, self.2), rhs.0);
        Self(res.0, res.1, res.2)
    }
}

impl Mul<&GF192> for GF576 {
    type Output = GF576;

    #[inline(always)]
    fn mul(self, rhs: &GF192) -> Self::Output {
        let res = mul_gf576_gf192((self.0, self.1, self.2), rhs.0);
        Self(res.0, res.1, res.2)
    }
}

impl ExtensionField for GF576 {
    const ZERO: Self = Self(u64_as_m256(0), u64_as_m256(0), 0);
    const ONE: Self = Self(u64_as_m256(1), u64_as_m256(0), 0);

    type Length = U72;

    type BaseField = GF192;

    fn as_bytes(&self) -> GenericArray<u8, Self::Length> {
        let mut ret = GenericArray::<u8, Self::Length>::default();
        unsafe { _mm256_storeu_si256(ret.as_mut_ptr().cast(), self.0) };
        unsafe { _mm256_storeu_si256(ret.as_mut_ptr().add(32).cast(), self.1) };
        ret[64..].copy_from_slice(&self.2.to_le_bytes());
        ret
    }

    fn as_boxed_bytes(&self) -> Box<GenericArray<u8, Self::Length>> {
        let mut ret = GenericArray::<u8, Self::Length>::default_boxed();
        unsafe { _mm256_storeu_si256(ret.as_mut_ptr().cast(), self.0) };
        unsafe { _mm256_storeu_si256(ret.as_mut_ptr().add(32).cast(), self.1) };
        ret[64..].copy_from_slice(&self.2.to_le_bytes());
        ret
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const RUNS: usize = 100;

    use rand::{
        distributions::{Distribution, Standard},
        rngs::SmallRng,
        Rng, RngCore, SeedableRng,
    };

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

    #[generic_tests::define]
    mod big_gf_ops {
        use super::*;

        use std::fmt::Debug;

        use rand::{
            distributions::{Distribution, Standard},
            rngs::SmallRng,
            Rng, RngCore, SeedableRng,
        };

        #[test]
        fn byte_combine_sq<Fu, F: BigGaloisField + Debug + Eq>()
        where
            Standard: Distribution<Fu>,
            Fu: BigGaloisField<Length = F::Length> + Debug + Eq,
        {
            let mut rng = SmallRng::from_entropy();

            for _ in 0..RUNS {
                let byte1: [Fu; 8] = std::array::from_fn(|_| rng.gen());
                let byte2: [F; 8] = std::array::from_fn(|i| F::from(&byte1[i].as_bytes()));
                let byte3 = rand::thread_rng().gen::<u8>();

                let v1 = Fu::byte_combine(&byte1);
                let v2 = F::byte_combine(&byte2);
                assert_eq!(v1.as_bytes(), v2.as_bytes());

                let v2 = F::byte_combine_slice(byte2.as_slice());
                assert_eq!(v1.as_bytes(), v2.as_bytes());

                let v1 = Fu::byte_combine_bits_sq(byte3);
                let v2 = Fu::byte_combine_bits_sq(byte3);
                assert_eq!(v1.as_bytes(), v2.as_bytes());
            }

            assert_eq!(
                F::BYTE_COMBINE_SQ_2.as_bytes(),
                Fu::BYTE_COMBINE_SQ_2.as_bytes()
            );
            assert_eq!(
                F::BYTE_COMBINE_SQ_3.as_bytes(),
                Fu::BYTE_COMBINE_SQ_3.as_bytes()
            );
        }

        #[test]
        fn constants<Fu, F: BigGaloisField + Alphas + Debug + Eq>()
        where
            Standard: Distribution<Fu>,
            Fu: BigGaloisField<Length = F::Length> + Alphas + Debug + Eq,
        {
            for (x, y) in itertools::izip!(F::ALPHA, Fu::ALPHA) {
                assert_eq!(x.as_bytes(), y.as_bytes());
            }
            for (x, y) in itertools::izip!(F::BETA_CUBES, Fu::BETA_CUBES) {
                assert_eq!(x.as_bytes(), y.as_bytes());
            }
            for (x, y) in itertools::izip!(F::BETA_SQUARES, Fu::BETA_SQUARES) {
                assert_eq!(x.as_bytes(), y.as_bytes());
            }
            for (x, y) in itertools::izip!(F::SIGMA, Fu::SIGMA) {
                assert_eq!(x.as_bytes(), y.as_bytes());
            }
            for (x, y) in itertools::izip!(F::SIGMA_SQUARES, Fu::SIGMA_SQUARES) {
                assert_eq!(x.as_bytes(), y.as_bytes());
            }
        }

        #[instantiate_tests(<UnoptimizedGF128, GF128>)]
        mod gf128 {}

        #[instantiate_tests(<UnoptimizedGF192, GF192>)]
        mod gf192 {}

        #[instantiate_tests(<UnoptimizedGF256, GF256>)]
        mod gf256 {}
    }

    #[generic_tests::define]
    mod extended_fields {
        use super::*;

        use std::fmt::Debug;
        use std::{ops::AddAssign, process::Output};

        use generic_array::typenum::Le;
        use rand::{
            distributions::{Distribution, Standard},
            rngs::SmallRng,
            Rng, RngCore, SeedableRng,
        };

        #[test]
        fn add<Fu, F>()
        where
            Standard: Distribution<Fu>,
            Fu: ExtensionField + Debug + Eq + Copy,
            for<'a> F: ExtensionField<Length = Fu::Length> + Debug + Eq + From<&'a [u8]> + Copy,
        {
            let mut rng = SmallRng::from_entropy();

            for _ in 0..RUNS {
                let mut lhs1: Fu = rng.gen();
                let rhs1: Fu = rng.gen();

                let mut lhs2 = F::from(lhs1.as_bytes().as_slice());
                let rhs2 = F::from(rhs1.as_bytes().as_slice());

                let r1 = lhs1 + rhs1;
                let r2 = lhs2 + rhs2;
                assert_eq!(r1.as_bytes(), r2.as_bytes());

                lhs1 += rhs1;
                lhs2 += rhs2;
                assert_eq!(r1.as_bytes(), r2.as_bytes())
            }
        }

        #[test]
        fn mul<Fu, F>()
        where
            Standard: Distribution<Fu> + Distribution<Fu::BaseField>,
            Fu: ExtensionField + Debug + Eq + Copy,
            for<'a> F: ExtensionField<Length = Fu::Length, BaseField: From<&'a [u8]>>
                + Debug
                + Eq
                + From<&'a [u8]>
                + Copy,
        {
            let mut rng = SmallRng::from_entropy();

            for _ in 0..RUNS {
                let lhs1: Fu = rng.gen();
                let rhs1: Fu::BaseField = rng.gen::<Fu::BaseField>();

                let lhs2 = F::from(lhs1.as_bytes().as_slice());
                let rhs2 = F::BaseField::from(rhs1.as_bytes().as_slice());

                let r1 = lhs1 * rhs1;
                let r2 = lhs2 * rhs2;
                assert_eq!(r1.as_bytes(), r2.as_bytes());
            }
        }

        #[instantiate_tests(<UnoptimizedGF384, GF384>)]
        mod gf384 {}

        #[instantiate_tests(<UnoptimizedGF576, GF576>)]
        mod gf576 {}
    }
}
