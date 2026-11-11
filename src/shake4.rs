//! Synchronized SHAKE streams. AVX2 stores each Keccak word as four lanes.
use super::{Hasher, Hasher4, Reader4};
use crate::utils::Reader;

#[derive(Clone)]
pub(crate) enum Four<H, const RATE: usize, const SEP: u8> {
    Scalar([H; 4]),
    #[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
    Avx2(avx2::Sponge<RATE>),
}

impl<H: Default, const RATE: usize, const SEP: u8> Default for Four<H, RATE, SEP> {
    fn default() -> Self {
        #[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
        if std::is_x86_feature_detected!("avx2") {
            return Self::Avx2(avx2::Sponge::default());
        }
        Self::Scalar(core::array::from_fn(|_| H::default()))
    }
}

pub(crate) enum FourReader<R, const RATE: usize> {
    Scalar([R; 4]),
    #[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
    Avx2(avx2::Sponge<RATE>),
}

impl<H: Hasher + Clone, const RATE: usize, const SEP: u8> Hasher4 for Four<H, RATE, SEP> {
    type Reader = FourReader<H::Reader, RATE>;
    fn update(&mut self, data: [&[u8]; 4]) {
        assert!(
            data.iter().all(|s| s.len() == data[0].len()),
            "unequal SHAKE input lengths"
        );
        match self {
            Self::Scalar(hashers) => {
                for (h, d) in hashers.iter_mut().zip(data) {
                    h.update(d);
                }
            }
            #[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
            Self::Avx2(s) => s.update(data),
        }
    }
    fn finish(self) -> Self::Reader {
        match self {
            Self::Scalar(h) => FourReader::Scalar(h.map(Hasher::finish)),
            #[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
            Self::Avx2(mut s) => {
                s.update([&[SEP]; 4]);
                s.pad();
                FourReader::Avx2(s)
            }
        }
    }
}

impl<R: Reader, const RATE: usize> Reader4 for FourReader<R, RATE> {
    fn read(&mut self, dst: [&mut [u8]; 4]) {
        assert!(
            dst.iter().all(|s| s.len() == dst[0].len()),
            "unequal SHAKE output lengths"
        );
        match self {
            Self::Scalar(readers) => {
                for (r, d) in readers.iter_mut().zip(dst) {
                    r.read(d);
                }
            }
            #[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
            Self::Avx2(s) => s.read(dst),
        }
    }
}

#[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
mod avx2 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    // The word-major layout stays packed throughout absorption and squeezing.
    #[derive(Clone)]
    pub(crate) struct Sponge<const RATE: usize> {
        words: [[u64; 4]; 25],
        pos: usize,
    }
    impl<const RATE: usize> Default for Sponge<RATE> {
        fn default() -> Self {
            Self {
                words: [[0; 4]; 25],
                pos: 0,
            }
        }
    }
    impl<const RATE: usize> Sponge<RATE> {
        fn permute(&mut self) {
            // SAFETY: this variant is constructed only after runtime AVX2 detection.
            unsafe {
                keccak(&mut self.words);
            }
        }
        pub(super) fn update(&mut self, data: [&[u8]; 4]) {
            let mut offset = 0;
            while offset < data[0].len() {
                let count = (RATE - self.pos).min(data[0].len() - offset);
                let mut j = 0;
                while j < count {
                    let p = self.pos + j;
                    if p % 8 == 0 && count - j >= 8 {
                        for lane in 0..4 {
                            self.words[p / 8][lane] ^= u64::from_le_bytes(
                                data[lane][offset + j..offset + j + 8].try_into().unwrap(),
                            );
                        }
                        j += 8;
                    } else {
                        for lane in 0..4 {
                            self.words[p / 8][lane] ^=
                                (data[lane][offset + j] as u64) << (8 * (p % 8));
                        }
                        j += 1;
                    }
                }
                offset += count;
                self.pos += count;
                if self.pos == RATE {
                    self.permute();
                    self.pos = 0;
                }
            }
        }
        pub(super) fn pad(&mut self) {
            for lane in 0..4 {
                self.words[self.pos / 8][lane] ^= 0x1f << (8 * (self.pos % 8));
                self.words[RATE / 8 - 1][lane] ^= 1 << 63;
            }
            self.permute();
            self.pos = 0;
        }
        pub(super) fn read(&mut self, mut dst: [&mut [u8]; 4]) {
            for offset in 0..dst[0].len() {
                if self.pos == RATE {
                    self.permute();
                    self.pos = 0;
                }
                for (lane, d) in dst.iter_mut().enumerate() {
                    d[offset] = (self.words[self.pos / 8][lane] >> (8 * (self.pos % 8))) as u8;
                }
                self.pos += 1;
            }
        }
    }

    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];

    #[target_feature(enable = "avx2")]
    unsafe fn keccak(words: &mut [[u64; 4]; 25]) {
        let mut a = [_mm256_setzero_si256(); 25];
        for i in 0..25 {
            // SAFETY: each word contains exactly 32 initialized bytes; unaligned loads are allowed.
            a[i] = unsafe { _mm256_loadu_si256(words[i].as_ptr().cast()) };
        }
        for rc in RC {
            let mut c = [_mm256_setzero_si256(); 5];
            for x in 0..5 {
                c[x] = _mm256_xor_si256(
                    _mm256_xor_si256(a[x], a[x + 5]),
                    _mm256_xor_si256(_mm256_xor_si256(a[x + 10], a[x + 15]), a[x + 20]),
                );
            }
            for x in 0..5 {
                let next = c[(x + 1) % 5];
                let d = _mm256_xor_si256(
                    c[(x + 4) % 5],
                    _mm256_or_si256(_mm256_slli_epi64::<1>(next), _mm256_srli_epi64::<63>(next)),
                );
                for y in 0..5 {
                    a[x + 5 * y] = _mm256_xor_si256(a[x + 5 * y], d);
                }
            }
            let mut b = [_mm256_setzero_si256(); 25];
            b[0] = a[0];
            b[10] = _mm256_or_si256(_mm256_slli_epi64::<1>(a[1]), _mm256_srli_epi64::<63>(a[1]));
            b[20] = _mm256_or_si256(_mm256_slli_epi64::<62>(a[2]), _mm256_srli_epi64::<2>(a[2]));
            b[5] = _mm256_or_si256(_mm256_slli_epi64::<28>(a[3]), _mm256_srli_epi64::<36>(a[3]));
            b[15] = _mm256_or_si256(_mm256_slli_epi64::<27>(a[4]), _mm256_srli_epi64::<37>(a[4]));
            b[16] = _mm256_or_si256(_mm256_slli_epi64::<36>(a[5]), _mm256_srli_epi64::<28>(a[5]));
            b[1] = _mm256_or_si256(_mm256_slli_epi64::<44>(a[6]), _mm256_srli_epi64::<20>(a[6]));
            b[11] = _mm256_or_si256(_mm256_slli_epi64::<6>(a[7]), _mm256_srli_epi64::<58>(a[7]));
            b[21] = _mm256_or_si256(_mm256_slli_epi64::<55>(a[8]), _mm256_srli_epi64::<9>(a[8]));
            b[6] = _mm256_or_si256(_mm256_slli_epi64::<20>(a[9]), _mm256_srli_epi64::<44>(a[9]));
            b[7] = _mm256_or_si256(
                _mm256_slli_epi64::<3>(a[10]),
                _mm256_srli_epi64::<61>(a[10]),
            );
            b[17] = _mm256_or_si256(
                _mm256_slli_epi64::<10>(a[11]),
                _mm256_srli_epi64::<54>(a[11]),
            );
            b[2] = _mm256_or_si256(
                _mm256_slli_epi64::<43>(a[12]),
                _mm256_srli_epi64::<21>(a[12]),
            );
            b[12] = _mm256_or_si256(
                _mm256_slli_epi64::<25>(a[13]),
                _mm256_srli_epi64::<39>(a[13]),
            );
            b[22] = _mm256_or_si256(
                _mm256_slli_epi64::<39>(a[14]),
                _mm256_srli_epi64::<25>(a[14]),
            );
            b[23] = _mm256_or_si256(
                _mm256_slli_epi64::<41>(a[15]),
                _mm256_srli_epi64::<23>(a[15]),
            );
            b[8] = _mm256_or_si256(
                _mm256_slli_epi64::<45>(a[16]),
                _mm256_srli_epi64::<19>(a[16]),
            );
            b[18] = _mm256_or_si256(
                _mm256_slli_epi64::<15>(a[17]),
                _mm256_srli_epi64::<49>(a[17]),
            );
            b[3] = _mm256_or_si256(
                _mm256_slli_epi64::<21>(a[18]),
                _mm256_srli_epi64::<43>(a[18]),
            );
            b[13] = _mm256_or_si256(
                _mm256_slli_epi64::<8>(a[19]),
                _mm256_srli_epi64::<56>(a[19]),
            );
            b[14] = _mm256_or_si256(
                _mm256_slli_epi64::<18>(a[20]),
                _mm256_srli_epi64::<46>(a[20]),
            );
            b[24] = _mm256_or_si256(
                _mm256_slli_epi64::<2>(a[21]),
                _mm256_srli_epi64::<62>(a[21]),
            );
            b[9] = _mm256_or_si256(
                _mm256_slli_epi64::<61>(a[22]),
                _mm256_srli_epi64::<3>(a[22]),
            );
            b[19] = _mm256_or_si256(
                _mm256_slli_epi64::<56>(a[23]),
                _mm256_srli_epi64::<8>(a[23]),
            );
            b[4] = _mm256_or_si256(
                _mm256_slli_epi64::<14>(a[24]),
                _mm256_srli_epi64::<50>(a[24]),
            );
            for y in 0..5 {
                for x in 0..5 {
                    a[x + 5 * y] = _mm256_xor_si256(
                        b[x + 5 * y],
                        _mm256_andnot_si256(b[(x + 1) % 5 + 5 * y], b[(x + 2) % 5 + 5 * y]),
                    );
                }
            }
            a[0] = _mm256_xor_si256(a[0], _mm256_set1_epi64x(rc as i64));
        }
        for i in 0..25 {
            // SAFETY: each destination word has space for all four lanes.
            unsafe {
                _mm256_storeu_si256(words[i].as_mut_ptr().cast(), a[i]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random_oracles::{Hasher128, Hasher256};
    #[cfg(not(feature = "std"))]
    use alloc::{vec, vec::Vec};

    fn differential<H: Hasher + Default + Clone, const RATE: usize, const SEP: u8>() {
        for len in [
            0,
            1,
            7,
            8,
            RATE - 2,
            RATE - 1,
            RATE,
            RATE + 1,
            2 * RATE - 1,
            3 * RATE + 13,
        ] {
            let inputs: [Vec<u8>; 4] =
                core::array::from_fn(|lane| (0..len).map(|i| (i * 37 + lane * 61) as u8).collect());
            for fragment in [1, 7, RATE - 1, RATE + 1] {
                let mut four = Four::<H, RATE, SEP>::default();
                let mut scalar =
                    Four::<H, RATE, SEP>::Scalar(core::array::from_fn(|_| H::default()));
                // Exercise shared prefixes, including a prefix that crosses a rate boundary.
                let shared = vec![0x93; RATE + 3];
                four.update_shared(&shared);
                scalar.update_shared(&shared);
                for start in (0..len).step_by(fragment) {
                    let end = (start + fragment).min(len);
                    let parts = inputs.each_ref().map(|s| &s[start..end]);
                    four.update(parts);
                    scalar.update(parts);
                }
                for suffix in [b"".as_slice(), b"cloned branch".as_slice()] {
                    let mut four = four.clone();
                    let mut scalar = scalar.clone();
                    four.update_shared(suffix);
                    scalar.update_shared(suffix);
                    let mut four = four.finish();
                    let mut scalar = scalar.finish();
                    for count in [0, 1, RATE - 1, 0, RATE + 7, 2 * RATE] {
                        let mut actual: [Vec<u8>; 4] = core::array::from_fn(|_| vec![0; count]);
                        let mut expected = actual.clone();
                        four.read(actual.each_mut().map(|s| s.as_mut_slice()));
                        scalar.read(expected.each_mut().map(|s| s.as_mut_slice()));
                        assert_eq!(
                            actual, expected,
                            "rate={RATE} sep={SEP} len={len} fragment={fragment}"
                        );
                    }
                }
            }
            // No prefix: in particular, SEP itself can complete an absorption block.
            let mut four = Four::<H, RATE, SEP>::default();
            let mut scalar = Four::<H, RATE, SEP>::Scalar(core::array::from_fn(|_| H::default()));
            four.update(inputs.each_ref().map(|s| s.as_slice()));
            scalar.update(inputs.each_ref().map(|s| s.as_slice()));
            let mut actual = [[0; 200]; 4];
            let mut expected = actual;
            four.finish()
                .read(actual.each_mut().map(|s| s.as_mut_slice()));
            scalar
                .finish()
                .read(expected.each_mut().map(|s| s.as_mut_slice()));
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn matches_scalar_shake() {
        macro_rules! check {
            ($($sep:literal),*) => {$({
                differential::<Hasher128<$sep>, 168, $sep>();
                differential::<Hasher256<$sep>, 136, $sep>();
            })*};
        }
        check!(0, 1, 3, 4, 5, 8, 9, 10, 11, 255);
    }

    #[test]
    #[should_panic(expected = "unequal SHAKE input lengths")]
    fn rejects_unsynchronized_updates() {
        Four::<Hasher128<1>, 168, 1>::default().update([b"a", b"", b"a", b"a"]);
    }

    #[test]
    #[should_panic(expected = "unequal SHAKE output lengths")]
    fn rejects_unsynchronized_reads() {
        Four::<Hasher256<1>, 136, 1>::default().finish().read([
            &mut [0; 1],
            &mut [],
            &mut [0; 1],
            &mut [0; 1],
        ]);
    }
}
