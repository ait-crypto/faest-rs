//! AES expansion and CTR encryption for eight streams using 256-bit vectors

use crate::prg::{IV, Twk, add_tweak};
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use core::marker::PhantomData;
use hybrid_array::{Array, ArraySize};
use std::arch::is_x86_feature_detected;

pub(super) fn available() -> bool {
    // AVX2 detection checks OS support for YMM state. VAES implies AES in Rust.
    is_x86_feature_detected!("avx2")
        && is_x86_feature_detected!("gfni")
        && is_x86_feature_detected!("vaes")
        && is_x86_feature_detected!("aes")
}

#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
#[repr(C, align(32))]
struct RoundKeys([[[u8; 32]; 4]; 15]);

// Each vector holds the same word from all eight keys, with even seeds in
// the low 128-bit half and odd seeds in the high half.
struct PackedState<const WORDS: usize>([__m256i; WORDS]);

#[cfg(feature = "zeroize")]
impl<const WORDS: usize> Drop for PackedState<WORDS> {
    fn drop(&mut self) {
        use zeroize::Zeroize;

        // SAFETY: The array and the vectors have no padding. The entire
        // buffer consists of initialized bytes and is aligned for u64.
        let words = unsafe {
            core::slice::from_raw_parts_mut(self.0.as_mut_ptr().cast::<u64>(), 4 * WORDS)
        };
        words.zeroize();
    }
}

const RCON: [i32; 10] = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54];

#[inline]
#[target_feature(enable = "avx2")]
fn transpose([a, b, c, d]: [__m256i; 4]) -> [__m256i; 4] {
    // Each unpack transposes the low and high 128-bit halves independently.
    let ab_lo = _mm256_unpacklo_epi32(a, b);
    let ab_hi = _mm256_unpackhi_epi32(a, b);
    let cd_lo = _mm256_unpacklo_epi32(c, d);
    let cd_hi = _mm256_unpackhi_epi32(c, d);
    [
        _mm256_unpacklo_epi64(ab_lo, cd_lo),
        _mm256_unpackhi_epi64(ab_lo, cd_lo),
        _mm256_unpacklo_epi64(ab_hi, cd_hi),
        _mm256_unpackhi_epi64(ab_hi, cd_hi),
    ]
}

#[inline]
#[target_feature(enable = "avx2,gfni")]
fn schedule_assist<const ROTATE: bool>(word: __m256i) -> __m256i {
    const AES_SBOX_CONSTANT: i32 = 0x63; // byte 0110 0011
    const AES_SBOX_MATRIX: i64 = 0xf1e3_c78f_1f3e_7cf8u64 as i64;

    let word = if ROTATE {
        // RotWord rotates the bytes within each packed 32-bit key word.
        _mm256_shuffle_epi8(
            word,
            _mm256_setr_epi8(
                1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4, 9,
                10, 11, 8, 13, 14, 15, 12,
            ),
        )
    } else {
        word
    };
    _mm256_gf2p8affineinv_epi64_epi8::<AES_SBOX_CONSTANT>(word, _mm256_set1_epi64x(AES_SBOX_MATRIX))
}

#[inline]
#[target_feature(enable = "avx2")]
fn expand_words<const N: usize>(previous: &[__m256i], assist: __m256i, rcon: i32) -> [__m256i; N] {
    // Fold Rcon into the prefix XOR so it can be applied independently of SubWord.
    let mut prefix = _mm256_set1_epi32(rcon);
    core::array::from_fn(|i| {
        prefix = _mm256_xor_si256(prefix, previous[i]);
        _mm256_xor_si256(prefix, assist)
    })
}

#[inline]
#[target_feature(enable = "avx2")]
fn store_round(keys: &mut RoundKeys, round: usize, pairs: [__m256i; 4]) {
    for (pair, dest) in pairs.into_iter().zip(&mut keys.0[round]) {
        // SAFETY: RoundKeys is 32-byte aligned, and each pair starts at a multiple of 32.
        unsafe { _mm256_store_si256(dest.as_mut_ptr().cast(), pair) };
    }
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn load_seed_pairs<const BYTES: usize, K: ArraySize>(
    seeds: [&Array<u8, K>; 8],
    offset: usize,
) -> [__m256i; 4] {
    const { assert!(matches!(BYTES, 8 | 16)) };
    core::array::from_fn(|pair| {
        let load = |lane: usize| {
            // SAFETY: The caller guarantees BYTES bytes are available at offset.
            unsafe {
                let ptr = seeds[lane].as_ptr().add(offset).cast();
                if BYTES == 8 {
                    _mm_loadl_epi64(ptr)
                } else {
                    _mm_loadu_si128(ptr)
                }
            }
        };
        _mm256_set_m128i(load(2 * pair + 1), load(2 * pair))
    })
}

#[inline]
#[target_feature(enable = "avx2,gfni")]
fn expand<const WORDS: usize, K: ArraySize>(seeds: [&Array<u8, K>; 8], keys: &mut RoundKeys) {
    assert!(K::USIZE == 4 * WORDS && matches!(WORDS, 4 | 6 | 8));
    let mut state = PackedState([_mm256_setzero_si256(); WORDS]);
    let words = &mut state.0;
    // SAFETY: All supported seeds have at least 16 bytes.
    let low = unsafe { load_seed_pairs::<16, K>(seeds, 0) };
    store_round(keys, 0, low);
    words[..4].copy_from_slice(&transpose(low));
    if WORDS == 6 {
        // SAFETY: AES-192 seeds have eight more bytes after the first 16.
        let high = unsafe { load_seed_pairs::<8, K>(seeds, 16) };
        words[4..].copy_from_slice(&transpose(high)[..2]);
    } else if WORDS == 8 {
        // SAFETY: AES-256 seeds have a second 16-byte block.
        let high = unsafe { load_seed_pairs::<16, K>(seeds, 16) };
        store_round(keys, 1, high);
        words[4..].copy_from_slice(&transpose(high));
    }

    if WORDS == 4 {
        for (step, rcon) in RCON.into_iter().enumerate() {
            let next = expand_words::<4>(words, schedule_assist::<true>(words[3]), rcon);
            store_round(keys, step + 1, transpose(next));
            words.copy_from_slice(&next);
        }
    } else if WORDS == 6 {
        // Two six-word schedule steps span three four-word round keys.
        for (step, rcon) in RCON[..8].chunks_exact(2).enumerate() {
            let round = 3 * step + 1;
            let [a, b, c, d, e, f] =
                expand_words::<6>(words, schedule_assist::<true>(words[5]), rcon[0]);
            store_round(keys, round, transpose([words[4], words[5], a, b]));
            store_round(keys, round + 1, transpose([c, d, e, f]));
            let current = [a, b, c, d, e, f];
            let assist = schedule_assist::<true>(f);
            if round + 2 == 12 {
                store_round(
                    keys,
                    round + 2,
                    transpose(expand_words::<4>(&current, assist, rcon[1])),
                );
            } else {
                let [a, b, c, d, e, f] = expand_words::<6>(&current, assist, rcon[1]);
                store_round(keys, round + 2, transpose([a, b, c, d]));
                words.copy_from_slice(&[a, b, c, d, e, f]);
            }
        }
    } else {
        for round in 2..=14 {
            let (offset, assist, rcon) = if round % 2 == 0 {
                (0, schedule_assist::<true>(words[7]), RCON[round / 2 - 1])
            } else {
                (4, schedule_assist::<false>(words[3]), 0)
            };
            let current = &mut words[offset..][..4];
            let next = expand_words::<4>(current, assist, rcon);
            store_round(keys, round, transpose(next));
            current.copy_from_slice(&next);
        }
    }
}

pub(super) struct Prg8<K> {
    keys: RoundKeys,
    counters: [IV; 8],
    tail: Option<BufferedTile>,
    key_size: PhantomData<K>,
}

#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
struct BufferedTile {
    blocks: [[u8; 16]; 8],
    offset: usize,
}

#[target_feature(enable = "avx2,gfni")]
fn expand_keys<K: ArraySize>(seeds: [&Array<u8, K>; 8], keys: &mut RoundKeys) {
    match K::USIZE {
        16 => expand::<4, K>(seeds, keys),
        24 => expand::<6, K>(seeds, keys),
        32 => expand::<8, K>(seeds, keys),
        _ => unreachable!(),
    }
}

impl<K: ArraySize> Prg8<K> {
    #[inline]
    pub(super) fn new(iv: &IV, tweaks: [Twk; 8]) -> Self {
        Self {
            keys: RoundKeys([[[0; 32]; 4]; 15]),
            counters: tweaks.map(|tweak| add_tweak(iv, tweak)),
            tail: None,
            key_size: PhantomData,
        }
    }

    /// The caller has checked that `available()` is true.
    #[inline]
    pub(super) unsafe fn expand_keys(&mut self, seeds: [&Array<u8, K>; 8]) {
        // SAFETY: The caller checks the required CPU features.
        unsafe { expand_keys(seeds, &mut self.keys) };
    }

    /// The caller has checked CPU features.
    #[inline]
    pub(super) unsafe fn read_block(&mut self, dst: &mut [[u8; 16]; 8], active: u8) {
        // SAFETY: The caller checks CPU features. All destinations hold one block.
        unsafe {
            if self.tail.is_some() {
                self.read(dst.each_mut().map(<[u8; 16]>::as_mut_slice), active);
            } else {
                encrypt_contiguous::<K>(&self.keys, &mut self.counters, active, dst);
            }
        }
    }

    /// The caller has checked CPU features and equal destination lengths.
    #[inline]
    pub(super) unsafe fn read(&mut self, mut dst: [&mut [u8]; 8], active: u8) {
        let len = dst[0].len();
        let mut offset = 0;
        if let Some(tail) = &mut self.tail {
            offset = len.min(16 - tail.offset);
            for (lane, dest) in dst.iter_mut().enumerate() {
                dest[..offset].copy_from_slice(&tail.blocks[lane][tail.offset..][..offset]);
            }
            tail.offset += offset;
            if tail.offset == 16 {
                self.tail = None;
            }
        }

        if len - offset >= 16 {
            let bases = &dst.each_mut().map(|lane| lane.as_mut_ptr());
            while len - offset >= 16 {
                // SAFETY: The caller checks CPU features. The equal-length,
                // disjoint destinations each have a full block at offset.
                unsafe {
                    encrypt_tile::<K, false>(&self.keys, &mut self.counters, active, move |lane| {
                        bases[lane].add(offset)
                    });
                }
                offset += 16;
            }
        }
        if offset != len {
            let used = len - offset;
            let tail = self.tail.insert(BufferedTile {
                blocks: [[0; 16]; 8],
                offset: used,
            });
            // SAFETY: The caller checks the required CPU features.
            unsafe {
                encrypt_contiguous::<K>(&self.keys, &mut self.counters, active, &mut tail.blocks);
            };
            for (dest, block) in dst.iter_mut().zip(&tail.blocks) {
                dest[offset..].copy_from_slice(&block[..used]);
            }
        }
    }
}

#[inline]
unsafe fn encrypt_contiguous<K: ArraySize>(
    keys: &RoundKeys,
    counters: &mut [IV; 8],
    active: u8,
    dst: &mut [[u8; 16]; 8],
) {
    let base = dst.as_mut_ptr().cast::<u8>();
    // SAFETY: The caller checks CPU features. The tile holds eight consecutive blocks.
    unsafe { encrypt_tile::<K, true>(keys, counters, active, move |lane| base.add(lane * 16)) };
}

// Keep the four pairs interleaved independently of how the caller uses the output.
#[inline(never)]
#[target_feature(enable = "avx2,vaes,aes")]
unsafe fn encrypt_tile<K: ArraySize, const CONTIGUOUS: bool>(
    keys: &RoundKeys,
    counters: &mut [IV; 8],
    active: u8,
    dest: impl Fn(usize) -> *mut u8,
) {
    let rounds = match K::USIZE {
        16 => 10,
        24 => 12,
        32 => 14,
        _ => unreachable!(),
    };
    // SAFETY: The round key pairs are 32-byte aligned. The counters are adjacent
    // 16-byte blocks. Each destination has 16 bytes, or 32 bytes per pair when
    // CONTIGUOUS is true, and the counter and destination accesses are unaligned.
    unsafe {
        let increment = _mm256_setr_epi32(1, 0, 0, 0, 1, 0, 0, 0);
        let mut blocks: [__m256i; 4] = core::array::from_fn(|pair| {
            let ptr = counters.as_mut_ptr().add(pair * 2).cast();
            let counter = _mm256_loadu_si256(ptr);
            _mm256_storeu_si256(ptr, _mm256_add_epi32(counter, increment));
            _mm256_xor_si256(counter, _mm256_load_si256(keys.0[0][pair].as_ptr().cast()))
        });
        for round in &keys.0[1..rounds] {
            for (block, pair) in blocks.iter_mut().zip(round) {
                *block = _mm256_aesenc_epi128(*block, _mm256_load_si256(pair.as_ptr().cast()));
            }
        }
        let active = _mm256_set1_epi32(i32::from(active));
        for (pair, (block, key)) in blocks.into_iter().zip(&keys.0[rounds]).enumerate() {
            let block = _mm256_aesenclast_epi128(block, _mm256_load_si256(key.as_ptr().cast()));
            let lane = pair * 2;
            let even = 1 << lane;
            let odd = 2 << lane;
            let bits = _mm256_setr_epi32(even, even, even, even, odd, odd, odd, odd);
            let inactive =
                _mm256_cmpeq_epi32(_mm256_and_si256(active, bits), _mm256_setzero_si256());
            let block = _mm256_andnot_si256(inactive, block);
            if CONTIGUOUS {
                _mm256_storeu_si256(dest(lane).cast(), block);
            } else {
                _mm_storeu_si128(dest(lane).cast(), _mm256_castsi256_si128(block));
                _mm_storeu_si128(dest(lane + 1).cast(), _mm256_extracti128_si256::<1>(block));
            }
        }
    }
}
