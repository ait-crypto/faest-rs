//! Encryption-only AES expansion in two groups of four packed keys.

use super::{IV, Twk};
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use hybrid_array::{Array, ArraySize};

cpufeatures::new!(caps, "aes", "sse2", "ssse3");

pub(super) fn available() -> bool {
    caps::get()
}

#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
#[repr(align(16))]
struct RoundKeys([[[u8; 16]; 8]; 15]);

// Each vector holds one word from each of four independent keys.
struct PackedState<const WORDS: usize>([[__m128i; WORDS]; 2]);

#[cfg(feature = "zeroize")]
impl<const WORDS: usize> Drop for PackedState<WORDS> {
    fn drop(&mut self) {
        use zeroize::Zeroize;

        // SAFETY: The nested arrays and the vectors have no padding. The entire
        // buffer consists of initialized bytes and is aligned for u64.
        let words = unsafe {
            core::slice::from_raw_parts_mut(self.0.as_mut_ptr().cast::<u64>(), 4 * WORDS)
        };
        words.zeroize();
    }
}

const RCON: [i32; 10] = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54];

#[inline]
#[target_feature(enable = "sse2")]
fn transpose([a, b, c, d]: [__m128i; 4]) -> [__m128i; 4] {
    let ab_lo = _mm_unpacklo_epi32(a, b);
    let ab_hi = _mm_unpackhi_epi32(a, b);
    let cd_lo = _mm_unpacklo_epi32(c, d);
    let cd_hi = _mm_unpackhi_epi32(c, d);
    [
        _mm_unpacklo_epi64(ab_lo, cd_lo),
        _mm_unpackhi_epi64(ab_lo, cd_lo),
        _mm_unpacklo_epi64(ab_hi, cd_hi),
        _mm_unpackhi_epi64(ab_hi, cd_hi),
    ]
}

#[inline]
#[target_feature(enable = "aes,sse2,ssse3")]
fn schedule_assist<const ROTATE: bool>(word: __m128i, rcon: i32) -> __m128i {
    // Pre-permute the bytes to cancel AESENCLAST's ShiftRows. Fold RotWord
    // into the same shuffle for the steps that use a round constant.
    let shuffle = if ROTATE {
        _mm_setr_epi8(1, 14, 11, 4, 5, 2, 15, 8, 9, 6, 3, 12, 13, 10, 7, 0)
    } else {
        _mm_setr_epi8(0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3)
    };
    _mm_aesenclast_si128(_mm_shuffle_epi8(word, shuffle), _mm_set1_epi32(rcon))
}

#[inline]
#[target_feature(enable = "sse2")]
fn expand_words<const N: usize>(previous: &[__m128i], assist: __m128i) -> [__m128i; N] {
    let mut prefix = _mm_setzero_si128();
    core::array::from_fn(|i| {
        prefix = _mm_xor_si128(prefix, previous[i]);
        _mm_xor_si128(prefix, assist)
    })
}

#[inline]
#[target_feature(enable = "sse2")]
fn store_round(dest: &mut [[u8; 16]], packed: [__m128i; 4]) {
    for (key, dest) in transpose(packed).into_iter().zip(dest) {
        // SAFETY: Each destination is a full 16-byte block.
        unsafe { _mm_storeu_si128(dest.as_mut_ptr().cast(), key) };
    }
}

#[inline]
#[target_feature(enable = "aes,sse2,ssse3")]
fn expand<const WORDS: usize, K: ArraySize>(seeds: [&Array<u8, K>; 8], keys: &mut RoundKeys) {
    assert!(K::USIZE == 4 * WORDS && matches!(WORDS, 4 | 6 | 8));
    let mut state = PackedState([[_mm_setzero_si128(); WORDS]; 2]);
    for (group, words) in state.0.iter_mut().enumerate() {
        let first = group * 4;
        // SAFETY: The size check above guarantees that all seeds have
        // 16 initial bytes, followed by eight or sixteen when needed.
        unsafe {
            let low =
                core::array::from_fn(|lane| _mm_loadu_si128(seeds[first + lane].as_ptr().cast()));
            words[..4].copy_from_slice(&transpose(low));
            if WORDS == 6 {
                let high: [__m128i; 4] = core::array::from_fn(|lane| {
                    _mm_loadl_epi64(seeds[first + lane].as_ptr().add(16).cast())
                });
                words[4..].copy_from_slice(&transpose(high)[..2]);
            } else if WORDS == 8 {
                let high = core::array::from_fn(|lane| {
                    _mm_loadu_si128(seeds[first + lane].as_ptr().add(16).cast())
                });
                words[4..].copy_from_slice(&transpose(high));
            }
        }
    }

    if WORDS == 4 {
        for (step, rcon) in RCON.into_iter().enumerate() {
            for (group, words) in state.0.iter_mut().enumerate() {
                let next = expand_words::<4>(words, schedule_assist::<true>(words[3], rcon));
                words.copy_from_slice(&next);
                store_round(&mut keys.0[step + 1][group * 4..][..4], next);
            }
        }
    } else if WORDS == 6 {
        for (step, rcon) in RCON[..8].iter().copied().enumerate() {
            for (group, words) in state.0.iter_mut().enumerate() {
                let assist = schedule_assist::<true>(words[5], rcon);
                let first = group * 4;
                if step % 2 == 0 {
                    let [a, b, c, d, e, f] = expand_words::<6>(words, assist);
                    let round = step / 2 * 3 + 1;
                    store_round(&mut keys.0[round][first..][..4], [words[4], words[5], a, b]);
                    store_round(&mut keys.0[round + 1][first..][..4], [c, d, e, f]);
                    words.copy_from_slice(&[a, b, c, d, e, f]);
                } else {
                    let round = (step / 2 + 1) * 3;
                    if step == 7 {
                        let next = expand_words::<4>(words, assist);
                        store_round(&mut keys.0[round][first..][..4], next);
                    } else {
                        let [a, b, c, d, e, f] = expand_words::<6>(words, assist);
                        store_round(&mut keys.0[round][first..][..4], [a, b, c, d]);
                        words.copy_from_slice(&[a, b, c, d, e, f]);
                    }
                }
            }
        }
    } else {
        for round in 2..=14 {
            for (group, words) in state.0.iter_mut().enumerate() {
                let (offset, assist) = if round % 2 == 0 {
                    (0, schedule_assist::<true>(words[7], RCON[round / 2 - 1]))
                } else {
                    (4, schedule_assist::<false>(words[3], 0))
                };
                let current = &mut words[offset..][..4];
                let next = expand_words::<4>(current, assist);
                current.copy_from_slice(&next);
                store_round(&mut keys.0[round][group * 4..][..4], next);
            }
        }
    }
}

/// Caller checks AES, SSE2 and SSSE3 once before entering.
#[target_feature(enable = "aes,sse2,ssse3")]
pub(super) unsafe fn generate<K: ArraySize>(
    seeds: [&Array<u8, K>; 8],
    iv: &IV,
    tweaks: [Twk; 8],
    active: u8,
    len: usize,
    mut consume: impl FnMut(usize, usize, &[[u8; 16]; 8]),
) {
    let mut keys = RoundKeys([[[0; 16]; 8]; 15]);
    for lane in 0..8 {
        keys.0[0][lane].copy_from_slice(&seeds[lane][..16]);
    }
    let rounds = match K::USIZE {
        16 => {
            expand::<4, K>(seeds, &mut keys);
            10
        }
        24 => {
            expand::<6, K>(seeds, &mut keys);
            12
        }
        32 => {
            for lane in 0..8 {
                keys.0[1][lane].copy_from_slice(&seeds[lane][16..]);
            }
            expand::<8, K>(seeds, &mut keys);
            14
        }
        _ => unreachable!(),
    };
    // SAFETY: AES/SSE2 are covered by the entry point's runtime check.
    unsafe {
        let mut counters = [*iv; 8];
        for lane in 0..8 {
            counters[lane] = super::add_tweak(iv, tweaks[lane]);
        }
        let mut offset = 0;
        while len - offset >= 16 {
            let tile = match rounds {
                10 => encrypt_tile::<10>(&keys, &mut counters, active),
                12 => encrypt_tile::<12>(&keys, &mut counters, active),
                14 => encrypt_tile::<14>(&keys, &mut counters, active),
                _ => unreachable!(),
            };
            consume(offset, 16, &tile);
            offset += 16;
        }
        if offset < len {
            let valid = len - offset;
            let mut tile = match rounds {
                10 => encrypt_tile::<10>(&keys, &mut counters, active),
                12 => encrypt_tile::<12>(&keys, &mut counters, active),
                14 => encrypt_tile::<14>(&keys, &mut counters, active),
                _ => unreachable!(),
            };
            for lane in &mut tile {
                lane[valid..].fill(0);
            }
            consume(offset, valid, &tile);
        }
    }
}

// A separate full-tile loop makes the consumer's length constant. In particular,
// it prevents memcpy/memset calls for each column of every complete VOLE tile.
// Keep encryption out of line so LLVM cannot split the eight interleaved
// streams into smaller groups according to the consumer's XOR dependencies.
#[inline(never)]
#[target_feature(enable = "aes,sse2")]
unsafe fn encrypt_tile<const ROUNDS: usize>(
    keys: &RoundKeys,
    counters: &mut [IV; 8],
    active: u8,
) -> [[u8; 16]; 8] {
    // SAFETY: RoundKeys and all its blocks are aligned; counters and tile each
    // hold eight complete blocks and use unaligned loads/stores.
    unsafe {
        let mut blocks: [__m128i; 8] = core::array::from_fn(|lane| {
            let counter = _mm_loadu_si128(counters[lane].as_ptr().cast());
            _mm_storeu_si128(
                counters[lane].as_mut_ptr().cast(),
                _mm_add_epi32(counter, _mm_set_epi32(0, 0, 0, 1)),
            );
            _mm_xor_si128(counter, _mm_load_si128(keys.0[0][lane].as_ptr().cast()))
        });
        for round in 1..ROUNDS {
            for lane in 0..8 {
                blocks[lane] = _mm_aesenc_si128(
                    blocks[lane],
                    _mm_load_si128(keys.0[round][lane].as_ptr().cast()),
                );
            }
        }
        let mut tile = [[0; 16]; 8];
        for lane in 0..8 {
            let block = _mm_aesenclast_si128(
                blocks[lane],
                _mm_load_si128(keys.0[ROUNDS][lane].as_ptr().cast()),
            );
            let mask = _mm_set1_epi8(-(((active >> lane) & 1) as i8));
            _mm_storeu_si128(tile[lane].as_mut_ptr().cast(), _mm_and_si128(block, mask));
        }
        tile
    }
}
