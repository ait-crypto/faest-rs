/*
Based on the KeccakP-1600-times4 implementation from:

The eXtended Keccak Code Package (XKCP)
<https://github.com/XKCP/XKCP/tree/master/lib/low/KeccakP-1600-times4/AVX2>.

The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Gilles Van Assche and Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

pub(super) fn available() -> bool {
    is_x86_feature_detected!("avx2")
}

// The word-major layout stays packed throughout absorption and squeezing.
#[derive(Clone)]
pub(crate) struct Sponge<const RATE: usize> {
    state: [[u64; 4]; 25],
    pos: usize,
}

impl<const RATE: usize> Default for Sponge<RATE> {
    fn default() -> Self {
        Self {
            state: [[0; 4]; 25],
            pos: 0,
        }
    }
}

impl<const RATE: usize> Sponge<RATE> {
    fn permute(&mut self) {
        // SAFETY: this variant is constructed only after runtime AVX2 detection
        unsafe {
            keccak_p1600_times4_avx2(&mut self.state);
        }
    }

    pub(super) fn update(&mut self, data: [&[u8]; 4]) {
        let mut offset = 0;
        while offset < data[0].len() {
            let count = (RATE - self.pos).min(data[0].len() - offset);
            let mut j = 0;
            while j < count {
                let p = self.pos + j;
                if p.is_multiple_of(8) && count - j >= 8 {
                    for lane in 0..4 {
                        self.state[p / 8][lane] ^= u64::from_le_bytes(
                            data[lane][offset + j..offset + j + 8].try_into().unwrap(),
                        );
                    }
                    j += 8;
                } else {
                    for lane in 0..4 {
                        self.state[p / 8][lane] ^= (data[lane][offset + j] as u64) << (8 * (p % 8));
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
            self.state[self.pos / 8][lane] ^= 0x1f << (8 * (self.pos % 8));
            self.state[RATE / 8 - 1][lane] ^= 1 << 63;
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
                d[offset] = (self.state[self.pos / 8][lane] >> (8 * (self.pos % 8))) as u8;
            }
            self.pos += 1;
        }
    }
}

const F1600_ROUND_CONSTANT: [u64; 24] = [
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

// Indexed by the source word, x + 5 * y.
#[rustfmt::skip]
    const RHO_OFFSETS: [i32; 25] = [
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    ];

#[inline]
#[target_feature(enable = "avx2")]
fn rotate_words(word: __m256i, bits: i32) -> __m256i {
    if bits == 0 {
        return word;
    }
    _mm256_or_si256(
        _mm256_sll_epi64(word, _mm_cvtsi32_si128(bits)),
        _mm256_srl_epi64(word, _mm_cvtsi32_si128(64 - bits)),
    )
}

#[inline]
#[target_feature(enable = "avx2")]
fn theta_column_parities(state: &[__m256i; 25]) -> [__m256i; 5] {
    core::array::from_fn(|x| {
        _mm256_xor_si256(
            _mm256_xor_si256(state[x], state[x + 5]),
            _mm256_xor_si256(
                _mm256_xor_si256(state[x + 10], state[x + 15]),
                state[x + 20],
            ),
        )
    })
}

#[inline]
#[target_feature(enable = "avx2")]
fn theta_corrections(parities: &[__m256i; 5]) -> [__m256i; 5] {
    core::array::from_fn(|x| {
        _mm256_xor_si256(
            parities[(x + 4) % 5],
            rotate_words(parities[(x + 1) % 5], 1),
        )
    })
}

#[inline]
#[target_feature(enable = "avx2")]
fn rho_pi_word<const X: usize, const Y: usize>(
    state: &[__m256i; 25],
    theta: &[__m256i; 5],
) -> __m256i {
    // Invert pi: destination (X, Y) came from ((X + 3 * Y) % 5, X).
    let source_x = (X + 3 * Y) % 5;
    let source = source_x + 5 * X;
    let corrected = _mm256_xor_si256(state[source], theta[source_x]);
    rotate_words(corrected, RHO_OFFSETS[source])
}

#[inline]
#[target_feature(enable = "avx2")]
fn chi_word(word: __m256i, next: __m256i, after_next: __m256i) -> __m256i {
    _mm256_xor_si256(word, _mm256_andnot_si256(next, after_next))
}

#[inline]
#[target_feature(enable = "avx2")]
fn round_row<const Y: usize>(state: &[__m256i; 25], theta: &[__m256i; 5]) -> [__m256i; 5] {
    // Start chi as soon as its three inputs are ready, then finish the wraparound words.
    let b0 = rho_pi_word::<0, Y>(state, theta);
    let b1 = rho_pi_word::<1, Y>(state, theta);
    let b2 = rho_pi_word::<2, Y>(state, theta);
    let word0 = chi_word(b0, b1, b2);
    let b3 = rho_pi_word::<3, Y>(state, theta);
    let word1 = chi_word(b1, b2, b3);
    let b4 = rho_pi_word::<4, Y>(state, theta);
    [
        word0,
        word1,
        chi_word(b2, b3, b4),
        chi_word(b3, b4, b0),
        chi_word(b4, b0, b1),
    ]
}

#[inline]
#[target_feature(enable = "avx2")]
fn write_round_row<const Y: usize, const PREPARE_NEXT: bool>(
    state: &[__m256i; 25],
    theta: &[__m256i; 5],
    output: &mut [__m256i; 25],
    parities: &mut [__m256i; 5],
    round_constant: u64,
) {
    let mut row = round_row::<Y>(state, theta);
    if Y == 0 {
        // Iota changes word (0, 0) before it contributes to the next theta.
        row[0] = _mm256_xor_si256(row[0], _mm256_set1_epi64x(round_constant as i64));
    }
    output[5 * Y..5 * Y + 5].copy_from_slice(&row);

    if PREPARE_NEXT {
        if Y == 0 {
            *parities = row;
        } else {
            for (parity, word) in parities.iter_mut().zip(row) {
                *parity = _mm256_xor_si256(*parity, word);
            }
        }
    }
}

#[inline]
#[target_feature(enable = "avx2")]
fn keccak_round<const PREPARE_NEXT: bool>(
    state: &[__m256i; 25],
    output: &mut [__m256i; 25],
    parities: &mut [__m256i; 5],
    round_constant: u64,
) {
    // All five corrections must use the input parities before the rows replace them.
    let theta = theta_corrections(parities);
    write_round_row::<0, PREPARE_NEXT>(state, &theta, output, parities, round_constant);
    write_round_row::<1, PREPARE_NEXT>(state, &theta, output, parities, round_constant);
    write_round_row::<2, PREPARE_NEXT>(state, &theta, output, parities, round_constant);
    write_round_row::<3, PREPARE_NEXT>(state, &theta, output, parities, round_constant);
    write_round_row::<4, PREPARE_NEXT>(state, &theta, output, parities, round_constant);
}

#[target_feature(enable = "avx2")]
unsafe fn keccak_p1600_times4_avx2(state: &mut [[u64; 4]; 25]) {
    let mut current = core::array::from_fn(|i| {
        // SAFETY: each word contains exactly 32 initialized bytes.
        unsafe { _mm256_loadu_si256(state[i].as_ptr().cast()) }
    });
    let mut next = [_mm256_setzero_si256(); 25];
    let mut parities = theta_column_parities(&current);

    // Alternate the input and output buffers, with parity carried between rounds.
    let (earlier_rounds, final_pair) = F1600_ROUND_CONSTANT.split_last_chunk::<2>().unwrap();
    let (pairs, _) = earlier_rounds.as_chunks::<2>();
    for &[first, second] in pairs {
        keccak_round::<true>(&current, &mut next, &mut parities, first);
        keccak_round::<true>(&next, &mut current, &mut parities, second);
    }
    keccak_round::<true>(&current, &mut next, &mut parities, final_pair[0]);
    keccak_round::<false>(&next, &mut current, &mut parities, final_pair[1]);

    for (word, value) in state.iter_mut().zip(current) {
        // SAFETY: each destination word has space for all four lanes.
        unsafe { _mm256_storeu_si256(word.as_mut_ptr().cast(), value) };
    }
}
