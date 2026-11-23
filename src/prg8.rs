//! AES expansion and CTR encryption for eight streams using 256-bit vectors
use hybrid_array::Array;

use crate::{
    prg::{IV, PseudoRandomGenerator, Twk},
    utils::Reader8,
};

#[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
#[path = "avx2/prg.rs"]
mod avx2;

pub(crate) fn batch_available() -> bool {
    #[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
    {
        avx2::available()
    }
    #[cfg(not(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64"))))]
    {
        false
    }
}

/// Owns the expanded keys and buffered output for one batch.
pub(crate) struct Prg8Storage<P: PseudoRandomGenerator> {
    state: Option<Prg8State<P>>,
}

impl<P: PseudoRandomGenerator> Prg8Storage<P> {
    #[inline]
    pub(crate) fn new() -> Self {
        Self { state: None }
    }
}

/// Eight independent CTR streams read in lockstep. Inactive lanes emit zeros.
pub(crate) struct Prg8<'a, P: PseudoRandomGenerator> {
    state: &'a mut Prg8State<P>,
    active: u8,
    remaining: u64,
}

#[allow(
    clippy::large_enum_variant,
    reason = "Clippy treats P as zero-sized but both SHAKE backends hold eight PRG states"
)]
enum Prg8State<P: PseudoRandomGenerator> {
    Scalar([P; 8]),
    #[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
    Optimized(avx2::Prg8<P::KeySize>),
}

// ctr::Ctr32LE accepts this many blocks from the initial nonce.
const PRG_STREAM_BYTES: u64 = u32::MAX as u64 * 16;

impl<'a, P: PseudoRandomGenerator> Prg8<'a, P> {
    #[inline]
    pub(crate) fn new(
        storage: &'a mut Prg8Storage<P>,
        seeds: [&Array<u8, P::KeySize>; 8],
        iv: &IV,
        tweaks: [Twk; 8],
        active: u8,
    ) -> Prg8<'a, P> {
        #[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
        if batch_available() {
            let state = storage
                .state
                .insert(Prg8State::Optimized(avx2::Prg8::new(iv, tweaks)));
            let Prg8State::Optimized(streams) = state else {
                unreachable!()
            };
            // SAFETY: The CPU check covers the batched backend's intrinsics
            unsafe { streams.expand_keys(seeds) };
            return Prg8 {
                state,
                active,
                remaining: PRG_STREAM_BYTES,
            };
        }

        // fallback
        let state = storage
            .state
            .insert(Prg8State::Scalar(core::array::from_fn(|i| {
                P::new_prg(seeds[i], iv, tweaks[i])
            })));
        Prg8 {
            state,
            active,
            remaining: PRG_STREAM_BYTES,
        }
    }
}

impl<P: PseudoRandomGenerator> Prg8<'_, P> {
    /// Read 16 bytes from each stream into a tile.
    #[inline]
    pub(crate) fn read_block(&mut self, dst: &mut [[u8; 16]; 8]) {
        self.advance(16);
        match self.state {
            Prg8State::Scalar(streams) => {
                Self::read_scalar(
                    streams,
                    dst.each_mut().map(<[u8; 16]>::as_mut_slice),
                    self.active,
                );
            }
            #[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
            Prg8State::Optimized(streams) => {
                // SAFETY: This variant is constructed after checking CPU features.
                unsafe { streams.read_block(dst, self.active) };
            }
        }
    }

    #[inline]
    fn advance(&mut self, len: u64) {
        assert!(len <= self.remaining, "end of PRG keystream reached");
        self.remaining -= len;
    }

    #[inline]
    fn read_scalar(streams: &mut [P; 8], dst: [&mut [u8]; 8], active: u8) {
        for (lane, (stream, dst)) in streams.iter_mut().zip(dst).enumerate() {
            dst.fill(0);
            if active & (1 << lane) != 0 {
                stream.read(dst);
            }
        }
    }
}

impl<P: PseudoRandomGenerator> Reader8 for Prg8<'_, P> {
    #[inline]
    fn read(&mut self, dst: [&mut [u8]; 8]) {
        let len = dst[0].len();
        assert!(
            dst.iter().all(|lane| lane.len() == len),
            "unequal PRG output lengths"
        );
        if len == 0 {
            return;
        }
        self.advance(len as u64);

        match self.state {
            Prg8State::Scalar(streams) => {
                Self::read_scalar(streams, dst, self.active);
            }
            #[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
            Prg8State::Optimized(streams) => {
                // SAFETY: This variant is constructed after checking CPU features.
                unsafe { streams.read(dst, self.active) };
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        prg::{IV, PRG128, PRG192, PRG256},
        utils::Reader,
    };
    use hybrid_array::{Array, typenum::Unsigned};

    fn bench<P: PseudoRandomGenerator>() {
        use std::hint::black_box;
        let keys: [Array<u8, P::KeySize>; 8] = core::array::from_fn(|lane| {
            let mut key = Array::default();
            key.fill(lane as u8);
            key
        });
        let iv = IV::default();
        let mut out = [[0; 1024]; 8];
        for len in [2 * P::KeySize::USIZE, 4 * P::KeySize::USIZE, 1024] {
            crate::bench_util::measure(
                &std::format!("PRG-{}/{len}/scalar", P::KeySize::USIZE * 8),
                || {
                    for lane in 0..8 {
                        out[lane][..len].fill(0);
                        P::new_prg(black_box(&keys[lane]), &iv, 0).read(&mut out[lane][..len]);
                    }
                    black_box(&out);
                },
            );
            crate::bench_util::measure(
                &std::format!("PRG-{}/{len}/batch", P::KeySize::USIZE * 8),
                || {
                    let mut storage = Prg8Storage::new();
                    P::new_prg8(
                        &mut storage,
                        black_box(core::array::from_fn(|i| &keys[i])),
                        &iv,
                        [0; 8],
                        0xff,
                    )
                    .read(out.each_mut().map(|lane| &mut lane[..len]));
                    black_box(&out);
                },
            );
        }
    }

    #[test]
    #[ignore = "component benchmark; run in release with fat LTO and fixed CPU affinity"]
    fn benchmark_batch_expansion() {
        bench::<PRG128>();
        bench::<PRG192>();
        bench::<PRG256>();
    }

    fn bench_parameter<P: crate::parameter::FAESTParameters>(name: &str) {
        use crate::bavc::BatchVectorCommitment;
        use std::hint::black_box;
        type G<P> = <<P as crate::parameter::FAESTParameters>::BAVC as BatchVectorCommitment>::PRG;
        let keys: [Array<u8, <G<P> as PseudoRandomGenerator>::KeySize>; 8] =
            core::array::from_fn(|lane| {
                let mut seed = Array::default();
                seed.fill(lane as u8);
                seed
            });
        let iv = IV::default();
        let mut out: [Array<u8, P::LHatBytes>; 8] = core::array::from_fn(|_| Array::default());
        crate::bench_util::measure(&std::format!("{name}/expand/scalar"), || {
            for lane in 0..8 {
                out[lane].fill(0);
                G::<P>::new_prg(black_box(&keys[lane]), &iv, 0).read(&mut out[lane]);
            }
            black_box(&out);
        });
        crate::bench_util::measure(&std::format!("{name}/expand/batch"), || {
            let mut storage = Prg8Storage::new();
            G::<P>::new_prg8(
                &mut storage,
                black_box(core::array::from_fn(|lane| &keys[lane])),
                &iv,
                [0; 8],
                0xff,
            )
            .read(out.each_mut().map(Array::as_mut_slice));
            black_box(&out);
        });
    }

    #[test]
    #[ignore = "component benchmark; run in release with fat LTO and fixed CPU affinity"]
    fn benchmark_parameter_expansion() {
        use crate::parameter::*;
        macro_rules! run { ($($p:ty),*) => { $(bench_parameter::<$p>(stringify!($p));)* }; }
        run!(
            FAEST128fParameters,
            FAEST128sParameters,
            FAEST192fParameters,
            FAEST192sParameters,
            FAEST256fParameters,
            FAEST256sParameters,
            FAESTEM128fParameters,
            FAESTEM128sParameters,
            FAESTEM192fParameters,
            FAESTEM192sParameters,
            FAESTEM256fParameters,
            FAESTEM256sParameters
        );
    }

    fn differential<P: PseudoRandomGenerator>() {
        #[repr(align(16))]
        struct Destination([u8; 151]);

        let seeds: [Array<u8, P::KeySize>; 8] = core::array::from_fn(|lane| {
            let mut key = Array::default();
            for (byte, value) in key.iter_mut().enumerate() {
                *value = (lane as u8).wrapping_mul(71).wrapping_add(byte as u8 * 3);
            }
            key
        });
        for iv in [IV::default(), IV::from([0xff; 16])] {
            let tweaks = [0, 1, 2, u32::MAX, u32::MAX - 1, 0x8000_0000, 127, 42];
            // Exhaustive masks and lengths on either side of blocks and seed boundaries.
            for active in 0..=255 {
                for len in [0, 1, 15, 16, 17, 23, 24, 25, 31, 32, 33, 48, 64, 135] {
                    let mut actual = [[0xa5; 135]; 8];
                    let seeds_ref = seeds.each_ref();
                    {
                        let mut storage = Prg8Storage::new();
                        P::new_prg8(&mut storage, seeds_ref, &iv, tweaks, active)
                            .read(actual.each_mut().map(|lane| &mut lane[..len]));
                    }

                    // Separate, aligned backing arrays with a different odd offset per lane.
                    let mut split = [const { Destination([0xa5; 151]) }; 8];
                    let mut offsets = (1..16).step_by(2);
                    let mut split_dst = split.each_mut().map(|lane| {
                        let offset = offsets.next().unwrap();
                        &mut lane.0[offset..offset + len]
                    });
                    let mut storage = Prg8Storage::new();
                    let mut prg = P::new_prg8(&mut storage, seeds_ref, &iv, tweaks, active);
                    let mut start = 0;
                    // For the longest read, 25..73 drains seven buffered bytes,
                    // writes two complete blocks, then buffers a new partial block.
                    for end in [0, 1, 16, 24, 25, 73, len] {
                        let end = end.min(len);
                        prg.read(split_dst.each_mut().map(|lane| &mut lane[start..end]));
                        start = end;
                    }
                    for lane in 0..8 {
                        let mut expected = [0; 135];
                        if active & (1 << lane) != 0 {
                            P::new_prg(&seeds[lane], &iv, tweaks[lane]).read(&mut expected[..len]);
                        }
                        assert_eq!(
                            actual[lane][..len],
                            expected[..len],
                            "lane={lane}, mask={active}, len={len}"
                        );
                        assert!(actual[lane][len..].iter().all(|&x| x == 0xa5));
                        let offset = 2 * lane + 1;
                        let split_lane = &split[lane].0;
                        assert_eq!(
                            split_lane[offset..offset + len],
                            expected[..len],
                            "split read: lane={lane}, mask={active}, len={len}"
                        );
                        assert!(split_lane[..offset].iter().all(|&x| x == 0xa5));
                        assert!(split_lane[offset + len..].iter().all(|&x| x == 0xa5));
                    }
                }

                let mut storage = Prg8Storage::new();
                let mut prg = P::new_prg8(&mut storage, seeds.each_ref(), &iv, tweaks, active);
                let mut expected = [[0xa5; 49]; 8];
                {
                    let mut storage = Prg8Storage::new();
                    P::new_prg8(&mut storage, seeds.each_ref(), &iv, tweaks, active)
                        .read(expected.each_mut().map(<[u8; 49]>::as_mut_slice));
                }
                let mut tile = [[0xa5; 16]; 8];
                prg.read_block(&mut tile);
                assert_eq!(
                    tile,
                    expected.map(|lane| *lane.first_chunk::<16>().unwrap())
                );
                let mut byte = [[0xa5; 1]; 8];
                prg.read(byte.each_mut().map(<[u8; 1]>::as_mut_slice));
                assert_eq!(byte, expected.map(|lane| [lane[16]]));
                for offset in [17, 33] {
                    prg.read_block(&mut tile);
                    assert_eq!(
                        tile,
                        expected.map(|lane| *lane[offset..].first_chunk::<16>().unwrap())
                    );
                }
            }
        }
    }

    #[test]
    fn batch_matches_scalar() {
        differential::<PRG128>();
        differential::<PRG192>();
        differential::<PRG256>();
    }

    #[test]
    fn batch_rejects_invalid_reads_before_advancing() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let seed = Array::default();
        let iv = IV::default();
        let mut storage = Prg8Storage::new();
        let mut prg = PRG128::new_prg8(&mut storage, [&seed; 8], &iv, [0; 8], 0xff);
        let mut dst = [[0xa5; 2]; 8];

        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let [a, b, c, d, e, f, g, h] = &mut dst;
                prg.read([a, b, c, d, e, f, g, &mut h[..1]]);
            }))
            .is_err()
        );
        assert_eq!(dst, [[0xa5; 2]; 8]);
        assert_eq!(prg.remaining, PRG_STREAM_BYTES);

        prg.remaining = 1;
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                prg.read(dst.each_mut().map(|lane| lane.as_mut_slice()));
            }))
            .is_err()
        );
        assert_eq!(dst, [[0xa5; 2]; 8]);
        assert_eq!(prg.remaining, 1);

        let expected = PRG128::new_prg(&seed, &iv, 0).read_into::<hybrid_array::typenum::U1>();
        assert_eq!(prg.read_into::<hybrid_array::typenum::U1>(), [expected; 8]);
    }
}
