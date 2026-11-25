use crate::{
    random_oracles::{Hasher, Hasher4},
    utils::{Reader, Reader4},
};

#[cfg(all(feature = "opt-batch", any(target_arch = "x86", target_arch = "x86_64")))]
#[path = "avx2/keccak.rs"]
mod avx2;

#[allow(
    clippy::large_enum_variant,
    reason = "Clippy treats T as zero-sized but both SHAKE backends hold four Keccak states"
)]
#[derive(Clone)]
pub(crate) enum ShakeTimes4<T, const RATE: usize, const SEP: u8> {
    Scalar([T; 4]),
    #[cfg(all(feature = "opt-batch", any(target_arch = "x86", target_arch = "x86_64")))]
    Avx2(avx2::Sponge<RATE>),
}

impl<H: Hasher + Clone + Default, const RATE: usize, const SEP: u8> Default
    for ShakeTimes4<H, RATE, SEP>
{
    fn default() -> Self {
        #[cfg(all(feature = "opt-batch", any(target_arch = "x86", target_arch = "x86_64")))]
        if avx2::available() {
            return Self::Avx2(avx2::Sponge::default());
        }
        Self::Scalar(core::array::from_fn(|_| H::default()))
    }
}

impl<H: Hasher + Clone, const RATE: usize, const SEP: u8> Hasher4 for ShakeTimes4<H, RATE, SEP> {
    type Reader = ShakeTimes4<H::Reader, RATE, SEP>;

    fn update(&mut self, data: [&[u8]; 4]) {
        assert!(
            data.iter().all(|s| s.len() == data[0].len()),
            "unequal SHAKE input lengths"
        );
        match self {
            // fallback to sequential update
            Self::Scalar(hashers) => {
                for (h, d) in hashers.iter_mut().zip(data) {
                    h.update(d);
                }
            }

            #[cfg(all(feature = "opt-batch", any(target_arch = "x86", target_arch = "x86_64")))]
            Self::Avx2(s) => s.update(data),
        }
    }

    fn finish(self) -> Self::Reader {
        match self {
            Self::Scalar(h) => ShakeTimes4::Scalar(h.map(Hasher::finish)),
            #[cfg(all(feature = "opt-batch", any(target_arch = "x86", target_arch = "x86_64")))]
            Self::Avx2(mut s) => {
                s.update([[SEP].as_ref(); 4]);
                s.pad();
                ShakeTimes4::Avx2(s)
            }
        }
    }
}

impl<R: Reader, const RATE: usize, const SEP: u8> Reader4 for ShakeTimes4<R, RATE, SEP> {
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
            #[cfg(all(feature = "opt-batch", any(target_arch = "x86", target_arch = "x86_64")))]
            Self::Avx2(s) => s.read(dst),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        random_oracles::{Hasher128, Hasher256},
        shake4::ShakeTimes4,
    };
    #[cfg(not(feature = "std"))]
    use alloc::{vec, vec::Vec};
    use hybrid_array::sizes::U200;

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
                let mut four = ShakeTimes4::<H, RATE, SEP>::default();
                let mut scalar =
                    ShakeTimes4::<H, RATE, SEP>::Scalar(core::array::from_fn(|_| H::default()));
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
            let mut four = ShakeTimes4::<H, RATE, SEP>::default();
            let mut scalar =
                ShakeTimes4::<H, RATE, SEP>::Scalar(core::array::from_fn(|_| H::default()));
            four.update(inputs.each_ref().map(|s| s.as_slice()));
            scalar.update(inputs.each_ref().map(|s| s.as_slice()));
            let actual = four.finish().read_into::<U200>();
            let mut expected = [[0; 200]; 4];
            scalar
                .finish()
                .read(expected.each_mut().map(|s| s.as_mut_slice()));
            assert_eq!(actual.map(|digest| digest.0), expected);
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
        ShakeTimes4::<Hasher128<1>, 168, 1>::default().update([b"a", b"", b"a", b"a"]);
    }

    #[test]
    #[should_panic(expected = "unequal SHAKE output lengths")]
    fn rejects_unsynchronized_reads() {
        ShakeTimes4::<Hasher256<1>, 136, 1>::default()
            .finish()
            .read([&mut [0; 1], &mut [], &mut [0; 1], &mut [0; 1]]);
    }
}
