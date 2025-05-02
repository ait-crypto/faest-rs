use std::ops::Mul;

use generic_array::{
    ArrayLength, GenericArray,
    typenum::{U4, U8, marker_traits::Unsigned},
};
use itertools::izip;

use crate::{
    aes::{
        AddRoundKey, AddRoundKeyAssign, AddRoundKeyBytes, BytewiseMixColumns, InverseAffine,
        InverseShiftRows, MixColumns, SBoxAffine, ShiftRows, StateToBytes,
    },
    fields::{
        BigGaloisField, ByteCombine, ByteCombineConstants, ByteCombineSquaredConstants, Sigmas,
        Square,
    },
    parameter::{OWFField, OWFParameters},
    verifier::{VoleCommits, VoleCommitsRef},
};

impl<O> StateToBytes<O> for VoleCommits<'_, OWFField<O>, O::NSTBits>
where
    O: OWFParameters,
{
    type Output = GenericArray<OWFField<O>, O::NSTBytes>;

    fn state_to_bytes(&self) -> Self::Output {
        (0..O::NSTBytes::USIZE)
            .map(|i| OWFField::<O>::byte_combine_slice(&self.scalars[8 * i..8 * i + 8]))
            .collect()
    }
}

impl<O> StateToBytes<O> for VoleCommitsRef<'_, OWFField<O>, O::NSTBits>
where
    O: OWFParameters,
{
    type Output = GenericArray<OWFField<O>, O::NSTBytes>;

    fn state_to_bytes(&self) -> Self::Output {
        (0..O::NSTBytes::USIZE)
            .map(|i| OWFField::<O>::byte_combine_slice(&self.scalars[8 * i..8 * i + 8]))
            .collect()
    }
}

impl<'a, F, L> AddRoundKey<Self> for &VoleCommits<'a, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    type Output = VoleCommits<'a, F, L>;

    fn add_round_key(&self, rhs: Self) -> Self::Output {
        Self::Output {
            scalars: self
                .scalars
                .iter()
                .zip(rhs.scalars.iter())
                .map(|(x, y)| *x + y)
                .collect(),

            delta: self.delta,
        }
    }
}

impl<'a, F, L> AddRoundKey<&VoleCommits<'a, F, L>> for VoleCommitsRef<'a, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    type Output = VoleCommits<'a, F, L>;

    fn add_round_key(&self, rhs: &VoleCommits<'a, F, L>) -> Self::Output {
        Self::Output {
            scalars: self
                .scalars
                .iter()
                .zip(rhs.scalars.iter())
                .map(|(x, y)| *x + y)
                .collect(),

            delta: self.delta,
        }
    }
}

impl<'a, F, L> AddRoundKey<&Self> for VoleCommitsRef<'a, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    type Output = VoleCommits<'a, F, L>;

    fn add_round_key(&self, rhs: &Self) -> Self::Output {
        Self::Output {
            scalars: self
                .scalars
                .iter()
                .zip(rhs.scalars.iter())
                .map(|(x, y)| *x + y)
                .collect(),

            delta: self.delta,
        }
    }
}

impl<'a, F, L> AddRoundKey<&GenericArray<F, L>> for VoleCommitsRef<'a, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    type Output = VoleCommits<'a, F, L>;

    fn add_round_key(&self, rhs: &GenericArray<F, L>) -> Self::Output {
        Self::Output {
            scalars: self
                .scalars
                .iter()
                .zip(rhs.iter())
                .map(|(x, y)| *x + y)
                .collect(),

            delta: self.delta,
        }
    }
}

impl<'a, F, L, L2> AddRoundKey<&GenericArray<u8, L>> for VoleCommitsRef<'a, F, L2>
where
    F: BigGaloisField,
    L: ArrayLength + Mul<U8, Output = L2>,
    L2: ArrayLength,
{
    type Output = VoleCommits<'a, F, L2>;

    fn add_round_key(&self, rhs: &GenericArray<u8, L>) -> Self::Output {
        let scalars = self
            .scalars
            .into_iter()
            .enumerate()
            .map(|(i, comm_i)| {
                let scal_i = (rhs[i / 8] >> (i % 8)) & 1;
                if scal_i == 1 {
                    return *comm_i + self.delta;
                }
                *comm_i
            })
            .collect();

        VoleCommits {
            scalars,
            delta: self.delta,
        }
    }
}

impl<F, L> AddRoundKeyAssign<&Self> for VoleCommits<'_, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    fn add_round_key_assign(&mut self, rhs: &Self) {
        for (x, y) in izip!(self.scalars.iter_mut(), rhs.scalars.iter()) {
            *x += y;
        }
    }
}

impl<F, L> AddRoundKeyAssign<&VoleCommitsRef<'_, F, L>> for VoleCommits<'_, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    fn add_round_key_assign(&mut self, rhs: &VoleCommitsRef<'_, F, L>) {
        for (x, y) in izip!(self.scalars.iter_mut(), rhs.scalars.iter()) {
            *x += y;
        }
    }
}

impl<F, L> AddRoundKeyAssign<&GenericArray<F, L>> for VoleCommits<'_, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    fn add_round_key_assign(&mut self, rhs: &GenericArray<F, L>) {
        for (x, y) in izip!(self.scalars.iter_mut(), rhs.iter()) {
            *x += y;
        }
    }
}

impl<'a, O> InverseShiftRows<O> for VoleCommitsRef<'a, OWFField<O>, O::NSTBits>
where
    O: OWFParameters,
{
    type Output = VoleCommits<'a, OWFField<O>, O::NSTBits>;

    fn inverse_shift_rows(&self) -> Self::Output {
        let mut state_prime = GenericArray::default_boxed();

        for r in 0..4 {
            for c in 0..O::NST::USIZE {
                // :: 3-6
                let i = if (O::NST::USIZE != 8) || (r <= 1) {
                    4 * ((O::NST::USIZE + c - r) % O::NST::USIZE) + r
                } else {
                    4 * ((O::NST::USIZE + c - r - 1) % O::NST::USIZE) + r
                };

                // :: 7
                state_prime[8 * (4 * c + r)..8 * (4 * c + r) + 8]
                    .copy_from_slice(&self.scalars[8 * i..8 * i + 8]);
            }
        }

        Self::Output {
            scalars: state_prime,
            delta: self.delta,
        }
    }
}

impl<'a, O> InverseShiftRows<O> for &VoleCommits<'a, OWFField<O>, O::NSTBits>
where
    O: OWFParameters,
{
    type Output = VoleCommits<'a, OWFField<O>, O::NSTBits>;

    fn inverse_shift_rows(&self) -> Self::Output {
        let mut state_prime = GenericArray::default_boxed();

        for r in 0..4 {
            for c in 0..O::NST::USIZE {
                // :: 3-6
                let i = if (O::NST::USIZE != 8) || (r <= 1) {
                    4 * ((O::NST::USIZE + c - r) % O::NST::USIZE) + r
                } else {
                    4 * ((O::NST::USIZE + c - r - 1) % O::NST::USIZE) + r
                };

                // :: 7
                state_prime[8 * (4 * c + r)..8 * (4 * c + r) + 8]
                    .copy_from_slice(&self.scalars[8 * i..8 * i + 8]);
            }
        }

        Self::Output {
            scalars: state_prime,
            delta: self.delta,
        }
    }
}

impl<'a, O> BytewiseMixColumns<O> for VoleCommitsRef<'a, OWFField<O>, O::NSTBits>
where
    O: OWFParameters,
{
    type Output = VoleCommits<'a, OWFField<O>, O::NSTBits>;

    fn bytewise_mix_columns(&self) -> Self::Output {
        let mut o = GenericArray::<_, O::NSTBits>::default_boxed();

        for c in 0..O::NST::USIZE {
            for r in 0..4 {
                // ::4
                let a_key = &self.scalars[32 * c + 8 * r..32 * c + 8 * r + 8];

                // ::5
                let b_key = [
                    a_key[7],
                    a_key[0] + a_key[7],
                    a_key[1],
                    a_key[2] + a_key[7],
                    a_key[3] + a_key[7],
                    a_key[4],
                    a_key[5],
                    a_key[6],
                ];

                // ::6..10
                for j in 0..2 {
                    let off = 32 * c + 8 * ((4 + r - j) % 4);
                    o[off..off + 8]
                        .iter_mut()
                        .zip(b_key.iter())
                        .for_each(|(o, b)| {
                            *o += b;
                        });
                }

                for j in 1..4 {
                    let off = 32 * c + 8 * ((r + j) % 4);

                    o[off..off + 8]
                        .iter_mut()
                        .zip(a_key.iter())
                        .for_each(|(o, a)| {
                            *o += a;
                        });
                }
            }
        }

        VoleCommits {
            scalars: o,
            delta: self.delta,
        }
    }
}

impl<'a, O> SBoxAffine<O> for VoleCommits<'a, OWFField<O>, O::NSTBits>
where
    O: OWFParameters,
{
    type Output = VoleCommits<'a, OWFField<O>, O::NSTBytes>;

    fn s_box_affine(&self, sq: bool) -> Self::Output {
        let sigmas = if sq {
            &OWFField::<O>::SIGMA_SQUARES
        } else {
            &OWFField::<O>::SIGMA
        };

        let t = sq as usize;

        // :: 8-10
        let scalars = (0..O::NSTBytes::USIZE)
            .map(|i| {
                // :: 9
                let mut y_i = sigmas[8] * self.delta.square();

                for (sigma_idx, sigma) in sigmas.iter().enumerate().take(8) {
                    y_i += self.scalars[i * 8 + (sigma_idx + t) % 8] * sigma;
                }

                y_i
            })
            .collect();

        Self::Output {
            scalars,
            delta: self.delta,
        }
    }
}

impl<F, L> ShiftRows for VoleCommits<'_, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    fn shift_rows(&mut self) {
        // TODO: Copy row by row instead of entire state
        let mut tmp = self.scalars.clone();

        let nst = L::USIZE / 4;

        for r in 0..4 {
            for c in 0..nst {
                let off = if (nst != 8) || (r <= 1) { 0 } else { 1 };
                std::mem::swap(
                    &mut self.scalars[4 * c + r],
                    &mut tmp[4 * ((c + r + off) % nst) + r],
                );
            }
        }
    }
}

impl<F, L> InverseAffine for VoleCommits<'_, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    fn inverse_affine(&mut self) {
        let nst_bytes = L::USIZE / 8;

        for i in 0..nst_bytes {
            let xi_tags: GenericArray<_, U8> =
                GenericArray::from_slice(&self.scalars[8 * i..8 * i + 8]).to_owned();
            for bit_i in 0..8 {
                // ::6
                self.scalars[8 * i + bit_i] = xi_tags[(bit_i + 8 - 1) % 8]
                    + xi_tags[(bit_i + 8 - 3) % 8]
                    + xi_tags[(bit_i + 8 - 6) % 8];

                if bit_i == 0 || bit_i == 2 {
                    self.scalars[8 * i + bit_i] += self.delta;
                }
            }
        }
    }
}

impl<O> MixColumns<O> for VoleCommits<'_, OWFField<O>, O::NSTBytes>
where
    O: OWFParameters,
{
    fn mix_columns(&mut self, sq: bool) {
        let (v2, v3) = if sq {
            (
                OWFField::<O>::BYTE_COMBINE_SQ_2,
                OWFField::<O>::BYTE_COMBINE_SQ_3,
            )
        } else {
            (OWFField::<O>::BYTE_COMBINE_2, OWFField::<O>::BYTE_COMBINE_3)
        };

        for c in 0..O::NST::USIZE {
            // Save the 4 state's columns that will be modified in this round
            let tmp = GenericArray::<_, U4>::from_slice(&self.scalars[4 * c..4 * c + 4]).to_owned();

            let i0 = 4 * c;
            let i1 = 4 * c + 1;
            let i2 = 4 * c + 2;
            let i3 = 4 * c + 3;

            // ::7
            self.scalars[i0] = tmp[0] * v2 + tmp[1] * v3 + tmp[2] + tmp[3];

            // ::8
            self.scalars[i1] = tmp[1] * v2 + tmp[2] * v3 + tmp[0] + tmp[3];

            // ::9
            self.scalars[i2] = tmp[2] * v2 + tmp[3] * v3 + tmp[0] + tmp[1];

            // ::10
            // SAFETY: tmp has length 4, hence unwrapping the first 4 elements is safe
            let mut tmp = tmp.into_iter();
            let tmp0 = tmp.next().unwrap();
            let tmp1 = tmp.next().unwrap();
            let tmp2 = tmp.next().unwrap();
            let tmp3 = tmp.next().unwrap();

            self.scalars[i3] = tmp0 * v3 + tmp3 * v2 + tmp1 + tmp2;
        }
    }
}

impl<F, L> AddRoundKeyBytes<&GenericArray<F, L>> for VoleCommits<'_, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    fn add_round_key_bytes(&mut self, rhs: &GenericArray<F, L>, sq: bool) {
        if sq {
            for (st, k) in izip!(self.scalars.iter_mut(), rhs) {
                (*st) += k;
            }
        } else {
            for (st, k) in izip!(self.scalars.iter_mut(), rhs) {
                (*st) += *k * self.delta;
            }
        }
    }
}
