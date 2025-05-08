use std::{
    iter::zip,
    ops::{AddAssign, Mul},
};

use generic_array::{
    ArrayLength, GenericArray,
    typenum::{Prod, U4, U8, Unsigned},
};

use super::{ByteCommits, ByteCommitsRef, FieldCommitDegOne, FieldCommitDegTwo};
use crate::{
    aes::*,
    fields::{
        BigGaloisField, ByteCombine, ByteCombineConstants, Sigmas,
        large_fields::ByteCombineSquaredConstants,
    },
    parameter::{BaseParameters, OWFField, OWFParameters, SecurityParameter},
};

// Helper type aliases
pub(crate) type StateBitsSquaredCommits<O> =
    Box<GenericArray<FieldCommitDegTwo<OWFField<O>>, <O as OWFParameters>::NStBits>>;

pub(crate) type StateBytesCommits<O> =
    Box<GenericArray<FieldCommitDegOne<OWFField<O>>, <O as OWFParameters>::NStBytes>>;

pub(crate) type StateBytesSquaredCommits<O> =
    Box<GenericArray<FieldCommitDegTwo<OWFField<O>>, <O as OWFParameters>::NStBytes>>;

// implementations of StateToBytes

// Committed state
impl<O, L> StateToBytes<O> for ByteCommitsRef<'_, OWFField<O>, L>
where
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
    O: OWFParameters,
{
    type Output = StateBytesCommits<O>;

    fn state_to_bytes(&self) -> Self::Output
where {
        zip(self.keys, self.tags.chunks_exact(8))
            .map(|(&key_i, tags_i)| {
                FieldCommitDegOne::new(
                    OWFField::<O>::byte_combine_bits(key_i),
                    OWFField::<O>::byte_combine_slice(tags_i),
                )
            })
            .collect()
    }
}

// Scalar commitments to known state
impl<O, L> StateToBytes<O> for GenericArray<u8, L>
where
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
    O: OWFParameters,
{
    type Output = Box<GenericArray<OWFField<O>, O::NStBytes>>;

    fn state_to_bytes(&self) -> Self::Output {
        self.iter()
            .map(|&k| OWFField::<O>::byte_combine_bits(k))
            .collect()
    }
}

// Implementations of AddRound key

// Known state, owned hidden key
impl<F, L> AddRoundKey<&GenericArray<u8, L>> for ByteCommits<F, L>
where
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
    F: BigGaloisField,
{
    type Output = Self;

    fn add_round_key(&self, rhs: &GenericArray<u8, L>) -> Self::Output {
        Self::new(
            zip(self.keys.iter(), rhs).map(|(a, b)| a ^ b).collect(),
            self.tags.to_owned(),
        )
    }
}

// Known state, ref to hidden key
impl<F, L> AddRoundKey<&GenericArray<u8, L>> for ByteCommitsRef<'_, F, L>
where
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
    F: BigGaloisField,
{
    type Output = ByteCommits<F, L>;

    fn add_round_key(&self, rhs: &GenericArray<u8, L>) -> Self::Output {
        ByteCommits {
            keys: zip(self.keys, rhs).map(|(a, b)| a ^ b).collect(),
            tags: <Box<GenericArray<F, Prod<L, U8>>>>::from_iter(self.tags.to_owned()),
        }
    }
}

// Committed state, ref to hidden known key
impl<F, L> AddRoundKey<&ByteCommitsRef<'_, F, L>> for &GenericArray<u8, L>
where
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
    F: BigGaloisField,
{
    type Output = ByteCommits<F, L>;

    fn add_round_key(&self, rhs: &ByteCommitsRef<'_, F, L>) -> Self::Output {
        ByteCommits {
            keys: zip(self.iter(), rhs.keys).map(|(a, b)| a ^ b).collect(),
            tags: <Box<GenericArray<F, Prod<L, U8>>>>::from_iter(
                rhs.tags[..L::USIZE * 8].to_owned(),
            ),
        }
    }
}

// Committed state, hidden key
impl<F, L> AddRoundKey<&ByteCommitsRef<'_, F, L>> for ByteCommits<F, L>
where
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
    F: BigGaloisField,
{
    type Output = Self;

    fn add_round_key(&self, rhs: &ByteCommitsRef<'_, F, L>) -> Self::Output {
        Self {
            keys: zip(self.keys.iter(), rhs.keys)
                .map(|(a, b)| a ^ b)
                .collect(),
            tags: zip(self.tags.iter(), rhs.tags)
                .map(|(&a, b)| a + b)
                .collect(),
        }
    }
}

// Implementations for AddRoundKeyAssign

// Known state, hidden key
impl<F, L> AddRoundKeyAssign<&GenericArray<u8, L>> for ByteCommits<F, L>
where
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
    F: BigGaloisField,
{
    fn add_round_key_assign(&mut self, rhs: &GenericArray<u8, L>) {
        for (a, b) in zip(self.keys.iter_mut(), rhs) {
            *a ^= b;
        }
    }
}

// Committed state, hidden key
impl<F, L> AddRoundKeyAssign<&ByteCommitsRef<'_, F, L>> for ByteCommits<F, L>
where
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
    F: BigGaloisField,
{
    fn add_round_key_assign(&mut self, rhs: &ByteCommitsRef<'_, F, L>) {
        for (a, b) in zip(self.keys.iter_mut(), rhs.keys) {
            *a ^= b;
        }

        for (a, b) in zip(self.tags.iter_mut(), rhs.tags.iter()) {
            *a += b;
        }
    }
}

impl<T, L> ShiftRows for GenericArray<T, L>
where
    T: Clone,
    L: ArrayLength,
{
    fn shift_rows(&mut self) {
        // TODO: Copy row by row instead of entire state
        let mut tmp = self.clone();
        let nst = L::USIZE / 4;

        for r in 0..4 {
            for c in 0..nst {
                let off = if (nst != 8) || (r <= 1) { 0 } else { 1 };
                std::mem::swap(
                    &mut self[4 * c + r],
                    &mut tmp[4 * ((c + r + off) % nst) + r],
                );
            }
        }
    }
}

impl<F, L, T> AddRoundKeyBytes<&GenericArray<T, L>> for Box<GenericArray<FieldCommitDegTwo<F>, L>>
where
    F: BigGaloisField,
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
    for<'a> FieldCommitDegTwo<F>: AddAssign<&'a T>,
{
    fn add_round_key_bytes(&mut self, key: &GenericArray<T, L>, _sq: bool) {
        for (st, k) in zip(self.iter_mut(), key) {
            (*st) += k;
        }
    }
}

impl<O> InverseShiftRows<O> for ByteCommitsRef<'_, OWFField<O>, O::NStBytes>
where
    O: OWFParameters,
{
    type Output = ByteCommits<OWFField<O>, O::NStBytes>;

    fn inverse_shift_rows(&self) -> Self::Output {
        let mut state_prime = ByteCommits::<OWFField<O>, O::NStBytes>::default();

        for r in 0..4 {
            for c in 0..O::NSt::USIZE {
                // :: 3-6
                let i = if (O::NSt::USIZE != 8) || (r <= 1) {
                    4 * ((O::NSt::USIZE + c - r) % O::NSt::USIZE) + r
                } else {
                    4 * ((O::NSt::USIZE + c - r - 1) % O::NSt::USIZE) + r
                };

                // :: 7
                state_prime.keys[4 * c + r] = self.keys[i];
                state_prime.tags[8 * (4 * c + r)..8 * (4 * c + r) + 8]
                    .copy_from_slice(&self.tags[8 * i..8 * i + 8]);
            }
        }

        state_prime
    }
}

impl<O> MixColumns<O> for StateBytesSquaredCommits<O>
where
    O: OWFParameters,
{
    fn mix_columns(&mut self, sq: bool) {
        let v2 = if sq {
            OWFField::<O>::BYTE_COMBINE_SQ_2
        } else {
            OWFField::<O>::BYTE_COMBINE_2
        };
        let v3: <<O as OWFParameters>::BaseParams as BaseParameters>::Field = if sq {
            OWFField::<O>::BYTE_COMBINE_SQ_3
        } else {
            OWFField::<O>::BYTE_COMBINE_3
        };

        for c in 0..O::NSt::USIZE {
            // Save the 4 state's columns that will be modified in this round
            let tmp = GenericArray::<_, U4>::from_slice(&self[4 * c..4 * c + 4]).to_owned();

            let i0 = 4 * c;
            let i1 = i0 + 1;
            let i2 = i0 + 2;
            let i3 = i0 + 3;

            // ::7
            self[i0] = tmp[0].clone() * v2 + tmp[1].clone() * v3 + &tmp[2] + &tmp[3];

            // ::8
            self[i1] = tmp[1].clone() * v2 + tmp[2].clone() * v3 + &tmp[0] + &tmp[3];

            // ::9
            self[i2] = tmp[2].clone() * v2 + tmp[3].clone() * v3 + &tmp[0] + &tmp[1];

            // ::10
            let (tmp0, tmp1, tmp2, tmp3) = tmp.into();
            self[i3] = tmp0 * v3 + tmp3 * v2 + &tmp1 + &tmp2;
        }
    }
}

impl<O> BytewiseMixColumns<O> for ByteCommitsRef<'_, OWFField<O>, O::NStBytes>
where
    O: OWFParameters,
{
    type Output = ByteCommits<OWFField<O>, O::NStBytes>;

    fn bytewise_mix_columns(&self) -> Self::Output {
        let mut o = ByteCommits::<_, O::NStBytes>::default();

        for c in 0..O::NSt::USIZE {
            for r in 0..4 {
                // ::4
                let a_key = self.keys[4 * c + r];
                let a_tags = &self.tags[32 * c + 8 * r..32 * c + 8 * r + 8];

                // ::5
                let a_key_7 = a_key & 0x80;
                let b_key = a_key.rotate_left(1) ^ (a_key_7 >> 6) ^ (a_key_7 >> 4) ^ (a_key_7 >> 3);
                let b_tags = [
                    a_tags[7],
                    a_tags[0] + a_tags[7],
                    a_tags[1],
                    a_tags[2] + a_tags[7],
                    a_tags[3] + a_tags[7],
                    a_tags[4],
                    a_tags[5],
                    a_tags[6],
                ];

                // ::6..10
                // Add b(r) to o_{4*c+r} and o_{4* c + (r - 1 mod 4)}
                for j in 0..2 {
                    let off = (4 + r - j) % 4;
                    o.keys[4 * c + off] ^= b_key;
                    o.tags[32 * c + 8 * off..32 * c + 8 * off + 8]
                        .iter_mut()
                        .zip(b_tags.iter())
                        .for_each(|(o, b)| {
                            *o += b;
                        });
                }

                // Add a(r) to o_{4*c + (r+1 mod 4)}, o_{4*c + (r+2 mod 4)}, o_{4*c + (r+3 mod 4)}
                for j in 1..4 {
                    let off = (r + j) % 4;

                    o.keys[4 * c + off] ^= a_key;

                    o.tags[32 * c + 8 * off..32 * c + 8 * off + 8]
                        .iter_mut()
                        .zip(a_tags.iter())
                        .for_each(|(o, a)| {
                            *o += a;
                        });
                }
            }
        }

        o
    }
}

impl<O> SBoxAffine<O> for StateBitsSquaredCommits<O>
where
    O: OWFParameters,
{
    type Output = StateBytesSquaredCommits<O>;

    fn s_box_affine(&self, sq: bool) -> Self::Output {
        let sigmas = if sq {
            &OWFField::<O>::SIGMA_SQUARES
        } else {
            &OWFField::<O>::SIGMA
        };

        let t = sq as usize;

        // :: 8-10
        (0..O::NStBytes::USIZE)
            .map(|i| {
                // :: 9

                let mut y_i = self[i * 8 + t % 8].clone() * sigmas[0];

                for sigma_idx in 1..8 {
                    y_i += self[i * 8 + (sigma_idx + t) % 8].clone() * sigmas[sigma_idx];
                }

                y_i += sigmas[8];

                y_i
            })
            .collect()
    }
}

impl<F, L> InverseAffine for ByteCommits<F, L>
where
    F: BigGaloisField,
    L: SecurityParameter,
{
    fn inverse_affine(&mut self) {
        for i in 0..L::USIZE {
            // ::5
            self.keys[i] = self.keys[i].rotate_right(7)
                ^ self.keys[i].rotate_right(5)
                ^ self.keys[i].rotate_right(2)
                ^ 0x5;

            let xi_tags: GenericArray<_, U8> =
                GenericArray::from_slice(&self.tags[8 * i..8 * i + 8]).to_owned();

            for bit_i in 0..8 {
                // ::6
                self.tags[8 * i + bit_i] = xi_tags[(bit_i + 8 - 1) % 8]
                    + xi_tags[(bit_i + 8 - 3) % 8]
                    + xi_tags[(bit_i + 8 - 6) % 8];
            }
        }
    }
}
