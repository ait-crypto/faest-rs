use crate::{
    aes::*,
    fields::{
        large_fields::{Betas, ByteCombineSquared, ByteCombineSquaredConstants, SquareBytes},
        small_fields::{GF8, GF8_INV_NORM},
        BigGaloisField, ByteCombine, ByteCombineConstants, Field, Sigmas, SumPoly,
    },
    parameter::{BaseParameters, OWFField, OWFParameters, SecurityParameter},
    universal_hashing::ZKProofHasher,
    utils::get_bits,
};

use super::{ByteCommitment, ByteCommits, ByteCommitsRef, FieldCommitDegOne, FieldCommitDegTwo};
use generic_array::{
    typenum::{Prod, Quot, Unsigned, U2, U4, U8},
    ArrayLength, GenericArray,
};
use itertools::izip;
use std::convert::AsRef;
use std::ops::{AddAssign, Deref, Index, Mul};

// Helper type aliases
pub(crate) type StateBitsCommits<O> =
    Box<GenericArray<FieldCommitDegOne<OWFField<O>>, <O as OWFParameters>::NSTBits>>;

pub(crate) type StateBitsSquaredCommits<O> =
    Box<GenericArray<FieldCommitDegTwo<OWFField<O>>, <O as OWFParameters>::NSTBits>>;

pub(crate) type StateBytesCommits<O> =
    Box<GenericArray<FieldCommitDegOne<OWFField<O>>, <O as OWFParameters>::NSTBytes>>;

pub(crate) type StateBytesSquaredCommits<O> =
    Box<GenericArray<FieldCommitDegTwo<OWFField<O>>, <O as OWFParameters>::NSTBytes>>;

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
        (0..O::NSTBytes::USIZE)
            .map(|i| {
                FieldCommitDegOne::new(
                    OWFField::<O>::byte_combine_bits(self.keys[i]),
                    OWFField::<O>::byte_combine_slice(&self.tags[i * 8..i * 8 + 8]),
                )
            })
            .collect()
    }
}

// Scalar commitments to known state
// TODO: Only return the keys (efficiency)
impl<O, L> StateToBytes<O> for GenericArray<u8, L>
where
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
    O: OWFParameters,
{
    type Output = Box<GenericArray<OWFField<O>, O::NSTBytes>>;

    fn state_to_bytes(&self) -> Self::Output {
        self.iter()
            .map(|k| OWFField::<O>::byte_combine_bits(*k))
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
    type Output = ByteCommits<F, L>;

    fn add_round_key(&self, rhs: &GenericArray<u8, L>) -> Self::Output {
        ByteCommits {
            keys: self.keys.iter().zip(rhs).map(|(a, b)| a ^ b).collect(),
            tags: <Box<GenericArray<F, Prod<L, U8>>>>::from_iter(self.tags.to_owned()),
        }
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
            keys: self.keys.iter().zip(rhs).map(|(a, b)| a ^ b).collect(),
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
            keys: self
                .into_iter()
                .zip(rhs.keys.iter())
                .map(|(a, b)| a ^ b)
                .collect(),
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
    type Output = ByteCommits<F, L>;

    fn add_round_key(&self, rhs: &ByteCommitsRef<'_, F, L>) -> Self::Output {
        ByteCommits {
            keys: self.keys.iter().zip(rhs.keys).map(|(a, b)| a ^ b).collect(),
            tags: self
                .tags
                .iter()
                .zip(rhs.tags.iter())
                .map(|(a, b)| *a + b)
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
        self.keys
            .iter_mut()
            .zip(rhs.iter())
            .for_each(|(a, b)| *a ^= b);
    }
}

// Committed state, hidden key
impl<F, L> AddRoundKeyAssign<&ByteCommitsRef<'_, F, L>> for ByteCommits<F, L>
where
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
    F: BigGaloisField,
{
    fn add_round_key_assign(&mut self, rhs: &ByteCommitsRef<'_, F, L>) {
        self.keys
            .iter_mut()
            .zip(rhs.keys.iter())
            .for_each(|(a, b)| *a ^= b);
        self.tags
            .iter_mut()
            .zip(rhs.tags.iter())
            .for_each(|(a, b)| *a += b);
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
        for (st, k) in izip!(self.iter_mut(), key) {
            (*st) += k;
        }
    }
}

impl<O> InverseShiftRows<O> for ByteCommitsRef<'_, OWFField<O>, O::NSTBytes>
where
    O: OWFParameters,
{
    type Output = ByteCommits<OWFField<O>, O::NSTBytes>;

    fn inverse_shift_rows(&self) -> Self::Output {
        let mut state_prime = ByteCommits::<OWFField<O>, O::NSTBytes>::default();

        for r in 0..4 {
            for c in 0..O::NST::USIZE {
                // :: 3-6
                let i = if (O::NST::USIZE != 8) || (r <= 1) {
                    4 * ((O::NST::USIZE + c - r) % O::NST::USIZE) + r
                } else {
                    4 * ((O::NST::USIZE + c - r - 1) % O::NST::USIZE) + r
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

        for c in 0..O::NST::USIZE {
            // Save the 4 state's columns that will be modified in this round
            let tmp = GenericArray::<_, U4>::from_slice(&self[4 * c..4 * c + 4]).to_owned();

            let i0 = 4 * c;
            let i1 = 4 * c + 1;
            let i2 = 4 * c + 2;
            let i3 = 4 * c + 3;

            // ::7
            self[i0] = tmp[0].clone() * &v2 + tmp[1].clone() * &v3 + &tmp[2] + &tmp[3];

            // ::8
            self[i1] = tmp[1].clone() * &v2 + tmp[2].clone() * &v3 + &tmp[0] + &tmp[3];

            // ::9
            self[i2] = tmp[2].clone() * &v2 + tmp[3].clone() * &v3 + &tmp[0] + &tmp[1];

            // ::10
            // SAFETY: tmp has length 4, hence unwrapping the first 4 elements is safe
            let mut tmp = tmp.into_iter();
            let tmp0 = tmp.next().unwrap();
            let tmp1 = tmp.next().unwrap();
            let tmp2 = tmp.next().unwrap();
            let tmp3 = tmp.next().unwrap();

            self[i3] = tmp0 * &v3 + tmp3 * &v2 + &tmp1 + &tmp2;
        }
    }
}

pub(crate) fn mix_columns<O>(state: &mut StateBytesSquaredCommits<O>, sq: bool)
where
    O: OWFParameters,
{
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

    for c in 0..O::NST::USIZE {
        // Save the 4 state's columns that will be modified in this round
        let tmp = GenericArray::<_, U4>::from_slice(&state[4 * c..4 * c + 4]).to_owned();

        let i0 = 4 * c;
        let i1 = 4 * c + 1;
        let i2 = 4 * c + 2;
        let i3 = 4 * c + 3;

        // ::7
        state[i0] = tmp[0].clone() * &v2 + tmp[1].clone() * &v3 + &tmp[2] + &tmp[3];

        // ::8
        state[i1] = tmp[1].clone() * &v2 + tmp[2].clone() * &v3 + &tmp[0] + &tmp[3];

        // ::9
        state[i2] = tmp[2].clone() * &v2 + tmp[3].clone() * &v3 + &tmp[0] + &tmp[1];

        // ::10
        // SAFETY: tmp has length 4, hence unwrapping the first 4 elements is safe
        let mut tmp = tmp.into_iter();
        let tmp0 = tmp.next().unwrap();
        let tmp1 = tmp.next().unwrap();
        let tmp2 = tmp.next().unwrap();
        let tmp3 = tmp.next().unwrap();

        state[i3] = tmp0 * &v3 + tmp3 * &v2 + &tmp1 + &tmp2;
    }
}

impl<O> BytewiseMixColumns<O> for ByteCommitsRef<'_, OWFField<O>, O::NSTBytes>
where
    O: OWFParameters,
{
    type Output = ByteCommits<OWFField<O>, O::NSTBytes>;

    fn bytewise_mix_columns(&self) -> Self::Output {
        let mut o = ByteCommits::<_, O::NSTBytes>::default();

        for c in 0..O::NST::USIZE {
            for r in 0..4 {
                // ::4
                let a_key = self.keys[4 * c + r];
                let a_tags = &self.tags[32 * c + 8 * r..32 * c + 8 * r + 8];
                let a_key_bits = get_bits(a_key);

                // ::5
                let b_key = a_key_bits[7]
                    | ((a_key_bits[0] ^ a_key_bits[7]) << 1)
                    | (a_key_bits[1] << 2)
                    | ((a_key_bits[2] ^ a_key_bits[7]) << 3)
                    | ((a_key_bits[3] ^ a_key_bits[7]) << 4)
                    | (a_key_bits[4] << 5)
                    | (a_key_bits[5] << 6)
                    | (a_key_bits[6] << 7);
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
        (0..O::NSTBytes::USIZE)
            .map(|i| {
                // :: 9

                let mut y_i = self[i * 8 + t % 8].clone() * &sigmas[0];

                for sigma_idx in 1..8 {
                    y_i += self[i * 8 + (sigma_idx + t) % 8].clone() * &sigmas[sigma_idx];
                }

                y_i += &sigmas[8];

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
                    + &xi_tags[(bit_i + 8 - 3) % 8]
                    + &xi_tags[(bit_i + 8 - 6) % 8];
            }
        }
    }
}
