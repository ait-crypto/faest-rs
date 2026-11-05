use core::{iter::zip, mem, ops::Mul};

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box};

use hybrid_array::{Array, ArraySize, typenum::U8};

use super::{ByteCommits, ByteCommitsRef};
use crate::{
    aes::*,
    fields::{BigGaloisField, ByteCombine},
    parameter::{OWFField, OWFParameters, SecurityParameter},
    utils::xor_arrays_inplace,
};

// Scalar commitments to known state
impl<O, L> StateToBytes<O> for Array<u8, L>
where
    L: ArraySize + Mul<U8, Output: ArraySize>,
    O: OWFParameters,
{
    type Output = Box<Array<OWFField<O>, O::NStBytes>>;

    fn state_to_bytes(&self) -> Self::Output {
        Box::new(
            self.iter()
                .map(|&k| OWFField::<O>::byte_combine_bits(k))
                .collect(),
        )
    }
}

// Implementations of AddRound key

// Known state, owned hidden key
impl<F, L> AddRoundKey<&Array<u8, L>> for ByteCommits<F, L>
where
    L: ArraySize + Mul<U8, Output: ArraySize>,
    F: BigGaloisField,
{
    type Output = Self;

    fn add_round_key(&self, rhs: &Array<u8, L>) -> Self::Output {
        Self::new(
            Box::new(zip(self.keys.iter(), rhs).map(|(a, b)| a ^ b).collect()),
            self.tags.to_owned(),
        )
    }
}

// Known state, ref to hidden key
impl<F, L> AddRoundKey<&Array<u8, L>> for ByteCommitsRef<'_, F, L>
where
    L: ArraySize + Mul<U8, Output: ArraySize>,
    F: BigGaloisField,
{
    type Output = ByteCommits<F, L>;

    fn add_round_key(&self, rhs: &Array<u8, L>) -> Self::Output {
        ByteCommits {
            keys: Box::new(zip(self.keys, rhs).map(|(a, b)| a ^ b).collect()),
            tags: Box::new(self.tags.to_owned()),
        }
    }
}

// Committed state, ref to hidden known key
impl<F, L> AddRoundKey<&ByteCommitsRef<'_, F, L>> for &Array<u8, L>
where
    L: ArraySize + Mul<U8, Output: ArraySize>,
    F: BigGaloisField,
{
    type Output = ByteCommits<F, L>;

    fn add_round_key(&self, rhs: &ByteCommitsRef<'_, F, L>) -> Self::Output {
        ByteCommits {
            keys: Box::new(zip(self.iter(), rhs.keys).map(|(a, b)| a ^ b).collect()),
            tags: Box::new(rhs.tags[..L::USIZE * 8].iter().cloned().collect()),
        }
    }
}

// Committed state, hidden key
impl<F, L> AddRoundKey<&ByteCommitsRef<'_, F, L>> for ByteCommits<F, L>
where
    L: ArraySize + Mul<U8, Output: ArraySize>,
    F: BigGaloisField,
{
    type Output = Self;

    fn add_round_key(&self, rhs: &ByteCommitsRef<'_, F, L>) -> Self::Output {
        Self {
            keys: Box::new(
                zip(self.keys.iter(), rhs.keys)
                    .map(|(a, b)| a ^ b)
                    .collect(),
            ),
            tags: Box::new(
                zip(self.tags.iter(), rhs.tags)
                    .map(|(&a, b)| a + b)
                    .collect(),
            ),
        }
    }
}

// Implementations for AddRoundKeyAssign

// Known state, hidden key
impl<F, L> AddRoundKeyAssign<&Array<u8, L>> for ByteCommits<F, L>
where
    L: ArraySize + Mul<U8, Output: ArraySize>,
    F: BigGaloisField,
{
    fn add_round_key_assign(&mut self, rhs: &Array<u8, L>) {
        xor_arrays_inplace(self.keys.as_mut_slice(), rhs.as_slice());
    }
}

// Committed state, hidden key
impl<F, L> AddRoundKeyAssign<&ByteCommitsRef<'_, F, L>> for ByteCommits<F, L>
where
    L: ArraySize + Mul<U8, Output: ArraySize>,
    F: BigGaloisField,
{
    fn add_round_key_assign(&mut self, rhs: &ByteCommitsRef<'_, F, L>) {
        xor_arrays_inplace(self.keys.as_mut_slice(), rhs.keys.as_slice());
        for (a, b) in zip(self.tags.iter_mut(), rhs.tags.iter()) {
            *a += b;
        }
    }
}

impl<T, L> ShiftRows for Array<T, L>
where
    T: Clone,
    L: ArraySize,
{
    fn shift_rows(&mut self) {
        // TODO: Copy row by row instead of entire state
        let mut tmp = self.clone();
        let nst = L::USIZE / 4;

        for r in 0..4 {
            for c in 0..nst {
                let off = if (nst != 8) || (r <= 1) { 0 } else { 1 };
                mem::swap(
                    &mut self[4 * c + r],
                    &mut tmp[4 * ((c + r + off) % nst) + r],
                );
            }
        }
    }
}

impl<F, L> ByteCommitsRef<'_, F, L>
where
    F: BigGaloisField,
    L: ArraySize + Mul<U8, Output: ArraySize>,
{
    /// Inverse ShiftRows into a reusable encryption-round buffer.
    pub(super) fn inverse_shift_rows_into(&self, state_prime: &mut ByteCommits<F, L>) {
        let n = L::USIZE / 4;
        for r in 0..4 {
            for c in 0..n {
                // ::3-6
                let i = if (n != 8) || (r <= 1) {
                    4 * ((n + c - r) % n) + r
                } else {
                    4 * ((n + c - r - 1) % n) + r
                };

                // ::7
                state_prime.keys[4 * c + r] = self.keys[i];
                state_prime.tags[8 * (4 * c + r)..8 * (4 * c + r) + 8]
                    .copy_from_slice(&self.tags[8 * i..8 * i + 8]);
            }
        }
    }

    /// Bytewise MixColumns into a reusable encryption-round buffer.
    pub(super) fn bytewise_mix_columns_into(&self, o: &mut ByteCommits<F, L>) {
        o.keys.fill(0);
        o.tags.fill(F::ZERO);
        for c in 0..(L::USIZE / 4) {
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

                // ::6-9
                // Add b(r) to o_{4*c+r} and o_{4* c + (r - 1 mod 4)}
                for j in 0..2 {
                    let off = (4 + r - j) % 4;
                    o.keys[4 * c + off] ^= b_key;
                    for (o, b) in zip(
                        o.tags[32 * c + 8 * off..32 * c + 8 * off + 8].iter_mut(),
                        b_tags,
                    ) {
                        *o += b;
                    }
                }

                // Add a(r) to o_{4*c + (r+1 mod 4)}, o_{4*c + (r+2 mod 4)}, o_{4*c + (r+3 mod 4)}
                for j in 1..4 {
                    let off = (r + j) % 4;
                    o.keys[4 * c + off] ^= a_key;
                    for (o, a) in zip(
                        o.tags[32 * c + 8 * off..32 * c + 8 * off + 8].iter_mut(),
                        a_tags,
                    ) {
                        *o += a;
                    }
                }
            }
        }
    }
}

impl<O: OWFParameters> InverseShiftRows<O> for ByteCommitsRef<'_, OWFField<O>, O::NStBytes> {
    type Output = ByteCommits<OWFField<O>, O::NStBytes>;
    fn inverse_shift_rows(&self) -> Self::Output {
        let mut output = ByteCommits::default();
        self.inverse_shift_rows_into(&mut output);
        output
    }
}

impl<O: OWFParameters> BytewiseMixColumns<O> for ByteCommitsRef<'_, OWFField<O>, O::NStBytes> {
    type Output = ByteCommits<OWFField<O>, O::NStBytes>;
    fn bytewise_mix_columns(&self) -> Self::Output {
        let mut output = ByteCommits::default();
        self.bytewise_mix_columns_into(&mut output);
        output
    }
}

/// FAEST v3 Figure 7.6.
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
        }

        for scalars in self.tags.as_chunks_mut::<8>().0 {
            // ::6
            let xi_tags = *scalars;
            for bit_i in 0..8 {
                // ::6
                scalars[bit_i] = xi_tags[(bit_i + 8 - 1) % 8]
                    + xi_tags[(bit_i + 8 - 3) % 8]
                    + xi_tags[(bit_i + 8 - 6) % 8];
            }
        }
    }
}
