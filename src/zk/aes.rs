use core::{iter::zip, ops::Mul};

use hybrid_array::{ArraySize, typenum::U8};

use super::{ByteCommits, ByteCommitsRef};
use crate::{fields::BigGaloisField, parameter::SecurityParameter, utils::xor_arrays_inplace};

impl<F, L> ByteCommits<F, L>
where
    L: ArraySize + Mul<U8, Output: ArraySize>,
    F: BigGaloisField,
{
    /// Add a committed round key to the state in place.
    pub(super) fn add_round_key_assign(&mut self, rhs: &ByteCommitsRef<'_, F, L>) {
        xor_arrays_inplace(self.keys.as_mut_slice(), rhs.keys.as_slice());
        for (a, b) in zip(self.tags.iter_mut(), rhs.tags.iter()) {
            *a += b;
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

impl<F, L> ByteCommits<F, L>
where
    F: BigGaloisField,
    L: SecurityParameter,
{
    pub(super) fn inverse_affine(&mut self) {
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
