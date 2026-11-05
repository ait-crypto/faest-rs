use super::{
    ByteCommits, ByteCommitsRef,
    algebra::{ConstraintAlgebra, Lift},
    byte_commitment::ByteCommitment,
    hashing::ConstraintHasher,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::{
    aes::{AddRoundKeyAssign, InverseAffine},
    fields::BigGaloisField,
    parameter::{OWFField, OWFParameters},
};
use core::array;
use hybrid_array::typenum::Unsigned;

pub(super) fn enc_cstrnts<O: OWFParameters>(
    hasher: &mut impl ConstraintHasher<OWFField<O>>,
    input: ByteCommitsRef<OWFField<O>, O::NStBytes>,
    output: ByteCommitsRef<OWFField<O>, O::NStBytes>,
    w: ByteCommitsRef<OWFField<O>, O::LEncBytes>,
    extended_key: &[ByteCommitsRef<OWFField<O>, O::NStBytes>],
) {
    let algebra = *hasher.algebra();

    // line 1
    let mut state = input.to_owned();
    state.add_round_key_assign(&extended_key[0]);
    let mut forward = Vec::with_capacity(O::NStBytes::USIZE);
    let mut backward = ByteCommits::default();

    // lines 10-14 (prepare the last-round state once)
    let mut final_state = output.to_owned();
    final_state.add_round_key_assign(&extended_key[O::R::USIZE]);

    for r in 0..O::R::USIZE / 2 {
        // line 4
        forward.clear();
        forward.extend(state.iter().map(|byte| sbox(&algebra, byte)));

        // line 5
        shift_rows(&mut forward);

        // line 6
        mix_columns::<OWFField<O>, _>(&mut forward);

        // line 7
        for (i, st_i) in forward.iter_mut().enumerate() {
            *st_i += extended_key[2 * r + 1]
                .get_field_commit(&algebra, i)
                .lift(&algebra);
        }

        // lines 10-14
        let last = r == O::R::USIZE / 2 - 1;
        let s_tilde = if last {
            final_state.to_ref()
        } else {
            w.get_commits_ref::<O::NStBytes>(O::NStBytes::USIZE * r)
        };
        // line 15-16
        s_tilde.inverse_shift_rows_into(&mut backward);
        backward.inverse_affine();

        // line 17-19
        for (b, &f) in backward.iter().zip(&forward) {
            hasher.hash_constraint(inverse_sbox(&algebra, b) + f);
        }
        // line 21-23
        if !last {
            s_tilde.bytewise_mix_columns_into(&mut state);
            state.add_round_key_assign(&extended_key[2 * r + 2]);
        }
    }
}

fn shift_rows<T: Copy>(state: &mut [T]) {
    let n = state.len() / 4;
    for row in 1..4 {
        let shift = row + usize::from(n == 8 && row > 1);
        let mut buffer = [state[row]; 8];
        for column in 0..n {
            buffer[column] = state[4 * ((column + shift) % n) + row];
        }
        for column in 0..n {
            state[4 * column + row] = buffer[column];
        }
    }
}

fn mix_columns<F: BigGaloisField, T>(state: &mut [T])
where
    T: Copy + core::ops::Add<Output = T> + core::ops::Mul<F, Output = T>,
{
    for column in state.as_chunks_mut::<4>().0 {
        let x = *column;
        let sum = x[0] + x[1] + x[2] + x[3];
        // lines 7-10 (3 mult per column instead of 8)
        let t0 = (x[0] + x[1]) * F::BYTE_COMBINE_2;
        let t1 = (x[1] + x[2]) * F::BYTE_COMBINE_2;
        let t2 = (x[2] + x[3]) * F::BYTE_COMBINE_2;
        // The four adjacent sums add to zero
        let products = [t0, t1, t2, t0 + t1 + t2];
        for r in 0..4 {
            column[r] = x[r] + sum + products[r];
        }
    }
}

#[inline]
fn f256_f2_conjugates<F: BigGaloisField, A: ConstraintAlgebra<F>>(
    algebra: &A,
    byte: &mut ByteCommitment<F>,
) -> [A::ConstraintDeg1; 8] {
    array::from_fn(|_| {
        let conjugate = byte.combine(algebra);
        byte.square_inplace();
        conjugate
    })
}

fn inverse_sbox<F: BigGaloisField, A: ConstraintAlgebra<F>>(
    algebra: &A,
    mut byte: ByteCommitment<F>,
) -> A::ConstraintDeg7 {
    // skip inverse_affine: computed in enc_cstrnts

    // line 3
    let conjugates = f256_f2_conjugates(algebra, &mut byte);

    // lines 4-6
    let p12 = conjugates[1] * conjugates[2];
    let p34 = conjugates[3] * conjugates[4];
    let p56 = conjugates[5] * conjugates[6];
    let left = p12 * p34;
    let right = p56 * conjugates[7];
    left * right
}

fn sbox<F: BigGaloisField, A: ConstraintAlgebra<F>>(
    algebra: &A,
    mut byte: ByteCommitment<F>,
) -> A::ConstraintDeg7 {
    // line 1
    let conjugates = f256_f2_conjugates(algebra, &mut byte);

    // line 8-10
    let p1: [A::ConstraintDeg2; 4] = array::from_fn(|i| conjugates[2 * i] * conjugates[2 * i + 1]);
    let f1: [A::ConstraintDeg1; 4] = array::from_fn(|i| {
        conjugates[2 * i + 1] * F::SIGMA[2 * i] + conjugates[2 * i] * F::SIGMA[2 * i + 1]
    });
    // line 11-13
    let p2: [A::ConstraintDeg4; 2] = array::from_fn(|i| p1[2 * i] * p1[2 * i + 1]);
    let f2: [A::ConstraintDeg3; 2] =
        array::from_fn(|i| f1[2 * i] * p1[2 * i + 1] + f1[2 * i + 1] * p1[2 * i]);
    // line 14
    f2[0] * p2[1] + f2[1] * p2[0] + algebra.constant_deg7(F::SIGMA[8])
}
