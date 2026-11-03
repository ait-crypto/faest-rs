use super::hashing::ConstraintHasher;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::{ByteCommitsRef, byte_commitment::ByteCommitment, polynomial::Polynomial};
use crate::{
    aes::{AddRoundKeyAssign, BytewiseMixColumns, InverseAffine, InverseShiftRows}, fields::{BigGaloisField, ByteCombineConstants, Sigmas}, parameter::{OWFField, OWFParameters},
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
    // line 1
    let mut state = input.to_owned();
    state.add_round_key_assign(&extended_key[0]);

    for r in 0..O::R::USIZE / 2 {
        // line 4
        let mut st: Vec<_> = state.iter().map(sbox).collect();

        // line 5
        shift_rows::<O>(&mut st);

        // line 6
        mix_columns::<O>(&mut st);

        // line 7
        add_round_key::<O>(&mut st, &extended_key[2 * r + 1]);

        // lines 10-14
        let last = r == O::R::USIZE / 2 - 1;
        // TODO: should we avoid this?
        let final_state;
        let s_tilde = if last {
            final_state = {
                let mut state = output.to_owned();
                state.add_round_key_assign(&extended_key[O::R::USIZE]);
                state
            };
            final_state.to_ref()
        } else {
            w.get_commits_ref::<O::NStBytes>(O::NStBytes::USIZE * r)
        };

        // line 15-16
        let mut backward =
            <ByteCommitsRef<OWFField<O>, O::NStBytes> as InverseShiftRows<O>>::inverse_shift_rows(
                &s_tilde,
            );
        backward.inverse_affine();

        // line 17-19
        for (b, forward) in backward.iter().zip(st) {
            hasher.hash_constraint(inverse_sbox(b) + forward);
        }

        // line 21-23
        if !last {
            state = <ByteCommitsRef<OWFField<O>, O::NStBytes> as BytewiseMixColumns<O>>::bytewise_mix_columns(&s_tilde);
            state.add_round_key_assign(&extended_key[2 * r + 2]);
        }
    }
}

fn shift_rows<O: OWFParameters>(state: &mut [Polynomial<OWFField<O>>]) {
    let n = O::NSt::USIZE;
    for row in 1..4 {
        let shift = row + usize::from(n == 8 && row > 1);
        for _ in 0..shift {
            for column in 0..n - 1 {
                state.swap(4 * column + row, 4 * (column + 1) + row);
            }
        }
    }
}

fn mix_columns<O: OWFParameters>(state: &mut [Polynomial<OWFField<O>>]) {
    let v2 = OWFField::<O>::BYTE_COMBINE_2;
    let v3 = OWFField::<O>::BYTE_COMBINE_3;
    for scalars in state.as_chunks_mut::<4>().0 {
        let xi = *scalars;
        // lines 7-10
        scalars[0] = xi[0] * v2 + xi[1] * v3 + xi[2] + xi[3];
        scalars[1] = xi[1] * v2 + xi[2] * v3 + xi[0] + xi[3];
        scalars[2] = xi[2] * v2 + xi[3] * v3 + xi[0] + xi[1];
        scalars[3] = xi[0] * v3 + xi[3] * v2 + xi[1] + xi[2];
    }
}

fn add_round_key<O: OWFParameters>(
    state: &mut [Polynomial<OWFField<O>>],
    key: &ByteCommitsRef<OWFField<O>, O::NStBytes>,
) {
    for (i, st_i) in state.iter_mut().enumerate() {
        *st_i += &key.get_field_commit(i).lift(7);
    }
}

#[inline]
fn f256_f2_conjugates<F: BigGaloisField>(byte: &mut ByteCommitment<F>) -> [Polynomial<F>; 8] {
    array::from_fn(|_| {
        let conjugate = byte.combine();
        byte.square_inplace();
        conjugate
    })
}

fn inverse_sbox<F: BigGaloisField>(mut byte: ByteCommitment<F>) -> Polynomial<F> {
    // skip inverse_affine: computed in encr_constraints

    // line 3
    let conjugates = f256_f2_conjugates(&mut byte);

    // lines 4-6
    conjugates
        .into_iter()
        .skip(1)
        .fold(Polynomial::constant(F::ONE), |p, c| p * c)
}

fn sbox<F: BigGaloisField>(mut byte: ByteCommitment<F>) -> Polynomial<F> {
    // line 1
    let conjugates: [Polynomial<F>; 8] = f256_f2_conjugates(&mut byte);

    // line 8-10
    let p1: [Polynomial<F>; 4] =
        core::array::from_fn(|i| &conjugates[2 * i] * &conjugates[2 * i + 1]);
    let f1: [Polynomial<F>; 4] = core::array::from_fn(|i| {
        conjugates[2 * i + 1] * F::SIGMA[2 * i] + conjugates[2 * i] * F::SIGMA[2 * i + 1]
    });

    // line 11-13
    let p2: [Polynomial<F>; 2] = core::array::from_fn(|i| &p1[2 * i] * &p1[2 * i + 1]);
    let f2: [Polynomial<F>; 2] =
        core::array::from_fn(|i| &f1[2 * i] * &p1[2 * i + 1] + &f1[2 * i + 1] * &p1[2 * i]);

    // line 14
    let [f_left, f_right] = f2;
    let [p_left, p_right] = p2;
    f_left * p_right + f_right * p_left + Polynomial::constant(F::SIGMA[8]).lift(7)
}
