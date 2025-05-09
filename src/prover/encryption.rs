use std::{iter::zip, ops::AddAssign};

use generic_array::{
    GenericArray,
    typenum::{Quot, U2, U4, U8, Unsigned},
};

use super::{ByteCommits, ByteCommitsRef, FieldCommitDegOne, FieldCommitDegTwo};
use crate::{
    aes::*,
    fields::{Betas, FromBit, Square},
    parameter::{OWFField, OWFParameters},
    prover::aes::{StateBitsSquaredCommits, StateBytesSquaredCommits},
    universal_hashing::ZKProofHasher,
};

pub(crate) fn enc_cstrnts<O, K, S>(
    zk_hasher: &mut ZKProofHasher<OWFField<O>>,
    input: impl for<'a> AddRoundKey<&'a K, Output = ByteCommits<OWFField<O>, O::NStBytes>>,
    output: impl for<'a> AddRoundKey<&'a K, Output = ByteCommits<OWFField<O>, O::NStBytes>>,
    w: ByteCommitsRef<OWFField<O>, O::LEncBytes>,
    extended_key: &[K],
) where
    O: OWFParameters,
    K: StateToBytes<O, Output = Box<GenericArray<S, O::NStBytes>>>,
    S: Square + Clone,
    for<'a> FieldCommitDegTwo<OWFField<O>>: AddAssign<&'a S>,
    for<'a> FieldCommitDegTwo<OWFField<O>>: AddAssign<&'a <S as Square>::Output>,
    ByteCommits<OWFField<O>, O::NStBytes>: for<'a> AddRoundKeyAssign<&'a K>,
    for<'a> ByteCommitsRef<'a, OWFField<O>, O::NStBytes>:
        BytewiseMixColumns<O, Output = ByteCommits<OWFField<O>, O::NStBytes>>,
{
    // ::1
    let mut state = input.add_round_key(&extended_key[0]);

    // ::2
    for r in 0..O::R::USIZE / 2 {
        // ::3-15
        let state_prime = enc_cstrnts_even::<O>(
            zk_hasher,
            &state,
            w.get_commits_ref::<Quot<O::NStBytes, U2>>(3 * O::NStBytes::USIZE * r / 2),
        );

        // ::16-17
        let round_key = extended_key[2 * r + 1].state_to_bytes();
        let round_key_sq = (&round_key).square();

        // ::18-22
        let st_0 = aes_round::<O, _>(&state_prime, &round_key, false);
        let st_1 = aes_round::<O, _>(&state_prime, &round_key_sq, true);

        let round_key = &extended_key[2 * r + 2];

        if r != O::R::USIZE / 2 - 1 {
            let s_tilde = w.get_commits_ref::<O::NStBytes>(
                O::NStBytes::USIZE / 2 + 3 * O::NStBytes::USIZE * r / 2,
            );

            // ::29-38
            enc_cstrnts_odd::<O>(zk_hasher, s_tilde, &st_0, &st_1);

            // ::39-40
            state = s_tilde.bytewise_mix_columns();
            state.add_round_key_assign(round_key);
        } else {
            let s_tilde = output.add_round_key(round_key);

            // ::29-38
            enc_cstrnts_odd::<O>(zk_hasher, s_tilde.to_ref(), &st_0, &st_1);
        }
    }
}

fn enc_cstrnts_even<O>(
    zk_hasher: &mut ZKProofHasher<OWFField<O>>,
    state: &ByteCommits<OWFField<O>, O::NStBytes>,
    w: ByteCommitsRef<OWFField<O>, Quot<O::NStBytes, U2>>,
) -> StateBitsSquaredCommits<O>
where
    O: OWFParameters,
{
    // ::4
    let mut state_prime = StateBitsSquaredCommits::<O>::default();
    let mut state_conj = GenericArray::default();

    // ::7
    for (i, state_prime) in state_prime.chunks_exact_mut(8).enumerate() {
        // ::9
        let norm = (w.keys[i / 2] >> ((i % 2) * 4)) & 0xf;
        let ys = invnorm_to_conjugates::<O>(norm, &w.tags[4 * i..4 * i + 4]);

        // ::4
        f256_f2_conjugates_2::<O>(&mut state_conj, state, i);

        //::11
        // Save 1 mul by storing intermediate constraint in state'[0]
        state_prime[0] = &ys[0] * &state_conj[4];
        let cnstr = &state_prime[0] * &state_conj[1] + &state_conj[0];
        zk_hasher.update(&cnstr);

        // ::12
        for j in 1..8 {
            state_prime[j] = &state_conj[(j + 4) % 8] * &ys[j % 4];
        }
    }

    state_prime
}

fn enc_cstrnts_odd<O>(
    zk_hasher: &mut ZKProofHasher<OWFField<O>>,
    s_tilde: ByteCommitsRef<OWFField<O>, O::NStBytes>,
    st_0: &StateBytesSquaredCommits<O>,
    st_1: &StateBytesSquaredCommits<O>,
) where
    O: OWFParameters,
    ByteCommits<OWFField<O>, O::NStBytes>: InverseAffine,
    for<'a> ByteCommitsRef<'a, OWFField<O>, O::NStBytes>:
        InverseShiftRows<O, Output = ByteCommits<OWFField<O>, O::NStBytes>>,
{
    // ::29-30
    let mut s = s_tilde.inverse_shift_rows();
    s.inverse_affine();

    // ::31-37
    for (si, si_sq, st0_i, st1_i) in
        zip(st_0.iter(), st_1.iter())
            .enumerate()
            .map(|(byte_i, (st0, st1))| {
                (
                    s.get_field_commit(byte_i),
                    s.get_field_commit_sq(byte_i),
                    st0,
                    st1,
                )
            })
    {
        zk_hasher.odd_round_cstrnts(&si, &si_sq, st0_i, st1_i);
    }
}

fn aes_round<O, T>(
    state: &StateBitsSquaredCommits<O>,
    key_bytes: &GenericArray<T, O::NStBytes>,
    sq: bool,
) -> StateBytesSquaredCommits<O>
where
    O: OWFParameters,
    StateBitsSquaredCommits<O>: SBoxAffine<O, Output = StateBytesSquaredCommits<O>>,
    FieldCommitDegTwo<OWFField<O>>: for<'a> AddAssign<&'a T>,
    StateBytesSquaredCommits<O>: MixColumns<O>,
{
    // ::19-22
    let mut st = state.s_box_affine(sq);
    st.shift_rows();
    st.mix_columns(sq);
    st.add_round_key_bytes(key_bytes, sq);
    st
}

fn invnorm_to_conjugates<O>(
    x_val: u8,
    x_tag: &[OWFField<O>],
) -> GenericArray<FieldCommitDegOne<OWFField<O>>, U4>
where
    O: OWFParameters,
{
    (0..4)
        .map(|j| {
            let key = OWFField::<O>::from_bit(x_val & 1)
                + OWFField::<O>::BETA_SQUARES[j] * ((x_val >> 1) & 1)
                + OWFField::<O>::BETA_SQUARES[j + 1] * ((x_val >> 2) & 1)
                + OWFField::<O>::BETA_CUBES[j] * ((x_val >> 3) & 1);

            let tag = x_tag[0]
                + OWFField::<O>::BETA_SQUARES[j] * x_tag[1]
                + OWFField::<O>::BETA_SQUARES[j + 1] * x_tag[2]
                + OWFField::<O>::BETA_CUBES[j] * x_tag[3];

            FieldCommitDegOne::new(key, tag)
        })
        .collect()
}

pub(crate) fn f256_f2_conjugates_2<O>(
    state_conj: &mut GenericArray<FieldCommitDegOne<OWFField<O>>, U8>,
    state: &ByteCommits<OWFField<O>, O::NStBytes>,
    round: usize,
) where
    O: OWFParameters,
{
    let mut x0 = state.get(round);
    // ::4-8
    for st_conj_i in state_conj.iter_mut() {
        *st_conj_i = x0.combine();
        x0.square_inplace();
    }
}
