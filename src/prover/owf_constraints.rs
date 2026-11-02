use hybrid_array::{Array, typenum::Unsigned};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::{
    ByteCommits, ByteCommitsRef, FieldCommitDegOne, encryption::enc_cstrnts,
    key_expansion::key_exp_cstrnts,
};
use crate::{
    fields::FromBit,
    internal_keys::PublicKey,
    parameter::{OWFField, OWFParameters},
    prover::polynomial::Polynomial,
    rijndael_32::{rijndael_key_schedule_unbitsliced, ske},
    utils::xor_arrays,
    zk_constraints::ConstraintHasher,
};

pub(crate) fn owf_constraints<O>(
    zk_hasher: &mut impl ConstraintHasher<OWFField<O>>,
    w: ByteCommitsRef<OWFField<O>, O::LBytes>,
    pk: &PublicKey<O>,
) where
    O: OWFParameters,
{
    // line 1
    let PublicKey {
        owf_input: x,
        owf_output: y,
    } = pk;

    // line 5
    {
        let (k_0, k_1) = ((w.keys[0] & 0b1), (w.keys[0] & 0b10) >> 1);
        let a = Polynomial::commitment(&FieldCommitDegOne::new(
            OWFField::<O>::from_bit(k_0),
            w.tags[0],
        ));
        let b = Polynomial::commitment(&FieldCommitDegOne::new(
            OWFField::<O>::from_bit(k_1),
            w.tags[1],
        ));
        zk_hasher.hash_constraint((a * b).lift(7));
    }

    if O::IS_EM {
        // lines 8-9
        let ext_key = key_schedule_commits::<O>(x);
        let ext_key_refs: Vec<_> = ext_key.iter().map(|k| k.to_ref()).collect();
        // line 10
        let owf_input = w.get_commits_ref::<O::NStBytes>(0);
        // line 11
        let owf_output_keys: Array<u8, O::NStBytes> =
            xor_arrays(owf_input.keys.as_slice(), y.as_slice()).collect();
        let owf_output = ByteCommitsRef::from_slices(&owf_output_keys, owf_input.tags);
        // line 19 - EM = true
        let w_tilde = w.get_commits_ref::<O::LEncBytes>(O::LKeBytes::USIZE);
        // line 21 - EM = true
        enc_cstrnts::<O>(
            zk_hasher,
            owf_input,
            owf_output,
            w_tilde,
            ext_key_refs.as_slice(),
        );
    } else {
        // line 13
        let mut owf_input = ByteCommits::<OWFField<O>, O::NStBytes>::default();
        owf_input.keys.copy_from_slice(x);

        // lines 16-17
        let k = key_exp_cstrnts::<O>(zk_hasher, w.get_commits_ref::<O::LKeBytes>(0));
        // Get references to the R+1 key commitments
        let extended_key: Vec<_> = (0..=O::R::USIZE)
            .map(|i| k.get_commits_ref::<O::NStBytes>(i * O::NStBytes::USIZE))
            .collect();

        // lines 18-22
        for b in 0..O::Beta::USIZE {
            // lines 19 - EM = false
            let w_tilde =
                w.get_commits_ref::<O::LEncBytes>(O::LKeBytes::USIZE + b * O::LEncBytes::USIZE);

            // lines 14-15
            let mut owf_output = ByteCommits::<OWFField<O>, O::NStBytes>::default();
            owf_output
                .keys
                .copy_from_slice(&y[O::NStBytes::USIZE * b..O::NStBytes::USIZE * (b + 1)]);

            // lines 20
            if b == 1 {
                owf_input.keys[0] ^= 1;
            }

            // lines 21-22 - EM = false
            enc_cstrnts::<O>(
                zk_hasher,
                owf_input.to_ref(),
                owf_output.to_ref(),
                w_tilde,
                extended_key.as_slice(),
            );
        }
    }
}

#[inline]
fn key_schedule_commits<O>(
    key: &Array<u8, O::InputSize>,
) -> Vec<ByteCommits<OWFField<O>, O::NStBytes>>
where
    O: OWFParameters,
{
    rijndael_key_schedule_unbitsliced::<O::NSt, O::NK, O::R>(
        key,
        ske(O::R::USIZE, O::NSt::USIZE, O::NK::USIZE),
    )
    .chunks_exact(32)
    .take(O::R::USIZE + 1)
    .map(|chunk| {
        let mut commitment = ByteCommits::<OWFField<O>, O::NStBytes>::default();
        commitment
            .keys
            .copy_from_slice(&chunk[..O::NStBytes::USIZE]);
        commitment
    })
    .collect()
}
