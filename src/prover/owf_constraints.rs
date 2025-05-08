use generic_array::{GenericArray, typenum::Unsigned};

use super::{
    ByteCommitsRef, FieldCommitDegThree, encryption::enc_cstrnts, key_expansion::key_exp_cstrnts,
};
use crate::{
    fields::{Field, FromBit},
    internal_keys::PublicKey,
    parameter::{OWFField, OWFParameters},
    rijndael_32::rijndael_key_schedule_unbitsliced,
    universal_hashing::ZKProofHasher,
    utils::xor_arrays,
};

pub(crate) fn owf_constraints<O>(
    zk_hasher: &mut ZKProofHasher<OWFField<O>>,
    w: ByteCommitsRef<OWFField<O>, O::LBytes>,
    pk: &PublicKey<O>,
) where
    O: OWFParameters,
{
    // ::1
    let PublicKey {
        owf_input: x,
        owf_output: y,
    } = pk;

    // ::5
    {
        let (k_0, k_1) = ((w.keys[0] & 0b1), (w.keys[0] & 0b10) >> 1);
        zk_hasher.update(&FieldCommitDegThree {
            key: OWFField::<O>::from_bit(k_0 & k_1),
            tag: [
                OWFField::<O>::ZERO,
                w.tags[0] * w.tags[1],
                w.tags[0] * k_1 + w.tags[1] * k_0,
            ],
        });
    }

    // ::7
    if O::is_em() {
        // ::8-9
        let ext_key = key_schedule_bytes::<O>(x);
        // ::10
        let owf_input = w.get_commits_ref::<O::NStBytes>(0);
        // ::11
        let owf_output_keys: GenericArray<u8, O::NStBytes> =
            xor_arrays(owf_input.keys.as_slice(), y.as_slice()).collect();
        let owf_output = ByteCommitsRef::from_slices(&owf_output_keys, owf_input.tags);
        // ::19 - EM = true
        let w_tilde = w.get_commits_ref::<O::LEncBytes>(O::LKeBytes::USIZE);
        // ::21 - EM = true
        enc_cstrnts::<O, _, _>(
            zk_hasher,
            owf_input,
            owf_output,
            w_tilde,
            ext_key.as_slice(),
        );
    } else {
        // ::13
        let mut owf_input = GenericArray::from_slice(x).to_owned();

        // ::16
        let k = key_exp_cstrnts::<O>(zk_hasher, w.get_commits_ref::<O::LKeBytes>(0));
        // Get references to the R+1 key commitments
        let extended_key: Vec<_> = (0..O::R::USIZE + 1)
            .map(|i| k.get_commits_ref::<O::NStBytes>(i * O::NStBytes::USIZE))
            .collect();

        // ::18-22
        for b in 0..O::Beta::USIZE {
            // ::19 - EM = false
            let w_tilde =
                w.get_commits_ref::<O::LEncBytes>(O::LKeBytes::USIZE + b * O::LEncBytes::USIZE);

            let owf_output = GenericArray::from_slice(
                &y[O::InputSize::USIZE * b..O::InputSize::USIZE * (b + 1)],
            );

            // ::21 - EM = false
            enc_cstrnts::<O, _, _>(
                zk_hasher,
                &owf_input,
                owf_output,
                w_tilde,
                extended_key.as_slice(),
            );

            // ::20
            owf_input[0] ^= 1;
        }
    }
}

#[inline]
fn key_schedule_bytes<O>(key: &GenericArray<u8, O::InputSize>) -> Vec<GenericArray<u8, O::NStBytes>>
where
    O: OWFParameters,
{
    rijndael_key_schedule_unbitsliced::<O::NSt, O::NK, O::R>(key, O::SKe::USIZE)
        .chunks_exact(32)
        .take(O::R::USIZE + 1)
        .map(|chunk| {
            chunk
                .iter()
                .copied()
                .take(O::NStBytes::USIZE)
                .collect::<GenericArray<u8, O::NStBytes>>()
        })
        .collect()
}
