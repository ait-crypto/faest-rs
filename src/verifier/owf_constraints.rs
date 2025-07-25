use std::array;

use generic_array::{GenericArray, typenum::Unsigned};

use super::{
    encryption,
    key_expansion::key_exp_cstrnts,
    vole_commitments::{VoleCommits, VoleCommitsRef},
};

use crate::{
    aes::AddRoundKey,
    fields::BigGaloisField,
    internal_keys::PublicKey,
    parameter::{OWFField, OWFParameters},
    rijndael_32::rijndael_key_schedule_unbitsliced,
    universal_hashing::ZKVerifyHasher,
};

pub(crate) fn owf_constraints<O>(
    zk_hasher: &mut ZKVerifyHasher<OWFField<O>>,
    w: VoleCommitsRef<'_, OWFField<O>, O::L>,
    delta: &OWFField<O>,
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
    zk_hasher.mul_and_update(&w.scalars[0], &w.scalars[1]);

    // ::7
    if O::IS_EM {
        // ::8-9
        let extended_key = key_schedule_bytes::<O>(x, delta);
        // ::10
        let owf_input = w.get_commits_ref::<O::NStBits>(0);
        // ::11
        let owf_output = owf_input.add_round_key(GenericArray::<u8, O::NStBytes>::from_slice(y));
        // ::19 - EM = true
        let w_tilde = w.get_commits_ref::<O::LEnc>(O::LKe::USIZE);
        // ::21 - EM = true
        encryption::enc_cstrnts::<O, _>(
            zk_hasher,
            owf_input,
            owf_output.to_ref(),
            w_tilde,
            extended_key.as_slice(),
        );
    } else {
        // ::13
        let mut owf_input: VoleCommits<_, O::NStBits> = VoleCommits::from_constant(
            GenericArray::<u8, O::NStBytes>::from_slice(x.as_slice()),
            delta,
        );

        // ::16
        let k = key_exp_cstrnts::<O>(zk_hasher, w.get_commits_ref::<O::LKe>(0));
        let extended_key: Vec<_> = (0..=O::R::USIZE)
            .map(|i| k.get_commits_ref::<O::NStBits>(i * O::NStBits::USIZE))
            .collect();

        // ::18-22
        for b in 0..O::Beta::USIZE {
            // ::19 - EM = false
            let w_tilde = w.get_commits_ref::<O::LEnc>(O::LKe::USIZE + b * O::LEnc::USIZE);
            let owf_output = GenericArray::<u8, O::NStBytes>::from_slice(
                &y[O::InputSize::USIZE * b..O::InputSize::USIZE * (b + 1)],
            );
            let owf_output = VoleCommits::from_constant(owf_output, delta);
            // ::21 - EM = false
            encryption::enc_cstrnts::<O, _>(
                zk_hasher,
                owf_input.to_ref(),
                owf_output.to_ref(),
                w_tilde,
                extended_key.as_slice(),
            );
            // ::20
            owf_input.scalars[0] += delta;
        }
    }
}

#[inline]
fn byte_to_field<F>(byte: u8, delta: F) -> [F; 8]
where
    F: BigGaloisField,
{
    array::from_fn(|i| delta * ((byte >> i) & 1))
}

#[inline]
fn key_schedule_bytes<'a, O>(
    key: &GenericArray<u8, O::InputSize>,
    delta: &'a OWFField<O>,
) -> Vec<VoleCommits<'a, OWFField<O>, O::NStBits>>
where
    O: OWFParameters,
{
    rijndael_key_schedule_unbitsliced::<O::NSt, O::NK, O::R>(key, O::SKe::USIZE)
        .chunks_exact(32)
        .take(O::R::USIZE + 1)
        .map(|chunk| {
            let scalars = chunk[..O::NStBytes::USIZE]
                .iter()
                .flat_map(|&byte| byte_to_field(byte, *delta))
                .collect();
            VoleCommits { scalars, delta }
        })
        .collect()
}
