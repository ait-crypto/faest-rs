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
    parameter::{BaseParameters, OWFField, OWFParameters},
    rijndael_32::{convert_from_batchblocks, inv_bitslice, rijndael_key_schedule},
    universal_hashing::ZKVerifyHasher,
    utils::get_bit,
};

pub(crate) fn owf_constraints<O>(
    zk_hasher: &mut ZKVerifyHasher<OWFField<O>>,
    w: VoleCommitsRef<'_, OWFField<O>, O::L>,
    delta: &OWFField<O>,
    pk: &PublicKey<O>,
) where
    O: OWFParameters,
    <<O as OWFParameters>::BaseParams as BaseParameters>::Field: PartialEq,
{
    // ::1
    let PublicKey {
        owf_input: x,
        owf_output: y,
    } = pk;

    // ::5
    zk_hasher.mul_and_update(&w.scalars[0], &w.scalars[1]);

    // ::7
    if O::is_em() {
        // ::8-9
        let extended_key = key_schedule_bytes::<O>(x, delta);
        // ::10
        let owf_input = w.get_commits_ref::<O::NSTBits>(0);
        // ::11
        let owf_output = owf_input.add_round_key(GenericArray::<u8, O::NSTBytes>::from_slice(y));
        // ::19 - EM = true
        let w_tilde = w.get_commits_ref::<O::LENC>(O::LKE::USIZE);
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
        let mut owf_input: VoleCommits<_, O::NSTBits> = VoleCommits::from_constant(
            GenericArray::<u8, O::NSTBytes>::from_slice(x.as_slice()),
            delta,
        );

        // ::16
        let k = key_exp_cstrnts::<O>(zk_hasher, w.get_commits_ref::<O::LKE>(0));
        let extended_key: Vec<_> = (0..O::R::USIZE + 1)
            .map(|i| k.get_commits_ref::<O::NSTBits>(i * O::NSTBits::USIZE))
            .collect();

        // ::18-22
        for b in 0..O::BETA::USIZE {
            // ::19 - EM = false
            let w_tilde = w.get_commits_ref::<O::LENC>(O::LKE::USIZE + b * O::LENC::USIZE);
            let owf_output = GenericArray::<u8, O::NSTBytes>::from_slice(
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

// Converts a byte into an iterator of field elements, where the bit 1 is represented by the delta and 0 by the field's neutral element.
fn byte_to_vole<F>(x: u8, delta: &F) -> impl Iterator<Item = F> + '_
where
    F: BigGaloisField,
{
    (0..8).map(move |i| {
        if get_bit(&[x], i) != 0 {
            return *delta;
        }
        F::ZERO
    })
}

#[inline]
fn key_schedule_bytes<'a, O>(
    key: &GenericArray<u8, O::InputSize>,
    delta: &'a OWFField<O>,
) -> Vec<VoleCommits<'a, OWFField<O>, O::NSTBits>>
where
    O: OWFParameters,
{
    rijndael_key_schedule::<O::NST, O::NK, O::R>(key, O::SKE::USIZE)
        .0
        .chunks_exact(8)
        .take(O::R::USIZE + 1)
        .map(|chunk| {
            let scalars = <Box<GenericArray<OWFField<O>, O::NSTBits>>>::from_iter(
                convert_from_batchblocks(inv_bitslice(chunk))
                    .take(O::NST::USIZE)
                    .flat_map(|word| word.into_iter().flat_map(|byte| byte_to_vole(byte, delta))),
            );

            VoleCommits { scalars, delta }
        })
        .collect()
}
