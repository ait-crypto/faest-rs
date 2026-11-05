mod aes;
mod algebra;
mod byte_commitment;
mod encryption;
mod hashing;
mod key_expansion;
mod owf_constraints;
mod polynomial;
#[cfg(test)]
mod tests;

use byte_commitment::{ByteCommits, ByteCommitsRef};
use hashing::{ZKProofHasher, ZKVerifyHasher};
use owf_constraints::owf_constraints;

use crate::{
    internal_keys::PublicKeyView,
    parameter::{BaseParameters, OWFField, OWFParameters, QSProof},
    universal_hashing::ZKHasherInit,
    utils::get_bit,
};
use hybrid_array::{Array, typenum::Unsigned};

pub(crate) type Challenge<O> =
    Array<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>;

pub(crate) fn owf_prove<O: OWFParameters>(
    w: &Array<u8, O::LBytes>,
    v: &Array<OWFField<O>, O::L>,
    masks: &[(OWFField<O>, OWFField<O>); 6],
    pk: &PublicKeyView<'_, O>,
    chall_2: &Challenge<O>,
) -> QSProof<O> {
    let mut hasher = ZKProofHasher::new(
        <O::BaseParams as BaseParameters>::ZKHasher::new_zk_hasher(chall_2),
    );
    // lines 2-3 + lift (line 9)
    hasher.hash_bit_constraints(v);

    // line 11
    owf_constraints::<O>(&mut hasher, ByteCommitsRef::from_slices(w, v), pk);
    debug_assert_eq!(hasher.count, O::C::USIZE);

    // lines 12-19
    hasher.finalize(masks)
}

/// Applies witness corrections to raw VOLE shares in place and recovers the proof constant.
pub(crate) fn owf_verify<O: OWFParameters>(
    d: &Array<u8, O::LBytes>,
    q: &mut Array<OWFField<O>, O::L>,
    q_bar: &[OWFField<O>; 6],
    pk: &PublicKeyView<'_, O>,
    chall_2: &Challenge<O>,
    delta: OWFField<O>,
    a_tilde: &[OWFField<O>; 6],
) -> OWFField<O> {
    let mut hasher = ZKVerifyHasher::new(
        <O::BaseParams as BaseParameters>::ZKHasher::new_zk_hasher(chall_2),
        delta,
    );

    // lines 2-3
    for (i, share) in q.iter_mut().enumerate() {
        *share += delta * get_bit(d, i);
    }

    // line 9
    hasher.hash_bit_constraints(q);

    // line 11
    let zero = Array::<u8, O::LBytes>::default();
    owf_constraints::<O>(&mut hasher, ByteCommitsRef::from_slices(&zero, q), pk);
    debug_assert_eq!(hasher.count, O::C::USIZE);

    // lines 5,14-16
    hasher.finalize(q_bar, a_tilde)
}
