use super::algebra::ConstraintAlgebra;
use core::ops::Mul;

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box};

use hybrid_array::{
    Array, ArraySize,
    typenum::{Prod, U8},
};

use crate::{
    fields::{BigGaloisField, GF8},
    utils::array_ref,
};

#[derive(Clone, Debug, Default)]
pub(super) struct ByteCommitment<F>
where
    F: BigGaloisField,
{
    pub(super) key: u8,
    pub(super) tags: Array<F, U8>,
}

impl<F> ByteCommitment<F>
where
    F: BigGaloisField,
{
    pub fn square_inplace(&mut self) {
        F::square_byte_inplace(self.tags.as_mut_slice());
        self.key = GF8::square_bits(self.key);
    }

    pub fn combine<A: ConstraintAlgebra<F>>(&self, algebra: &A) -> A::ConstraintDeg1 {
        algebra.linear_constraint(
            F::byte_combine_bits(self.key),
            F::byte_combine_slice(self.tags.as_slice()),
        )
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct ByteCommits<F, L>
where
    F: BigGaloisField,
    L: ArraySize + Mul<U8, Output: ArraySize>,
{
    pub(super) keys: Box<Array<u8, L>>,
    pub(super) tags: Box<Array<F, Prod<L, U8>>>,
}

impl<F, L> ByteCommits<F, L>
where
    F: BigGaloisField,
    L: ArraySize + Mul<U8, Output: ArraySize>,
{
    pub(super) fn get_field_commit<A: ConstraintAlgebra<F>>(
        &self,
        algebra: &A,
        index: usize,
    ) -> A::ConstraintDeg1 {
        algebra.linear_constraint(
            F::byte_combine_bits(self.keys[index]),
            F::byte_combine_slice(&self.tags[index * 8..index * 8 + 8]),
        )
    }

    pub(super) fn get_field_commit_sq<A: ConstraintAlgebra<F>>(
        &self,
        algebra: &A,
        index: usize,
    ) -> A::ConstraintDeg1 {
        algebra.linear_constraint(
            F::byte_combine_bits_sq(self.keys[index]),
            F::byte_combine_sq_slice(&self.tags[index * 8..index * 8 + 8]),
        )
    }

    pub(super) fn get_commits_ref<L2>(&self, start_byte: usize) -> ByteCommitsRef<'_, F, L2>
    where
        L2: ArraySize + Mul<U8, Output: ArraySize>,
    {
        debug_assert!(start_byte + L2::USIZE <= L::USIZE);

        ByteCommitsRef {
            keys: array_ref(&self.keys[start_byte..start_byte + L2::USIZE]),
            tags: array_ref(&self.tags[start_byte * 8..(start_byte + L2::USIZE) * 8]),
        }
    }

    pub(super) fn to_ref(&self) -> ByteCommitsRef<'_, F, L> {
        ByteCommitsRef {
            keys: &self.keys,
            tags: &self.tags,
        }
    }

    fn get(&self, idx: usize) -> ByteCommitment<F> {
        ByteCommitment {
            key: self.keys[idx],
            tags: self.tags[idx * 8..idx * 8 + 8].iter().cloned().collect(),
        }
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = ByteCommitment<F>> {
        (0..L::USIZE).map(|idx| self.get(idx))
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ByteCommitsRef<'a, F, L>
where
    F: BigGaloisField,
    L: ArraySize + Mul<U8, Output: ArraySize>,
{
    pub(super) keys: &'a Array<u8, L>,
    pub(super) tags: &'a Array<F, Prod<L, U8>>,
}

impl<'a, F, L> ByteCommitsRef<'a, F, L>
where
    F: BigGaloisField,
    L: ArraySize + Mul<U8, Output: ArraySize>,
{
    pub(super) fn to_owned(self) -> ByteCommits<F, L> {
        ByteCommits {
            keys: Box::new(self.keys.clone()),
            tags: Box::new(self.tags.clone()),
        }
    }

    /// Create a new instance of ByteCommitsRef from slices to commitment keys and tags.
    ///
    /// Panics if the lengths of the keys is not equal to the length of the tags divided by 8.
    pub(super) fn from_slices(keys: &'a [u8], tags: &'a [F]) -> Self {
        Self {
            keys: array_ref(keys),
            tags: array_ref(tags),
        }
    }

    pub(super) fn get_field_commit<A: ConstraintAlgebra<F>>(
        &self,
        algebra: &A,
        index: usize,
    ) -> A::ConstraintDeg1 {
        algebra.linear_constraint(
            F::byte_combine_bits(self.keys[index]),
            F::byte_combine_slice(&self.tags[index * 8..index * 8 + 8]),
        )
    }

    pub(super) fn get_commits_ref<L2>(&self, start_byte: usize) -> ByteCommitsRef<'_, F, L2>
    where
        L2: ArraySize + Mul<U8, Output: ArraySize>,
    {
        debug_assert!(start_byte + L2::USIZE <= L::USIZE);

        ByteCommitsRef {
            keys: array_ref(&self.keys[start_byte..start_byte + L2::USIZE]),
            tags: array_ref(&self.tags[start_byte * 8..(start_byte + L2::USIZE) * 8]),
        }
    }
}
