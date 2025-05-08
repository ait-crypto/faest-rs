use std::ops::Mul;

use generic_array::{
    ArrayLength, GenericArray,
    typenum::{Prod, U8},
};

use super::field_commitment::FieldCommitDegOne;
use crate::fields::{BigGaloisField, GF8};

#[derive(Clone, Debug, Default)]
pub(crate) struct ByteCommitment<F>
where
    F: BigGaloisField,
{
    pub(crate) key: u8,
    pub(crate) tags: GenericArray<F, U8>,
}

impl<F> ByteCommitment<F>
where
    F: BigGaloisField,
{
    pub fn square_inplace(&mut self) {
        F::square_byte_inplace(self.tags.as_mut_slice());
        self.key = GF8::square_bits(self.key);
    }

    pub fn combine(&self) -> FieldCommitDegOne<F> {
        FieldCommitDegOne::new(
            F::byte_combine_bits(self.key),
            F::byte_combine_slice(self.tags.as_slice()),
        )
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ByteCommits<F, L>
where
    F: BigGaloisField,
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
{
    pub(crate) keys: Box<GenericArray<u8, L>>,
    pub(crate) tags: Box<GenericArray<F, Prod<L, U8>>>,
}

impl<F, L> ByteCommits<F, L>
where
    F: BigGaloisField,
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
{
    pub(crate) fn new(
        keys: Box<GenericArray<u8, L>>,
        tags: Box<GenericArray<F, Prod<L, U8>>>,
    ) -> Self {
        Self { keys, tags }
    }

    pub(crate) fn get_field_commit(&self, index: usize) -> FieldCommitDegOne<F> {
        FieldCommitDegOne::new(
            F::byte_combine_bits(self.keys[index]),
            F::byte_combine_slice(&self.tags[index * 8..index * 8 + 8]),
        )
    }

    pub(crate) fn get_field_commit_sq(&self, index: usize) -> FieldCommitDegOne<F> {
        FieldCommitDegOne::new(
            F::byte_combine_bits_sq(self.keys[index]),
            F::byte_combine_sq_slice(&self.tags[index * 8..index * 8 + 8]),
        )
    }

    pub(crate) fn get_commits_ref<L2>(&self, start_byte: usize) -> ByteCommitsRef<F, L2>
    where
        L2: ArrayLength + Mul<U8, Output: ArrayLength>,
    {
        debug_assert!(start_byte + L2::USIZE <= L::USIZE);

        ByteCommitsRef {
            keys: GenericArray::from_slice(&self.keys[start_byte..start_byte + L2::USIZE]),
            tags: GenericArray::from_slice(
                &self.tags[start_byte * 8..(start_byte + L2::USIZE) * 8],
            ),
        }
    }

    pub(crate) fn to_ref(&self) -> ByteCommitsRef<F, L> {
        ByteCommitsRef {
            keys: &self.keys,
            tags: &self.tags,
        }
    }

    pub(crate) fn get(&self, idx: usize) -> ByteCommitment<F> {
        ByteCommitment {
            key: self.keys[idx],
            tags: GenericArray::from_slice(&self.tags[idx * 8..idx * 8 + 8]).to_owned(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ByteCommitsRef<'a, F, L>
where
    F: BigGaloisField,
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
{
    pub(crate) keys: &'a GenericArray<u8, L>,
    pub(crate) tags: &'a GenericArray<F, Prod<L, U8>>,
}

impl<'a, F, L> ByteCommitsRef<'a, F, L>
where
    F: BigGaloisField,
    L: ArrayLength + Mul<U8, Output: ArrayLength>,
{
    /// Create a new instance of ByteCommitsRef from slices to commitment keys and tags.
    ///
    /// Panics if the lengths of the keys is not equal to the length of the tags divided by 8.
    pub(crate) fn from_slices(keys: &'a [u8], tags: &'a [F]) -> Self {
        Self {
            keys: GenericArray::from_slice(keys),
            tags: GenericArray::from_slice(tags),
        }
    }

    pub(crate) fn get_commits_ref<L2>(&self, start_byte: usize) -> ByteCommitsRef<F, L2>
    where
        L2: ArrayLength + Mul<U8, Output: ArrayLength>,
    {
        debug_assert!(start_byte + L2::USIZE <= L::USIZE);

        ByteCommitsRef {
            keys: GenericArray::from_slice(&self.keys[start_byte..start_byte + L2::USIZE]),
            tags: GenericArray::from_slice(
                &self.tags[start_byte * 8..(start_byte + L2::USIZE) * 8],
            ),
        }
    }
}
