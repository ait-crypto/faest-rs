use std::ops::{Index, Mul, Range};

use generic_array::{ArrayLength, GenericArray, typenum::U8};

use crate::{fields::BigGaloisField, utils::get_bit};

#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub(crate) struct VoleCommits<'a, F: BigGaloisField, L: ArrayLength> {
    pub(crate) scalars: Box<GenericArray<F, L>>,
    pub(crate) delta: &'a F,
}

impl<'a, F, L> VoleCommits<'a, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    /// Turns the input array into vole commitments using the challenge delta.
    pub(crate) fn from_constant<L2>(
        input: &GenericArray<u8, L>,
        delta: &'a F,
    ) -> VoleCommits<'a, F, L2>
    where
        L: ArrayLength + Mul<U8, Output = L2>,
        L2: ArrayLength,
    {
        let scalars = <Box<GenericArray<F, L2>>>::from_iter((0..L2::USIZE).map(|i| {
            if get_bit(input, i) != 0 {
                return *delta;
            }
            F::ZERO
        }));

        VoleCommits { scalars, delta }
    }

    pub(crate) fn to_ref(&self) -> VoleCommitsRef<'_, F, L> {
        VoleCommitsRef {
            scalars: &self.scalars,
            delta: self.delta,
        }
    }

    pub(crate) fn get_commits_ref<L2>(&self, start_idx: usize) -> VoleCommitsRef<F, L2>
    where
        L2: ArrayLength,
    {
        VoleCommitsRef {
            scalars: GenericArray::from_slice(&self.scalars[start_idx..start_idx + L2::USIZE]),
            delta: self.delta,
        }
    }

    pub(crate) fn get_field_commit(&self, idx: usize) -> F {
        debug_assert!(idx * 8 + 8 <= L::USIZE);
        F::byte_combine_slice(&self.scalars[8 * idx..8 * idx + 8])
    }

    pub(crate) fn get_field_commit_sq(&self, idx: usize) -> F {
        debug_assert!(idx * 8 + 8 <= L::USIZE);
        F::byte_combine_sq_slice(&self.scalars[8 * idx..8 * idx + 8])
    }
}

#[derive(Debug, PartialEq, PartialOrd, Copy, Clone)]
pub(crate) struct VoleCommitsRef<'a, F: BigGaloisField, L: ArrayLength> {
    pub(crate) scalars: &'a GenericArray<F, L>,
    pub(crate) delta: &'a F,
}

impl<'a, F, L> VoleCommitsRef<'a, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    pub(crate) fn get_commits_ref<L2>(&self, start_idx: usize) -> VoleCommitsRef<'a, F, L2>
    where
        L2: ArrayLength,
    {
        VoleCommitsRef {
            scalars: GenericArray::from_slice(&self.scalars[start_idx..start_idx + L2::USIZE]),
            delta: self.delta,
        }
    }
}

impl<F, L> Index<usize> for VoleCommits<'_, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        &self.scalars[index]
    }
}

impl<F, L> Index<Range<usize>> for VoleCommits<'_, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    type Output = [F];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.scalars[index]
    }
}

impl<F, L> Index<usize> for VoleCommitsRef<'_, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        &self.scalars[index]
    }
}

impl<F, L> Index<Range<usize>> for VoleCommitsRef<'_, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    type Output = [F];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.scalars[index]
    }
}

impl<F, L> AsRef<GenericArray<F, L>> for VoleCommits<'_, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    fn as_ref(&self) -> &GenericArray<F, L> {
        &self.scalars
    }
}
