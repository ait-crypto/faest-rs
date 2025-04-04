use crate::{aes::{AddRoundKey, AddRoundKeyAssign}, fields::BigGaloisField};
use std::ops::{Add, Mul};
use generic_array::{GenericArray, ArrayLength, typenum::U8};


pub(crate) mod zk_constraints;
mod encryption;
mod aes;

#[derive(Debug, PartialEq, PartialOrd)]
pub(crate) struct ScalarCommitment<'a, F>
where
    F: BigGaloisField,
{
    pub(crate) scalar: F,
    pub(crate) vole_chall: &'a F,
}

#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub(crate) struct ScalarCommitmentRef<'a, F>
where
    F: BigGaloisField,
{
    pub(crate) scalar: &'a F,
    pub(crate) vole_chall: &'a F,
}

impl<'a, F> Add for ScalarCommitment<'a, F>
where
    F: BigGaloisField,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        ScalarCommitment {
            scalar: self.scalar + &rhs.scalar,
            vole_chall: self.vole_chall,
        }
    }
}

impl<'a, F> Add<ScalarCommitmentRef<'a, F>> for ScalarCommitment<'a, F>
where
    F: BigGaloisField,
{
    type Output = Self;

    fn add(self, rhs: ScalarCommitmentRef<'a, F>) -> Self::Output {
        ScalarCommitment {
            scalar: self.scalar + rhs.scalar,
            vole_chall: self.vole_chall,
        }
    }
}

impl<'a, F> Mul for ScalarCommitment<'a, F>
where
    F: BigGaloisField,
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        ScalarCommitment {
            scalar: self.scalar * &rhs.scalar * self.vole_chall,
            vole_chall: self.vole_chall,
        }
    }
}

impl<'a, F> Mul<ScalarCommitmentRef<'a, F>> for ScalarCommitment<'a, F>
where
    F: BigGaloisField,
{
    type Output = Self;

    fn mul(self, rhs: ScalarCommitmentRef<'a, F>) -> Self::Output {
        ScalarCommitment {
            scalar: self.scalar * rhs.scalar * self.vole_chall,
            vole_chall: self.vole_chall,
        }
    }
}

#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub(crate) struct ScalarCommits<F: BigGaloisField, L: ArrayLength> {
    scalars: Box<GenericArray<F, L>>,
    vole_challenge: F,
}

impl<F, L> ScalarCommits<F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    pub(crate) fn get(&self, index: usize) -> ScalarCommitment<'_, F> {
        ScalarCommitment {
            scalar: self.scalars[index],
            vole_chall: &self.vole_challenge,
        }
    }

    pub(crate) fn as_ref(&self) -> ScalarCommitsRef<'_, F, L> {
        ScalarCommitsRef {
            scalars: &self.scalars,
            vole_challenge: &self.vole_challenge,
        }
    }

    pub(crate) fn get_ref(&self, index: usize) -> ScalarCommitmentRef<'_, F> {
        ScalarCommitmentRef {
            scalar: &self.scalars[index],
            vole_chall: &self.vole_challenge,
        }
    }

    pub(crate) fn get_commits_ref<L2>(&self, start_idx: usize) -> ScalarCommitsRef<'_, F, L2>
    where
        L2: ArrayLength,
    {
        ScalarCommitsRef {
            scalars: GenericArray::from_slice(&self.scalars[start_idx..start_idx + L2::USIZE]),
            vole_challenge: &self.vole_challenge,
        }
    }
}

#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub(crate) struct ScalarCommitsRef<'a, F: BigGaloisField, L: ArrayLength> {
    scalars: &'a GenericArray<F, L>,
    vole_challenge: &'a F,
}

impl<F, L> ScalarCommitsRef<'_, F, L>
where
    F: BigGaloisField,
    L: ArrayLength,
{
    pub(crate) fn get(&self, index: usize) -> ScalarCommitment<'_, F> {
        ScalarCommitment {
            scalar: self.scalars[index],
            vole_chall: self.vole_challenge,
        }
    }

    pub(crate) fn as_ref(&self) -> ScalarCommitsRef<'_, F, L> {
        ScalarCommitsRef {
            scalars: &self.scalars,
            vole_challenge: &self.vole_challenge,
        }
    }

    pub(crate) fn get_ref(&self, index: usize) -> ScalarCommitmentRef<'_, F> {
        ScalarCommitmentRef {
            scalar: &self.scalars[index],
            vole_chall: self.vole_challenge,
        }
    }

    pub(crate) fn get_commits_ref<L2>(&self, start_idx: usize) -> ScalarCommitsRef<'_, F, L2>
    where
        L2: ArrayLength,
    {
        ScalarCommitsRef {
            scalars: GenericArray::from_slice(&self.scalars[start_idx..start_idx + L2::USIZE]),
            vole_challenge: &self.vole_challenge,
        }
    }
}

impl<F, L, L2> AddRoundKey<&GenericArray<u8, L>> for ScalarCommitsRef<'_, F, L2>
where
    F: BigGaloisField,
    L: ArrayLength + Mul<U8, Output = L2>,
    L2: ArrayLength,
{
    type Output = ScalarCommits<F, L2>;

    fn add_round_key(&self, rhs: &GenericArray<u8, L>) -> Self::Output {
        let scalars = self
            .scalars
            .into_iter()
            .enumerate()
            .map(|(i, comm_i)| {
                let scal_i = (rhs[i / 8] >> (i % 8)) & 1;
                if scal_i == 1 {
                    return *comm_i + self.vole_challenge;
                }
                *comm_i
            })
            .collect();

        ScalarCommits {
            scalars,
            vole_challenge: *self.vole_challenge,
        }
    }
}


impl<F,L,L2> AddRoundKeyAssign<&GenericArray<u8, L>> for ScalarCommits<F,L2>
where F: BigGaloisField, L: ArrayLength + Mul<U8, Output = L2>, L2: ArrayLength{
    fn add_round_key_assign(&mut self, rhs: &GenericArray<u8, L>) {
        self.scalars.iter_mut().enumerate().for_each(
            |(i, comm_i)| {
                let scal_i = (rhs[i / 8] >> (i % 8)) & 1;
                if scal_i == 1{
                    *comm_i += self.vole_challenge;
                }
            }
        )
    }
}

