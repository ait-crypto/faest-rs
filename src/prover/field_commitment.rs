use core::{
    iter::zip,
    ops::{Add, AddAssign, Mul},
};

use crate::fields::BigGaloisField;

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct FieldCommitment<F, const TAG_SIZE: usize>
where
    F: BigGaloisField,
{
    pub key: F,
    pub tag: [F; TAG_SIZE],
}

impl<F, const TAG_SIZE: usize> Default for FieldCommitment<F, TAG_SIZE>
where
    F: BigGaloisField,
{
    fn default() -> Self {
        Self {
            key: F::ZERO,
            tag: [F::ZERO; TAG_SIZE],
        }
    }
}

impl<F, const TAG_SIZE: usize> AddAssign<Self> for FieldCommitment<F, TAG_SIZE>
where
    F: BigGaloisField,
{
    fn add_assign(&mut self, rhs: Self) {
        self.key += rhs.key;
        for (l, r) in zip(self.tag.iter_mut(), rhs.tag) {
            *l += r;
        }
    }
}

impl<F, const TAG_SIZE: usize> AddAssign<&Self> for FieldCommitment<F, TAG_SIZE>
where
    F: BigGaloisField,
{
    fn add_assign(&mut self, rhs: &Self) {
        self.key += rhs.key;
        for (l, r) in zip(self.tag.iter_mut(), rhs.tag) {
            *l += r;
        }
    }
}

impl<F, const TAG_SIZE: usize> AddAssign<F> for FieldCommitment<F, TAG_SIZE>
where
    F: BigGaloisField,
{
    fn add_assign(&mut self, rhs: F) {
        self.key += rhs;
    }
}

impl<F, const TAG_SIZE: usize> AddAssign<&F> for FieldCommitment<F, TAG_SIZE>
where
    F: BigGaloisField,
{
    fn add_assign(&mut self, rhs: &F) {
        self.key += rhs;
    }
}

impl<F, const TAG_SIZE: usize> Add for FieldCommitment<F, TAG_SIZE>
where
    F: BigGaloisField,
{
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<F, const TAG_SIZE: usize> Add<&Self> for FieldCommitment<F, TAG_SIZE>
where
    F: BigGaloisField,
{
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<F, const TAG_SIZE: usize> Add for &FieldCommitment<F, TAG_SIZE>
where
    F: BigGaloisField,
{
    type Output = FieldCommitment<F, TAG_SIZE>;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        // TODO: implement without clone
        self.clone() + rhs
    }
}

/// Represents a polynomial commitment in GF of degree one
pub type FieldCommitDegOne<F> = FieldCommitment<F, 1>;

impl<F> FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    pub fn new(key: F, tag: F) -> Self {
        Self { key, tag: [tag] }
    }
}

impl<F> Mul<&F> for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &F) -> Self::Output {
        Self {
            key: self.key * rhs,
            tag: self.tag.map(|coefficient| coefficient * rhs),
        }
    }
}
