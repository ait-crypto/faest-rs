use crate::fields::{BigGaloisField, Square, GF8};
use generic_array::{
    typenum::{Prod, U8},
    ArrayLength, GenericArray,
};
use std::ops::{Add, AddAssign, Index, Mul, MulAssign, Neg};

/// Represents a polynomial commitment in GF of degree one
#[derive(Default, Debug, Clone, PartialEq, PartialOrd)]
pub(crate) struct FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    pub(crate) key: F,
    pub(crate) tag: F,
}

impl<F> FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    pub(crate) fn new(key: F, tag: F) -> Self {
        Self { key, tag }
    }
}

impl<F> AddAssign<Self> for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    fn add_assign(&mut self, rhs: Self) {
        self.key += rhs.key;
        self.tag += rhs.tag;
    }
}

impl<F> AddAssign<&Self> for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    fn add_assign(&mut self, rhs: &Self) {
        self.key += rhs.key;
        self.tag += rhs.tag;
    }
}

impl<F> Add for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<F> Add<&Self> for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegOne<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<F> Add for &FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegOne<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        self.clone() + rhs
    }
}

impl<F> Mul for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegTwo<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: Self) -> Self::Output {
        FieldCommitDegTwo {
            key: self.key * rhs.key,
            tag: [self.tag * rhs.tag, self.key * rhs.tag + self.tag * rhs.key],
        }
    }
}

impl<F> Mul<&Self> for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegTwo<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: &Self) -> Self::Output {
        self * rhs.clone()
    }
}

impl<F> Mul<FieldCommitDegTwo<F>> for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegThree<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: FieldCommitDegTwo<F>) -> Self::Output {
        FieldCommitDegThree {
            key: self.key * rhs.key,
            tag: [
                self.tag * rhs.tag[0],
                self.key * rhs.tag[0] + self.tag * rhs.tag[1],
                self.key * rhs.tag[1] + self.tag * rhs.key,
            ],
        }
    }
}

impl<F> Mul<&FieldCommitDegTwo<F>> for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegThree<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: &FieldCommitDegTwo<F>) -> Self::Output {
        FieldCommitDegThree {
            key: self.key * rhs.key,
            tag: [
                self.tag * rhs.tag[0],
                self.key * rhs.tag[0] + self.tag * rhs.tag[1],
                self.key * rhs.tag[1] + self.tag * rhs.key,
            ],
        }
    }
}

impl<F> Mul<&F> for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegOne<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: &F) -> Self::Output {
        FieldCommitDegOne {
            key: self.key * rhs,
            tag: self.tag,
        }
    }
}

impl<F> Square for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegTwo<F>;

    fn square(self) -> Self::Output {
        FieldCommitDegTwo {
            key: self.key.square(),
            tag: [self.tag.square(), F::ZERO],
        }
    }
}

/// Represents a polynomial commitment in GF of degree 2
#[derive(Default, Debug, Clone, PartialEq, PartialOrd)]
pub(crate) struct FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    pub(crate) key: F,
    pub(crate) tag: [F; 2],
}

impl<F> FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    /// Lifts a field element to a degree 2 polynomial commitment
    pub(crate) fn from_field(c: &F) -> Self {
        FieldCommitDegTwo {
            key: *c,
            tag: [F::ZERO, F::ZERO],
        }
    }
}

impl<F> Mul<F> for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    type Output = Self;

    fn mul(mut self, rhs: F) -> Self::Output {
        self.key *= rhs;
        self.tag[0] *= rhs;
        self.tag[1] *= rhs;

        self
    }
}

impl<F> Mul<&F> for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    type Output = Self;

    fn mul(mut self, rhs: &F) -> Self::Output {
        self.key *= rhs;
        self.tag[0] *= rhs;
        self.tag[1] *= rhs;
        self
    }
}

impl<F> AddAssign<Self> for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    fn add_assign(&mut self, rhs: Self) {
        self.key += rhs.key;
        self.tag[0] += rhs.tag[0];
        self.tag[1] += rhs.tag[1];
    }
}

impl<F> AddAssign<&Self> for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    fn add_assign(&mut self, rhs: &Self) {
        self.key += rhs.key;
        self.tag[0] += rhs.tag[0];
        self.tag[1] += rhs.tag[1];
    }
}

impl<F> AddAssign<&FieldCommitDegOne<F>> for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    fn add_assign(&mut self, rhs: &FieldCommitDegOne<F>) {
        self.key += rhs.key;
        self.tag[1] += rhs.tag;
    }
}

impl<F> AddAssign<F> for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    fn add_assign(&mut self, rhs: F) {
        self.key += rhs;
    }
}

impl<F> AddAssign<&F> for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    fn add_assign(&mut self, rhs: &F) {
        self.key += rhs;
    }
}

impl<F> Add for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<F> Add<&Self> for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<F> Mul<FieldCommitDegOne<F>> for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegThree<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: FieldCommitDegOne<F>) -> Self::Output {
        rhs * self
    }
}

impl<F> Mul<&FieldCommitDegOne<F>> for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegThree<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: &FieldCommitDegOne<F>) -> Self::Output {
        rhs.clone() * self
    }
}

/// Represents a polynomial commitment in GF of degree 3
#[derive(Default, Debug, Clone, PartialEq, PartialOrd)]
pub(crate) struct FieldCommitDegThree<F>
where
    F: BigGaloisField,
{
    pub(crate) key: F,
    pub(crate) tag: [F; 3],
}

impl<F> AddAssign<Self> for FieldCommitDegThree<F>
where
    F: BigGaloisField,
{
    fn add_assign(&mut self, rhs: Self) {
        self.key += rhs.key;
        self.tag
            .iter_mut()
            .zip(rhs.tag.into_iter())
            .for_each(|(a, b)| *a = *a + b);
    }
}

impl<F> AddAssign<&Self> for FieldCommitDegThree<F>
where
    F: BigGaloisField,
{
    fn add_assign(&mut self, rhs: &Self) {
        self.key += rhs.key;
        self.tag
            .iter_mut()
            .zip(rhs.tag.iter())
            .for_each(|(a, b)| *a = *a + b);
    }
}

impl<F> Add for FieldCommitDegThree<F>
where
    F: BigGaloisField,
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<F> Add<&Self> for FieldCommitDegThree<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegThree<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<F> Add<&FieldCommitDegOne<F>> for FieldCommitDegThree<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegThree<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(mut self, rhs: &FieldCommitDegOne<F>) -> Self::Output {
        self.tag[2] += rhs.tag;
        Self {
            key: self.key + rhs.key,
            tag: self.tag,
        }
    }
}

impl<F> Add<&FieldCommitDegTwo<F>> for FieldCommitDegThree<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegThree<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(mut self, rhs: &FieldCommitDegTwo<F>) -> Self::Output {
        self.tag[2] += rhs.tag[1];
        self.tag[1] += rhs.tag[0];
        Self {
            key: self.key + rhs.key,
            tag: self.tag,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Default)]
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
        GF8::square_bits_inplace(&mut self.key);
    }

    pub fn combine(&self) -> FieldCommitDegOne<F> {
        FieldCommitDegOne {
            key: F::byte_combine_bits(self.key),
            tag: F::byte_combine_slice(self.tags.as_slice()),
        }
    }
}


#[derive(Clone, Debug, PartialEq, Default)]
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
        ByteCommits { keys, tags }
    }

    pub(crate) fn get_field_commit(&self, index: usize) -> FieldCommitDegOne<F> {
        FieldCommitDegOne {
            key: F::byte_combine_bits(self.keys[index]),
            tag: F::byte_combine_slice(&self.tags[index * 8..index * 8 + 8]),
        }
    }

    pub(crate) fn get_field_commit_sq(&self, index: usize) -> FieldCommitDegOne<F> {
        FieldCommitDegOne {
            key: F::byte_combine_bits_sq(self.keys[index]),
            tag: F::byte_combine_sq(&self.tags[index * 8..index * 8 + 8]),
        }
    }

    pub fn get_commits_ref(&self) -> ByteCommitsRef<F, L> {
        ByteCommitsRef {
            keys: &self.keys,
            tags: &self.tags,
        }
    }

    pub fn get(&self, idx: usize) -> ByteCommitment<F> {
        ByteCommitment {
            key: self.keys[idx],
            tags: GenericArray::from_slice(&self.tags[idx * 8..idx * 8 + 8]).to_owned(),
        }
    }

}


#[derive(Debug, PartialEq, Clone, Copy)]
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
    pub(crate) fn new(
        keys: &'a GenericArray<u8, L>,
        tags: &'a GenericArray<F, Prod<L, U8>>,
    ) -> Self {
        Self { keys, tags }
    }

    pub(crate) fn get_field_commit(&self, index: usize) -> FieldCommitDegOne<F> {
        FieldCommitDegOne {
            key: F::byte_combine_bits(self.keys[index]),
            tag: F::byte_combine_slice(&self.tags[index * 8..index * 8 + 8]),
        }
    }

    pub(crate) fn get_field_commit_sq(&self, index: usize) -> FieldCommitDegOne<F> {
        FieldCommitDegOne {
            key: F::byte_combine_bits_sq(self.keys[index]),
            tag: F::byte_combine_sq(&self.tags[index * 8..index * 8 + 8]),
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::fields::{Field, GF128};
    use rand::{rngs::SmallRng, Rng, RngCore, SeedableRng};

    #[test]
    fn field_commit_mul() {
        let lhs = FieldCommitDegTwo {
            key: GF128::ONE,
            tag: [GF128::ONE, GF128::ONE],
        };

        let rhs = FieldCommitDegOne {
            key: GF128::ONE,
            tag: GF128::ONE,
        };

        let exp_res = FieldCommitDegThree {
            key: GF128::ONE,
            tag: [GF128::ONE, GF128::ONE * 2, GF128::ONE * 2],
        };

        assert!(lhs.clone() * &rhs == exp_res);
        assert!(rhs.clone() * &lhs == exp_res);
        assert!(lhs.clone() * rhs.clone() == exp_res);
        assert!(rhs * lhs == exp_res);

        let lhs = FieldCommitDegOne {
            key: GF128::ONE,
            tag: GF128::ONE,
        };

        let rhs = FieldCommitDegOne {
            key: GF128::ONE * 2,
            tag: GF128::ZERO,
        };

        let exp_res = FieldCommitDegTwo {
            key: GF128::ONE * 2,
            tag: [GF128::ZERO, GF128::ONE * 2],
        };

        assert!(lhs.clone() * &rhs == exp_res);
        assert!(rhs.clone() * &lhs == exp_res);
        assert!(lhs.clone() * rhs.clone() == exp_res);
        assert!(rhs * lhs == exp_res);
    }

    #[test]
    fn field_commit_sum() {
        let lhs = FieldCommitDegOne {
            key: GF128::ONE,
            tag: GF128::ONE * 3,
        };

        let rhs = FieldCommitDegOne {
            key: GF128::ONE * 4,
            tag: GF128::ONE * 2,
        };

        let exp_res = FieldCommitDegOne {
            key: GF128::ONE * 5,
            tag: GF128::ONE * 5,
        };

        assert!(lhs.clone() + &rhs == exp_res);
        assert!(rhs.clone() + &lhs == exp_res);
        assert!(lhs.clone() + rhs.clone() == exp_res);
        assert!(rhs + lhs == exp_res);

        let lhs = FieldCommitDegTwo {
            key: GF128::ONE,
            tag: [GF128::ONE, GF128::ONE],
        };

        let rhs = FieldCommitDegTwo {
            key: GF128::ONE,
            tag: [GF128::ONE, GF128::ZERO],
        };

        let exp_res = FieldCommitDegTwo {
            key: GF128::ONE * 2,
            tag: [GF128::ONE * 2, GF128::ONE],
        };

        assert!(lhs.clone() + &rhs == exp_res);
        assert!(rhs.clone() + &lhs == exp_res);
        assert!(lhs.clone() + rhs.clone() == exp_res);
        assert!(rhs + lhs == exp_res);

        let lhs = FieldCommitDegThree {
            key: GF128::ONE * 2,
            tag: [GF128::ZERO, GF128::ONE * 2, GF128::ONE],
        };

        let rhs = FieldCommitDegThree {
            key: GF128::ONE,
            tag: [GF128::ONE, GF128::ONE * 2, GF128::ZERO],
        };

        let exp_res = FieldCommitDegThree {
            key: GF128::ONE * 3,
            tag: [GF128::ONE, GF128::ONE * 4, GF128::ONE],
        };

        assert!(lhs.clone() + &rhs == exp_res);
        assert!(rhs.clone() + &lhs == exp_res);
        assert!(lhs.clone() + rhs.clone() == exp_res);
        assert!(rhs + lhs == exp_res);
    }
}
