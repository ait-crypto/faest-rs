use std::ops::{Add, AddAssign, Mul};

use itertools::izip;

use crate::fields::{BigGaloisField, Square};

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
        for (l, r) in izip!(self.tag.iter_mut(), rhs.tag) {
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
        for (l, r) in izip!(self.tag.iter_mut(), rhs.tag) {
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

impl<F> Mul<&Self> for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegTwo<F>;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        FieldCommitDegTwo {
            key: self.key * rhs.key,
            tag: [
                self.tag[0] * rhs.tag[0],
                self.key * rhs.tag[0] + self.tag[0] * rhs.key,
            ],
        }
    }
}

impl<F> Mul for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegTwo<F>;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        FieldCommitDegTwo {
            key: self.key * rhs.key,
            tag: [
                self.tag[0] * rhs.tag[0],
                self.key * rhs.tag[0] + self.tag[0] * rhs.key,
            ],
        }
    }
}

impl<F> Mul<FieldCommitDegTwo<F>> for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegThree<F>;

    #[inline]
    fn mul(self, rhs: FieldCommitDegTwo<F>) -> Self::Output {
        FieldCommitDegThree {
            key: self.key * rhs.key,
            tag: [
                self.tag[0] * rhs.tag[0],
                self.key * rhs.tag[0] + self.tag[0] * rhs.tag[1],
                self.key * rhs.tag[1] + self.tag[0] * rhs.key,
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
    fn mul(self, rhs: &FieldCommitDegTwo<F>) -> Self::Output {
        FieldCommitDegThree {
            key: self.key * rhs.key,
            tag: [
                self.tag[0] * rhs.tag[0],
                self.key * rhs.tag[0] + self.tag[0] * rhs.tag[1],
                self.key * rhs.tag[1] + self.tag[0] * rhs.key,
            ],
        }
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
            tag: self.tag,
        }
    }
}

impl<F> Square for &FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegTwo<F>;

    fn square(self) -> Self::Output {
        FieldCommitDegTwo {
            key: self.key.square(),
            tag: [self.tag[0].square(), F::ZERO],
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
            tag: [self.tag[0].square(), F::ZERO],
        }
    }
}

/// Represents a polynomial commitment in GF of degree 2
pub type FieldCommitDegTwo<F> = FieldCommitment<F, 2>;

impl<F> AddAssign<&FieldCommitDegOne<F>> for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    #[inline]
    fn add_assign(&mut self, rhs: &FieldCommitDegOne<F>) {
        self.key += rhs.key;
        self.tag[1] += rhs.tag[0];
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

impl<F> Mul<FieldCommitDegOne<F>> for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegThree<F>;

    #[inline]
    fn mul(self, rhs: FieldCommitDegOne<F>) -> Self::Output {
        self * &rhs
    }
}

impl<F> Mul<&FieldCommitDegOne<F>> for FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegThree<F>;

    #[inline]
    fn mul(self, rhs: &FieldCommitDegOne<F>) -> Self::Output {
        FieldCommitDegThree {
            key: self.key * rhs.key,
            tag: [
                rhs.tag[0] * self.tag[0],
                rhs.key * self.tag[0] + rhs.tag[0] * self.tag[1],
                rhs.key * self.tag[1] + rhs.tag[0] * self.key,
            ],
        }
    }
}

/// Represents a polynomial commitment in GF of degree 3
pub type FieldCommitDegThree<F> = FieldCommitment<F, 3>;

impl<F> Add<&FieldCommitDegOne<F>> for FieldCommitDegThree<F>
where
    F: BigGaloisField,
{
    type Output = Self;

    #[inline]
    fn add(self, rhs: &FieldCommitDegOne<F>) -> Self::Output {
        Self {
            key: self.key + rhs.key,
            tag: [self.tag[0], self.tag[1], self.tag[2] + rhs.tag[0]],
        }
    }
}

impl<F> Add<&FieldCommitDegTwo<F>> for FieldCommitDegThree<F>
where
    F: BigGaloisField,
{
    type Output = Self;

    #[inline]
    fn add(self, rhs: &FieldCommitDegTwo<F>) -> Self::Output {
        Self {
            key: self.key + rhs.key,
            tag: [
                self.tag[0],
                self.tag[1] + rhs.tag[0],
                self.tag[2] + rhs.tag[1],
            ],
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fields::{Field, GF128};

    #[test]
    fn field_commit_mul() {
        let lhs = FieldCommitDegTwo {
            key: GF128::ONE,
            tag: [GF128::ONE, GF128::ONE],
        };

        let rhs = FieldCommitDegOne::new(GF128::ONE, GF128::ONE);

        let exp_res = FieldCommitDegThree {
            key: GF128::ONE,
            tag: [GF128::ONE, GF128::ONE * 2, GF128::ONE * 2],
        };

        assert!(lhs.clone() * &rhs == exp_res);
        assert!(rhs.clone() * &lhs == exp_res);
        assert!(lhs.clone() * rhs.clone() == exp_res);
        assert!(rhs * lhs == exp_res);

        let lhs = FieldCommitDegOne::new(GF128::ONE, GF128::ONE);

        let rhs = FieldCommitDegOne::new(GF128::ONE * 2, GF128::ZERO);

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
        let lhs = FieldCommitDegOne::new(GF128::ONE, GF128::ONE * 3);

        let rhs = FieldCommitDegOne::new(GF128::ONE * 4, GF128::ONE * 2);

        let exp_res = FieldCommitDegOne::new(GF128::ONE * 5, GF128::ONE * 5);

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
