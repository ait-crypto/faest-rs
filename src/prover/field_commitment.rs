use std::ops::{Add, AddAssign, Mul};

use crate::fields::{BigGaloisField, Square};

/// Represents a polynomial commitment in GF of degree one
#[derive(Default, Debug, Clone, PartialEq)]
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
    type Output = Self;

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

impl<F> Mul<&Self> for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegTwo<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: &Self) -> Self::Output {
        FieldCommitDegTwo {
            key: self.key * rhs.key,
            tag: [self.tag * rhs.tag, self.key * rhs.tag + self.tag * rhs.key],
        }
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
        self * &rhs
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
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(mut self, rhs: &F) -> Self::Output {
        self.key *= rhs;
        self
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
            tag: [self.tag.square(), F::ZERO],
        }
    }
}

impl<F> Square for FieldCommitDegOne<F>
where
    F: BigGaloisField,
{
    type Output = FieldCommitDegTwo<F>;

    fn square(self) -> Self::Output {
        (&self).square()
    }
}

/// Represents a polynomial commitment in GF of degree 2
#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct FieldCommitDegTwo<F>
where
    F: BigGaloisField,
{
    pub(crate) key: F,
    pub(crate) tag: [F; 2],
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

// impl<F> Mul<&FieldCommitDegTwo<F>> for F
// where
//     F: BigGaloisField,
// {
//     type Output = FieldCommitDegTwo<F>;

//     fn mul(mut self, rhs: &FieldCommitDegTwo<F>) -> Self::Output {

//         FieldCommitDegTwo{
//             key: self * rhs,
//             tag: [self * rhs.tag[0], self * rhs.tag[1]]
//         }
//     }
// }

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
        self * &rhs
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
        FieldCommitDegThree {
            key: self.key * rhs.key,
            tag: [
                rhs.tag * self.tag[0],
                rhs.key * self.tag[0] + rhs.tag * self.tag[1],
                rhs.key * self.tag[1] + rhs.tag * self.key,
            ],
        }
    }
}

/// Represents a polynomial commitment in GF of degree 3
#[derive(Default, Debug, Clone, PartialEq)]
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
            .zip(rhs.tag)
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
    type Output = Self;

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
    type Output = Self;

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
    type Output = Self;

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
