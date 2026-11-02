use crate::fields::BigGaloisField;
use core::ops::{Add, AddAssign, Mul, MulAssign};

#[derive(Copy, Clone, Debug)]
pub(super) struct Polynomial<F: BigGaloisField> {
    pub(super) coefficients: [F; 8],
    pub(super) degree: usize,
}

impl<F: BigGaloisField> Polynomial<F> {
    pub(super) fn from_key_tag(key: F, tag: F) -> Self {
        let mut coefficients = [F::ZERO; 8];
        coefficients[0] = tag;
        coefficients[1] = key;
        Self {
            degree: 1,
            coefficients,
        }
    }

    pub(super) fn constant(value: F) -> Self {
        let mut coefficients = [F::ZERO; 8];
        coefficients[0] = value;
        Self {
            coefficients,
            degree: 0,
        }
    }

    /// DegLift multiplies by X^(degree - self.degree), including zero coefficients.
    pub(super) fn lift(mut self, degree: usize) -> Self {
        assert!(self.degree <= degree && degree <= 7);
        self.coefficients
            .copy_within(..=self.degree, degree - self.degree);
        self.coefficients[..degree - self.degree].fill(F::ZERO);
        self.degree = degree;
        self
    }

    pub(super) fn evaluate(&self, delta: F) -> F {
        self.coefficients[..=self.degree]
            .iter()
            .rev()
            .fold(F::ZERO, |acc, c| acc * delta + c)
    }
}

impl<F: BigGaloisField> AddAssign<&Self> for Polynomial<F> {
    fn add_assign(&mut self, rhs: &Self) {
        assert_eq!(self.degree, rhs.degree);
        for (a, b) in self.coefficients.iter_mut().zip(rhs.coefficients) {
            *a += b;
        }
    }
}

impl<F: BigGaloisField> Add<&Self> for Polynomial<F> {
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<F: BigGaloisField> Add for Polynomial<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self + &rhs
    }
}

impl<F: BigGaloisField> Mul for Polynomial<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        &self * &rhs
    }
}

impl<F: BigGaloisField> Mul<&Self> for Polynomial<F> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        &self * rhs
    }
}

impl<F: BigGaloisField> Mul<Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn mul(self, rhs: Polynomial<F>) -> Self::Output {
        self * &rhs
    }
}

impl<F: BigGaloisField> Mul for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn mul(self, rhs: Self) -> Self::Output {
        let degree = self.degree + rhs.degree;
        assert!(degree <= 7);
        let mut coefficients = [F::ZERO; 8];
        for i in 0..=self.degree {
            for j in 0..=rhs.degree {
                coefficients[i + j] += self.coefficients[i] * rhs.coefficients[j];
            }
        }
        Polynomial {
            coefficients,
            degree,
        }
    }
}

impl<F: BigGaloisField> MulAssign<F> for Polynomial<F> {
    fn mul_assign(&mut self, rhs: F) {
        for coefficient in &mut self.coefficients {
            *coefficient *= rhs;
        }
    }
}

impl<F: BigGaloisField> Mul<F> for Polynomial<F> {
    type Output = Self;

    fn mul(mut self, rhs: F) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<F: BigGaloisField> Mul<F> for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn mul(self, rhs: F) -> Self::Output {
        *self * rhs
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fields::{GF128, GF192, GF256};

    fn arithmetic<F: BigGaloisField>() {
        let scalar = F::byte_combine_bits(0x31);
        let p = Polynomial::from_key_tag(F::byte_combine_bits(0x53), F::byte_combine_bits(0xca));
        let q = Polynomial::from_key_tag(F::byte_combine_bits(0xf1), F::byte_combine_bits(0x77));
        let mut power = Polynomial::constant(F::ONE);
        for degree in 0..=7 {
            assert_eq!(power.degree, degree);
            let scaled = power * scalar;
            for factor in [F::ZERO, F::ONE, scalar] {
                let owned = power * factor;
                let borrowed = &power * factor;
                let mut assigned = power;
                assigned *= factor;
                assert_eq!(owned.degree, degree);
                assert_eq!(borrowed.degree, degree);
                assert_eq!(assigned.degree, degree);
                for i in 0..8 {
                    let expected = power.coefficients[i] * factor;
                    assert_eq!(owned.coefficients[i], expected);
                    assert_eq!(borrowed.coefficients[i], expected);
                    assert_eq!(assigned.coefficients[i], expected);
                }
            }
            for i in 0..=degree {
                assert_eq!(scaled.coefficients[i], power.coefficients[i] * scalar);
            }
            for delta in [F::ZERO, F::ONE, F::byte_combine_bits(0x42)] {
                let expected = (0..degree).fold(F::ONE, |acc, _| acc * p.evaluate(delta));
                assert_eq!(power.evaluate(delta), expected);
                assert_eq!(scaled.evaluate(delta), expected * scalar);
                assert_eq!(
                    power.clone().lift(7).evaluate(delta),
                    expected * (0..7 - degree).fold(F::ONE, |acc, _| acc * delta)
                );
                if degree < 7 {
                    assert_eq!((&power * &q).evaluate(delta), expected * q.evaluate(delta));
                }
            }
            if degree < 7 {
                power = power * &p;
            }
        }
        // A quadratic key-expansion constraint must occupy only coefficients 5,6,7.
        let lifted = (&p * &q).lift(7);
        assert_eq!(&lifted.coefficients[..5], &[F::ZERO; 5]);
        assert_eq!(&lifted.coefficients[5..], &(&p * &q).coefficients[..3]);
    }

    #[test]
    fn arithmetic_128() {
        arithmetic::<GF128>();
    }
    #[test]
    fn arithmetic_192() {
        arithmetic::<GF192>();
    }
    #[test]
    fn arithmetic_256() {
        arithmetic::<GF256>();
    }
}
