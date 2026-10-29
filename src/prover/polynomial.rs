use super::field_commitment::FieldCommitment;
use crate::fields::BigGaloisField;
use core::ops::{Add, Mul};

#[derive(Clone, Debug)]
pub(crate) struct Polynomial<F: BigGaloisField> {
    pub(crate) coefficients: [F; 8],
    pub(crate) degree: usize,
}

impl<F: BigGaloisField> Polynomial<F> {
    pub(crate) fn constant(value: F) -> Self {
        let mut coefficients = [F::ZERO; 8];
        coefficients[0] = value;
        Self {
            coefficients,
            degree: 0,
        }
    }

    pub(crate) fn commitment<const D: usize>(value: &FieldCommitment<F, D>) -> Self {
        const {
            assert!(D <= 7);
        }
        let mut coefficients = [F::ZERO; 8];
        coefficients[..D].copy_from_slice(&value.tag);
        coefficients[D] = value.key;
        Self {
            coefficients,
            degree: D,
        }
    }

    /// DegLift multiplies by X^(degree - self.degree), including zero coefficients.
    pub(crate) fn lift(mut self, degree: usize) -> Self {
        assert!(self.degree <= degree && degree <= 7);
        self.coefficients
            .copy_within(..=self.degree, degree - self.degree);
        self.coefficients[..degree - self.degree].fill(F::ZERO);
        self.degree = degree;
        self
    }

    pub(crate) fn scale(mut self, scalar: F) -> Self {
        for a in &mut self.coefficients {
            *a *= scalar;
        }
        self
    }

    pub(crate) fn evaluate(&self, delta: F) -> F {
        self.coefficients[..=self.degree]
            .iter()
            .rev()
            .fold(F::ZERO, |acc, c| acc * delta + c)
    }
}

impl<F: BigGaloisField> Add<&Self> for Polynomial<F> {
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self::Output {
        assert_eq!(self.degree, rhs.degree);
        for (a, b) in self.coefficients.iter_mut().zip(rhs.coefficients) {
            *a += b;
        }
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        fields::{GF128, GF192, GF256},
        prover::field_commitment::FieldCommitDegOne,
    };

    fn arithmetic<F: BigGaloisField>() {
        let a = FieldCommitDegOne::new(F::byte_combine_bits(0x53), F::byte_combine_bits(0xca));
        let b = FieldCommitDegOne::new(F::byte_combine_bits(0xf1), F::byte_combine_bits(0x77));
        let scalar = F::byte_combine_bits(0x31);
        let p = Polynomial::commitment(&a);
        let q = Polynomial::commitment(&b);
        let mut power = Polynomial::constant(F::ONE);
        for degree in 0..=7 {
            assert_eq!(power.degree, degree);
            let scaled = power.clone().scale(scalar);
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
