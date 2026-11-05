use super::algebra::{Lift, Prover, Verifier};
use crate::fields::BigGaloisField;
use core::{
    marker::PhantomData,
    ops::{Add, AddAssign, Mul, Sub},
};
use hybrid_array::{
    Array, ArraySize,
    typenum::{B1, Diff, IsGreaterOrEqual, IsLessOrEqual, Min, Minimum, Sum, U1, U2, U7, U8},
};

/// Coefficient counts supported by the constraint algebra.
/// Degree-seven polynomials omit coefficient 7, which is never hashed by the prover (must be zero).
pub(super) trait PolynomialSize: ArraySize {
    type Stored: ArraySize;
}

impl<L> PolynomialSize for L
where
    L: ArraySize + IsGreaterOrEqual<U1, Output = B1> + IsLessOrEqual<U8, Output = B1> + Min<U7>,
    Minimum<L, U7>: ArraySize,
{
    type Stored = Minimum<L, U7>;
}

/// A constraint polynomial with coefficient count L.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Polynomial<F, L: PolynomialSize> {
    pub(super) coefficients: Array<F, L::Stored>,
}

impl<F: Copy, L: PolynomialSize> Copy for Polynomial<F, L> where Array<F, L::Stored>: Copy {}

impl<F: BigGaloisField, L: PolynomialSize> Polynomial<F, L> {
    #[cfg(test)]
    pub(super) fn evaluate(self, delta: F) -> F {
        self.coefficients
            .iter()
            .rev()
            .fold(F::ZERO, |acc, &c| acc * delta + c)
    }
}

impl<F: BigGaloisField> Polynomial<F, U2> {
    pub(super) fn from_key_tag(key: F, tag: F) -> Self {
        Self {
            coefficients: Array([tag, key]),
        }
    }
}

impl<F, L, R> Mul<Polynomial<F, R>> for Polynomial<F, L>
where
    F: BigGaloisField,
    L: PolynomialSize + Add<R>,
    R: PolynomialSize,
    Sum<L, R>: Sub<U1>,
    Diff<Sum<L, R>, U1>: PolynomialSize,
{
    type Output = Polynomial<F, Diff<Sum<L, R>, U1>>;

    fn mul(self, rhs: Polynomial<F, R>) -> Self::Output {
        let mut coefficients = Array::from_fn(|_| F::ZERO);
        for i in 0..self.coefficients.len() {
            // Degree-seven products omit the highest coefficient.
            for j in 0..rhs.coefficients.len().min(coefficients.len() - i) {
                coefficients[i + j] += self.coefficients[i] * rhs.coefficients[j];
            }
        }
        Polynomial { coefficients }
    }
}

impl<F, L, R> Lift<Polynomial<F, R>, Prover> for Polynomial<F, L>
where
    F: BigGaloisField,
    L: PolynomialSize,
    R: PolynomialSize + IsGreaterOrEqual<L, Output = B1>,
{
    fn lift(self, _context: &Prover) -> Polynomial<F, R> {
        let shift = R::USIZE - L::USIZE;
        Polynomial {
            coefficients: Array::from_fn(|i| {
                if i < shift {
                    F::ZERO
                } else {
                    self.coefficients[i - shift]
                }
            }),
        }
    }
}

impl<F: BigGaloisField, L: PolynomialSize> AddAssign for Polynomial<F, L> {
    fn add_assign(&mut self, rhs: Self) {
        for (a, b) in self.coefficients.iter_mut().zip(rhs.coefficients) {
            *a += b;
        }
    }
}

impl<F: BigGaloisField, L: PolynomialSize> Add for Polynomial<F, L> {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self += rhs;
        self
    }
}

impl<F: BigGaloisField, L: PolynomialSize> Mul<F> for Polynomial<F, L> {
    type Output = Self;
    fn mul(mut self, rhs: F) -> Self {
        for c in &mut self.coefficients {
            *c *= rhs;
        }
        self
    }
}

/// A polynomial evaluation, with coefficient count L retained in the type.
#[derive(Copy, Clone)]
pub(super) struct Evaluation<F, L: PolynomialSize>(pub(super) F, PhantomData<L>);

impl<F, L: PolynomialSize> Evaluation<F, L> {
    pub(super) fn new(value: F) -> Self {
        Self(value, PhantomData)
    }
}

impl<F: BigGaloisField, L: PolynomialSize> AddAssign for Evaluation<F, L> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl<F: BigGaloisField, L: PolynomialSize> Add for Evaluation<F, L> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self::new(self.0 + rhs.0)
    }
}

impl<F: BigGaloisField, L: PolynomialSize> Mul<F> for Evaluation<F, L> {
    type Output = Self;
    fn mul(self, rhs: F) -> Self {
        Self::new(self.0 * rhs)
    }
}

impl<F, L, R> Mul<Evaluation<F, R>> for Evaluation<F, L>
where
    F: BigGaloisField,
    L: PolynomialSize + Add<R>,
    R: PolynomialSize,
    Sum<L, R>: Sub<U1>,
    Diff<Sum<L, R>, U1>: PolynomialSize,
{
    type Output = Evaluation<F, Diff<Sum<L, R>, U1>>;

    fn mul(self, rhs: Evaluation<F, R>) -> Self::Output {
        Evaluation::new(self.0 * rhs.0)
    }
}

impl<F, L, R> Lift<Evaluation<F, R>, Verifier<F>> for Evaluation<F, L>
where
    F: BigGaloisField,
    L: PolynomialSize,
    R: PolynomialSize + IsGreaterOrEqual<L, Output = B1>,
{
    fn lift(self, context: &Verifier<F>) -> Evaluation<F, R> {
        // use precomputed challenge powers to compute lift
        Evaluation::new(self.0 * context.powers[R::USIZE - L::USIZE])
    }
}
