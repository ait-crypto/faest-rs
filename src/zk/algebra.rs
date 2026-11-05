use core::ops::{Add, AddAssign, Mul};

use super::polynomial::{Evaluation, Polynomial};
use crate::fields::BigGaloisField;
use hybrid_array::{
    Array,
    typenum::{U2, U3, U4, U5, U8},
};

pub(super) trait AlgebraValue<F>:
    Copy + Add<Output = Self> + AddAssign + Mul<F, Output = Self>
{
}

impl<F, T> AlgebraValue<F> for T where
    T: Copy + Add<Output = Self> + AddAssign + Mul<F, Output = Self>
{
}

/// Multiply by a power of X to reach the destination's degree.
/// The verifier needs its challenge powers to compute this operation efficiently.
pub(super) trait Lift<T, Context> {
    fn lift(self, context: &Context) -> T;
}

/// Degree combinations required for constraint evaluation
pub(super) trait ConstraintAlgebra<F: BigGaloisField>: Copy {
    type ConstraintDeg1: AlgebraValue<F>
        + Mul<Self::ConstraintDeg1, Output = Self::ConstraintDeg2>
        + Mul<Self::ConstraintDeg2, Output = Self::ConstraintDeg3>
        + Lift<Self::ConstraintDeg2, Self>
        + Lift<Self::ConstraintDeg7, Self>;
    type ConstraintDeg2: AlgebraValue<F>
        + Mul<Self::ConstraintDeg1, Output = Self::ConstraintDeg3>
        + Mul<Self::ConstraintDeg2, Output = Self::ConstraintDeg4>
        + Lift<Self::ConstraintDeg7, Self>;
    type ConstraintDeg3: AlgebraValue<F> + Mul<Self::ConstraintDeg4, Output = Self::ConstraintDeg7>;
    type ConstraintDeg4: AlgebraValue<F> + Mul<Self::ConstraintDeg3, Output = Self::ConstraintDeg7>;
    type ConstraintDeg7: AlgebraValue<F>;

    fn linear_constraint(&self, key: F, tag: F) -> Self::ConstraintDeg1;

    fn constant_deg7(&self, value: F) -> Self::ConstraintDeg7;
}

#[derive(Copy, Clone)]
pub(super) struct Prover;

impl<F: BigGaloisField> ConstraintAlgebra<F> for Prover {
    type ConstraintDeg1 = Polynomial<F, U2>;
    type ConstraintDeg2 = Polynomial<F, U3>;
    type ConstraintDeg3 = Polynomial<F, U4>;
    type ConstraintDeg4 = Polynomial<F, U5>;
    type ConstraintDeg7 = Polynomial<F, U8>;

    fn linear_constraint(&self, key: F, tag: F) -> Self::ConstraintDeg1 {
        Polynomial::from_key_tag(key, tag)
    }

    fn constant_deg7(&self, _value: F) -> Self::ConstraintDeg7 {
        // prover doesn't compute degree 7 coefficients (must be 0)
        Polynomial {
            coefficients: Array([F::ZERO; 7]),
        }
    }
}

#[derive(Copy, Clone)]
pub(super) struct Verifier<F> {
    // precomputed powers of the challenge
    pub(super) powers: [F; 8],
}

impl<F: BigGaloisField> Verifier<F> {
    pub(super) fn new(delta: F) -> Self {
        let mut powers = [F::ONE; 8];
        for i in 1..8 {
            powers[i] = powers[i - 1] * delta;
        }
        Self { powers }
    }
}

impl<F: BigGaloisField> ConstraintAlgebra<F> for Verifier<F> {
    type ConstraintDeg1 = Evaluation<F, U2>;
    type ConstraintDeg2 = Evaluation<F, U3>;
    type ConstraintDeg3 = Evaluation<F, U4>;
    type ConstraintDeg4 = Evaluation<F, U5>;
    type ConstraintDeg7 = Evaluation<F, U8>;

    fn linear_constraint(&self, key: F, tag: F) -> Self::ConstraintDeg1 {
        Evaluation::new(tag + key * self.powers[1])
    }

    fn constant_deg7(&self, value: F) -> Self::ConstraintDeg7 {
        Evaluation::new(value * self.powers[7])
    }
}
