use core::array;
use hybrid_array::typenum::U8;

use super::{
    algebra::{ConstraintAlgebra, Prover, Verifier},
    polynomial::{Evaluation, Polynomial},
};
use crate::{
    fields::BigGaloisField,
    universal_hashing::{ZKHashParameters, ZKHashState, ZKHasher, ZKHasherProcess},
};

/// Hashes OWF constraint polynomials.
///
/// The prover hashes their coefficients, while the verifier hashes their evaluations at Delta.
pub(super) trait ConstraintHasher<F: BigGaloisField> {
    type Algebra: ConstraintAlgebra<F>;
    fn algebra(&self) -> &Self::Algebra;
    fn hash_constraint(
        &mut self,
        constraint: <Self::Algebra as ConstraintAlgebra<F>>::ConstraintDeg7,
    );
}

#[derive(Debug)]
pub(super) struct ZKProofHasher<F: BigGaloisField> {
    parameters: ZKHashParameters<F>,
    hashers: [ZKHashState<F>; 7],
    pub(super) count: usize,
}

impl<F: BigGaloisField> ZKProofHasher<F> {
    pub(super) fn new(hasher: ZKHasher<F>) -> Self {
        Self {
            parameters: hasher.parameters,
            hashers: [hasher.state; 7],
            count: 0,
        }
    }

    pub(super) fn hash_bit_constraints(&mut self, tags: &[F]) {
        debug_assert_eq!(self.count, 0);
        for &tag in tags {
            self.hashers[5].update(&self.parameters, &tag.square());
            self.hashers[6].update(&self.parameters, &tag);
        }
        self.count += tags.len();
    }

    pub(super) fn finalize(self, masks: &[(F, F); 6]) -> [F; 7] {
        let mut hashers = self.hashers.into_iter();
        array::from_fn(|j| {
            // OWFProve lines 15-18
            let mask = match j {
                0 => masks[0].1,
                // OWFProve line 18
                6 => masks[5].0,
                // OWFProve line 17
                _ => masks[j - 1].0 + masks[j].1,
            };
            // SAFETY: hashers have same length as output array
            hashers.next().unwrap().finalize(&self.parameters, &mask)
        })
    }
}

impl<F: BigGaloisField> ConstraintHasher<F> for ZKProofHasher<F> {
    type Algebra = Prover;
    fn algebra(&self) -> &Prover {
        &Prover
    }

    fn hash_constraint(&mut self, polynomial: Polynomial<F, U8>) {
        // Always advance all seven streams, even when the coefficient is zero
        for (hasher, coefficient) in self.hashers.iter_mut().zip(polynomial.coefficients) {
            hasher.update(&self.parameters, &coefficient);
        }
        self.count += 1;
    }
}

pub(super) struct ZKVerifyHasher<F: BigGaloisField> {
    hasher: ZKHasher<F>,
    algebra: Verifier<F>,
    pub(super) count: usize,
}

impl<F: BigGaloisField> ZKVerifyHasher<F> {
    pub(super) fn new(hasher: ZKHasher<F>, delta: F) -> Self {
        Self {
            hasher,
            algebra: Verifier::new(delta),
            count: 0,
        }
    }

    pub(super) fn hash_bit_constraints(&mut self, tags: &[F]) {
        let delta = self.algebra.powers[1];
        let delta5 = self.algebra.powers[5];
        for &q in tags {
            self.hasher.update(&(q * (q + delta) * delta5));
        }
        self.count += tags.len();
    }

    pub(super) fn finalize(self, q_bar: &[F; 6], a_tilde: &[F; 6]) -> F {
        // OWFVerify line 5
        let q_star = q_bar
            .iter()
            .rev()
            .fold(F::ZERO, |acc, q_j| acc * self.algebra.powers[1] + q_j);
        // OWFVerify lines 14-16
        let rhs = a_tilde
            .iter()
            .rev()
            .fold(F::ZERO, |acc, a_j| acc * self.algebra.powers[1] + a_j)
            * self.algebra.powers[1];
        self.hasher.finalize(&q_star) + rhs
    }
}

impl<F: BigGaloisField> ConstraintHasher<F> for ZKVerifyHasher<F> {
    type Algebra = Verifier<F>;
    fn algebra(&self) -> &Verifier<F> {
        &self.algebra
    }

    fn hash_constraint(&mut self, evaluation: Evaluation<F, U8>) {
        self.hasher.update(&evaluation.0);
        self.count += 1;
    }
}
