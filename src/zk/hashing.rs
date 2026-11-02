use core::array;

use super::polynomial::Polynomial;
use crate::{
    fields::BigGaloisField,
    universal_hashing::{ZKHasher, ZKHasherProcess},
};

/// Hashes OWF constraint polynomials.
///
/// The prover hashes their coefficients, while the verifier hashes their evaluations at Delta.
pub(super) trait ConstraintHasher<F: BigGaloisField> {
    fn hash_constraint(&mut self, polynomial: Polynomial<F>);
}

#[derive(Debug)]
pub(super) struct ZKProofHasher<F: BigGaloisField> {
    // TODO: consider sharing s, t, r0, r1
    hashers: [ZKHasher<F>; 7],
    pub(super) count: usize,
}

impl<F: BigGaloisField> ZKProofHasher<F> {
    pub(super) fn new(hasher: ZKHasher<F>) -> Self {
        Self {
            hashers: array::from_fn(|_| hasher.clone()),
            count: 0,
        }
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
            hashers.next().unwrap().finalize(&mask)
        })
    }
}

impl<F: BigGaloisField> ConstraintHasher<F> for ZKProofHasher<F> {
    fn hash_constraint(&mut self, polynomial: Polynomial<F>) {
        // Always advance all seven streams, even when the coefficient is zero
        for (hasher, coefficient) in self.hashers.iter_mut().zip(polynomial.coefficients) {
            hasher.update(&coefficient);
        }
        self.count += 1;
    }
}

pub(super) struct ZKVerifyHasher<F: BigGaloisField> {
    hasher: ZKHasher<F>,
    delta: F,
    pub(super) count: usize,
}

impl<F: BigGaloisField> ZKVerifyHasher<F> {
    pub(super) fn new(hasher: ZKHasher<F>, delta: F) -> Self {
        Self {
            hasher,
            delta,
            count: 0,
        }
    }

    pub(super) fn finalize(self, q_bar: &[F; 6], a_tilde: &[F; 6]) -> F {
        // OWFVerify line 5
        let q_star = q_bar
            .iter()
            .rev()
            .fold(F::ZERO, |acc, q_j| acc * self.delta + q_j);
        // OWFVerify lines 14-16
        let rhs = a_tilde
            .iter()
            .rev()
            .fold(F::ZERO, |acc, a_j| acc * self.delta + a_j)
            * self.delta;
        self.hasher.finalize(&q_star) + rhs
    }
}

impl<F: BigGaloisField> ConstraintHasher<F> for ZKVerifyHasher<F> {
    fn hash_constraint(&mut self, polynomial: Polynomial<F>) {
        self.hasher.update(&polynomial.evaluate(self.delta));
        self.count += 1;
    }
}
