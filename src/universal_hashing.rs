use core::{
    array,
    fmt::Debug,
    ops::{Add, Mul},
};

use hybrid_array::{
    Array, ArraySize,
    typenum::{Prod, Sum, U2, U3, U4, U8, U16, Unsigned},
};

use crate::{
    fields::{BaseField, BigGaloisField, ExtensionField, Field, GF64, GF128, GF192, GF256},
    parameter::SecurityParameter,
    // prover::field_commitment::{FieldCommitDegOne, FieldCommitDegThree, FieldCommitDegTwo},
};

/// Seed size for FAEST VOLEHash
pub(crate) type VoleHashSeedLength<LambdaBytes> = Sum<Prod<LambdaBytes, U8>, U8>;
/// Output size for FAEST VOLEHash.
pub(crate) type VoleHashOutputLength<LambdaBytes> = Prod<LambdaBytes, U4>;

/// Interface to instantiate a VOLE hasher
pub(crate) trait VoleHasherInit<F>
where
    F: BigGaloisField,
{
    type SDLength: ArraySize;
    type OutputLength: ArraySize;
    type Hasher: VoleHasherProcess<F, Self::OutputLength>;

    fn new_vole_hasher(sd: &Array<u8, Self::SDLength>) -> Self::Hasher {
        // Parse `r0 || ... || r3 || s0 || ... || s3 || t`
        let n = F::Length::USIZE;
        let r = array::from_fn(|i| F::from(&sd[i * n..(i + 1) * n]));
        let s = array::from_fn(|i| F::from(&sd[(4 + i) * n..(5 + i) * n]));
        let t = GF64::from(&sd[8 * n..8 * n + <GF64 as Field>::Length::USIZE]);

        Self::Hasher::from_r_s_t(r, s, t)
    }
}

/// Process the input to VOLE hash and produce the hash
pub(crate) trait VoleHasherProcess<F, OutputLength>
where
    Self: Clone + Sized,
    F: BigGaloisField,
    OutputLength: ArraySize,
{
    fn process_split(&self, x0: &[u8], x1: &[u8]) -> Array<u8, OutputLength>;

    fn process(&self, x: &[u8]) -> Array<u8, OutputLength> {
        let (x0, x1) = x.split_at(x.len() - OutputLength::USIZE);
        self.process_split(x0, x1)
    }

    fn from_r_s_t(r: [F; 4], s: [F; 4], t: GF64) -> Self;
}

#[derive(Debug, Clone)]
pub(crate) struct VoleHasher<F: BigGaloisField> {
    r: [F; 4],
    s: [F; 4],
    t: GF64,
}

impl<F> VoleHasherInit<F> for VoleHasher<F>
where
    F: BigGaloisField<Length: SecurityParameter>,
    Prod<F::Length, U8>: Add<U8, Output: ArraySize>,
{
    type SDLength = VoleHashSeedLength<F::Length>;
    type OutputLength = VoleHashOutputLength<F::Length>;
    type Hasher = Self;
}

impl<F> VoleHasherProcess<F, VoleHashOutputLength<F::Length>> for VoleHasher<F>
where
    F: BigGaloisField<Length: Mul<U4, Output: ArraySize>>,
{
    fn process_split(&self, x0: &[u8], x1: &[u8]) -> Array<u8, VoleHashOutputLength<F::Length>> {
        // TODO: consider using hybrid arrays
        let mut x0s = x0.chunks_exact(F::Length::USIZE);

        // line 7
        // SAFETY: caller must ensure coefficients have correct lengths
        let mut y = [F::from(x0s.next().unwrap()); 5];
        for bytes in x0s {
            let x0_i = F::from(bytes);
            for (yj, sj) in y.iter_mut().zip(&self.s) {
                *yj = *yj * *sj + x0_i;
            }
            y[4] = y[4] * self.t + x0_i;
        }

        // line 8
        let mut output = Array::<u8, VoleHashOutputLength<F::Length>>::default();
        for (j, (chunk, x1_j)) in output
            .chunks_exact_mut(F::Length::USIZE)
            .zip(x1.chunks_exact(F::Length::USIZE))
            .enumerate()
        {
            let mask = F::from(x1_j);
            chunk.copy_from_slice(&(self.r[j] * y[0] + y[j + 1] + mask).as_bytes());
        }
        output
    }

    fn from_r_s_t(r: [F; 4], s: [F; 4], t: GF64) -> Self {
        Self { r, s, t }
    }
}

/// Interface for Init-Update-Finalize-style implementations of ZK-Hash covering the Init part
pub(crate) trait ZKHasherInit<F>
where
    F: BigGaloisField + Debug,
{
    type SDLength: ArraySize;

    fn new_zk_hasher(sd: &Array<u8, Self::SDLength>) -> ZKHasher<F> {
        let r0 = F::from(&sd[..F::Length::USIZE]);
        let r1 = F::from(&sd[F::Length::USIZE..2 * F::Length::USIZE]);
        let s = F::from(&sd[2 * F::Length::USIZE..3 * F::Length::USIZE]);
        let t = GF64::from(
            &sd[3 * F::Length::USIZE..3 * F::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );

        ZKHasher {
            h0: F::ZERO,
            h1: F::ZERO,
            s,
            t,
            r0,
            r1,
        }
    }

    // fn new_zk_proof_hasher(sd: &Array<u8, Self::SDLength>) -> ZKProofHasher<F> {
    //     let hasher = Self::new_zk_hasher(sd);
    //     ZKProofHasher::new(hasher.clone(), hasher.clone(), hasher)
    // }

    // fn new_zk_verify_hasher(sd: &Array<u8, Self::SDLength>, delta: F) -> ZKVerifyHasher<F> {
    //     ZKVerifyHasher::new(Self::new_zk_hasher(sd), delta)
    // }
}

/// Interface for Init-Update-Finalize-style implementations of ZK-Hash covering the Update and Finalize part
pub(crate) trait ZKHasherProcess<F>
where
    Self: Clone,
    F: BigGaloisField,
{
    fn update(&mut self, v: &F);

    fn finalize(self, x1: &F) -> F;
}

#[derive(Debug, Clone)]
pub(crate) struct ZKHasher<F>
where
    F: BigGaloisField,
{
    h0: F,
    h1: F,
    s: F,
    t: GF64,
    r0: F,
    r1: F,
}

impl<F> ZKHasherInit<F> for ZKHasher<F>
where
    F: BigGaloisField<Length: SecurityParameter>,
    <F as Field>::Length:
        Mul<U3, Output: ArraySize + Add<U8, Output: ArraySize>> + Add<U2, Output: ArraySize>,
{
    type SDLength = Sum<Prod<<F as Field>::Length, U3>, <GF64 as Field>::Length>;
}

impl<F> ZKHasherProcess<F> for ZKHasher<F>
where
    F: BigGaloisField,
{
    fn update(&mut self, v: &F) {
        self.h0 = (self.h0 * self.s) + v;
        self.h1 = (self.h1 * self.t) + v;
    }

    fn finalize(self, x1: &F) -> F {
        (self.r0 * self.h0) + (self.r1 * self.h1) + x1
    }
}

// #[derive(Debug)]
// pub(crate) struct ZKProofHasher<F>
// where
//     F: BigGaloisField,
// {
//     a0_hasher: ZKHasher<F>,
//     a1_hasher: ZKHasher<F>,
//     a2_hasher: ZKHasher<F>,
// }

// impl<F> ZKProofHasher<F>
// where
//     F: BigGaloisField + PartialEq + Debug,
// {
//     pub(crate) const fn new(
//         a0_hasher: ZKHasher<F>,
//         a1_hasher: ZKHasher<F>,
//         a2_hasher: ZKHasher<F>,
//     ) -> Self {
//         Self {
//             a0_hasher,
//             a1_hasher,
//             a2_hasher,
//         }
//     }

//     pub(crate) fn update(&mut self, val: &FieldCommitDegThree<F>) {
//         // Degree 0
//         self.a0_hasher.update(&val.tag[0]);
//         // Degree 1
//         self.a1_hasher.update(&val.tag[1]);
//         // Degree 2
//         self.a2_hasher.update(&val.tag[2]);

//         // Should be a commitment to 0
//         debug_assert_eq!(val.key, F::ZERO);
//     }

//     /// Lift and hash coefficients of <a^2> * <b> - <a> and <b^2> * <a> - <b>
//     pub(crate) fn lift_and_process(
//         &mut self,
//         a: &FieldCommitDegOne<F>,
//         a_sq: &FieldCommitDegOne<F>,
//         b: &FieldCommitDegOne<F>,
//         b_sq: &FieldCommitDegOne<F>,
//     ) {
//         // Degree 1
//         self.a1_hasher.update(&(a_sq.tag[0] * b.tag[0]));
//         self.a1_hasher.update(&(b_sq.tag[0] * a.tag[0]));

//         // Degree 2
//         self.a2_hasher
//             .update(&(a_sq.key * b.tag[0] + a_sq.tag[0] * b.key - a.tag[0]));
//         self.a2_hasher
//             .update(&(b_sq.key * a.tag[0] + b_sq.tag[0] * a.key - b.tag[0]));

//         // Degree 3 (i.e., commitments) should be zero
//         debug_assert_eq!(a_sq.key * b.key - a.key, F::ZERO);
//         debug_assert_eq!(b_sq.key * a.key - b.key, F::ZERO);
//     }

//     pub(crate) fn odd_round_cstrnts(
//         &mut self,
//         si: &FieldCommitDegOne<F>,
//         si_sq: &FieldCommitDegOne<F>,
//         st0_i: &FieldCommitDegTwo<F>,
//         st1_i: &FieldCommitDegTwo<F>,
//     ) where
//         F: BigGaloisField,
//     {
//         self.update(&(si_sq * st0_i + si));
//         self.update(&(si * st1_i + st0_i));
//     }

//     pub(crate) fn finalize(self, u: &F, u_plus_v: &F, v: &F) -> (F, F, F) {
//         let a0 = self.a0_hasher.finalize(u);
//         let a1 = self.a1_hasher.finalize(u_plus_v);
//         let a2 = self.a2_hasher.finalize(v);

//         (a0, a1, a2)
//     }
// }

// pub(crate) struct ZKVerifyHasher<F>
// where
//     F: BigGaloisField,
// {
//     pub(crate) b_hasher: ZKHasher<F>,
//     pub(crate) delta: F,
//     pub(crate) delta_squared: F,
// }

// impl<F> ZKVerifyHasher<F>
// where
//     F: BigGaloisField,
// {
//     pub(crate) fn new(b_hasher: ZKHasher<F>, delta: F) -> Self {
//         Self {
//             b_hasher,
//             delta,
//             delta_squared: delta.square(),
//         }
//     }

//     pub(crate) fn update(&mut self, val: &F) {
//         self.b_hasher.update(val);
//     }

//     pub(crate) fn mul_and_update(&mut self, a: &F, b: &F) {
//         self.b_hasher.update(&(self.delta * a * b));
//     }

//     pub(crate) fn inv_norm_constraints(&mut self, conjugates: &[F], y: &F) {
//         let cnstr = *y * conjugates[1] * conjugates[4] + self.delta_squared * conjugates[0];
//         self.b_hasher.update(&cnstr);
//     }

//     pub(crate) fn odd_round_cstrnts(&mut self, si: &F, si_sq: &F, st0_i: &F, st1_i: &F) {
//         self.update(&(self.delta_squared * si + *si_sq * st0_i));
//         self.update(&(self.delta * st0_i + *si * st1_i));
//     }

//     /// Lift and hash coefficients of <a^2> * <b> - <a> and <b^2> * <a> - <b>
//     pub(crate) fn lift_and_process(&mut self, a: &F, a_sq: &F, b: &F, b_sq: &F) {
//         // Raise to degree 3 and update
//         self.update(&(self.delta * (*a_sq * b - self.delta * a)));
//         self.update(&(self.delta * (*a * b_sq - self.delta * b)));
//     }

//     pub(crate) fn finalize(self, v: &F) -> F {
//         self.b_hasher.finalize(v)
//     }
// }

pub(crate) trait LeafHasher {
    type F: BigGaloisField<Length = Self::LambdaBytes>;
    type ExtensionField: ExtensionField<Length = Prod<Self::LambdaBytes, U3>, BaseField = Self::F>;
    type Lambda: ArraySize;
    type LambdaBytes: SecurityParameter;

    fn hash(
        uhash: &Array<u8, Prod<Self::LambdaBytes, U3>>,
        x: &Array<u8, Prod<Self::LambdaBytes, U4>>,
    ) -> Array<u8, Prod<Self::LambdaBytes, U3>>;
}
use core::marker::PhantomData;
use hybrid_array::typenum::{U24, U32, U48, U72, U96};

pub(crate) struct LeafHasher128<F = GF128>(PhantomData<F>);
impl<F> LeafHasher for LeafHasher128<F>
where
    F: BigGaloisField<Length = U16> + BaseField,
    <F as BaseField>::ExtenionField: ExtensionField<Length = U48>,
{
    type F = F;
    type ExtensionField = F::ExtenionField;
    type LambdaBytes = <GF128 as Field>::Length;
    type Lambda = Prod<Self::LambdaBytes, U8>;

    fn hash(
        uhash: &Array<u8, Prod<Self::LambdaBytes, U3>>,
        x: &Array<u8, Prod<Self::LambdaBytes, U4>>,
    ) -> Array<u8, Prod<Self::LambdaBytes, U3>> {
        let u = <Self as LeafHasher>::ExtensionField::from(uhash.as_slice());
        let x0 =
            <Self as LeafHasher>::F::from(&x[..<<Self as LeafHasher>::F as Field>::Length::USIZE]);
        let x1 = <Self as LeafHasher>::ExtensionField::from(
            &x[<<Self as LeafHasher>::F as Field>::Length::USIZE..],
        );

        let h = (u * x0) + x1;
        h.as_bytes()
    }
}

pub(crate) struct LeafHasher192<F = GF192>(PhantomData<F>);
impl<F> LeafHasher for LeafHasher192<F>
where
    F: BigGaloisField<Length = U24> + BaseField,
    F::ExtenionField: ExtensionField<Length = U72>,
{
    type F = F;
    type ExtensionField = F::ExtenionField;
    type LambdaBytes = <GF192 as Field>::Length;
    type Lambda = Prod<Self::LambdaBytes, U8>;

    fn hash(
        uhash: &Array<u8, Prod<Self::LambdaBytes, U3>>,
        x: &Array<u8, Prod<Self::LambdaBytes, U4>>,
    ) -> Array<u8, Prod<Self::LambdaBytes, U3>> {
        let u = <Self as LeafHasher>::ExtensionField::from(uhash.as_slice());
        let x0 =
            <Self as LeafHasher>::F::from(&x[..<<Self as LeafHasher>::F as Field>::Length::USIZE]);
        let x1 = <Self as LeafHasher>::ExtensionField::from(
            &x[<<Self as LeafHasher>::F as Field>::Length::USIZE..],
        );

        let h = (u * x0) + x1;
        h.as_bytes()
    }
}

pub(crate) struct LeafHasher256<F = GF256>(PhantomData<F>);
impl<F> LeafHasher for LeafHasher256<F>
where
    F: BigGaloisField<Length = U32> + BaseField,
    F::ExtenionField: ExtensionField<Length = U96>,
{
    type F = F;
    type ExtensionField = F::ExtenionField;
    type LambdaBytes = <GF256 as Field>::Length;
    type Lambda = Prod<Self::LambdaBytes, U8>;

    fn hash(
        uhash: &Array<u8, Prod<Self::LambdaBytes, U3>>,
        x: &Array<u8, Prod<Self::LambdaBytes, U4>>,
    ) -> Array<u8, Prod<Self::LambdaBytes, U3>> {
        let u = <Self as LeafHasher>::ExtensionField::from(uhash.as_slice());
        let x0 =
            <Self as LeafHasher>::F::from(&x[..<<Self as LeafHasher>::F as Field>::Length::USIZE]);
        let x1 = <Self as LeafHasher>::ExtensionField::from(
            &x[<<Self as LeafHasher>::F as Field>::Length::USIZE..],
        );

        let h = (u * x0) + x1;
        h.as_bytes()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

    use serde::{Deserialize, de::DeserializeOwned};

    use crate::{
        fields::{GF128, GF192, GF256},
        utils::{array_ref, test::read_test_data},
    };

    #[derive(Debug, Deserialize)]
    #[serde(bound = "F: DeserializeOwned")]
    struct ZKHashDatabaseEntry<F> {
        sd: Vec<u8>,
        x0: Vec<F>,
        x1: F,
        h: Vec<u8>,
    }

    #[derive(Debug, Deserialize)]
    struct VoleHashDatabaseEntry {
        lambda: usize,
        ell: usize,
        sd: Vec<u8>,
        x: Vec<u8>,
        h: Vec<u8>,
    }

    #[derive(Debug, Deserialize)]
    struct LeafHashDatabaseEntry {
        uhash: Vec<u8>,
        x: Vec<u8>,
        expected_h: Vec<u8>,
    }

    fn check_volehash_vectors<F>()
    where
        F: BigGaloisField<Length: SecurityParameter>,
        Prod<F::Length, U8>: Add<U8, Output: ArraySize>,
    {
        let database: Vec<VoleHashDatabaseEntry> =
            serde_json::from_str(include_str!("../tests/vole_hash.json")).unwrap();
        let entries: Vec<_> = database
            .iter()
            .filter(|v| v.lambda == F::Length::USIZE * 8)
            .collect();
        for data in &entries {
            let hasher = VoleHasher::<F>::new_vole_hasher(array_ref(&data.sd));
            assert_eq!(hasher.process(&data.x).as_slice(), data.h);
            let (x0, x1) = data.x.split_at(data.x.len() - data.h.len());
            assert_eq!(hasher.process_split(x0, x1).as_slice(), data.h);
        }
    }

    macro_rules! volehash_tests {
        ($name:ident, $field:ty) => {
            #[test]
            fn $name() {
                check_volehash_vectors::<$field>();
            }
        };
    }

    volehash_tests!(test_volehash_128, crate::fields::large_fields::GF128);
    volehash_tests!(test_volehash_192, crate::fields::large_fields::GF192);
    volehash_tests!(test_volehash_256, crate::fields::large_fields::GF256);

    #[test]
    fn test_zkhash_128() {
        let database: Vec<ZKHashDatabaseEntry<GF128>> = read_test_data("zkhash_128.json");

        for data in database {
            let sd = array_ref(&data.sd);

            let mut hasher = ZKHasher::<GF128>::new_zk_hasher(sd);
            for v in &data.x0 {
                hasher.update(v);
            }
            let res = hasher.finalize(&data.x1);
            assert_eq!(GF128::from(data.h.as_slice()), res);
        }
    }

    #[test]
    fn test_zkhash_192() {
        let database: Vec<ZKHashDatabaseEntry<GF192>> = read_test_data("zkhash_192.json");

        for data in database {
            let sd = array_ref(&data.sd);

            let mut hasher = ZKHasher::<GF192>::new_zk_hasher(sd);
            for v in &data.x0 {
                hasher.update(v);
            }
            let res = hasher.finalize(&data.x1);
            assert_eq!(GF192::from(data.h.as_slice()), res);
        }
    }

    #[test]
    fn test_zkhash_256() {
        let database: Vec<ZKHashDatabaseEntry<GF256>> = read_test_data("zkhash_256.json");

        for data in database {
            let sd = array_ref(&data.sd);

            let mut hasher = ZKHasher::<GF256>::new_zk_hasher(sd);
            for v in &data.x0 {
                hasher.update(v);
            }
            let res = hasher.finalize(&data.x1);
            assert_eq!(GF256::from(data.h.as_slice()), res);
        }
    }

    #[test]
    fn test_leaf_hash_128() {
        let database: Vec<LeafHashDatabaseEntry> = read_test_data("leafhash_128.json");

        for data in database {
            let x = array_ref(&data.x);
            let uhash = array_ref(&data.uhash);

            let h = LeafHasher128::<GF128>::hash(uhash, x);
            assert_eq!(h.as_slice(), &data.expected_h)
        }
    }

    #[test]
    fn test_leaf_hash_192() {
        let database: Vec<LeafHashDatabaseEntry> = read_test_data("leafhash_192.json");

        for data in database {
            let x = array_ref(&data.x);
            let uhash = array_ref(&data.uhash);

            let h = LeafHasher192::<GF192>::hash(uhash, x);
            assert_eq!(h.as_slice(), &data.expected_h)
        }
    }

    #[test]
    fn test_leaf_hash_256() {
        let database: Vec<LeafHashDatabaseEntry> = read_test_data("leafhash_256.json");

        for data in database {
            let x = array_ref(&data.x);
            let uhash = array_ref(&data.uhash);

            let h = LeafHasher256::<GF256>::hash(uhash, x);

            assert_eq!(h.as_slice(), &data.expected_h)
        }
    }
}
