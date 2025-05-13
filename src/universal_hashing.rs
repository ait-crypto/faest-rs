use std::{
    array,
    iter::zip,
    ops::{Add, Mul},
};

use generic_array::{
    ArrayLength, GenericArray,
    typenum::{Prod, Quot, Sum, U2, U3, U4, U5, U8, U16, Unsigned},
};
use itertools::chain;

use crate::{
    fields::{
        BigGaloisField, ExtensionField, Field, GF64, GF128, GF192, GF256, GF384, GF576, GF768,
    },
    prover::field_commitment::{FieldCommitDegOne, FieldCommitDegThree, FieldCommitDegTwo},
};

type BBits = U16;
// Additional bytes returned by VOLE hash
pub(crate) type B = Quot<BBits, U8>;

/// Interface to instantiate a VOLE hasher
pub(crate) trait VoleHasherInit<F>
where
    F: BigGaloisField,
{
    type SDLength: ArrayLength;
    type OutputLength: ArrayLength;
    type Hasher: VoleHasherProcess<F, Self::OutputLength>;

    fn new_vole_hasher(sd: &GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        let r = array::from_fn(|i| F::from(&sd[i * F::Length::USIZE..(i + 1) * F::Length::USIZE]));
        let s = F::from(&sd[4 * F::Length::USIZE..5 * F::Length::USIZE]);
        let t = GF64::from(
            &sd[5 * F::Length::USIZE..5 * F::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );

        Self::Hasher::from_r_s_t(r, s, t)
    }
}

/// Process the input to VOLE hash and produce the hash
pub(crate) trait VoleHasherProcess<F, OutputLength>
where
    Self: Clone + Sized,
    F: BigGaloisField,
    OutputLength: ArrayLength,
{
    fn process_split(
        &self,
        x0: &[u8],
        x1: &GenericArray<u8, OutputLength>,
    ) -> GenericArray<u8, OutputLength>;

    fn process(&self, x: &[u8]) -> GenericArray<u8, OutputLength> {
        debug_assert!(x.len() > OutputLength::USIZE);

        let x0 = &x[..x.len() - OutputLength::USIZE];
        let x1 = &x[x.len() - OutputLength::USIZE..];

        self.process_split(x0, GenericArray::from_slice(x1))
    }

    fn from_r_s_t(r: [F; 4], s: F, t: GF64) -> Self;
}

/// The VOLE hasher
#[derive(Debug, Clone)]
pub(crate) struct VoleHasher<F>
where
    F: BigGaloisField,
{
    r: [F; 4],
    s: F,
    t: GF64,
}

impl VoleHasherInit<GF128> for VoleHasher<GF128> {
    type SDLength = Sum<Prod<<GF128 as Field>::Length, U5>, <GF64 as Field>::Length>;
    type OutputLength = Sum<<GF128 as Field>::Length, B>;
    type Hasher = Self;
}

impl VoleHasherInit<GF192> for VoleHasher<GF192> {
    type SDLength = Sum<Prod<<GF192 as Field>::Length, U5>, <GF64 as Field>::Length>;
    type OutputLength = Sum<<GF192 as Field>::Length, B>;
    type Hasher = Self;
}

impl VoleHasherInit<GF256> for VoleHasher<GF256> {
    type SDLength = Sum<Prod<<GF256 as Field>::Length, U5>, <GF64 as Field>::Length>;
    type OutputLength = Sum<<GF256 as Field>::Length, B>;
    type Hasher = Self;
}

impl<F> VoleHasherProcess<F, <Self as VoleHasherInit<F>>::OutputLength> for VoleHasher<F>
where
    F: BigGaloisField,
    Self: VoleHasherInit<F>,
{
    fn process_split(
        &self,
        x0: &[u8],
        x1: &GenericArray<u8, <Self as VoleHasherInit<F>>::OutputLength>,
    ) -> GenericArray<u8, <Self as VoleHasherInit<F>>::OutputLength> {
        let mut h0 = F::ZERO;
        let mut h1 = GF64::ZERO;

        let iter = x0.chunks_exact(<F as Field>::Length::USIZE);
        let remainder = iter.remainder();
        for data in iter {
            self.process_block(&mut h0, &mut h1, data);
        }
        if !remainder.is_empty() {
            self.process_unpadded_block(&mut h0, &mut h1, remainder);
        }

        let h2 = self.r[0] * h0 + self.r[1] * h1;
        let h3 = self.r[2] * h0 + self.r[3] * h1;

        GenericArray::from_iter(
            zip(
                chain(h2.as_bytes(), h3.as_bytes().into_iter().take(B::USIZE)),
                x1,
            )
            .map(|(x1, x2)| x1 ^ x2),
        )
    }

    fn from_r_s_t(r: [F; 4], s: F, t: GF64) -> Self {
        Self { r, s, t }
    }
}

impl<F> VoleHasher<F>
where
    F: BigGaloisField,
{
    fn process_block(&self, h0: &mut F, h1: &mut GF64, data: &[u8]) {
        *h0 = *h0 * self.s + F::from(data);
        for data in data.chunks_exact(<GF64 as Field>::Length::USIZE) {
            *h1 = *h1 * self.t + GF64::from(data);
        }
    }

    fn process_unpadded_block(&self, h0: &mut F, h1: &mut GF64, data: &[u8]) {
        let mut buf = GenericArray::<u8, F::Length>::default();
        buf[..data.len()].copy_from_slice(data);
        self.process_block(h0, h1, &buf);
    }
}

/// Interface for Init-Update-Finalize-style implementations of ZK-Hash covering the Init part
pub(crate) trait ZKHasherInit<F>
where
    F: BigGaloisField + PartialEq + std::fmt::Debug,
{
    type SDLength: ArrayLength;

    fn new_zk_hasher(sd: &GenericArray<u8, Self::SDLength>) -> ZKHasher<F> {
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

    fn new_zk_proof_hasher(sd: &GenericArray<u8, Self::SDLength>) -> ZKProofHasher<F> {
        let hasher = Self::new_zk_hasher(sd);
        ZKProofHasher::new(hasher.clone(), hasher.clone(), hasher)
    }

    fn new_zk_verify_hasher(sd: &GenericArray<u8, Self::SDLength>, delta: F) -> ZKVerifyHasher<F> {
        ZKVerifyHasher::new(Self::new_zk_hasher(sd), delta)
    }
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

impl ZKHasherInit<GF128> for ZKHasher<GF128> {
    type SDLength = Sum<Prod<<GF128 as Field>::Length, U3>, <GF64 as Field>::Length>;
}

impl ZKHasherInit<GF192> for ZKHasher<GF192> {
    type SDLength = Sum<Prod<<GF192 as Field>::Length, U3>, <GF64 as Field>::Length>;
}

impl ZKHasherInit<GF256> for ZKHasher<GF256> {
    type SDLength = Sum<Prod<<GF256 as Field>::Length, U3>, <GF64 as Field>::Length>;
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

#[derive(Debug)]
pub(crate) struct ZKProofHasher<F>
where
    F: BigGaloisField,
{
    a0_hasher: ZKHasher<F>,
    a1_hasher: ZKHasher<F>,
    a2_hasher: ZKHasher<F>,
}

impl<F> ZKProofHasher<F>
where
    F: BigGaloisField + PartialEq + std::fmt::Debug,
{
    pub(crate) const fn new(
        a0_hasher: ZKHasher<F>,
        a1_hasher: ZKHasher<F>,
        a2_hasher: ZKHasher<F>,
    ) -> Self {
        Self {
            a0_hasher,
            a1_hasher,
            a2_hasher,
        }
    }

    pub(crate) fn update(&mut self, val: &FieldCommitDegThree<F>) {
        // Degree 0
        self.a0_hasher.update(&val.tag[0]);
        // Degree 1
        self.a1_hasher.update(&val.tag[1]);
        // Degree 2
        self.a2_hasher.update(&val.tag[2]);

        // Should be a commitment to 0
        debug_assert_eq!(val.key, F::ZERO);
    }

    pub(crate) fn lift_and_process(
        &mut self,
        a: &FieldCommitDegOne<F>,
        a_sq: &FieldCommitDegOne<F>,
        b: &FieldCommitDegOne<F>,
        b_sq: &FieldCommitDegOne<F>,
    ) {
        // Lift and hash coefficients of <a^2> * <b> - <a> and <b^2> * <a> - <b>

        // Degree 1
        self.a1_hasher.update(&(a_sq.tag[0] * b.tag[0]));
        self.a1_hasher.update(&(b_sq.tag[0] * a.tag[0]));

        // Degree 2
        self.a2_hasher
            .update(&(a_sq.key * b.tag[0] + a_sq.tag[0] * b.key - a.tag[0]));
        self.a2_hasher
            .update(&(b_sq.key * a.tag[0] + b_sq.tag[0] * a.key - b.tag[0]));

        // Degree 3 (i.e., commitments) should be zero
        debug_assert_eq!(a_sq.key * b.key - a.key, F::ZERO);
        debug_assert_eq!(b_sq.key * a.key - b.key, F::ZERO);
    }

    pub(crate) fn odd_round_cstrnts(
        &mut self,
        si: &FieldCommitDegOne<F>,
        si_sq: &FieldCommitDegOne<F>,
        st0_i: &FieldCommitDegTwo<F>,
        st1_i: &FieldCommitDegTwo<F>,
    ) {
        self.update(&(si_sq.to_owned() * st0_i + si));
        self.update(&(si.to_owned() * st1_i + st0_i));
    }

    pub(crate) fn inv_norm_constraints(
        &mut self,
        conjugates: &[FieldCommitDegOne<F>],
        y: &FieldCommitDegOne<F>,
    ) {
        let cnstr = y.to_owned() * &conjugates[1] * &conjugates[4] + &conjugates[0];
        self.update(&cnstr);
    }

    pub(crate) fn finalize(self, u: &F, u_plus_v: &F, v: &F) -> (F, F, F) {
        let a0 = self.a0_hasher.finalize(u);
        let a1 = self.a1_hasher.finalize(u_plus_v);
        let a2 = self.a2_hasher.finalize(v);

        (a0, a1, a2)
    }
}

pub(crate) struct ZKVerifyHasher<F>
where
    F: BigGaloisField,
{
    pub(crate) b_hasher: ZKHasher<F>,
    pub(crate) delta: F,
    pub(crate) delta_squared: F,
}

impl<F> ZKVerifyHasher<F>
where
    F: BigGaloisField,
{
    pub(crate) fn new(b_hasher: ZKHasher<F>, delta: F) -> Self {
        Self {
            b_hasher,
            delta,
            delta_squared: delta.square(),
        }
    }

    pub(crate) fn update(&mut self, val: &F) {
        self.b_hasher.update(val);
    }

    pub(crate) fn mul_and_update(&mut self, a: &F, b: &F) {
        self.b_hasher.update(&(self.delta * a * b));
    }

    pub(crate) fn inv_norm_constraints(&mut self, conjugates: &[F], y: &F) {
        let cnstr = *y * conjugates[1] * conjugates[4] + self.delta_squared * conjugates[0];
        self.b_hasher.update(&cnstr);
    }

    pub(crate) fn odd_round_cstrnts(&mut self, si: &F, si_sq: &F, st0_i: &F, st1_i: &F) {
        self.update(&(self.delta_squared * si + *si_sq * st0_i));
        self.update(&(self.delta * st0_i + *si * st1_i));
    }

    pub(crate) fn lift_and_process(&mut self, a: &F, a_sq: &F, b: &F, b_sq: &F) {
        // Lift and hash coefficients of <a^2> * <b> - <a> and <b^2> * <a> - <b>

        // Raise to degree 3 and update
        self.update(&(self.delta * (*a_sq * b - self.delta * a)));
        self.update(&(self.delta * (*a * b_sq - self.delta * b)));
    }

    pub(crate) fn finalize(self, v: &F) -> F {
        self.b_hasher.finalize(v)
    }
}

pub(crate) trait LeafHasher
where
    Self::LambdaBytes: Mul<U2, Output: ArrayLength>
        + Mul<U3, Output: ArrayLength>
        + Mul<U4, Output: ArrayLength>
        + Mul<U8, Output = Self::Lambda>
        + PartialEq,
    Self::ExtensionField: for<'a> From<&'a [u8]>
        + for<'a> Mul<&'a Self::F, Output = Self::ExtensionField>
        + for<'a> Add<&'a Self::ExtensionField, Output = Self::ExtensionField>
        + Mul<Self::F, Output = Self::ExtensionField>,
{
    type F: Field + for<'a> From<&'a [u8]>;
    type ExtensionField: ExtensionField<Length = Prod<Self::LambdaBytes, U3>, BaseField = Self::F>;
    type Lambda: ArrayLength;
    type LambdaBytes: ArrayLength;

    fn hash(
        uhash: &GenericArray<u8, Prod<Self::LambdaBytes, U3>>,
        x: &GenericArray<u8, Prod<Self::LambdaBytes, U4>>,
    ) -> GenericArray<u8, Prod<Self::LambdaBytes, U3>> {
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
pub(crate) struct LeafHasher128;
impl LeafHasher for LeafHasher128 {
    type F = GF128;
    type ExtensionField = GF384;
    type LambdaBytes = <GF128 as Field>::Length;
    type Lambda = Prod<Self::LambdaBytes, U8>;
}

pub(crate) struct LeafHasher192;
impl LeafHasher for LeafHasher192 {
    type F = GF192;
    type ExtensionField = GF576;
    type LambdaBytes = <GF192 as Field>::Length;
    type Lambda = Prod<Self::LambdaBytes, U8>;
}

pub(crate) struct LeafHasher256;
impl LeafHasher for LeafHasher256 {
    type F = GF256;
    type ExtensionField = GF768;
    type LambdaBytes = <GF256 as Field>::Length;
    type Lambda = Prod<Self::LambdaBytes, U8>;
}

#[cfg(test)]
mod test {
    use super::*;

    use generic_array::GenericArray;
    use serde::{Deserialize, de::DeserializeOwned};

    use crate::{
        fields::{GF128, GF192, GF256},
        utils::test::read_test_data,
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
        sd: Vec<u8>,
        xs: Vec<u8>,
        h: Vec<u8>,
    }

    #[derive(Debug, Deserialize)]
    struct LeafHashDatabaseEntry {
        uhash: Vec<u8>,
        x: Vec<u8>,
        expected_h: Vec<u8>,
    }

    #[test]
    fn test_volehash_128() {
        let database: Vec<VoleHashDatabaseEntry> = read_test_data("volehash_128.json");
        for data in database {
            let sd = GenericArray::from_slice(&data.sd);
            let h = *GenericArray::from_slice(&data.h);

            let hasher = VoleHasher::<GF128>::new_vole_hasher(sd);
            let res = hasher.process(&data.xs);
            assert_eq!(h, res);
        }
    }

    #[test]
    fn test_volehash_192() {
        let database: Vec<VoleHashDatabaseEntry> = read_test_data("volehash_192.json");
        for data in database {
            let sd = GenericArray::from_slice(&data.sd);
            let h = *GenericArray::from_slice(&data.h);

            let hasher = VoleHasher::<GF192>::new_vole_hasher(sd);
            let res = hasher.process(&data.xs);
            assert_eq!(h, res);
        }
    }

    #[test]
    fn test_volehash_256() {
        let database: Vec<VoleHashDatabaseEntry> = read_test_data("volehash_256.json");

        for data in database {
            let sd = GenericArray::from_slice(&data.sd);
            let h = *GenericArray::from_slice(&data.h);

            let hasher = VoleHasher::<GF256>::new_vole_hasher(sd);
            let res = hasher.process(&data.xs);
            assert_eq!(h, res);
        }
    }

    #[test]
    fn test_zkhash_128() {
        let database: Vec<ZKHashDatabaseEntry<GF128>> = read_test_data("zkhash_128.json");

        for data in database {
            let sd = GenericArray::from_slice(&data.sd);

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
            let sd = GenericArray::from_slice(&data.sd);

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
            let sd = GenericArray::from_slice(&data.sd);

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
            let x = GenericArray::from_slice(&data.x);
            let uhash = GenericArray::from_slice(&data.uhash);

            let h = LeafHasher128::hash(uhash, x);
            assert_eq!(h.as_slice(), &data.expected_h)
        }
    }

    #[test]
    fn test_leaf_hash_192() {
        let database: Vec<LeafHashDatabaseEntry> = read_test_data("leafhash_192.json");

        for data in database {
            let x = GenericArray::from_slice(&data.x);
            let uhash = GenericArray::from_slice(&data.uhash);

            let h = LeafHasher192::hash(uhash, x);
            assert_eq!(h.as_slice(), &data.expected_h)
        }
    }

    #[test]
    fn test_leaf_hash_256() {
        let database: Vec<LeafHashDatabaseEntry> = read_test_data("leafhash_256.json");

        for data in database {
            let x = GenericArray::from_slice(&data.x);
            let uhash = GenericArray::from_slice(&data.uhash);

            let h = LeafHasher256::hash(uhash, x);

            assert_eq!(h.as_slice(), &data.expected_h)
        }
    }
}
