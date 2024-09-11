use std::array;

use generic_array::{
    typenum::{Prod, Quot, Sum, Unsigned, U16, U3, U5, U8},
    ArrayLength, GenericArray,
};

use crate::fields::{BigGaloisField, Field, GF128, GF192, GF256, GF64};

type BBits = U16;
// Additional bytes returned by VOLE hash
pub type B = Quot<BBits, U8>;

/// Interface to instantiate a VOLE hasher
pub trait VoleHasherInit<F>
where
    F: BigGaloisField,
{
    type SDLength: ArrayLength;
    type OutputLength: ArrayLength;
    type Hasher: VoleHasherProcess<F, Self::OutputLength>;

    fn new_vole_hasher(sd: &GenericArray<u8, Self::SDLength>) -> Self::Hasher;
}

/// Process the input to VOLE hash and produce the hash
pub trait VoleHasherProcess<F, OutputLength>
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
}

/// The VOLE hasher
#[derive(Debug, Clone)]
pub struct VoleHasher<F>
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
    type Hasher = VoleHasher<GF128>;

    fn new_vole_hasher(sd: &GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        let r = array::from_fn(|i| {
            GF128::from(
                &sd[i * <GF128 as Field>::Length::USIZE..(i + 1) * <GF128 as Field>::Length::USIZE],
            )
        });
        let s = GF128::from(
            &sd[4 * <GF128 as Field>::Length::USIZE..5 * <GF128 as Field>::Length::USIZE],
        );
        let t = GF64::from(
            &sd[5 * <GF128 as Field>::Length::USIZE
                ..5 * <GF128 as Field>::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );

        Self { r, s, t }
    }
}

impl VoleHasherInit<GF192> for VoleHasher<GF192> {
    type SDLength = Sum<Prod<<GF192 as Field>::Length, U5>, <GF64 as Field>::Length>;
    type OutputLength = Sum<<GF192 as Field>::Length, B>;
    type Hasher = VoleHasher<GF192>;

    fn new_vole_hasher(sd: &GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        let r = array::from_fn(|i| {
            GF192::from(
                &sd[i * <GF192 as Field>::Length::USIZE..(i + 1) * <GF192 as Field>::Length::USIZE],
            )
        });
        let s = GF192::from(
            &sd[4 * <GF192 as Field>::Length::USIZE..5 * <GF192 as Field>::Length::USIZE],
        );
        let t = GF64::from(
            &sd[5 * <GF192 as Field>::Length::USIZE
                ..5 * <GF192 as Field>::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );

        Self { r, s, t }
    }
}

impl VoleHasherInit<GF256> for VoleHasher<GF256> {
    type SDLength = Sum<Prod<<GF256 as Field>::Length, U5>, <GF64 as Field>::Length>;
    type OutputLength = Sum<<GF256 as Field>::Length, B>;
    type Hasher = VoleHasher<GF256>;

    fn new_vole_hasher(sd: &GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        let r = array::from_fn(|i| {
            GF256::from(
                &sd[i * <GF256 as Field>::Length::USIZE..(i + 1) * <GF256 as Field>::Length::USIZE],
            )
        });
        let s = GF256::from(
            &sd[4 * <GF256 as Field>::Length::USIZE..5 * <GF256 as Field>::Length::USIZE],
        );
        let t = GF64::from(
            &sd[5 * <GF256 as Field>::Length::USIZE
                ..5 * <GF256 as Field>::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );

        Self { r, s, t }
    }
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
        iter.for_each(|data| self.process_block(&mut h0, &mut h1, data));
        if !remainder.is_empty() {
            self.process_unpadded_block(&mut h0, &mut h1, remainder);
        }

        let h2 = self.r[0] * h0 + self.r[1] * h1;
        let h3 = self.r[2] * h0 + self.r[3] * h1;

        let mut ret = GenericArray::default();
        ret[..<F as Field>::Length::USIZE].copy_from_slice(&h2.as_bytes());
        ret[<F as Field>::Length::USIZE..<F as Field>::Length::USIZE + B::USIZE]
            .copy_from_slice(&h3.as_bytes()[0..B::USIZE]);
        ret.iter_mut()
            .zip(x1.iter())
            .for_each(|(x1, x2)| *x1 ^= *x2);
        ret
    }
}

impl<F> VoleHasher<F>
where
    F: BigGaloisField,
{
    fn process_block(&self, h0: &mut F, h1: &mut GF64, data: &[u8]) {
        *h0 = *h0 * self.s + F::from(data);
        data.chunks_exact(<GF64 as Field>::Length::USIZE)
            .for_each(|data| {
                *h1 = *h1 * self.t + GF64::from(data);
            });
    }

    fn process_unpadded_block(&self, h0: &mut F, h1: &mut GF64, data: &[u8]) {
        let mut buf = GenericArray::<u8, F::Length>::default();
        buf[..data.len()].copy_from_slice(data);
        self.process_block(h0, h1, &buf);
    }
}

/// Interface for Init-Update-Finalize-style implementations of ZK-Hash covering the Init part
pub trait ZKHasherInit<F>
where
    F: BigGaloisField,
{
    type SDLength: ArrayLength;
    type Hasher: ZKHasherProcess<F>;

    fn new_zk_hasher(sd: &GenericArray<u8, Self::SDLength>) -> Self::Hasher;
}

/// Interface for Init-Update-Finalize-style implementations of ZK-Hash covering the Update and Finalize part
pub trait ZKHasherProcess<F>
where
    Self: Clone,
    F: BigGaloisField,
{
    fn update(&mut self, v: &F);

    fn finalize(self, x1: &F) -> F;
}

#[derive(Debug, Clone)]
pub struct ZKHasher<F>
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
    type Hasher = Self;

    fn new_zk_hasher(sd: &GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        let s = GF128::from(
            &sd[2 * <GF128 as Field>::Length::USIZE..3 * <GF128 as Field>::Length::USIZE],
        );
        let t = GF64::from(
            &sd[3 * <GF128 as Field>::Length::USIZE
                ..3 * <GF128 as Field>::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );
        let r0 = GF128::from(&sd[..<GF128 as Field>::Length::USIZE]);
        let r1 =
            GF128::from(&sd[<GF128 as Field>::Length::USIZE..2 * <GF128 as Field>::Length::USIZE]);

        ZKHasher {
            h0: GF128::ZERO,
            h1: GF128::ZERO,
            s,
            t,
            r0,
            r1,
        }
    }
}

impl ZKHasherInit<GF192> for ZKHasher<GF192> {
    type SDLength = Sum<Prod<<GF192 as Field>::Length, U3>, <GF64 as Field>::Length>;
    type Hasher = Self;

    fn new_zk_hasher(sd: &GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        let s = GF192::from(
            &sd[2 * <GF192 as Field>::Length::USIZE..3 * <GF192 as Field>::Length::USIZE],
        );
        let t = GF64::from(
            &sd[3 * <GF192 as Field>::Length::USIZE
                ..3 * <GF192 as Field>::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );
        let r0 = GF192::from(&sd[..<GF192 as Field>::Length::USIZE]);
        let r1 =
            GF192::from(&sd[<GF192 as Field>::Length::USIZE..2 * <GF192 as Field>::Length::USIZE]);

        ZKHasher {
            h0: GF192::ZERO,
            h1: GF192::ZERO,
            s,
            t,
            r0,
            r1,
        }
    }
}

impl ZKHasherInit<GF256> for ZKHasher<GF256> {
    type SDLength = Sum<Prod<<GF256 as Field>::Length, U3>, <GF64 as Field>::Length>;
    type Hasher = Self;

    fn new_zk_hasher(sd: &GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        let s = GF256::from(
            &sd[2 * <GF256 as Field>::Length::USIZE..3 * <GF256 as Field>::Length::USIZE],
        );
        let t = GF64::from(
            &sd[3 * <GF256 as Field>::Length::USIZE
                ..3 * <GF256 as Field>::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );
        let r0 = GF256::from(&sd[..<GF256 as Field>::Length::USIZE]);
        let r1 =
            GF256::from(&sd[<GF256 as Field>::Length::USIZE..2 * <GF256 as Field>::Length::USIZE]);

        ZKHasher {
            h0: GF256::ZERO,
            h1: GF256::ZERO,
            s,
            t,
            r0,
            r1,
        }
    }
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

#[cfg(test)]
mod test {
    use super::*;

    use generic_array::GenericArray;
    use serde::{de::DeserializeOwned, Deserialize};

    use crate::fields::{GF128, GF192, GF256};

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

    #[test]
    fn test_volehash_128() {
        let database: Vec<VoleHashDatabaseEntry> =
            serde_json::from_str(include_str!("../tests/data/volehash_128.json")).unwrap();

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
        let database: Vec<VoleHashDatabaseEntry> =
            serde_json::from_str(include_str!("../tests/data/volehash_192.json")).unwrap();

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
        let database: Vec<VoleHashDatabaseEntry> =
            serde_json::from_str(include_str!("../tests/data/volehash_256.json")).unwrap();

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
        let database: Vec<ZKHashDatabaseEntry<GF128>> =
            serde_json::from_str(include_str!("../tests/data/zkhash_128.json")).unwrap();

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
        let database: Vec<ZKHashDatabaseEntry<GF192>> =
            serde_json::from_str(include_str!("../tests/data/zkhash_192.json")).unwrap();

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
        let database: Vec<ZKHashDatabaseEntry<GF256>> =
            serde_json::from_str(include_str!("../tests/data/zkhash_256.json")).unwrap();

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
}
