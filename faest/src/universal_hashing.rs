use std::array;

use generic_array::{
    typenum::{Prod, Quot, Sum, Unsigned, U16, U3, U8},
    ArrayLength, GenericArray,
};

use crate::{
    fields::{BigGaloisField, Field, GF128, GF192, GF256, GF64},
    parameter::PARAMOWF,
};

type BBits = U16;
// Additional bytes returned by VOLE hash
pub type B = Quot<BBits, U8>;

/*
struct VoleHasher<F>
where
    F: BigGaloisField,
{
    h0: F,
    h1: GF64,
    r: [F; 4],
    s: F,
    t: GF64,
}

impl<F, L> VoleHasher<F>
where
    F: BigGaloisField,
    L: ArrayLength,
    F::Length: std::ops::Add<B, Output = L>,
{
    fn new(sd: &[u8]) -> Self {
        assert_eq!(
            sd.len(),
            F::Length::USIZE * 5 + <GF64 as Field>::Length::USIZE
        );

        let r = array::from_fn(|i| F::from(&sd[i * F::Length::USIZE..(i + 1) * F::Length::USIZE]));
        let s = F::from(&sd[4 * F::Length::USIZE..5 * F::Length::USIZE]);
        let t = GF64::from(
            &sd[5 * F::Length::USIZE..5 * F::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );

        Self {
            h0: F::ZERO,
            h1: GF64::ZERO,
            r,
            s,
            t,
        }
    }

    fn process_block(&mut self, data: &[u8]) {
        self.h0 = self.h0 * self.s + F::from(data);
        data.chunks_exact(<GF64 as Field>::Length::USIZE)
            .for_each(|data| {
                self.h1 = self.h1 * self.t + GF64::from(data);
            });
    }

    fn process_unpadded_block(&mut self, data: &[u8]) {
        let mut buf = GenericArray::<u8, F::Length>::default();
        buf[..data.len()].copy_from_slice(data);
        self.process_block(&buf);
    }

    fn finalize(mut self, x0: &[u8], x1: &[u8]) -> GenericArray<u8, L> {
        let iter = x0.chunks_exact(F::Length::USIZE);
        let remainder = iter.remainder();
        iter.for_each(|data| self.process_block(data));
        if !remainder.is_empty() {
            self.process_unpadded_block(remainder);
        }

        assert_eq!(x1.len(), L::USIZE);

        let h2 = self.r[0] * self.h0 + self.r[1] * self.h1;
        let h3 = self.r[2] * self.h0 + self.r[3] * self.h1;

        let mut ret = GenericArray::default();
        ret[..F::Length::USIZE].copy_from_slice(&h2.as_bytes());
        ret[F::Length::USIZE..].copy_from_slice(&h3.as_bytes()[0..B::USIZE]);
        ret.iter_mut()
            .zip(x1.iter())
            .for_each(|(x1, x2)| *x1 ^= *x2);
        ret
    }
}
*/

fn process_block<T: BigGaloisField>(
    mut h0: T,
    mut h1: GF64,
    data: &[u8],
    s: &T,
    t: GF64,
) -> (T, GF64) {
    h0 = h0 * s + T::from(data);
    data.chunks_exact(<GF64 as Field>::Length::USIZE)
        .for_each(|data| {
            h1 = h1 * t + GF64::from(data);
        });
    (h0, h1)
}

fn process_unpadded_block<T: BigGaloisField>(
    h0: T,
    h1: GF64,
    data: &[u8],
    s: &T,
    t: GF64,
) -> (T, GF64) {
    let mut buf = GenericArray::<u8, T::Length>::default();
    buf[..data.len()].copy_from_slice(data);
    process_block(h0, h1, &buf, s, t)
}

pub fn volehash<O>(
    sd: &GenericArray<u8, O::CHALL1>,
    x0: &[u8],
    x1: &[u8],
) -> GenericArray<u8, O::LAMBDAPLUS2>
where
    O: PARAMOWF,
{
    let r: [_; 4] = array::from_fn(|i| {
        O::Field::from(
            &sd[i * <O::Field as Field>::Length::USIZE
                ..(i + 1) * <O::Field as Field>::Length::USIZE],
        )
    });
    let s = O::Field::from(
        &sd[4 * <O::Field as Field>::Length::USIZE..5 * <O::Field as Field>::Length::USIZE],
    );
    let t = GF64::from(
        &sd[5 * <O::Field as Field>::Length::USIZE
            ..5 * <O::Field as Field>::Length::USIZE + <GF64 as Field>::Length::USIZE],
    );

    let mut h0 = O::Field::ZERO;
    let mut h1 = GF64::ZERO;

    let iter = x0.chunks_exact(<O::Field as Field>::Length::USIZE);
    let remainder = iter.remainder();
    iter.for_each(|data| (h0, h1) = process_block(h0, h1, data, &s, t));
    if !remainder.is_empty() {
        (h0, h1) = process_unpadded_block(h0, h1, remainder, &s, t);
    }

    let h2 = r[0] * h0 + r[1] * h1;
    let h3 = r[2] * h0 + r[3] * h1;

    let mut ret = GenericArray::default();
    ret[..<O::Field as Field>::Length::USIZE].copy_from_slice(&h2.as_bytes());
    ret[<O::Field as Field>::Length::USIZE..].copy_from_slice(&h3.as_bytes()[0..B::USIZE]);
    ret.iter_mut()
        .zip(x1.iter())
        .for_each(|(x1, x2)| *x1 ^= *x2);
    ret
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
    F: BigGaloisField,
{
    fn update(&mut self, v: &F);

    fn finalize(self, x1: &F) -> F;
}

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

impl ZKHasherInit<Self> for GF128 {
    type SDLength = Sum<Prod<<Self as Field>::Length, U3>, <GF64 as Field>::Length>;
    type Hasher = ZKHasher<Self>;

    fn new_zk_hasher(sd: &GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        let s =
            Self::from(&sd[2 * <Self as Field>::Length::USIZE..3 * <Self as Field>::Length::USIZE]);
        let t = GF64::from(
            &sd[3 * <Self as Field>::Length::USIZE
                ..3 * <Self as Field>::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );
        let r0 = Self::from(&sd[..<Self as Field>::Length::USIZE]);
        let r1 =
            Self::from(&sd[<Self as Field>::Length::USIZE..2 * <Self as Field>::Length::USIZE]);

        ZKHasher {
            h0: Self::ZERO,
            h1: Self::ZERO,
            s,
            t,
            r0,
            r1,
        }
    }
}

impl ZKHasherInit<Self> for GF192 {
    type SDLength = Sum<Prod<<Self as Field>::Length, U3>, <GF64 as Field>::Length>;
    type Hasher = ZKHasher<Self>;

    fn new_zk_hasher(sd: &GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        let s =
            Self::from(&sd[2 * <Self as Field>::Length::USIZE..3 * <Self as Field>::Length::USIZE]);
        let t = GF64::from(
            &sd[3 * <Self as Field>::Length::USIZE
                ..3 * <Self as Field>::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );
        let r0 = Self::from(&sd[..<Self as Field>::Length::USIZE]);
        let r1 =
            Self::from(&sd[<Self as Field>::Length::USIZE..2 * <Self as Field>::Length::USIZE]);

        ZKHasher {
            h0: Self::ZERO,
            h1: Self::ZERO,
            s,
            t,
            r0,
            r1,
        }
    }
}

impl ZKHasherInit<Self> for GF256 {
    type SDLength = Sum<Prod<<Self as Field>::Length, U3>, <GF64 as Field>::Length>;
    type Hasher = ZKHasher<Self>;

    fn new_zk_hasher(sd: &GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        let s =
            Self::from(&sd[2 * <Self as Field>::Length::USIZE..3 * <Self as Field>::Length::USIZE]);
        let t = GF64::from(
            &sd[3 * <Self as Field>::Length::USIZE
                ..3 * <Self as Field>::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );
        let r0 = Self::from(&sd[..<Self as Field>::Length::USIZE]);
        let r1 =
            Self::from(&sd[<Self as Field>::Length::USIZE..2 * <Self as Field>::Length::USIZE]);

        ZKHasher {
            h0: Self::ZERO,
            h1: Self::ZERO,
            s,
            t,
            r0,
            r1,
        }
    }
}

impl<F> ZKHasherInit<F> for ZKHasher<F>
where
    F: BigGaloisField + ZKHasherInit<F>,
{
    type SDLength = <F as ZKHasherInit<F>>::SDLength;
    type Hasher = <F as ZKHasherInit<F>>::Hasher;

    fn new_zk_hasher(sd: &GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        <F as ZKHasherInit<F>>::new_zk_hasher(sd)
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

#[allow(dead_code)]
pub fn zkhash<F>(
    sd: &GenericArray<u8, <F as ZKHasherInit<F>>::SDLength>,
    x0: &[F],
    x1: &F,
) -> GenericArray<u8, F::Length>
where
    F: BigGaloisField + ZKHasherInit<F>,
{
    let mut hasher = F::new_zk_hasher(sd);
    for x in x0 {
        hasher.update(x);
    }
    hasher.finalize(x1).as_bytes()
}

#[cfg(test)]
mod test {
    use super::*;

    use generic_array::GenericArray;
    use serde::{de::DeserializeOwned, Deserialize};

    use crate::fields::{GF128, GF192, GF256};
    use crate::parameter::{PARAMOWF128, PARAMOWF192, PARAMOWF256};

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
        x0: Vec<u8>,
        x1: Vec<u8>,
        h: Vec<u8>,
    }

    #[test]
    fn test_volehash_128() {
        let database: Vec<VoleHashDatabaseEntry> =
            serde_json::from_str(include_str!("../tests/data/volehash_128.json")).unwrap();

        for data in database {
            let sd = GenericArray::from_slice(&data.sd);
            let h = *GenericArray::from_slice(&data.h);
            let res = volehash::<PARAMOWF128>(sd, &data.x0, &data.x1);
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
            let res = volehash::<PARAMOWF192>(sd, &data.x0, &data.x1);
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
            let res = volehash::<PARAMOWF256>(sd, &data.x0, &data.x1);
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

            let res = zkhash(sd, &data.x0, &data.x1);
            assert_eq!(data.h.as_slice(), res.as_slice());
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

            let res = zkhash(sd, &data.x0, &data.x1);
            assert_eq!(data.h.as_slice(), res.as_slice());
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

            let res = zkhash(sd, &data.x0, &data.x1);
            assert_eq!(data.h.as_slice(), res.as_slice());
        }
    }
}
