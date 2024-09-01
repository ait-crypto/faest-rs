use generic_array::{
    sequence::GenericSequence,
    typenum::Unsigned,
    typenum::{Prod, Sum, U3},
    ArrayLength, GenericArray,
};

use crate::{
    fields::{BigGaloisField, Field, GF128, GF192, GF256, GF64},
    parameter::PARAMOWF,
};

#[allow(dead_code)]
pub fn volehash<T, O>(
    sd: &GenericArray<u8, O::CHALL1>,
    x0: &GenericArray<u8, O::LAMBDALBYTES>,
    x1: &GenericArray<u8, O::LAMBDAPLUS2>,
) -> GenericArray<u8, O::LAMBDAPLUS2>
where
    T: BigGaloisField + std::fmt::Debug,
    O: PARAMOWF,
{
    let l = <O::L as Unsigned>::to_usize() / 8;
    let lambda = (T::LENGTH as usize) / 8;
    let l_p: usize = lambda * 8 * (l + lambda * 8).div_ceil(lambda * 8);
    let mut r: [T; 4] = [T::new(0u128, 0u128); 4];
    for i in 0..4 {
        r[i] = T::to_field(&sd[i * lambda..(i + 1) * lambda])[0];
    }

    let s = T::to_field(&sd[4 * lambda..5 * lambda])[0];

    let t = &GF64::to_field(&sd[5 * lambda..(5 * lambda) + 8])[0];

    let x0: GenericArray<u8, O::LPRIMEBYTE> =
        GenericArray::generate(|i: usize| if i < lambda + l { x0[i] } else { 0u8 });

    //use resize to get rid of the vec
    let y_h = T::to_field(&x0.clone());

    let y_b = GF64::to_field(&x0);

    let mut h0 = T::new(0u128, 0u128);
    let mut s_add = T::ONE;
    for i in 0..l_p / (lambda * 8) {
        h0 += s_add * y_h[(l_p / (lambda * 8)) - 1 - i];
        s_add *= s;
    }
    let mut h1 = GF64::default();
    let mut t_add = GF64::ONE;
    for i in 0..(l_p / 64) {
        h1 += t_add * y_b[(l_p / 64) - 1 - i];
        t_add *= *t;
    }

    let (h2, h3) = ((r[0] * h0) + (r[1] * h1), ((r[2] * h0) + (r[3] * h1)));
    let mut h = h2.get_value().0.to_le_bytes().to_vec();
    h.append(&mut h2.get_value().1.to_le_bytes()[..(lambda) - 16].to_vec());
    //taking the B first bytes of h3
    h.append(&mut h3.get_value().0.to_le_bytes()[..2].to_vec());
    h.iter_mut().zip(x1.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    (*GenericArray::from_slice(&h)).clone()
}

/// Interface for Init-Update-Finalize-style implementations of ZK-Hash covering the Init part
pub trait ZKHasherInit<'a, F>
where
    F: BigGaloisField,
{
    type SDLength: ArrayLength;
    type Hasher: ZKHasherProcess<F>;

    fn new_zk_hasher(sd: &'a GenericArray<u8, Self::SDLength>) -> Self::Hasher;
}

/// Interface for Init-Update-Finalize-style implementations of ZK-Hash covering the Update and Finalize part
pub trait ZKHasherProcess<F>
where
    F: BigGaloisField,
{
    fn update(&mut self, v: &F);

    fn finalize(self, x1: &F) -> F;
}

pub struct ZKHasher<'a, F>
where
    F: BigGaloisField,
{
    h0: F,
    h1: F,
    s: F,
    t: GF64,
    sd: &'a [u8],
}

impl<'a> ZKHasherInit<'a, Self> for GF128 {
    type SDLength = Sum<Prod<<Self as Field>::Length, U3>, <GF64 as Field>::Length>;
    type Hasher = ZKHasher<'a, Self>;

    fn new_zk_hasher(sd: &'a GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        let s =
            Self::from(&sd[2 * <Self as Field>::Length::USIZE..3 * <Self as Field>::Length::USIZE]);
        let t = GF64::from(
            &sd[3 * <Self as Field>::Length::USIZE
                ..3 * <Self as Field>::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );

        ZKHasher {
            h0: Self::ZERO,
            h1: Self::ZERO,
            sd: sd.as_slice(),
            s,
            t,
        }
    }
}

impl<'a> ZKHasherInit<'a, Self> for GF192 {
    type SDLength = Sum<Prod<<Self as Field>::Length, U3>, <GF64 as Field>::Length>;
    type Hasher = ZKHasher<'a, Self>;

    fn new_zk_hasher(sd: &'a GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        let s =
            Self::from(&sd[2 * <Self as Field>::Length::USIZE..3 * <Self as Field>::Length::USIZE]);
        let t = GF64::from(
            &sd[3 * <Self as Field>::Length::USIZE
                ..3 * <Self as Field>::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );

        ZKHasher {
            h0: Self::ZERO,
            h1: Self::ZERO,
            sd: sd.as_slice(),
            s,
            t,
        }
    }
}

impl<'a, F> ZKHasherInit<'a, F> for ZKHasher<'a, F>
where
    F: BigGaloisField + ZKHasherInit<'a, F>,
{
    type SDLength = <F as ZKHasherInit<'a, F>>::SDLength;
    type Hasher = <F as ZKHasherInit<'a, F>>::Hasher;

    fn new_zk_hasher(sd: &'a GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        <F as ZKHasherInit<'a, F>>::new_zk_hasher(sd)
    }
}

impl<'a, F> ZKHasherProcess<F> for ZKHasher<'a, F>
where
    F: BigGaloisField,
{
    fn update(&mut self, v: &F) {
        self.h0 = (self.h0 * self.s) + v;
        self.h1 = (self.h1 * self.t) + v;
    }

    fn finalize(self, x1: &F) -> F {
        let r0 = F::from(&self.sd[..F::Length::USIZE]);
        let r1 = F::from(&self.sd[F::Length::USIZE..2 * F::Length::USIZE]);

        (r0 * self.h0) + (r1 * self.h1) + x1
    }
}

impl<'a> ZKHasherInit<'a, Self> for GF256 {
    type SDLength = Sum<Prod<<Self as Field>::Length, U3>, <GF64 as Field>::Length>;
    type Hasher = ZKHasher<'a, Self>;

    fn new_zk_hasher(sd: &'a GenericArray<u8, Self::SDLength>) -> Self::Hasher {
        let s =
            Self::from(&sd[2 * <Self as Field>::Length::USIZE..3 * <Self as Field>::Length::USIZE]);
        let t = GF64::from(
            &sd[3 * <Self as Field>::Length::USIZE
                ..3 * <Self as Field>::Length::USIZE + <GF64 as Field>::Length::USIZE],
        );

        ZKHasher {
            h0: Self::ZERO,
            h1: Self::ZERO,
            sd: sd.as_slice(),
            s,
            t,
        }
    }
}

#[allow(dead_code)]
pub fn zkhash<'a, F>(
    sd: &'a GenericArray<u8, <F as ZKHasherInit<'a, F>>::SDLength>,
    x0: &[F],
    x1: &F,
) -> GenericArray<u8, F::Length>
where
    F: BigGaloisField + ZKHasherInit<'a, F>,
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
            let x0 = GenericArray::from_slice(&data.x0);
            let x1 = GenericArray::from_slice(&data.x1);
            let h = *GenericArray::from_slice(&data.h);
            let res = volehash::<GF128, PARAMOWF128>(sd, x0, x1);
            assert_eq!(h, res);
        }
    }

    #[test]
    fn test_volehash_192() {
        let database: Vec<VoleHashDatabaseEntry> =
            serde_json::from_str(include_str!("../tests/data/volehash_192.json")).unwrap();

        for data in database {
            let sd = GenericArray::from_slice(&data.sd);
            let x0 = GenericArray::from_slice(&data.x0);
            let x1 = GenericArray::from_slice(&data.x1);
            let h = *GenericArray::from_slice(&data.h);
            let res = volehash::<GF192, PARAMOWF192>(sd, x0, x1);
            assert_eq!(h, res);
        }
    }

    #[test]
    fn test_volehash_256() {
        let database: Vec<VoleHashDatabaseEntry> =
            serde_json::from_str(include_str!("../tests/data/volehash_256.json")).unwrap();

        for data in database {
            let sd = GenericArray::from_slice(&data.sd);
            let x0 = GenericArray::from_slice(&data.x0);
            let x1 = GenericArray::from_slice(&data.x1);
            let h = *GenericArray::from_slice(&data.h);
            let res = volehash::<GF256, PARAMOWF256>(sd, x0, x1);
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
