use generic_array::{typenum::Unsigned, GenericArray};

use crate::fields::BigGaloisField;
use crate::random_oracles::{Hasher, PseudoRandomGenerator, RandomOracle, Reader, IV};

#[allow(clippy::type_complexity)]
pub fn commit<T, R>(
    r: T, // why is this T?
    iv: &IV,
    n: usize,
) -> (
    GenericArray<u8, R::PRODLAMBDA2>,
    (
        Vec<GenericArray<u8, R::LAMBDA>>,
        Vec<GenericArray<u8, R::PRODLAMBDA2>>,
    ),
    Vec<Option<GenericArray<u8, R::LAMBDA>>>,
)
where
    T: BigGaloisField<Length = R::LAMBDA>,
    R: RandomOracle,
{
    let mut k: Vec<GenericArray<u8, R::LAMBDA>> = vec![GenericArray::default(); 2 * n - 1];
    //step 2..3
    k[0] = r.as_bytes();

    for i in 0..n - 1 {
        let mut prg = R::PRG::new_prg(&k[i], iv);
        prg.read(&mut k[2 * i + 1]);
        prg.read(&mut k[2 * i + 2]);
    }
    //step 4..5
    let mut h1_hasher = R::h1_init();
    let mut sd = vec![None; n];
    let mut com = vec![GenericArray::default(); n];
    for j in 0..n {
        let mut h0_hasher = R::h0_init();
        h0_hasher.update(&k[n - 1 + j]);
        h0_hasher.update(iv);
        let mut reader = h0_hasher.finish();
        let mut sd_j = GenericArray::default();
        reader.read(&mut sd_j);
        sd[j] = Some(sd_j);
        reader.read(&mut com[j]);
        h1_hasher.update(&com[j]);
    }
    //step 6
    let mut h = GenericArray::default();
    let mut reader = h1_hasher.finish();
    reader.read(&mut h);
    (h, (k, com), sd)
}

pub fn open<R, DPOW /*2N - 1 */, D, N>(
    decom: &(
        Vec<GenericArray<u8, R::LAMBDA>>,
        Vec<GenericArray<u8, R::PRODLAMBDA2>>,
    ),
    b: GenericArray<u8, D>,
) -> (Vec<GenericArray<u8, R::LAMBDA>>, Vec<u8>)
where
    R: RandomOracle,
    D: generic_array::ArrayLength,
{
    let mut a = 0;
    let d = (usize::BITS - decom.0.len().leading_zeros() - 1) as usize;
    let mut cop = Vec::with_capacity(d);
    //step 4

    for i in 0..d {
        cop.push(decom.0[(1 << (i + 1)) + 2 * a + (1 - b[d - i - 1] as usize) - 1].clone());
        a = 2 * a + b[d - i - 1] as usize;
    }
    (cop, decom.1[a].to_vec())
}

#[allow(clippy::type_complexity)]
pub fn reconstruct<T, R>(
    pdecom: &(
        Vec<GenericArray<u8, R::LAMBDA>>,
        GenericArray<u8, R::PRODLAMBDA2>,
    ),
    b: &[u8],
    iv: &IV,
) -> (
    GenericArray<u8, R::PRODLAMBDA2>,
    Vec<GenericArray<u8, R::LAMBDA>>,
)
where
    R: RandomOracle,
    T: BigGaloisField,
{
    let length = R::LAMBDA::USIZE;
    let mut a = 0;
    let d = b.len() as u32;
    let mut k: Vec<Option<GenericArray<u8, R::LAMBDA>>> =
        vec![Some(GenericArray::default()); (1 << (d + 1)) - 1];
    k[0] = None;

    //step 4
    for i in 1..d + 1 {
        let b_d_i = b[(d - i) as usize] as u16;
        k[((1_u16 << (i)) - 1 + (2 * a) + (1_u16 - b_d_i)) as usize] =
            Some(pdecom.0[(i - 1) as usize].clone());
        k[((1_u16 << (i)) - 1 + (2 * a) + b_d_i) as usize] = None;
        //step 7
        for j in 0..1 << (i - 1) {
            if j != a {
                let rank = (1 << (i - 1)) - 1 + j;
                let new_ks = R::prg::<R::PRODLAMBDA2>(k[rank as usize].as_ref().unwrap(), iv);
                (k[(rank * 2 + 1) as usize], k[(rank * 2 + 2) as usize]) = (
                    Some((*GenericArray::from_slice(&new_ks[..length])).clone()),
                    Some((*GenericArray::from_slice(&new_ks[length..])).clone()),
                );
            }
        }
        a = 2 * a + b_d_i;
    }
    let mut sd: Vec<GenericArray<u8, R::LAMBDA>> = vec![GenericArray::default(); 1 << d];
    let mut com: Vec<GenericArray<u8, R::PRODLAMBDA2>> = vec![GenericArray::default(); 1 << d];
    let mut pre_h = Vec::new();
    //step 11
    for j in 0..(1_u16 << d) {
        if j != a {
            let seed: GenericArray<u8, <R as RandomOracle>::LAMBDA16> = (*GenericArray::from_slice(
                &[
                    k[(1 << d) - 1 + j as usize].clone().unwrap().to_vec(),
                    iv.to_vec(),
                ]
                .concat(),
            ))
            .clone();
            let mut hash: GenericArray<u8, R::PRODLAMBDA3> = GenericArray::default();
            R::h0(seed, &mut hash);
            sd[j as usize] = (*GenericArray::from_slice(&hash[..length])).clone();
            com[j as usize] = (*GenericArray::from_slice(&hash[length..])).clone();
            pre_h.append(&mut com[j as usize].to_vec());
        } else {
            pre_h.append(&mut pdecom.1.to_vec());
        }
    }
    let mut h: GenericArray<u8, R::PRODLAMBDA2> = GenericArray::default();
    R::h1(&pre_h, &mut h);
    (h, sd)
}

#[allow(clippy::type_complexity)]
pub fn verify<T, R, D, POWD, N>(
    com: GenericArray<u8, R::PRODLAMBDA2>,
    pdecom: (
        Vec<GenericArray<u8, R::LAMBDA>>,
        GenericArray<u8, R::PRODLAMBDA2>,
    ),
    b: GenericArray<u8, D>,
    iv: &IV,
) -> u8
where
    R: RandomOracle,
    D: generic_array::ArrayLength,
    T: BigGaloisField,
{
    let (com_b, _sd) = reconstruct::<T, R>(&pdecom, &b, iv);
    if com_b == com {
        1
    } else {
        0
    }
}

//reconstruct is tested in the integration_test_vc test_commitment_and_decomitment() function.

#[cfg(test)]
mod test {
    use super::*;

    use generic_array::{
        sequence::GenericSequence,
        typenum::{U16, U31, U32, U4, U5, U63},
        GenericArray,
    };
    use serde::Deserialize;

    use crate::{
        fields::{GF128, GF192, GF256},
        random_oracles::{RandomOracleShake128, RandomOracleShake192, RandomOracleShake256},
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataCommit {
        keyroot: Vec<u8>,
        iv: u128, // FIXME: use IV
        depth: u8,
        h: Vec<u8>,
        k: Vec<Vec<u8>>,
        com: Vec<Vec<u8>>,
        sd: Vec<Vec<u8>>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataOpen {
        k: Vec<Vec<u8>>,
        b: Vec<u8>,
        com: Vec<Vec<u8>>,
        cop: Vec<Vec<u8>>,
        com_j: Vec<u8>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataReconstruct {
        cop: Vec<Vec<u8>>,
        com_j: Vec<u8>,
        b: Vec<u8>,
        iv: [u8; 16],
        h: Vec<u8>,
        sd: Vec<Vec<u8>>,
    }

    #[test]
    fn commit_test() {
        let database: Vec<DataCommit> = serde_json::from_str(include_str!("../DataVc.json"))
            .expect("error while reading or parsing");
        for mut data in database {
            let lamdabytes = data.keyroot.len();
            if lamdabytes == 16 {
                let res = commit::<GF128, RandomOracleShake128>(
                    GF128::from(&data.keyroot[..]),
                    &data.iv.to_be_bytes(),
                    1 << data.depth,
                );
                let mut sd = Vec::new();
                for val in data.sd {
                    sd.push(Some(val));
                }
                assert_eq!(res.0, *GenericArray::from_slice(&data.h));
                assert_eq!(
                    res.1 .0,
                    data.k
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec::<GenericArray<u8, _>>>()
                );
                assert_eq!(
                    res.1 .1,
                    data.com
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec::<GenericArray<u8, _>>>()
                );
                assert_eq!(
                    res.2,
                    sd.iter()
                        .map(|x| x.as_ref().map(|y| *GenericArray::from_slice(y)))
                        .collect::<Vec::<Option::<GenericArray<u8, _>>>>()
                );
            } else if lamdabytes == 24 {
                let res = commit::<GF192, RandomOracleShake192>(
                    GF192::from(&data.keyroot[..]),
                    &data.iv.to_be_bytes(),
                    1 << data.depth,
                );
                let mut sd = Vec::new();
                for val in data.sd {
                    sd.push(Some(val));
                }
                assert_eq!(res.0, *GenericArray::from_slice(&data.h));
                assert_eq!(
                    res.1 .0,
                    data.k
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec::<GenericArray<u8, _>>>()
                );
                assert_eq!(
                    res.1 .1,
                    data.com
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec::<GenericArray<u8, _>>>()
                );
                assert_eq!(
                    res.2,
                    sd.iter()
                        .map(|x| x.as_ref().map(|y| *GenericArray::from_slice(y)))
                        .collect::<Vec::<Option::<GenericArray<u8, _>>>>()
                );
            } else {
                let res = commit::<GF256, RandomOracleShake256>(
                    GF256::from(&data.keyroot[0..32]),
                    &data.iv.to_be_bytes(),
                    1 << data.depth,
                );
                let mut sd = Vec::new();
                for val in data.sd {
                    sd.push(Some(val));
                }
                assert_eq!(res.0, *GenericArray::from_slice(&data.h));
                assert_eq!(
                    res.1 .0,
                    data.k
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec::<GenericArray<u8, _>>>()
                );
                assert_eq!(
                    res.1 .1,
                    data.com
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec::<GenericArray<u8, _>>>()
                );
                assert_eq!(
                    res.2,
                    sd.iter()
                        .map(|x| x.as_ref().map(|y| *GenericArray::from_slice(y)))
                        .collect::<Vec::<Option::<GenericArray<u8, _>>>>()
                );
            }
        }
    }

    #[test]
    fn open_test() {
        let database: Vec<DataOpen> = serde_json::from_str(include_str!("../Dataopen.json"))
            .expect("error while reading or parsing");
        for data in database {
            if data.k[0].len() == 16 {
                type D = U4;
                type DPOW = U31;
                type N = U16;
                let res = open::<RandomOracleShake128, DPOW, D, N>(
                    &(
                        data.k
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                        data.com
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    *GenericArray::from_slice(&data.b),
                );
                assert_eq!(
                    res.0,
                    data.cop
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec::<GenericArray<u8, _>>>()
                );
                assert_eq!(res.1, data.com_j);
            } else if data.k[0].len() == 24 {
                type D = U4;
                type DPOW = U31;
                type N = U16;
                let res = open::<RandomOracleShake192, DPOW, D, N>(
                    &(
                        data.k
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                        data.com
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    *GenericArray::from_slice(&data.b),
                );
                assert_eq!(
                    res.0,
                    data.cop
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec::<GenericArray<u8, _>>>()
                );
                assert_eq!(res.1, data.com_j);
            } else if data.b.len() == 4 {
                type D = U4;
                type DPOW = U31;
                type N = U16;
                let res = open::<RandomOracleShake256, DPOW, D, N>(
                    &(
                        data.k
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                        data.com
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    *GenericArray::from_slice(&data.b),
                );
                assert_eq!(
                    res.0,
                    data.cop
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec::<GenericArray<u8, _>>>()
                );
                assert_eq!(res.1, data.com_j);
            } else {
                type D = U5;
                type DPOW = U63;
                type N = U32;
                let res = open::<RandomOracleShake256, DPOW, D, N>(
                    &(
                        data.k
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                        data.com
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    *GenericArray::from_slice(&data.b),
                );
                assert_eq!(
                    res.0,
                    data.cop
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec::<GenericArray<u8, _>>>()
                );
                assert_eq!(res.1, data.com_j);
            }
        }
    }

    #[test]
    fn reconstruct_test() {
        let database: Vec<DataReconstruct> =
            serde_json::from_str(include_str!("../DataReconstruct.json"))
                .expect("error while reading or parsing");
        for data in database {
            let lambdabyte = data.com_j.len();
            if lambdabyte == 32 {
                let res = reconstruct::<GF128, RandomOracleShake128>(
                    &(
                        data.cop
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect(),
                        *GenericArray::from_slice(&data.com_j),
                    ),
                    &data.b,
                    &data.iv,
                );
                assert_eq!(res.0.as_slice(), data.h.as_slice());
                for (r, x) in res.1.iter().zip(data.sd.iter()) {
                    if !x.is_empty() {
                        assert_eq!(r.as_slice(), x.as_slice());
                    } else {
                        assert_eq!(r, &GenericArray::default());
                    }
                }
            } else if lambdabyte == 48 {
                type D = U4;
                type POWD = U31;
                type N = U16;
                let res = reconstruct::<GF192, RandomOracleShake192>(
                    &(
                        data.cop
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect(),
                        *GenericArray::from_slice(&data.com_j),
                    ),
                    &data.b,
                    &data.iv,
                );
                assert_eq!(res.0.as_slice(), data.h.as_slice());
                for (r, x) in res.1.iter().zip(data.sd.iter()) {
                    if !x.is_empty() {
                        assert_eq!(r.as_slice(), x.as_slice());
                    } else {
                        assert_eq!(r, &GenericArray::default());
                    }
                }
            } else {
                type D = U5;
                type POWD = U63;
                type N = U32;
                let res = reconstruct::<GF256, RandomOracleShake256>(
                    &(
                        data.cop
                            .iter()
                            .map(|x| *GenericArray::from_slice(&x))
                            .collect(),
                        *GenericArray::from_slice(&data.com_j),
                    ),
                    &data.b,
                    &data.iv,
                );
                assert_eq!(res.0.as_slice(), data.h.as_slice());
                for (r, x) in res.1.iter().zip(data.sd.iter()) {
                    if !x.is_empty() {
                        assert_eq!(r.as_slice(), x.as_slice());
                    } else {
                        assert_eq!(r, &GenericArray::default());
                    }
                }
            }
        }
    }
}
