use std::{marker::PhantomData, ops::Add};

use generic_array::{
    typenum::{Sum, Unsigned},
    ArrayLength, GenericArray,
};

use crate::{
    prg::{PseudoRandomGenerator, IV},
    random_oracles::{Hasher, RandomOracle},
    utils::Reader,
};

type Decom<L, L2> = (Vec<GenericArray<u8, L>>, Vec<GenericArray<u8, L2>>);

pub(crate) trait VectorCommitment {
    type Lambda: ArrayLength;
    type LambdaTimes2: ArrayLength;
    type PRG: PseudoRandomGenerator<Lambda = Self::Lambda>;
    type RO: RandomOracle;

    fn commit(
        r: &GenericArray<u8, Self::Lambda>,
        iv: &IV,
        n: usize,
    ) -> (
        GenericArray<u8, Self::LambdaTimes2>,
        (
            Vec<GenericArray<u8, Self::Lambda>>,
            Vec<GenericArray<u8, Self::LambdaTimes2>>,
        ),
        Vec<GenericArray<u8, Self::Lambda>>,
    );

    fn open<DPOW /*2N - 1 */, D, N>(
        decom: &Decom<Self::Lambda, Self::LambdaTimes2>,
        b: &GenericArray<u8, D>,
    ) -> (Vec<GenericArray<u8, Self::Lambda>>, Vec<u8>)
    where
        D: ArrayLength;

    fn reconstruct(
        pdecom: &[u8],
        b: &[u8],
        iv: &IV,
    ) -> (
        GenericArray<u8, Self::LambdaTimes2>,
        Vec<GenericArray<u8, Self::Lambda>>,
    );
}

pub(crate) struct VC<PRG, R>(PhantomData<PRG>, PhantomData<R>)
where
    PRG: PseudoRandomGenerator,
    R: RandomOracle;

impl<PRG, R> VectorCommitment for VC<PRG, R>
where
    PRG: PseudoRandomGenerator,
    PRG::Lambda: Add<PRG::Lambda>,
    <PRG::Lambda as Add<PRG::Lambda>>::Output: ArrayLength,
    R: RandomOracle,
{
    type Lambda = PRG::Lambda;
    type LambdaTimes2 = Sum<PRG::Lambda, PRG::Lambda>;
    type PRG = PRG;
    type RO = R;

    fn commit(
        r: &GenericArray<u8, Self::Lambda>,
        iv: &IV,
        n: usize,
    ) -> (
        GenericArray<u8, Self::LambdaTimes2>,
        (
            Vec<GenericArray<u8, Self::Lambda>>,
            Vec<GenericArray<u8, Self::LambdaTimes2>>,
        ),
        Vec<GenericArray<u8, Self::Lambda>>,
    ) {
        let mut k = vec![GenericArray::default(); 2 * n - 1];
        //step 2..3
        k[0].copy_from_slice(r);

        for i in 0..n - 1 {
            let mut prg = PRG::new_prg(&k[i], iv);
            prg.read(&mut k[2 * i + 1]);
            prg.read(&mut k[2 * i + 2]);
        }
        //step 4..5
        let mut h1_hasher = R::h1_init();
        let mut sd = vec![GenericArray::default(); n];
        let mut com = vec![GenericArray::default(); n];
        for j in 0..n {
            let mut h0_hasher = R::h0_init();
            h0_hasher.update(&k[n - 1 + j]);
            h0_hasher.update(iv);
            let mut reader = h0_hasher.finish();
            reader.read(&mut sd[j]);
            reader.read(&mut com[j]);
            h1_hasher.update(&com[j]);
        }
        //step 6
        let mut h = GenericArray::default();
        let mut reader = h1_hasher.finish();
        reader.read(&mut h);
        (h, (k, com), sd)
    }

    fn open<DPOW /*2N - 1 */, D, N>(
        decom: &Decom<Self::Lambda, Self::LambdaTimes2>,
        b: &GenericArray<u8, D>,
    ) -> (Vec<GenericArray<u8, Self::Lambda>>, Vec<u8>)
    where
        D: ArrayLength,
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

    fn reconstruct(
        pdecom: &[u8],
        b: &[u8],
        iv: &IV,
    ) -> (
        GenericArray<u8, Self::LambdaTimes2>,
        Vec<GenericArray<u8, Self::Lambda>>,
    ) {
        let mut a = 0;
        let d = b.len();
        let def = GenericArray::default();
        let mut k = vec![def; (1 << (d + 1)) - 1];
        //step 4
        for i in 1..d + 1 {
            let b_d_i = b[d - i] as usize;
            k[(1 << (i)) - 1 + (2 * a) + (1 - b_d_i)]
                .copy_from_slice(&pdecom[(i - 1) * Self::Lambda::USIZE..i * Self::Lambda::USIZE]);
            //step 7
            for j in 0..1 << (i - 1) {
                if j != a {
                    let rank = (1 << (i - 1)) - 1 + j;
                    let mut prg = PRG::new_prg(&k[rank], iv);
                    prg.read(&mut k[rank * 2 + 1]);
                    prg.read(&mut k[rank * 2 + 2]);
                }
            }
            a = 2 * a + b_d_i;
        }
        let mut sd = vec![GenericArray::default(); 1 << d];
        let mut h1_hasher = R::h1_init();
        //step 11
        for j in 0..(1 << d) {
            if j != a {
                let mut h0_hasher = R::h0_init();
                h0_hasher.update(&k[(1 << d) - 1 + j]);
                h0_hasher.update(iv);
                let mut reader = h0_hasher.finish();
                reader.read(&mut sd[j]);
                let mut com_j = GenericArray::<u8, Self::LambdaTimes2>::default();
                reader.read(&mut com_j);
                h1_hasher.update(&com_j);
            } else {
                h1_hasher.update(&pdecom[pdecom.len() - 2 * Self::Lambda::USIZE..]);
            }
        }
        let mut h = GenericArray::default();
        h1_hasher.finish().read(&mut h);
        (h, sd)
    }
}

//reconstruct is tested in the integration_test_vc test_commitment_and_decomitment() function.

#[cfg(test)]
mod test {
    use std::iter::zip;

    use super::*;

    use generic_array::{
        typenum::{U16, U31, U32, U4, U5, U63},
        GenericArray,
    };
    use serde::Deserialize;

    use crate::{
        prg::{PRG128, PRG192, PRG256},
        random_oracles::{RandomOracleShake128, RandomOracleShake256},
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataCommit {
        keyroot: Vec<u8>,
        iv: IV,
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

    type Result<Lambda, Lambda2> = (
        GenericArray<u8, Lambda2>,
        (
            Vec<GenericArray<u8, Lambda>>,
            Vec<GenericArray<u8, Lambda2>>,
        ),
        Vec<GenericArray<u8, Lambda>>,
    );

    fn compare_expected_with_result<Lambda: ArrayLength, Lambda2: ArrayLength>(
        expected: &DataCommit,
        res: Result<Lambda, Lambda2>,
    ) {
        assert_eq!(res.0.as_slice(), expected.h.as_slice());
        for (k, k_expected) in zip(&res.1 .0, &expected.k) {
            assert_eq!(k.as_slice(), k_expected.as_slice());
        }
        for (com, com_expected) in zip(&res.1 .1, &expected.com) {
            assert_eq!(com.as_slice(), com_expected.as_slice());
        }
        for (sd, sd_expected) in zip(&res.2, &expected.sd) {
            assert_eq!(sd.as_slice(), sd_expected.as_slice());
        }
    }

    #[test]
    fn commit_test() {
        let database: Vec<DataCommit> =
            serde_json::from_str(include_str!("../tests/data/vc_com.json"))
                .expect("error while reading or parsing");
        for data in database {
            let lamdabytes = data.keyroot.len();
            if lamdabytes == 16 {
                let res = VC::<PRG128, RandomOracleShake128>::commit(
                    GenericArray::from_slice(&data.keyroot),
                    &data.iv,
                    1 << data.depth,
                );
                compare_expected_with_result(&data, res);
            } else if lamdabytes == 24 {
                let res = VC::<PRG192, RandomOracleShake256>::commit(
                    GenericArray::from_slice(&data.keyroot),
                    &data.iv,
                    1 << data.depth,
                );
                compare_expected_with_result(&data, res);
            } else {
                let res = VC::<PRG256, RandomOracleShake256>::commit(
                    GenericArray::from_slice(&data.keyroot),
                    &data.iv,
                    1 << data.depth,
                );
                compare_expected_with_result(&data, res);
            }
        }
    }

    #[test]
    fn open_test() {
        let database: Vec<DataOpen> =
            serde_json::from_str(include_str!("../tests/data/vc_open.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.k[0].len() == 16 {
                type D = U4;
                type Dpow = U31;
                type N = U16;
                let res = VC::<PRG128, RandomOracleShake128>::open::<Dpow, D, N>(
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
                    GenericArray::from_slice(&data.b),
                );
                for (res_0, expected) in zip(&res.0, &data.cop) {
                    assert_eq!(res_0.as_slice(), expected);
                }
                assert_eq!(res.1, data.com_j);
            } else if data.k[0].len() == 24 {
                type D = U4;
                type Dpow = U31;
                type N = U16;
                let res = VC::<PRG192, RandomOracleShake256>::open::<Dpow, D, N>(
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
                    GenericArray::from_slice(&data.b),
                );
                for (res_0, expected) in zip(&res.0, &data.cop) {
                    assert_eq!(res_0.as_slice(), expected);
                }
                assert_eq!(res.1, data.com_j);
            } else if data.b.len() == 4 {
                type D = U4;
                type Dpow = U31;
                type N = U16;
                let res = VC::<PRG256, RandomOracleShake256>::open::<Dpow, D, N>(
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
                    GenericArray::from_slice(&data.b),
                );
                for (res_0, expected) in zip(&res.0, &data.cop) {
                    assert_eq!(res_0.as_slice(), expected);
                }
                assert_eq!(res.1, data.com_j);
            } else {
                type D = U5;
                type Dpow = U63;
                type N = U32;
                let res = VC::<PRG256, RandomOracleShake256>::open::<Dpow, D, N>(
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
                    GenericArray::from_slice(&data.b),
                );
                for (res_0, expected) in zip(&res.0, &data.cop) {
                    assert_eq!(res_0.as_slice(), expected);
                }
                assert_eq!(res.1, data.com_j);
            }
        }
    }

    fn compare_expected_with_reconstruct_result<Lambda: ArrayLength, Lambda2: ArrayLength>(
        data: &DataReconstruct,
        res: (GenericArray<u8, Lambda2>, Vec<GenericArray<u8, Lambda>>),
    ) {
        assert_eq!(res.0.as_slice(), data.h.as_slice());
        for (r, x) in zip(res.1, &data.sd) {
            if !x.is_empty() {
                assert_eq!(r.as_slice(), x.as_slice());
            } else {
                assert_eq!(r, GenericArray::default());
            }
        }
    }

    #[test]
    fn reconstruct_test() {
        let database: Vec<DataReconstruct> =
            serde_json::from_str(include_str!("../tests/data/vc_reconstruct.json"))
                .expect("error while reading or parsing");
        for data in database {
            let lambdabyte = data.com_j.len();
            if lambdabyte == 32 {
                let res = VC::<PRG128, RandomOracleShake128>::reconstruct(
                    &[
                        &data.cop.iter().flatten().copied().collect::<Vec<u8>>()[..],
                        &data.com_j[..],
                    ]
                    .concat(),
                    &data.b,
                    &data.iv,
                );
                compare_expected_with_reconstruct_result(&data, res);
            } else if lambdabyte == 48 {
                let res = VC::<PRG192, RandomOracleShake256>::reconstruct(
                    &[
                        &data.cop.iter().flatten().copied().collect::<Vec<u8>>()[..],
                        &data.com_j[..],
                    ]
                    .concat(),
                    &data.b,
                    &data.iv,
                );
                compare_expected_with_reconstruct_result(&data, res);
            } else {
                let res = VC::<PRG256, RandomOracleShake256>::reconstruct(
                    &[
                        &data.cop.iter().flatten().copied().collect::<Vec<u8>>()[..],
                        &data.com_j[..],
                    ]
                    .concat(),
                    &data.b,
                    &data.iv,
                );
                compare_expected_with_reconstruct_result(&data, res);
            }
        }
    }
}