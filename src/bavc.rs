use core::panic;
use std::{
    convert, default,
    f32::consts::TAU,
    marker::PhantomData,
    ops::{Add, Mul},
    process::id,
    vec,
};

use bit_set::BitSet;

use generic_array::{
    typenum::{
        Const, IsEqual, Negate, Prod, Sum, Unsigned, N1, U10, U128, U16, U216, U3, U4, U48, U64, U8,
    },
    ArrayLength, GenericArray, IntoArrayLength,
};

use crate::{
    fields::{BigGaloisField, Field, GF128},
    parameter::TauParameters,
    prg::{PseudoRandomGenerator, IV, PRG128, PRG192, PRG256, TWK},
    random_oracles::{Hasher, RandomOracle},
    universal_hashing::{LeafHasher, LeafHasher128, LeafHasher192, LeafHasher256},
    utils::Reader,
};

pub trait LeafCommit {
    type LambdaBytes: ArrayLength;
    type LambdaBytesTimesTwo: ArrayLength;
    type LambdaByesTimesThree: ArrayLength;
    type LambdaByesTimesFour: ArrayLength;

    fn commit(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
        tweak: TWK,
        uhash: &GenericArray<u8, Self::LambdaByesTimesThree>,
    ) -> (
        GenericArray<u8, Self::LambdaBytes>,
        GenericArray<u8, Self::LambdaByesTimesThree>,
    );

    fn commit_em(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
        tewak: TWK,
    ) -> (
        GenericArray<u8, Self::LambdaBytes>,
        GenericArray<u8, Self::LambdaBytesTimesTwo>,
    );
}

pub(crate) struct LeafCommitment<PRG, LH>(PhantomData<PRG>, PhantomData<LH>)
where
    PRG: PseudoRandomGenerator,
    LH: LeafHasher;

impl<PRG, LH> LeafCommit for LeafCommitment<PRG, LH>
where
    PRG: PseudoRandomGenerator<KeySize = LH::LambdaBytes>,
    LH: LeafHasher,
{
    type LambdaBytes = LH::LambdaBytes;
    type LambdaBytesTimesTwo = LH::LambdaBytesTwo;
    type LambdaByesTimesThree = LH::LambdaBytesThree;
    type LambdaByesTimesFour = LH::LambdaBytesFour;

    fn commit(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
        tweak: TWK,
        uhash: &GenericArray<u8, Self::LambdaByesTimesThree>,
    ) -> (
        GenericArray<u8, Self::LambdaBytes>,
        GenericArray<u8, Self::LambdaByesTimesThree>,
    ) {
        let mut prg = PRG::new_prg(&r, iv, tweak);
        let mut hash: GenericArray<u8, Self::LambdaByesTimesFour> = GenericArray::default();
        prg.read(&mut hash);

        let com = LH::finalize(&uhash, &GenericArray::from_slice(&hash));

        // TODO: Find a better way for converting sizes
        let mut sd = GenericArray::default();
        sd.copy_from_slice(&hash[..Self::LambdaBytes::USIZE]);
        return (sd, com);
    }

    fn commit_em(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
        tweak: TWK,
    ) -> (
        GenericArray<u8, Self::LambdaBytes>,
        GenericArray<u8, Self::LambdaBytesTimesTwo>,
    ) {
        let mut prg = PRG::new_prg(r, iv, tweak);
        let mut com = GenericArray::default();
        prg.read(&mut com);
        let mut sd = GenericArray::default();
        sd.copy_from_slice(r);
        (sd, com)
    }
}

pub(crate) trait BatchVectorCommitment {
    type LambdaBytes: ArrayLength;
    type LambdaBytesTimes2: ArrayLength;
    type LambdaBytesTimes3: ArrayLength;
    type LC: LeafCommit;
    type Tau: ArrayLength;

    fn commit(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
    ) -> (
        //com
        GenericArray<u8, Self::LambdaBytesTimes2>,
        //decom
        (
            Vec<GenericArray<u8, Self::LambdaBytes>>,
            Vec<GenericArray<u8, Self::LambdaBytesTimes3>>,
        ),
        //seeds
        Vec<GenericArray<u8, Self::LambdaBytes>>,
    );

    fn open(
        decom: &(
            Vec<GenericArray<u8, Self::LambdaBytes>>,
            Vec<GenericArray<u8, Self::LambdaBytesTimes3>>,
        ),
        i_delta: &GenericArray<u16, Self::Tau>,
    ) -> Result<
        (
            Vec<GenericArray<u8, Self::LambdaBytesTimes3>>, // com
            Vec<GenericArray<u8, Self::LambdaBytes>>,       // nodes
        ),
        Box<dyn std::error::Error>,
    >;

    fn reconstruct(
        decom_i: &(
            Vec<GenericArray<u8, Self::LambdaBytesTimes3>>,
            Vec<GenericArray<u8, Self::LambdaBytes>>,
        ),
        i_delta: &GenericArray<u16, Self::Tau>,
        iv: &IV,
    ) -> (
        Box<GenericArray<u8, Self::LambdaBytesTimes2>>, // commitment
        Vec<GenericArray<u8, Self::LambdaBytes>>,       // seeds
    );
}

pub(crate) struct BAVAC<RO, PRG, LH, TAU>(
    PhantomData<RO>,
    PhantomData<PRG>,
    PhantomData<LH>,
    PhantomData<TAU>,
)
where
    RO: RandomOracle,
    PRG: PseudoRandomGenerator,
    TAU: TauParameters,
    LH: LeafHasher;

impl<RO, PRG, LH, TAU> BatchVectorCommitment for BAVAC<RO, PRG, LH, TAU>
where
    RO: RandomOracle,
    PRG: PseudoRandomGenerator<KeySize = LH::LambdaBytes>,
    TAU: TauParameters,
    LH: LeafHasher,
{
    type LambdaBytes = LH::LambdaBytes;
    type LambdaBytesTimes2 = LH::LambdaBytesTwo;
    type LambdaBytesTimes3 = LH::LambdaBytesThree;
    type LC = LeafCommitment<PRG, LH>;
    type Tau = TAU::Tau;

    fn commit(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
    ) -> (
        //com
        GenericArray<u8, Self::LambdaBytesTimes2>,
        //decom
        (
            Vec<GenericArray<u8, Self::LambdaBytes>>,
            Vec<GenericArray<u8, Self::LambdaBytesTimes3>>,
        ),
        //seeds
        Vec<GenericArray<u8, Self::LambdaBytes>>,
    ) {
        // step 1..2: init H_0 with IV
        let mut h0_hasher = RO::h0_init();
        h0_hasher.update(&iv);
        let mut h0_hasher = h0_hasher.finish();

        //step 5..7: generate GCM tree nodes
        let l = TAU::L::USIZE;
        let mut k = vec![GenericArray::default(); 2 * l - 1];
        k[0].copy_from_slice(r);

        for alpha in 0..l - 1 {
            let mut prg = PRG::new_prg(&k[alpha], &iv, alpha as TWK);
            prg.read(&mut k[2 * alpha + 1]);
            prg.read(&mut k[2 * alpha + 2]);
        }

        //setp 8..13: generate seeds and commitment
        let mut com_hasher = RO::h1_init();
        let mut sd = vec![GenericArray::default(); TAU::L::USIZE];
        let mut com = vec![GenericArray::default(); TAU::L::USIZE];

        for i in 0..TAU::Tau::USIZE {
            let mut hi_hasher = RO::h1_init();
            let mut uhash_i = GenericArray::default();
            h0_hasher.read(&mut uhash_i);

            let n_i: usize = TAU::bavac_max_node_index(i);
            for j in 0..n_i {
                let alpha = TAU::pos_in_tree(i, j);

                let idx = TAU::convert_index(i) + j;
                let tweak = (i + l - 1) as TWK;

                (sd[idx], com[idx]) = Self::LC::commit(&k[alpha], &iv, tweak, &uhash_i);
                hi_hasher.update(&com[idx]);
            }

            let hi: GenericArray<u8, Self::LambdaBytesTimes2> = hi_hasher.finish().read_into();
            com_hasher.update(&hi);
        }

        let decom = (k, com);
        let com = com_hasher.finish().read_into();
        (com, decom, sd)
    }

    fn open(
        decom: &(
            Vec<GenericArray<u8, Self::LambdaBytes>>,
            Vec<GenericArray<u8, Self::LambdaBytesTimes3>>,
        ),
        i_delta: &GenericArray<u16, TAU::Tau>,
    ) -> Result<
        (
            Vec<GenericArray<u8, Self::LambdaBytesTimes3>>, // com
            Vec<GenericArray<u8, Self::LambdaBytes>>,       // nodes
        ),
        Box<dyn std::error::Error>,
    > {
        // Line 3
        let com_i: Vec<GenericArray<u8, Self::LambdaBytesTimes3>> = (0..TAU::Tau::USIZE)
            .map(|i| decom.1[TAU::convert_index(i) + i_delta[i] as usize].clone())
            .collect();

        // Line 5
        let mut s = BitSet::with_capacity(2 * TAU::L::USIZE - 1);

        // Line 6 ..15
        let mut n_h = 0;
        for i in 0..TAU::Tau::USIZE {
            let mut alpha = TAU::pos_in_tree(i, i_delta[i] as usize);
            s.insert(alpha);
            n_h += 1;
            while alpha > 0 && s.insert((alpha - 1) / 2) {
                alpha = (alpha - 1) / 2;
                n_h += 1;
            }
        }

        // Line 16
        if n_h - 2 * TAU::Tau::USIZE + 1 > TAU::Topen::USIZE {
            return Err("Chosen path larger than treshold".into());
        }

        // Lines 19..23
        let mut nodes_i: Vec<_> = Vec::with_capacity(TAU::Topen::USIZE);
        for i in (0..TAU::L::USIZE - 1).rev() {
            if s.contains(2 * i + 1) ^ s.contains(2 * i + 2) {
                let alpha = 2 * i + 1 + (s.contains(2 * i + 1) as usize);
                nodes_i.push(decom.0[alpha].clone());
            }
        }

        // Line 24
        nodes_i.resize(TAU::Topen::USIZE, GenericArray::default());

        Ok((com_i, nodes_i))
    }

    // TODO: handle failure case
    fn reconstruct(
        decom_i: &(
            Vec<GenericArray<u8, Self::LambdaBytesTimes3>>,
            Vec<GenericArray<u8, Self::LambdaBytes>>,
        ),
        i_delta: &GenericArray<u16, TAU::Tau>,
        iv: &IV,
    ) -> (
        Box<GenericArray<u8, Self::LambdaBytesTimes2>>, // commitment
        Vec<GenericArray<u8, Self::LambdaBytes>>,       // seeds
    ) {
        // Step 7
        let mut s = BitSet::with_capacity(2 * TAU::L::USIZE - 1);

        // Steps 8..11
        for i in 0..TAU::Tau::USIZE {
            let alpha = TAU::pos_in_tree(i, i_delta[i] as usize);
            s.insert(alpha);
        }

        // Steps 13..21
        let mut keys = vec![GenericArray::default(); 2 * TAU::L::USIZE - 1];
        let mut decom_iter = decom_i.1.iter();
        for i in (0..TAU::L::USIZE - 1).rev() {
            let (left_child, right_child) = (s.contains(2 * i + 1), s.contains(2 * i + 2));

            if left_child | right_child {
                s.insert(i);
            }

            if left_child ^ right_child {
                if let Some(key) = decom_iter.next() {
                    let alpha = 2 * i + 1 + (left_child as usize);
                    keys[alpha].copy_from_slice(key);
                } else {
                    panic!("Error")
                }
            }
        }

        //TODO: Steps 22,23
        while let Some(k) = decom_iter.next() {
            if *k != GenericArray::default() {
                panic!("Error")
            }
        }

        // // Steps 25..27
        for i in 0..TAU::L::USIZE - 1 {
            if !s.contains(i) {
                let mut rng = PRG::new_prg(&keys[i], iv, i as TWK);
                rng.read(&mut keys[2 * i + 1]);
                rng.read(&mut keys[2 * i + 2]);
            }
        }

        // Step 4
        let mut h0_hasher = RO::h0_init();
        h0_hasher.update(&iv);
        let mut h0_hasher = h0_hasher.finish();

        // Steps 28..34
        let mut h1_com_hasher = RO::h1_init();
        let mut seeds = Vec::new();
        let mut com_it = decom_i.0.iter();

        for i in 0..TAU::Tau::USIZE {
            let mut uhash_i = GenericArray::default();
            h0_hasher.read(&mut uhash_i);

            let mut h1_hasher = RO::h1_init();

            for j in 0..TAU::bavac_max_node_index(i) {
                let alpha = TAU::pos_in_tree(i, j);
                // Step 33
                if !s.contains(alpha) {
                    let (sd, h) = Self::LC::commit(
                        &keys[alpha],
                        iv,
                        (i + TAU::L::USIZE - 1) as TWK,
                        &uhash_i,
                    );

                    seeds.push(sd);
                    h1_hasher.update(&h);
                }
                // Step 31
                else {
                    if let Some(com_ij) = com_it.next() {
                        h1_hasher.update(com_ij);
                    } else {
                        panic!("Error");
                    }
                }
            }
            h1_com_hasher.update(&h1_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        (Box::new(h1_com_hasher.finish().read_into()), seeds)
    }
}

type Decom<L, L2> = (Vec<GenericArray<u8, L>>, Vec<GenericArray<u8, L2>>);

pub(crate) trait VectorCommitment {
    type LambdaBytes: ArrayLength;
    type LambdaBytesTimes2: ArrayLength;
    type Lambda: ArrayLength;
    type PRG: PseudoRandomGenerator<KeySize = Self::LambdaBytes>;
    type RO: RandomOracle;

    fn commit(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
        n: usize,
    ) -> (
        GenericArray<u8, Self::LambdaBytesTimes2>,
        (
            Vec<GenericArray<u8, Self::LambdaBytes>>,
            Vec<GenericArray<u8, Self::LambdaBytesTimes2>>,
        ),
        Vec<GenericArray<u8, Self::LambdaBytes>>,
    );

    fn open<'a, DPOW /*2N - 1 */, D, N>(
        decom: &'a Decom<Self::LambdaBytes, Self::LambdaBytesTimes2>,
        b: &GenericArray<u8, D>,
    ) -> (Vec<&'a [u8]>, &'a [u8])
    where
        D: ArrayLength;

    fn reconstruct(
        pdecom: &[u8],
        b: &[u8],
        iv: &IV,
    ) -> (
        GenericArray<u8, Self::LambdaBytesTimes2>,
        Vec<GenericArray<u8, Self::LambdaBytes>>,
    );
}

// pub(crate) struct VC<PRG, R>(PhantomData<PRG>, PhantomData<R>)
// where
//     PRG: PseudoRandomGenerator,
//     R: RandomOracle;

// impl<PRG, R> VectorCommitment for VC<PRG, R>
// where
//     PRG: PseudoRandomGenerator,
//     PRG::KeySize: Add<PRG::KeySize> + Mul<U8>,
//     <PRG::KeySize as Add<PRG::KeySize>>::Output: ArrayLength,
//     <PRG::KeySize as Mul<U8>>::Output: ArrayLength,
//     R: RandomOracle,
// {
//     type LambdaBytes = PRG::KeySize;
//     type LambdaBytesTimes2 = Sum<PRG::KeySize, PRG::KeySize>;
//     type Lambda = Prod<PRG::KeySize, U8>;
//     type PRG = PRG;
//     type RO = R;

//     fn commit(
//         r: &GenericArray<u8, Self::LambdaBytes>,
//         iv: &IV,
//         n: usize,
//     ) -> (
//         GenericArray<u8, Self::LambdaBytesTimes2>,
//         (
//             Vec<GenericArray<u8, Self::LambdaBytes>>,
//             Vec<GenericArray<u8, Self::LambdaBytesTimes2>>,
//         ),
//         Vec<GenericArray<u8, Self::LambdaBytes>>,
//     ) {
//         let mut k = vec![GenericArray::default(); 2 * n - 1];
//         //step 2..3
//         k[0].copy_from_slice(r);

//         for i in 0..n - 1 {
//             let mut prg = PRG::new_prg(&k[i], iv);
//             prg.read(&mut k[2 * i + 1]);
//             prg.read(&mut k[2 * i + 2]);
//         }
//         //step 4..5
//         let mut h1_hasher = R::h1_init();
//         let mut sd = vec![GenericArray::default(); n];
//         let mut com = vec![GenericArray::default(); n];
//         for j in 0..n {
//             let mut h0_hasher = R::h0_init();
//             h0_hasher.update(&k[n - 1 + j]);
//             h0_hasher.update(iv);
//             let mut reader = h0_hasher.finish();
//             reader.read(&mut sd[j]);
//             reader.read(&mut com[j]);
//             h1_hasher.update(&com[j]);
//         }
//         //step 6
//         (h1_hasher.finish().read_into(), (k, com), sd)
//     }

//     fn open<'a, DPOW /*2N - 1 */, D, N>(
//         decom: &'a Decom<Self::LambdaBytes, Self::LambdaBytesTimes2>,
//         b: &GenericArray<u8, D>,
//     ) -> (Vec<&'a [u8]>, &'a [u8])
//     where
//         D: ArrayLength,
//     {
//         let mut a = 0;
//         let d = (usize::BITS - decom.0.len().leading_zeros() - 1) as usize;
//         let mut cop = Vec::with_capacity(d);
//         //step 4

//         for i in 0..d {
//             cop.push(decom.0[(1 << (i + 1)) + 2 * a + (1 - b[d - i - 1] as usize) - 1].as_ref());
//             a = 2 * a + b[d - i - 1] as usize;
//         }
//         (cop, decom.1[a].as_ref())
//     }

//     fn reconstruct(
//         pdecom: &[u8],
//         b: &[u8],
//         iv: &IV,
//     ) -> (
//         GenericArray<u8, Self::LambdaBytesTimes2>,
//         Vec<GenericArray<u8, Self::LambdaBytes>>,
//     ) {
//         let mut a = 0;
//         let d = b.len();
//         let mut k = vec![GenericArray::default(); (1 << (d + 1)) - 1];
//         //step 4
//         for i in 1..=d {
//             let b_d_i = b[d - i] as usize;
//             k[(1 << (i)) - 1 + (2 * a) + (1 - b_d_i)].copy_from_slice(
//                 &pdecom[(i - 1) * Self::LambdaBytes::USIZE..i * Self::LambdaBytes::USIZE],
//             );
//             //step 7
//             for j in 0..1 << (i - 1) {
//                 if j != a {
//                     let rank = (1 << (i - 1)) - 1 + j;
//                     let mut prg = PRG::new_prg(&k[rank], iv);
//                     prg.read(&mut k[rank * 2 + 1]);
//                     prg.read(&mut k[rank * 2 + 2]);
//                 }
//             }
//             a = 2 * a + b_d_i;
//         }
//         let mut sd = vec![GenericArray::default(); 1 << d];
//         let mut h1_hasher = R::h1_init();
//         //step 11
//         for j in 0..(1 << d) {
//             if j != a {
//                 let mut h0_hasher = R::h0_init();
//                 h0_hasher.update(&k[(1 << d) - 1 + j]);
//                 h0_hasher.update(iv);
//                 let mut reader = h0_hasher.finish();
//                 reader.read(&mut sd[j]);
//                 let com_j: GenericArray<_, Self::LambdaBytesTimes2> = reader.read_into();
//                 h1_hasher.update(&com_j);
//             } else {
//                 h1_hasher.update(&pdecom[pdecom.len() - 2 * Self::LambdaBytes::USIZE..]);
//             }
//         }
//         (h1_hasher.finish().read_into(), sd)
//     }
// }

//reconstruct is tested in the integration_test_vc test_commitment_and_decomitment() function.

#[cfg(test)]
mod test {
    use super::*;
    use core::panic;
    use std::iter::zip;

    use generic_array::{
        typenum::{U16, U31, U32, U4, U5, U63},
        GenericArray,
    };
    use serde::{de::Expected, Deserialize};

    use crate::{
        parameter::{Tau128Fast, Tau128Small, Tau192Fast, Tau192Small, Tau256Fast, Tau256Small},
        prg::{IVSize, PRG128, PRG192, PRG256},
        random_oracles::{RandomOracleShake128, RandomOracleShake256},
        utils::test::read_test_data,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataLeafCommit {
        lambda: u32,
        key: Vec<u8>,
        iv: [u8; IVSize::USIZE],
        tweak: u32,
        uhash: Vec<u8>,
        expected_com: Vec<u8>,
        expected_sd: Vec<u8>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataLeafCommitEM {
        lambda: u32,
        key: Vec<u8>,
        iv: [u8; IVSize::USIZE],
        tweak: u32,
        expected_com: Vec<u8>,
        expected_sd: Vec<u8>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataCommit {
        lambda: u32,
        mode: String,
        h: Vec<u8>,
        hashed_k: Vec<u8>,
        hashed_com: Vec<u8>,
        hashed_sd: Vec<u8>,
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

    type Result<Lambda, Lambda2, Lambda3> = (
        GenericArray<u8, Lambda2>,
        (
            Vec<GenericArray<u8, Lambda>>,
            Vec<GenericArray<u8, Lambda3>>,
        ),
        Vec<GenericArray<u8, Lambda>>,
    );

    fn compare_expected_with_result<
        Lambda: ArrayLength,
        Lambda2: ArrayLength,
        Lambda3: ArrayLength,
    >(
        expected: &DataCommit,
        res: Result<Lambda, Lambda2, Lambda3>,
    ) {
        let (h, decom, sd) = res;

        let hashed_sd = hash_array(&sd.iter().flat_map(|x| x.clone()).collect::<Vec<u8>>());
        let hashed_k = hash_array(&decom.0.iter().flat_map(|x| x.clone()).collect::<Vec<u8>>());
        let hashed_coms = hash_array(&decom.1.iter().flat_map(|x| x.clone()).collect::<Vec<u8>>());

        assert_eq!(expected.h.as_slice(), h.as_slice());
        assert_eq!(expected.hashed_sd.as_slice(), hashed_sd.as_slice());
        assert_eq!(expected.hashed_k.as_slice(), hashed_k.as_slice());
        assert_eq!(expected.hashed_com.as_slice(), hashed_coms.as_slice());
    }

    fn hash_array(data: &[u8]) -> Vec<u8> {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake256,
        };

        let mut hasher = sha3::Shake256::default();
        hasher.update(data);
        let mut reader = hasher.finalize_xof();
        let mut ret = [0u8; 64];

        reader.read(&mut ret);
        ret.to_vec()
    }

    #[test]
    fn leaf_commit_test() {
        let database: Vec<DataLeafCommit> = read_test_data("leaf_com.json");
        for data in database {
            let iv = IV::from_slice(&data.iv);

            match data.lambda {
                128 => {
                    println!("lambda = 128 - testing leaf_commitment..");
                    let (sd, com) = LeafCommitment::<PRG128, LeafHasher128>::commit(
                        &GenericArray::from_slice(&data.key),
                        iv,
                        data.tweak,
                        &GenericArray::from_slice(&data.uhash),
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd.as_slice());
                    assert_eq!(com.as_slice(), data.expected_com.as_slice());
                }

                192 => {
                    println!("lambda = 192 - testing leaf_commitment..");
                    let (sd, com) = LeafCommitment::<PRG192, LeafHasher192>::commit(
                        &GenericArray::from_slice(&data.key),
                        iv,
                        data.tweak,
                        &GenericArray::from_slice(&data.uhash),
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd.as_slice());
                    assert_eq!(com.as_slice(), data.expected_com.as_slice());
                }

                256 => {
                    println!("lambda = 256 - testing leaf_commitment..");
                    let (sd, com) = LeafCommitment::<PRG256, LeafHasher256>::commit(
                        &GenericArray::from_slice(&data.key),
                        iv,
                        data.tweak,
                        &GenericArray::from_slice(&data.uhash),
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd.as_slice());
                    assert_eq!(com.as_slice(), data.expected_com.as_slice());
                }

                _ => panic!("Invalid lambda"),
            }
        }
    }

    #[test]
    fn leaf_commit_em_test() {
        let database: Vec<DataLeafCommitEM> = read_test_data("leaf_com_em.json");
        for data in database {
            let iv = IV::from_slice(&data.iv);

            match data.lambda {
                128 => {
                    println!("lambda = 128 - testing leaf_commitment_em..");
                    let (sd, com) = LeafCommitment::<PRG128, LeafHasher128>::commit_em(
                        &GenericArray::from_slice(&data.key),
                        iv,
                        data.tweak,
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd.as_slice());
                    assert_eq!(com.as_slice(), data.expected_com.as_slice());
                }

                192 => {
                    println!("lambda = 192 - testing leaf_commitment_em..");
                    let (sd, com) = LeafCommitment::<PRG192, LeafHasher192>::commit_em(
                        &GenericArray::from_slice(&data.key),
                        iv,
                        data.tweak,
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd.as_slice());
                    assert_eq!(com.as_slice(), data.expected_com.as_slice());
                }

                256 => {
                    println!("lambda = 256 - testing leaf_commitment_em..");
                    let (sd, com) = LeafCommitment::<PRG256, LeafHasher256>::commit_em(
                        &GenericArray::from_slice(&data.key),
                        iv,
                        data.tweak,
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd.as_slice());
                    assert_eq!(com.as_slice(), data.expected_com.as_slice());
                }

                _ => panic!("Invalid lambda"),
            }
        }
    }

    #[test]
    fn commit_test() {
        let r: GenericArray<u8, _> = GenericArray::from_array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let iv: IV = GenericArray::from_array([
            0x64, 0x2b, 0xb1, 0xf9, 0x7c, 0x5f, 0x97, 0x9a, 0x72, 0xb1, 0xee, 0x39, 0xbe, 0x4e,
            0x78, 0x22,
        ]);

        let decom_i_expected = GenericArray::from_array([
            0xb0, 0x8e, 0x51, 0x64, 0x5d, 0x1f, 0xec, 0x39, 0x23, 0x43, 0x6b, 0x9c, 0x5e, 0x55,
            0x23, 0x53, 0x77, 0x1e, 0x7f, 0x2c, 0x2d, 0xd9, 0xba, 0xed, 0xd4, 0xcc, 0x7e, 0x64,
            0xc6, 0xb4, 0x65, 0x16, 0xbc, 0x62, 0xa9, 0x4a, 0x6a, 0x74, 0x41, 0x96, 0x2b, 0x5c,
            0xae, 0x86, 0x0c, 0x91, 0xdb, 0x46, 0xa2, 0x5b, 0x34, 0x2b, 0xad, 0xcc, 0x6c, 0x7f,
            0x81, 0xb7, 0x99, 0x6f, 0x00, 0x30, 0x44, 0xe7,
        ]);

        let rec_sd_expected = GenericArray::from_array([
            0x3b, 0x42, 0xb6, 0x4a, 0xc7, 0x23, 0x9f, 0x47, 0x90, 0x99, 0xdc, 0x87, 0x48, 0x3f,
            0x76, 0xba, 0xc8, 0xf7, 0xee, 0xa8, 0xb5, 0xc8, 0x8b, 0xd2, 0xf2, 0x5d, 0xde, 0xaf,
            0x60, 0xa2, 0x0f, 0xed, 0x41, 0xaf, 0xd0, 0x4c, 0x20, 0xf0, 0xb8, 0xaa, 0x24, 0xf6,
            0x27, 0x52, 0xe6, 0x36, 0x85, 0x3a, 0xfd, 0x7c, 0x3c, 0x62, 0x29, 0x6e, 0x82, 0xc7,
            0xb0, 0x1f, 0x37, 0xc2, 0x77, 0xdf, 0x73, 0x81,
        ]);

        let database: Vec<DataCommit> = read_test_data("bavac_com.json");
        for data in database {
            match data.lambda {
                128 => {
                    let r = GenericArray::from_slice(&r[..16]);
                    let res;
                    if data.mode == "s" {
                        println!("FAEST-128s - testing BAVAC_commitment..");
                        res = BAVAC::<RandomOracleShake128, PRG128, LeafHasher128, Tau128Small>::commit(
                        r, &iv);

                        let i_delta = GenericArray::from_array([
                            0x00f2, 0x0008, 0x02b5, 0x02cd, 0x004c, 0x0223, 0x023a, 0x016b, 0x016c,
                            0x0699, 0x0233,
                        ]);
                        let decom_i = BAVAC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128Small,
                        >::open(&res.1, &i_delta)
                        .unwrap();

                        let data = decom_i
                            .0
                            .iter()
                            .map(|v| v.clone().to_vec())
                            .chain(decom_i.1.iter().map(|v| v.clone().to_vec()))
                            .flatten()
                            .collect::<Vec<u8>>();
                        assert_eq!(decom_i_expected.as_slice(), hash_array(data.as_slice()));

                        let rec_i = BAVAC::<RandomOracleShake128, PRG128, LeafHasher128, Tau128Small>::reconstruct(&decom_i, &i_delta, &iv);
                        assert_eq!(res.0.as_slice(), rec_i.0.as_slice());
                    } else {
                        println!("FAEST-128f - testing BAVAC_commitment..");
                        res = BAVAC::<RandomOracleShake128, PRG128, LeafHasher128, Tau128Fast>::commit(
                        r, &iv,
                    );
                    }
                    compare_expected_with_result(&data, res);
                }
                // 192 => {
                //     let r = GenericArray::from_slice(&r[..24]);
                //     let res;

                //     if data.mode == "s" {
                //         println!("FAEST-192s - testing BAVAC_commitment..");
                //         res = BAVAC::<RandomOracleShake256, PRG192, LeafHasher192, Tau192Small>::commit(
                //         r, &iv,
                //     );
                //     } else {
                //         println!("FAEST-192f - testing BAVAC_commitment..");
                //         res = BAVAC::<RandomOracleShake256, PRG192, LeafHasher192, Tau192Fast>::commit(
                //         r, &iv,
                //     );
                //     }
                //     compare_expected_with_result(&data, res);
                // }
                _ => {
                    // let res;

                    // if data.mode == "s" {
                    //     println!("FAEST-256s - testing BAVAC_commitment..");
                    //     res = BAVAC::<RandomOracleShake256, PRG256, LeafHasher256, Tau256Small>::commit(
                    //     &r, &iv,
                    // );
                    // } else {
                    //     println!("FAEST-256f - testing BAVAC_commitment..");
                    //     res = BAVAC::<RandomOracleShake256, PRG256, LeafHasher256, Tau256Fast>::commit(
                    //     &r, &iv,
                    // );
                    // }
                    // compare_expected_with_result(&data, res);
                }
            }
        }
    }

    #[test]
    fn open_test() {
        let r: GenericArray<u8, _> = GenericArray::from_array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let iv: IV = GenericArray::from_array([
            0x64, 0x2b, 0xb1, 0xf9, 0x7c, 0x5f, 0x97, 0x9a, 0x72, 0xb1, 0xee, 0x39, 0xbe, 0x4e,
            0x78, 0x22,
        ]);

        // let database: Vec<DataCommit> = read_test_data("bavac_com.json");
        // for data in database {
        //     match data.lambda {
        //         128 => {
        //             let r = GenericArray::from_slice(&r[..16]);
        //             let res;
        //             if data.mode == "s" {
        //                 println!("FAEST-128s - testing BAVAC_commitment..");
        //                 res = BAVAC::<RandomOracleShake128, PRG128, LeafHasher128, Tau128Small>::commit(
        //                 r, &iv,
        //             );
        //             } else {
        //                 println!("FAEST-128f - testing BAVAC_commitment..");
        //                 res = BAVAC::<RandomOracleShake128, PRG128, LeafHasher128, Tau128Fast>::commit(
        //                 r, &iv,
        //             );
        //             }
        //             compare_expected_with_result(&data, res);
        //         }
        //         192 => {
        //             let r = GenericArray::from_slice(&r[..24]);
        //             let res;

        //             if data.mode == "s" {
        //                 println!("FAEST-192s - testing BAVAC_commitment..");
        //                 res = BAVAC::<RandomOracleShake256, PRG192, LeafHasher192, Tau192Small>::commit(
        //                 r, &iv,
        //             );
        //             } else {
        //                 println!("FAEST-192f - testing BAVAC_commitment..");
        //                 res = BAVAC::<RandomOracleShake256, PRG192, LeafHasher192, Tau192Fast>::commit(
        //                 r, &iv,
        //             );
        //             }
        //             compare_expected_with_result(&data, res);
        //         }
        //         _ => {
        //             let res;

        //             if data.mode == "s" {
        //                 println!("FAEST-256s - testing BAVAC_commitment..");
        //                 res = BAVAC::<RandomOracleShake256, PRG256, LeafHasher256, Tau256Small>::commit(
        //                 &r, &iv,
        //             );
        //             } else {
        //                 println!("FAEST-256f - testing BAVAC_commitment..");
        //                 res = BAVAC::<RandomOracleShake256, PRG256, LeafHasher256, Tau256Fast>::commit(
        //                 &r, &iv,
        //             );
        //             }
        //             compare_expected_with_result(&data, res);
        //         }
        //     }
        // }
    }

    // #[test]
    // fn open_test() {
    // println!(", {{ \"lambda\": 256, \"mode\": \"f\", \"h\": {:?}, \"hashedK\": {:?}, \"hashedCom\": {:?}, \"hashedSd\": {:?}}}, ", expected_com.as_slice(), hashed_k_expected.as_slice(), hashed_coms_expected.as_slice(), hashed_sd_expected.as_slice());
    //     let database: Vec<DataOpen> = read_test_data("vc_open.json");
    //     for data in database {
    //         if data.k[0].len() == 16 {
    //             type D = U4;
    //             type Dpow = U31;
    //             type N = U16;
    //             let decom = (
    //                 data.k
    //                     .iter()
    //                     .map(|x| *GenericArray::from_slice(x))
    //                     .collect::<Vec<GenericArray<u8, _>>>(),
    //                 data.com
    //                     .iter()
    //                     .map(|x| *GenericArray::from_slice(x))
    //                     .collect::<Vec<GenericArray<u8, _>>>(),
    //             );
    //             let res = VC::<PRG128, RandomOracleShake128>::open::<Dpow, D, N>(
    //                 &decom,
    //                 GenericArray::from_slice(&data.b),
    //             );
    //             for (res_0, expected) in zip(&res.0, &data.cop) {
    //                 assert_eq!(res_0, expected);
    //             }
    //             assert_eq!(res.1, data.com_j);
    //         } else if data.k[0].len() == 24 {
    //             type D = U4;
    //             type Dpow = U31;
    //             type N = U16;
    //             let decom = (
    //                 data.k
    //                     .iter()
    //                     .map(|x| *GenericArray::from_slice(x))
    //                     .collect::<Vec<GenericArray<u8, _>>>(),
    //                 data.com
    //                     .iter()
    //                     .map(|x| *GenericArray::from_slice(x))
    //                     .collect::<Vec<GenericArray<u8, _>>>(),
    //             );
    //             let res = VC::<PRG192, RandomOracleShake256>::open::<Dpow, D, N>(
    //                 &decom,
    //                 GenericArray::from_slice(&data.b),
    //             );
    //             for (res_0, expected) in zip(&res.0, &data.cop) {
    //                 assert_eq!(res_0, expected);
    //             }
    //             assert_eq!(res.1, data.com_j);
    //         } else if data.b.len() == 4 {
    //             type D = U4;
    //             type Dpow = U31;
    //             type N = U16;
    //             let decom = (
    //                 data.k
    //                     .iter()
    //                     .map(|x| *GenericArray::from_slice(x))
    //                     .collect::<Vec<GenericArray<u8, _>>>(),
    //                 data.com
    //                     .iter()
    //                     .map(|x| *GenericArray::from_slice(x))
    //                     .collect::<Vec<GenericArray<u8, _>>>(),
    //             );
    //             let res = VC::<PRG256, RandomOracleShake256>::open::<Dpow, D, N>(
    //                 &decom,
    //                 GenericArray::from_slice(&data.b),
    //             );
    //             for (res_0, expected) in zip(&res.0, &data.cop) {
    //                 assert_eq!(res_0, expected);
    //             }
    //             assert_eq!(res.1, data.com_j);
    //         } else {
    //             type D = U5;
    //             type Dpow = U63;
    //             type N = U32;
    //             let decom = (
    //                 data.k
    //                     .iter()
    //                     .map(|x| *GenericArray::from_slice(x))
    //                     .collect::<Vec<GenericArray<u8, _>>>(),
    //                 data.com
    //                     .iter()
    //                     .map(|x| *GenericArray::from_slice(x))
    //                     .collect::<Vec<GenericArray<u8, _>>>(),
    //             );
    //             let res = VC::<PRG256, RandomOracleShake256>::open::<Dpow, D, N>(
    //                 &decom,
    //                 GenericArray::from_slice(&data.b),
    //             );
    //             for (res_0, expected) in zip(&res.0, &data.cop) {
    //                 assert_eq!(res_0, expected);
    //             }
    //             assert_eq!(res.1, data.com_j);
    //         }
    //     }
    // }

    // fn compare_expected_with_reconstruct_result<Lambda: ArrayLength, Lambda2: ArrayLength>(
    //     data: &DataReconstruct,
    //     res: (GenericArray<u8, Lambda2>, Vec<GenericArray<u8, Lambda>>),
    // ) {
    //     assert_eq!(res.0.as_slice(), data.h.as_slice());
    //     for (r, x) in zip(res.1, &data.sd) {
    //         if !x.is_empty() {
    //             assert_eq!(r.as_slice(), x.as_slice());
    //         } else {
    //             assert_eq!(r, GenericArray::default());
    //         }
    //     }
    // }

    // #[test]
    // fn reconstruct_test() {
    //     let database: Vec<DataReconstruct> = read_test_data("vc_reconstruct.json");
    //     for data in database {leaf_
    //         let iv = IV::from_slice(&data.iv);
    //         let lambdabyte = data.com_j.len();
    //         if lambdabyte == 32 {
    //             let res = VC::<PRG128, RandomOracleShake128>::reconstruct(
    //                 &[
    //                     &data.cop.iter().flatten().copied().collect::<Vec<u8>>()[..],
    //                     &data.com_j[..],
    //                 ]
    //                 .concat(),
    //                 &data.b,
    //                 iv,
    //             );
    //             compare_expected_with_reconstruct_result(&data, res);
    //         } else if lambdabyte == 48 {
    //             let res = VC::<PRG192, RandomOracleShake256>::reconstruct(
    //                 &[
    //                     &data.cop.iter().flatten().copied().collect::<Vec<u8>>()[..],
    //                     &data.com_j[..],
    //                 ]
    //                 .concat(),
    //                 &data.b,
    //                 iv,
    //             );
    //             compare_expected_with_reconstruct_result(&data, res);
    //         } else {
    //             let res = VC::<PRG256, RandomOracleShake256>::reconstruct(
    //                 &[
    //                     &data.cop.iter().flatten().copied().collect::<Vec<u8>>()[..],
    //                     &data.com_j[..],
    //                 ]
    //                 .concat(),
    //                 &data.b,
    //                 iv,
    //             );
    //             compare_expected_with_reconstruct_result(&data, res);
    //         }
    //     }
    // }
}
