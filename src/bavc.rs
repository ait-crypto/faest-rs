use core::panic;
use std::{
    convert, default,
    marker::PhantomData,
    ops::{Add, Mul},
    process::{id, Output},
    vec,
};

use aes::cipher::KeyInit;
use bit_set::BitSet;

use generic_array::{
    typenum::{
        Const, IsEqual, Negate, Prod, Sum, Unsigned, N1, U10, U128, U16, U2, U216, U3, U4, U48,
        U64, U8,
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
    type LambdaBytesTimes2: ArrayLength;
    type LambdaByesTimesThree: ArrayLength;
    type LambdaByesTimesFour: ArrayLength;
    type PRG: PseudoRandomGenerator;

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
        GenericArray<u8, Self::LambdaBytesTimes2>,
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
    type LambdaBytesTimes2 = LH::LambdaBytesTimes2;
    type LambdaByesTimesThree = LH::LambdaBytesTimes3;
    type LambdaByesTimesFour = LH::LambdaBytesTimes4;
    type PRG = PRG;

    fn commit(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
        tweak: TWK,
        uhash: &GenericArray<u8, Self::LambdaByesTimesThree>,
    ) -> (
        GenericArray<u8, Self::LambdaBytes>,
        GenericArray<u8, Self::LambdaByesTimesThree>,
    ) {
        // Step 2
        let hash: GenericArray<u8, Self::LambdaByesTimesFour> =
            PRG::new_prg(&r, iv, tweak).read_into();

        let mut sd = GenericArray::default();
        sd.copy_from_slice(&hash[..Self::LambdaBytes::USIZE]);

        // Step 3
        return (sd, LH::hash(&uhash, &hash));
    }

    fn commit_em(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
        tweak: TWK,
    ) -> (
        GenericArray<u8, Self::LambdaBytes>,
        GenericArray<u8, Self::LambdaBytesTimes2>,
    ) {
        // Step 1
        let com = PRG::new_prg(r, iv, tweak).read_into();

        // Step 2
        let sd = r.to_owned();

        (sd, com)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Commitment<LambdaBytes, NLeafCommit>
where
    LambdaBytes: ArrayLength + Mul<U2, Output: ArrayLength> + Mul<NLeafCommit, Output: ArrayLength>,
    NLeafCommit: ArrayLength,
{
    pub com: GenericArray<u8, Prod<LambdaBytes, U2>>,
    pub decom: Decommitment<LambdaBytes, NLeafCommit>,
    pub seeds: Vec<GenericArray<u8, LambdaBytes>>,
}

#[derive(Clone, Debug)]
pub(crate) struct Opening<'a> {
    pub coms: Vec<&'a [u8]>,
    pub nodes: Vec<&'a [u8]>,
}
impl<'a> Opening<'a> {
    fn decom_i(&'a self) -> (&'a [&'a [u8]], &'a [&'a [u8]]) {
        (self.coms.as_slice(), self.nodes.as_slice())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Decommitment<LambdaBytes, NLeafCommit>
where
    LambdaBytes: ArrayLength + Mul<NLeafCommit, Output: ArrayLength>,
    NLeafCommit: ArrayLength,
{
    keys: Vec<GenericArray<u8, LambdaBytes>>,
    coms: Vec<GenericArray<u8, Prod<LambdaBytes, NLeafCommit>>>,
}

pub(crate) trait BatchVectorCommitment
where
    Self::LambdaBytes: Mul<U2, Output = Self::LambdaBytesTimes2>
        + Mul<U3, Output = Self::LambdaBytesTimes3>
        + Mul<Self::NLeafCommit, Output: ArrayLength>,
{
    type LambdaBytes: ArrayLength;
    type LambdaBytesTimes2: ArrayLength;
    type LambdaBytesTimes3: ArrayLength;
    type Tau: ArrayLength;
    type L: ArrayLength;
    type LC: LeafCommit;
    type NLeafCommit: ArrayLength;
    type Topen: ArrayLength;
    type PRG: PseudoRandomGenerator<KeySize = Self::LambdaBytes>;
    type TAU: TauParameters;

    fn commit(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
    ) -> Commitment<Self::LambdaBytes, Self::NLeafCommit>;

    fn open<'a>(
        decom: &'a Decommitment<Self::LambdaBytes, Self::NLeafCommit>,
        i_delta: &GenericArray<u16, Self::Tau>,
    ) -> Option<Opening<'a>>;

    fn reconstruct(
        decom_i: (&[&[u8]], &[&[u8]]),
        i_delta: &GenericArray<u16, Self::Tau>,
        iv: &IV,
    ) -> Option<(
        GenericArray<u8, Self::LambdaBytesTimes2>, // commitment
        Vec<GenericArray<u8, Self::LambdaBytes>>,  // seeds
    )>;

    fn construct_keys(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
    ) -> Vec<GenericArray<u8, Self::LambdaBytes>> {
        let mut keys = vec![GenericArray::default(); 2 * Self::L::USIZE - 1];
        keys[0].copy_from_slice(r);

        for alpha in 0..Self::L::USIZE - 1 {
            let mut prg = Self::PRG::new_prg(&keys[alpha], &iv, alpha as TWK);
            prg.read(&mut keys[2 * alpha + 1]);
            prg.read(&mut keys[2 * alpha + 2]);
        }

        keys
    }

    fn reconstruct_keys(
        s: &mut BitSet,
        decom_keys: &[&[u8]],
        i_delta: &GenericArray<u16, Self::Tau>,
        iv: &IV,
    ) -> Option<Vec<GenericArray<u8, Self::LambdaBytes>>> {
        // Steps 8..11
        for i in 0..Self::Tau::USIZE {
            let alpha = Self::TAU::pos_in_tree(i, i_delta[i] as usize);
            s.insert(alpha);
        }

        // Steps 13..21
        let mut keys = vec![GenericArray::default(); 2 * Self::L::USIZE - 1];
        let mut decom_iter = decom_keys.iter();
        for i in (0..Self::L::USIZE - 1).rev() {
            let (left_child, right_child) = (s.contains(2 * i + 1), s.contains(2 * i + 2));

            if left_child | right_child {
                s.insert(i);
            }

            if left_child ^ right_child {
                if let Some(key) = decom_iter.next() {
                    let alpha = 2 * i + 1 + (left_child as usize);
                    keys[alpha].copy_from_slice(key);
                } else {
                    return None;
                }
            }
        }

        // Step 22: in BAVC::open we don't actually pad decom with 0s => we must have reached the end of the iterator
        if decom_iter.next().is_some() {
            return None;
        }

        // Steps 25..27
        for i in 0..Self::L::USIZE - 1 {
            if !s.contains(i) {
                let mut rng = Self::PRG::new_prg(&keys[i], iv, i as TWK);
                rng.read(&mut keys[2 * i + 1]);
                rng.read(&mut keys[2 * i + 2]);
            }
        }

        Some(keys)
    }

    fn mark_nodes(s: &mut BitSet, i_delta: &GenericArray<u16, Self::Tau>) -> Option<u32> {
        // Steps 6 ..15
        let mut n_h = 0;
        for i in 0..Self::Tau::USIZE {
            let mut alpha = Self::TAU::pos_in_tree(i, i_delta[i] as usize);
            s.insert(alpha);
            n_h += 1;
            while alpha > 0 && s.insert((alpha - 1) / 2) {
                alpha = (alpha - 1) / 2;
                n_h += 1;
            }
        }

        // Step 16
        if n_h - 2 * Self::Tau::U32 + 1 > Self::Topen::U32 {
            return None;
        }

        Some(n_h)
    }
}

pub(crate) struct BAVC<RO, PRG, LH, TAU>(
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

impl<RO, PRG, LH, TAU> BAVC<RO, PRG, LH, TAU>
where
    RO: RandomOracle,
    PRG: PseudoRandomGenerator<KeySize = LH::LambdaBytes>,
    TAU: TauParameters,
    LH: LeafHasher,
{
}

impl<RO, PRG, LH, TAU> BatchVectorCommitment for BAVC<RO, PRG, LH, TAU>
where
    RO: RandomOracle,
    PRG: PseudoRandomGenerator<KeySize = LH::LambdaBytes>,
    TAU: TauParameters,
    LH: LeafHasher,
{
    type LambdaBytes = LH::LambdaBytes;
    type LambdaBytesTimes2 = LH::LambdaBytesTimes2;
    type LambdaBytesTimes3 = LH::LambdaBytesTimes3;
    type LC = LeafCommitment<PRG, LH>;
    type TAU = TAU;
    type Tau = TAU::Tau;
    type L = TAU::L;
    type PRG = PRG;
    type Topen = TAU::Topen;
    type NLeafCommit = U3;

    fn commit(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
    ) -> Commitment<Self::LambdaBytes, Self::NLeafCommit> {
        // Step 3
        let mut h0_hasher = RO::h0_init();
        h0_hasher.update(&iv);
        let mut h0_hasher = h0_hasher.finish();

        // Steps 5..7
        let keys = <Self as BatchVectorCommitment>::construct_keys(r, iv);

        // Setps 8..13
        let mut com_hasher = RO::h1_init();
        let mut seeds = vec![GenericArray::default(); TAU::L::USIZE];
        let mut coms = vec![GenericArray::default(); TAU::L::USIZE];
        for i in 0..TAU::Tau::U32 {
            // Step 2
            let mut hi_hasher = RO::h1_init();
            let mut uhash_i = GenericArray::default();
            h0_hasher.read(&mut uhash_i);

            let n_i = TAU::bavc_max_node_index(i as usize);
            for j in 0..n_i {
                let alpha = TAU::pos_in_tree(i as usize, j);
                let idx = TAU::convert_index(i as usize) + j;
                let tweak = i + TAU::L::U32 - 1;

                (seeds[idx], coms[idx]) = Self::LC::commit(&keys[alpha], &iv, tweak, &uhash_i);
                hi_hasher.update(&coms[idx]);
            }

            // Step 14
            com_hasher.update(&hi_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        // Steps 15, 16
        let decom = Decommitment { keys, coms };
        let com = com_hasher.finish().read_into();

        Commitment { com, decom, seeds }
    }

    fn open<'a>(
        decom: &'a Decommitment<Self::LambdaBytes, Self::NLeafCommit>,
        i_delta: &GenericArray<u16, TAU::Tau>,
    ) -> Option<Opening<'a>> {
        // Step 5
        let mut s = BitSet::with_capacity(2 * TAU::L::USIZE - 1);

        // Steps 6..17
        if <Self as BatchVectorCommitment>::mark_nodes(&mut s, i_delta).is_none() {
            return None;
        }

        // Steps 19..23
        let nodes = (0..TAU::L::USIZE - 1)
            .rev()
            .filter_map(|i| {
                if s.contains(2 * i + 1) ^ s.contains(2 * i + 2) {
                    let alpha = 2 * i + 1 + (s.contains(2 * i + 1) as usize);
                    return Some(decom.keys[alpha].as_ref());
                }
                None
            })
            .collect();

        // Skip step 24: as we know expected nodes len we can keep the 0s-pad implicit

        // Step 3
        let coms = (0..TAU::Tau::USIZE)
            .map(|i| decom.coms[TAU::convert_index(i) + i_delta[i] as usize].as_ref())
            .collect();

        Some(Opening { coms, nodes })
    }

    fn reconstruct(
        decom_i: (&[&[u8]], &[&[u8]]),
        i_delta: &GenericArray<u16, TAU::Tau>,
        iv: &IV,
    ) -> Option<(
        GenericArray<u8, Self::LambdaBytesTimes2>, // commitment
        Vec<GenericArray<u8, Self::LambdaBytes>>,  // seeds
    )> {
        // Step 7
        let mut s = BitSet::with_capacity(2 * TAU::L::USIZE - 1);

        // Steps 8..27
        let keys =
            <Self as BatchVectorCommitment>::reconstruct_keys(&mut s, &decom_i.1, i_delta, iv)
                .unwrap_or_default();
        if keys.is_empty() {
            return None;
        }

        // Step 4
        let mut h0_hasher = RO::h0_init();
        h0_hasher.update(&iv);
        let mut h0_hasher = h0_hasher.finish();

        // Steps 28..34
        let mut h1_com_hasher = RO::h1_init();
        let mut seeds = Vec::with_capacity(TAU::L::USIZE - TAU::Tau::USIZE);
        let mut com_it = decom_i.0.iter();

        for i in 0u32..TAU::Tau::U32 {
            // Step 3
            let mut uhash_i = GenericArray::default();
            h0_hasher.read(&mut uhash_i);

            let mut h1_hasher = RO::h1_init();

            let n_i = TAU::bavc_max_node_index(i as usize);
            for j in 0..n_i {
                let alpha = TAU::pos_in_tree(i as usize, j);
                // Step 33
                if !s.contains(alpha) {
                    let (sd, h) = Self::LC::commit(&keys[alpha], iv, i + TAU::L::U32 - 1, &uhash_i);

                    seeds.push(sd);
                    h1_hasher.update(&h);
                }
                // Step 31
                else {
                    if let Some(com_ij) = com_it.next() {
                        h1_hasher.update(com_ij);
                    } else {
                        return None;
                    }
                }
            }

            // Step 37
            h1_com_hasher.update(&h1_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        Some((h1_com_hasher.finish().read_into(), seeds))
    }
}

#[allow(non_camel_case_types)]
pub(crate) struct BAVC_EM<RO, PRG, LH, TAU>(
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

impl<RO, PRG, LH, TAU> BAVC<RO, PRG, LH, TAU>
where
    RO: RandomOracle,
    PRG: PseudoRandomGenerator<KeySize = LH::LambdaBytes>,
    TAU: TauParameters,
    LH: LeafHasher,
{
}

impl<RO, PRG, LH, TAU> BatchVectorCommitment for BAVC_EM<RO, PRG, LH, TAU>
where
    RO: RandomOracle,
    PRG: PseudoRandomGenerator<KeySize = LH::LambdaBytes>,
    TAU: TauParameters,
    LH: LeafHasher,
{
    type LambdaBytes = LH::LambdaBytes;
    type LambdaBytesTimes2 = LH::LambdaBytesTimes2;
    type LambdaBytesTimes3 = LH::LambdaBytesTimes3;
    type LC = LeafCommitment<PRG, LH>;
    type TAU = TAU;
    type Tau = TAU::Tau;
    type L = TAU::L;
    type PRG = PRG;
    type Topen = TAU::Topen;
    type NLeafCommit = U2;

    fn commit(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
    ) -> Commitment<Self::LambdaBytes, Self::NLeafCommit> {
        // Steps 5..7
        let keys = Self::construct_keys(r, iv);

        // Setps 8..13
        let mut com_hasher = RO::h1_init();
        let mut seeds = vec![GenericArray::default(); TAU::L::USIZE];
        let mut coms = vec![GenericArray::default(); TAU::L::USIZE];
        for i in 0..TAU::Tau::U32 {
            let mut hi_hasher = RO::h1_init();

            let n_i = TAU::bavc_max_node_index(i as usize);
            for j in 0..n_i {
                let alpha = TAU::pos_in_tree(i as usize, j);
                let idx = TAU::convert_index(i as usize) + j;
                let tweak = i + TAU::L::U32 - 1;

                (seeds[idx], coms[idx]) = Self::LC::commit_em(&keys[alpha], &iv, tweak);

                // Step 13
                hi_hasher.update(&coms[idx]);
            }

            // Step 14
            com_hasher.update(&hi_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        // Steps 15, 16
        let decom = Decommitment { keys, coms };
        let com = com_hasher.finish().read_into();

        Commitment { com, decom, seeds }
    }

    fn open<'a>(
        decom: &'a Decommitment<Self::LambdaBytes, Self::NLeafCommit>,
        i_delta: &GenericArray<u16, Self::Tau>,
    ) -> Option<Opening<'a>> {
        // Step 5
        let mut s = BitSet::with_capacity(2 * TAU::L::USIZE - 1);

        // Steps 6..17
        if Self::mark_nodes(&mut s, i_delta).is_none() {
            return None;
        }

        // Steps 19..23
        let nodes = (0..TAU::L::USIZE - 1)
            .rev()
            .filter_map(|i| {
                if s.contains(2 * i + 1) ^ s.contains(2 * i + 2) {
                    let alpha = 2 * i + 1 + (s.contains(2 * i + 1) as usize);
                    return Some(decom.keys[alpha].as_ref());
                }
                None
            })
            .collect();

        // Skip step 24: as we know expected nodes len we can keep the 0s-pad implicit

        // Step 3
        let coms = (0..TAU::Tau::USIZE)
            .map(|i| decom.coms[TAU::convert_index(i) + i_delta[i] as usize].as_ref())
            .collect();

        Some(Opening { coms, nodes })
    }

    fn reconstruct(
        decom_i: (&[&[u8]], &[&[u8]]),
        i_delta: &GenericArray<u16, Self::Tau>,
        iv: &IV,
    ) -> Option<(
        GenericArray<u8, Self::LambdaBytesTimes2>, // commitment
        Vec<GenericArray<u8, Self::LambdaBytes>>,  // seeds
    )> {
        // Step 7
        let mut s = BitSet::with_capacity(2 * TAU::L::USIZE - 1);

        // Steps 8..11
        for i in 0..TAU::Tau::USIZE {
            let alpha = TAU::pos_in_tree(i, i_delta[i] as usize);
            s.insert(alpha);
        }

        // Steps 13..21
        let keys = Self::reconstruct_keys(&mut s, &decom_i.1, i_delta, iv).unwrap_or_default();
        if keys.is_empty() {
            return None;
        }

        // Steps 28..34
        let mut h1_com_hasher = RO::h1_init();
        let mut seeds = Vec::with_capacity(TAU::L::USIZE - TAU::Tau::USIZE);
        let mut com_it = decom_i.0.iter();

        for i in 0u32..TAU::Tau::U32 {
            let mut h1_hasher = RO::h1_init();

            let n_i = TAU::bavc_max_node_index(i as usize);
            for j in 0..n_i {
                let alpha = TAU::pos_in_tree(i as usize, j);

                // Step 33
                if !s.contains(alpha) {
                    let (sd, h) = Self::LC::commit_em(&keys[alpha], iv, i + TAU::L::U32 - 1);

                    seeds.push(sd);
                    h1_hasher.update(&h);
                }
                // Step 31
                else if let Some(com_ij) = com_it.next() {
                    h1_hasher.update(com_ij);
                } else {
                    return None;
                }
            }

            // Step 37
            h1_com_hasher.update(&h1_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        Some((h1_com_hasher.finish().read_into(), seeds))
    }
}

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
    use serde_json::de;

    use crate::{
        parameter::{
            Tau128Fast, Tau128FastEM, Tau128Small, Tau128SmallEM, Tau192Fast, Tau192FastEM,
            Tau192Small, Tau192SmallEM, Tau256Fast, Tau256FastEM, Tau256Small, Tau256SmallEM,
        },
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
    struct DataBAVAC {
        lambda: u32,
        mode: String,
        h: Vec<u8>,
        hashed_k: Vec<u8>,
        hashed_com: Vec<u8>,
        hashed_sd: Vec<u8>,
        i_delta: Vec<u16>,
        hashed_decom_i: Vec<u8>,
        hashed_rec_sd: Vec<u8>,
    }

    type Result<'a, LambdaBytes, NLeafCommit> = (
        // Commit
        Commitment<LambdaBytes, NLeafCommit>,
        // Open
        Opening<'a>,
        // Reconstruct
        (
            GenericArray<u8, Prod<LambdaBytes, U2>>, // commitment
            Vec<GenericArray<u8, LambdaBytes>>,      // seeds
        ),
    );

    fn compare_expected_with_result<
        'a,
        Lambda: ArrayLength + Mul<NLeafCommit, Output: ArrayLength> + Mul<U2, Output: ArrayLength>,
        NLeafCommit: ArrayLength,
        TAU: TauParameters,
    >(
        expected: &DataBAVAC,
        res: Result<'a, Lambda, NLeafCommit>,
    ) {
        let (Commitment { com, decom, seeds }, decom_i, (rec_h, rec_sd)) = res;

        let Decommitment { keys, coms } = decom;

        let hashed_sd = hash_array(&seeds.iter().flat_map(|x| x.clone()).collect::<Vec<u8>>());
        let hashed_k = hash_array(&keys.iter().flat_map(|x| x.clone()).collect::<Vec<u8>>());
        let hashed_coms = hash_array(&coms.iter().flat_map(|x| x.clone()).collect::<Vec<u8>>());

        // Check commitment
        assert_eq!(expected.h.as_slice(), com.as_slice());
        assert_eq!(expected.hashed_sd.as_slice(), hashed_sd.as_slice());
        assert_eq!(expected.hashed_k.as_slice(), hashed_k.as_slice());
        assert_eq!(expected.hashed_com.as_slice(), hashed_coms.as_slice());

        // Check decommitment
        let mut data_decom: Vec<u8> = decom_i
            .coms
            .into_iter()
            .flat_map(|v| v.to_vec())
            .chain(decom_i.nodes.into_iter().flat_map(|v| v.to_vec()))
            .collect::<Vec<u8>>();
        // As we skipped step 22 in BAVC::commit we need to pad accordingly before checking result
        let decom_size = NLeafCommit::USIZE * Lambda::USIZE * TAU::Tau::USIZE
            + TAU::Topen::USIZE * Lambda::USIZE;
        data_decom.resize_with(decom_size, Default::default);
        assert_eq!(expected.hashed_decom_i, hash_array(data_decom.as_slice()));

        // Check reconstruct
        let rec_sd: Vec<u8> = rec_sd.iter().flat_map(|b| b.clone()).collect();
        assert_eq!(expected.hashed_rec_sd.as_slice(), hash_array(&rec_sd));
        assert_eq!(expected.h.as_slice(), rec_h.as_slice());
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

    type BAVC128S = BAVC<RandomOracleShake128, PRG128, LeafHasher128, Tau128Small>;
    type BAVC128F = BAVC<RandomOracleShake128, PRG128, LeafHasher128, Tau128Fast>;
    type BAVC192S = BAVC<RandomOracleShake256, PRG192, LeafHasher192, Tau192Small>;
    type BAVC192F = BAVC<RandomOracleShake256, PRG192, LeafHasher192, Tau192Fast>;
    type BAVC256S = BAVC<RandomOracleShake256, PRG256, LeafHasher256, Tau256Small>;
    type BAVC256F = BAVC<RandomOracleShake256, PRG256, LeafHasher256, Tau256Fast>;

    type BAVCEM128S = BAVC_EM<RandomOracleShake128, PRG128, LeafHasher128, Tau128SmallEM>;
    type BAVCEM128F = BAVC_EM<RandomOracleShake128, PRG128, LeafHasher128, Tau128FastEM>;
    type BAVCEM192S = BAVC_EM<RandomOracleShake256, PRG192, LeafHasher192, Tau192SmallEM>;
    type BAVCEM192F = BAVC_EM<RandomOracleShake256, PRG192, LeafHasher192, Tau192FastEM>;
    type BAVCEM256S = BAVC_EM<RandomOracleShake256, PRG256, LeafHasher256, Tau256SmallEM>;
    type BAVCEM256F = BAVC_EM<RandomOracleShake256, PRG256, LeafHasher256, Tau256FastEM>;

    #[test]
    fn bavc_test() {
        let r: GenericArray<u8, _> = GenericArray::from_array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        // Differently from C test vectors I've created a random initialization vector
        let iv: IV = GenericArray::from_array([
            0x64, 0x2b, 0xb1, 0xf9, 0x7c, 0x5f, 0x97, 0x9a, 0x72, 0xb1, 0xee, 0x39, 0xbe, 0x4e,
            0x78, 0x22,
        ]);

        let database: Vec<DataBAVAC> = read_test_data("bavac.json");
        for data in database {
            match data.lambda {
                128 => {
                    let r = GenericArray::from_slice(&r[..16]);

                    if data.mode == "s" {
                        println!("FAEST-128s - testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC128S::commit(r, &iv);

                        let res_open = BAVC128S::open(&res_commit.decom, &i_delta).unwrap();

                        let res_reconstruct =
                            BAVC128S::reconstruct(res_open.decom_i(), &i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau128Small>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        println!("FAEST-128f - testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC128F::commit(r, &iv);

                        let res_open = BAVC128F::open(&res_commit.decom, &i_delta).unwrap();

                        let res_reconstruct =
                            BAVC128F::reconstruct(res_open.decom_i(), &i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau128Fast>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    }
                }
                192 => {
                    let r = GenericArray::from_slice(&r[..24]);

                    if data.mode == "s" {
                        println!("FAEST-192s - testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC192S::commit(r, &iv);

                        let res_open = BAVC192S::open(&res_commit.decom, &i_delta).unwrap();

                        let res_reconstruct =
                            BAVC192S::reconstruct(res_open.decom_i(), &i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau192Small>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        println!("FAEST-192f - testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC192F::commit(r, &iv);

                        let res_open = BAVC192F::open(&res_commit.decom, &i_delta).unwrap();

                        let res_reconstruct =
                            BAVC192F::reconstruct(res_open.decom_i(), &i_delta, &iv).unwrap();
                        compare_expected_with_result::<_, _, Tau192Fast>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    }
                }

                _ => {
                    if data.mode == "s" {
                        println!("FAEST-256s - testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC256S::commit(&r, &iv);

                        let res_open = BAVC256S::open(&res_commit.decom, &i_delta).unwrap();

                        let res_reconstruct =
                            BAVC256S::reconstruct(res_open.decom_i(), &i_delta, &iv).unwrap();
                        compare_expected_with_result::<_, _, Tau256Small>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        println!("FAEST-256f - testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC256F::commit(&r, &iv);

                        let res_open = BAVC256F::open(&res_commit.decom, &i_delta).unwrap();

                        let res_reconstruct =
                            BAVC256F::reconstruct(res_open.decom_i(), &i_delta, &iv).unwrap();
                        compare_expected_with_result::<_, _, Tau256Fast>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn bavc_em_test() {
        let r: GenericArray<u8, _> = GenericArray::from_array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let iv: IV = GenericArray::from_array([
            0x64, 0x2b, 0xb1, 0xf9, 0x7c, 0x5f, 0x97, 0x9a, 0x72, 0xb1, 0xee, 0x39, 0xbe, 0x4e,
            0x78, 0x22,
        ]);

        let database: Vec<DataBAVAC> = read_test_data("bavc_em.json");
        for data in database {
            match data.lambda {
                128 => {
                    let r = GenericArray::from_slice(&r[..16]);

                    if data.mode == "s" {
                        println!("FAEST-EM-128s: testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVCEM128S::commit(r, &iv);

                        let res_open = BAVCEM128S::open(&res_commit.decom, &i_delta).unwrap();

                        let res_reconstruct =
                            BAVCEM128S::reconstruct(res_open.decom_i(), &i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau128SmallEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        println!("FAEST-EM-128f: testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVCEM128F::commit(r, &iv);

                        let res_open = BAVCEM128F::open(&res_commit.decom, &i_delta).unwrap();

                        let res_reconstruct =
                            BAVCEM128F::reconstruct(res_open.decom_i(), &i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau128FastEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    }
                }
                192 => {
                    let r = GenericArray::from_slice(&r[..24]);

                    if data.mode == "s" {
                        println!("FAEST-EM-192s: testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVCEM192S::commit(r, &iv);

                        let res_open = BAVCEM192S::open(&res_commit.decom, &i_delta).unwrap();

                        let res_reconstruct =
                            BAVCEM192S::reconstruct(res_open.decom_i(), &i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau192SmallEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        println!("FAEST-EM-192f: testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVCEM192F::commit(r, &iv);

                        let res_open = BAVCEM192F::open(&res_commit.decom, &i_delta).unwrap();

                        let res_reconstruct =
                            BAVCEM192F::reconstruct(res_open.decom_i(), &i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau192FastEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    }
                }
                _ => {
                    if data.mode == "s" {
                        println!("FAEST-EM-256s: testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVCEM256S::commit(&r, &iv);

                        let res_open = BAVCEM256S::open(&res_commit.decom, &i_delta).unwrap();

                        let res_reconstruct =
                            BAVCEM256S::reconstruct(res_open.decom_i(), &i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau256SmallEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        println!("FAEST-EM-256f: testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVCEM256F::commit(&r, &iv);

                        let res_open = BAVCEM256F::open(&res_commit.decom, &i_delta).unwrap();

                        let res_reconstruct =
                            BAVCEM256F::reconstruct(res_open.decom_i(), &i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau256FastEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    }
                }
            }
        }
    }
}
