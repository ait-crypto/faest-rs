use std::{marker::PhantomData, ops::Mul};

use bitvec::prelude::*;
use generic_array::{
    ArrayLength, GenericArray,
    typenum::{Prod, U2, U3, U8, Unsigned},
};

use crate::{
    parameter::{
        Tau128Fast, Tau128FastEM, Tau128Small, Tau128SmallEM, Tau192Fast, Tau192FastEM,
        Tau192Small, Tau192SmallEM, Tau256Fast, Tau256FastEM, Tau256Small, Tau256SmallEM,
        TauParameters,
    },
    prg::{IV, PRG128, PRG192, PRG256, PseudoRandomGenerator, Twk},
    random_oracles::{Hasher, RandomOracle, RandomOracleShake128, RandomOracleShake256},
    universal_hashing::{LeafHasher, LeafHasher128, LeafHasher192, LeafHasher256},
    utils::Reader,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct BavcCommitResult<LambdaBytes, NLeafCommit>
where
    LambdaBytes: ArrayLength + Mul<U2, Output: ArrayLength> + Mul<NLeafCommit, Output: ArrayLength>,
    NLeafCommit: ArrayLength,
{
    pub com: GenericArray<u8, Prod<LambdaBytes, U2>>,
    pub decom: BavcDecommitment<LambdaBytes, NLeafCommit>,
    pub seeds: Vec<GenericArray<u8, LambdaBytes>>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BavcOpenResult<'a> {
    pub coms: Vec<&'a [u8]>,
    pub nodes: Vec<&'a [u8]>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BavcReconstructResult<LambdaBytes>
where
    LambdaBytes: ArrayLength + Mul<U2, Output: ArrayLength>,
{
    pub com: GenericArray<u8, Prod<LambdaBytes, U2>>,
    pub seeds: Vec<GenericArray<u8, LambdaBytes>>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BavcDecommitment<LambdaBytes, NLeafCommit>
where
    LambdaBytes: ArrayLength + Mul<NLeafCommit, Output: ArrayLength>,
    NLeafCommit: ArrayLength,
{
    keys: Vec<GenericArray<u8, LambdaBytes>>,
    coms: Vec<GenericArray<u8, Prod<LambdaBytes, NLeafCommit>>>,
}

pub(crate) trait LeafCommit {
    type LambdaBytes: ArrayLength;
    type LambdaBytesTimes2: ArrayLength;
    type LambdaBytesTimes3: ArrayLength;
    type PRG: PseudoRandomGenerator;

    fn commit(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
        tweak: Twk,
        uhash: &GenericArray<u8, Self::LambdaBytesTimes3>,
    ) -> (
        GenericArray<u8, Self::LambdaBytes>,
        GenericArray<u8, Self::LambdaBytesTimes3>,
    );

    fn commit_em(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
        tewak: Twk,
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
    type LambdaBytesTimes2 = Prod<LH::LambdaBytes, U2>;
    type LambdaBytesTimes3 = Prod<LH::LambdaBytes, U3>;
    type PRG = PRG;

    fn commit(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
        tweak: Twk,
        uhash: &GenericArray<u8, Self::LambdaBytesTimes3>,
    ) -> (
        GenericArray<u8, Self::LambdaBytes>,
        GenericArray<u8, Self::LambdaBytesTimes3>,
    ) {
        // Step 2
        let hash = PRG::new_prg(r, iv, tweak).read_into();

        let com = LH::hash(uhash, &hash);

        let sd = hash.into_iter().take(Self::LambdaBytes::USIZE).collect();

        (sd, com)
    }

    fn commit_em(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
        tweak: Twk,
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

fn construct_keys<PRG, L>(
    r: &GenericArray<u8, PRG::KeySize>,
    iv: &IV,
) -> Vec<GenericArray<u8, PRG::KeySize>>
where
    PRG: PseudoRandomGenerator,
    L: ArrayLength,
{
    let mut keys = vec![GenericArray::default(); 2 * L::USIZE - 1];
    keys[0].copy_from_slice(r);

    for alpha in 0..L::USIZE - 1 {
        let mut prg = PRG::new_prg(&keys[alpha], iv, alpha as Twk);
        prg.read(&mut keys[2 * alpha + 1]);
        prg.read(&mut keys[2 * alpha + 2]);
    }

    keys
}

fn reconstruct_keys<PRG, TAU>(
    s: &mut BitSlice,
    decom_keys: &[&[u8]],
    i_delta: &GenericArray<u16, TAU::Tau>,
    iv: &IV,
) -> Option<Vec<GenericArray<u8, PRG::KeySize>>>
where
    PRG: PseudoRandomGenerator,
    TAU: TauParameters,
{
    // Steps 8..11
    for i in 0..TAU::Tau::USIZE {
        let alpha = TAU::pos_in_tree(i, i_delta[i] as usize);
        s.set(alpha, true);
    }

    // Steps 13..21
    let mut keys = vec![GenericArray::default(); 2 * TAU::L::USIZE - 1];
    let mut decom_iter = decom_keys.iter();
    for i in (0..TAU::L::USIZE - 1).rev() {
        let (left_child, right_child) = (s[2 * i + 1], s[2 * i + 2]);

        if left_child | right_child {
            s.set(i, true);
        }

        if left_child ^ right_child {
            let key = decom_iter.next()?;
            let alpha = 2 * i + 1 + (left_child as usize);
            keys[alpha].copy_from_slice(key);
        }
    }

    // Step 22
    for &pad in decom_iter {
        if pad.iter().any(|&x| x != 0) {
            return None;
        }
    }

    // Steps 25..27
    for i in s[..TAU::L::USIZE - 1].iter_zeros() {
        let mut rng = PRG::new_prg(&keys[i], iv, i as Twk);
        rng.read(&mut keys[2 * i + 1]);
        rng.read(&mut keys[2 * i + 2]);
    }

    Some(keys)
}

fn mark_nodes<TAU>(s: &mut BitSlice, i_delta: &GenericArray<u16, TAU::Tau>) -> Option<u32>
where
    TAU: TauParameters,
{
    // Steps 6 ..15
    let mut n_h = 0;
    for i in 0..TAU::Tau::USIZE {
        let mut alpha = TAU::pos_in_tree(i, i_delta[i] as usize);
        s.set(alpha, true);
        n_h += 1;
        while alpha > 0 && !s.replace((alpha - 1) / 2, true) {
            alpha = (alpha - 1) / 2;
            n_h += 1;
        }
    }

    // Step 16
    if n_h - 2 * TAU::Tau::U32 + 1 > TAU::Topen::U32 {
        None
    } else {
        Some(n_h)
    }
}

fn construct_nodes<'a, LambdaBytes, L>(
    keys: &'a [GenericArray<u8, LambdaBytes>],
    s: &BitSlice,
) -> Vec<&'a [u8]>
where
    L: ArrayLength,
    LambdaBytes: ArrayLength,
{
    // Steps 19..22
    (0..L::USIZE - 1)
        .rev()
        .filter_map(|i| {
            let (left_child, right_child) = (s.get(2 * i + 1)?, s.get(2 * i + 2)?);

            if *left_child ^ *right_child {
                let alpha = 2 * i + 1 + (*left_child as usize);
                return Some(keys[alpha].as_ref());
            }
            None
        })
        .collect()
}

pub(crate) trait BatchVectorCommitment
where
    Self::LambdaBytes: Mul<U2, Output = Self::LambdaBytesTimes2>
        + Mul<U3, Output = Self::LambdaBytesTimes3>
        + Mul<U8, Output = Self::Lambda>
        + Mul<Self::NLeafCommit, Output: ArrayLength>,
{
    type PRG: PseudoRandomGenerator<KeySize = Self::LambdaBytes>;
    type TAU: TauParameters<Tau = Self::Tau, L = Self::L>;
    type LH: LeafHasher;
    type RO: RandomOracle;

    type Lambda: ArrayLength;
    type LambdaBytes: ArrayLength;
    type LambdaBytesTimes2: ArrayLength;
    type LambdaBytesTimes3: ArrayLength;
    type Tau: ArrayLength;
    type L: ArrayLength;
    type LC: LeafCommit;
    type NLeafCommit: ArrayLength;
    type Topen: ArrayLength;

    fn commit(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
    ) -> BavcCommitResult<Self::LambdaBytes, Self::NLeafCommit>;

    fn open<'a>(
        decom: &'a BavcDecommitment<Self::LambdaBytes, Self::NLeafCommit>,
        i_delta: &GenericArray<u16, Self::Tau>,
    ) -> Option<BavcOpenResult<'a>>;

    fn reconstruct(
        decom_i: &BavcOpenResult,
        i_delta: &GenericArray<u16, Self::Tau>,
        iv: &IV,
    ) -> Option<BavcReconstructResult<Self::LambdaBytes>>;
}

pub(crate) struct Bavc<RO, PRG, LH, TAU>(
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

impl<RO, PRG, LH, TAU> BatchVectorCommitment for Bavc<RO, PRG, LH, TAU>
where
    RO: RandomOracle,
    PRG: PseudoRandomGenerator<KeySize = LH::LambdaBytes>,
    TAU: TauParameters,
    LH: LeafHasher,
{
    type LH = LH;
    type RO = RO;
    type Lambda = LH::Lambda;
    type LambdaBytes = LH::LambdaBytes;
    type LambdaBytesTimes2 = Prod<LH::LambdaBytes, U2>;
    type LambdaBytesTimes3 = Prod<LH::LambdaBytes, U3>;
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
    ) -> BavcCommitResult<Self::LambdaBytes, Self::NLeafCommit> {
        // Step 3
        let mut h0_hasher = RO::h0_init();
        h0_hasher.update(iv);
        let mut h0_hasher = h0_hasher.finish();

        // Steps 5..7
        let keys = construct_keys::<PRG, Self::L>(r, iv);

        // Setps 8..13
        let mut com_hasher = RO::h1_init();
        let mut seeds = Vec::with_capacity(TAU::L::USIZE);
        let mut coms = Vec::with_capacity(TAU::L::USIZE);

        for i in 0..TAU::Tau::U32 {
            // Step 2
            let mut hi_hasher = RO::h1_init();
            let mut uhash_i = GenericArray::default();
            h0_hasher.read(&mut uhash_i);

            let n_i = TAU::bavc_max_node_index(i as usize);
            for j in 0..n_i {
                let alpha = TAU::pos_in_tree(i as usize, j);
                let tweak = i + TAU::L::U32 - 1;

                let (sd, com) = Self::LC::commit(&keys[alpha], iv, tweak, &uhash_i);

                hi_hasher.update(&com);

                seeds.push(sd);
                coms.push(com);
            }

            // Step 14
            com_hasher.update(&hi_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        // Steps 15, 16
        let decom = BavcDecommitment { keys, coms };
        let com = com_hasher.finish().read_into();

        BavcCommitResult { com, decom, seeds }
    }

    fn open<'a>(
        decom: &'a BavcDecommitment<Self::LambdaBytes, Self::NLeafCommit>,
        i_delta: &GenericArray<u16, TAU::Tau>,
    ) -> Option<BavcOpenResult<'a>> {
        // Step 5
        let mut s = bitvec![0; 2 * TAU::L::USIZE - 1];

        // Steps 6..17
        mark_nodes::<TAU>(&mut s, i_delta)?;

        // Steps 19..23
        let nodes = construct_nodes::<Self::LambdaBytes, Self::L>(&decom.keys, &s);

        // Skip step 24: as we know expected nodes len we can keep the 0s-pad implicit

        // Step 3
        let coms = (0..TAU::Tau::USIZE)
            .map(|i| decom.coms[TAU::bavc_index_offset(i) + i_delta[i] as usize].as_slice())
            .collect();

        Some(BavcOpenResult { coms, nodes })
    }

    fn reconstruct(
        decom_i: &BavcOpenResult,
        i_delta: &GenericArray<u16, TAU::Tau>,
        iv: &IV,
    ) -> Option<BavcReconstructResult<Self::LambdaBytes>> {
        // Step 7
        let mut s = bitvec![0; 2 * TAU::L::USIZE - 1];

        // Steps 8..27
        let keys = reconstruct_keys::<PRG, TAU>(&mut s, &decom_i.nodes, i_delta, iv)?;

        // Step 4
        let mut h0_hasher = RO::h0_init();
        h0_hasher.update(iv);
        let mut h0_hasher = h0_hasher.finish();

        // Steps 28..34
        let mut h1_com_hasher = RO::h1_init();
        let mut seeds = Vec::with_capacity(TAU::L::USIZE - TAU::Tau::USIZE);
        let mut com_it = decom_i.coms.iter();

        for i in 0u32..TAU::Tau::U32 {
            // Step 3
            let mut uhash_i = GenericArray::default();
            h0_hasher.read(&mut uhash_i);

            let mut h1_hasher = RO::h1_init();

            let n_i = TAU::bavc_max_node_index(i as usize);
            for j in 0..n_i {
                let alpha = TAU::pos_in_tree(i as usize, j);
                // Step 33
                if !*s.get(alpha)? {
                    let (sd, h) = Self::LC::commit(&keys[alpha], iv, i + TAU::L::U32 - 1, &uhash_i);

                    seeds.push(sd);
                    h1_hasher.update(&h);
                }
                // Step 31
                else {
                    let com_ij = com_it.next()?;
                    h1_hasher.update(com_ij);
                }
            }

            // Step 37
            h1_com_hasher.update(&h1_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        Some(BavcReconstructResult {
            com: h1_com_hasher.finish().read_into(),
            seeds,
        })
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

impl<RO, PRG, LH, TAU> BatchVectorCommitment for BAVC_EM<RO, PRG, LH, TAU>
where
    RO: RandomOracle,
    PRG: PseudoRandomGenerator<KeySize = LH::LambdaBytes>,
    TAU: TauParameters,
    LH: LeafHasher,
{
    type RO = RO;
    type PRG = PRG;
    type LH = LH;
    type TAU = TAU;
    type LC = LeafCommitment<PRG, LH>;

    type Lambda = LH::Lambda;
    type LambdaBytes = LH::LambdaBytes;
    type LambdaBytesTimes2 = Prod<LH::LambdaBytes, U2>;
    type LambdaBytesTimes3 = Prod<LH::LambdaBytes, U3>;
    type Tau = TAU::Tau;
    type L = TAU::L;
    type Topen = TAU::Topen;
    type NLeafCommit = U2;

    fn commit(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
    ) -> BavcCommitResult<Self::LambdaBytes, Self::NLeafCommit> {
        // Steps 5..7
        let keys = construct_keys::<PRG, Self::L>(r, iv);

        // Setps 8..13
        let mut com_hasher = RO::h1_init();
        let mut seeds = Vec::with_capacity(TAU::L::USIZE);
        let mut coms = Vec::with_capacity(TAU::L::USIZE);

        for i in 0..TAU::Tau::U32 {
            let mut hi_hasher = RO::h1_init();

            let n_i = TAU::bavc_max_node_index(i as usize);
            for j in 0..n_i {
                let alpha = TAU::pos_in_tree(i as usize, j);
                let tweak = i + TAU::L::U32 - 1;

                let (seed, com) = Self::LC::commit_em(&keys[alpha], iv, tweak);

                // Step 13
                hi_hasher.update(&com);

                seeds.push(seed);
                coms.push(com);
            }

            // Step 14
            com_hasher.update(&hi_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        // Steps 15, 16
        let decom = BavcDecommitment { keys, coms };
        let com = com_hasher.finish().read_into();

        BavcCommitResult { com, decom, seeds }
    }

    fn open<'a>(
        decom: &'a BavcDecommitment<Self::LambdaBytes, Self::NLeafCommit>,
        i_delta: &GenericArray<u16, Self::Tau>,
    ) -> Option<BavcOpenResult<'a>> {
        // Step 5
        let mut s = bitvec![0; 2 * TAU::L::USIZE - 1];

        // Steps 6..17
        mark_nodes::<TAU>(&mut s, i_delta)?;

        // Steps 19..23
        let nodes = construct_nodes::<Self::LambdaBytes, Self::L>(&decom.keys, &s);

        // Skip step 24: as we know expected nodes len we can keep the 0s-pad implicit

        // Step 3
        let coms = (0..TAU::Tau::USIZE)
            .map(|i| decom.coms[TAU::bavc_index_offset(i) + i_delta[i] as usize].as_slice())
            .collect();

        Some(BavcOpenResult { coms, nodes })
    }

    fn reconstruct(
        decom_i: &BavcOpenResult,
        i_delta: &GenericArray<u16, Self::Tau>,
        iv: &IV,
    ) -> Option<BavcReconstructResult<Self::LambdaBytes>> {
        // Step 7
        let mut s = bitvec![0; 2 * TAU::L::USIZE - 1];

        // Steps 8..11
        for i in 0..TAU::Tau::USIZE {
            let alpha = TAU::pos_in_tree(i, i_delta[i] as usize);
            s.set(alpha, true);
        }

        // Steps 13..21
        let keys = reconstruct_keys::<PRG, TAU>(&mut s, &decom_i.nodes, i_delta, iv)?;

        // Steps 28..34
        let mut h1_com_hasher = RO::h1_init();
        let mut seeds = Vec::with_capacity(TAU::L::USIZE - TAU::Tau::USIZE);
        let mut com_it = decom_i.coms.iter();

        for i in 0u32..TAU::Tau::U32 {
            let mut h1_hasher = RO::h1_init();

            let n_i = TAU::bavc_max_node_index(i as usize);
            for j in 0..n_i {
                let alpha = TAU::pos_in_tree(i as usize, j);

                // Step 33
                if !*s.get(alpha)? {
                    let (sd, h) = Self::LC::commit_em(&keys[alpha], iv, i + TAU::L::U32 - 1);
                    seeds.push(sd);
                    h1_hasher.update(&h);
                }
                // Step 31
                else {
                    let com_ij = com_it.next()?;
                    h1_hasher.update(com_ij);
                }
            }

            // Step 37
            h1_com_hasher.update(&h1_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        Some(BavcReconstructResult {
            com: h1_com_hasher.finish().read_into(),
            seeds,
        })
    }
}

pub(crate) type BAVC128Small = Bavc<RandomOracleShake128, PRG128, LeafHasher128, Tau128Small>;
pub(crate) type BAVC128Fast = Bavc<RandomOracleShake128, PRG128, LeafHasher128, Tau128Fast>;
pub(crate) type BAVC192Small = Bavc<RandomOracleShake256, PRG192, LeafHasher192, Tau192Small>;
pub(crate) type BAVC192Fast = Bavc<RandomOracleShake256, PRG192, LeafHasher192, Tau192Fast>;
pub(crate) type BAVC256Small = Bavc<RandomOracleShake256, PRG256, LeafHasher256, Tau256Small>;
pub(crate) type BAVC256Fast = Bavc<RandomOracleShake256, PRG256, LeafHasher256, Tau256Fast>;

pub(crate) type BAVC128SmallEM =
    BAVC_EM<RandomOracleShake128, PRG128, LeafHasher128, Tau128SmallEM>;
pub(crate) type BAVC128FastEM = BAVC_EM<RandomOracleShake128, PRG128, LeafHasher128, Tau128FastEM>;
pub(crate) type BAVC192SmallEM =
    BAVC_EM<RandomOracleShake256, PRG192, LeafHasher192, Tau192SmallEM>;
pub(crate) type BAVC192FastEM = BAVC_EM<RandomOracleShake256, PRG192, LeafHasher192, Tau192FastEM>;
pub(crate) type BAVC256SmallEM =
    BAVC_EM<RandomOracleShake256, PRG256, LeafHasher256, Tau256SmallEM>;
pub(crate) type BAVC256FastEM = BAVC_EM<RandomOracleShake256, PRG256, LeafHasher256, Tau256FastEM>;

#[cfg(test)]
mod test {
    use super::*;
    use core::panic;

    use generic_array::GenericArray;
    use serde::Deserialize;

    use crate::{
        parameter::{
            Tau128Fast, Tau128FastEM, Tau128Small, Tau128SmallEM, Tau192Fast, Tau192FastEM,
            Tau192Small, Tau192SmallEM, Tau256Fast, Tau256FastEM, Tau256Small, Tau256SmallEM,
        },
        prg::{IVSize, PRG128, PRG192, PRG256},
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
        BavcCommitResult<LambdaBytes, NLeafCommit>,
        // Open
        BavcOpenResult<'a>,
        // Reconstruct
        BavcReconstructResult<LambdaBytes>,
    );

    fn compare_expected_with_result<
        Lambda: ArrayLength + Mul<NLeafCommit, Output: ArrayLength> + Mul<U2, Output: ArrayLength>,
        NLeafCommit: ArrayLength,
        TAU: TauParameters,
    >(
        expected: &DataBAVAC,
        res: Result<'_, Lambda, NLeafCommit>,
    ) {
        let (
            BavcCommitResult { com, decom, seeds },
            decom_i,
            BavcReconstructResult {
                com: rec_h,
                seeds: rec_sd,
            },
        ) = res;

        let BavcDecommitment { keys, coms } = decom;

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
        use sha3::digest::{ExtendableOutput, Update, XofReader};

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
                        GenericArray::from_slice(&data.key),
                        iv,
                        data.tweak,
                        GenericArray::from_slice(&data.uhash),
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd.as_slice());
                    assert_eq!(com.as_slice(), data.expected_com.as_slice());
                }

                192 => {
                    println!("lambda = 192 - testing leaf_commitment..");
                    let (sd, com) = LeafCommitment::<PRG192, LeafHasher192>::commit(
                        GenericArray::from_slice(&data.key),
                        iv,
                        data.tweak,
                        GenericArray::from_slice(&data.uhash),
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd.as_slice());
                    assert_eq!(com.as_slice(), data.expected_com.as_slice());
                }

                256 => {
                    println!("lambda = 256 - testing leaf_commitment..");
                    let (sd, com) = LeafCommitment::<PRG256, LeafHasher256>::commit(
                        GenericArray::from_slice(&data.key),
                        iv,
                        data.tweak,
                        GenericArray::from_slice(&data.uhash),
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
                        GenericArray::from_slice(&data.key),
                        iv,
                        data.tweak,
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd.as_slice());
                    assert_eq!(com.as_slice(), data.expected_com.as_slice());
                }

                192 => {
                    println!("lambda = 192 - testing leaf_commitment_em..");
                    let (sd, com) = LeafCommitment::<PRG192, LeafHasher192>::commit_em(
                        GenericArray::from_slice(&data.key),
                        iv,
                        data.tweak,
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd.as_slice());
                    assert_eq!(com.as_slice(), data.expected_com.as_slice());
                }

                256 => {
                    println!("lambda = 256 - testing leaf_commitment_em..");
                    let (sd, com) = LeafCommitment::<PRG256, LeafHasher256>::commit_em(
                        GenericArray::from_slice(&data.key),
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

        let database: Vec<DataBAVAC> = read_test_data("bavc.json");
        for data in database {
            match data.lambda {
                128 => {
                    let r = GenericArray::from_slice(&r[..16]);

                    if data.mode == "s" {
                        println!("FAEST-128s - testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC128Small::commit(r, &iv);

                        let res_open = BAVC128Small::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC128Small::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau128Small>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        println!("FAEST-128f - testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC128Fast::commit(r, &iv);

                        let res_open = BAVC128Fast::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC128Fast::reconstruct(&res_open, i_delta, &iv).unwrap();

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

                        let res_commit = BAVC192Small::commit(r, &iv);

                        let res_open = BAVC192Small::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC192Small::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau192Small>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        println!("FAEST-192f - testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC192Fast::commit(r, &iv);

                        let res_open = BAVC192Fast::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC192Fast::reconstruct(&res_open, i_delta, &iv).unwrap();
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

                        let res_commit = BAVC256Small::commit(&r, &iv);

                        let res_open = BAVC256Small::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC256Small::reconstruct(&res_open, i_delta, &iv).unwrap();
                        compare_expected_with_result::<_, _, Tau256Small>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        println!("FAEST-256f - testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC256Fast::commit(&r, &iv);

                        let res_open = BAVC256Fast::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC256Fast::reconstruct(&res_open, i_delta, &iv).unwrap();
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

                        let res_commit = BAVC128SmallEM::commit(r, &iv);

                        let res_open = BAVC128SmallEM::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC128SmallEM::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau128SmallEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        println!("FAEST-EM-128f: testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC128FastEM::commit(r, &iv);

                        let res_open = BAVC128FastEM::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC128FastEM::reconstruct(&res_open, i_delta, &iv).unwrap();

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

                        let res_commit = BAVC192SmallEM::commit(r, &iv);

                        let res_open = BAVC192SmallEM::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC192SmallEM::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau192SmallEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        println!("FAEST-EM-192f: testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC192FastEM::commit(r, &iv);

                        let res_open = BAVC192FastEM::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC192FastEM::reconstruct(&res_open, i_delta, &iv).unwrap();

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

                        let res_commit = BAVC256SmallEM::commit(&r, &iv);

                        let res_open = BAVC256SmallEM::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC256SmallEM::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau256SmallEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        println!("FAEST-EM-256f: testing BAVC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC256FastEM::commit(&r, &iv);

                        let res_open = BAVC256FastEM::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC256FastEM::reconstruct(&res_open, i_delta, &iv).unwrap();

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
