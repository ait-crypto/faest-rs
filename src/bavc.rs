use core::panic;
use std::{
    convert, default,
    marker::PhantomData,
    ops::{Add, Mul},
    process::id,
    vec,
};

use aes::cipher::KeyInit;
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
    type LambdaBytesTimesTwo = LH::LambdaBytesTimes2;
    type LambdaByesTimesThree = LH::LambdaBytesTimesThree;
    type LambdaByesTimesFour = LH::LambdaBytesTimesFour;
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
        GenericArray<u8, Self::LambdaBytesTimesTwo>,
    ) {
        // Step 1
        let com = PRG::new_prg(r, iv, tweak).read_into();

        // Step 2
        let sd = r.to_owned();

        (sd, com)
    }
}

// Easiest thing would be to implement distinct traits for BAVAC and BAVAC_em
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

    // Here we loose structure as GenericArray only implement AsRef<&[u8]>
    fn open<'a>(
        decom: (
            &'a [GenericArray<u8, Self::LambdaBytes>],
            &'a [GenericArray<u8, Self::LambdaBytesTimes3>],
        ),
        i_delta: &GenericArray<u16, Self::Tau>,
    ) -> Option<(
        Vec<&'a [u8]>, // com
        Vec<&'a [u8]>, // nodes
    )>;

    fn reconstruct(
        decom_i: (&[&[u8]], &[&[u8]]),
        i_delta: &GenericArray<u16, Self::Tau>,
        iv: &IV,
    ) -> Option<(
        GenericArray<u8, Self::LambdaBytesTimes2>, // commitment
        Vec<GenericArray<u8, Self::LambdaBytes>>,  // seeds
    )>;
}

pub(crate) trait BatchVectorCommitmentEM {
    type LambdaBytes: ArrayLength;
    type LambdaBytesTimes2: ArrayLength;
    type LambdaBytesTimes3: ArrayLength;
    type LC: LeafCommit;
    type Tau: ArrayLength;

    fn commit_em(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
    ) -> (
        //com
        GenericArray<u8, Self::LambdaBytesTimes2>,
        //decom
        (
            Vec<GenericArray<u8, Self::LambdaBytes>>,
            Vec<GenericArray<u8, Self::LambdaBytesTimes2>>,
        ),
        //seeds
        Vec<GenericArray<u8, Self::LambdaBytes>>,
    );

    // Here we loose structure as GenericArray only implement AsRef<&[u8]>
    fn open_em<'a>(
        decom: (
            &'a [GenericArray<u8, Self::LambdaBytes>],
            &'a [GenericArray<u8, Self::LambdaBytesTimes2>],
        ),
        i_delta: &GenericArray<u16, Self::Tau>,
    ) -> Option<(
        Vec<&'a [u8]>, // com
        Vec<&'a [u8]>, // nodes
    )>;

    fn reconstruct_em(
        decom_i: (&[&[u8]], &[&[u8]]),
        i_delta: &GenericArray<u16, Self::Tau>,
        iv: &IV,
    ) -> Option<(
        GenericArray<u8, Self::LambdaBytesTimes2>, // commitment
        Vec<GenericArray<u8, Self::LambdaBytes>>,  // seeds
    )>;
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
    #[inline]
    fn construct_keys(
        r: &GenericArray<u8, LH::LambdaBytes>,
        iv: &IV,
    ) -> Vec<GenericArray<u8, <LH as LeafHasher>::LambdaBytes>> {
        let mut keys = vec![GenericArray::default(); 2 * TAU::L::USIZE - 1];
        keys[0].copy_from_slice(r);

        for alpha in 0..TAU::L::USIZE - 1 {
            let mut prg = PRG::new_prg(&keys[alpha], &iv, alpha as TWK);
            prg.read(&mut keys[2 * alpha + 1]);
            prg.read(&mut keys[2 * alpha + 2]);
        }

        keys
    }

    #[inline]
    fn reconstruct_keys(
        s: &mut BitSet,
        decom_keys: &[&[u8]],
        i_delta: &GenericArray<u16, TAU::Tau>,
        iv: &IV,
    ) -> Option<Vec<GenericArray<u8, LH::LambdaBytes>>> {
        // Steps 8..11
        for i in 0..TAU::Tau::USIZE {
            let alpha = TAU::pos_in_tree(i, i_delta[i] as usize);
            s.insert(alpha);
        }

        // Steps 13..21
        let mut keys = vec![GenericArray::default(); 2 * TAU::L::USIZE - 1];
        let mut decom_iter = decom_keys.iter();
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
                    return None;
                }
            }
        }

        // Step 22: in BAVAC::open we don't actually pad decom with 0s => we must have reached the end of the iterator
        if decom_iter.next().is_some() {
            return None;
        }

        // Steps 25..27
        for i in 0..TAU::L::USIZE - 1 {
            if !s.contains(i) {
                let mut rng = PRG::new_prg(&keys[i], iv, i as TWK);
                rng.read(&mut keys[2 * i + 1]);
                rng.read(&mut keys[2 * i + 2]);
            }
        }

        Some(keys)
    }

    #[inline]
    fn mark_nodes(s: &mut BitSet, i_delta: &GenericArray<u16, TAU::Tau>) -> Option<u32> {
        // Steps 6 ..15
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

        // Step 16
        if n_h - 2 * TAU::Tau::U32 + 1 > TAU::Topen::U32 {
            println!("{n_h}, {}", 2 * TAU::Tau::U32 - 1 + TAU::Topen::U32);
            return None;
        }

        Some(n_h)
    }
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
    type LambdaBytesTimes3 = LH::LambdaBytesTimesThree;
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
        // Step 3
        let mut h0_hasher = RO::h0_init();
        h0_hasher.update(&iv);
        let mut h0_hasher = h0_hasher.finish();

        // Steps 5..7
        let keys = Self::construct_keys(r, iv);

        // Setps 8..13
        let mut com_hasher = RO::h1_init();
        let mut sd = vec![GenericArray::default(); TAU::L::USIZE];
        let mut com = vec![GenericArray::default(); TAU::L::USIZE];
        for i in 0..TAU::Tau::U32 {
            // Step 2
            let mut hi_hasher = RO::h1_init();
            let mut uhash_i = GenericArray::default();
            h0_hasher.read(&mut uhash_i);

            let n_i = TAU::bavac_max_node_index(i as usize);
            for j in 0..n_i {
                let alpha = TAU::pos_in_tree(i as usize, j);
                let idx = TAU::convert_index(i as usize) + j;
                let tweak = i + TAU::L::U32 - 1;

                (sd[idx], com[idx]) = Self::LC::commit(&keys[alpha], &iv, tweak, &uhash_i);
                hi_hasher.update(&com[idx]);
            }

            // Step 14
            com_hasher.update(&hi_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        // Steps 15, 16
        let decom = (keys, com);
        let com = com_hasher.finish().read_into();

        (com, decom, sd)
    }

    fn open<'a>(
        decom: (
            &'a [GenericArray<u8, Self::LambdaBytes>],
            &'a [GenericArray<u8, Self::LambdaBytesTimes3>],
        ),
        i_delta: &GenericArray<u16, TAU::Tau>,
    ) -> Option<(
        Vec<&'a [u8]>, // com
        Vec<&'a [u8]>, // nodes
    )> {
        // Step 5
        let mut s = BitSet::with_capacity(2 * TAU::L::USIZE - 1);

        // Steps 6..17
        if Self::mark_nodes(&mut s, i_delta).is_none() {
            return None;
        }

        // Steps 19..23
        let nodes_i = (0..TAU::L::USIZE - 1)
            .rev()
            .filter_map(|i| {
                if s.contains(2 * i + 1) ^ s.contains(2 * i + 2) {
                    let alpha = 2 * i + 1 + (s.contains(2 * i + 1) as usize);
                    return Some(decom.0[alpha].as_ref());
                }
                None
            })
            .collect();

        // Skip step 24: as we know expected nodes len we can keep the 0s-pad implicit

        // Step 3
        let com_i = (0..TAU::Tau::USIZE)
            .map(|i| decom.1[TAU::convert_index(i) + i_delta[i] as usize].as_ref())
            .collect();

        Some((com_i, nodes_i))
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
        let keys = Self::reconstruct_keys(&mut s, &decom_i.1, i_delta, iv).unwrap_or_default();
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

            let n_i = TAU::bavac_max_node_index(i as usize);
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

impl<RO, PRG, LH, TAU> BatchVectorCommitmentEM for BAVC<RO, PRG, LH, TAU>
where
    RO: RandomOracle,
    PRG: PseudoRandomGenerator<KeySize = LH::LambdaBytes>,
    TAU: TauParameters,
    LH: LeafHasher,
{
    type LambdaBytes = LH::LambdaBytes;
    type LambdaBytesTimes2 = LH::LambdaBytesTimes2;
    type LambdaBytesTimes3 = LH::LambdaBytesTimesThree;
    type LC = LeafCommitment<PRG, LH>;
    type Tau = TAU::Tau;

    fn commit_em(
        r: &GenericArray<u8, Self::LambdaBytes>,
        iv: &IV,
    ) -> (
        //com
        GenericArray<u8, Self::LambdaBytesTimes2>,
        //decom
        (
            Vec<GenericArray<u8, Self::LambdaBytes>>,
            Vec<GenericArray<u8, Self::LambdaBytesTimes2>>,
        ),
        //seeds
        Vec<GenericArray<u8, Self::LambdaBytes>>,
    ) {
        // Steps 5..7
        let keys = Self::construct_keys(r, iv);

        // Setps 8..13
        let mut com_hasher = RO::h1_init();
        let mut sd = vec![GenericArray::default(); TAU::L::USIZE];
        let mut com = vec![GenericArray::default(); TAU::L::USIZE];
        for i in 0..TAU::Tau::U32 {
            let mut hi_hasher = RO::h1_init();

            let n_i = TAU::bavac_max_node_index(i as usize);
            for j in 0..n_i {
                let alpha = TAU::pos_in_tree(i as usize, j);
                let idx = TAU::convert_index(i as usize) + j;
                let tweak = i + TAU::L::U32 - 1;

                (sd[idx], com[idx]) = Self::LC::commit_em(&keys[alpha], &iv, tweak);

                // Step 13
                hi_hasher.update(&com[idx]);
            }

            // Step 14
            com_hasher.update(&hi_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        // Steps 15, 16
        let decom = (keys, com);
        let com = com_hasher.finish().read_into();
        (com, decom, sd)
    }

    fn open_em<'a>(
        decom: (
            &'a [GenericArray<u8, Self::LambdaBytes>],
            &'a [GenericArray<u8, Self::LambdaBytesTimes2>],
        ),
        i_delta: &GenericArray<u16, Self::Tau>,
    ) -> Option<(
        Vec<&'a [u8]>, // com
        Vec<&'a [u8]>, // nodes
    )> {
        // Step 5
        let mut s = BitSet::with_capacity(2 * TAU::L::USIZE - 1);

        // Steps 6..17
        if Self::mark_nodes(&mut s, i_delta).is_none() {
            return None;
        }

        // Steps 19..23
        let nodes_i = (0..TAU::L::USIZE - 1)
            .rev()
            .filter_map(|i| {
                if s.contains(2 * i + 1) ^ s.contains(2 * i + 2) {
                    let alpha = 2 * i + 1 + (s.contains(2 * i + 1) as usize);
                    return Some(decom.0[alpha].as_ref());
                }
                None
            })
            .collect();

        // Skip step 24: as we know expected nodes len we can keep the 0s-pad implicit

        // Step 3
        let com_i = (0..TAU::Tau::USIZE)
            .map(|i| decom.1[TAU::convert_index(i) + i_delta[i] as usize].as_ref())
            .collect();

        Some((com_i, nodes_i))
    }

    fn reconstruct_em(
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

            let n_i = TAU::bavac_max_node_index(i as usize);
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

    type Result<'a, Lambda, Lambda2, Lambda3> = (
        // Commit
        (
            GenericArray<u8, Lambda2>,
            (
                Vec<GenericArray<u8, Lambda>>,
                Vec<GenericArray<u8, Lambda3>>,
            ),
            Vec<GenericArray<u8, Lambda>>,
        ),
        // Open
        (
            Vec<&'a [u8]>, // com
            Vec<&'a [u8]>, // nodes
        ),
        // Reconstruct
        (
            GenericArray<u8, Lambda2>,     // commitment
            Vec<GenericArray<u8, Lambda>>, // seeds
        ),
    );

    fn compare_expected_with_result<
        Lambda: ArrayLength,
        Lambda2: ArrayLength,
        Lambda3: ArrayLength,
        TAU: TauParameters,
    >(
        expected: &DataBAVAC,
        res: Result<Lambda, Lambda2, Lambda3>,
        n_leafcom: usize,
    ) {
        let ((h, (k, coms), sd), decom_i, (rec_h, rec_sd)) = res;

        let hashed_sd = hash_array(&sd.iter().flat_map(|x| x.clone()).collect::<Vec<u8>>());
        let hashed_k = hash_array(&k.iter().flat_map(|x| x.clone()).collect::<Vec<u8>>());
        let hashed_coms = hash_array(&coms.iter().flat_map(|x| x.clone()).collect::<Vec<u8>>());

        // Check commitment
        assert_eq!(expected.h.as_slice(), h.as_slice());
        assert_eq!(expected.hashed_sd.as_slice(), hashed_sd.as_slice());
        assert_eq!(expected.hashed_k.as_slice(), hashed_k.as_slice());
        assert_eq!(expected.hashed_com.as_slice(), hashed_coms.as_slice());

        // Check decommitment
        let mut data_decom: Vec<u8> = decom_i
            .0
            .into_iter()
            .flat_map(|v| v.to_vec())
            .chain(decom_i.1.into_iter().flat_map(|v| v.to_vec()))
            .collect::<Vec<u8>>();
        // As we skipped step 22 in BAVAC::commit we need to pad accordingly before checking result
        let decom_size =
            n_leafcom * Lambda::USIZE * TAU::Tau::USIZE + TAU::Topen::USIZE * Lambda::USIZE;
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

    #[test]
    fn bavac_test() {
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
                        println!("FAEST-128s - testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128Small,
                        >::commit(r, &iv);

                        let res_open = BAVC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128Small,
                        >::open(
                            (res_commit.1 .0.as_slice(), res_commit.1 .1.as_slice()),
                            &i_delta,
                        )
                        .unwrap();

                        let res_reconstruct = BAVC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128Small,
                        >::reconstruct(
                            (res_open.0.as_slice(), res_open.1.as_slice()),
                            &i_delta,
                            &iv,
                        )
                        .unwrap();

                        compare_expected_with_result::<_, _, _, Tau128Small>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                            3,
                        );
                    } else {
                        println!("FAEST-128f - testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128Fast,
                        >::commit(r, &iv);

                        let res_open =
                            BAVC::<RandomOracleShake128, PRG128, LeafHasher128, Tau128Fast>::open(
                                (&res_commit.1 .0, &res_commit.1 .1),
                                &i_delta,
                            )
                            .unwrap();

                        let res_reconstruct = BAVC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128Fast,
                        >::reconstruct(
                            (res_open.0.as_slice(), res_open.1.as_slice()),
                            &i_delta,
                            &iv,
                        )
                        .unwrap();

                        compare_expected_with_result::<_, _, _, Tau128Fast>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                            3,
                        );
                    }
                }
                192 => {
                    let r = GenericArray::from_slice(&r[..24]);

                    if data.mode == "s" {
                        println!("FAEST-192s - testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192Small,
                        >::commit(r, &iv);

                        let res_open = BAVC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192Small,
                        >::open(
                            (&res_commit.1 .0, &res_commit.1 .1), &i_delta
                        )
                        .unwrap();

                        let res_reconstruct = BAVC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192Small,
                        >::reconstruct(
                            (res_open.0.as_slice(), res_open.1.as_slice()),
                            &i_delta,
                            &iv,
                        )
                        .unwrap();

                        compare_expected_with_result::<_, _, _, Tau192Small>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                            3,
                        );
                    } else {
                        println!("FAEST-192f - testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192Fast,
                        >::commit(r, &iv);

                        let res_open =
                            BAVC::<RandomOracleShake256, PRG192, LeafHasher192, Tau192Fast>::open(
                                (&res_commit.1 .0, &res_commit.1 .1),
                                &i_delta,
                            )
                            .unwrap();

                        let res_reconstruct = BAVC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192Fast,
                        >::reconstruct(
                            (res_open.0.as_slice(), res_open.1.as_slice()),
                            &i_delta,
                            &iv,
                        )
                        .unwrap();
                        compare_expected_with_result::<_, _, _, Tau192Fast>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                            3,
                        );
                    }
                }
                _ => {
                    if data.mode == "s" {
                        println!("FAEST-256s - testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256Small,
                        >::commit(&r, &iv);

                        let res_open = BAVC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256Small,
                        >::open(
                            (&res_commit.1 .0, &res_commit.1 .1), &i_delta
                        )
                        .unwrap();

                        let res_reconstruct = BAVC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256Small,
                        >::reconstruct(
                            (res_open.0.as_slice(), res_open.1.as_slice()),
                            &i_delta,
                            &iv,
                        )
                        .unwrap();
                        compare_expected_with_result::<_, _, _, Tau256Small>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                            3,
                        );
                    } else {
                        println!("FAEST-256f - testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256Fast,
                        >::commit(&r, &iv);

                        let res_open =
                            BAVC::<RandomOracleShake256, PRG256, LeafHasher256, Tau256Fast>::open(
                                (&res_commit.1 .0, &res_commit.1 .1),
                                &i_delta,
                            )
                            .unwrap();

                        let res_reconstruct = BAVC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256Fast,
                        >::reconstruct(
                            (res_open.0.as_slice(), res_open.1.as_slice()),
                            &i_delta,
                            &iv,
                        )
                        .unwrap();
                        compare_expected_with_result::<_, _, _, Tau256Fast>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                            3,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn bavac_em_test() {
        let r: GenericArray<u8, _> = GenericArray::from_array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let iv: IV = GenericArray::from_array([
            0x64, 0x2b, 0xb1, 0xf9, 0x7c, 0x5f, 0x97, 0x9a, 0x72, 0xb1, 0xee, 0x39, 0xbe, 0x4e,
            0x78, 0x22,
        ]);

        let database: Vec<DataBAVAC> = read_test_data("bavac_em.json");
        for data in database {
            match data.lambda {
                128 => {
                    let r = GenericArray::from_slice(&r[..16]);

                    if data.mode == "s" {
                        println!("FAEST-EM-128s: testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128SmallEM,
                        >::commit_em(r, &iv);

                        let res_open = BAVC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128SmallEM,
                        >::open_em(
                            (&res_commit.1 .0, &res_commit.1 .1), &i_delta
                        )
                        .unwrap();

                        let res_reconstruct = BAVC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128SmallEM,
                        >::reconstruct_em(
                            (&res_open.0, &res_open.1), &i_delta, &iv
                        )
                        .unwrap();

                        compare_expected_with_result::<_, _, _, Tau128SmallEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                            2,
                        );
                    } else {
                        println!("FAEST-EM-128f: testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128FastEM,
                        >::commit_em(r, &iv);

                        let res_open = BAVC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128FastEM,
                        >::open_em(
                            (&res_commit.1 .0, &res_commit.1 .1), &i_delta
                        )
                        .unwrap();

                        let res_reconstruct = BAVC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128FastEM,
                        >::reconstruct_em(
                            (res_open.0.as_slice(), res_open.1.as_slice()),
                            &i_delta,
                            &iv,
                        )
                        .unwrap();

                        compare_expected_with_result::<_, _, _, Tau128FastEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                            2,
                        );
                    }
                }
                192 => {
                    let r = GenericArray::from_slice(&r[..24]);

                    if data.mode == "s" {
                        println!("FAEST-EM-192s: testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192SmallEM,
                        >::commit_em(r, &iv);


                        let res_open = BAVC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192SmallEM,
                        >::open_em(
                            (&res_commit.1 .0, &res_commit.1 .1), &i_delta
                        )
                        .unwrap();

                        let res_reconstruct = BAVC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192SmallEM,
                        >::reconstruct_em(
                            (res_open.0.as_slice(), res_open.1.as_slice()),
                            &i_delta,
                            &iv,
                        )
                        .unwrap();

                        compare_expected_with_result::<_, _, _, Tau192SmallEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                            2,
                        );
                    } else {
                        println!("FAEST-EM-192f: testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192FastEM,
                        >::commit_em(r, &iv);

                        let res_open = BAVC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192FastEM,
                        >::open_em(
                            (&res_commit.1 .0, &res_commit.1 .1), &i_delta
                        )
                        .unwrap();

                        let res_reconstruct = BAVC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192FastEM,
                        >::reconstruct_em(
                            (res_open.0.as_slice(), res_open.1.as_slice()),
                            &i_delta,
                            &iv,
                        )
                        .unwrap();

                        compare_expected_with_result::<_, _, _, Tau192FastEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                            2,
                        );
                    }
                }
                _ => {
                    if data.mode == "s" {
                        println!("FAEST-EM-256s: testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256SmallEM,
                        >::commit_em(&r, &iv);

                        let res_open = BAVC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256SmallEM,
                        >::open_em(
                            (&res_commit.1 .0, &res_commit.1 .1), &i_delta
                        )
                        .unwrap();

                        let res_reconstruct = BAVC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256SmallEM,
                        >::reconstruct_em(
                            (res_open.0.as_slice(), res_open.1.as_slice()),
                            &i_delta,
                            &iv,
                        )
                        .unwrap();

                        compare_expected_with_result::<_, _, _, Tau256SmallEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                            2,
                        );
                    } else {
                        println!("FAEST-EM-256f: testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        let res_commit = BAVC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256FastEM,
                        >::commit_em(&r, &iv);

                        let res_open = BAVC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256FastEM,
                        >::open_em(
                            (&res_commit.1 .0, &res_commit.1 .1), &i_delta
                        )
                        .unwrap();

                        let res_reconstruct = BAVC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256FastEM,
                        >::reconstruct_em(
                            (res_open.0.as_slice(), res_open.1.as_slice()),
                            &i_delta,
                            &iv,
                        )
                        .unwrap();

                        compare_expected_with_result::<_, _, _, Tau256FastEM>(
                            &data,
                            (res_commit.clone(), res_open, res_reconstruct),
                            2,
                        );
                    }
                }
            }
        }
    }
}
