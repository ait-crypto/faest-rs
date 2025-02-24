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
    ) -> Result<
        (
            Box<GenericArray<u8, Self::LambdaBytesTimes2>>, // commitment
            Vec<GenericArray<u8, Self::LambdaBytes>>,       // seeds
        ),
        Box<dyn std::error::Error>,
    >;
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

    // TODO: use references instead of cloning values for decommitment info
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
            return Err("BAVAC open: Chosen path larger than treshold".into());
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
    ) -> Result<
        (
            Box<GenericArray<u8, Self::LambdaBytesTimes2>>, // commitment
            Vec<GenericArray<u8, Self::LambdaBytes>>,       // seeds
        ),
        Box<dyn std::error::Error>,
    > {
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
                    return Err(
                        "BAVAC reconstruct: cannot expand tree (nodes array too short)".into(),
                    );
                }
            }
        }

        // Steps 22,23
        while let Some(k) = decom_iter.next() {
            if *k != GenericArray::default() {
                return Err("BAVAC reconstruct: cannot expand tree (nodes array too long)".into());
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
                        return Err("BAVAC reconstruct: cannot generate BAVAC commitment (commitment vector too short)".into());
                    }
                }
            }
            h1_com_hasher.update(&h1_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        Ok((Box::new(h1_com_hasher.finish().read_into()), seeds))
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

    type Result<Lambda, Lambda2, Lambda3> = (
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
            Vec<GenericArray<u8, Lambda3>>, // com
            Vec<GenericArray<u8, Lambda>>,  // nodes
        ),
        // Reconstruct
        (
            Box<GenericArray<u8, Lambda2>>, // commitment
            Vec<GenericArray<u8, Lambda>>,  // seeds
        ),
    );

    fn compare_expected_with_result<
        Lambda: ArrayLength,
        Lambda2: ArrayLength,
        Lambda3: ArrayLength,
    >(
        expected: &DataBAVAC,
        res: Result<Lambda, Lambda2, Lambda3>,
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
        let data_decom = decom_i
            .0
            .iter()
            .flat_map(|v| v.clone())
            .chain(decom_i.1.iter().flat_map(|v| v.clone()))
            .collect::<Vec<u8>>();
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

        let iv: IV = GenericArray::from_array([
            0x64, 0x2b, 0xb1, 0xf9, 0x7c, 0x5f, 0x97, 0x9a, 0x72, 0xb1, 0xee, 0x39, 0xbe, 0x4e,
            0x78, 0x22,
        ]);

        let database: Vec<DataBAVAC> = read_test_data("bavac_com.json");
        for data in database {
            match data.lambda {
                128 => {
                    let r = GenericArray::from_slice(&r[..16]);
                    let res_commit;
                    let res_open;
                    let res_reconstruct;

                    if data.mode == "s" {
                        println!("FAEST-128s - testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        res_commit = BAVAC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128Small,
                        >::commit(r, &iv);

                        res_open = BAVAC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128Small,
                        >::open(&res_commit.1, &i_delta)
                        .unwrap();

                        res_reconstruct = BAVAC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128Small,
                        >::reconstruct(
                            &res_open, &i_delta, &iv
                        )
                        .unwrap();
                    } else {
                        println!("FAEST-128f - testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        res_commit = BAVAC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128Fast,
                        >::commit(r, &iv);

                        res_open =
                            BAVAC::<RandomOracleShake128, PRG128, LeafHasher128, Tau128Fast>::open(
                                &res_commit.1,
                                &i_delta,
                            )
                            .unwrap();

                        res_reconstruct = BAVAC::<
                            RandomOracleShake128,
                            PRG128,
                            LeafHasher128,
                            Tau128Fast,
                        >::reconstruct(
                            &res_open, &i_delta, &iv
                        )
                        .unwrap();
                    }

                    compare_expected_with_result(&data, (res_commit, res_open, res_reconstruct));
                }
                192 => {
                    let r = GenericArray::from_slice(&r[..24]);
                    let res_commit;
                    let res_open;
                    let res_reconstruct;

                    if data.mode == "s" {
                        println!("FAEST-192s - testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        res_commit = BAVAC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192Small,
                        >::commit(r, &iv);

                        res_open = BAVAC::<
                        RandomOracleShake256, PRG192, LeafHasher192, Tau192Small
                        >::open(&res_commit.1, &i_delta)
                        .unwrap();

                        res_reconstruct = BAVAC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192Small,
                        >::reconstruct(
                            &res_open, &i_delta, &iv
                        )
                        .unwrap();
                    } else {
                        println!("FAEST-192f - testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        res_commit = BAVAC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192Fast,
                        >::commit(r, &iv);

                        res_open =
                            BAVAC::<RandomOracleShake256, PRG192, LeafHasher192, Tau192Fast>::open(
                                &res_commit.1,
                                &i_delta,
                            )
                            .unwrap();

                        res_reconstruct = BAVAC::<
                            RandomOracleShake256,
                            PRG192,
                            LeafHasher192,
                            Tau192Fast,
                        >::reconstruct(
                            &res_open, &i_delta, &iv
                        )
                        .unwrap();
                    }

                    compare_expected_with_result(&data, (res_commit, res_open, res_reconstruct));
                }
                _ => {
                    let res_commit;
                    let res_open;
                    let res_reconstruct;

                    if data.mode == "s" {
                        println!("FAEST-256s - testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        res_commit = BAVAC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256Small,
                        >::commit(&r, &iv);

                        res_open = BAVAC::<
                        RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256Small,
                        >::open(&res_commit.1, &i_delta)
                        .unwrap();

                        res_reconstruct = BAVAC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256Small,
                        >::reconstruct(
                            &res_open, &i_delta, &iv
                        )
                        .unwrap();
                    } else {
                        println!("FAEST-256f - testing BAVAC..");

                        let i_delta = GenericArray::from_slice(&data.i_delta);

                        res_commit = BAVAC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256Fast,
                        >::commit(&r, &iv);

                        res_open = BAVAC::<RandomOracleShake256,
                        PRG256,
                        LeafHasher256,
                        Tau256Fast,
                        >::open(&res_commit.1, &i_delta)
                        .unwrap();

                        res_reconstruct = BAVAC::<
                            RandomOracleShake256,
                            PRG256,
                            LeafHasher256,
                            Tau256Fast,
                        >::reconstruct(
                            &res_open, &i_delta, &iv
                        )
                        .unwrap();
                    }
                    compare_expected_with_result(&data, (res_commit, res_open, res_reconstruct));
                }
            }
        }
    }
}
