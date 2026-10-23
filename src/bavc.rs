//! Batch all-but-one vector commitments.
//!
//! Algorithm line references follow FAEST v3, Figures 5.3–5.5:
//! <https://faest.info/faest-spec-v3.0.pdf>

use core::{marker::PhantomData, ops::Mul};

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, vec, vec::Vec};

use bitvec::{bitvec, slice::BitSlice};
use hybrid_array::{
    Array, ArraySize,
    typenum::{Prod, U2, U3, U8, Unsigned},
};

use crate::{
    parameter::{SecurityParameter, TauParameters},
    prg::{IV, PseudoRandomGenerator, Twk},
    random_oracles::{Hasher, RandomOracle},
    universal_hashing::LeafHasher,
    utils::Reader,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct BavcCommitResult<LambdaBytes, NLeafCommit>
where
    LambdaBytes: ArraySize + Mul<U2, Output: ArraySize> + Mul<NLeafCommit, Output: ArraySize>,
    NLeafCommit: ArraySize,
{
    pub com: Array<u8, Prod<LambdaBytes, U2>>,
    pub decom: BavcDecommitment<LambdaBytes, NLeafCommit>,
    pub seeds: Vec<Array<u8, LambdaBytes>>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BavcOpenResult<'a> {
    pub coms: Vec<&'a [u8]>,
    pub nodes: Vec<&'a [u8]>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BavcReconstructResult<LambdaBytes>
where
    LambdaBytes: ArraySize + Mul<U2, Output: ArraySize>,
{
    pub com: Array<u8, Prod<LambdaBytes, U2>>,
    pub seeds: Vec<Array<u8, LambdaBytes>>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BavcDecommitment<LambdaBytes, NLeafCommit>
where
    LambdaBytes: ArraySize + Mul<NLeafCommit, Output: ArraySize>,
    NLeafCommit: ArraySize,
{
    keys: Vec<Array<u8, LambdaBytes>>,
    coms: Vec<Array<u8, Prod<LambdaBytes, NLeafCommit>>>,
}

pub(crate) trait LeafCommit {
    type LambdaBytes: SecurityParameter + Mul<Self::NLeafCommit, Output: ArraySize>;
    type PRG: PseudoRandomGenerator<KeySize = Self::LambdaBytes>;
    type NLeafCommit: ArraySize;
    type Context;

    fn init<RO: RandomOracle>(iv: &IV) -> Self::Context;

    fn commit(
        r: &Array<u8, Self::LambdaBytes>,
        iv: &IV,
        tweak: Twk,
        context: &Self::Context,
    ) -> (
        Array<u8, Self::LambdaBytes>,
        Array<u8, Prod<Self::LambdaBytes, Self::NLeafCommit>>,
    );
}

pub(crate) struct LeafCommitment<PRG, LH>(PhantomData<(PRG, LH)>);

impl<PRG, LH> LeafCommit for LeafCommitment<PRG, LH>
where
    PRG: PseudoRandomGenerator<KeySize = LH::LambdaBytes>,
    LH: LeafHasher,
{
    type LambdaBytes = LH::LambdaBytes;
    type PRG = PRG;
    type NLeafCommit = U3;
    type Context = Array<u8, Prod<LH::LambdaBytes, U3>>;

    fn init<RO: RandomOracle>(iv: &IV) -> Self::Context {
        let mut hasher = RO::h0_init();
        hasher.update(iv);
        hasher.finish().read_into()
    }

    fn commit(
        r: &Array<u8, Self::LambdaBytes>,
        iv: &IV,
        tweak: Twk,
        uhash: &Self::Context,
    ) -> (
        Array<u8, Self::LambdaBytes>,
        Array<u8, Prod<Self::LambdaBytes, Self::NLeafCommit>>,
    ) {
        let hash = PRG::new_prg(r, iv, tweak).read_into();
        let com = <LH as LeafHasher>::hash(uhash, &hash);
        let sd = hash.into_iter().take(Self::LambdaBytes::USIZE).collect();

        (sd, com)
    }
}

pub(crate) struct LeafCommitmentEm<PRG>(PhantomData<PRG>);

impl<PRG> LeafCommit for LeafCommitmentEm<PRG>
where
    PRG: PseudoRandomGenerator,
    PRG::KeySize:
        Mul<U2, Output: ArraySize> + Mul<U3, Output: ArraySize> + Mul<U8, Output: ArraySize>,
{
    type LambdaBytes = PRG::KeySize;
    type PRG = PRG;
    type NLeafCommit = U2;
    type Context = ();

    fn init<RO: RandomOracle>(_iv: &IV) -> Self::Context {}

    fn commit(
        r: &Array<u8, Self::LambdaBytes>,
        iv: &IV,
        tweak: Twk,
        _context: &Self::Context,
    ) -> (
        Array<u8, Self::LambdaBytes>,
        Array<u8, Prod<Self::LambdaBytes, Self::NLeafCommit>>,
    ) {
        let com = PRG::new_prg(r, iv, tweak).read_into();
        let sd = r.to_owned();

        (sd, com)
    }
}

fn construct_keys<PRG, TAU>(r: &Array<u8, PRG::KeySize>, iv: &IV) -> Vec<Array<u8, PRG::KeySize>>
where
    PRG: PseudoRandomGenerator,
    TAU: TauParameters,
{
    // BAVC.Commit, lines 3–5
    let mut keys = vec![Array::default(); 2 * TAU::L - 1];
    keys[0].copy_from_slice(r);

    for alpha in 0..TAU::L - 1 {
        let mut prg = PRG::new_prg(&keys[alpha], iv, alpha as Twk);
        prg.read(&mut keys[2 * alpha + 1]);
        prg.read(&mut keys[2 * alpha + 2]);
    }

    keys
}

fn reconstruct_keys<PRG, TAU>(
    s: &mut BitSlice,
    decom_keys: &[&[u8]],
    i_delta: &Array<u16, TAU::Tau>,
    iv: &IV,
) -> Option<Vec<Array<u8, PRG::KeySize>>>
where
    PRG: PseudoRandomGenerator,
    TAU: TauParameters,
{
    // BAVC.Reconstruct, lines 6–9
    for i in 0..TAU::Tau::USIZE {
        let alpha = TAU::pos_in_tree(i, i_delta[i] as usize);
        s.set(alpha, true);
    }

    // BAVC.Reconstruct, lines 11–19
    let mut keys = vec![Array::default(); 2 * TAU::L - 1];
    let mut decom_iter = decom_keys.iter();
    for i in (0..TAU::L - 1).rev() {
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

    // BAVC.Reconstruct, lines 20–21
    for &pad in decom_iter {
        if pad.iter().any(|&x| x != 0) {
            return None;
        }
    }

    // BAVC.Reconstruct, lines 23–25
    for i in s[..TAU::L - 1].iter_zeros() {
        let mut rng = PRG::new_prg(&keys[i], iv, i as Twk);
        rng.read(&mut keys[2 * i + 1]);
        rng.read(&mut keys[2 * i + 2]);
    }

    Some(keys)
}

fn mark_nodes<TAU>(s: &mut BitSlice, i_delta: &Array<u16, TAU::Tau>) -> Option<u32>
where
    TAU: TauParameters,
{
    // BAVC.Open, lines 6–15
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

    // BAVC.Open, lines 16–17
    if n_h - 2 * TAU::Tau::U32 + 1 > TAU::Topen::U32 {
        None
    } else {
        Some(n_h)
    }
}

fn construct_nodes<'a, LambdaBytes, TAU>(
    keys: &'a [Array<u8, LambdaBytes>],
    s: &BitSlice,
) -> Vec<&'a [u8]>
where
    LambdaBytes: ArraySize,
    TAU: TauParameters,
{
    // BAVC.Open, lines 19–22
    (0..TAU::L - 1)
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

pub(crate) trait BatchVectorCommitment {
    type PRG: PseudoRandomGenerator<KeySize = Self::LambdaBytes>;
    type TAU: TauParameters<Tau = Self::Tau>;
    type RO: RandomOracle;

    type Lambda: ArraySize;
    type LambdaBytes: ArraySize
        + Mul<U2, Output = Self::LambdaBytesTimes2>
        + Mul<U3, Output = Self::LambdaBytesTimes3>
        + Mul<U8, Output = Self::Lambda>
        + Mul<Self::NLeafCommit, Output: ArraySize>;
    type LambdaBytesTimes2: ArraySize;
    type LambdaBytesTimes3: ArraySize;
    type Tau: ArraySize;
    const L: usize;
    type LC: LeafCommit<
            PRG = Self::PRG,
            LambdaBytes = Self::LambdaBytes,
            NLeafCommit = Self::NLeafCommit,
        >;
    type NLeafCommit: ArraySize;
    type Topen: ArraySize;

    fn commit(
        r: &Array<u8, Self::LambdaBytes>,
        iv: &IV,
    ) -> BavcCommitResult<Self::LambdaBytes, Self::NLeafCommit>;

    fn open<'a>(
        decom: &'a BavcDecommitment<Self::LambdaBytes, Self::NLeafCommit>,
        i_delta: &Array<u16, Self::Tau>,
    ) -> Option<BavcOpenResult<'a>>;

    fn reconstruct(
        decom_i: &BavcOpenResult,
        i_delta: &Array<u16, Self::Tau>,
        iv: &IV,
    ) -> Option<BavcReconstructResult<Self::LambdaBytes>>;
}

pub(crate) struct Bavc<RO, LC, TAU>(PhantomData<(RO, LC, TAU)>);

impl<RO, LC, TAU> BatchVectorCommitment for Bavc<RO, LC, TAU>
where
    RO: RandomOracle,
    LC: LeafCommit,
    TAU: TauParameters,
{
    type RO = RO;
    type Lambda = Prod<LC::LambdaBytes, U8>;
    type LambdaBytes = LC::LambdaBytes;
    type LambdaBytesTimes2 = Prod<LC::LambdaBytes, U2>;
    type LambdaBytesTimes3 = Prod<LC::LambdaBytes, U3>;
    type LC = LC;
    type TAU = TAU;
    type Tau = TAU::Tau;
    const L: usize = TAU::L;
    type PRG = LC::PRG;
    type Topen = TAU::Topen;
    type NLeafCommit = LC::NLeafCommit;

    fn commit(
        r: &Array<u8, Self::LambdaBytes>,
        iv: &IV,
    ) -> BavcCommitResult<Self::LambdaBytes, Self::NLeafCommit> {
        // lines 1–2: initialize uhash (placeholder for FAEST-EM)
        let uhash = LC::init::<RO>(iv);

        // lines 3–5
        let keys = construct_keys::<LC::PRG, TAU>(r, iv);

        let mut com_hasher = RO::h1_init();
        let mut seeds = Vec::with_capacity(Self::L);
        let mut coms = Vec::with_capacity(Self::L);

        // lines 6–12
        for i in 0..TAU::Tau::U32 {
            let mut hi_hasher = RO::h1_init();

            let n_i = TAU::bavc_max_node_index(i as usize);
            for j in 0..n_i {
                let alpha = TAU::pos_in_tree(i as usize, j);
                let tweak = i + Self::L as u32 - 1;

                let (sd, com) = Self::LC::commit(&keys[alpha], iv, tweak, &uhash);

                hi_hasher.update(&com);

                seeds.push(sd);
                coms.push(com);
            }

            // lines 13–14: hash each vector into the final commitment
            com_hasher.update(&hi_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        // lines 14–16
        let decom = BavcDecommitment { keys, coms };
        let com = com_hasher.finish().read_into();

        BavcCommitResult { com, decom, seeds }
    }

    fn open<'a>(
        decom: &'a BavcDecommitment<Self::LambdaBytes, Self::NLeafCommit>,
        i_delta: &Array<u16, TAU::Tau>,
    ) -> Option<BavcOpenResult<'a>> {
        // line 5
        let mut s = bitvec![0; 2 * TAU::L - 1];

        // lines 6–17
        mark_nodes::<TAU>(&mut s, i_delta)?;

        // lines 19–22
        let nodes = construct_nodes::<Self::LambdaBytes, TAU>(&decom.keys, &s);

        // skip line 23: as we know expected nodes len we can keep the 0s-pad implicit

        // line 3
        let coms = (0..TAU::Tau::USIZE)
            .map(|i| decom.coms[TAU::bavc_index_offset(i) + i_delta[i] as usize].as_slice())
            .collect();

        Some(BavcOpenResult { coms, nodes })
    }

    fn reconstruct(
        decom_i: &BavcOpenResult,
        i_delta: &Array<u16, TAU::Tau>,
        iv: &IV,
    ) -> Option<BavcReconstructResult<Self::LambdaBytes>> {
        // lines 2–3: recreate the per-IV leaf context
        let context = LC::init::<RO>(iv);

        // line 5
        let mut s = bitvec![0; 2 * TAU::L - 1];

        // lines 6–25
        let keys = reconstruct_keys::<LC::PRG, TAU>(&mut s, &decom_i.nodes, i_delta, iv)?;

        // lines 26–28
        let mut h1_com_hasher = RO::h1_init();
        let mut seeds = Vec::with_capacity(TAU::L - TAU::Tau::USIZE);
        let mut com_it = decom_i.coms.iter();

        for i in 0u32..TAU::Tau::U32 {
            let mut h1_hasher = RO::h1_init();

            let n_i = TAU::bavc_max_node_index(i as usize);
            for j in 0..n_i {
                let alpha = TAU::pos_in_tree(i as usize, j);
                // lines 31–35: recompute revealed leaves
                if !*s.get(alpha)? {
                    let (sd, h) =
                        Self::LC::commit(&keys[alpha], iv, i + TAU::L as u32 - 1, &context);

                    seeds.push(sd);
                    h1_hasher.update(&h);
                }
                // lines 29–30: use the hidden leaf commitment
                else {
                    let com_ij = com_it.next()?;
                    h1_hasher.update(com_ij);
                }
            }

            // lines 36–37
            h1_com_hasher.update(&h1_hasher.finish().read_into::<Self::LambdaBytesTimes2>());
        }

        Some(BavcReconstructResult {
            com: h1_com_hasher.finish().read_into(),
            seeds,
        })
    }
}

#[cfg(test)]
#[path = "../tests/data/bavc_tvs.rs"]
mod test_vectors;

#[cfg(test)]
mod test {
    use super::*;

    use super::test_vectors::{
        BAVC_EM_VECTORS, BAVC_VECTORS, BavcVector, LEAF_COMMIT_EM_VECTORS, LEAF_COMMIT_VECTORS,
        Mode,
    };
    use hybrid_array::Array;

    use crate::{
        fields::{GF128, GF192, GF256},
        parameter::{
            BAVC128Fast, BAVC128FastEM, BAVC128Small, BAVC128SmallEM, BAVC192Fast, BAVC192FastEM,
            BAVC192Small, BAVC192SmallEM, BAVC256Fast, BAVC256FastEM, BAVC256Small, BAVC256SmallEM,
            Tau128Fast, Tau128FastEM, Tau128Small, Tau128SmallEM, Tau192Fast, Tau192FastEM,
            Tau192Small, Tau192SmallEM, Tau256Fast, Tau256FastEM, Tau256Small, Tau256SmallEM,
        },
        prg::{PRG128, PRG192, PRG256},
        universal_hashing::{LeafHasher128, LeafHasher192, LeafHasher256},
        utils::array_ref,
    };

    type Result<'a, LambdaBytes, NLeafCommit> = (
        // Commit
        BavcCommitResult<LambdaBytes, NLeafCommit>,
        // Open
        BavcOpenResult<'a>,
        // Reconstruct
        BavcReconstructResult<LambdaBytes>,
    );

    fn compare_expected_with_result<
        Lambda: ArraySize + Mul<NLeafCommit, Output: ArraySize> + Mul<U2, Output: ArraySize>,
        NLeafCommit: ArraySize,
        TAU: TauParameters,
    >(
        expected: &BavcVector,
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

        let BavcDecommitment { keys, .. } = decom;

        let hashed_sd = hash_array(&seeds.iter().flat_map(|x| x.clone()).collect::<Vec<u8>>());
        let hashed_k = hash_array(&keys.iter().flat_map(|x| x.clone()).collect::<Vec<u8>>());

        // Check commitment
        assert_eq!(expected.h, com.as_slice());
        assert_eq!(expected.hashed_sd.as_slice(), hashed_sd.as_slice());
        assert_eq!(expected.hashed_k.as_slice(), hashed_k.as_slice());

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
        assert_eq!(
            expected.hashed_decom_i.as_slice(),
            hash_array(data_decom.as_slice())
        );

        // Check reconstruct
        let rec_sd: Vec<u8> = rec_sd.iter().flat_map(|b| b.clone()).collect();
        assert_eq!(expected.hashed_rec_sd.as_slice(), hash_array(&rec_sd));
        assert_eq!(expected.h, rec_h.as_slice());
    }

    fn hash_array(data: &[u8]) -> Vec<u8> {
        use shake::{
            Shake256,
            digest::{ExtendableOutput, Update, XofReader},
        };

        let mut hasher = Shake256::default();
        hasher.update(data);
        let mut reader = hasher.finalize_xof();
        let mut ret = [0u8; 64];

        reader.read(&mut ret);
        ret.to_vec()
    }

    #[test]
    fn leaf_commit_test() {
        for data in LEAF_COMMIT_VECTORS {
            let iv = array_ref(&data.iv);

            match data.lambda {
                128 => {
                    let (sd, com) = LeafCommitment::<PRG128, LeafHasher128>::commit(
                        array_ref(data.key),
                        iv,
                        data.tweak,
                        array_ref(data.uhash),
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd);
                    assert_eq!(com.as_slice(), data.expected_com);
                }

                192 => {
                    let (sd, com) = LeafCommitment::<PRG192, LeafHasher192>::commit(
                        array_ref(data.key),
                        iv,
                        data.tweak,
                        array_ref(data.uhash),
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd);
                    assert_eq!(com.as_slice(), data.expected_com);
                }

                256 => {
                    let (sd, com) = LeafCommitment::<PRG256, LeafHasher256>::commit(
                        array_ref(data.key),
                        iv,
                        data.tweak,
                        array_ref(data.uhash),
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd);
                    assert_eq!(com.as_slice(), data.expected_com);
                }

                _ => panic!("Invalid lambda"),
            }
        }
    }

    #[test]
    fn leaf_commit_em_test() {
        for data in LEAF_COMMIT_EM_VECTORS {
            let iv = array_ref(&data.iv);

            match data.lambda {
                128 => {
                    let (sd, com) = LeafCommitmentEm::<PRG128>::commit(
                        array_ref(data.key),
                        iv,
                        data.tweak,
                        &(),
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd);
                    assert_eq!(com.as_slice(), data.expected_com);
                }

                192 => {
                    let (sd, com) = LeafCommitmentEm::<PRG192>::commit(
                        array_ref(data.key),
                        iv,
                        data.tweak,
                        &(),
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd);
                    assert_eq!(com.as_slice(), data.expected_com);
                }

                256 => {
                    let (sd, com) = LeafCommitmentEm::<PRG256>::commit(
                        array_ref(data.key),
                        iv,
                        data.tweak,
                        &(),
                    );
                    assert_eq!(sd.as_slice(), data.expected_sd);
                    assert_eq!(com.as_slice(), data.expected_com);
                }

                _ => panic!("Invalid lambda"),
            }
        }
    }

    #[test]
    fn bavc_test() {
        let r: Array<u8, _> = Array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let iv = IV::default();

        for data in BAVC_VECTORS {
            match data.lambda {
                128 => {
                    let r = array_ref(&r[..16]);

                    if data.mode == Mode::Small {
                        let i_delta = array_ref(data.i_delta);

                        let res_commit = BAVC128Small::<GF128>::commit(r, &iv);

                        let res_open =
                            BAVC128Small::<GF128>::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC128Small::<GF128>::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau128Small>(
                            data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        let i_delta = array_ref(data.i_delta);

                        let res_commit = BAVC128Fast::<GF128>::commit(r, &iv);

                        let res_open =
                            BAVC128Fast::<GF128>::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC128Fast::<GF128>::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau128Fast>(
                            data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    }
                }
                192 => {
                    let r = array_ref(&r[..24]);

                    if data.mode == Mode::Small {
                        let i_delta = array_ref(data.i_delta);

                        let res_commit = BAVC192Small::<GF192>::commit(r, &iv);

                        let res_open =
                            BAVC192Small::<GF192>::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC192Small::<GF192>::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau192Small>(
                            data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        let i_delta = array_ref(data.i_delta);

                        let res_commit = BAVC192Fast::<GF192>::commit(r, &iv);

                        let res_open =
                            BAVC192Fast::<GF192>::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC192Fast::<GF192>::reconstruct(&res_open, i_delta, &iv).unwrap();
                        compare_expected_with_result::<_, _, Tau192Fast>(
                            data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    }
                }

                _ => {
                    if data.mode == Mode::Small {
                        let i_delta = array_ref(data.i_delta);

                        let res_commit = BAVC256Small::<GF256>::commit(&r, &iv);

                        let res_open =
                            BAVC256Small::<GF256>::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC256Small::<GF256>::reconstruct(&res_open, i_delta, &iv).unwrap();
                        compare_expected_with_result::<_, _, Tau256Small>(
                            data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        let i_delta = array_ref(data.i_delta);

                        let res_commit = BAVC256Fast::<GF256>::commit(&r, &iv);

                        let res_open =
                            BAVC256Fast::<GF256>::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC256Fast::<GF256>::reconstruct(&res_open, i_delta, &iv).unwrap();
                        compare_expected_with_result::<_, _, Tau256Fast>(
                            data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn bavc_em_test() {
        let r: Array<u8, _> = Array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let iv = IV::default();

        for data in BAVC_EM_VECTORS {
            match data.lambda {
                128 => {
                    let r = array_ref(&r[..16]);

                    if data.mode == Mode::Small {
                        let i_delta = array_ref(data.i_delta);

                        let res_commit = BAVC128SmallEM::commit(r, &iv);

                        let res_open = BAVC128SmallEM::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC128SmallEM::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau128SmallEM>(
                            data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        let i_delta = array_ref(data.i_delta);

                        let res_commit = BAVC128FastEM::commit(r, &iv);

                        let res_open = BAVC128FastEM::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC128FastEM::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau128FastEM>(
                            data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    }
                }
                192 => {
                    let r = array_ref(&r[..24]);

                    if data.mode == Mode::Small {
                        let i_delta = array_ref(data.i_delta);

                        let res_commit = BAVC192SmallEM::commit(r, &iv);

                        let res_open = BAVC192SmallEM::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC192SmallEM::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau192SmallEM>(
                            data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        let i_delta = array_ref(data.i_delta);

                        let res_commit = BAVC192FastEM::commit(r, &iv);

                        let res_open = BAVC192FastEM::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC192FastEM::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau192FastEM>(
                            data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    }
                }
                _ => {
                    if data.mode == Mode::Small {
                        let i_delta = array_ref(data.i_delta);

                        let res_commit = BAVC256SmallEM::commit(&r, &iv);

                        let res_open = BAVC256SmallEM::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC256SmallEM::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau256SmallEM>(
                            data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    } else {
                        let i_delta = array_ref(data.i_delta);

                        let res_commit = BAVC256FastEM::commit(&r, &iv);

                        let res_open = BAVC256FastEM::open(&res_commit.decom, i_delta).unwrap();

                        let res_reconstruct =
                            BAVC256FastEM::reconstruct(&res_open, i_delta, &iv).unwrap();

                        compare_expected_with_result::<_, _, Tau256FastEM>(
                            data,
                            (res_commit.clone(), res_open, res_reconstruct),
                        );
                    }
                }
            }
        }
    }
}
