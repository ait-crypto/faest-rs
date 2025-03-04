use std::{
    f32::consts::TAU,
    iter::zip,
    marker::PhantomData,
    mem::swap,
    ops::{Index, IndexMut},
};

use generic_array::{
    typenum::{Prod, Unsigned, U128, U3, U8},
    ArrayLength, GenericArray,
};
use itertools::izip;

use crate::{
    bavc::{BatchVectorCommitment, Commitment, Decommitment, Opening},
    parameter::TauParameters,
    prg::{PseudoRandomGenerator, IV, TWK},
    random_oracles::{Hasher, RandomOracle},
    universal_hashing::{LeafHasher, B},
    utils::{decode_all_chall_3, Reader},
};

const TWEAK_OFFSET: u32 = 1 << 31;

#[allow(clippy::type_complexity)]
fn convert_to_vole<'a, BAVC, LHatBytes>(
    v: &mut GenericArray<GenericArray<u8, BAVC::Lambda>, LHatBytes>,
    sd: impl ExactSizeIterator<Item = &'a GenericArray<u8, BAVC::LambdaBytes>>,
    iv: &IV,
    round: u32,
) -> GenericArray<u8, LHatBytes>
where
    BAVC: BatchVectorCommitment,
    LHatBytes: ArrayLength,
{
    // Step 1
    let twk = round + TWEAK_OFFSET;
    let d = BAVC::TAU::bavc_max_node_depth(round as usize);
    let ni = BAVC::TAU::bavc_max_node_index(round as usize);

    // For step 6 we only need two rows at a time
    let mut rj: Vec<GenericArray<u8, LHatBytes>> = vec![GenericArray::default(); ni];
    let mut rj1: Vec<GenericArray<u8, LHatBytes>> = vec![GenericArray::default(); ni];

    // Step 2
    let offset = (sd.len() != ni) as usize;
    debug_assert!(sd.len() == ni || sd.len() + 1 == ni);

    // Step 3,4
    for (i, sdi) in sd.enumerate() {
        BAVC::PRG::new_prg(sdi, iv, twk).read(&mut rj[i + offset]);
    }

    // Step 6..9
    let vcol_offset = BAVC::TAU::get_round_offset(round as usize);
    for j in 0..d {
        for i in 0..(ni >> (j + 1)) {
            // Join steps 8 and 9
            for (vrow, (r_dst, r_src, r_src1)) in
                izip!(&mut rj1[i], &rj[2 * i], &rj[2 * i + 1]).enumerate()
            {
                // Step 8
                v[vrow][vcol_offset + j] ^= r_src1;

                // Step 9
                *r_dst = r_src ^ r_src1;
            }
        }

        swap(&mut rj, &mut rj1); // At next iteration we want to have last row in rj
    }

    // Step 10
    rj.into_iter().next().unwrap() // Move rj[0] (after last swap, rj[0] contains r_d,0)
}

/// Reference to storage area in signature for all `c`s.
pub(crate) struct VoleCommitmentCRef<'a, LHatBytes>(&'a mut [u8], PhantomData<LHatBytes>);
impl<LHatBytes> Index<usize> for VoleCommitmentCRef<'_, LHatBytes>
where
    LHatBytes: ArrayLength,
{
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index * LHatBytes::USIZE..(index + 1) * LHatBytes::USIZE]
    }
}

impl<LHatBytes> IndexMut<usize> for VoleCommitmentCRef<'_, LHatBytes>
where
    LHatBytes: ArrayLength,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index * LHatBytes::USIZE..(index + 1) * LHatBytes::USIZE]
    }
}

impl<'a, LHatBytes> VoleCommitmentCRef<'a, LHatBytes>
where
    LHatBytes: ArrayLength,
{
    pub(crate) fn new(buffer: &'a mut [u8]) -> Self {
        Self(buffer, PhantomData)
    }
}

#[allow(clippy::type_complexity)]
pub fn volecommit<BAVC, LHatBytes>(
    mut c: VoleCommitmentCRef<LHatBytes>,
    r: &GenericArray<u8, BAVC::LambdaBytes>,
    iv: &IV,
) -> (
    GenericArray<u8, BAVC::LambdaBytesTimes2>, // com
    //decom
    Decommitment<BAVC::LambdaBytes, BAVC::NLeafCommit>,
    GenericArray<u8, LHatBytes>,                                  // u
    Box<GenericArray<GenericArray<u8, BAVC::Lambda>, LHatBytes>>, // V
)
where
    BAVC: BatchVectorCommitment,
    LHatBytes: ArrayLength,
{
    let Commitment { com, decom, seeds } = BAVC::commit(r, iv);

    let mut v: GenericArray<GenericArray<u8, BAVC::Lambda>, LHatBytes> = GenericArray::default();

    let u = convert_to_vole::<BAVC, LHatBytes>(
        &mut v,
        seeds[..BAVC::TAU::bavc_max_node_index(0)].iter(),
        iv,
        0,
    );

    for i in 1..BAVC::Tau::U32 {
        let sdi_start = BAVC::TAU::convert_index(i as usize);
        let sdi_end = sdi_start + BAVC::TAU::bavc_max_node_index(i as usize);

        // Step 4
        let u_i =
            convert_to_vole::<BAVC, LHatBytes>(&mut v, seeds[sdi_start..sdi_end].iter(), iv, i);

        // Step 8
        for (u_i, u, c) in izip!(&u_i, &u, &mut c[i as usize - 1]) {
            *c = u_i ^ u;
        }
    }

    (com, decom, u, Box::new(v))
}

#[allow(clippy::type_complexity)]
pub fn volereconstruct<BAVC, LHatBytes>(
    chall: &GenericArray<u8, BAVC::LambdaBytes>,
    decom_i: &Opening,
    c: VoleCommitmentCRef<LHatBytes>,
    iv: &IV,
) -> Option<(
    GenericArray<u8, BAVC::LambdaBytesTimes2>,
    Box<GenericArray<GenericArray<u8, BAVC::Lambda>, LHatBytes>>,
)>
where
    LHatBytes: ArrayLength,
    BAVC: BatchVectorCommitment,
{
    // Step 1
    let i_delta = decode_all_chall_3::<BAVC::TAU>(chall);

    // Step 4
    let rec = BAVC::reconstruct(decom_i, &i_delta, iv);

    if rec.is_none() {
        return None;
    }

    let rec = rec.unwrap();

    let mut q = GenericArray::default_boxed();

    let mut off = 0;

    // Step 7
    for i in 0..BAVC::Tau::U32 {
        let ni = BAVC::TAU::bavc_max_node_index(i as usize);
        let delta_i = i_delta[i as usize];

        let seeds_i: Vec<_> = (0..ni)
            .filter_map(|j_delta| {
                let j = j_delta ^ delta_i as usize;

                if j < delta_i as usize {
                    return Some(&rec.seeds[off + j]);
                } else if j > delta_i as usize {
                    return Some(&rec.seeds[off + j - 1]);
                }

                None
            })
            .collect();

        let _ = convert_to_vole::<BAVC, LHatBytes>(&mut q, seeds_i.into_iter(), iv, i);

        if i != 0 {
            let q_col_offset = BAVC::TAU::get_round_offset(i as usize);
            let ki = BAVC::TAU::bavc_max_node_depth(i as usize);
            // Step 14
            for j in (0..ki).filter(|j| delta_i & (1 << j) != 0) {
                // Step 15
                for (row, c_ij) in c[i as usize - 1].iter().enumerate() {
                    q[row][q_col_offset + j] ^= c_ij; // Column range q_col_offset,...,q_col_offset + k_i
                }
            }
        }

        off += ni - 1;
    }

    Some((rec.com, q))
}

#[cfg(test)]
mod test {
    use super::*;

    use generic_array::{
        sequence::GenericSequence,
        typenum::{U210, U434},
        GenericArray,
    };
    use serde::Deserialize;

    use crate::{
        bavc::{self, BatchVectorCommitment, BAVC128S, BAVCEM256F},
        parameter::{Tau128Small, Tau256FastEM},
        prg::PRG128,
        random_oracles::RandomOracleShake128,
        universal_hashing::LeafHasher128,
        utils::test::read_test_data,
    };

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
    fn vole128s_test() {
        let iv = GenericArray::default();
        let r = GenericArray::from_array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let h = GenericArray::from_array([
            0x7b, 0xe2, 0x76, 0xd1, 0x6b, 0x90, 0x16, 0x87, 0x50, 0x81, 0x97, 0xdb, 0x27, 0xb5,
            0x46, 0x10, 0x39, 0xbe, 0xab, 0x9d, 0x42, 0x6c, 0x6a, 0xbf, 0xee, 0x4a, 0x7c, 0x03,
            0x38, 0x99, 0x2d, 0x05,
        ]);

        let hashed_c = GenericArray::from_array([
            0x50, 0x5b, 0xe2, 0x84, 0xf9, 0x8b, 0x7d, 0x69, 0xa3, 0x92, 0x36, 0x4f, 0xa5, 0x5c,
            0x4a, 0x32, 0x73, 0xba, 0xd2, 0xae, 0x23, 0xa9, 0x01, 0x4f, 0xbb, 0x19, 0x2c, 0x82,
            0x5a, 0x0b, 0x51, 0x57, 0xa9, 0xf6, 0xdd, 0xe9, 0x24, 0x71, 0xfd, 0x64, 0x59, 0xd8,
            0xbe, 0x2d, 0x73, 0xe5, 0xfe, 0x45, 0x9b, 0xf9, 0xfc, 0xe8, 0xef, 0x74, 0x15, 0xd4,
            0x2b, 0x83, 0x4f, 0xff, 0xef, 0x2f, 0xfb, 0xfc,
        ]);

        let hashed_u = GenericArray::from_array([
            0xf0, 0xf3, 0x08, 0x6c, 0x71, 0x8c, 0xfb, 0x03, 0x40, 0xfd, 0x0f, 0xf0, 0x70, 0xd5,
            0x7e, 0x5a, 0x87, 0xc6, 0x42, 0xc5, 0x9f, 0x86, 0xab, 0x83, 0xf2, 0x14, 0x29, 0x54,
            0x9b, 0xe5, 0x62, 0xb3, 0xf2, 0x51, 0x88, 0x82, 0x55, 0xab, 0x8e, 0x74, 0x3d, 0x39,
            0xf6, 0x0d, 0x6b, 0xb2, 0x59, 0xef, 0x3a, 0x42, 0x78, 0x3e, 0xb4, 0xd8, 0x93, 0x81,
            0x25, 0xe8, 0xbd, 0x1e, 0x51, 0x31, 0x41, 0x9a,
        ]);

        let hashed_v_trans = GenericArray::from_array([
            0x9a, 0x59, 0x3e, 0xf5, 0x92, 0xae, 0x2a, 0xd8, 0x4c, 0x00, 0xc7, 0xd5, 0xa5, 0x03,
            0x86, 0xa2, 0x24, 0x18, 0x52, 0x30, 0x2c, 0x7c, 0xb0, 0x0d, 0xc7, 0xb4, 0x2e, 0x50,
            0x8a, 0x78, 0x78, 0x7b, 0xe5, 0xba, 0x00, 0x97, 0x1b, 0x6e, 0x84, 0x2c, 0x0a, 0x6d,
            0x64, 0xc1, 0xd2, 0xa6, 0xd4, 0xe4, 0x01, 0x05, 0xd3, 0x4f, 0xe9, 0x89, 0x04, 0x2e,
            0xa7, 0xb4, 0x49, 0xac, 0x39, 0x44, 0x67, 0x96,
        ]);

        let hashed_q_trans = GenericArray::from_array([
            0x20, 0x4c, 0x57, 0x11, 0xa2, 0x0b, 0xb4, 0xb9, 0x41, 0xa4, 0x02, 0x03, 0x5e, 0xe2,
            0x99, 0x59, 0x10, 0x5a, 0xb7, 0x27, 0x71, 0xeb, 0x3d, 0x47, 0xc1, 0xae, 0xfe, 0x45,
            0xc2, 0xa8, 0x14, 0xb6, 0xe5, 0x1c, 0xce, 0x9d, 0xc7, 0x98, 0x6f, 0xee, 0xfe, 0x30,
            0x36, 0x85, 0x4c, 0x15, 0x2a, 0x0f, 0xe1, 0x63, 0x9a, 0x6c, 0x95, 0xed, 0x9f, 0x6c,
            0x4e, 0x6d, 0xa6, 0xfb, 0xe8, 0x19, 0x7c, 0xe2,
        ]);

        let chall = GenericArray::from_array([
            0x48, 0xb0, 0xcd, 0x3a, 0x03, 0x76, 0x84, 0x7b, 0xe0, 0xcd, 0x11, 0xb2, 0x7d, 0x44,
            0x0d, 0x01,
        ]);

        let r = GenericArray::from_slice(&r[..16]);

        let mut c = vec![0; U210::USIZE * (<Tau128Small as TauParameters>::Tau::USIZE - 1)];

        let (com, decom, u, v) =
            super::volecommit::<BAVC128S, U210>(VoleCommitmentCRef::new(c.as_mut_slice()), r, &iv);

        let mut v_trans = vec![vec![]; v[0].len()];
        for i in 0..v[0].len() {
            for j in 0..v.len() {
                v_trans[i].push(v[j][i]);
            }
        }
        let v_trans: Vec<u8> = v_trans.into_iter().flatten().collect();

        assert_eq!(com.as_slice(), h.as_slice());
        assert_eq!(hash_array(&u), hashed_u.as_slice());
        assert_eq!(hash_array(&c), hashed_c.as_slice());
        assert_eq!(hash_array(&v_trans), hashed_v_trans.as_slice());

        let i_delta = decode_all_chall_3::<Tau128Small>(&chall);
        let decom_i = BAVC128S::open(&decom, &i_delta).unwrap();

        let (com, q) = volereconstruct::<BAVC128S, U210>(
            &chall,
            &decom_i,
            VoleCommitmentCRef::new(c.as_mut_slice()),
            &iv,
        )
        .unwrap();

        let mut q_trans = vec![vec![]; q[0].len()];
        for i in 0..q[0].len() {
            for j in 0..q.len() {
                q_trans[i].push(q[j][i]);
            }
        }
        let q_trans: Vec<u8> = q_trans.into_iter().flatten().collect();

        assert_eq!(h.as_slice(), com.as_slice());
        assert_eq!(hashed_q_trans.as_slice(), hash_array(&q_trans).as_slice());
    }

    #[test]
    fn vole_faest_em_256_test() {
        let iv = GenericArray::default();
        let r = GenericArray::from_array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let h = GenericArray::from_array([
            0x5f, 0xe5, 0x63, 0x35, 0xd7, 0x43, 0x36, 0x98, 0x0b, 0x3e, 0x9d, 0x75, 0xe8, 0x6e,
            0x1f, 0x7d, 0x1c, 0x53, 0x59, 0x68, 0x49, 0x43, 0x70, 0x34, 0xa4, 0x25, 0x32, 0x00,
            0xcd, 0x86, 0xec, 0xfa, 0xdc, 0xd5, 0xac, 0x94, 0x46, 0xe1, 0x05, 0xbd, 0xa9, 0x1d,
            0xa5, 0xce, 0xeb, 0xaf, 0x6e, 0x68, 0x7a, 0xf4, 0x0e, 0x18, 0x46, 0xb5, 0xb7, 0x2c,
            0x38, 0xe9, 0x2c, 0x2a, 0x04, 0x45, 0x86, 0x7c,
        ]);

        let hashed_c = GenericArray::from_array([
            0xfc, 0x46, 0x48, 0x93, 0xb7, 0xc3, 0xf6, 0x3a, 0x5d, 0x86, 0xc6, 0xc9, 0xeb, 0x5e,
            0x35, 0xe3, 0x12, 0x18, 0x9d, 0x8f, 0xf8, 0xc4, 0xde, 0x7d, 0x74, 0xe7, 0x2d, 0x33,
            0x33, 0xa3, 0x0c, 0xc6, 0xea, 0x05, 0x4d, 0x02, 0x81, 0x73, 0x1b, 0x33, 0xdc, 0x44,
            0xf8, 0x15, 0xeb, 0x83, 0x43, 0xf9, 0x9d, 0x38, 0xbb, 0x55, 0x90, 0x0e, 0xa0, 0xab,
            0x31, 0xb3, 0xa2, 0xc4, 0xd0, 0x81, 0x3f, 0xec,
        ]);

        let hashed_u = GenericArray::from_array([
            0x8f, 0x47, 0x35, 0x90, 0x26, 0x08, 0x75, 0x2b, 0xc4, 0x5b, 0x9f, 0x7b, 0x9b, 0xda,
            0x3f, 0xfb, 0xc1, 0x18, 0x6b, 0xb2, 0x51, 0x46, 0xd2, 0x79, 0xa8, 0xaa, 0xb9, 0xcd,
            0x19, 0x8e, 0x98, 0x0d, 0x09, 0x6f, 0xce, 0x6c, 0xf3, 0x74, 0xa2, 0xa3, 0x58, 0x6d,
            0x1e, 0x9a, 0x7f, 0x1a, 0x96, 0x1f, 0x93, 0x46, 0xef, 0xaa, 0x06, 0x9e, 0x4c, 0x2c,
            0x42, 0x36, 0xae, 0x2c, 0xb6, 0x65, 0xb0, 0x1c,
        ]);

        let hashed_v_trans = GenericArray::from_array([
            0xf9, 0xaf, 0x33, 0xbe, 0xc7, 0x2c, 0x21, 0x3e, 0x97, 0x20, 0xa1, 0x1e, 0xc2, 0x44,
            0xaa, 0x19, 0x4d, 0x7e, 0x11, 0x88, 0x47, 0x4b, 0xe0, 0x1a, 0x12, 0x4e, 0xaf, 0x44,
            0xae, 0x76, 0x9f, 0x0e, 0xb6, 0xba, 0xbe, 0x9a, 0xa1, 0xe7, 0x07, 0xc5, 0x91, 0x4e,
            0x55, 0xe5, 0x9e, 0xec, 0xe9, 0x46, 0xe6, 0x70, 0xc0, 0x3e, 0xeb, 0x6b, 0x0a, 0x99,
            0x55, 0x81, 0x50, 0x99, 0x31, 0xf3, 0x9d, 0x53,
        ]);

        let hashed_q_trans = GenericArray::from_array([
            0xb6, 0x49, 0x4e, 0x0d, 0x95, 0x75, 0x26, 0xbd, 0x32, 0x6a, 0xe1, 0x65, 0x2e, 0x7a,
            0xf1, 0xd8, 0xe6, 0xd8, 0x4b, 0x44, 0xcc, 0x7a, 0x23, 0x9c, 0x70, 0x6c, 0xd5, 0x65,
            0xb0, 0x99, 0xd7, 0x13, 0x12, 0x4e, 0x6a, 0x9a, 0xe2, 0x72, 0x0f, 0x35, 0xd6, 0x59,
            0x88, 0x87, 0x3c, 0x62, 0x51, 0xa0, 0x1c, 0x1a, 0x73, 0x1d, 0x94, 0xf7, 0x3c, 0x08,
            0x18, 0x2b, 0x03, 0x34, 0xb5, 0x57, 0x9c, 0xde,
        ]);

        let chall = GenericArray::from_array([
            0xc1, 0x33, 0xf4, 0x23, 0x75, 0x70, 0x03, 0x97, 0xba, 0x68, 0x9b, 0x7b, 0xf3, 0x8b,
            0xd1, 0xf5, 0x8c, 0xb7, 0xe3, 0x56, 0x5a, 0x37, 0x1e, 0x3c, 0x12, 0x97, 0x8a, 0x8d,
            0x09, 0xb7, 0x5b, 0x00,
        ]);

        let mut c = vec![0; U434::USIZE * (<Tau256FastEM as TauParameters>::Tau::USIZE - 1)];

        let (com, decom, u, v) = super::volecommit::<BAVCEM256F, U434>(
            VoleCommitmentCRef::new(c.as_mut_slice()),
            &r,
            &iv,
        );

        let mut v_trans = vec![vec![]; v[0].len()];
        for i in 0..v[0].len() {
            for j in 0..v.len() {
                v_trans[i].push(v[j][i]);
            }
        }
        let v_trans: Vec<u8> = v_trans.into_iter().flatten().collect();

        assert_eq!(com.as_slice(), h.as_slice());
        assert_eq!(hash_array(&c), hashed_c.as_slice());
        assert_eq!(hash_array(&u), hashed_u.as_slice());
        assert_eq!(hash_array(&v_trans), hashed_v_trans.as_slice());

        let i_delta = decode_all_chall_3::<Tau256FastEM>(&chall);
        let decom_i = BAVCEM256F::open(&decom, &i_delta).unwrap();

        let (com, q) = volereconstruct::<BAVCEM256F, U434>(
            &chall,
            &decom_i,
            VoleCommitmentCRef::new(c.as_mut_slice()),
            &iv,
        )
        .unwrap();

        let mut q_trans = vec![vec![]; q[0].len()];
        for i in 0..q[0].len() {
            for j in 0..q.len() {
                q_trans[i].push(q[j][i]);
            }
        }
        let q_trans: Vec<u8> = q_trans.into_iter().flatten().collect();

        assert_eq!(h.as_slice(), com.as_slice());
        assert_eq!(hashed_q_trans.as_slice(), hash_array(&q_trans).as_slice());
    }

    //     type VC<P> = <<<P as FAESTParameters>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC;
    //     type Tau<P> = <P as FAESTParameters>::Tau;
    //     type LH<P> = <<P as FAESTParameters>::OWF as OWFParameters>::LHATBYTES;

    //     #[derive(Debug, Deserialize)]
    //     #[serde(rename_all = "camelCase")]
    //     struct DataVoleCommit {
    //         lambdabytes: [u16; 1],
    //         k0: [u8; 1],
    //         hcom: Vec<u8>,
    //         u: Vec<u8>,
    //     }

    //     fn volecommit<VC, Tau, LH>(
    //         r: &GenericArray<u8, VC::LambdaBytes>,
    //         iv: &IV,
    //     ) -> (
    //         GenericArray<u8, VC::LambdaBytesTimes2>,
    //         Box<GenericArray<u8, LH>>,
    //     )
    //     where
    //         Tau: TauParameters,
    //         VC: VectorCommitment,
    //         LH: ArrayLength,
    //     {
    //         let mut c = vec![0; LH::USIZE * (Tau::Tau::USIZE - 1)];
    //         let ret =
    //             super::volecommit::<VC, Tau, LH>(VoleCommitmentCRef::new(c.as_mut_slice()), r, iv);
    //         (ret.0, ret.2)
    //     }

    //     #[test]
    //     fn volecommit_test() {
    //         let database: Vec<DataVoleCommit> = read_test_data("DataVoleCommit.json");
    //         for data in database {
    //             if data.lambdabytes[0] == 16 {
    //                 if data.u.len() == 234 {
    //                     if data.k0[0] == 12 {
    //                         let res = volecommit::<
    //                             VC<FAEST128sParameters>,
    //                             Tau<FAEST128sParameters>,
    //                             LH<FAEST128sParameters>,
    //                         >(
    //                             &GenericArray::generate(|idx| idx as u8), &IV::default()
    //                         );
    //                         assert_eq!(res.0.as_slice(), &data.hcom);
    //                         assert_eq!(res.1.as_slice(), &data.u);
    //                     } else {
    //                         let res = volecommit::<
    //                             VC<FAEST128fParameters>,
    //                             Tau<FAEST128fParameters>,
    //                             LH<FAEST128fParameters>,
    //                         >(
    //                             &GenericArray::generate(|idx| idx as u8), &IV::default()
    //                         );
    //                         assert_eq!(res.0.as_slice(), &data.hcom);
    //                         assert_eq!(res.1.as_slice(), &data.u);
    //                     }
    //                 } else if data.k0[0] == 12 {
    //                     let res = volecommit::<
    //                         VC<FAESTEM128sParameters>,
    //                         Tau<FAESTEM128sParameters>,
    //                         LH<FAESTEM128sParameters>,
    //                     >(
    //                         &GenericArray::generate(|idx| idx as u8), &IV::default()
    //                     );
    //                     assert_eq!(res.0.as_slice(), &data.hcom);
    //                     assert_eq!(res.1.as_slice(), &data.u);
    //                 } else {
    //                     let res = volecommit::<
    //                         VC<FAESTEM128fParameters>,
    //                         Tau<FAESTEM128fParameters>,
    //                         LH<FAESTEM128fParameters>,
    //                     >(
    //                         &GenericArray::generate(|idx| idx as u8), &IV::default()
    //                     );
    //                     assert_eq!(res.0.as_slice(), &data.hcom);
    //                     assert_eq!(res.1.as_slice(), &data.u);
    //                 }
    //             } else if data.lambdabytes[0] == 24 {
    //                 if data.u.len() == 458 {
    //                     if data.k0[0] == 12 {
    //                         let res = volecommit::<
    //                             VC<FAEST192sParameters>,
    //                             Tau<FAEST192sParameters>,
    //                             LH<FAEST192sParameters>,
    //                         >(
    //                             &GenericArray::generate(|idx| idx as u8), &IV::default()
    //                         );
    //                         assert_eq!(res.0.as_slice(), &data.hcom);
    //                         assert_eq!(res.1.as_slice(), &data.u);
    //                     } else {
    //                         let res = volecommit::<
    //                             VC<FAEST192fParameters>,
    //                             Tau<FAEST192fParameters>,
    //                             LH<FAEST192fParameters>,
    //                         >(
    //                             &GenericArray::generate(|idx| idx as u8), &IV::default()
    //                         );
    //                         assert_eq!(res.0.as_slice(), &data.hcom);
    //                         assert_eq!(res.1.as_slice(), &data.u);
    //                     }
    //                 } else if data.k0[0] == 12 {
    //                     let res = volecommit::<
    //                         VC<FAESTEM192sParameters>,
    //                         Tau<FAESTEM192sParameters>,
    //                         LH<FAESTEM192sParameters>,
    //                     >(
    //                         &GenericArray::generate(|idx| idx as u8), &IV::default()
    //                     );
    //                     assert_eq!(res.0.as_slice(), &data.hcom);
    //                     assert_eq!(res.1.as_slice(), &data.u);
    //                 } else {
    //                     let res = volecommit::<
    //                         VC<FAESTEM192fParameters>,
    //                         Tau<FAESTEM192fParameters>,
    //                         LH<FAESTEM192fParameters>,
    //                     >(
    //                         &GenericArray::generate(|idx| idx as u8), &IV::default()
    //                     );
    //                     assert_eq!(res.0.as_slice(), &data.hcom);
    //                     assert_eq!(res.1.as_slice(), &data.u);
    //                 }
    //             } else if data.u.len() == 566 {
    //                 if data.k0[0] == 12 {
    //                     let res = volecommit::<
    //                         VC<FAEST256sParameters>,
    //                         Tau<FAEST256sParameters>,
    //                         LH<FAEST256sParameters>,
    //                     >(
    //                         &GenericArray::generate(|idx| idx as u8), &IV::default()
    //                     );
    //                     assert_eq!(res.0.as_slice(), &data.hcom);
    //                     assert_eq!(res.1.as_slice(), &data.u);
    //                 } else {
    //                     let res = volecommit::<
    //                         VC<FAEST256fParameters>,
    //                         Tau<FAEST256fParameters>,
    //                         LH<FAEST256fParameters>,
    //                     >(
    //                         &GenericArray::generate(|idx| idx as u8), &IV::default()
    //                     );
    //                     assert_eq!(res.0.as_slice(), &data.hcom);
    //                     assert_eq!(res.1.as_slice(), &data.u);
    //                 }
    //             } else if data.k0[0] == 12 {
    //                 let res =
    //                     volecommit::<
    //                         VC<FAESTEM256sParameters>,
    //                         Tau<FAESTEM256sParameters>,
    //                         LH<FAESTEM256sParameters>,
    //                     >(&GenericArray::generate(|idx| idx as u8), &IV::default());
    //                 assert_eq!(res.0.as_slice(), &data.hcom);
    //                 assert_eq!(res.1.as_slice(), &data.u);
    //             } else {
    //                 let res =
    //                     volecommit::<
    //                         VC<FAESTEM256fParameters>,
    //                         Tau<FAESTEM256fParameters>,
    //                         LH<FAESTEM256fParameters>,
    //                     >(&GenericArray::generate(|idx| idx as u8), &IV::default());
    //                 assert_eq!(res.0.as_slice(), &data.hcom);
    //                 assert_eq!(res.1.as_slice(), &data.u);
    //             }
    //         }
    //     }

    //     #[derive(Debug, Deserialize)]
    //     #[serde(rename_all = "camelCase")]
    //     struct DataVoleReconstruct {
    //         chal: Vec<u8>,
    //         pdec: Vec<Vec<Vec<u8>>>,
    //         com: Vec<Vec<u8>>,
    //         hcom: Vec<u8>,
    //         q: Vec<Vec<Vec<u8>>>,
    //     }

    //     #[test]
    //     fn volereconstruct_test() {
    //         let database: Vec<DataVoleReconstruct> = read_test_data("DataVoleReconstruct.json");
    //         for data in database {
    //             if data.chal.len() == 16 {
    //                 if data.q[0].len() == 8 {
    //                     let pdecom = &data
    //                         .pdec
    //                         .into_iter()
    //                         .zip(&data.com)
    //                         .flat_map(|(x, y)| {
    //                             [x.into_iter().flatten().collect::<Vec<u8>>(), y.to_vec()].concat()
    //                         })
    //                         .collect::<Vec<u8>>();
    //                     let res = volereconstruct::<
    //                         VC<FAEST128fParameters>,
    //                         Tau<FAEST128fParameters>,
    //                         LH<FAEST128fParameters>,
    //                     >(&data.chal, pdecom, &IV::default());
    //                     assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
    //                 } else {
    //                     let pdecom = &data
    //                         .pdec
    //                         .into_iter()
    //                         .zip(&data.com)
    //                         .flat_map(|(x, y)| {
    //                             [x.into_iter().flatten().collect::<Vec<u8>>(), y.to_vec()].concat()
    //                         })
    //                         .collect::<Vec<u8>>();
    //                     let res = volereconstruct::<
    //                         VC<FAEST128sParameters>,
    //                         Tau<FAEST128sParameters>,
    //                         LH<FAEST128sParameters>,
    //                     >(&data.chal, pdecom, &IV::default());
    //                     assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
    //                 }
    //             } else if data.chal.len() == 24 {
    //                 if data.q[0].len() == 8 {
    //                     let pdecom = &data
    //                         .pdec
    //                         .into_iter()
    //                         .zip(&data.com)
    //                         .flat_map(|(x, y)| {
    //                             [x.into_iter().flatten().collect::<Vec<u8>>(), y.to_vec()].concat()
    //                         })
    //                         .collect::<Vec<u8>>();
    //                     let res = volereconstruct::<
    //                         VC<FAEST192fParameters>,
    //                         Tau<FAEST192fParameters>,
    //                         LH<FAEST192fParameters>,
    //                     >(&data.chal, pdecom, &IV::default());
    //                     assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
    //                 } else {
    //                     let pdecom = &data
    //                         .pdec
    //                         .into_iter()
    //                         .zip(&data.com)
    //                         .flat_map(|(x, y)| {
    //                             [x.into_iter().flatten().collect::<Vec<u8>>(), y.to_vec()].concat()
    //                         })
    //                         .collect::<Vec<u8>>();
    //                     let res = volereconstruct::<
    //                         VC<FAEST192sParameters>,
    //                         Tau<FAEST192sParameters>,
    //                         LH<FAEST192sParameters>,
    //                     >(&data.chal, pdecom, &IV::default());
    //                     assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
    //                 }
    //             } else if data.q[0].len() == 8 {
    //                 let pdecom = &data
    //                     .pdec
    //                     .into_iter()
    //                     .zip(&data.com)
    //                     .flat_map(|(x, y)| {
    //                         [x.into_iter().flatten().collect::<Vec<u8>>(), y.to_vec()].concat()
    //                     })
    //                     .collect::<Vec<u8>>();
    //                 let res = volereconstruct::<
    //                     VC<FAEST256fParameters>,
    //                     Tau<FAEST256fParameters>,
    //                     LH<FAEST256fParameters>,
    //                 >(&data.chal, pdecom, &IV::default());
    //                 assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
    //             } else {
    //                 let pdecom = &data
    //                     .pdec
    //                     .into_iter()
    //                     .zip(&data.com)
    //                     .flat_map(|(x, y)| {
    //                         [x.into_iter().flatten().collect::<Vec<u8>>(), y.to_vec()].concat()
    //                     })
    //                     .collect::<Vec<u8>>();
    //                 let res = volereconstruct::<
    //                     VC<FAEST256sParameters>,
    //                     Tau<FAEST256sParameters>,
    //                     LH<FAEST256sParameters>,
    //                 >(&data.chal, pdecom, &IV::default());
    //                 assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
    //             }
    //         }
    //     }
}
