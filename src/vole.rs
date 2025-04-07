use std::{
    f32::consts::TAU,
    iter::zip,
    marker::PhantomData,
    mem::swap,
    ops::{Index, IndexMut, Mul},
};

use generic_array::{
    typenum::{Prod, Unsigned, U128, U2, U3, U8},
    ArrayLength, GenericArray,
};
use itertools::izip;

use crate::{
    bavc::{
        BatchVectorCommitment, BavcCommitResult, BavcDecommitment, BavcOpenResult,
        BavcReconstructResult,
    },
    parameter::{Lambda, LambdaBytesTimes2, LambdaBytesTimes3, LambdaBytesTimes4, TauParameters},
    prg::{PseudoRandomGenerator, IV, TWK},
    random_oracles::{Hasher, RandomOracle},
    universal_hashing::{LeafHasher, B},
    utils::{decode_all_chall_3, Reader},
};

const TWEAK_OFFSET: u32 = 1 << 31;

#[allow(clippy::type_complexity)]
fn convert_to_vole<'a, BAVC, LHatBytes>(
    v: &mut GenericArray<GenericArray<u8, BAVC::Lambda>, LHatBytes>, // We directly work with the lambda*l_hat matrix instead of transposing it later
    sd: impl ExactSizeIterator<Item = &'a GenericArray<u8, BAVC::LambdaBytes>>,
    iv: &IV,
    round: u32,
) -> GenericArray<u8, LHatBytes>
// Should it be boxed?
where
    BAVC: BatchVectorCommitment,
    LHatBytes: ArrayLength,
{
    let twk = round + TWEAK_OFFSET;

    // Step 1
    let d = BAVC::TAU::bavc_max_node_depth(round as usize);
    let ni = BAVC::TAU::bavc_max_node_index(round as usize);

    // Step 2
    // As in steps 8,9 we only work with two rows at a time, we just allocate 2 r-vectors
    let mut rj: Vec<GenericArray<u8, LHatBytes>> = vec![GenericArray::default(); ni];
    let mut rj1: Vec<GenericArray<u8, LHatBytes>> = vec![GenericArray::default(); ni];

    debug_assert!(sd.len() == ni || sd.len() + 1 == ni);
    let offset = (sd.len() != ni) as usize;

    // Step 3,4
    for (i, sdi) in sd.enumerate() {
        BAVC::PRG::new_prg(sdi, iv, twk).read(&mut rj[i + offset]);
    }

    let vcol_offset = BAVC::TAU::bavc_depth_offset(round as usize);

    // Step 6..9
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
    rj.into_iter().next().unwrap() // Move rj[0] (after last swap, rj[0] will contain r_d,0)
}

/// Mutable eference to storage area in signature for all `c`s.
#[derive(Debug, PartialEq)]
pub(crate) struct VoleCommitmentCRefMut<'a, LHatBytes>(&'a mut [u8], PhantomData<LHatBytes>);
impl<LHatBytes> Index<usize> for VoleCommitmentCRefMut<'_, LHatBytes>
where
    LHatBytes: ArrayLength,
{
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index * LHatBytes::USIZE..(index + 1) * LHatBytes::USIZE]
    }
}

impl<LHatBytes> IndexMut<usize> for VoleCommitmentCRefMut<'_, LHatBytes>
where
    LHatBytes: ArrayLength,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index * LHatBytes::USIZE..(index + 1) * LHatBytes::USIZE]
    }
}

impl<'a, LHatBytes> VoleCommitmentCRefMut<'a, LHatBytes>
where
    LHatBytes: ArrayLength,
{
    pub(crate) fn new(buffer: &'a mut [u8]) -> Self {
        Self(buffer, PhantomData)
    }
}

/// Immutable reference to storage area in signature for all `c`s.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) struct VoleCommitmentCRef<'a, LHatBytes>(&'a [u8], PhantomData<LHatBytes>);

impl<LHatBytes> Index<usize> for VoleCommitmentCRef<'_, LHatBytes>
where
    LHatBytes: ArrayLength,
{
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index * LHatBytes::USIZE..(index + 1) * LHatBytes::USIZE]
    }
}

impl<'a, LHatBytes> VoleCommitmentCRef<'a, LHatBytes>
where
    LHatBytes: ArrayLength,
{
    pub(crate) fn new(buffer: &'a [u8]) -> Self {
        Self(buffer, PhantomData)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0
    }
}

#[derive(Clone, Debug, Default, PartialEq, PartialOrd)]
pub struct VoleCommitResult<LambdaBytes, NLeafCommit, LHatBytes>
where
    LambdaBytes: ArrayLength
        + Mul<U2, Output: ArrayLength>
        + Mul<U8, Output: ArrayLength>
        + Mul<NLeafCommit, Output: ArrayLength>,
    NLeafCommit: ArrayLength,
    LHatBytes: ArrayLength,
{
    pub com: GenericArray<u8, LambdaBytesTimes2<LambdaBytes>>,
    pub decom: BavcDecommitment<LambdaBytes, NLeafCommit>,
    pub u: GenericArray<u8, LHatBytes>,
    pub v: Box<GenericArray<GenericArray<u8, Lambda<LambdaBytes>>, LHatBytes>>,
}

#[derive(Clone, Debug, Default, PartialEq, PartialOrd)]
pub struct VoleReconstructResult<LambdaBytes, LHatBytes>
where
    LambdaBytes: ArrayLength + Mul<U2, Output: ArrayLength> + Mul<U8, Output: ArrayLength>,
    LHatBytes: ArrayLength,
{
    pub com: GenericArray<u8, LambdaBytesTimes2<LambdaBytes>>,
    pub q: Box<GenericArray<GenericArray<u8, Lambda<LambdaBytes>>, LHatBytes>>,
}

#[allow(clippy::type_complexity)]
pub fn volecommit<BAVC, LHatBytes>(
    mut c: VoleCommitmentCRefMut<LHatBytes>,
    r: &GenericArray<u8, BAVC::LambdaBytes>,
    iv: &IV,
) -> VoleCommitResult<
    <BAVC as BatchVectorCommitment>::LambdaBytes,
    <BAVC as BatchVectorCommitment>::NLeafCommit,
    LHatBytes,
>
where
    BAVC: BatchVectorCommitment,
    LHatBytes: ArrayLength,
{
    let BavcCommitResult { com, decom, seeds } = BAVC::commit(r, iv);

    let mut v: Box<GenericArray<GenericArray<u8, BAVC::Lambda>, LHatBytes>> =
        GenericArray::default_boxed();

    // Step 3.0
    let u = convert_to_vole::<BAVC, LHatBytes>(
        &mut v,
        seeds[..BAVC::TAU::bavc_max_node_index(0)].iter(),
        iv,
        0,
    );

    // Step 3
    for i in 1..BAVC::Tau::U32 {
        // Step 4
        let sdi_start = BAVC::TAU::bavc_index_offset(i as usize);
        let sdi_end = sdi_start + BAVC::TAU::bavc_max_node_index(i as usize);

        let u_i =
            convert_to_vole::<BAVC, LHatBytes>(&mut v, seeds[sdi_start..sdi_end].iter(), iv, i);

        // Step 8
        for (u_i, u, c) in izip!(&u_i, &u, &mut c[i as usize - 1]) {
            *c = u_i ^ u;
        }
    }

    VoleCommitResult { com, decom, u, v }
}

#[allow(clippy::type_complexity)]
pub fn volereconstruct<BAVC, LHatBytes>(
    chall: &GenericArray<u8, BAVC::LambdaBytes>,
    decom_i: &BavcOpenResult,
    c: VoleCommitmentCRef<LHatBytes>,
    iv: &IV,
) -> Option<VoleReconstructResult<BAVC::LambdaBytes, LHatBytes>>
where
    LHatBytes: ArrayLength,
    BAVC: BatchVectorCommitment,
{
    // Step 1
    let i_delta = decode_all_chall_3::<BAVC::TAU>(chall);

    // Skip step 2 as decode_all_chall_3 can't fail (parameter constraints ensure that we only provide valid challenges/indexes)

    // Step 4
    let rec = BAVC::reconstruct(decom_i, &i_delta, iv).unwrap_or_default();
    if rec == BavcReconstructResult::default() {
        return None;
    }

    let mut q = GenericArray::default_boxed();

    let mut sdi_off = 0; // At round i, seeds_i has offset \sum_{j=0}^{i-1} N_j in the seeds vector
                         // Step 7
    for i in 0..BAVC::Tau::U32 {
        // Step 8
        let delta_i = i_delta[i as usize];
        let ni = BAVC::TAU::bavc_max_node_index(i as usize);

        let seeds_i = (1..ni)
            // To map values in-order, instead of iterating over j we iterate over j ^ delta_i
            .map(|j_xor_delta| {
                // Step 9
                let j = j_xor_delta ^ delta_i as usize;

                if j < delta_i as usize {
                    return &rec.seeds[sdi_off + j];
                }

                // As we start from j_xor_delta = 1, we skip case j = delta_i
                &rec.seeds[sdi_off + j - 1]
            });

        // Step 10
        let _ = convert_to_vole::<BAVC, LHatBytes>(&mut q, seeds_i, iv, i);

        // Step 14
        if i != 0 {
            let q_col_offset = BAVC::TAU::bavc_depth_offset(i as usize);
            let ki = BAVC::TAU::bavc_max_node_depth(i as usize);
            // Step 15
            for j in (0..ki).filter(|j| delta_i & (1 << j) != 0) {
                // xor column q_{i,j} with c_i
                for (row, c_ij) in c[i as usize - 1].iter().enumerate() {
                    q[row][q_col_offset + j] ^= c_ij; // Column range q_col_offset,...,q_col_offset + k_i
                }
            }
        }

        sdi_off += ni - 1; // Round i+1 will write the next N_{i+1} columns
    }

    Some(VoleReconstructResult { com: rec.com, q })
}

#[cfg(test)]
mod test {
    use std::{f64::consts::TAU, str::FromStr};

    use super::*;

    use generic_array::{
        sequence::GenericSequence,
        typenum::{U210, U434, U486},
        GenericArray,
    };
    use serde::Deserialize;

    use crate::{
        bavc::{
            self, BAVC128Fast, BAVC128FastEM, BAVC128Small, BAVC128SmallEM, BAVC192Fast,
            BAVC192FastEM, BAVC192Small, BAVC192SmallEM, BAVC256Fast, BAVC256FastEM, BAVC256Small,
            BAVC256SmallEM, BatchVectorCommitment,
        },
        parameter::{
            OWFParameters, Tau128Fast, Tau128Small, Tau192Fast, Tau192Small, Tau256Fast,
            Tau256FastEM, Tau256Small, MAX_TAU, OWF128, OWF128EM, OWF192, OWF192EM, OWF256,
            OWF256EM,
        },
        prg::PRG128,
        random_oracles::RandomOracleShake128,
        universal_hashing::LeafHasher128,
        utils::test::{hash_array, read_test_data},
    };

    impl<LambdaBytes, NLeafCommit, LHatBytes> VoleCommitResult<LambdaBytes, NLeafCommit, LHatBytes>
    where
        LambdaBytes: ArrayLength
            + Mul<U2, Output: ArrayLength>
            + Mul<U8, Output: ArrayLength>
            + Mul<NLeafCommit, Output: ArrayLength>,
        NLeafCommit: ArrayLength,
        LHatBytes: ArrayLength,
    {
        pub fn check_commitment(&self, expected_com: &[u8]) -> bool {
            self.com.as_slice() == expected_com
        }

        pub fn check_c(c: &[u8], expected_c: &[u8]) -> bool {
            hash_array(c) == expected_c
        }

        pub fn check_u(&self, expected_u: &[u8]) -> bool {
            hash_array(self.u.as_slice()) == expected_u
        }

        pub fn check_v(&self, expected_v: &[u8]) -> bool {
            let v_trans = transpose_matrix(
                &self
                    .v
                    .iter()
                    .map(|row| row.as_slice())
                    .collect::<Vec<&[u8]>>(),
            );
            hash_array(&v_trans) == expected_v
        }

        pub fn verify(
            &self,
            expected_com: &[u8],
            expected_u: &[u8],
            expected_v: &[u8],
            c_pair: (&[u8], &[u8]),
        ) -> bool {
            self.check_commitment(expected_com)
                && Self::check_c(c_pair.0, c_pair.1)
                && self.check_u(expected_u)
                && self.check_v(expected_v)
        }
    }

    impl<LambdaBytes, LHatBytes> VoleReconstructResult<LambdaBytes, LHatBytes>
    where
        LambdaBytes: ArrayLength + Mul<U2, Output: ArrayLength> + Mul<U8, Output: ArrayLength>,
        LHatBytes: ArrayLength,
    {
        pub fn check_commitment(&self, expected_com: &[u8]) -> bool {
            self.com.as_slice() == expected_com
        }

        pub fn check_q(&self, expected_q: &[u8]) -> bool {
            let q_trans = transpose_matrix(
                &self
                    .q
                    .iter()
                    .map(|row| row.as_slice())
                    .collect::<Vec<&[u8]>>(),
            );
            hash_array(&q_trans) == expected_q
        }

        pub fn verify(&self, expected_com: &[u8], expected_q: &[u8]) -> bool {
            self.check_commitment(expected_com) && self.check_q(expected_q)
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataVOLE {
        lambda: u32,
        mode: String,
        h: Vec<u8>,
        hashed_c: Vec<u8>,
        hashed_u: Vec<u8>,
        hashed_v: Vec<u8>,
        chall: Vec<u8>,
        hashed_q: Vec<u8>,
    }

    fn transpose_matrix(m: &[&[u8]]) -> Vec<u8> {
        let mut m_trans = vec![vec![]; m[0].len()];
        for i in 0..m[0].len() {
            for j in 0..m.len() {
                m_trans[i].push(m[j][i]);
            }
        }
        m_trans.into_iter().flatten().collect()
    }

    fn vole_check<OWF: OWFParameters, BAVC: BatchVectorCommitment>(
        test_vector: DataVOLE,
        r: &GenericArray<u8, BAVC::LambdaBytes>,
    ) {
        let iv = GenericArray::default();

        let DataVOLE {
            lambda: _,
            mode: _,
            h,
            hashed_c,
            hashed_u,
            hashed_v,
            chall,
            hashed_q,
        } = test_vector;

        let mut c = vec![
            0;
            OWF::LHATBYTES::USIZE
                * (<<BAVC as BatchVectorCommitment>::TAU as TauParameters>::Tau::USIZE
                    - 1)
        ];

        let res_commit =
            volecommit::<BAVC, OWF::LHATBYTES>(VoleCommitmentCRefMut::new(&mut c), r, &iv);

        let i_delta = decode_all_chall_3::<BAVC::TAU>(&chall);
        let decom_i = BAVC::open(&res_commit.decom, &i_delta).unwrap();

        let res_rec = volereconstruct::<BAVC, OWF::LHATBYTES>(
            GenericArray::from_slice(&chall),
            &decom_i,
            VoleCommitmentCRef::new(&c),
            &iv,
        )
        .unwrap();

        assert!(res_commit.verify(&h, &hashed_u, &hashed_v, (&c, &hashed_c)));
        assert!(res_rec.verify(&h, &hashed_q));
    }

    #[test]
    fn vole_test() {
        let r = GenericArray::from_array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let datatabase = read_test_data::<DataVOLE>("vole.json");

        for data in datatabase {
            match data.lambda {
                128 => {
                    let r = GenericArray::from_slice(&r[..16]);

                    if data.mode == "s" {
                        println!("FAEST-128s - testing VOLE..");
                        vole_check::<OWF128, BAVC128Small>(data, &r);
                    } else {
                        println!("FAEST-128f - testing VOLE..");
                        vole_check::<OWF128, BAVC128Fast>(data, &r);
                    }
                }

                192 => {
                    let r = GenericArray::from_slice(&r[..24]);

                    if data.mode == "s" {
                        println!("FAEST-192s - testing VOLE..");
                        vole_check::<OWF192, BAVC192Small>(data, &r);
                    } else {
                        println!("FAEST-192f - testing VOLE..");
                        vole_check::<OWF192, BAVC192Fast>(data, &r);
                    }
                }

                _ => {
                    if data.mode == "s" {
                        println!("FAEST-256s - testing VOLE..");
                        vole_check::<OWF256, BAVC256Small>(data, &r);
                    } else {
                        println!("FAEST-256f - testing VOLE..");
                        vole_check::<OWF256, BAVC256Fast>(data, &r);
                    }
                }
            }
        }
    }

    #[test]
    fn vole_em_test() {
        let r = GenericArray::from_array([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let datatabase = read_test_data::<DataVOLE>("vole_em.json");

        for data in datatabase {
            match data.lambda {
                128 => {
                    let r = GenericArray::from_slice(&r[..16]);

                    if data.mode == "s" {
                        println!("FAEST-EM-128s - testing VOLE..");
                        vole_check::<OWF128EM, BAVC128SmallEM>(data, &r);
                    } else {
                        println!("FAEST-EM-128f - testing VOLE..");
                        vole_check::<OWF128EM, BAVC128FastEM>(data, &r);
                    }
                }

                192 => {
                    let r = GenericArray::from_slice(&r[..24]);

                    if data.mode == "s" {
                        println!("FAEST-EM-192s - testing VOLE..");
                        vole_check::<OWF192EM, BAVC192SmallEM>(data, &r);
                    } else {
                        println!("FAEST-EM-192s - testing VOLE..");
                        vole_check::<OWF192EM, BAVC192FastEM>(data, &r);
                    }
                }

                _ => {
                    if data.mode == "s" {
                        println!("FAEST-EM-256s - testing VOLE..");
                        vole_check::<OWF256EM, BAVC256SmallEM>(data, &r);
                    } else {
                        println!("FAEST-EM-256f - testing VOLE..");
                        vole_check::<OWF256EM, BAVC256FastEM>(data, &r);
                    }
                }
            }
        }
    }
}
