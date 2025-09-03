use std::{
    iter::zip,
    marker::PhantomData,
    ops::{Index, IndexMut, Mul},
};

use generic_array::{
    ArrayLength, GenericArray,
    typenum::{Prod, U2, U8, Unsigned},
};
use itertools::izip;

use crate::{
    bavc::{BatchVectorCommitment, BavcCommitResult, BavcDecommitment, BavcOpenResult},
    parameter::TauParameters,
    prg::{IV, PseudoRandomGenerator},
    utils::{Reader, decode_all_chall_3, xor_arrays_inplace},
};

/// Initial tweak value as by FEAST specification
const TWEAK_OFFSET: u32 = 1 << 31;

/// Result of VOLE commitment
#[derive(Clone, Debug, Default)]
pub struct VoleCommitResult<LambdaBytes, NLeafCommit, LHatBytes>
where
    LambdaBytes: ArrayLength
        + Mul<U2, Output: ArrayLength>
        + Mul<U8, Output: ArrayLength>
        + Mul<NLeafCommit, Output: ArrayLength>,
    NLeafCommit: ArrayLength,
    LHatBytes: ArrayLength,
{
    pub com: GenericArray<u8, Prod<LambdaBytes, U2>>,
    pub decom: BavcDecommitment<LambdaBytes, NLeafCommit>,
    pub u: Box<GenericArray<u8, LHatBytes>>,
    pub v: Box<GenericArray<GenericArray<u8, LHatBytes>, Prod<LambdaBytes, U8>>>,
}

/// Result of VOLE reconstruction
#[derive(Clone, Debug, Default)]
pub struct VoleReconstructResult<LambdaBytes, LHatBytes>
where
    LambdaBytes: ArrayLength + Mul<U2, Output: ArrayLength> + Mul<U8, Output: ArrayLength>,
    LHatBytes: ArrayLength,
{
    pub com: GenericArray<u8, Prod<LambdaBytes, U2>>,
    pub q: Box<GenericArray<GenericArray<u8, LHatBytes>, Prod<LambdaBytes, U8>>>,
}

/// Immutable reference to storage area in signature for all `c`s.
#[derive(Copy, Clone, Debug)]
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

/// Mutable eference to storage area in signature for all `c`s.
#[derive(Debug)]
pub(crate) struct VoleCommitmentCRefMut<'a, LHatBytes>(&'a mut [u8], PhantomData<LHatBytes>);

impl<'a, LHatBytes> VoleCommitmentCRefMut<'a, LHatBytes>
where
    LHatBytes: ArrayLength,
{
    pub(crate) fn new(buffer: &'a mut [u8]) -> Self {
        Self(buffer, PhantomData)
    }
}

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

pub(crate) fn convert_to_vole<'a, 'b, BAVC, LHatBytes>(
    v: &'a mut [GenericArray<u8, LHatBytes>],
    mut sd: impl ExactSizeIterator<Item = &'a GenericArray<u8, BAVC::LambdaBytes>>,
    iv: &IV,
    round: u32,
) -> Box<GenericArray<u8, LHatBytes>>
where
    BAVC: BatchVectorCommitment,
    LHatBytes: ArrayLength,
{
    let twk = round + TWEAK_OFFSET;

    let ni = BAVC::TAU::bavc_max_node_index(round as usize);
    debug_assert!(sd.len() == ni);

    // Init auxiliary memory
    let mut rj: Vec<Box<GenericArray<u8, LHatBytes>>> =
        vec![GenericArray::default_boxed(); BAVC::TAU::vole_array_length(round as usize)];
    let mut right_leaf: GenericArray<u8, LHatBytes> = GenericArray::default();

    let mut next = 0;
    for i in 0..ni / 2 {
        // 1. Read left leaf and right leaf
        // SAFETY: FAEST parameters ensure sd.len() = ni, hence the two unwraps are safe
        BAVC::PRG::new_prg(sd.next().unwrap(), iv, twk).read(&mut rj[next]);
        BAVC::PRG::new_prg(sd.next().unwrap(), iv, twk).read(&mut right_leaf);

        // 2. Level 0 => update V[0]
        xor_arrays_inplace(v[0].as_mut_slice(), right_leaf.as_slice());

        // 3. Father (level 1) is left leaf xor right leaf
        xor_arrays_inplace(&mut rj[next], right_leaf.as_slice());

        // Move one position forward and clean right leaf
        next += 1;
        right_leaf.fill(0);

        // Traverse all levels for which we can already compute internal nodes
        for (d, v_d) in v[1..].iter_mut().enumerate() {
            // Last two nodes are on different levels => abort
            if (i + 1) % (1 << (d + 1)) != 0 {
                break;
            }

            // Last two nodes are on same level:

            // 1. Save them as left, right
            let (left, right) = {
                let (l, r) = rj.split_at_mut(next - 1);
                (l[l.len() - 1].as_mut_slice(), r[0].as_mut_slice())
            };

            // 2. Level d => Update V[d]
            xor_arrays_inplace(v_d.as_mut_slice(), right);

            // 3. Father (level d+1) is left node xor right node
            xor_arrays_inplace(left, right);

            // 4. Move one position back and clean right node
            right.fill(0);
            next -= 1;
        }
    }

    // ::10: after traversing all levels, rj[0] will contain r_{d,0}
    // SAFETY: FAEST parameters ensure LHatBytes > 0 (hence rj is not empty)
    rj.into_iter().next().unwrap()
}

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
    // ::2
    let BavcCommitResult { com, decom, seeds } = BAVC::commit(r, iv);

    let mut v = GenericArray::default_boxed();

    let mut seeds_iter = seeds.iter();

    // ::3.0
    let (mut v_in, mut v_next) = v.split_at_mut(BAVC::TAU::bavc_max_node_depth(0));
    let u = convert_to_vole::<BAVC, LHatBytes>(
        v_in,
        seeds_iter.by_ref().take(BAVC::TAU::bavc_max_node_index(0)),
        iv,
        0,
    );

    // ::3.1..
    for i in 1..BAVC::Tau::U32 {
        let ni = BAVC::TAU::bavc_max_node_index(i as usize);
        let ki = BAVC::TAU::bavc_max_node_depth(i as usize);

        (v_in, v_next) = v_next.split_at_mut(ki);

        // ::4..6
        let u_i = convert_to_vole::<BAVC, LHatBytes>(v_in, seeds_iter.by_ref().take(ni), iv, i);

        // ::8
        for (u_i, u, c) in izip!(u_i.iter(), u.iter(), &mut c[i as usize - 1]) {
            *c = u_i ^ u;
        }
    }

    VoleCommitResult { com, decom, u, v }
}

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
    // ::1
    let i_delta = decode_all_chall_3::<BAVC::TAU>(chall);

    // Skip ::2 as decode_all_chall_3 can't fail (parameter constraints ensure that we only provide valid challenges/indexes)

    // ::4
    let rec = BAVC::reconstruct(decom_i, &i_delta, iv)?;

    let mut q: Box<
        GenericArray<GenericArray<u8, LHatBytes>, <BAVC as BatchVectorCommitment>::Lambda>,
    > = GenericArray::default_boxed();
    let mut q_ref = q.as_mut_slice();

    // At round i, seeds_i has offset \sum_{j=0}^{i-1} N_j in the seeds vector
    let mut sdi_off = 0;

    // ::7
    let zero_arr = GenericArray::default();
    for i in 0..BAVC::Tau::U32 {
        // ::8
        let delta_i = i_delta[i as usize];
        let ni = BAVC::TAU::bavc_max_node_index(i as usize);
        let ki = BAVC::TAU::bavc_max_node_depth(i as usize);

        let qi_ref;
        (qi_ref, q_ref) = q_ref.split_at_mut(ki);

        let seeds_i = (0..ni)
            // To map values in-order, instead of iterating over j we iterate over j ^ delta_i
            .map(|j_xor_delta| {
                if j_xor_delta == 0 {
                    return &zero_arr;
                }
                let j = j_xor_delta ^ delta_i as usize;

                let seeds_idx = if j < delta_i as usize {
                    sdi_off + j
                } else {
                    sdi_off + j - 1
                };

                // ::9
                // As we start from j_xor_delta = 1, we skip case j = delta_i
                &rec.seeds[seeds_idx]
            });

        // ::10
        let _ = convert_to_vole::<BAVC, LHatBytes>(qi_ref, seeds_i, iv, i);

        // ::14
        if i != 0 {
            // ::15
            for (_, q_ij) in qi_ref
                .iter_mut()
                .enumerate()
                .filter(|(j, _)| delta_i & (1 << j) != 0)
            {
                // xor column q_{i,j} with correction c_i
                for (q_ij, c_ij) in zip(q_ij.iter_mut(), c[i as usize - 1].iter()) {
                    *q_ij ^= c_ij;
                }
            }
        }

        // Round i+1 will write the next N_{i+1} columns
        sdi_off += ni - 1;
    }

    Some(VoleReconstructResult { com: rec.com, q })
}

#[cfg(test)]
mod test {
    use super::*;

    use generic_array::GenericArray;
    use serde::Deserialize;

    use crate::{
        bavc::{
            BAVC128Fast, BAVC128FastEM, BAVC128Small, BAVC128SmallEM, BAVC192Fast, BAVC192FastEM,
            BAVC192Small, BAVC192SmallEM, BAVC256Fast, BAVC256FastEM, BAVC256Small, BAVC256SmallEM,
            BatchVectorCommitment,
        },
        parameter::{OWF128, OWF128EM, OWF192, OWF192EM, OWF256, OWF256EM, OWFParameters},
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
            let v_trans = self
                .v
                .iter()
                .flat_map(|row| row.to_owned())
                .collect::<Vec<u8>>();
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
            let q = self
                .q
                .iter()
                .flat_map(|row| row.to_owned())
                .collect::<Vec<u8>>();
            hash_array(q.as_slice()) == expected_q
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
            OWF::LHatBytes::USIZE
                * (<<BAVC as BatchVectorCommitment>::TAU as TauParameters>::Tau::USIZE
                    - 1)
        ];

        let res_commit =
            volecommit::<BAVC, OWF::LHatBytes>(VoleCommitmentCRefMut::new(&mut c), r, &iv);

        let i_delta = decode_all_chall_3::<BAVC::TAU>(&chall);
        let decom_i = BAVC::open(&res_commit.decom, &i_delta).unwrap();

        let res_rec = volereconstruct::<BAVC, OWF::LHatBytes>(
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
                        vole_check::<OWF128, BAVC128Small>(data, r);
                    } else {
                        vole_check::<OWF128, BAVC128Fast>(data, r);
                    }
                }

                192 => {
                    let r = GenericArray::from_slice(&r[..24]);

                    if data.mode == "s" {
                        vole_check::<OWF192, BAVC192Small>(data, r);
                    } else {
                        vole_check::<OWF192, BAVC192Fast>(data, r);
                    }
                }

                _ => {
                    if data.mode == "s" {
                        vole_check::<OWF256, BAVC256Small>(data, &r);
                    } else {
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
                        vole_check::<OWF128EM, BAVC128SmallEM>(data, r);
                    } else {
                        vole_check::<OWF128EM, BAVC128FastEM>(data, r);
                    }
                }

                192 => {
                    let r = GenericArray::from_slice(&r[..24]);

                    if data.mode == "s" {
                        vole_check::<OWF192EM, BAVC192SmallEM>(data, r);
                    } else {
                        vole_check::<OWF192EM, BAVC192FastEM>(data, r);
                    }
                }

                _ => {
                    if data.mode == "s" {
                        vole_check::<OWF256EM, BAVC256SmallEM>(data, &r);
                    } else {
                        vole_check::<OWF256EM, BAVC256FastEM>(data, &r);
                    }
                }
            }
        }
    }
}
