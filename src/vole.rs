use std::{
    iter::zip,
    marker::PhantomData,
    mem::swap,
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
    utils::{Reader, decode_all_chall_3, xor_arrays_inplace, xor_arrays_into},
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

fn convert_to_vole<'a, BAVC, LHatBytes>(
    v: impl ExactSizeIterator<Item = &'a mut GenericArray<u8, LHatBytes>>,
    sd: impl ExactSizeIterator<Item = &'a GenericArray<u8, BAVC::LambdaBytes>>,
    iv: &IV,
    round: u32,
) -> Box<GenericArray<u8, LHatBytes>>
where
    BAVC: BatchVectorCommitment,
    LHatBytes: ArrayLength,
{
    let twk = round + TWEAK_OFFSET;

    // ::1
    let ni = BAVC::TAU::bavc_max_node_index(round as usize);
    debug_assert!(sd.len() == ni || sd.len() + 1 == ni);

    // ::2
    // As in steps 8,9 we only work with two rows at a time, we just allocate 2 r-vectors
    let mut rj: Vec<Box<GenericArray<u8, LHatBytes>>> = Vec::with_capacity(ni);
    let mut rj1: Vec<Box<GenericArray<u8, LHatBytes>>> = vec![GenericArray::default_boxed(); ni];

    // ::3,4
    let offset = (sd.len() != ni) as usize;
    if offset != 0 {
        rj.push(GenericArray::default_boxed());
    }
    for sdi in sd {
        rj.push(BAVC::PRG::new_prg(sdi, iv, twk).read_into_boxed());
    }

    // ::6..9
    for (j, vj) in v.enumerate() {
        for i in 0..(ni >> (j + 1)) {
            // ::8
            xor_arrays_inplace(vj.as_mut_slice(), rj[2 * i + 1].as_slice());
            // ::9
            xor_arrays_into(
                rj1[i].as_mut_slice(),
                rj[2 * i].as_slice(),
                rj[2 * i + 1].as_slice(),
            );
        }

        swap(&mut rj, &mut rj1); // At next iteration we want to have last row in rj
    }

    // ::10: after last swap, rj[0] will contain r_{d,0}
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
    let mut v_iter = v.iter_mut();

    let mut seeds_iter = seeds.iter();

    // ::3.0
    let u = convert_to_vole::<BAVC, LHatBytes>(
        v_iter.by_ref().take(BAVC::TAU::bavc_max_node_depth(0)),
        seeds_iter.by_ref().take(BAVC::TAU::bavc_max_node_index(0)),
        iv,
        0,
    );

    // ::3.1..
    for i in 1..BAVC::Tau::U32 {
        let ni = BAVC::TAU::bavc_max_node_index(i as usize);
        let ki = BAVC::TAU::bavc_max_node_depth(i as usize);

        // ::4..6
        let u_i = convert_to_vole::<BAVC, LHatBytes>(
            v_iter.by_ref().take(ki),
            seeds_iter.by_ref().take(ni),
            iv,
            i,
        );

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
    for i in 0..BAVC::Tau::U32 {
        // ::8
        let delta_i = i_delta[i as usize];
        let ni = BAVC::TAU::bavc_max_node_index(i as usize);
        let ki = BAVC::TAU::bavc_max_node_depth(i as usize);

        let qi_ref;
        (qi_ref, q_ref) = q_ref.split_at_mut(ki);

        let seeds_i = (1..ni)
            // To map values in-order, instead of iterating over j we iterate over j ^ delta_i
            .map(|j_xor_delta| {
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
        let _ = convert_to_vole::<BAVC, LHatBytes>(qi_ref.iter_mut(), seeds_i, iv, i);

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
                        println!("FAEST-128s - testing VOLE..");
                        vole_check::<OWF128, BAVC128Small>(data, r);
                    } else {
                        println!("FAEST-128f - testing VOLE..");
                        vole_check::<OWF128, BAVC128Fast>(data, r);
                    }
                }

                192 => {
                    let r = GenericArray::from_slice(&r[..24]);

                    if data.mode == "s" {
                        println!("FAEST-192s - testing VOLE..");
                        vole_check::<OWF192, BAVC192Small>(data, r);
                    } else {
                        println!("FAEST-192f - testing VOLE..");
                        vole_check::<OWF192, BAVC192Fast>(data, r);
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
                        vole_check::<OWF128EM, BAVC128SmallEM>(data, r);
                    } else {
                        println!("FAEST-EM-128f - testing VOLE..");
                        vole_check::<OWF128EM, BAVC128FastEM>(data, r);
                    }
                }

                192 => {
                    let r = GenericArray::from_slice(&r[..24]);

                    if data.mode == "s" {
                        println!("FAEST-EM-192s - testing VOLE..");
                        vole_check::<OWF192EM, BAVC192SmallEM>(data, r);
                    } else {
                        println!("FAEST-EM-192s - testing VOLE..");
                        vole_check::<OWF192EM, BAVC192FastEM>(data, r);
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
