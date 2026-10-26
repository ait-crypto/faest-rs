pub(crate) mod tables;

use crate::{
    bavc::{BatchVectorCommitment, BavcCommitResult, BavcDecommitment, BavcOpenResult},
    parameter::{FAESTParameters, NMask, OWFParameters, TauParameters},
    prg::{IV, PseudoRandomGenerator},
    random_oracles::{Hasher, RandomOracle},
    utils::{
        Reader, bit_word_mask, decode_all_chall_3, extract_bit_slice, get_bit, insert_bit_slice,
        load_u64, set_bit, xor_arrays_inplace,
    },
    vole::tables::PackedMatrix,
};
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec};
use core::{
    marker::PhantomData,
    ops::{Index, IndexMut, Mul},
};
use hybrid_array::{
    Array, ArraySize,
    typenum::{Diff, Prod, Sum, U1, U2, U8, Unsigned},
};

const TWEAK_OFFSET: u32 = 1 << 31;

#[derive(Clone, Debug, Default)]
pub struct VoleCommitResult<LambdaBytes, NLeafCommit, LBytes>
where
    LambdaBytes: ArraySize
        + Mul<U2, Output: ArraySize>
        + Mul<U8, Output: ArraySize>
        + Mul<NLeafCommit, Output: ArraySize>,
    NLeafCommit: ArraySize,
    LBytes: ArraySize,
{
    pub com: Array<u8, Prod<LambdaBytes, U2>>,
    pub decom: BavcDecommitment<LambdaBytes, NLeafCommit>,
    pub u: Box<Array<u8, LBytes>>,
    pub v: Box<Array<Array<u8, LBytes>, Prod<LambdaBytes, U8>>>,
    pub u_bar: Array<Array<u8, LambdaBytes>, NMask>,
    pub v_bar: Array<Array<u8, LambdaBytes>, NMask>,
}

/// Result of VOLE reconstruction.
#[derive(Clone, Debug, Default)]
pub struct VoleReconstructResult<LambdaBytes, LHatBytes>
where
    LambdaBytes: ArraySize + Mul<U2, Output: ArraySize> + Mul<U8, Output: ArraySize>,
    LHatBytes: ArraySize,
{
    pub com: Array<u8, Prod<LambdaBytes, U2>>,
    pub q: Box<Array<Array<u8, LHatBytes>, Prod<LambdaBytes, U8>>>,
}

/// Immutable reference to storage area in signature for all `c`s.
#[derive(Copy, Clone, Debug)]
pub(crate) struct VoleCommitmentCRef<'a, LHatBytes>(&'a [u8], PhantomData<LHatBytes>);

impl<LHatBytes> Index<usize> for VoleCommitmentCRef<'_, LHatBytes>
where
    LHatBytes: ArraySize,
{
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index * LHatBytes::USIZE..(index + 1) * LHatBytes::USIZE]
    }
}

impl<'a, LHatBytes> VoleCommitmentCRef<'a, LHatBytes>
where
    LHatBytes: ArraySize,
{
    pub(crate) fn new(buffer: &'a [u8]) -> Self {
        Self(buffer, PhantomData)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0
    }
}

/// Mutable storage storage area in signature for witness correction vectors.
#[derive(Debug)]
pub(crate) struct VoleCommitmentCRefMut<'a, LBytes>(&'a mut [u8], PhantomData<LBytes>);

impl<'a, LBytes> VoleCommitmentCRefMut<'a, LBytes>
where
    LBytes: ArraySize,
{
    pub(crate) fn new(buffer: &'a mut [u8]) -> Self {
        Self(buffer, PhantomData)
    }
}

impl<LBytes> Index<usize> for VoleCommitmentCRefMut<'_, LBytes>
where
    LBytes: ArraySize,
{
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index * LBytes::USIZE..(index + 1) * LBytes::USIZE]
    }
}

impl<LBytes> IndexMut<usize> for VoleCommitmentCRefMut<'_, LBytes>
where
    LBytes: ArraySize,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index * LBytes::USIZE..(index + 1) * LBytes::USIZE]
    }
}

/// Overwrite a packed binary matrix product, clearing all output padding
fn matrix_mul_table(dst: &mut [u8], src: &[u8], table: &PackedMatrix) {
    assert_eq!(dst.len(), table.rows.div_ceil(8));
    dst.fill(0);
    for i in 0..table.rows {
        let mut acc = 0;
        for j in 0..table.stride {
            let valid = table.columns.saturating_sub(j * 64).min(64);
            acc ^= table.words[i * table.stride + j] & load_u64(src, j) & bit_word_mask(valid);
        }
        set_bit(dst, i, (acc.count_ones() & 1) as u8);
    }
}

fn xor_dst_word(dst: &mut [u8], word_idx: usize, dst_bits: usize, value: u64) {
    if word_idx >= dst_bits.div_ceil(64) {
        return;
    }
    let word_bits = (dst_bits - word_idx * 64).min(64);
    let word_bytes = word_bits.div_ceil(8);
    let ret = (load_u64(dst, word_idx) ^ value) & bit_word_mask(word_bits);
    dst[word_idx * 8..word_idx * 8 + word_bytes].copy_from_slice(&ret.to_le_bytes()[..word_bytes]);
}

fn xor_shifted_table(
    dst: &mut [u8],
    dst_bits: usize,
    table: &[u64],
    table_bits: usize,
    shift: usize,
    mask: u64,
) {
    let offset = shift % 64;
    let mut carry = 0;
    for (i, &word) in table[..table_bits.div_ceil(64)].iter().enumerate() {
        let word = word & bit_word_mask((table_bits - i * 64).min(64));
        let shifted = if offset == 0 {
            word
        } else {
            (word << offset) | carry
        };
        carry = if offset == 0 {
            0
        } else {
            word >> (64 - offset)
        };
        xor_dst_word(dst, shift / 64 + i, dst_bits, shifted & mask);
    }
    xor_dst_word(
        dst,
        shift / 64 + table_bits.div_ceil(64),
        dst_bits,
        carry & mask,
    );
}

/// Overwrite an unreduced GF(2) polynomial product, in coefficient order
fn poly_mul(dst: &mut [u8], src: &[u8], src_bits: usize, table: &[u64], table_bits: usize) {
    let dst_bits = src_bits + table_bits - 1;
    assert_eq!(dst.len(), dst_bits.div_ceil(8));
    dst.fill(0);
    for bit in 0..src_bits {
        let mask = 0u64.wrapping_sub(u64::from(get_bit(src, bit)));
        xor_shifted_table(dst, dst_bits, table, table_bits, bit, mask);
    }
}

fn reduce_tree_product(mut value: u32, modulus: u16, degree: usize) -> u16 {
    for bit in (degree..2 * degree).rev() {
        let mask = 0u32.wrapping_sub((value >> bit) & 1);
        value ^= (u32::from(modulus) << (bit - degree)) & mask;
    }
    value as u16
}

fn crt_transform_columns<L: ArraySize, LHatBytes: ArraySize>(
    dst: &mut [Array<u8, L>],
    src: &[Array<u8, LHatBytes>],
    table: &PackedMatrix,
) {
    for (out, column) in dst.iter_mut().enumerate() {
        column.fill(0);
        for word in 0..table.stride {
            let mut bits = table.words[out * table.stride + word]
                & bit_word_mask(table.columns.saturating_sub(word * 64).min(64));
            while bits != 0 {
                let input = word * 64 + bits.trailing_zeros() as usize;
                xor_arrays_inplace(column, &src[input][..L::USIZE]);
                bits &= bits - 1;
            }
        }
    }
}

fn convert_to_vole<'a, BAVC: BatchVectorCommitment, LHatBytes: ArraySize>(
    sd: impl ExactSizeIterator<Item = &'a Array<u8, BAVC::LambdaBytes>>,
    iv: &IV,
    round: u32,
    ubot: bool,
    u: &mut [u8],
    v: &mut [Array<u8, LHatBytes>],
    scratch: &mut [Array<u8, LHatBytes>],
) {
    let di = BAVC::TAU::bavc_max_node_depth(round as usize);

    v.fill(Array::default());

    // SAFETY: scratch has size d0+1
    let (mut current, stack) = scratch.split_last_mut().unwrap();

    // optimized traversal algo with reduced scratch memory: d0+1 vs 2^d_i
    for (leaf, seed) in sd.enumerate() {
        // line 4
        current.fill(0);
        BAVC::PRG::new_prg(seed, iv, TWEAK_OFFSET + round).read(&mut current);

        let mut level = 0;
        while (leaf >> level) & 1 != 0 {
            // line 8-9
            xor_arrays_inplace(&mut v[level], &current);
            xor_arrays_inplace(&mut current, &stack[level]);
            level += 1;
        }

        if level != di {
            // becomes left subtree with 2^level leaves
            stack[level].copy_from_slice(&current);
        } else if !ubot {
            // line 10 (u = r_d,0)
            u.copy_from_slice(&current);
        }
    }
}

fn h5_init<P: FAESTParameters>(iv: &IV, e: usize) -> impl Hasher + Clone {
    let mut hash = <P::BAVC as BatchVectorCommitment>::RO::h5_init();
    hash.update(&iv);
    hash.update(&(e as u32).to_le_bytes());
    return hash;
}

pub(crate) fn volecommit<P: FAESTParameters>(
    mut c: VoleCommitmentCRefMut<<P::OWF as OWFParameters>::LBytes>,
    c_mult: &mut [u8],
    r: &Array<u8, <P::OWF as OWFParameters>::LambdaBytes>,
    iv: &IV,
) -> VoleCommitResult<
    <P::BAVC as BatchVectorCommitment>::LambdaBytes,
    <P::BAVC as BatchVectorCommitment>::NLeafCommit,
    <P::OWF as OWFParameters>::LBytes,
> {
    let tables = P::Tau::VOLE_TABLES;
    let tau = <P::Tau as TauParameters>::Tau::USIZE;
    let ell = <P::OWF as OWFParameters>::L::USIZE;
    let ell_bytes = <P::OWF as OWFParameters>::LBytes::USIZE;
    let lambda_bytes = <P::OWF as OWFParameters>::LambdaBytes::USIZE;
    let d0 = P::Tau::bavc_max_node_depth(0);
    let len = P::LHatBytes::USIZE;
    assert_eq!(len, (ell + NMask::USIZE * d0).div_ceil(8));
    let low_bits = tables.w_crt.columns;
    let low_bytes = low_bits.div_ceil(8);
    let n_mult = tables.gates;
    let n_mult_bytes = tables.gates.div_ceil(8);
    assert_eq!(c.0.len(), (tau - 1) * ell_bytes,);
    assert_eq!(c_mult.len(), NMask::USIZE * n_mult_bytes,);

    // line 1
    let BavcCommitResult { com, decom, seeds } = P::BAVC::commit(r, iv);

    // init v matrix and buffers
    let mut raw_v = Box::<
        Array<Array<u8, P::LHatBytes>, Diff<<P::BAVC as BatchVectorCommitment>::Lambda, P::WGRIND>>,
    >::default();
    let mut scratch =
        Box::<Array<Array<u8, P::LHatBytes>, Sum<<P::Tau as TauParameters>::K, U1>>>::default();
    let mut ui = Box::<Array<Array<u8, P::LHatBytes>, <P::Tau as TauParameters>::Tau>>::default();

    // line 2-4
    let mut offset = 0;
    for tau_i in 0..tau {
        let tree_offset = P::Tau::bavc_index_offset(tau_i);
        let di = P::Tau::bavc_max_node_depth(tau_i);
        let ni = 1 << di;
        convert_to_vole::<P::BAVC, P::LHatBytes>(
            seeds[tree_offset..tree_offset + ni].iter(),
            iv,
            tau_i as u32,
            false,
            &mut ui[tau_i],
            &mut raw_v[offset..offset + di],
            &mut scratch,
        );
        offset += di;
    }

    // line 6-8
    let mut u: Box<Array<u8, <<P as FAESTParameters>::OWF as OWFParameters>::LBytes>> =
        Box::<Array<u8, <P::OWF as OWFParameters>::LBytes>>::default();
    u.copy_from_slice(&ui[0][..<P::OWF as OWFParameters>::LBytes::USIZE]);
    for tree in 1..tau {
        for byte in 0..ell_bytes {
            c[tree - 1][byte] = u[byte] ^ ui[tree][byte];
        }
    }

    // line 10
    let mut u_hi_all = vec![0; (NMask::USIZE * P::WGRIND::USIZE).div_ceil(8)];
    <P::BAVC as BatchVectorCommitment>::PRG::new_prg(r, iv, TWEAK_OFFSET - 1).read(&mut u_hi_all);
    let mut u_hi = vec![0; P::WGRIND::USIZE.div_ceil(8)];

    let mut u_bar = Array::<Array<u8, <P::OWF as OWFParameters>::LambdaBytes>, NMask>::default();
    let mut r_tilde = vec![0; NMask::USIZE * low_bytes];
    let mut u_low = vec![0; low_bytes];
    let mut product = vec![0; lambda_bytes];

    for m in 0..NMask::USIZE {
        u_low.fill(0);
        offset = 0;
        let ell_m = ell + m * d0;

        for tau_i in 0..tau {
            let d_i = P::Tau::bavc_max_node_depth(tau_i);

            // line 13
            insert_bit_slice(
                &mut u_low,
                offset,
                extract_bit_slice(&ui[tau_i], ell_m, d_i as u32),
                d_i as u32,
            );

            // line 15
            let mut acc = 0u32;
            for t in 0..d_i {
                acc ^= u32::from(extract_bit_slice(&raw_v[offset + t], ell_m, d_i as u32)) << t;
            }
            let reduced = reduce_tree_product(acc, tables.tree_moduli[tau_i], d_i);
            insert_bit_slice(
                &mut r_tilde[m * low_bytes..(m + 1) * low_bytes],
                offset,
                reduced,
                d_i as u32,
            );
            offset += d_i;
        }

        // line 14
        matrix_mul_table(&mut u_bar[m], &u_low, &tables.w_crt);
        u_hi.fill(0);
        insert_bit_slice(
            &mut u_hi,
            0,
            extract_bit_slice(&u_hi_all, m * P::WGRIND::USIZE, P::WGRIND::USIZE as u32),
            P::WGRIND::USIZE as u32,
        );
        poly_mul(
            &mut product,
            &u_hi,
            P::WGRIND::USIZE,
            tables.m_tree,
            low_bits + 1,
        );
        xor_arrays_inplace(&mut u_bar[m], &product);

        // line 26
        matrix_mul_table(
            &mut c_mult[m * n_mult_bytes..(m + 1) * n_mult_bytes],
            &u_bar[m],
            &tables.f,
        );
    }

    let mut v_tilde = vec![0; NMask::USIZE * n_mult];
    // line 21
    for e in 0..n_mult {
        let mut l_e = Array::<u8, <P::OWF as OWFParameters>::LambdaBytes>::default();

        // line 22
        for word in 0..tables.g.stride {
            let mut bits = tables.g.words[e * tables.g.stride + word]
                & bit_word_mask(low_bits.saturating_sub(word * 64).min(64));
            while bits != 0 {
                let col = word * 64 + bits.trailing_zeros() as usize;
                xor_arrays_inplace(&mut l_e, &raw_v[col][..lambda_bytes]);
                bits &= bits - 1;
            }
        }

        // init hashers
        let mut hash_one = h5_init::<P>(iv, e);
        let mut hash_two = hash_one.clone();

        // line 23.1
        let mut he_0 = [0u8; 2];
        hash_one.update(&l_e);
        hash_one.finish().read(&mut he_0);

        // line 22.2
        xor_arrays_inplace(&mut l_e, &u[..lambda_bytes]);

        // line 23.2
        let mut he_1 = [0u8; 2];
        hash_two.update(&l_e);
        hash_two.finish().read(&mut he_1);

        for m in 0..NMask::USIZE {
            // line 25
            set_bit(
                &mut v_tilde[m * n_mult_bytes..(m + 1) * n_mult_bytes],
                e,
                get_bit(&he_0, m),
            );
            c_mult[m * n_mult_bytes + e / 8] ^= (get_bit(&he_0, m) ^ get_bit(&he_1, m)) << (e % 8);
        }
    }

    // line 29
    let mut v_bar = Array::<Array<u8, <P::OWF as OWFParameters>::LambdaBytes>, NMask>::default();
    for m in 0..NMask::USIZE {
        matrix_mul_table(
            &mut v_bar[m],
            &r_tilde[m * low_bytes..(m + 1) * low_bytes],
            &tables.w_tree,
        );
        matrix_mul_table(
            &mut product,
            &v_tilde[m * n_mult_bytes..(m + 1) * n_mult_bytes],
            &tables.w_gate,
        );
        xor_arrays_inplace(&mut v_bar[m], &product);
    }

    // line 31-32
    let mut v = Box::<
        Array<Array<u8, <P::OWF as OWFParameters>::LBytes>, <P::OWF as OWFParameters>::Lambda>,
    >::default();
    crt_transform_columns(&mut v[..], &raw_v[..], &tables.w_crt);

    VoleCommitResult {
        com,
        decom,
        u,
        v,
        u_bar,
        v_bar,
    }
}

// pub fn volereconstruct<P: FAESTParameters>(
//     chall: &Array<u8, <P::BAVC as BatchVectorCommitment>::LambdaBytes>,
//     decom_i: &BavcOpenResult,
//     c: VoleCommitmentCRef<P::LHatBytes>,
//     iv: &IV,
// ) -> Option<VoleReconstructResult<<P::BAVC as BatchVectorCommitment>::LambdaBytes, P::LHatBytes>> {
//     // line 1
//     let i_delta = decode_all_chall_3::<<P::BAVC as BatchVectorCommitment>::TAU>(chall);

//     // Skip line 2 as decode_all_chall_3 can't fail (parameter constraints ensure that we only provide valid challenges/indexes)

//     // line 3
//     let rec = P::BAVC::reconstruct(decom_i, &i_delta, iv)?;

//     let mut q =
//         Box::<Array<Array<u8, P::LHatBytes>, <P::BAVC as BatchVectorCommitment>::Lambda>>::default(
//         );
//     let mut q_ref = q.as_mut_slice();

//     // At round i, seeds_i has offset \sum_{j=0}^{i-1} N_j in the seeds vector
//     let mut sdi_off = 0;

//     // line 7
//     let mut zero_arr = Array::default();
//     let mut scratch =
//         Box::<Array<Array<u8, P::LHatBytes>, Sum<<P::Tau as TauParameters>::K, U1>>>::default();
//     for i in 0..<P::BAVC as BatchVectorCommitment>::Tau::U32 {
//         // ::8
//         let delta_i = i_delta[i as usize];
//         let ni = <P::BAVC as BatchVectorCommitment>::TAU::bavc_max_node_index(i as usize);
//         let ki = <P::BAVC as BatchVectorCommitment>::TAU::bavc_max_node_depth(i as usize);

//         let qi_ref;
//         (qi_ref, q_ref) = q_ref.split_at_mut(ki);

//         // line 7
//         let seeds_i = (0..ni)
//             // To map values in-order, instead of iterating over j we iterate over j ^ delta_i
//             .map(|j_xor_delta| {
//                 if j_xor_delta == 0 {
//                     return &zero_arr;
//                 }
//                 let j = j_xor_delta ^ delta_i as usize;

//                 let seeds_idx = if j < delta_i as usize {
//                     sdi_off + j
//                 } else {
//                     sdi_off + j - 1
//                 };

//                 // As we start from j_xor_delta = 1, we skip case j = delta_i
//                 &rec.seeds[seeds_idx]
//             });

//         // line 8
//         let _ = convert_to_vole::<P::BAVC, P::LHatBytes>(
//             seeds_i,
//             iv,
//             i,
//             true,
//             &mut [],
//             qi_ref,
//             &mut scratch,
//         );

//         // line 12
//         if i != 0 {
//             // ::15
//             for (_, q_ij) in qi_ref
//                 .iter_mut()
//                 .take(<P::OWF as OWFParameters>::L::USIZE)
//                 .enumerate()
//                 .filter(|(j, _)| delta_i & (1 << j) != 0)
//             {
//                 // xor column q_{i,j} with correction c_i
//                 for (q_ij, c_ij) in q_ij.iter_mut().zip(&c[i as usize - 1]) {
//                     *q_ij ^= c_ij;
//                 }
//             }
//         }

//         // Round i+1 will write the next N_{i+1} columns
//         sdi_off += ni - 1;
//     }

//     Some(VoleReconstructResult { com: rec.com, q })
// }

#[cfg(test)]
#[path = "../tests/data/vole_tvs.rs"]
mod test_vectors;

#[cfg(test)]
mod test {
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

    use super::test_vectors::{DataVOLE, FAEST_EM_TEST_VECTORS, ROOT_KEY, VOLE_TEST_VECTORS};
    use super::*;
    use crate::{parameter::*, utils::test::hash_array};

    fn check_vector<P: FAESTParameters>(tv: &DataVOLE) {
        assert_eq!(tv.lambda as usize, <P::OWF as OWFParameters>::Lambda::USIZE);
        let len = <P::OWF as OWFParameters>::LBytes::USIZE;
        let mut c = vec![0xff; (<P::Tau as TauParameters>::Tau::USIZE - 1) * len];
        let mut cm = vec![0xff; 10 * P::Tau::VOLE_TABLES.gates.div_ceil(8)];
        let r =
            Array::try_from(&ROOT_KEY[..<P::OWF as OWFParameters>::LambdaBytes::USIZE]).unwrap();
        let res = volecommit::<P>(
            VoleCommitmentCRefMut::new(&mut c),
            &mut cm,
            &r,
            &IV::default(),
        );
        assert_eq!(res.com.as_slice(), tv.h, "com");
        assert_eq!(hash_array(&c), tv.hashed_c, "c");
        assert_eq!(hash_array(&cm), tv.hashed_c_mult, "c_mult");
        assert_eq!(hash_array(&res.u[..]), tv.hashed_u, "u");
        let mut rows = vec![0; len * 8 * <P::OWF as OWFParameters>::LambdaBytes::USIZE];
        for bit in 0..len * 8 {
            let row = &mut rows[bit * r.len()..(bit + 1) * r.len()];
            for (col, v) in res.v.iter().enumerate() {
                set_bit(row, col, get_bit(v, bit));
            }
        }
        assert_eq!(hash_array(&rows), tv.hashed_v, "v");
        assert_eq!(
            hash_array(res.u_bar.as_flattened()),
            tv.hashed_bar_u,
            "u_bar"
        );
        assert_eq!(
            hash_array(res.v_bar.as_flattened()),
            tv.hashed_bar_v,
            "v_bar"
        );
        let mut c2 = vec![0; c.len()];
        let mut cm2 = vec![0; cm.len()];
        let res2 = volecommit::<P>(
            VoleCommitmentCRefMut::new(&mut c2),
            &mut cm2,
            &r,
            &IV::default(),
        );
        assert_eq!(c, c2);
        assert_eq!(cm, cm2);
        assert_eq!(res.com, res2.com);
        assert_eq!(res.u, res2.u);
        assert_eq!(res.v, res2.v);
        assert_eq!(res.u_bar, res2.u_bar);
        assert_eq!(res.v_bar, res2.v_bar);
        for column in &res.v[P::Tau::VOLE_TABLES.w_crt.columns..] {
            assert!(column.iter().all(|&b| b == 0));
        }
        let gates = P::Tau::VOLE_TABLES.gates;
        if gates % 8 != 0 {
            for row in cm.chunks(gates.div_ceil(8)) {
                assert_eq!(row[row.len() - 1] >> (gates % 8), 0);
            }
        }
    }

    macro_rules! vector_test {
        ($name:ident, $p:ty, $i:expr) => {
            #[test]
            fn $name() {
                check_vector::<$p>(if $i < 6 {
                    &VOLE_TEST_VECTORS[$i]
                } else {
                    &FAEST_EM_TEST_VECTORS[$i - 6]
                });
            }
        };
    }
    vector_test!(commit_128s, FAEST128sParameters, 0);
    vector_test!(commit_128f, FAEST128fParameters, 1);
    vector_test!(commit_192s, FAEST192sParameters, 2);
    vector_test!(commit_192f, FAEST192fParameters, 3);
    vector_test!(commit_256s, FAEST256sParameters, 4);
    vector_test!(commit_256f, FAEST256fParameters, 5);
    vector_test!(commit_em_128s, FAESTEM128sParameters, 6);
    vector_test!(commit_em_128f, FAESTEM128fParameters, 7);
    vector_test!(commit_em_192s, FAESTEM192sParameters, 8);
    vector_test!(commit_em_192f, FAESTEM192fParameters, 9);
    vector_test!(commit_em_256s, FAESTEM256sParameters, 10);
    vector_test!(commit_em_256f, FAESTEM256fParameters, 11);

    #[test]
    fn packed_polynomial_products() {
        // Independent coefficient convolution, including dirty padding and carries
        // past the final source/table word.
        for src_bits in [1usize, 7, 8, 9, 63, 64, 65, 127, 129] {
            for table_bits in [1usize, 7, 9, 63, 64, 65, 121, 193] {
                for pattern in 0..4 {
                    let mut src = vec![0; src_bits.div_ceil(8)];
                    let mut table = vec![0; table_bits.div_ceil(64)];
                    for i in 0..src_bits {
                        let bit = match pattern {
                            0 => 0,
                            1 => u8::from(i == src_bits - 1),
                            2 => 1,
                            _ => u8::from(i % 3 == 1),
                        };
                        set_bit(&mut src, i, bit);
                    }
                    for i in 0..table_bits {
                        let bit = match pattern {
                            0 => 1,
                            1 => u64::from(i == table_bits - 1),
                            2 => 1,
                            _ => u64::from(i % 5 < 2),
                        };
                        table[i / 64] |= bit << (i % 64);
                    }
                    if src_bits % 8 != 0 {
                        *src.last_mut().unwrap() |= 0xff << (src_bits % 8);
                    }
                    if table_bits % 64 != 0 {
                        *table.last_mut().unwrap() |= u64::MAX << (table_bits % 64);
                    }
                    let bits = src_bits + table_bits - 1;
                    let mut expected = vec![0; bits.div_ceil(8)];
                    for i in 0..src_bits {
                        for j in 0..table_bits {
                            expected[(i + j) / 8] ^= (get_bit(&src, i)
                                & ((table[j / 64] >> (j % 64)) as u8 & 1))
                                << ((i + j) % 8);
                        }
                    }
                    let mut actual = vec![0xff; expected.len()];
                    poly_mul(&mut actual, &src, src_bits, &table, table_bits);
                    assert_eq!(
                        actual, expected,
                        "src={src_bits}, table={table_bits}, pattern={pattern}"
                    );
                }
            }
        }
    }

    #[test]
    fn packed_matrix_products() {
        // Exercise every generated map with zero, every basis vector and dense
        // inputs. Coefficient lookup is independent of packed word parity.
        for tables in [
            Tau128Small::VOLE_TABLES,
            Tau128Fast::VOLE_TABLES,
            Tau192Small::VOLE_TABLES,
            Tau192Fast::VOLE_TABLES,
            Tau256Small::VOLE_TABLES,
            Tau256Fast::VOLE_TABLES,
            Tau128SmallEM::VOLE_TABLES,
            Tau128FastEM::VOLE_TABLES,
            Tau192SmallEM::VOLE_TABLES,
            Tau192FastEM::VOLE_TABLES,
            Tau256SmallEM::VOLE_TABLES,
            Tau256FastEM::VOLE_TABLES,
        ] {
            for table in [
                &tables.f,
                &tables.g,
                &tables.w_tree,
                &tables.w_gate,
                &tables.w_crt,
            ] {
                for pattern in 0..table.columns + 3 {
                    let mut src = vec![0; table.columns.div_ceil(8)];
                    if pattern < table.columns {
                        set_bit(&mut src, pattern, 1);
                    } else if pattern == table.columns + 1 {
                        src.fill(0xff);
                    } else if pattern == table.columns + 2 {
                        src.fill(0xa5);
                    }
                    let mut expected = vec![0; table.rows.div_ceil(8)];
                    for row in 0..table.rows {
                        let mut bit = 0;
                        for col in 0..table.columns {
                            bit ^= get_bit(&src, col)
                                & ((table.words[row * table.stride + col / 64] >> (col % 64))
                                    as u8
                                    & 1);
                        }
                        set_bit(&mut expected, row, bit);
                    }
                    let mut actual = vec![0xff; expected.len()];
                    matrix_mul_table(&mut actual, &src, table);
                    assert_eq!(actual, expected);
                }
            }
        }
    }

    #[test]
    fn tree_polynomial_reduction() {
        for tables in [
            Tau128Small::VOLE_TABLES,
            Tau192Small::VOLE_TABLES,
            Tau192FastEM::VOLE_TABLES,
            Tau256Small::VOLE_TABLES,
        ] {
            for &modulus in tables.tree_moduli {
                let degree = 15 - modulus.leading_zeros() as usize;
                let limit = 2 * degree;
                // A coefficient-based polynomial long division, using explicit
                // coefficient arrays rather than word masks and shifts.
                for value in (0..limit).map(|i| 1u32 << i).chain([
                    0,
                    (1u32 << limit) - 1,
                    0xaaaa_aaaa & ((1u32 << limit) - 1),
                ]) {
                    let mut coeff: Vec<u8> = (0..limit).map(|i| ((value >> i) & 1) as u8).collect();
                    for i in (degree..limit).rev() {
                        if coeff[i] != 0 {
                            for j in 0..=degree {
                                coeff[i - degree + j] ^= ((modulus >> j) & 1) as u8;
                            }
                        }
                    }
                    let expected = coeff[..degree]
                        .iter()
                        .enumerate()
                        .fold(0u16, |acc, (i, &b)| acc | (u16::from(b) << i));
                    assert_eq!(reduce_tree_product(value, modulus, degree), expected);
                }
            }
        }
    }

    #[test]
    fn correction_buffer_sizes_are_exact() {
        type P = FAEST128fParameters;
        let c_len = (<<P as FAESTParameters>::Tau as TauParameters>::Tau::USIZE - 1)
            * <<P as FAESTParameters>::OWF as OWFParameters>::LBytes::USIZE;
        let cm_len = 10
            * <<P as FAESTParameters>::Tau as TauParameters>::VOLE_TABLES
                .gates
                .div_ceil(8);
        for (c_size, cm_size) in [
            (c_len - 1, cm_len),
            (c_len + 1, cm_len),
            (c_len, cm_len - 1),
            (c_len, cm_len + 1),
        ] {
            let mut c = vec![0x5a; c_size];
            let mut cm = vec![0xa5; cm_size];
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                volecommit::<P>(
                    VoleCommitmentCRefMut::new(&mut c),
                    &mut cm,
                    &Array::default(),
                    &IV::default(),
                );
            }));
            assert!(result.is_err());
            assert!(c.iter().all(|&b| b == 0x5a));
            assert!(cm.iter().all(|&b| b == 0xa5));
        }
    }
}
