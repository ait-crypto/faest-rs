//! FAEST v3 VOLE commitments and reconstruction
//!
//! Algorithm line comments refer to Figure 5.6, 6.2 and 6.3:
//! <https://faest.info/faest-spec-v3.0.pdf>.

pub(crate) mod tables;

use crate::{
    bavc::{BatchVectorCommitment, BavcCommitResult, BavcDecommitment, BavcOpenResult},
    parameter::{
        FAESTParameters, MaxDepthPlusOne, NMask, OWFParameters, SecurityParameter, TauParameters,
        ToBytes,
    },
    prg::{IV, PseudoRandomGenerator},
    random_oracles::{Hasher, RandomOracle},
    utils::{
        Reader, bit_word_mask, decode_all_chall_3, extract_bit_slice, get_bit, insert_bit_slice,
        load_u64, set_bit, xor_arrays, xor_arrays_inplace,
    },
    vole::tables::{PackedMatrix, VoleTables},
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

/// Reconstructed VOLE shares. Bit i is coefficient i (least significant bit first).
#[derive(Clone, Debug, Default)]
pub struct VoleReconstructResult<LambdaBytes, LBytes>
where
    LambdaBytes: SecurityParameter,
    LBytes: ArraySize,
{
    pub com: Array<u8, Prod<LambdaBytes, U2>>,
    /// Contiguous witness columns; a witness row encodes one field element.
    pub q: Box<Array<Array<u8, LBytes>, Prod<LambdaBytes, U8>>>,
    /// Ten mask shares, encoded as field coefficients in little-endian order.
    pub q_bar: Array<Array<u8, LambdaBytes>, NMask>,
    pub delta: Array<u8, LambdaBytes>,
}

/// Immutable signature storage containing tau-1 witness-length corrections.
#[derive(Copy, Clone, Debug)]
pub(crate) struct VoleCommitmentCRef<'a, LBytes>(&'a [u8], PhantomData<LBytes>);

impl<LBytes: ArraySize> Index<usize> for VoleCommitmentCRef<'_, LBytes> {
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index * LBytes::USIZE..(index + 1) * LBytes::USIZE]
    }
}

impl<'a, LBytes: ArraySize> VoleCommitmentCRef<'a, LBytes> {
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

#[inline]
fn h5_init<P: FAESTParameters>(iv: &IV, e: usize) -> impl Hasher + Clone {
    let mut hash = <P::BAVC as BatchVectorCommitment>::RO::h5_init();
    hash.update(iv);
    hash.update(&(e as u32).to_le_bytes());
    hash
}

/// Compute a packed binary matrix product of the input vector, clearing all output padding
fn matrix_mul_table(dst: &mut [u8], src: &[u8], table: &PackedMatrix) {
    assert_eq!(dst.len(), table.rows.div_ceil(8));
    dst.fill(0);
    for i in 0..table.rows {
        let mut acc = 0;
        for j in 0..table.stride {
            // Note: table words are always zero-padded
            acc ^= table.words[i * table.stride + j] & load_u64(src, j);
        }
        set_bit(dst, i, (acc.count_ones() & 1) as u8); // set parity bit
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
    let dst_word_idx = shift / 64;
    let dst_bit_offset = shift % 64;

    let mut carry = 0;
    for (i, &word) in table.iter().enumerate() {
        let shifted = (word << dst_bit_offset) | carry;
        carry = word.unbounded_shr(64 - dst_bit_offset as u32);
        xor_dst_word(dst, dst_word_idx + i, dst_bits, shifted & mask);
    }
    xor_dst_word(
        dst,
        dst_word_idx + table_bits.div_ceil(64),
        dst_bits,
        carry & mask,
    );
}

/// Compute an unreduced GF(2) polynomial product, in coefficient order (most significant first)
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

fn tree_product_share<LHatBytes: ArraySize>(
    columns: &[Array<u8, LHatBytes>],
    bit_offset: usize,
    modulus: u16,
) -> u16 {
    let degree = columns.len();
    let mut acc = 0;

    for (t, column) in columns.iter().enumerate() {
        acc ^= u32::from(extract_bit_slice(column, bit_offset, degree as u32)) << t;
    }
    reduce_tree_product(acc, modulus, degree)
}

/// XOR wire labels selected by G
fn gate_label<LHatBytes: ArraySize>(
    ell_e: &mut [u8],
    raw_v: &[Array<u8, LHatBytes>],
    g: &PackedMatrix,
    e: usize,
) {
    ell_e.fill(0);
    for word in 0..g.stride {
        let mut bits = g.words[e * g.stride + word];
        while bits != 0 {
            let col = word * 64 + bits.trailing_zeros() as usize;
            xor_arrays_inplace(ell_e, &raw_v[col][..ell_e.len()]);
            bits &= bits - 1; // clear the lowest 1 bit
        }
    }
}

fn recombine_mask_shares<LambdaBytes: SecurityParameter, LambdaMinusWgrind: ArraySize>(
    v_bar: &mut Array<Array<u8, LambdaBytes>, NMask>,
    r_tilde: &[Array<u8, LambdaMinusWgrind>],
    v_tilde: &[u8],
    tables: &VoleTables,
) {
    let mut product = Array::<u8, LambdaBytes>::default();
    let gate_bytes = tables.gates.div_ceil(8);

    for m in 0..NMask::USIZE {
        matrix_mul_table(&mut v_bar[m], &r_tilde[m], &tables.w_tree);
        matrix_mul_table(
            &mut product,
            &v_tilde[m * gate_bytes..(m + 1) * gate_bytes],
            &tables.w_gate,
        );
        xor_arrays_inplace(&mut v_bar[m], &product);
    }
}

fn crt_transform_columns<LBytes: ArraySize, LHatBytes: ArraySize>(
    v: &mut [Array<u8, LBytes>],
    raw_v: &[Array<u8, LHatBytes>],
    w_crt: &PackedMatrix,
) {
    for (i, v_i) in v.iter_mut().enumerate() {
        for word_idx in 0..w_crt.stride {
            let mut bits = w_crt.words[i * w_crt.stride + word_idx];
            while bits != 0 {
                let input = word_idx * 64 + bits.trailing_zeros() as usize;
                xor_arrays_inplace(v_i, &raw_v[input][..LBytes::USIZE]);
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

    assert_eq!(sd.len(), 1 << di);
    assert_eq!(v.len(), di);
    assert!(scratch.len() > di);
    if !ubot {
        assert_eq!(u.len(), LHatBytes::USIZE);
    }
    v.fill(Array::default());

    // One current vector and at least di saved left subtrees.
    let (current, stack) = scratch.split_last_mut().unwrap();

    // optimized traversal algo with reduced scratch memory: d0+1 vs 2^d_i
    for (leaf, seed) in sd.enumerate() {
        // ConvertToVOLE (Figure 5.6), lines 1-4: bottom expands to zero.
        current.fill(0);
        if leaf != 0 || !ubot {
            BAVC::PRG::new_prg(seed, iv, TWEAK_OFFSET + round).read(current);
        }

        let mut level = 0;
        while (leaf >> level) & 1 != 0 {
            // line 8-9
            xor_arrays_inplace(&mut v[level], current);
            xor_arrays_inplace(current, &stack[level]);
            level += 1;
        }

        if level != di {
            // becomes left subtree with 2^level leaves
            stack[level].copy_from_slice(current);
        } else if !ubot {
            // line 10 (u = r_d,0)
            u.copy_from_slice(current);
        }
    }
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
    let d0 = P::Tau::bavc_max_node_depth(0);
    let n_mult = tables.gates;
    let n_mult_bytes = n_mult.div_ceil(8);

    // line 1
    let BavcCommitResult { com, decom, seeds } = P::BAVC::commit(r, iv);

    // V stored in column major
    let mut raw_v = Box::<Array<Array<u8, P::LHatBytes>, P::LambdaMinusWGrind>>::default();
    // extra buffers
    let mut ui = Box::<Array<Array<u8, P::LHatBytes>, <P::Tau as TauParameters>::Tau>>::default();
    let mut scratch = Box::<Array<Array<u8, P::LHatBytes>, MaxDepthPlusOne<P>>>::default();

    // line 2-4
    let mut offset = 0;
    for i in 0..tau {
        let tree_offset = P::Tau::bavc_index_offset(i);
        let di = P::Tau::bavc_max_node_depth(i);
        let ni = 1 << di;
        convert_to_vole::<P::BAVC, P::LHatBytes>(
            seeds[tree_offset..tree_offset + ni].iter(),
            iv,
            i as u32,
            false,
            &mut ui[i],
            &mut raw_v[offset..offset + di],
            &mut scratch,
        );
        offset += di;
    }

    // line 6-8
    let mut u = Box::<Array<u8, <P::OWF as OWFParameters>::LBytes>>::default();
    u.copy_from_slice(&ui[0][..<P::OWF as OWFParameters>::LBytes::USIZE]);
    for i in 1..tau {
        c[i - 1].copy_from_slice(&u);
        xor_arrays_inplace(&mut c[i - 1], &ui[i][..ell_bytes]);
    }

    // line 10
    let mut u_hi_all = vec![0; (NMask::USIZE * P::WGRIND::USIZE).div_ceil(8)];
    <P::BAVC as BatchVectorCommitment>::PRG::new_prg(r, iv, TWEAK_OFFSET - 1).read(&mut u_hi_all);

    let mut u_bar = Array::<Array<u8, <P::OWF as OWFParameters>::LambdaBytes>, NMask>::default();
    let mut r_tilde = Box::<Array<Array<u8, P::LambdaMinusWGrind>, NMask>>::default();
    let mut u_bar_high = Array::<u8, <P::OWF as OWFParameters>::LambdaBytes>::default();
    for m in 0..NMask::USIZE {
        offset = 0;
        let ell_m = ell + m * d0;

        let mut u_low = Array::<u8, ToBytes<P::LambdaMinusWGrind>>::default();
        for i in 0..tau {
            let d_i = P::Tau::bavc_max_node_depth(i);

            // line 13
            insert_bit_slice(
                &mut u_low,
                offset,
                extract_bit_slice(&ui[i], ell_m, d_i as u32),
                d_i as u32,
            );

            // lines 15-17
            let reduced =
                tree_product_share(&raw_v[offset..offset + d_i], ell_m, tables.tree_moduli[i]);
            insert_bit_slice(&mut r_tilde[m], offset, reduced, d_i as u32);
            offset += d_i;
        }

        // line 14
        matrix_mul_table(&mut u_bar[m], &u_low, &tables.w_crt);
        let u_hi = extract_bit_slice(&u_hi_all, m * P::WGRIND::USIZE, P::WGRIND::USIZE as u32);
        // TODO: when carry-less mul available, consider mapping into GF elements
        poly_mul(
            &mut u_bar_high,
            &u_hi.to_le_bytes(),
            P::WGRIND::USIZE,
            tables.m_tree,
            P::LambdaMinusWGrind::USIZE + 1,
        );
        xor_arrays_inplace(&mut u_bar[m], &u_bar_high);

        // line 26
        matrix_mul_table(
            &mut c_mult[m * n_mult_bytes..(m + 1) * n_mult_bytes],
            &u_bar[m],
            &tables.f,
        );
    }

    // line 21
    let mut v_tilde = vec![0; NMask::USIZE * n_mult_bytes];
    let mut ell_e = Array::<u8, <P::OWF as OWFParameters>::LambdaBytes>::default();
    for e in 0..n_mult {
        // line 22: L_e_0
        gate_label(&mut ell_e, &raw_v, &tables.g, e);

        // init hashers
        let mut hash_one = h5_init::<P>(iv, e);
        let mut hash_two = hash_one.clone();

        // line 23: hash(L_e_0)
        let mut he_0 = [0u8; 2];
        hash_one.update(&ell_e);
        hash_one.finish().read(&mut he_0);

        // line 22: L_e_1
        xor_arrays_inplace(
            &mut ell_e,
            &u[..<P::OWF as OWFParameters>::LambdaBytes::USIZE],
        );

        // line 23: hash(L_e_1)
        let mut he_1 = [0u8; 2];
        hash_two.update(&ell_e);
        hash_two.finish().read(&mut he_1);

        for m in 0..NMask::USIZE {
            // line 25
            // TODO: maybe transpose he_0s, he_1s instead
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
    recombine_mask_shares(&mut v_bar, &r_tilde, &v_tilde, tables);

    // line 31-32
    let mut v = Box::<
        Array<Array<u8, <P::OWF as OWFParameters>::LBytes>, <P::OWF as OWFParameters>::Lambda>,
    >::default();
    // TODO: possibly directly add transpose here
    crt_transform_columns(&mut v, &raw_v, &tables.w_crt);

    VoleCommitResult {
        com,
        decom,
        u,
        v,
        u_bar,
        v_bar,
    }
}

pub fn volereconstruct<P: FAESTParameters>(
    chall: &Array<u8, <P::BAVC as BatchVectorCommitment>::LambdaBytes>,
    decom_i: &BavcOpenResult,
    c: VoleCommitmentCRef<<P::OWF as OWFParameters>::LBytes>,
    c_mult: &[u8],
    iv: &IV,
) -> Option<
    VoleReconstructResult<
        <P::BAVC as BatchVectorCommitment>::LambdaBytes,
        <P::OWF as OWFParameters>::LBytes,
    >,
> {
    let tables = P::Tau::VOLE_TABLES;
    let tau = <P::Tau as TauParameters>::Tau::USIZE;
    let ell = <P::OWF as OWFParameters>::L::USIZE;
    let ell_bytes = <P::OWF as OWFParameters>::LBytes::USIZE;
    // TODO: would be nice if this was a constant
    let n_mult_bytes = tables.gates.div_ceil(8);
    let d0 = P::Tau::bavc_max_node_depth(0);

    // lines 1
    let i_delta = decode_all_chall_3::<P::Tau>(chall);

    // lines 3
    let rec = P::BAVC::reconstruct(decom_i, &i_delta, iv)?;

    let mut raw_q = Box::<Array<Array<u8, P::LHatBytes>, P::LambdaMinusWGrind>>::default();
    let mut scratch =
        Box::<Array<Array<u8, P::LHatBytes>, Sum<<P::Tau as TauParameters>::K, U1>>>::default(); // Tau::K is always >= d0

    // lines 6-10
    let zeros = Array::default();
    let mut seed_offset = 0;
    let mut offset = 0;
    for i in 0..tau {
        let delta_i = i_delta[i] as usize;
        let di = P::Tau::bavc_max_node_depth(i);
        let ni = 1 << di;

        // line 7: iterate the XOR-permuted seeds
        let seeds = (0..ni).map(|j| {
            if j == 0 {
                &zeros
            } else {
                let original = j ^ delta_i;
                &rec.seeds[seed_offset + original - usize::from(original > delta_i)]
            }
        });

        // line 8
        let columns = &mut raw_q[offset..offset + di];
        convert_to_vole::<P::BAVC, P::LHatBytes>(
            seeds,
            iv,
            i as u32,
            true,
            &mut [],
            columns,
            &mut scratch,
        );

        // line 11
        if i != 0 {
            for (d, column) in columns.iter_mut().enumerate() {
                let delta_mask = 0u8.wrapping_sub(((delta_i >> d) & 1) as u8);
                for (q_ij, &c_ij) in column[..ell_bytes].iter_mut().zip(&c[i - 1]) {
                    *q_ij ^= c_ij & delta_mask;
                }
            }
        }
        offset += di;
        seed_offset += ni - 1;
    }

    // line 13-14: delta prime is the low challenge bits
    let mut delta = Array::default();
    matrix_mul_table(&mut delta, chall, &tables.w_crt);

    // line 16
    let mut r_tilde = Box::<Array<Array<u8, P::LambdaMinusWGrind>, NMask>>::default();
    for m in 0..NMask::USIZE {
        let ell_m = ell + m * d0;
        offset = 0;
        for i in 0..tau {
            // line 19
            let di = P::Tau::bavc_max_node_depth(i);
            let mut columns = &mut raw_q[offset..offset + di];
            let reduced = tree_product_share(&mut columns, ell_m, tables.tree_moduli[i]);
            insert_bit_slice(&mut r_tilde[m], offset, reduced, di as u32);
            offset += di;
        }
    }

    // lines 21-27: corrected witness columns are the verifier's wire labels.
    let mut q_tilde = vec![0; NMask::USIZE * n_mult_bytes];
    let mut gamma = vec![0; n_mult_bytes];
    let mut l_e_prime = Array::<u8, <P::OWF as OWFParameters>::LambdaBytes>::default();
    matrix_mul_table(&mut gamma, chall, &tables.g);
    for e in 0..tables.gates {
        // line 24
        gate_label(&mut l_e_prime, &raw_q, &tables.g, e);

        // line 25
        let mut hash = h5_init::<P>(iv, e);
        hash.update(&l_e_prime);
        let mut he = [0u8; 2];
        hash.finish().read(&mut he);

        // lines 27: part one (implicit transpose of he)
        // TODO: transpose he vector instead
        for m in 0..NMask::USIZE {
            set_bit(
                &mut q_tilde[m * n_mult_bytes..(m + 1) * n_mult_bytes],
                e,
                get_bit(&he, m),
            );
        }
    }

    // lines 27: part two
    for m in 0..NMask::USIZE {
        for j in 0..n_mult_bytes {
            q_tilde[m * n_mult_bytes + j] ^= gamma[j] & c_mult[m * n_mult_bytes + j];
        }
    }

    // line 30
    let mut q_bar = Array::default();
    recombine_mask_shares(&mut q_bar, &r_tilde, &q_tilde, tables);

    // lines 31: lift witness rows
    let mut q = Box::<
        Array<Array<u8, <P::OWF as OWFParameters>::LBytes>, <P::OWF as OWFParameters>::Lambda>,
    >::default();
    crt_transform_columns(&mut q, &raw_q, &tables.w_crt);

    // line 33
    Some(VoleReconstructResult {
        com: rec.com,
        q,
        q_bar,
        delta,
    })
}

#[cfg(test)]
#[path = "../tests/data/vole_tvs.rs"]
mod test_vectors;

#[cfg(test)]
mod test {
// TODO: refactor

    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

    use super::test_vectors::{DataVOLE, FAEST_EM_TEST_VECTORS, ROOT_KEY, VOLE_TEST_VECTORS};
    use super::*;
    use crate::{fields::Field, parameter::*, utils::test::hash_array};

    fn witness_rows<L: ArraySize>(columns: &[Array<u8, L>], lambda_bytes: usize) -> Vec<u8> {
        let mut rows = vec![0; L::USIZE * 8 * lambda_bytes];
        for (bit, row) in rows.chunks_exact_mut(lambda_bytes).enumerate() {
            for (col, column) in columns.iter().enumerate() {
                set_bit(row, col, get_bit(column, bit));
            }
        }
        rows
    }

    fn check_correlations<P: FAESTParameters>(
        committed: &VoleCommitResult<
            <P::BAVC as BatchVectorCommitment>::LambdaBytes,
            <P::BAVC as BatchVectorCommitment>::NLeafCommit,
            <P::OWF as OWFParameters>::LBytes,
        >,
        reconstructed: &VoleReconstructResult<
            <P::BAVC as BatchVectorCommitment>::LambdaBytes,
            <P::OWF as OWFParameters>::LBytes,
        >,
        challenge: &[u8],
    ) {
        assert_eq!(committed.com, reconstructed.com);
        let table = &P::Tau::VOLE_TABLES.w_crt;
        let mut expected_delta = vec![0; table.rows.div_ceil(8)];
        // Independent coefficient matrix product, including non-word-aligned inputs.
        for row in 0..table.rows {
            let mut bit = 0;
            for col in 0..table.columns {
                bit ^= get_bit(challenge, col)
                    & ((table.words[row * table.stride + col / 64] >> (col % 64)) as u8 & 1);
            }
            set_bit(&mut expected_delta, row, bit);
        }
        assert_eq!(reconstructed.delta.as_slice(), expected_delta);
        for (col, (q, v)) in reconstructed.q.iter().zip(committed.v.iter()).enumerate() {
            let mask = 0u8.wrapping_sub(get_bit(&expected_delta, col));
            for byte in 0..<P::OWF as OWFParameters>::LBytes::USIZE {
                assert_eq!(
                    q[byte],
                    v[byte] ^ (committed.u[byte] & mask),
                    "witness column {col}, byte {byte}"
                );
            }
        }
        type F<P> =
            <<<P as FAESTParameters>::OWF as OWFParameters>::BaseParams as BaseParameters>::Field;
        let delta = F::<P>::from(reconstructed.delta.as_slice());
        for m in 0..NMask::USIZE {
            let expected = F::<P>::from(committed.v_bar[m].as_slice())
                + F::<P>::from(committed.u_bar[m].as_slice()) * delta;
            assert_eq!(
                reconstructed.q_bar[m].as_slice(),
                expected.as_bytes().as_slice(),
                "mask {m}"
            );
        }
    }

    fn check_vector<P: FAESTParameters>(tv: &DataVOLE) {
        assert_eq!(tv.lambda as usize, <P::OWF as OWFParameters>::Lambda::USIZE);
        let len = <P::OWF as OWFParameters>::LBytes::USIZE;
        let mut c = vec![0xff; (<P::Tau as TauParameters>::Tau::USIZE - 1) * len];
        let mut cm = vec![0xff; 10 * P::Tau::VOLE_TABLES.gates.div_ceil(8)];
        let r =
            Array::try_from(&ROOT_KEY[..<P::OWF as OWFParameters>::LambdaBytes::USIZE]).unwrap();

        // check VOLECommit
        let res = volecommit::<P>(
            VoleCommitmentCRefMut::new(&mut c),
            &mut cm,
            &r,
            &IV::default(),
        );
        assert_eq!(res.com.as_slice(), tv.h, "com");
        assert_eq!(hash_array(&c), tv.hashed_c, "c");
        assert_eq!(hash_array(&cm), tv.hashed_c_mult, "c_mult");
        assert_eq!(hash_array(&res.u), tv.hashed_u, "u");
        // transpose V matrix to match test vector
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

        // check VOLEReconstruct
        let challenge = Array::try_from(tv.chall).unwrap();
        let indices = decode_all_chall_3::<P::Tau>(&challenge);
        let opening = P::BAVC::open(&res.decom, &indices).unwrap();
        let rec = volereconstruct::<P>(
            &challenge,
            &opening,
            VoleCommitmentCRef::new(&c),
            &cm,
            &IV::default(),
        )
        .expect("VOLEReconstruct failed");
        assert_eq!(hash_array(&witness_rows(&rec.q, r.len())), tv.hashed_q, "q");
        assert_eq!(
            hash_array(rec.q_bar.as_flattened()),
            tv.hashed_bar_q,
            "q_bar"
        );
        check_correlations::<P>(&res, &rec, &challenge);

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
        // Exercise the complete path with a different root and nonzero IV.
        let mut other_root = r.clone();
        other_root[0] ^= 0xa5;
        let iv = IV::from([0x37; 16]);
        let other = volecommit::<P>(
            VoleCommitmentCRefMut::new(&mut c2),
            &mut cm2,
            &other_root,
            &iv,
        );
        let opening = P::BAVC::open(&other.decom, &indices).unwrap();
        let rec = volereconstruct::<P>(
            &challenge,
            &opening,
            VoleCommitmentCRef::new(&c2),
            &cm2,
            &iv,
        )
        .unwrap();
        check_correlations::<P>(&other, &rec, &challenge);
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
        // Independent coefficient convolution with zero-padded tables, dirty source
        // padding and carries past the final source/table word.
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

    fn check_streaming<B: BatchVectorCommitment, L: ArraySize>() {
        let iv = IV::from([0x91; 16]);
        for tree in [0, <B::TAU as TauParameters>::Tau::USIZE - 1] {
            let depth = B::TAU::bavc_max_node_depth(tree);
            let count = 1 << depth;
            let seeds: Vec<Array<u8, B::LambdaBytes>> = (0..count)
                .map(|leaf| {
                    let mut seed = Array::default();
                    for (byte, dst) in seed.iter_mut().enumerate() {
                        *dst = (leaf as u8)
                            .wrapping_mul(37)
                            .wrapping_add((leaf >> 8) as u8)
                            .wrapping_add(byte as u8);
                    }
                    seed
                })
                .collect();
            let mut scratch = vec![Array::<u8, L>::default(); B::TAU::bavc_max_node_depth(0) + 1];
            for hidden in [None, Some(0), Some(1), Some(count / 2), Some(count - 1)] {
                for column in &mut scratch {
                    column.fill(0xa5);
                }
                let mut expanded = vec![Array::<u8, L>::default(); count];
                for (leaf, out) in expanded.iter_mut().enumerate() {
                    if hidden.is_some() && leaf == 0 {
                        continue;
                    }
                    let original = leaf ^ hidden.unwrap_or(0);
                    B::PRG::new_prg(&seeds[original], &iv, TWEAK_OFFSET + tree as u32).read(out);
                }
                // Straightforward specification traversal, materializing all leaves.
                let mut expected = vec![Array::<u8, L>::default(); depth];
                for (level, column) in expected.iter_mut().enumerate() {
                    for pair in 0..count >> (level + 1) {
                        xor_arrays_inplace(column, &expanded[2 * pair + 1]);
                        let mut sum = expanded[2 * pair].clone();
                        xor_arrays_inplace(&mut sum, &expanded[2 * pair + 1]);
                        expanded[pair] = sum;
                    }
                }
                let mut actual = vec![Array::<u8, L>::default(); depth];
                for col in &mut actual {
                    col.fill(0xff);
                }
                let mut u = vec![0x5a; L::USIZE];
                let bottom = Array::default();
                let permuted = (0..count).map(|leaf| {
                    if hidden.is_some() && leaf == 0 {
                        &bottom
                    } else {
                        &seeds[leaf ^ hidden.unwrap_or(0)]
                    }
                });
                convert_to_vole::<B, L>(
                    permuted,
                    &iv,
                    tree as u32,
                    hidden.is_some(),
                    &mut u,
                    &mut actual,
                    &mut scratch,
                );
                assert_eq!(actual, expected, "tree={tree}, hidden={hidden:?}");
                if hidden.is_none() {
                    assert_eq!(u, expanded[0].as_slice());
                } else {
                    assert!(u.iter().all(|&b| b == 0x5a));
                }
            }
        }
    }

    #[test]
    fn streaming_conversion_matches_leaf_reduction() {
        use hybrid_array::typenum::{U9, U17, U135};
        check_streaming::<BAVC128Small<crate::fields::GF128>, U1>();
        check_streaming::<BAVC128Fast<crate::fields::GF128>, U9>();
        check_streaming::<BAVC192SmallEM, U17>();
        check_streaming::<BAVC256FastEM, U135>();
    }

    #[test]
    fn reconstruction_opening_contents() {
        type P = FAEST128fParameters;
        let tables = <P as FAESTParameters>::Tau::VOLE_TABLES;
        let mut c = vec![
            0;
            (tables.tau - 1)
                * <<P as FAESTParameters>::OWF as OWFParameters>::LBytes::USIZE
        ];
        let mut cm = vec![0; NMask::USIZE * tables.gates.div_ceil(8)];
        let iv = IV::default();
        let committed = volecommit::<P>(
            VoleCommitmentCRefMut::new(&mut c),
            &mut cm,
            &Array::default(),
            &iv,
        );
        let challenge = Array::try_from(VOLE_TEST_VECTORS[1].chall).unwrap();
        let indices = decode_all_chall_3::<<P as FAESTParameters>::Tau>(&challenge);
        let opening = <P as FAESTParameters>::BAVC::open(&committed.decom, &indices).unwrap();
        let reconstruct = |opening: &BavcOpenResult, c: &[u8], cm: &[u8]| {
            volereconstruct::<P>(&challenge, opening, VoleCommitmentCRef::new(c), cm, &iv)
        };
        // Padding is allowed up to Topen, but must be zero.
        let pad = [0u8; 16];
        let mut padded = opening.clone();
        padded.nodes.push(&pad);
        let rec = reconstruct(&padded, &c, &cm).unwrap();
        assert_eq!(rec.com, committed.com);
        let nonzero_pad = [1u8; 16];
        padded.nodes.pop();
        padded.nodes.push(&nonzero_pad);
        assert!(reconstruct(&padded, &c, &cm).is_none());
        // Reconstruction computes a commitment; it cannot authenticate it.
        let mut altered_com = opening.coms[0].to_vec();
        altered_com[0] ^= 1;
        let mut altered = opening.clone();
        altered.coms[0] = &altered_com;
        assert_ne!(reconstruct(&altered, &c, &cm).unwrap().com, committed.com);
    }
}
