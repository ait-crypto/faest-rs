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
        load_u64, set_bit, xor_arrays_inplace,
    },
    vole::tables::{PackedMatrix, VoleTables},
};
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec};
use cmov::Cmov;
use core::{
    marker::PhantomData,
    ops::{Index, IndexMut, Mul},
};
use hybrid_array::{
    Array, ArraySize,
    typenum::{Prod, Sum, U1, U2, U8, Unsigned},
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
    debug_assert_eq!(dst.len(), table.rows.div_ceil(8));
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
    dst.fill(0);
    debug_assert_eq!(dst.len(), dst_bits.div_ceil(8));
    for bit in 0..src_bits {
        let mask = 0u64.wrapping_sub(u64::from(get_bit(src, bit)));
        xor_shifted_table(dst, dst_bits, table, table_bits, bit, mask);
    }
}

fn reduce_tree_product(mut value: u32, modulus: u16, degree: usize) -> u16 {
    for bit in (degree..2 * degree).rev() {
        let mut mask = 0u32;
        mask.cmovnz(&u32::MAX, ((value >> bit) & 1) as u8);
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

    // faest parameters ensure require buffer lengths are always met
    debug_assert_eq!(sd.len(), 1 << di);
    debug_assert_eq!(v.len(), di);
    debug_assert!(scratch.len() > di);
    if !ubot {
        debug_assert_eq!(u.len(), LHatBytes::USIZE);
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

#[allow(clippy::type_complexity)]
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

#[allow(clippy::type_complexity)]
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
        for (i, modulus) in tables.tree_moduli.iter().enumerate().take(tau) {
            // line 19
            let di = P::Tau::bavc_max_node_depth(i);
            let columns = &raw_q[offset..offset + di];
            let reduced = tree_product_share(columns, ell_m, *modulus);
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
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

    use super::test_vectors::{DataVOLE, ROOT_KEY, VOLE_TEST_VECTORS};
    use super::*;
    use crate::{parameter::*, utils::test::hash_array};

    fn witness_rows<L: ArraySize>(columns: &[Array<u8, L>], lambda_bytes: usize) -> Vec<u8> {
        let mut rows = vec![0; L::USIZE * 8 * lambda_bytes];
        for (bit, row) in rows.chunks_exact_mut(lambda_bytes).enumerate() {
            for (col, column) in columns.iter().enumerate() {
                set_bit(row, col, get_bit(column, bit));
            }
        }
        rows
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
            &IV::from(tv.iv),
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
            &IV::from(tv.iv),
        )
        .expect("VOLEReconstruct failed");
        assert_eq!(rec.com.as_slice(), tv.h, "reconstructed com");
        assert_eq!(hash_array(&witness_rows(&rec.q, r.len())), tv.hashed_q, "q");
        assert_eq!(
            hash_array(rec.q_bar.as_flattened()),
            tv.hashed_bar_q,
            "q_bar"
        );
    }

    macro_rules! vector_test {
        ($name:ident, $p:ty, $i:expr) => {
            #[test]
            fn $name() {
                check_vector::<$p>(&VOLE_TEST_VECTORS[$i]);
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
}
