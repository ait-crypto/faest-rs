//! Packed bilinear multiplication tables. Bit i is word i/64, bit i%64.
//! These descriptors borrow build-generated static storage and never allocate.
// Tables are selected by Tau parameters

#![allow(dead_code)]
#[derive(Debug)]
pub(crate) struct PackedMatrix {
    pub rows: usize,
    pub columns: usize,
    /// Number of words per row, including zero padding.
    pub stride: usize,
    /// Caller may assume zero-padding
    pub words: &'static [u64],
}

#[derive(Debug)]
pub(crate) struct VoleTables {
    pub name: &'static str,
    pub lambda: usize,
    pub tau: usize,
    pub grinding_bits: usize,
    pub gates: usize,
    pub f: PackedMatrix,
    pub g: PackedMatrix,
    pub w_tree: PackedMatrix,
    pub w_gate: PackedMatrix,
    pub w_crt: PackedMatrix,
    pub tree_moduli: &'static [u16],
    /// Product of the tree moduli, including its leading coefficient.
    /// Caller may assume zero-padding
    pub m_tree: &'static [u64],
}
include!(concat!(env!("OUT_DIR"), "/vole_tables.rs"));
