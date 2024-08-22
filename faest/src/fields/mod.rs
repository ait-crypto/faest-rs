pub(crate) mod large_fields;
pub(crate) mod small_fields;

pub use large_fields::{BigGaloisField, GF128, GF192, GF256};
pub use small_fields::{GaloisField, GF64, GF8};
