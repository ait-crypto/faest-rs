#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unexpected_cfgs)]

#[cfg(has_valgrind)]
pub const HAS_VALGRIND: bool = true;
#[cfg(not(has_valgrind))]
pub const HAS_VALGRIND: bool = false;

#[cfg(has_valgrind)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(not(has_valgrind))]
mod bindings_fallback;
#[cfg(not(has_valgrind))]
pub use bindings_fallback::*;
