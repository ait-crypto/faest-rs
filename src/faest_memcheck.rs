use crate::{
    FAEST128fSigningKey, FAEST128sSigningKey, FAEST192fSigningKey, FAEST192sSigningKey,
    FAEST256fSigningKey, FAEST256sSigningKey, FAESTEM128fSigningKey, FAESTEM128sSigningKey,
    FAESTEM192fSigningKey, FAESTEM192sSigningKey, FAESTEM256fSigningKey, FAESTEM256sSigningKey,
};
use core::ffi::c_void;
use pastey::paste;
use std::convert::AsRef;
use valgrind_bindings::{valgrind_make_mem_defined, valgrind_make_mem_undefined};

/// Defines valgrind wrappers that allow checking constant-time implementation.
pub trait FaestMemcheck {
    /// Makes valgrind see underlying memory as addressable but undefined.
    ///
    ///
    /// Can be used in combination with valgrind to verify constant-time implementation.
    /// NOTE: this wrapper should mimic behaviors of the VALGRIND_MAKE_MEMORY_UNDEFINED macro (see valgrind/memcheck.h).
    fn faest_classify(&self);

    /// Makes valgrind see underlying memory as addressable and defined.
    ///
    /// Can be used in combination with valgrind to verify constant-time implementation.
    /// NOTE: this wrapper should mimic behaviors of the VALGRIND_MAKE_MEMORY_DEFINED macro (see valgrind/memcheck.h).
    fn faest_declassify(&self);
}

macro_rules! define_impl {
    ($param:ident) => {
        paste! {
            impl FaestMemcheck for [<$param SigningKey>] {
                fn faest_classify(&self) {
                    unsafe {
                    valgrind_make_mem_undefined(self.0.owf_key.as_ptr() as *mut c_void, self.0.owf_key.len());
                    }
                }

                fn faest_declassify(&self) {
                    unsafe {
                        valgrind_make_mem_defined(self.0.owf_key.as_ptr() as *mut c_void, self.0.owf_key.len());
                    }
                }
            }
        }


    }
}

define_impl!(FAEST128f);
define_impl!(FAEST128s);
define_impl!(FAEST192f);
define_impl!(FAEST192s);
define_impl!(FAEST256f);
define_impl!(FAEST256s);
define_impl!(FAESTEM128f);
define_impl!(FAESTEM128s);
define_impl!(FAESTEM192f);
define_impl!(FAESTEM192s);
define_impl!(FAESTEM256f);
define_impl!(FAESTEM256s);

impl<T> FaestMemcheck for T
where
    T: AsRef<[u8]>,
{
    fn faest_classify(&self) {
        unsafe {
            valgrind_make_mem_undefined(self.as_ref().as_ptr() as *mut c_void, self.as_ref().len());
        }
    }

    fn faest_declassify(&self) {
        unsafe {
            valgrind_make_mem_defined(self.as_ref().as_ptr() as *mut c_void, self.as_ref().len());
        }
    }
}
