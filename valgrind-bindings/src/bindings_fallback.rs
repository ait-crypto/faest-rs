pub unsafe fn valgrind_make_mem_undefined(
    _qzz_addr: *mut ::core::ffi::c_void,
    _qzz_len: usize,
) -> ::core::ffi::c_ulonglong {
    panic!("Unable to find valgrind library")
}

pub unsafe fn valgrind_make_mem_defined(
    _qzz_addr: *mut ::core::ffi::c_void,
    _qzz_len: usize,
) -> ::core::ffi::c_ulonglong {
    panic!("Unable to find valgrind library")
}
