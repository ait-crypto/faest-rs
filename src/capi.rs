//! C interface to produce shared library with cargo-c
//!
//! The interface is intended by compatible with the reference implementation of FAEST.

use std::{ffi::c_int, slice};

use generic_array::GenericArray;
use libc::size_t;
use paste::paste;
use signature::Keypair;
use zeroize::Zeroize;

use crate::{ByteEncoding, KeypairGenerator};

/// Internal helper trait to map `Result`s to error codes
trait ResultToErrroCode: Sized {
    /// Map `Ok` values to `0`, `Err` to `-1`
    fn to_error_code(self) -> c_int;

    /// Apply [f] to `Ok`` values, map `Err` to `-1`
    fn map_to_error_code<F>(self, f: F) -> c_int
    where
        F: FnOnce(()) -> c_int;
}

impl ResultToErrroCode for Result<(), signature::Error> {
    fn to_error_code(self) -> c_int {
        self.map(|_| 0).unwrap_or(-1)
    }

    fn map_to_error_code<F>(self, f: F) -> c_int
    where
        F: FnOnce(()) -> c_int,
    {
        self.map(f).unwrap_or(-1)
    }
}

fn clear_private_key(sk: *mut u8, len: usize) {
    if !sk.is_null() {
        let sk = unsafe { slice::from_raw_parts_mut(sk, len) };
        sk.zeroize();
    }
}

macro_rules! define_capi_impl {
    (em, $bits:literal, $param:ident) => { define_capi_impl!(FAESTEM, FAEST_EM, $bits, $param); };
    ($bits:literal, $param:ident) => { define_capi_impl!(FAEST, FAEST, $bits, $param); };
    ($prefix:ident, $prefix_c:ident, $bits:literal, $param:ident) => {
        paste! {
            use crate::{
                [<$prefix $bits $param:lower>], [<$prefix $bits $param:lower SigningKey>], [<$prefix $bits $param:lower VerificationKey>],
            };

            fn [<$prefix_c:lower _ $bits $param:lower _keygen_impl>](sk: *mut u8, pk: *mut u8) -> c_int {
                if sk.is_null() || pk.is_null() {
                    return -1;
                }

                let sk = unsafe { slice::from_raw_parts_mut(sk, [<$prefix $bits $param:lower>]::SK_SIZE) };
                let pk = unsafe { slice::from_raw_parts_mut(pk, [<$prefix $bits $param:lower>]::PK_SIZE) };

                let key = [<$prefix $bits $param:lower SigningKey>]::generate(rand::thread_rng());
                sk.copy_from_slice(&key.to_bytes());
                pk.copy_from_slice(&key.verifying_key().to_bytes());
                0
            }

            fn [<$prefix_c:lower _ $bits $param:lower _sign_impl>](
                sk: *const u8,
                message: *const u8,
                message_len: size_t,
                signature: *mut u8,
                signature_len: *mut size_t,
            ) -> c_int {
                if sk.is_null()
                    || signature.is_null()
                    || signature_len.is_null()
                    || unsafe { *signature_len } < [<$prefix $bits $param:lower>]::SIGNATURE_SIZE
                    || (message.is_null() && message_len != 0)
                {
                    return -1;
                }

                let sk = unsafe { slice::from_raw_parts(sk, [<$prefix $bits $param:lower>]::SK_SIZE) };
                let msg = if message_len > 0 {
                    unsafe { slice::from_raw_parts(message, message_len) }
                } else {
                    &[]
                };
                let signature = unsafe { slice::from_raw_parts_mut(signature, [<$prefix $bits $param:lower>]::SIGNATURE_SIZE) };

                if let Ok(sk) = [<$prefix $bits $param:lower SigningKey>]::try_from(sk) {
                    let rho = [<$prefix $bits $param:lower>]::sample_rho(rand::thread_rng());
                    [<$prefix $bits $param:lower>]::sign(
                        msg,
                        &sk.0,
                        rho.as_slice(),
                        GenericArray::from_mut_slice(signature),
                    )
                    .map_to_error_code(|_| {
                        unsafe { *signature_len = [<$prefix $bits $param:lower>]::SIGNATURE_SIZE };
                        0
                    })
                } else {
                    -1
                }
            }

            fn [<$prefix_c:lower _ $bits $param:lower _sign_with_randomness_impl>](
                sk: *const u8,
                message: *const u8,
                message_len: size_t,
                rho: *const u8,
                rho_len: size_t,
                signature: *mut u8,
                signature_len: *mut size_t,
            ) -> c_int {
                if sk.is_null()
                    || signature.is_null()
                    || signature_len.is_null()
                    || unsafe { *signature_len } < [<$prefix $bits $param:lower>]::SIGNATURE_SIZE
                    || (message.is_null() && message_len != 0)
                    || (rho.is_null() && rho_len != 0)
                {
                    return -1;
                }

                let sk = unsafe { slice::from_raw_parts(sk, [<$prefix $bits $param:lower>]::SK_SIZE) };
                let msg = if message_len > 0 {
                    unsafe { slice::from_raw_parts(message, message_len) }
                } else {
                    &[]
                };
                let rho = if rho_len > 0 {
                    unsafe { slice::from_raw_parts(rho, rho_len) }
                } else {
                    &[]
                };
                let signature = unsafe { slice::from_raw_parts_mut(signature, [<$prefix $bits $param:lower>]::SIGNATURE_SIZE) };

                if let Ok(sk) = [<$prefix $bits $param:lower SigningKey>]::try_from(sk) {
                    [<$prefix $bits $param:lower>]::sign(msg, &sk.0, rho, GenericArray::from_mut_slice(signature)).map_to_error_code(
                        |_| {
                            unsafe { *signature_len = [<$prefix $bits $param:lower>]::SIGNATURE_SIZE };
                            0
                        },
                    )
                } else {
                    -1
                }
            }

            fn [<$prefix_c:lower _ $bits $param:lower _verify_impl>](
                pk: *const u8,
                message: *const u8,
                message_len: size_t,
                signature: *const u8,
                signature_len: size_t,
            ) -> c_int {
                if pk.is_null()
                    || signature.is_null()
                    || signature_len != [<$prefix $bits $param:lower>]::SIGNATURE_SIZE
                    || (message.is_null() && message_len != 0)
                {
                    return -1;
                }

                let pk = unsafe { slice::from_raw_parts(pk, [<$prefix $bits $param:lower>]::PK_SIZE) };
                let msg = if message_len > 0 {
                    unsafe { slice::from_raw_parts(message, message_len) }
                } else {
                    &[]
                };
                let signature = unsafe { slice::from_raw_parts(signature, [<$prefix $bits $param:lower>]::SIGNATURE_SIZE) };

                if let Ok(pk) = [<$prefix $bits $param:lower VerificationKey>]::try_from(pk) {
                    [<$prefix $bits $param:lower>]::verify(msg, &pk.0, GenericArray::from_slice(signature)).to_error_code()
                } else {
                    -1
                }
            }

            #[cfg(test)]
            mod [<$prefix_c:lower _ $bits $param:lower _test>] {
                use super::*;

                #[test]
                fn sign_and_verify() {
                    let mut sk = [0u8; [<$prefix_c _ $bits $param _PRIVATE_KEY_SIZE>]];
                    let mut pk = [0u8; [<$prefix_c _ $bits $param _PUBLIC_KEY_SIZE>]];

                    assert_eq!(
                        unsafe { [<$prefix_c:lower _ $bits $param:lower _keygen>](sk.as_mut_ptr(), pk.as_mut_ptr()) },
                        0
                    );

                    let message = b"the message";
                    let mut signature = [0xffu8; [<$prefix_c _ $bits $param _SIGNATURE_SIZE>]];
                    let mut signature_len = signature.len();
                    assert_eq!(
                        unsafe {
                            [<$prefix_c:lower _ $bits $param:lower _sign>](
                                sk.as_ptr(),
                                message.as_ptr(),
                                message.len(),
                                signature.as_mut_ptr(),
                                (&mut signature_len) as *mut usize,
                            )
                        },
                        0
                    );
                    assert_eq!(signature_len, signature.len());

                    assert_eq!(
                        unsafe {
                            [<$prefix_c:lower _ $bits $param:lower _verify>](
                                pk.as_ptr(),
                                message.as_ptr(),
                                message.len(),
                                signature.as_ptr(),
                                signature_len,
                            )
                        },
                        0
                    );
                }

                #[test]
                fn sign_and_verify_with_null() {
                    let mut sk = [0u8; [<$prefix_c _ $bits $param _PRIVATE_KEY_SIZE>]];
                    let mut pk = [0u8; [<$prefix_c _ $bits $param _PUBLIC_KEY_SIZE>]];

                    assert_eq!(
                        unsafe { [<$prefix_c:lower _ $bits $param:lower _keygen>](sk.as_mut_ptr(), pk.as_mut_ptr()) },
                        0
                    );

                    let mut signature = [0u8; [<$prefix_c _ $bits $param _SIGNATURE_SIZE>]];
                    let mut signature_len = signature.len();
                    assert_eq!(
                        unsafe {
                            [<$prefix_c:lower _ $bits $param:lower _sign>](
                                sk.as_ptr(),
                                std::ptr::null(),
                                0,
                                signature.as_mut_ptr(),
                                (&mut signature_len) as *mut usize,
                            )
                        },
                        0
                    );
                    assert_eq!(signature_len, signature.len());

                    assert_eq!(
                        unsafe {
                            [<$prefix_c:lower _ $bits $param:lower _verify>](
                                pk.as_ptr(),
                                std::ptr::null(),
                                0,
                                signature.as_ptr(),
                                signature_len,
                            )
                        },
                        0
                    );
                }

                #[test]
                fn sign_and_verify_with_randomness() {
                    let mut sk = [0u8; [<$prefix_c _ $bits $param _PRIVATE_KEY_SIZE>]];
                    let mut pk = [0u8; [<$prefix_c _ $bits $param _PUBLIC_KEY_SIZE>]];
                    let rho = [0u8; 16];

                    assert_eq!(
                        unsafe { [<$prefix_c:lower _ $bits $param:lower _keygen>](sk.as_mut_ptr(), pk.as_mut_ptr()) },
                        0
                    );

                    let mut signature = [0u8; [<$prefix_c _ $bits $param _SIGNATURE_SIZE>]];
                    let mut signature_len = signature.len();
                    assert_eq!(
                        unsafe {
                            [<$prefix_c:lower _ $bits $param:lower _sign_with_randomness>](
                                sk.as_ptr(),
                                std::ptr::null(),
                                0,
                                rho.as_ptr(),
                                rho.len(),
                                signature.as_mut_ptr(),
                                (&mut signature_len) as *mut usize,
                            )
                        },
                        0
                    );
                    assert_eq!(signature_len, signature.len());

                    assert_eq!(
                        unsafe {
                            [<$prefix_c:lower _ $bits $param:lower _verify>](
                                pk.as_ptr(),
                                std::ptr::null(),
                                0,
                                signature.as_ptr(),
                                signature_len,
                            )
                        },
                        0
                    );

                    let mut signature2 = [0u8; [<$prefix_c _ $bits $param _SIGNATURE_SIZE>]];
                    assert_eq!(
                        unsafe {
                            [<$prefix_c:lower _ $bits $param:lower _sign_with_randomness>](
                                sk.as_ptr(),
                                std::ptr::null(),
                                0,
                                rho.as_ptr(),
                                rho.len(),
                                signature2.as_mut_ptr(),
                                (&mut signature_len) as *mut usize,
                            )
                        },
                        0
                    );
                    assert_eq!(signature, signature2);
                }

                #[test]
                fn clear() {
                    let mut sk = [0xffu8; [<$prefix_c _ $bits $param _PRIVATE_KEY_SIZE>]];
                    unsafe { [<$prefix_c:lower _ $bits $param:lower _clear_private_key>](sk.as_mut_ptr()); }
                    let all_zeroes = [0u8; [<$prefix_c _ $bits $param _PRIVATE_KEY_SIZE>]];
                    assert_eq!(sk, all_zeroes);
                }
            }
        }
    };
}

define_capi_impl!(128, F);
define_capi_impl!(128, S);
define_capi_impl!(192, F);
define_capi_impl!(192, S);
define_capi_impl!(256, F);
define_capi_impl!(256, S);
define_capi_impl!(em, 128, F);
define_capi_impl!(em, 128, S);
define_capi_impl!(em, 192, F);
define_capi_impl!(em, 192, S);
define_capi_impl!(em, 256, F);
define_capi_impl!(em, 256, S);

// cbindgen fails to generate headers if consts and fns are defined via a macro

/// Size of the public key in bytes.
pub const FAEST_128F_PUBLIC_KEY_SIZE: usize = FAEST128f::PK_SIZE;
/// Size of the private key in bytes.
pub const FAEST_128F_PRIVATE_KEY_SIZE: usize = FAEST128f::SK_SIZE;
/// Size of the signature in bytes.
pub const FAEST_128F_SIGNATURE_SIZE: usize = FAEST128f::SIGNATURE_SIZE;

/// Generates a public and private key pair, for the specified parameter set. Returns 0 for success, or a nonzero value indicating an error.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_128F_PUBLIC_KEY_SIZE]
/// - `sk` must be a valid pointer to an array of size [FAEST_128F_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_128f_keygen(sk: *mut u8, pk: *mut u8) -> c_int {
    faest_128f_keygen_impl(sk, pk)
}

/// Signs a message with the private key. Samples rho internally.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_128F_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_128F_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_128f_sign(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_128f_sign_impl(sk, message, message_len, signature, signature_len)
}

/// Signs a message with the private key (with custom randomness input)
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_128F_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_128F_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_128f_sign_with_randomness(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    rho: *const u8,
    rho_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_128f_sign_with_randomness_impl(
        sk,
        message,
        message_len,
        rho,
        rho_len,
        signature,
        signature_len,
    )
}

/// Verifies a signature is valid with respect to a public key and message.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_128F_PUBLIC_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `signature_len`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_128f_verify(
    pk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
) -> c_int {
    faest_128f_verify_impl(pk, message, message_len, signature, signature_len)
}

/// Clear data of a private key.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_128F_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_128f_clear_private_key(sk: *mut u8) {
    clear_private_key(sk, FAEST128f::SK_SIZE);
}

/// Size of the public key in bytes.
pub const FAEST_128S_PUBLIC_KEY_SIZE: usize = FAEST128s::PK_SIZE;
/// Size of the private key in bytes.
pub const FAEST_128S_PRIVATE_KEY_SIZE: usize = FAEST128s::SK_SIZE;
/// Size of the signature in bytes.
pub const FAEST_128S_SIGNATURE_SIZE: usize = FAEST128s::SIGNATURE_SIZE;

/// Generates a public and private key pair, for the specified parameter set. Returns 0 for success, or a nonzero value indicating an error.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_128S_PUBLIC_KEY_SIZE]
/// - `sk` must be a valid pointer to an array of size [FAEST_128S_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_128s_keygen(sk: *mut u8, pk: *mut u8) -> c_int {
    faest_128s_keygen_impl(sk, pk)
}

/// Signs a message with the private key. Samples rho internally.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_128S_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_128S_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_128s_sign(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_128s_sign_impl(sk, message, message_len, signature, signature_len)
}

/// Signs a message with the private key (with custom randomness input)
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_128S_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_128S_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_128s_sign_with_randomness(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    rho: *const u8,
    rho_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_128s_sign_with_randomness_impl(
        sk,
        message,
        message_len,
        rho,
        rho_len,
        signature,
        signature_len,
    )
}

/// Verifies a signature is valid with respect to a public key and message.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_128S_PUBLIC_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `signature_len`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_128s_verify(
    pk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
) -> c_int {
    faest_128s_verify_impl(pk, message, message_len, signature, signature_len)
}

/// Clear data of a private key.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_128S_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_128s_clear_private_key(sk: *mut u8) {
    clear_private_key(sk, FAEST128s::SK_SIZE);
}

/// Size of the public key in bytes.
pub const FAEST_192F_PUBLIC_KEY_SIZE: usize = FAEST192f::PK_SIZE;
/// Size of the private key in bytes.
pub const FAEST_192F_PRIVATE_KEY_SIZE: usize = FAEST192f::SK_SIZE;
/// Size of the signature in bytes.
pub const FAEST_192F_SIGNATURE_SIZE: usize = FAEST192f::SIGNATURE_SIZE;

/// Generates a public and private key pair, for the specified parameter set. Returns 0 for success, or a nonzero value indicating an error.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_192F_PUBLIC_KEY_SIZE]
/// - `sk` must be a valid pointer to an array of size [FAEST_192F_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_192f_keygen(sk: *mut u8, pk: *mut u8) -> c_int {
    faest_192f_keygen_impl(sk, pk)
}

/// Signs a message with the private key. Samples rho internally.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_192F_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_192F_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_192f_sign(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_192f_sign_impl(sk, message, message_len, signature, signature_len)
}

/// Signs a message with the private key (with custom randomness input)
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_192F_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_192F_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_192f_sign_with_randomness(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    rho: *const u8,
    rho_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_192f_sign_with_randomness_impl(
        sk,
        message,
        message_len,
        rho,
        rho_len,
        signature,
        signature_len,
    )
}

/// Verifies a signature is valid with respect to a public key and message.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_192F_PUBLIC_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `signature_len`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_192f_verify(
    pk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
) -> c_int {
    faest_192f_verify_impl(pk, message, message_len, signature, signature_len)
}

/// Clear data of a private key.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_192F_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_192f_clear_private_key(sk: *mut u8) {
    clear_private_key(sk, FAEST192f::SK_SIZE);
}

/// Size of the public key in bytes.
pub const FAEST_192S_PUBLIC_KEY_SIZE: usize = FAEST192s::PK_SIZE;
/// Size of the private key in bytes.
pub const FAEST_192S_PRIVATE_KEY_SIZE: usize = FAEST192s::SK_SIZE;
/// Size of the signature in bytes.
pub const FAEST_192S_SIGNATURE_SIZE: usize = FAEST192s::SIGNATURE_SIZE;

/// Generates a public and private key pair, for the specified parameter set. Returns 0 for success, or a nonzero value indicating an error.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_192S_PUBLIC_KEY_SIZE]
/// - `sk` must be a valid pointer to an array of size [FAEST_192S_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_192s_keygen(sk: *mut u8, pk: *mut u8) -> c_int {
    faest_192s_keygen_impl(sk, pk)
}

/// Signs a message with the private key. Samples rho internally.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_192S_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_192S_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_192s_sign(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_192s_sign_impl(sk, message, message_len, signature, signature_len)
}

/// Signs a message with the private key (with custom randomness input)
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_192S_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_192S_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_192s_sign_with_randomness(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    rho: *const u8,
    rho_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_192s_sign_with_randomness_impl(
        sk,
        message,
        message_len,
        rho,
        rho_len,
        signature,
        signature_len,
    )
}

/// Verifies a signature is valid with respect to a public key and message.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_192S_PUBLIC_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `signature_len`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_192s_verify(
    pk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
) -> c_int {
    faest_192s_verify_impl(pk, message, message_len, signature, signature_len)
}

/// Clear data of a private key.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_192S_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_192s_clear_private_key(sk: *mut u8) {
    clear_private_key(sk, FAEST192s::SK_SIZE);
}

/// Size of the public key in bytes.
pub const FAEST_256F_PUBLIC_KEY_SIZE: usize = FAEST256f::PK_SIZE;
/// Size of the private key in bytes.
pub const FAEST_256F_PRIVATE_KEY_SIZE: usize = FAEST256f::SK_SIZE;
/// Size of the signature in bytes.
pub const FAEST_256F_SIGNATURE_SIZE: usize = FAEST256f::SIGNATURE_SIZE;

/// Generates a public and private key pair, for the specified parameter set. Returns 0 for success, or a nonzero value indicating an error.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_256F_PUBLIC_KEY_SIZE]
/// - `sk` must be a valid pointer to an array of size [FAEST_256F_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_256f_keygen(sk: *mut u8, pk: *mut u8) -> c_int {
    faest_256f_keygen_impl(sk, pk)
}

/// Signs a message with the private key. Samples rho internally.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_256F_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_256F_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_256f_sign(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_256f_sign_impl(sk, message, message_len, signature, signature_len)
}

/// Signs a message with the private key (with custom randomness input)
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_256F_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_256F_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_256f_sign_with_randomness(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    rho: *const u8,
    rho_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_256f_sign_with_randomness_impl(
        sk,
        message,
        message_len,
        rho,
        rho_len,
        signature,
        signature_len,
    )
}

/// Verifies a signature is valid with respect to a public key and message.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_256F_PUBLIC_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `signature_len`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_256f_verify(
    pk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
) -> c_int {
    faest_256f_verify_impl(pk, message, message_len, signature, signature_len)
}

/// Clear data of a private key.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_256F_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_256f_clear_private_key(sk: *mut u8) {
    clear_private_key(sk, FAEST256f::SK_SIZE);
}

/// Size of the public key in bytes.
pub const FAEST_256S_PUBLIC_KEY_SIZE: usize = FAEST256s::PK_SIZE;
/// Size of the private key in bytes.
pub const FAEST_256S_PRIVATE_KEY_SIZE: usize = FAEST256s::SK_SIZE;
/// Size of the signature in bytes.
pub const FAEST_256S_SIGNATURE_SIZE: usize = FAEST256s::SIGNATURE_SIZE;

/// Generates a public and private key pair, for the specified parameter set. Returns 0 for success, or a nonzero value indicating an error.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_256S_PUBLIC_KEY_SIZE]
/// - `sk` must be a valid pointer to an array of size [FAEST_256S_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_256s_keygen(sk: *mut u8, pk: *mut u8) -> c_int {
    faest_256s_keygen_impl(sk, pk)
}

/// Signs a message with the private key. Samples rho internally.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_256S_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_256S_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_256s_sign(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_256s_sign_impl(sk, message, message_len, signature, signature_len)
}

/// Signs a message with the private key (with custom randomness input)
///
/// # Safety
//`
/// - `sk` must be a valid pointer to an array of size [FAEST_256S_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_256S_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_256s_sign_with_randomness(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    rho: *const u8,
    rho_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_256s_sign_with_randomness_impl(
        sk,
        message,
        message_len,
        rho,
        rho_len,
        signature,
        signature_len,
    )
}

/// Verifies a signature is valid with respect to a public key and message.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_256S_PUBLIC_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `signature_len`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_256s_verify(
    pk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
) -> c_int {
    faest_256s_verify_impl(pk, message, message_len, signature, signature_len)
}

/// Clear data of a private key.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_256S_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_256s_clear_private_key(sk: *mut u8) {
    clear_private_key(sk, FAEST256s::SK_SIZE);
}

/// Size of the public key in bytes.
pub const FAEST_EM_128F_PUBLIC_KEY_SIZE: usize = FAESTEM128f::PK_SIZE;
/// Size of the private key in bytes.
pub const FAEST_EM_128F_PRIVATE_KEY_SIZE: usize = FAESTEM128f::SK_SIZE;
/// Size of the signature in bytes.
pub const FAEST_EM_128F_SIGNATURE_SIZE: usize = FAESTEM128f::SIGNATURE_SIZE;

/// Generates a public and private key pair, for the specified parameter set. Returns 0 for success, or a nonzero value indicating an error.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_EM_128F_PUBLIC_KEY_SIZE]
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_128F_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_128f_keygen(sk: *mut u8, pk: *mut u8) -> c_int {
    faest_em_128f_keygen_impl(sk, pk)
}

/// Signs a message with the private key. Samples rho internally.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_128F_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_EM_128F_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_128f_sign(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_em_128f_sign_impl(sk, message, message_len, signature, signature_len)
}

/// Signs a message with the private key (with custom randomness input)
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_128F_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_EM_128F_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_128f_sign_with_randomness(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    rho: *const u8,
    rho_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_em_128f_sign_with_randomness_impl(
        sk,
        message,
        message_len,
        rho,
        rho_len,
        signature,
        signature_len,
    )
}

/// Verifies a signature is valid with respect to a public key and message.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_EM_128F_PUBLIC_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `signature_len`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_128f_verify(
    pk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
) -> c_int {
    faest_em_128f_verify_impl(pk, message, message_len, signature, signature_len)
}

/// Clear data of a private key.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_128F_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_128f_clear_private_key(sk: *mut u8) {
    clear_private_key(sk, FAESTEM128f::SK_SIZE);
}

/// Size of the public key in bytes.
pub const FAEST_EM_128S_PUBLIC_KEY_SIZE: usize = FAESTEM128s::PK_SIZE;
/// Size of the private key in bytes.
pub const FAEST_EM_128S_PRIVATE_KEY_SIZE: usize = FAESTEM128s::SK_SIZE;
/// Size of the signature in bytes.
pub const FAEST_EM_128S_SIGNATURE_SIZE: usize = FAESTEM128s::SIGNATURE_SIZE;

/// Generates a public and private key pair, for the specified parameter set. Returns 0 for success, or a nonzero value indicating an error.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_EM_128S_PUBLIC_KEY_SIZE]
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_128S_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_128s_keygen(sk: *mut u8, pk: *mut u8) -> c_int {
    faest_em_128s_keygen_impl(sk, pk)
}

/// Signs a message with the private key. Samples rho internally.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_128S_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_EM_128S_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_128s_sign(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_em_128s_sign_impl(sk, message, message_len, signature, signature_len)
}

/// Signs a message with the private key (with custom randomness input)
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_128S_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_EM_128S_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_128s_sign_with_randomness(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    rho: *const u8,
    rho_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_em_128s_sign_with_randomness_impl(
        sk,
        message,
        message_len,
        rho,
        rho_len,
        signature,
        signature_len,
    )
}

/// Verifies a signature is valid with respect to a public key and message.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_EM_128S_PUBLIC_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `signature_len`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_128s_verify(
    pk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
) -> c_int {
    faest_em_128s_verify_impl(pk, message, message_len, signature, signature_len)
}

/// Clear data of a private key.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_128S_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_128s_clear_private_key(sk: *mut u8) {
    clear_private_key(sk, FAESTEM128s::SK_SIZE);
}

/// Size of the public key in bytes.
pub const FAEST_EM_192F_PUBLIC_KEY_SIZE: usize = FAESTEM192f::PK_SIZE;
/// Size of the private key in bytes.
pub const FAEST_EM_192F_PRIVATE_KEY_SIZE: usize = FAESTEM192f::SK_SIZE;
/// Size of the signature in bytes.
pub const FAEST_EM_192F_SIGNATURE_SIZE: usize = FAESTEM192f::SIGNATURE_SIZE;

/// Generates a public and private key pair, for the specified parameter set. Returns 0 for success, or a nonzero value indicating an error.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_EM_192F_PUBLIC_KEY_SIZE]
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_192F_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_192f_keygen(sk: *mut u8, pk: *mut u8) -> c_int {
    faest_em_192f_keygen_impl(sk, pk)
}
/// Signs a message with the private key. Samples rho internally.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_192F_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_EM_192F_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_192f_sign(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_em_192f_sign_impl(sk, message, message_len, signature, signature_len)
}

/// Signs a message with the private key (with custom randomness input)
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_192F_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_EM_192F_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_192f_sign_with_randomness(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    rho: *const u8,
    rho_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_em_192f_sign_with_randomness_impl(
        sk,
        message,
        message_len,
        rho,
        rho_len,
        signature,
        signature_len,
    )
}

/// Verifies a signature is valid with respect to a public key and message.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_EM_192F_PUBLIC_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `signature_len`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_192f_verify(
    pk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
) -> c_int {
    faest_em_192f_verify_impl(pk, message, message_len, signature, signature_len)
}

/// Clear data of a private key.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_192F_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_192f_clear_private_key(sk: *mut u8) {
    clear_private_key(sk, FAESTEM192f::SK_SIZE);
}

/// Size of the public key in bytes.
pub const FAEST_EM_192S_PUBLIC_KEY_SIZE: usize = FAESTEM192s::PK_SIZE;
/// Size of the private key in bytes.
pub const FAEST_EM_192S_PRIVATE_KEY_SIZE: usize = FAESTEM192s::SK_SIZE;
/// Size of the signature in bytes.
pub const FAEST_EM_192S_SIGNATURE_SIZE: usize = FAESTEM192s::SIGNATURE_SIZE;

/// Generates a public and private key pair, for the specified parameter set. Returns 0 for success, or a nonzero value indicating an error.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_EM_192S_PUBLIC_KEY_SIZE]
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_192S_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_192s_keygen(sk: *mut u8, pk: *mut u8) -> c_int {
    faest_em_192s_keygen_impl(sk, pk)
}

/// Signs a message with the private key. Samples rho internally.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_192S_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_EM_192S_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_192s_sign(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_em_192s_sign_impl(sk, message, message_len, signature, signature_len)
}

/// Signs a message with the private key (with custom randomness input)
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_192S_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_EM_192S_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_192s_sign_with_randomness(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    rho: *const u8,
    rho_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_em_192s_sign_with_randomness_impl(
        sk,
        message,
        message_len,
        rho,
        rho_len,
        signature,
        signature_len,
    )
}

/// Verifies a signature is valid with respect to a public key and message.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_EM_192S_PUBLIC_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `signature_len`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_192s_verify(
    pk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
) -> c_int {
    faest_em_192s_verify_impl(pk, message, message_len, signature, signature_len)
}

/// Clear data of a private key.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_192S_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_192s_clear_private_key(sk: *mut u8) {
    clear_private_key(sk, FAESTEM192s::SK_SIZE);
}

/// Size of the public key in bytes.
pub const FAEST_EM_256F_PUBLIC_KEY_SIZE: usize = FAESTEM256f::PK_SIZE;
/// Size of the private key in bytes.
pub const FAEST_EM_256F_PRIVATE_KEY_SIZE: usize = FAESTEM256f::SK_SIZE;
/// Size of the signature in bytes.
pub const FAEST_EM_256F_SIGNATURE_SIZE: usize = FAESTEM256f::SIGNATURE_SIZE;

/// Generates a public and private key pair, for the specified parameter set. Returns 0 for success, or a nonzero value indicating an error.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_EM_256F_PUBLIC_KEY_SIZE]
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_256F_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_256f_keygen(sk: *mut u8, pk: *mut u8) -> c_int {
    faest_em_256f_keygen_impl(sk, pk)
}

/// Signs a message with the private key. Samples rho internally.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_256F_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_EM_256F_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_256f_sign(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_em_256f_sign_impl(sk, message, message_len, signature, signature_len)
}

/// Signs a message with the private key (with custom randomness input)
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_256F_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_EM_256F_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_256f_sign_with_randomness(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    rho: *const u8,
    rho_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_em_256f_sign_with_randomness_impl(
        sk,
        message,
        message_len,
        rho,
        rho_len,
        signature,
        signature_len,
    )
}

/// Verifies a signature is valid with respect to a public key and message.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_EM_256F_PUBLIC_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `signature_len`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_256f_verify(
    pk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
) -> c_int {
    faest_em_256f_verify_impl(pk, message, message_len, signature, signature_len)
}

/// Clear data of a private key.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_256F_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_256f_clear_private_key(sk: *mut u8) {
    clear_private_key(sk, FAESTEM256f::SK_SIZE);
}

/// Size of the public key in bytes.
pub const FAEST_EM_256S_PUBLIC_KEY_SIZE: usize = FAESTEM256s::PK_SIZE;
/// Size of the private key in bytes.
pub const FAEST_EM_256S_PRIVATE_KEY_SIZE: usize = FAESTEM256s::SK_SIZE;
/// Size of the signature in bytes.
pub const FAEST_EM_256S_SIGNATURE_SIZE: usize = FAESTEM256s::SIGNATURE_SIZE;

/// Generates a public and private key pair, for the specified parameter set. Returns 0 for success, or a nonzero value indicating an error.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_EM_256S_PUBLIC_KEY_SIZE]
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_256S_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_256s_keygen(sk: *mut u8, pk: *mut u8) -> c_int {
    faest_em_256s_keygen_impl(sk, pk)
}

/// Signs a message with the private key. Samples rho internally.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_256S_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_EM_256S_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_256s_sign(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_em_256s_sign_impl(sk, message, message_len, signature, signature_len)
}

/// Signs a message with the private key (with custom randomness input)
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_256S_PRIVATE_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `*signature_len` (which needs to be at least [FAEST_EM_256S_SIGNATURE_SIZE] bytes large)
/// - `signature_len` must be a valid pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_256s_sign_with_randomness(
    sk: *const u8,
    message: *const u8,
    message_len: size_t,
    rho: *const u8,
    rho_len: size_t,
    signature: *mut u8,
    signature_len: *mut size_t,
) -> c_int {
    faest_em_256s_sign_with_randomness_impl(
        sk,
        message,
        message_len,
        rho,
        rho_len,
        signature,
        signature_len,
    )
}

/// Verifies a signature is valid with respect to a public key and message.
///
/// # Safety
///
/// - `pk` must be a valid pointer to an array of size [FAEST_EM_256S_PUBLIC_KEY_SIZE]
/// - `message` must be a valid pointer to an array of size `message_len` or `NULL` if `message_len` is `0`
/// - `signature` must be a valid pointer to an array of size `signature_len`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_256s_verify(
    pk: *const u8,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
) -> c_int {
    faest_em_256s_verify_impl(pk, message, message_len, signature, signature_len)
}

/// Clear data of a private key.
///
/// # Safety
///
/// - `sk` must be a valid pointer to an array of size [FAEST_EM_256S_PRIVATE_KEY_SIZE]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn faest_em_256s_clear_private_key(sk: *mut u8) {
    clear_private_key(sk, FAESTEM256s::SK_SIZE);
}
