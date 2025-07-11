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

trait ResultToErrroCode: Sized {
    fn to_error_code(self) -> c_int;

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

macro_rules! define_capi_impl {
    ($bits:literal, $param:ident) => {
        paste! {
            use crate::{
                [<FAEST $bits $param:lower>], [<FAEST $bits $param:lower SigningKey>], [<FAEST $bits $param:lower VerificationKey>],
            };

            /// Size of the public key in bytes.
            pub const [<FAEST_ $bits $param _PUBLIC_KEY_SIZE>]: usize = [<FAEST $bits $param:lower>]::PK_SIZE;
            /// Size of the private key in bytes.
            pub const [<FAEST_ $bits $param _PRIVATE_KEY_SIZE>]: usize = [<FAEST $bits $param:lower>]::SK_SIZE;
            /// Size of the signature in bytes.
            pub const [<FAEST_ $bits $param _SIGNATURE_SIZE>]: usize = [<FAEST $bits $param:lower>]::SIGNATURE_SIZE;

            /// Generates a public and private key pair, for the specified parameter set. Returns 0 for success, or a nonzero value indicating an error.
            ///
            /// # Safety
            ///
            /// - [pk] must be a valid pointer to an array of size [FAEST_128F_PUBLIC_KEY_SIZE]
            /// - [sk] must be a valid pointer to an array of size [FAEST_128F_PRIVATE_KEY_SIZE]
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn [<faest_ $bits $param:lower _keygen>](sk: *mut u8, pk: *mut u8) -> c_int {
                if sk.is_null() || pk.is_null() {
                    return -1;
                }

                let sk = unsafe { slice::from_raw_parts_mut(sk, [<FAEST $bits $param:lower>]::SK_SIZE) };
                let pk = unsafe { slice::from_raw_parts_mut(pk, [<FAEST $bits $param:lower>]::PK_SIZE) };

                let key = [<FAEST $bits $param:lower SigningKey>]::generate(rand::thread_rng());
                sk.copy_from_slice(&key.to_bytes());
                pk.copy_from_slice(&key.verifying_key().to_bytes());
                0
            }

            /// Signs a message with the private key. Samples rho internally.
            ///
            /// # Safety
            ///
            /// - [sk] must be a valid pointer to an array of size [FAEST_128F_PRIVATE_KEY_SIZE]
            /// - [message] must be a valid pointer to an array of size [message_len] or `NULL` if [message_len] is `0`
            /// - [signature] must be a valid pointer to an array of size [\*signature_len] (which needs to be at least [FAEST_128F_SIGNATURE_SIZE] bytes large)
            /// - [signature_len] must be a valid pointer
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn [<faest_ $bits $param:lower _sign>](
                sk: *const u8,
                message: *const u8,
                message_len: size_t,
                signature: *mut u8,
                signature_len: *mut size_t,
            ) -> c_int {
                if sk.is_null()
                    || signature.is_null()
                    || signature_len.is_null()
                    || unsafe { *signature_len } < [<FAEST $bits $param:lower>]::SIGNATURE_SIZE
                    || (message.is_null() && message_len != 0)
                {
                    return -1;
                }

                let sk = unsafe { slice::from_raw_parts(sk, [<FAEST $bits $param:lower>]::SK_SIZE) };
                let msg = if message_len > 0 {
                    unsafe { slice::from_raw_parts(message, message_len) }
                } else {
                    &[]
                };
                let signature = unsafe { slice::from_raw_parts_mut(signature, [<FAEST $bits $param:lower>]::SIGNATURE_SIZE) };

                if let Ok(sk) = [<FAEST $bits $param:lower SigningKey>]::try_from(sk) {
                    let rho = [<FAEST $bits $param:lower>]::sample_rho(rand::thread_rng());
                    [<FAEST $bits $param:lower>]::sign(
                        msg,
                        &sk.0,
                        rho.as_slice(),
                        GenericArray::from_mut_slice(signature),
                    )
                    .map_to_error_code(|_| {
                        unsafe { *signature_len = [<FAEST $bits $param:lower>]::SIGNATURE_SIZE };
                        0
                    })
                } else {
                    -1
                }
            }

            /// Signs a message with the private key (with custom randomness input)
            ///
            /// # Safety
            ///
            /// - [sk] must be a valid pointer to an array of size [FAEST_128F_PRIVATE_KEY_SIZE]
            /// - [message] must be a valid pointer to an array of size [message_len] or `NULL` if [message_len] is `0`
            /// - [signature] must be a valid pointer to an array of size [\*signature_len] (which needs to be at least [FAEST_128F_SIGNATURE_SIZE] bytes large)
            /// - [signature_len] must be a valid pointer
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn [<faest_ $bits $param:lower _sign_with_randomness>](
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
                    || unsafe { *signature_len } < [<FAEST $bits $param:lower>]::SIGNATURE_SIZE
                    || (message.is_null() && message_len != 0)
                    || (rho.is_null() && rho_len != 0)
                {
                    return -1;
                }

                let sk = unsafe { slice::from_raw_parts(sk, [<FAEST $bits $param:lower>]::SK_SIZE) };
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
                let signature = unsafe { slice::from_raw_parts_mut(signature, [<FAEST $bits $param:lower>]::SIGNATURE_SIZE) };

                if let Ok(sk) = [<FAEST $bits $param:lower SigningKey>]::try_from(sk) {
                    [<FAEST $bits $param:lower>]::sign(msg, &sk.0, rho, GenericArray::from_mut_slice(signature)).map_to_error_code(
                        |_| {
                            unsafe { *signature_len = [<FAEST $bits $param:lower>]::SIGNATURE_SIZE };
                            0
                        },
                    )
                } else {
                    -1
                }
            }

            /// Verifies a signature is valid with respect to a public key and message.
            ///
            /// # Safety
            ///
            /// - [pk] must be a valid pointer to an array of size [FAEST_128F_PUBLIC_KEY_SIZE]
            /// - [message] must be a valid pointer to an array of size [message_len] or `NULL` if [message_len] is `0`
            /// - [signature] must be a valid pointer to an array of size [signature_len]
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn [<faest_ $bits $param:lower _verify>](
                pk: *const u8,
                message: *const u8,
                message_len: size_t,
                signature: *const u8,
                signature_len: size_t,
            ) -> c_int {
                if pk.is_null()
                    || signature.is_null()
                    || signature_len != [<FAEST $bits $param:lower>]::SIGNATURE_SIZE
                    || (message.is_null() && message_len != 0)
                {
                    return -1;
                }

                let pk = unsafe { slice::from_raw_parts(pk, [<FAEST $bits $param:lower>]::PK_SIZE) };
                let msg = if message_len > 0 {
                    unsafe { slice::from_raw_parts(message, message_len) }
                } else {
                    &[]
                };
                let signature = unsafe { slice::from_raw_parts(signature, [<FAEST $bits $param:lower>]::SIGNATURE_SIZE) };

                if let Ok(pk) = [<FAEST $bits $param:lower VerificationKey>]::try_from(pk) {
                    [<FAEST $bits $param:lower>]::verify(msg, &pk.0, GenericArray::from_slice(signature)).to_error_code()
                } else {
                    -1
                }
            }

            /// Clear data of a private key.
            ///
            /// # Safety
            ///
            /// - [sk] must be a valid pointer to an array of size [FAEST_128F_PRIVATE_KEY_SIZE]
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn [<faest_ $bits $param:lower _clear_private_key>](sk: *mut u8) {
                if !sk.is_null() {
                    let sk = unsafe { slice::from_raw_parts_mut(sk, [<FAEST $bits $param:lower>]::SK_SIZE) };
                    sk.zeroize();
                }
            }

            #[cfg(test)]
            mod [<faest_ $bits $param:lower _test>] {
                use super::*;

                #[test]
                fn test() {
                    let mut sk = [0u8; [<FAEST_ $bits $param _PRIVATE_KEY_SIZE>]];
                    let mut pk = [0u8; [<FAEST_ $bits $param _PUBLIC_KEY_SIZE>]];

                    assert_eq!(
                        unsafe { [<faest_ $bits $param:lower _keygen>](sk.as_mut_ptr(), pk.as_mut_ptr()) },
                        0,
                        "keygen"
                    );

                    let message = b"the message";
                    let mut signature = [0xffu8; [<FAEST_ $bits $param _SIGNATURE_SIZE>]];
                    let mut signature_len = signature.len();
                    assert_eq!(
                        unsafe {
                            [<faest_ $bits $param:lower _sign>](
                                sk.as_ptr(),
                                message.as_ptr(),
                                message.len(),
                                signature.as_mut_ptr(),
                                (&mut signature_len) as *mut usize,
                            )
                        },
                        0,
                        "sign with message"
                    );
                    assert_eq!(signature_len, signature.len());

                    assert_eq!(
                        unsafe {
                            [<faest_ $bits $param:lower _verify>](
                                pk.as_ptr(),
                                message.as_ptr(),
                                message.len(),
                                signature.as_ptr(),
                                signature_len,
                            )
                        },
                        0,
                        "verify with message"
                    );
                }

                #[test]
                fn test_with_null() {
                    let mut sk = [0u8; [<FAEST_ $bits $param _PRIVATE_KEY_SIZE>]];
                    let mut pk = [0u8; [<FAEST_ $bits $param _PUBLIC_KEY_SIZE>]];

                    assert_eq!(
                        unsafe { [<faest_ $bits $param:lower _keygen>](sk.as_mut_ptr(), pk.as_mut_ptr()) },
                        0,
                        "keygen"
                    );

                    let mut signature = [0u8; [<FAEST_ $bits $param _SIGNATURE_SIZE>]];
                    let mut signature_len = signature.len();
                    assert_eq!(
                        unsafe {
                            [<faest_ $bits $param:lower _sign>](
                                sk.as_ptr(),
                                std::ptr::null(),
                                0,
                                signature.as_mut_ptr(),
                                (&mut signature_len) as *mut usize,
                            )
                        },
                        0,
                        "sign with empty message"
                    );
                    assert_eq!(signature_len, signature.len());

                    assert_eq!(
                        unsafe {
                            [<faest_ $bits $param:lower _verify>](
                                pk.as_ptr(),
                                std::ptr::null(),
                                0,
                                signature.as_ptr(),
                                signature_len,
                            )
                        },
                        0,
                        "verify with empty message"
                    );
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
