#![doc = include_str!("../README.md")]
//! ## Usage
//!
//! The crate implements the traits defined by the [signature] crate. The crate
//! itself together with the [Signer] and [Verifier] trait are re-exported for
//! convinience. The following examples are based on FAEST-128f. They work
//! exactly the same for the other variants by replacing the types of the
//! signing key and the signature.
//!
//! Key generation, signing and verification can be implemented as follows:
//! ```
//! use faest::{FAEST128fSigningKey, FAEST128fSignature};
//! use faest::{signature::{Signer, Verifier, Keypair}, KeypairGenerator};
//!
//! let sk = FAEST128fSigningKey::generate(rand::thread_rng());
//! let msg = "some message".as_bytes();
//! let signature: FAEST128fSignature = sk.sign(msg);
//!
//! let verification_key = sk.verifying_key();
//! verification_key.verify(msg, &signature).expect("Verification failed");
//! ```
//!
//! Due to the size of the signatures, all variants support signing into boxed signatures:
//! ```
//! use faest::{FAEST128fSigningKey, FAEST128fSignature};
//! use faest::{signature::{Signer, Verifier, Keypair}, KeypairGenerator};
//!
//! let sk = FAEST128fSigningKey::generate(rand::thread_rng());
//! let msg = "some message".as_bytes();
//! let signature: Box<FAEST128fSignature> = sk.sign(msg);
//!
//! let verification_key = sk.verifying_key();
//! verification_key.verify(msg, &signature).expect("Verification failed");
//! ```
//!
//! The signature generation is determinstic per default. If the
//! `randomized-signer` feature is enabled, the [signature::RandomizedSigner]
//! trait is also implemented which allows the caller to specify an RNG to
//! provide additional randomness:
//! ```
//! # #[cfg(feature="randomized-signer")] {
//! use faest::{FAEST128fSigningKey, FAEST128fSignature};
//! use faest::{signature::{RandomizedSigner, Verifier, Keypair}, KeypairGenerator};
//!
//! let mut rng = rand::thread_rng();
//! let sk = FAEST128fSigningKey::generate(&mut rng);
//! let msg = "some message".as_bytes();
//! let signature: FAEST128fSignature = sk.sign_with_rng(&mut rng, msg);
//!
//! let verification_key = sk.verifying_key();
//! verification_key.verify(msg, &signature).expect("Verification failed");
//! # }
//! ```
//!
//! As parts of the FAEST signing process relay on a message-independant
//! witness, "unpacked" secret keys store the pre-computed witness. These keys
//! provide a memory/runtime trade-off if the same secret key is used to sign
//! multiple messages. "Unpacked" keys support the same interfaces and keys can
//! be converted back and forth:
//! ```
//! use faest::{FAEST128fSigningKey, FAEST128fUnpackedSigningKey, FAEST128fSignature, ByteEncoding};
//! use faest::{signature::{Signer, Verifier, Keypair}, KeypairGenerator};
//!
//! let sk = FAEST128fSigningKey::generate(rand::thread_rng());
//! let unpacked_sk = FAEST128fUnpackedSigningKey::from(&sk);
//! assert_eq!(sk.to_bytes(), unpacked_sk.to_bytes());
//!
//! let msg = "some message".as_bytes();
//! let signature: FAEST128fSignature = unpacked_sk.sign(msg);
//!
//! let verification_key = unpacked_sk.verifying_key();
//! verification_key.verify(msg, &signature).expect("Verification failed");
//! ```

#![warn(missing_docs)]
// TODO: fix this
#![allow(clippy::type_complexity)]
#![warn(clippy::use_self)]

use generic_array::{GenericArray, typenum::Unsigned};
use paste::paste;
use rand_core::CryptoRngCore;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "randomized-signer")]
pub use signature::RandomizedSigner;
use signature::SignatureEncoding;
pub use signature::{self, Error, Keypair, Signer, Verifier};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

mod aes;
mod bavc;
mod faest;
mod fields;
mod internal_keys;
mod parameter;
mod prg;
mod prover;
mod random_oracles;
mod rijndael_32;
mod universal_hashing;
mod utils;
mod verifier;
mod vole;
mod witness;
mod zk_constraints;

use crate::{
    faest::{faest_keygen, faest_sign, faest_unpacked_keygen, faest_unpacked_sign, faest_verify},
    internal_keys::{PublicKey, SecretKey, UnpackedSecretKey},
    parameter::{
        FAEST128fParameters, FAEST128sParameters, FAEST192fParameters, FAEST192sParameters,
        FAEST256fParameters, FAEST256sParameters, FAESTEM128fParameters, FAESTEM128sParameters,
        FAESTEM192fParameters, FAESTEM192sParameters, FAESTEM256fParameters, FAESTEM256sParameters,
        FAESTParameters, OWFParameters,
    },
};

/// Generate a key pair from a cryptographically secure RNG
pub trait KeypairGenerator: Keypair {
    /// Generate a new keypair
    fn generate<R>(rng: R) -> Self
    where
        R: CryptoRngCore;
}

/// Workaround to verify signatures available as slice
///
/// [Verifier] requires its generic argument to be [Sized], but `[u8]` is not.
/// Hence, this struct simply wraps a slice.
#[derive(Debug)]
pub struct SignatureRef<'a>(&'a [u8]);

impl<'a, 'b> From<&'b [u8]> for SignatureRef<'a>
where
    'b: 'a,
{
    fn from(value: &'b [u8]) -> Self {
        Self(value)
    }
}

/// Byte-based encoding of signing and verification keys
///
/// This is similar to [`signature::SignatureEncoding`] but for keys.
pub trait ByteEncoding: Clone + Sized + for<'a> TryFrom<&'a [u8]> + TryInto<Self::Repr> {
    /// Byte representation of a key.
    type Repr: 'static + AsRef<[u8]> + Clone + Send + Sync;

    /// Encode key as its byte representation.
    fn to_bytes(&self) -> Self::Repr;

    /// Encode keys as a byte vector.
    fn to_vec(&self) -> Vec<u8>;

    /// Get length of encoded key.
    fn encoded_len(&self) -> usize;
}

macro_rules! define_impl {
    ($param:ident) => {
        paste! {
            struct $param;

            impl $param {
                #[inline]
                fn sign(
                    msg: &[u8],
                    sk: &SecretKey<<[<$param Parameters>] as FAESTParameters>::OWF>,
                    rho: &[u8],
                    signature: &mut GenericArray<u8, <[<$param Parameters>] as FAESTParameters>::SignatureSize>,
                ) {
                    faest_sign::<[<$param Parameters>]>(msg, sk, rho, signature);
                }

                #[inline]
                fn unpacked_sign(
                    msg: &[u8],
                    sk: &UnpackedSecretKey<<[<$param Parameters>] as FAESTParameters>::OWF>,
                    rho: &[u8],
                    signature: &mut GenericArray<u8, <[<$param Parameters>] as FAESTParameters>::SignatureSize>,
                ) {
                    faest_unpacked_sign::<[<$param Parameters>]>(msg, sk, rho, signature);
                }

                #[inline]
                fn verify(
                    msg: &[u8],
                    pk: &PublicKey<<[<$param Parameters>] as FAESTParameters>::OWF>,
                    sigma: &GenericArray<u8, <[<$param Parameters>] as FAESTParameters>::SignatureSize>,
                ) -> Result<(), Error>
                {
                    faest_verify::<[<$param Parameters>]>(msg, pk, sigma)
                }
            }

            #[doc = "Signing key for " $param]
            /// ```
            #[doc = "use faest::{" $param "SigningKey as SK, " $param "Signature as Sig};"]
            /// use faest::{Signer, Verifier, Keypair, KeypairGenerator};
            ///
            /// let sk = SK::generate(rand::thread_rng());
            /// let msg = "some message".as_bytes();
            /// let signature: Sig = sk.sign(msg);
            ///
            /// // verify with verification key
            /// let verification_key = sk.verifying_key();
            /// verification_key.verify(msg, &signature).expect("Verification failed");
            /// // secret keys can also verify
            /// sk.verify(msg, &signature).expect("Verification failed");
            /// ```
            #[derive(Debug, Clone, PartialEq, Eq)]
            #[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
            #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
            pub struct [<$param SigningKey>](SecretKey<<[<$param Parameters>] as FAESTParameters>::OWF>);

            impl TryFrom<&[u8]> for [<$param SigningKey>] {
                type Error = Error;

                fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                    SecretKey::try_from(value).map(|sk| Self(sk))
                }
            }

            impl From<&[<$param SigningKey>]> for [u8; <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::SK::USIZE] {
                fn from(value: &[<$param SigningKey>]) -> Self {
                    value.to_bytes()
                }
            }

            impl From<[<$param SigningKey>]> for [u8; <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::SK::USIZE] {
                fn from(value: [<$param SigningKey>]) -> Self {
                    value.to_bytes()
                }
            }

            impl ByteEncoding for [<$param SigningKey>] {
                type Repr = [u8; <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::SK::USIZE];

                fn to_bytes(&self) -> Self::Repr {
                    self.0.to_bytes().into_array()
                }

                fn to_vec(&self) -> Vec<u8> {
                    self.0.to_vec()
                }

                fn encoded_len(&self) -> usize {
                    self.0.encoded_len()
                }
            }


            #[doc = "Unpacked signing key for " $param]
            /// ```
            #[doc = "use faest::{" $param "UnpackedSigningKey as UnpackedSK, " $param "Signature as Sig};"]
            /// use faest::{Signer, Verifier, Keypair, KeypairGenerator};
            ///
            /// // secret key also contains a witness that can be reused to sign multiple messages
            /// let unpacked_sk = UnpackedSK::generate(rand::thread_rng());
            /// let msg = "some message".as_bytes();
            /// let signature: Sig = unpacked_sk.sign(msg);
            ///
            /// // verify with verification key
            /// let verification_key = unpacked_sk.verifying_key();
            /// verification_key.verify(msg, &signature).expect("Verification failed");
            /// // secret keys can also verify
            /// unpacked_sk.verify(msg, &signature).expect("Verification failed");
            /// ```
            #[derive(Debug, Clone, PartialEq, Eq)]
            #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
            pub struct [<$param UnpackedSigningKey>](UnpackedSecretKey<<[<$param Parameters>] as FAESTParameters>::OWF>);

            impl From<&[<$param SigningKey>]> for [<$param UnpackedSigningKey>] {
                fn from(value: &[<$param SigningKey>]) -> Self {
                    Self(UnpackedSecretKey::from(value.0.clone()))
                }
            }

            impl TryFrom<&[u8]> for [<$param UnpackedSigningKey>] {
                type Error = Error;

                fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                    UnpackedSecretKey::try_from(value).map(|sk| Self(sk))
                }
            }

            impl From<&[<$param UnpackedSigningKey>]> for [u8; <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::SK::USIZE] {
                fn from(value: &[<$param UnpackedSigningKey>]) -> Self {
                    value.to_bytes()
                }
            }

            impl From<[<$param UnpackedSigningKey>]> for [u8; <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::SK::USIZE] {
                fn from(value: [<$param UnpackedSigningKey>]) -> Self {
                    value.to_bytes()
                }
            }

            impl ByteEncoding for [<$param UnpackedSigningKey>] {
                type Repr = [u8; <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::SK::USIZE];

                fn to_bytes(&self) -> Self::Repr {
                    self.0.to_bytes().into_array()
                }

                fn to_vec(&self) -> Vec<u8> {
                    self.0.to_vec()
                }

                fn encoded_len(&self) -> usize {
                    self.0.encoded_len()
                }
            }

            #[doc = "Verification key for " $param]
            #[derive(Debug, Clone, PartialEq, Eq)]
            #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
            pub struct [<$param VerificationKey>](PublicKey<<[<$param Parameters>] as FAESTParameters>::OWF>);

            impl TryFrom<&[u8]> for [<$param VerificationKey>] {
                type Error = Error;

                fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                    PublicKey::try_from(value).map(|pk| Self(pk))
                }
            }

            impl From<&[<$param VerificationKey>]> for [u8; <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::PK::USIZE] {
                fn from(value: &[<$param VerificationKey>]) -> Self {
                    value.to_bytes()
                }
            }

            impl From<[<$param VerificationKey>]> for [u8; <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::PK::USIZE] {
                fn from(value: [<$param VerificationKey>]) -> Self {
                    value.to_bytes()
                }
            }

            impl ByteEncoding for [<$param VerificationKey>] {
                type Repr = [u8; <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::PK::USIZE];

                fn to_bytes(&self) -> Self::Repr {
                    self.0.to_bytes().into_array()
                }

                fn to_vec(&self) -> Vec<u8> {
                    self.0.to_vec()
                }

                fn encoded_len(&self) -> usize {
                    self.0.encoded_len()
                }
            }

            impl Keypair for [<$param SigningKey>] {
                type VerifyingKey = [<$param VerificationKey>];

                fn verifying_key(&self) -> Self::VerifyingKey {
                    [<$param VerificationKey>](self.0.as_public_key())
                }
            }

            impl KeypairGenerator for [<$param SigningKey>] {
                fn generate<R>(rng: R) -> Self
                where
                    R: CryptoRngCore,
                {
                    Self(faest_keygen::<<[<$param Parameters>] as FAESTParameters>::OWF, R>(rng))
                }
            }

            impl Keypair for [<$param UnpackedSigningKey>] {
                type VerifyingKey = [<$param VerificationKey>];

                fn verifying_key(&self) -> Self::VerifyingKey {
                    [<$param VerificationKey>](self.0.as_public_key())
                }
            }

            impl KeypairGenerator for [<$param UnpackedSigningKey>] {
                fn generate<R>(rng: R) -> Self
                where
                    R: CryptoRngCore,
                {
                    Self(faest_unpacked_keygen::<<[<$param Parameters>] as FAESTParameters>::OWF, R>(rng))
                }
            }

            #[doc = "Signature for " $param]
            #[derive(Debug, Clone, PartialEq, Eq)]
            #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
            pub struct [<$param Signature>](GenericArray<u8, <[<$param Parameters>] as FAESTParameters>::SignatureSize>);

            impl Signer<[<$param Signature>]> for [<$param SigningKey>] {
                fn try_sign(&self, msg: &[u8]) -> Result<[<$param Signature>], Error> {
                    Ok(self.sign(msg))
                }

                fn sign(&self, msg: &[u8]) -> [<$param Signature>] {
                    let mut signature = GenericArray::default();
                    $param::sign(msg, &self.0, &[], &mut signature);
                    [<$param Signature>](signature)
                }
            }

            impl Signer<Box<[<$param Signature>]>> for [<$param SigningKey>] {
                fn try_sign(&self, msg: &[u8]) -> Result<Box<[<$param Signature>]>, Error> {
                    Ok(self.sign(msg))
                }

                fn sign(&self, msg: &[u8]) -> Box<[<$param Signature>]> {
                    let mut signature = Box::new([<$param Signature>](GenericArray::default()));
                    $param::sign(msg, &self.0, &[], &mut signature.0);
                    signature
                }
            }

            impl Signer<[<$param Signature>]> for [<$param UnpackedSigningKey>] {
                fn try_sign(&self, msg: &[u8]) -> Result<[<$param Signature>], Error> {
                    Ok(self.sign(msg))
                }

                fn sign(&self, msg: &[u8]) -> [<$param Signature>] {
                    let mut signature = GenericArray::default();
                    $param::unpacked_sign(msg, &self.0, &[], &mut signature);
                    [<$param Signature>](signature)
                }
            }

            impl Verifier<[<$param Signature>]> for [<$param VerificationKey>] {
                fn verify(&self, msg: &[u8], signature: &[<$param Signature>]) -> Result<(), Error> {
                    $param::verify(msg, &self.0, &signature.0)
                }
            }

            impl Verifier<Box<[<$param Signature>]>> for [<$param VerificationKey>] {
                fn verify(&self, msg: &[u8], signature: &Box<[<$param Signature>]>) -> Result<(), Error> {
                    $param::verify(msg, &self.0, &signature.0)
                }
            }

            impl Verifier<SignatureRef<'_>> for [<$param VerificationKey>] {
                fn verify(&self, msg: &[u8], signature: &SignatureRef<'_>) -> Result<(), Error> {
                    GenericArray::try_from_slice(signature.0)
                        .map_err(|_| Error::new())
                        .and_then(|sig| $param::verify(msg, &self.0, sig))
                }
            }

            impl Verifier<[<$param Signature>]> for [<$param SigningKey>] {
                fn verify(&self, msg: &[u8], signature: &[<$param Signature>]) -> Result<(), Error> {
                    $param::verify(msg, &self.0.pk, &signature.0)
                }
            }

            impl Verifier<Box<[<$param Signature>]>> for [<$param SigningKey>] {
                fn verify(&self, msg: &[u8], signature: &Box<[<$param Signature>]>) -> Result<(), Error> {
                    $param::verify(msg, &self.0.pk, &signature.0)
                }
            }

            impl Verifier<SignatureRef<'_>> for [<$param SigningKey>] {
                fn verify(&self, msg: &[u8], signature: &SignatureRef<'_>) -> Result<(), Error> {
                    GenericArray::try_from_slice(signature.0)
                        .map_err(|_| Error::new())
                        .and_then(|sig| $param::verify(msg, &self.0.pk, sig))
                }
            }

            impl Verifier<[<$param Signature>]> for [<$param UnpackedSigningKey>] {
                fn verify(&self, msg: &[u8], signature: &[<$param Signature>]) -> Result<(), Error> {
                    $param::verify(msg, &self.verifying_key().0, &signature.0)
                }
            }

            impl Verifier<Box<[<$param Signature>]>> for [<$param UnpackedSigningKey>] {
                fn verify(&self, msg: &[u8], signature: &Box<[<$param Signature>]>) -> Result<(), Error> {
                    $param::verify(msg, &self.verifying_key().0, &signature.0)
                }
            }

            impl Verifier<SignatureRef<'_>> for [<$param UnpackedSigningKey>] {
                fn verify(&self, msg: &[u8], signature: &SignatureRef<'_>) -> Result<(), Error> {
                    GenericArray::try_from_slice(signature.0)
                        .map_err(|_| Error::new())
                        .and_then(|sig| $param::verify(msg, &self.verifying_key().0, sig))
                }
            }

            #[cfg(feature = "randomized-signer")]
            impl RandomizedSigner<[<$param Signature>]> for [<$param SigningKey>] {
                fn try_sign_with_rng(
                    &self,
                    rng: &mut impl CryptoRngCore,
                    msg: &[u8],
                ) -> Result<[<$param Signature>], Error> {
                    let mut rho = GenericArray::<
                        u8,
                        <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::LambdaBytes,
                    >::default();
                    rng.fill_bytes(&mut rho);
                    let mut signature = GenericArray::default();
                    $param::sign(msg, &self.0, &rho, &mut signature);
                    Ok([<$param Signature>](signature))
                }
            }

            #[cfg(feature = "randomized-signer")]
            impl RandomizedSigner<Box<[<$param Signature>]>> for [<$param SigningKey>] {
                fn try_sign_with_rng(
                    &self,
                    rng: &mut impl CryptoRngCore,
                    msg: &[u8],
                ) -> Result<Box<[<$param Signature>]>, Error> {
                    let mut rho = GenericArray::<
                        u8,
                        <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::LambdaBytes,
                    >::default();
                    rng.fill_bytes(&mut rho);
                    let mut signature = Box::new([<$param Signature>](GenericArray::default()));
                    $param::sign(msg, &self.0, &rho, &mut signature.0);
                    Ok(signature)
                }
            }

            #[cfg(feature = "randomized-signer")]
            impl RandomizedSigner<[<$param Signature>]> for [<$param UnpackedSigningKey>] {
                fn try_sign_with_rng(
                    &self,
                    rng: &mut impl CryptoRngCore,
                    msg: &[u8],
                ) -> Result<[<$param Signature>], Error> {
                    let mut rho = GenericArray::<
                        u8,
                        <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::LambdaBytes,
                    >::default();
                    rng.fill_bytes(&mut rho);
                    let mut signature = GenericArray::default();
                    $param::unpacked_sign(msg, &self.0, &rho, &mut signature);
                    Ok([<$param Signature>](signature))
                }
            }

            impl AsRef<[u8]> for [<$param Signature>] {
                fn as_ref(&self) -> &[u8] {
                    self.0.as_slice()
                }
            }

            impl TryFrom<&[u8]> for [<$param Signature>] {
                type Error = Error;

                fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                    GenericArray::try_from_slice(value)
                        .map_err(|_| Error::new())
                        .map(|arr| Self(arr.clone()))
                }
            }

            impl From<[<$param Signature>]> for [u8; <[<$param Parameters>] as FAESTParameters>::SignatureSize::USIZE] {
                fn from(value: [<$param Signature>]) -> Self {
                    value.to_bytes()
                }
            }

            impl SignatureEncoding for [<$param Signature>] {
                type Repr = [u8; <[<$param Parameters>] as FAESTParameters>::SignatureSize::USIZE];

                fn to_bytes(&self) -> Self::Repr {
                    // NOTE: this could be done with Into if it would be supported
                    let mut ret = [0; <[<$param Parameters>] as FAESTParameters>::SignatureSize::USIZE];
                    ret.copy_from_slice(self.0.as_slice());
                    ret
                }

                fn to_vec(&self) -> Vec<u8> {
                    self.0.to_vec()
                }

                fn encoded_len(&self) -> usize {
                    <[<$param Parameters>] as FAESTParameters>::SignatureSize::USIZE
                }
            }
        }
    };
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

#[cfg(test)]
#[generic_tests::define]
mod tests {
    use super::*;

    use std::fmt::Debug;

    #[cfg(feature = "serde")]
    use serde::{Serialize, de::DeserializeOwned};

    const TEST_MESSAGE: &[u8] = "test message".as_bytes();

    #[test]
    fn sign_and_verify<KP, S>()
    where
        KP: KeypairGenerator + Signer<S> + Verifier<S>,
        KP::VerifyingKey: Verifier<S> + for<'a> Verifier<SignatureRef<'a>>,
        S: AsRef<[u8]>,
    {
        let kp = KP::generate(rand::thread_rng());
        let vk = kp.verifying_key();
        let signature = kp.sign(TEST_MESSAGE);
        vk.verify(TEST_MESSAGE, &signature)
            .expect("signatures verifies");
        vk.verify(TEST_MESSAGE, &SignatureRef::from(signature.as_ref()))
            .expect("signature verifies as &[u8]");
        kp.verify(TEST_MESSAGE, &signature)
            .expect("signature verifies with sk");
    }

    #[cfg(feature = "randomized-signer")]
    #[test]
    fn randomized_sign_and_verify<KP, S>()
    where
        KP: KeypairGenerator + RandomizedSigner<S> + Verifier<S>,
        KP::VerifyingKey: Verifier<S> + for<'a> Verifier<SignatureRef<'a>>,
        S: AsRef<[u8]>,
    {
        let mut rng = rand::thread_rng();
        let kp = KP::generate(&mut rng);
        let vk = kp.verifying_key();
        let signature = kp.sign_with_rng(&mut rng, TEST_MESSAGE);
        vk.verify(TEST_MESSAGE, &signature)
            .expect("signatures verifies");
        vk.verify(TEST_MESSAGE, &SignatureRef::from(signature.as_ref()))
            .expect("signature verifies as &[u8]");
        kp.verify(TEST_MESSAGE, &signature)
            .expect("signature verifies with sk");
    }

    #[test]
    fn serialize_signature<KP, S>()
    where
        KP: KeypairGenerator + Signer<S> + Verifier<S>,
        KP::VerifyingKey: Verifier<S> + for<'a> Verifier<SignatureRef<'a>>,
        S: AsRef<[u8]> + for<'a> TryFrom<&'a [u8], Error = Error>,
    {
        let kp = KP::generate(rand::thread_rng());
        let vk = kp.verifying_key();
        let signature = kp.sign(TEST_MESSAGE);
        let signature2 = S::try_from(signature.as_ref()).expect("signature deserializes");
        vk.verify(TEST_MESSAGE, &signature2)
            .expect("signature verifies");
    }

    #[test]
    fn serialize_keys<KP, S>()
    where
        KP: KeypairGenerator + Signer<S> + Verifier<S> + ByteEncoding + Eq + Debug,
        KP::VerifyingKey: Verifier<S> + ByteEncoding + Eq + Debug,
        for<'a> <KP as TryFrom<&'a [u8]>>::Error: Debug,
        for<'a> <KP::VerifyingKey as TryFrom<&'a [u8]>>::Error: Debug,
    {
        let kp = KP::generate(rand::thread_rng());
        let vk = kp.verifying_key();
        let signature = kp.sign(TEST_MESSAGE);

        let kp2 = KP::try_from(kp.to_bytes().as_ref()).unwrap();
        let vk2 = KP::VerifyingKey::try_from(vk.to_bytes().as_ref()).unwrap();

        assert_eq!(kp, kp2);
        assert_eq!(vk, vk2);

        vk2.verify(TEST_MESSAGE, &signature)
            .expect("signature verifies");
        let signature = kp2.sign(TEST_MESSAGE);
        vk.verify(TEST_MESSAGE, &signature)
            .expect("signature verifies");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_serialization<KP, S>()
    where
        KP: KeypairGenerator + Signer<S> + Serialize + DeserializeOwned + Eq + Debug,
    {
        let mut out = vec![];
        let mut ser = serde_json::Serializer::new(&mut out);

        let kp = KP::generate(rand::thread_rng());
        kp.serialize(&mut ser).expect("serialize key pair");
        let serialized = String::from_utf8(out).expect("serialize to string");

        let mut de = serde_json::Deserializer::from_str(&serialized);
        let kp2 = KP::deserialize(&mut de).expect("deserialize key pair");
        assert_eq!(kp, kp2);
    }

    #[instantiate_tests(<FAEST128fSigningKey, FAEST128fSignature>)]
    mod faest_128f {}

    #[instantiate_tests(<FAEST128sSigningKey, FAEST128sSignature>)]
    mod faest_128s {}

    #[instantiate_tests(<FAEST192fSigningKey, FAEST192fSignature>)]
    mod faest_192f {}

    #[instantiate_tests(<FAEST192sSigningKey, FAEST192sSignature>)]
    mod faest_192s {}

    #[instantiate_tests(<FAEST256fSigningKey, FAEST256fSignature>)]
    mod faest_256f {}

    #[instantiate_tests(<FAEST256sSigningKey, FAEST256sSignature>)]
    mod faest_256s {}

    #[instantiate_tests(<FAESTEM128fSigningKey, FAESTEM128fSignature>)]
    mod faest_em_128f {}

    #[instantiate_tests(<FAESTEM128sSigningKey, FAESTEM128sSignature>)]
    mod faest_em_128s {}

    #[instantiate_tests(<FAESTEM192fSigningKey, FAESTEM192fSignature>)]
    mod faest_em_192f {}

    #[instantiate_tests(<FAESTEM192sSigningKey, FAESTEM192sSignature>)]
    mod faest_em_192s {}

    #[instantiate_tests(<FAESTEM256fSigningKey, FAESTEM256fSignature>)]
    mod faest_em_256f {}

    #[instantiate_tests(<FAESTEM256sSigningKey, FAESTEM256sSignature>)]
    mod faest_em_256s {}

    #[instantiate_tests(<FAEST128fUnpackedSigningKey, FAEST128fSignature>)]
    mod faest_128f_unpacked {}

    #[instantiate_tests(<FAEST128sUnpackedSigningKey, FAEST128sSignature>)]
    mod faest_128s_unpacked {}

    #[instantiate_tests(<FAEST192fUnpackedSigningKey, FAEST192fSignature>)]
    mod faest_192f_unpacked {}

    #[instantiate_tests(<FAEST192sUnpackedSigningKey, FAEST192sSignature>)]
    mod faest_192s_unpacked {}

    #[instantiate_tests(<FAEST256fUnpackedSigningKey, FAEST256fSignature>)]
    mod faest_256f_unpacked {}

    #[instantiate_tests(<FAEST256sUnpackedSigningKey, FAEST256sSignature>)]
    mod faest_256s_unpacked {}

    #[instantiate_tests(<FAESTEM128fUnpackedSigningKey, FAESTEM128fSignature>)]
    mod faest_em_128f_unpacked {}

    #[instantiate_tests(<FAESTEM128sUnpackedSigningKey, FAESTEM128sSignature>)]
    mod faest_em_128s_unpacked {}

    #[instantiate_tests(<FAESTEM192fUnpackedSigningKey, FAESTEM192fSignature>)]
    mod faest_em_192f_unpacked {}

    #[instantiate_tests(<FAESTEM192sUnpackedSigningKey, FAESTEM192sSignature>)]
    mod faest_em_192s_unpacked {}

    #[instantiate_tests(<FAESTEM256fUnpackedSigningKey, FAESTEM256fSignature>)]
    mod faest_em_256f_unpacked {}

    #[instantiate_tests(<FAESTEM256sUnpackedSigningKey, FAESTEM256sSignature>)]
    mod faest_em_256s_unpacked {}
}
