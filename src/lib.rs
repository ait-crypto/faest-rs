#![doc = include_str!("../README.md")]
//! ## Usage
//!
//! Key generation, signing and verification can be implemented as follows:
//! ```
//! use faest::{FAEST128fKeyPair, FAEST128fSignature, Signer, Verifier, Keypair, KeypairGenerator};
//!
//! let keypair = FAEST128fKeyPair::generate(rand::thread_rng());
//! let msg = "some message".as_bytes();
//! let signature: FAEST128fSignature = keypair.sign(msg);
//!
//! let verification_key = keypair.verifying_key();
//! verification_key.verify(msg, &signature).expect("Verification failed");
//! ```
//!
//! Due to the size of the sigantures, all variants support signing into boxed signatures:
//! ```
//! use faest::{FAEST128fKeyPair, FAEST128fSignature, Signer, Verifier, Keypair, KeypairGenerator};
//!
//! let keypair = FAEST128fKeyPair::generate(rand::thread_rng());
//! let msg = "some message".as_bytes();
//! let signature: Box<FAEST128fSignature> = keypair.sign(msg);
//!
//! let verification_key = keypair.verifying_key();
//! verification_key.verify(msg, &signature).expect("Verification failed");
//! ```
//!
//! The signature generation is determinstic per default. If the
//! `randomized-signer` feature is enabled, the [signature::RandomizedSigner]
//! trait is also implemented:
//! ```
//! # #[cfg(feature="randomized-signer")] {
//! use faest::{FAEST128fKeyPair, FAEST128fSignature, RandomizedSigner, Verifier, Keypair, KeypairGenerator};
//!
//! let mut rng = rand::thread_rng();
//! let keypair = FAEST128fKeyPair::generate(&mut rng);
//! let msg = "some message".as_bytes();
//! let signature: FAEST128fSignature = keypair.sign_with_rng(&mut rng, msg);
//!
//! let verification_key = keypair.verifying_key();
//! verification_key.verify(msg, &signature).expect("Verification failed");
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// TODO: fix those
#![allow(
    clippy::type_complexity,
    clippy::boxed_local,
    clippy::too_many_arguments
)]

use generic_array::{typenum::Unsigned, GenericArray};
use paste::paste;
use rand_core::CryptoRngCore;
#[cfg(feature = "serde")]
use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};
#[cfg(feature = "randomized-signer")]
pub use signature::RandomizedSigner;
use signature::SignatureEncoding;
pub use signature::{self, Error, Keypair, Signer, Verifier};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

mod aes;
mod em;
mod faest;
mod fields;
mod parameter;
mod prg;
mod random_oracles;
mod rijndael_32;
mod universal_hashing;
mod utils;
mod vc;
mod vole;

use crate::{
    faest::{faest_keygen, faest_sign, faest_verify, PublicKey, SecretKey},
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

//// Byte-based encoding of keys
///
/// This is similar to [signature::SignatureEncoding] but for keys.
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
            #[doc = "Signing key for " $param]
            /// ```
            #[doc = "use faest::{" $param "SigningKey as SK, " $param "Signature as Sig};"]
            /// use faest::{Signer, Verifier, Keypair, KeypairGenerator};
            ///
            /// let keypair = SG::generate(rand::thread_rng());
            /// let msg = "some message".as_bytes();
            /// let signature: Sig = keypair.sign(msg);
            ///
            /// let verification_key = keypair.verifying_key();
            /// verification_key.verify(msg, &signature).expect("Verification failed");
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

            #[doc = "Signature for " $param]
            #[derive(Debug, Clone, PartialEq, Eq)]
            #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
            pub struct [<$param Signature>](GenericArray<u8, <[<$param Parameters>] as FAESTParameters>::SIG>);

            impl Signer<[<$param Signature>]> for [<$param SigningKey>] {
                fn try_sign(&self, msg: &[u8]) -> Result<[<$param Signature>], Error> {
                    Ok(self.sign(msg))
                }

                fn sign(&self, msg: &[u8]) -> [<$param Signature>] {
                    let mut signature = GenericArray::default();
                    faest_sign::<[<$param Parameters>]>(msg, &self.0, &[], &mut signature);
                    [<$param Signature>](signature)
                }
            }

            impl Signer<Box<[<$param Signature>]>> for [<$param SigningKey>] {
                fn try_sign(&self, msg: &[u8]) -> Result<Box<[<$param Signature>]>, Error> {
                    Ok(self.sign(msg))
                }

                fn sign(&self, msg: &[u8]) -> Box<[<$param Signature>]> {
                    let mut signature = Box::new([<$param Signature>](GenericArray::default()));
                    faest_sign::<[<$param Parameters>]>(msg, &self.0, &[], &mut signature.0);
                    signature
                }
            }

            impl Verifier<[<$param Signature>]> for [<$param VerificationKey>] {
                fn verify(&self, msg: &[u8], signature: &[<$param Signature>]) -> Result<(), Error> {
                    faest_verify::<[<$param Parameters>]>(msg, &self.0, &signature.0)
                }
            }

            impl Verifier<Box<[<$param Signature>]>> for [<$param VerificationKey>] {
                fn verify(&self, msg: &[u8], signature: &Box<[<$param Signature>]>) -> Result<(), Error> {
                    faest_verify::<[<$param Parameters>]>(msg, &self.0, &signature.0)
                }
            }

            impl Verifier<SignatureRef<'_>> for [<$param VerificationKey>] {
                fn verify(&self, msg: &[u8], signature: &SignatureRef<'_>) -> Result<(), Error> {
                    GenericArray::try_from_slice(signature.0)
                        .map_err(|_| Error::new())
                        .and_then(|sig| faest_verify::<[<$param Parameters>]>(msg, &self.0, sig))
                }
            }

            impl Verifier<[<$param Signature>]> for [<$param SigningKey>] {
                fn verify(&self, msg: &[u8], signature: &[<$param Signature>]) -> Result<(), Error> {
                    faest_verify::<[<$param Parameters>]>(msg, &self.0.pk, &signature.0)
                }
            }

            impl Verifier<Box<[<$param Signature>]>> for [<$param SigningKey>] {
                fn verify(&self, msg: &[u8], signature: &Box<[<$param Signature>]>) -> Result<(), Error> {
                    faest_verify::<[<$param Parameters>]>(msg, &self.0.pk, &signature.0)
                }
            }

            impl Verifier<SignatureRef<'_>> for [<$param SigningKey>] {
                fn verify(&self, msg: &[u8], signature: &SignatureRef<'_>) -> Result<(), Error> {
                    GenericArray::try_from_slice(signature.0)
                        .map_err(|_| Error::new())
                        .and_then(|sig| faest_verify::<[<$param Parameters>]>(msg, &self.0.pk, sig))
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
                        <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::LAMBDABYTES,
                    >::default();
                    rng.fill_bytes(&mut rho);
                    let mut signature = GenericArray::default();
                    faest_sign::<[<$param Parameters>]>(msg, &self.0, &rho, &mut signature);
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
                        <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::LAMBDABYTES,
                    >::default();
                    rng.fill_bytes(&mut rho);
                    let mut signature = Box::new([<$param Signature>](GenericArray::default()));
                    faest_sign::<[<$param Parameters>]>(msg, &self.0, &rho, &mut signature.0);
                    Ok(signature)
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

            impl From<[<$param Signature>]> for [u8; <[<$param Parameters>] as FAESTParameters>::SIG::USIZE] {
                fn from(value: [<$param Signature>]) -> Self {
                    value.to_bytes()
                }
            }

            impl SignatureEncoding for [<$param Signature>] {
                type Repr = [u8; <[<$param Parameters>] as FAESTParameters>::SIG::USIZE];

                fn to_bytes(&self) -> Self::Repr {
                    // NOTE: this could be done with Into if it would be supported
                    let mut ret = [0; <[<$param Parameters>] as FAESTParameters>::SIG::USIZE];
                    ret.copy_from_slice(self.0.as_slice());
                    ret
                }

                fn to_vec(&self) -> Vec<u8> {
                    self.0.to_vec()
                }

                fn encoded_len(&self) -> usize {
                    <[<$param Parameters>] as FAESTParameters>::SIG::USIZE
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

    #[cfg(feature = "serde")]
    use std::fmt::Debug;

    #[cfg(feature = "serde")]
    use serde::{de::DeserializeOwned, Serialize};

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

    /*
    #[test]
    fn serialize_keys<KP, S>()
    where
        KP: KeypairGenerator + Signer<S> + Verifier<S> + for<'a> TryFrom<&'a [u8]> + Into<[u8; _]>,
        KP::VerifyingKey: Verifier<S> + for<'a> Verifier<SignatureRef<'a>>,
    {
        let kp = KP::generate(rand::thread_rng());
        let vk = kp.verifying_key();
        let signature = kp.sign(TEST_MESSAGE);

        let kp2 = KP::try_from(&kp.into());

        let sk2 = SigningKey::<P>::try_from(sk.as_ref()).expect("sk -> [u8] -> sk");
        let vk2 = VerificationKey::<P>::try_from(vk.as_ref()).expect("vk -> [u8] -> vk");

        assert_eq!(sk, sk2);
        assert_eq!(vk, vk2)
    } */

    /*
    #[cfg(feature = "subtle")]
    #[test]
    fn subtle_eq<P: Parameters>() {
        use subtle::ConstantTimeEq;

        let (sk1, _vk1) = SigningKey::<P>::random().expect("keygen success");
        let (sk2, _vk2) = SigningKey::<P>::random().expect("keygen success");
        let sk3 = sk1.clone();

        assert!(bool::from(sk1.ct_eq(&sk1)));
        assert!(bool::from(sk1.ct_eq(&sk3)));
        assert!(!bool::from(sk1.ct_eq(&sk2)));
    }
    */

    #[cfg(feature = "serde")]
    #[test]
    fn serde_serialization<KP, S>()
    where
        KP: KeypairGenerator + Serialize + DeserializeOwned + Eq + Debug,
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
}
