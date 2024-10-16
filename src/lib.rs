#![doc = include_str!("../README.md")]
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
use serde::{Deserialize, Serialize};
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

macro_rules! define_impl {
    ($param:ident) => {
        paste! {
            #[doc = "Signing key for " $param]
            #[derive(Debug, Clone, PartialEq, Eq)]
            #[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
            #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
            pub struct [<$param SigningKey>](SecretKey<<[<$param Parameters>] as FAESTParameters>::OWF>);

            impl TryFrom<&[u8]> for [<$param SigningKey>] {
                type Error = Error;

                fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                    SecretKey::try_from_bytes(value).map(|sk| Self(sk))
                }
            }

            impl From<&[<$param SigningKey>]> for [u8; <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::SK::USIZE] {
                fn from(value: &[<$param SigningKey>]) -> Self {
                    value.0.as_bytes().into_array()
                }
            }

            #[doc = "Verification key for " $param]
            #[derive(Debug, Clone, PartialEq, Eq)]
            #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
            pub struct [<$param VerificationKey>](PublicKey<<[<$param Parameters>] as FAESTParameters>::OWF>);

            impl TryFrom<&[u8]> for [<$param VerificationKey>] {
                type Error = Error;

                fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                    PublicKey::try_from_bytes(value).map(|pk| Self(pk))
                }
            }

            impl From<&[<$param VerificationKey>]> for [u8; <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::PK::USIZE] {
                fn from(value: &[<$param VerificationKey>]) -> Self {
                    value.0.as_bytes().into_array()
                }
            }

            #[doc = "Keypair for " $param]
            #[derive(Debug, Clone, PartialEq, Eq)]
            #[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
            pub struct [<$param KeyPair>]([<$param SigningKey>], #[cfg_attr(feature = "zeroize", zeroize(skip))] [<$param VerificationKey>]);

            impl TryFrom<&[u8]> for [<$param KeyPair>] {
                type Error = Error;

                fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                    SecretKey::try_from_bytes(value).map(|sk| {
                        let pk = sk.as_public_key();
                        Self([<$param SigningKey>](sk), [<$param VerificationKey>](pk))
                     }).map_err(|_| Error::new())
                }
            }

            impl From<&[<$param KeyPair>]> for [u8; <<[<$param Parameters>] as FAESTParameters>::OWF as OWFParameters>::SK::USIZE] {
                fn from(value: &[<$param KeyPair>]) -> Self {
                    Self::from(&value.0)
                }
            }

            impl Keypair for [<$param SigningKey>] {
                type VerifyingKey = [<$param VerificationKey>];

                fn verifying_key(&self) -> Self::VerifyingKey {
                    [<$param VerificationKey>](self.0.as_public_key())
                }
            }

            impl Keypair for [<$param KeyPair>] {
                type VerifyingKey = [<$param VerificationKey>];

                fn verifying_key(&self) -> Self::VerifyingKey {
                    self.1.clone()
                }
            }

            impl AsRef<[<$param SigningKey>]> for [<$param KeyPair>] {
                fn as_ref(&self) -> &[<$param SigningKey>] {
                    &self.0
                }
            }

            impl AsRef<[<$param VerificationKey>]> for [<$param KeyPair>] {
                fn as_ref(&self) -> &[<$param VerificationKey>] {
                    &self.1
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

            impl KeypairGenerator for [<$param KeyPair>] {
                fn generate<R>(rng: R) -> Self
                where
                    R: CryptoRngCore,
                {
                    let sk = faest_keygen::<<[<$param Parameters>] as FAESTParameters>::OWF, R>(rng);
                    let pk = sk.as_public_key();
                    Self([<$param SigningKey>](sk), [<$param VerificationKey>](pk))
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

            impl Verifier<SignatureRef<'_>> for [<$param VerificationKey>] {
                fn verify(&self, msg: &[u8], signature: &SignatureRef<'_>) -> Result<(), Error> {
                    GenericArray::try_from_slice(signature.0)
                        .map_err(|_| Error::new())
                        .and_then(|sig| faest_verify::<[<$param Parameters>]>(msg, &self.0, sig))
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

            impl Signer<[<$param Signature>]> for [<$param KeyPair>] {
                fn try_sign(&self, msg: &[u8]) -> Result<[<$param Signature>], Error> {
                    self.0.try_sign(msg)
                }

                fn sign(&self, msg: &[u8]) -> [<$param Signature>] {
                    self.0.sign(msg)
                }
            }

            impl Signer<Box<[<$param Signature>]>> for [<$param KeyPair>] {
                fn try_sign(&self, msg: &[u8]) -> Result<Box<[<$param Signature>]>, Error> {
                    self.0.try_sign(msg)
                }

                fn sign(&self, msg: &[u8]) -> Box<[<$param Signature>]> {
                    self.0.sign(msg)
                }
            }

            impl Verifier<[<$param Signature>]> for [<$param KeyPair>] {
                fn verify(&self, msg: &[u8], signature: &[<$param Signature>]) -> Result<(), Error> {
                    self.1.verify(msg, signature)
                }
            }

            #[cfg(feature = "randomized-signer")]
            impl RandomizedSigner<[<$param Signature>]> for [<$param KeyPair>] {
                fn try_sign_with_rng(
                    &self,
                    rng: &mut impl CryptoRngCore,
                    msg: &[u8],
                ) -> Result<[<$param Signature>], Error> {
                    self.0.try_sign_with_rng(rng, msg)
                }
            }

            #[cfg(feature = "randomized-signer")]
            impl RandomizedSigner<Box<[<$param Signature>]>> for [<$param KeyPair>] {
                fn try_sign_with_rng(
                    &self,
                    rng: &mut impl CryptoRngCore,
                    msg: &[u8],
                ) -> Result<Box<[<$param Signature>]>, Error> {
                    self.0.try_sign_with_rng(rng, msg)
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
