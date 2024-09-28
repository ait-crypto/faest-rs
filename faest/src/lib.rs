//! FAEST digital signature scheme

use generic_array::GenericArray;
use rand_core::CryptoRngCore;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "randomized-signer")]
use signature::RandomizedSigner;
pub use signature::{self, Error};
use signature::{Keypair, Signer, Verifier};
#[cfg(feature = "zeroize")]
use zeroize::ZeroizeOnDrop;

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
        OWFParameters, PARAM, PARAM128F, PARAM128FEM, PARAM128S, PARAM128SEM, PARAM192F,
        PARAM192FEM, PARAM192S, PARAM192SEM, PARAM256F, PARAM256FEM, PARAM256S, PARAM256SEM,
    },
};

/// Generate a key pair from a cryptographically secure RNG
pub trait KeypairGenerator: Keypair {
    /// Generate a new keypair
    fn generate<R>(rng: R) -> Self
    where
        R: CryptoRngCore;
}

macro_rules! define_impl {
    ($param:ident, $sk:ident, $vk:ident, $kp:ident, $sig:ident) => {
        #[derive(Debug, Clone)]
        #[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        pub struct $sk(SecretKey<<$param as PARAM>::OWF>);

        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        pub struct $vk(PublicKey<<$param as PARAM>::OWF>);

        #[derive(Debug, Clone)]
        #[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
        pub struct $kp($sk, #[cfg_attr(feature = "zeroize", zeroize(skip))] $vk);

        impl Keypair for $sk {
            type VerifyingKey = $vk;

            fn verifying_key(&self) -> Self::VerifyingKey {
                $vk(self.0.as_public_key())
            }
        }

        impl Keypair for $kp {
            type VerifyingKey = $vk;

            fn verifying_key(&self) -> Self::VerifyingKey {
                self.1.clone()
            }
        }

        impl AsRef<$sk> for $kp {
            fn as_ref(&self) -> &$sk {
                &self.0
            }
        }

        impl AsRef<$vk> for $kp {
            fn as_ref(&self) -> &$vk {
                &self.1
            }
        }

        impl KeypairGenerator for $sk {
            fn generate<R>(rng: R) -> Self
            where
                R: CryptoRngCore,
            {
                Self(faest_keygen::<$param, R>(rng))
            }
        }

        impl KeypairGenerator for $kp {
            fn generate<R>(rng: R) -> Self
            where
                R: CryptoRngCore,
            {
                let sk = faest_keygen::<$param, R>(rng);
                let pk = sk.as_public_key();
                Self($sk(sk), $vk(pk))
            }
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        pub struct $sig(GenericArray<u8, <$param as PARAM>::SIG>);

        impl Signer<$sig> for $sk {
            fn try_sign(&self, msg: &[u8]) -> Result<$sig, Error> {
                let mut signature = GenericArray::default();
                faest_sign::<$param, <$param as PARAM>::OWF>(msg, &self.0, &[], &mut signature);
                Ok($sig(signature))
            }
        }

        impl Signer<Box<$sig>> for $sk {
            fn try_sign(&self, msg: &[u8]) -> Result<Box<$sig>, Error> {
                let mut signature = Box::new($sig(GenericArray::default()));
                faest_sign::<$param, <$param as PARAM>::OWF>(msg, &self.0, &[], &mut signature.0);
                Ok(signature)
            }
        }

        impl Verifier<$sig> for $vk {
            fn verify(&self, msg: &[u8], signature: &$sig) -> Result<(), Error> {
                faest_verify::<$param, <$param as PARAM>::OWF>(msg, &self.0, &signature.0)
            }
        }

        #[cfg(feature = "randomized-signer")]
        impl RandomizedSigner<$sig> for $sk {
            fn try_sign_with_rng(
                &self,
                rng: &mut impl CryptoRngCore,
                msg: &[u8],
            ) -> Result<$sig, Error> {
                let mut rho = GenericArray::<
                    u8,
                    <<$param as PARAM>::OWF as OWFParameters>::LAMBDABYTES,
                >::default();
                rng.fill_bytes(&mut rho);
                let mut signature = GenericArray::default();
                faest_sign::<$param, <$param as PARAM>::OWF>(msg, &self.0, &rho, &mut signature);
                Ok($sig(signature))
            }
        }

        #[cfg(feature = "randomized-signer")]
        impl RandomizedSigner<Box<$sig>> for $sk {
            fn try_sign_with_rng(
                &self,
                rng: &mut impl CryptoRngCore,
                msg: &[u8],
            ) -> Result<Box<$sig>, Error> {
                let mut rho = GenericArray::<
                    u8,
                    <<$param as PARAM>::OWF as OWFParameters>::LAMBDABYTES,
                >::default();
                rng.fill_bytes(&mut rho);
                let mut signature = Box::new($sig(GenericArray::default()));
                faest_sign::<$param, <$param as PARAM>::OWF>(msg, &self.0, &rho, &mut signature.0);
                Ok(signature)
            }
        }

        impl Signer<$sig> for $kp {
            fn try_sign(&self, msg: &[u8]) -> Result<$sig, Error> {
                self.0.try_sign(msg)
            }
        }

        impl Signer<Box<$sig>> for $kp {
            fn try_sign(&self, msg: &[u8]) -> Result<Box<$sig>, Error> {
                self.0.try_sign(msg)
            }
        }

        impl Verifier<$sig> for $kp {
            fn verify(&self, msg: &[u8], signature: &$sig) -> Result<(), Error> {
                self.1.verify(msg, signature)
            }
        }

        #[cfg(feature = "randomized-signer")]
        impl RandomizedSigner<$sig> for $kp {
            fn try_sign_with_rng(
                &self,
                rng: &mut impl CryptoRngCore,
                msg: &[u8],
            ) -> Result<$sig, Error> {
                self.0.try_sign_with_rng(rng, msg)
            }
        }

        #[cfg(feature = "randomized-signer")]
        impl RandomizedSigner<Box<$sig>> for $kp {
            fn try_sign_with_rng(
                &self,
                rng: &mut impl CryptoRngCore,
                msg: &[u8],
            ) -> Result<Box<$sig>, Error> {
                self.0.try_sign_with_rng(rng, msg)
            }
        }
    };
}

define_impl!(
    PARAM128F,
    FAEST128fSigningKey,
    FAEST128fVerificationKey,
    FAEST128fKeyPair,
    FAEST128fSignature
);

define_impl!(
    PARAM128S,
    FAEST128sSigningKey,
    FAEST128sVerificationKey,
    FAEST128sKeyPair,
    FAEST128sSignature
);

define_impl!(
    PARAM192F,
    FAEST192fSigningKey,
    FAEST192fVerificationKey,
    FAEST192fKeyPair,
    FAEST192fSignature
);

define_impl!(
    PARAM192S,
    FAEST192sSigningKey,
    FAEST192sVerificationKey,
    FAEST192sKeyPair,
    FAEST192sSignature
);

define_impl!(
    PARAM256F,
    FAEST256fSigningKey,
    FAEST256fVerificationKey,
    FAEST256fKeyPair,
    FAEST256fSignature
);

define_impl!(
    PARAM256S,
    FAEST256sSigningKey,
    FAEST256sVerificationKey,
    FAEST256sKeyPair,
    FAEST256sSignature
);

define_impl!(
    PARAM128FEM,
    FAEST128EMfSigningKey,
    FAEST128EMfVerificationKey,
    FAEST128EMfKeyPair,
    FAEST128EMfSignature
);

define_impl!(
    PARAM128SEM,
    FAEST128EMsSigningKey,
    FAEST128EMsVerificationKey,
    FAEST128EMsKeyPair,
    FAEST128EMsSignature
);

define_impl!(
    PARAM192FEM,
    FAEST192EMfSigningKey,
    FAEST192EMfVerificationKey,
    FAEST192EMfKeyPair,
    FAEST192EMfSignature
);

define_impl!(
    PARAM192SEM,
    FAEST192EMsSigningKey,
    FAEST192EMsVerificationKey,
    FAEST192EMsKeyPair,
    FAEST192EMsSignature
);

define_impl!(
    PARAM256FEM,
    FAEST256EMfSigningKey,
    FAEST256EMfVerificationKey,
    FAEST256EMfKeyPair,
    FAEST256EMfSignature
);

define_impl!(
    PARAM256SEM,
    FAEST256EMsSigningKey,
    FAEST256EMsVerificationKey,
    FAEST256EMsKeyPair,
    FAEST256EMsSignature
);
