//! Implementation of internal representation of secret and public keys
//!
//! This module also handles serialization and deserialization of any keys.

use std::fmt::{self, Debug};

use generic_array::{GenericArray, typenum::Unsigned};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    ByteEncoding, Error,
    parameter::{OWFParameters, Witness},
};

/// Internal representation of a secret key.
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub(crate) struct SecretKey<O>
where
    O: OWFParameters,
{
    pub(crate) owf_key: GenericArray<u8, O::LambdaBytes>,
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub(crate) pk: PublicKey<O>,
}

impl<O> Clone for SecretKey<O>
where
    O: OWFParameters,
{
    fn clone(&self) -> Self {
        Self {
            owf_key: self.owf_key.clone(),
            pk: self.pk.clone(),
        }
    }
}

impl<O> TryFrom<&[u8]> for SecretKey<O>
where
    O: OWFParameters,
{
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == O::SK::USIZE {
            let owf_input = GenericArray::from_slice(&bytes[..O::InputSize::USIZE]);
            let owf_key = GenericArray::from_slice(&bytes[O::InputSize::USIZE..]);

            let mut owf_output = GenericArray::default();
            O::evaluate_owf(owf_key, owf_input, &mut owf_output);

            if owf_key[0] & 0b11 == 0b11 {
                return Err(Error::new());
            }

            Ok(Self {
                owf_key: owf_key.clone(),
                pk: PublicKey {
                    owf_input: owf_input.clone(),
                    owf_output,
                },
            })
        } else {
            Err(Error::new())
        }
    }
}

impl<O> From<SecretKey<O>> for GenericArray<u8, O::SK>
where
    O: OWFParameters,
{
    fn from(value: SecretKey<O>) -> Self {
        value.to_bytes()
    }
}

impl<O> ByteEncoding for SecretKey<O>
where
    O: OWFParameters,
{
    type Repr = GenericArray<u8, O::SK>;

    fn to_bytes(&self) -> Self::Repr {
        let mut buf = GenericArray::default();
        buf[..O::InputSize::USIZE].copy_from_slice(&self.pk.owf_input);
        buf[O::InputSize::USIZE..].copy_from_slice(&self.owf_key);
        buf
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(O::SK::USIZE);
        buf.extend_from_slice(&self.pk.owf_input);
        buf.extend_from_slice(&self.owf_key);
        buf
    }

    fn encoded_len(&self) -> usize {
        O::SK::USIZE
    }
}

impl<O> SecretKey<O>
where
    O: OWFParameters,
{
    pub(crate) fn as_public_key(&self) -> PublicKey<O> {
        self.pk.clone()
    }
}

impl<O> Debug for SecretKey<O>
where
    O: OWFParameters,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("owf_key", &"redacted")
            .field("owf_input", &self.pk.owf_input.as_slice())
            .field("owf_output", &self.pk.owf_output.as_slice())
            .finish()
    }
}

impl<O> PartialEq for SecretKey<O>
where
    O: OWFParameters,
{
    fn eq(&self, rhs: &Self) -> bool {
        self.owf_key == rhs.owf_key && self.pk == rhs.pk
    }
}

impl<O> Eq for SecretKey<O> where O: OWFParameters {}

#[cfg(feature = "serde")]
impl<O> Serialize for SecretKey<O>
where
    O: OWFParameters,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_bytes().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, O> Deserialize<'de> for SecretKey<O>
where
    O: OWFParameters,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        GenericArray::<u8, O::SK>::deserialize(deserializer).and_then(|bytes| {
            Self::try_from(bytes.as_slice())
                .map_err(|_| serde::de::Error::custom("expected a valid secret key"))
        })
    }
}

/// Internal representation of a secret key, including the zk witness.
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]

pub(crate) struct UnpackedSecretKey<O>
where
    O: OWFParameters,
{
    pub(crate) sk: SecretKey<O>,
    pub(crate) wit: Witness<O>,
}

impl<O> Clone for UnpackedSecretKey<O>
where
    O: OWFParameters,
{
    fn clone(&self) -> Self {
        Self {
            sk: self.sk.clone(),
            wit: self.wit.clone(),
        }
    }
}

impl<O> From<SecretKey<O>> for UnpackedSecretKey<O>
where
    O: OWFParameters,
{
    fn from(value: SecretKey<O>) -> Self {
        Self {
            wit: O::witness(&value),
            sk: value,
        }
    }
}

impl<O> TryFrom<&[u8]> for UnpackedSecretKey<O>
where
    O: OWFParameters,
{
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let sk = SecretKey::<O>::try_from(value)?;
        Ok(Self {
            wit: O::witness(&sk),
            sk,
        })
    }
}

impl<O> From<UnpackedSecretKey<O>> for GenericArray<u8, O::SK>
where
    O: OWFParameters,
{
    fn from(value: UnpackedSecretKey<O>) -> Self {
        value.to_bytes()
    }
}

impl<O> ByteEncoding for UnpackedSecretKey<O>
where
    O: OWFParameters,
{
    type Repr = GenericArray<u8, O::SK>;

    fn to_bytes(&self) -> Self::Repr {
        self.sk.to_bytes()
    }

    fn to_vec(&self) -> Vec<u8> {
        self.sk.to_vec()
    }

    fn encoded_len(&self) -> usize {
        O::SK::USIZE
    }
}

impl<O> UnpackedSecretKey<O>
where
    O: OWFParameters,
{
    pub(crate) fn as_public_key(&self) -> PublicKey<O> {
        self.sk.pk.clone()
    }
}

impl<O> Debug for UnpackedSecretKey<O>
where
    O: OWFParameters,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKeyUnpacked")
            .field("owf_key", &"redacted")
            .field("owf_input", &self.sk.pk.owf_input.as_slice())
            .field("owf_output", &self.sk.pk.owf_output.as_slice())
            .field("owf_key_witness", &"redacted")
            .finish()
    }
}

impl<O> PartialEq for UnpackedSecretKey<O>
where
    O: OWFParameters,
{
    fn eq(&self, rhs: &Self) -> bool {
        self.sk == rhs.sk
    }
}

impl<O> Eq for UnpackedSecretKey<O> where O: OWFParameters {}

#[cfg(feature = "serde")]
impl<O> Serialize for UnpackedSecretKey<O>
where
    O: OWFParameters,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_bytes().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, O> Deserialize<'de> for UnpackedSecretKey<O>
where
    O: OWFParameters,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        GenericArray::<u8, O::SK>::deserialize(deserializer).and_then(|bytes| {
            Self::try_from(bytes.as_slice())
                .map_err(|_| serde::de::Error::custom("expected a valid secret key"))
        })
    }
}

/// Internal representation of a public key
pub(crate) struct PublicKey<O>
where
    O: OWFParameters,
{
    pub(crate) owf_input: GenericArray<u8, O::InputSize>,
    pub(crate) owf_output: GenericArray<u8, O::OutputSize>,
}

impl<O> Clone for PublicKey<O>
where
    O: OWFParameters,
{
    fn clone(&self) -> Self {
        Self {
            owf_input: self.owf_input.clone(),
            owf_output: self.owf_output.clone(),
        }
    }
}

impl<O> TryFrom<&[u8]> for PublicKey<O>
where
    O: OWFParameters,
{
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == O::PK::USIZE {
            let owf_input = GenericArray::from_slice(&bytes[..O::InputSize::USIZE]);
            let owf_output = GenericArray::from_slice(&bytes[O::InputSize::USIZE..]);
            Ok(Self {
                owf_input: owf_input.clone(),
                owf_output: owf_output.clone(),
            })
        } else {
            Err(Error::new())
        }
    }
}

impl<O> From<PublicKey<O>> for GenericArray<u8, O::PK>
where
    O: OWFParameters,
{
    fn from(value: PublicKey<O>) -> Self {
        value.to_bytes()
    }
}

impl<O> ByteEncoding for PublicKey<O>
where
    O: OWFParameters,
{
    type Repr = GenericArray<u8, O::PK>;

    fn to_bytes(&self) -> Self::Repr {
        let mut buf = GenericArray::default();
        buf[..O::InputSize::USIZE].copy_from_slice(&self.owf_input);
        buf[O::InputSize::USIZE..].copy_from_slice(&self.owf_output);
        buf
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(O::PK::USIZE);
        buf.extend_from_slice(&self.owf_input);
        buf.extend_from_slice(&self.owf_output);
        buf
    }

    fn encoded_len(&self) -> usize {
        O::PK::USIZE
    }
}

impl<O> Debug for PublicKey<O>
where
    O: OWFParameters,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("owf_input", &self.owf_input.as_slice())
            .field("owf_output", &self.owf_output.as_slice())
            .finish()
    }
}

impl<O> PartialEq for PublicKey<O>
where
    O: OWFParameters,
{
    fn eq(&self, rhs: &Self) -> bool {
        self.owf_input == rhs.owf_input && self.owf_output == rhs.owf_output
    }
}

impl<O> Eq for PublicKey<O> where O: OWFParameters {}

#[cfg(feature = "serde")]
impl<O> Serialize for PublicKey<O>
where
    O: OWFParameters,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_bytes().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, O> Deserialize<'de> for PublicKey<O>
where
    O: OWFParameters,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        GenericArray::<u8, O::PK>::deserialize(deserializer).and_then(|bytes| {
            Self::try_from(bytes.as_slice())
                .map_err(|_| serde::de::Error::custom("expected a valid public key"))
        })
    }
}
