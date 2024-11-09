use std::{
    fmt::{self, Debug},
    io::Write,
    iter::zip,
};

use crate::{
    parameter::{BaseParameters, FAESTParameters, OWFParameters, TauParameters},
    prg::IV,
    random_oracles::{Hasher, RandomOracle},
    universal_hashing::{VoleHasherInit, VoleHasherProcess},
    utils::Reader,
    vc::VectorCommitment,
    vole::{volecommit, volereconstruct, VoleCommitmentCRef},
    ByteEncoding, Error,
};

use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use rand_core::CryptoRngCore;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub(crate) struct SecretKey<O>
where
    O: OWFParameters,
{
    pub(crate) owf_key: GenericArray<u8, O::LAMBDABYTES>,
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

            O::extendwitness(owf_key, owf_input)
                .map(|_| {
                    let mut owf_output = GenericArray::default();
                    O::evaluate_owf(owf_key, owf_input, &mut owf_output);
                    Self {
                        owf_key: owf_key.clone(),
                        pk: PublicKey {
                            owf_input: owf_input.clone(),
                            owf_output,
                        },
                    }
                })
                .ok_or_else(Error::new)
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
            SecretKey::<O>::try_from(bytes.as_slice())
                .map_err(|_| serde::de::Error::custom("expected a valid secret key"))
        })
    }
}

pub(crate) struct PublicKey<O>
where
    O: OWFParameters,
{
    pub(crate) owf_input: GenericArray<u8, O::InputSize>,
    pub(crate) owf_output: GenericArray<u8, O::InputSize>,
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
            PublicKey::<O>::try_from(bytes.as_slice())
                .map_err(|_| serde::de::Error::custom("expected a valid public key"))
        })
    }
}

type RO<P> =
    <<<P as FAESTParameters>::OWF as OWFParameters>::BaseParams as BaseParameters>::RandomOracle;
type VoleHasher<P> =
    <<<P as FAESTParameters>::OWF as OWFParameters>::BaseParams as BaseParameters>::VoleHasher;

/// Hashes required for FAEST implementation
trait FaestHash {
    /// Generate `µ`
    fn hash_mu(mu: &mut [u8], input: &[u8], output: &[u8], msg: &[u8]);
    /// Generate `r` and `iv`
    fn hash_r_iv(r: &mut [u8], iv: &mut IV, key: &[u8], mu: &[u8], rho: &[u8]);
    /// Generate first challange
    fn hash_challenge_1(chall1: &mut [u8], mu: &[u8], hcom: &[u8], c: &[u8], iv: &[u8]);
    /// Generate second challenge
    fn hash_challenge_2(chall2: &mut [u8], chall1: &[u8], u_t: &[u8], hv: &[u8], d: &[u8]);
    /// Generate third challenge
    fn hash_challenge_3(chall3: &mut [u8], chall2: &[u8], a_t: &[u8], b_t: &[u8]);
}

impl<RO> FaestHash for RO
where
    RO: RandomOracle,
{
    fn hash_mu(mu: &mut [u8], input: &[u8], output: &[u8], msg: &[u8]) {
        let mut h1_hasher = Self::h1_init();
        h1_hasher.update(input);
        h1_hasher.update(output);
        h1_hasher.update(msg);
        h1_hasher.finish().read(mu);
    }

    fn hash_r_iv(r: &mut [u8], iv: &mut IV, key: &[u8], mu: &[u8], rho: &[u8]) {
        let mut h3_hasher = Self::h3_init();
        h3_hasher.update(key);
        h3_hasher.update(mu);
        h3_hasher.update(rho);

        let mut h3_reader = h3_hasher.finish();
        h3_reader.read(r);
        h3_reader.read(iv);
    }

    fn hash_challenge_1(chall1: &mut [u8], mu: &[u8], hcom: &[u8], c: &[u8], iv: &[u8]) {
        let mut h2_hasher = Self::h2_init();
        h2_hasher.update(mu);
        h2_hasher.update(hcom);
        h2_hasher.update(c);
        h2_hasher.update(iv);
        h2_hasher.finish().read(chall1);
    }

    fn hash_challenge_2(chall2: &mut [u8], chall1: &[u8], u_t: &[u8], hv: &[u8], d: &[u8]) {
        let mut h2_hasher = Self::h2_init();
        h2_hasher.update(chall1);
        h2_hasher.update(u_t);
        h2_hasher.update(hv);
        h2_hasher.update(d);
        h2_hasher.finish().read(chall2);
    }

    fn hash_challenge_3(chall3: &mut [u8], chall2: &[u8], a_t: &[u8], b_t: &[u8]) {
        let mut h2_hasher = Self::h2_init();
        h2_hasher.update(chall2);
        h2_hasher.update(a_t);
        h2_hasher.update(b_t);
        h2_hasher.finish().read(chall3);
    }
}

#[inline]
pub(crate) fn faest_keygen<O, R>(rng: R) -> SecretKey<O>
where
    O: OWFParameters,
    R: CryptoRngCore,
{
    O::keygen_with_rng(rng)
}

#[inline(always)]
pub(crate) fn faest_sign<P>(
    msg: &[u8],
    sk: &SecretKey<P::OWF>,
    rho: &[u8],
    signature: &mut GenericArray<u8, P::SignatureSize>,
) where
    P: FAESTParameters,
{
    sign::<P, P::OWF>(msg, sk, rho, signature);
}

#[allow(clippy::type_complexity)]
fn sign<P, O>(
    msg: &[u8],
    sk: &SecretKey<O>,
    rho: &[u8],
    signature: &mut GenericArray<u8, P::SignatureSize>,
) where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    let mut mu =
        GenericArray::<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2>::default();
    RO::<P>::hash_mu(&mut mu, &sk.pk.owf_input, &sk.pk.owf_output, msg);

    let mut r = GenericArray::<u8, O::LAMBDABYTES>::default();
    let mut iv = IV::default();
    RO::<P>::hash_r_iv(&mut r, &mut iv, &sk.owf_key, &mu, rho);

    let volecommit_cs =
        &mut signature[..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)];
    let (hcom, decom, u, gv) = volecommit::<
        <O::BaseParams as BaseParameters>::VC,
        P::Tau,
        O::LHATBYTES,
    >(VoleCommitmentCRef::new(volecommit_cs), &r, &iv);
    let mut chall1 =
        GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall1>::default();
    RO::<P>::hash_challenge_1(&mut chall1, &mu, &hcom, volecommit_cs, &iv);

    let signature =
        &mut signature[O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)..];
    let (u_t, hv) = {
        let vole_hasher = VoleHasher::<P>::new_vole_hasher(&chall1);
        let u_t = vole_hasher.process(&u);

        let mut h1_hasher = RO::<P>::h1_init();
        for v in gv.iter() {
            v.iter()
                .for_each(|v| h1_hasher.update(&vole_hasher.process(v)));
        }

        let hv: GenericArray<_, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
            h1_hasher.finish().read_into();
        (u_t, hv)
    };

    let w = P::OWF::witness(&sk.owf_key, &sk.pk.owf_input);
    let d = Box::<GenericArray<u8, O::LBYTES>>::from_iter(
        zip(w.iter(), &u[..O::LBYTES::USIZE]).map(|(w, u)| w ^ *u),
    );

    let mut chall2 =
        GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>::default();
    RO::<P>::hash_challenge_2(&mut chall2, &chall1, &u_t, &hv, &d);

    let new_u = GenericArray::from_slice(&u[..O::LBYTES::USIZE + O::LAMBDABYTES::USIZE]);
    let new_gv = Box::<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>::from_iter(
        gv.into_iter().flat_map(|x| {
            x.into_iter().map(|y| {
                y.into_iter()
                    .take(O::LBYTES::USIZE + O::LAMBDABYTES::USIZE)
                    .collect::<GenericArray<u8, O::LAMBDALBYTES>>()
            })
        }),
    );

    let (a_t, b_t) = P::OWF::prove(
        &w,
        new_u,
        &new_gv,
        &sk.pk.owf_input,
        &sk.pk.owf_output,
        &chall2,
    );

    let mut chall3 = GenericArray::<u8, O::LAMBDABYTES>::default();
    RO::<P>::hash_challenge_3(&mut chall3, &chall2, &a_t, &b_t);

    sigma_to_signature(
        &u_t,
        &d,
        a_t.as_slice(),
        (0..<P::Tau as TauParameters>::Tau::USIZE).map(|i| {
            let s = P::Tau::decode_challenge(&chall3, i);
            if i < <P::Tau as TauParameters>::Tau0::USIZE {
                <O::BaseParams as BaseParameters>::VC::open::<
                    P::POWK0,
                    <P::Tau as TauParameters>::K0,
                    P::N0,
                >(&decom[i], GenericArray::from_slice(&s))
            } else {
                <O::BaseParams as BaseParameters>::VC::open::<
                    P::POWK1,
                    <P::Tau as TauParameters>::K1,
                    P::N1,
                >(&decom[i], GenericArray::from_slice(&s))
            }
        }),
        &chall3,
        &iv,
        signature,
    );
}

#[inline(always)]
pub(crate) fn faest_verify<P>(
    msg: &[u8],
    pk: &PublicKey<P::OWF>,
    sigma: &GenericArray<u8, P::SignatureSize>,
) -> Result<(), Error>
where
    P: FAESTParameters,
{
    verify::<P, P::OWF>(msg, pk, sigma)
}

#[allow(clippy::type_complexity)]
fn verify<P, O>(
    msg: &[u8],
    pk: &PublicKey<O>,
    sigma: &GenericArray<u8, P::SignatureSize>,
) -> Result<(), Error>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    let chall3 = GenericArray::from_slice(
        &sigma
            [P::SignatureSize::USIZE - (16 + O::LAMBDABYTES::USIZE)..P::SignatureSize::USIZE - 16],
    );
    let iv = &sigma[P::SignatureSize::USIZE - 16..];

    let mut mu: GenericArray<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
        GenericArray::default();
    RO::<P>::hash_mu(&mut mu, &pk.owf_input, &pk.owf_output, msg);

    let (hcom, gq_p) = volereconstruct::<<O::BaseParams as BaseParameters>::VC, P::Tau, O::LHATBYTES>(
        chall3,
        &sigma[(O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1))
            + (2 * O::LAMBDABYTES::USIZE)
            + O::LBYTES::USIZE
            + 2..P::SignatureSize::USIZE - (16 + O::LAMBDABYTES::USIZE)],
        &iv.try_into().unwrap(),
    );

    let mut chall1 =
        GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall1>::default();
    let c = &sigma[..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)];
    RO::<P>::hash_challenge_1(&mut chall1, &mu, &hcom, c, iv);

    let vole_hasher = VoleHasher::<P>::new_vole_hasher(&chall1);
    let def = GenericArray::default();
    let def2 = GenericArray::<u8, O::LHATBYTES>::default();
    let mut gq =
        GenericArray::<Vec<GenericArray<u8, O::LHATBYTES>>, <P::Tau as TauParameters>::Tau>::default_boxed();
    let mut gd_t = GenericArray::<
        Vec<&GenericArray<u8, O::LAMBDAPLUS2>>,
        <P::Tau as TauParameters>::Tau,
    >::default_boxed();

    let u_t = &sigma[O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
        ..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
            + O::LAMBDABYTES::USIZE
            + 2];

    gq[0].clone_from(&gq_p[0]);
    gd_t[0] = P::Tau::decode_challenge_as_iter(chall3, 0)
        .map(|d| {
            if d == 1 {
                GenericArray::from_slice(u_t)
            } else {
                &def
            }
        })
        .collect();

    for i in 1..<P::Tau as TauParameters>::Tau::USIZE {
        let delta = P::Tau::decode_challenge(chall3, i);
        gd_t[i] = delta
            .iter()
            .map(|d| {
                if *d == 1 {
                    GenericArray::from_slice(u_t)
                } else {
                    &def
                }
            })
            .collect();
        gq[i] = gq_p[i]
            .iter()
            .zip(delta.into_iter().map(|d| {
                if d == 1 {
                    GenericArray::from_slice(
                        &c[O::LHATBYTES::USIZE * (i - 1)..O::LHATBYTES::USIZE * i],
                    )
                } else {
                    &def2
                }
            }))
            .map(|(q, d)| zip(q, d).map(|(q, d)| (q ^ d)).collect())
            .collect::<Vec<GenericArray<u8, O::LHATBYTES>>>();
    }
    let gq_t = gq
        .iter()
        .flat_map(|q| q.iter().map(|q| vole_hasher.process(q)));

    let mut h1_hasher = RO::<P>::h1_init();
    zip(gq_t, gd_t.into_iter().flatten())
        .flat_map(|(q, d)| zip(q, d).map(|(q, d)| q ^ d))
        .for_each(|v| h1_hasher.update(&[v]));
    let hv: GenericArray<_, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
        h1_hasher.finish().read_into();

    let d = &sigma[O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
        + O::LAMBDABYTES::USIZE
        + 2
        ..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
            + O::LAMBDABYTES::USIZE
            + 2
            + O::LBYTES::USIZE];
    let mut chall2 =
        GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>::default();
    RO::<P>::hash_challenge_2(&mut chall2, &chall1, u_t, &hv, d);

    let a_t = &sigma[O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
        + O::LAMBDABYTES::USIZE
        + 2
        + O::LBYTES::USIZE
        ..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
            + 2 * O::LAMBDABYTES::USIZE
            + 2
            + O::LBYTES::USIZE];
    let b_t = P::OWF::verify::<P::Tau>(
        GenericArray::from_slice(d),
        Box::<GenericArray<_, _>>::from_iter(gq.into_iter().flat_map(|x| {
            x.into_iter()
                .map(|y| {
                    y.into_iter()
                        .take(O::LBYTES::USIZE + O::LAMBDABYTES::USIZE)
                        .collect::<GenericArray<u8, _>>()
                })
                .collect::<Vec<GenericArray<u8, _>>>()
        })),
        GenericArray::from_slice(a_t),
        &chall2,
        chall3,
        &pk.owf_input,
        &pk.owf_output,
    );

    let mut chall3_p = GenericArray::default();
    RO::<P>::hash_challenge_3(&mut chall3_p, &chall2, a_t, &b_t);
    if *chall3 == chall3_p {
        Ok(())
    } else {
        Err(Error::new())
    }
}

fn sigma_to_signature<Lambda>(
    u_t: &[u8],
    d: &[u8],
    a_t: &[u8],
    pdecom: impl Iterator<Item = (Vec<GenericArray<u8, Lambda>>, Vec<u8>)>,
    chall3: &[u8],
    iv: &IV,
    mut signature: &mut [u8],
) where
    Lambda: ArrayLength,
{
    signature.write_all(u_t).unwrap();
    signature.write_all(d).unwrap();
    signature.write_all(a_t).unwrap();
    pdecom.for_each(|x| {
        x.0.iter().for_each(|v| {
            signature.write_all(v).unwrap();
        });
        signature.write_all(&x.1).unwrap();
    });
    signature.write_all(chall3).unwrap();
    signature.write_all(iv).unwrap();
}

#[cfg(test)]
#[generic_tests::define]
mod test {
    use super::*;

    use generic_array::GenericArray;
    use rand::RngCore;

    use crate::parameter::{
        FAEST128fParameters, FAEST128sParameters, FAEST192fParameters, FAEST192sParameters,
        FAEST256fParameters, FAEST256sParameters, FAESTEM128fParameters, FAESTEM128sParameters,
        FAESTEM192fParameters, FAESTEM192sParameters, FAESTEM256fParameters, FAESTEM256sParameters,
        FAESTParameters,
    };

    const RUNS: usize = 3;

    fn random_message(mut rng: impl RngCore) -> Vec<u8> {
        let mut length = [0];
        while length[0] == 0 {
            rng.fill_bytes(&mut length);
        }
        let mut ret = vec![0; length[0] as usize];
        rng.fill_bytes(&mut ret);
        ret
    }

    #[test]
    fn sign_and_verify<P: FAESTParameters>() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let sk = P::OWF::keygen_with_rng(&mut rng);
            let msg = random_message(&mut rng);
            let mut sigma = GenericArray::default_boxed();
            faest_sign::<P>(&msg, &sk, &[], &mut sigma);
            let pk = sk.as_public_key();
            let res = faest_verify::<P>(&msg, &pk, &sigma);
            assert!(res.is_ok());
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize<P: FAESTParameters>() {
        let mut rng = rand::thread_rng();
        let sk = P::OWF::keygen_with_rng(&mut rng);

        let mut out = vec![];
        let mut ser = serde_json::Serializer::new(&mut out);

        sk.serialize(&mut ser).expect("serialize key pair");
        let serialized = String::from_utf8(out).expect("serialize to string");

        let mut de = serde_json::Deserializer::from_str(&serialized);
        let sk2 = SecretKey::<P::OWF>::deserialize(&mut de).expect("deserialize secret key");
        assert_eq!(sk, sk2);

        let pk = sk.as_public_key();
        let mut out = vec![];
        let mut ser = serde_json::Serializer::new(&mut out);

        pk.serialize(&mut ser).expect("serialize key pair");
        let serialized = String::from_utf8(out).expect("serialize to string");

        let mut de = serde_json::Deserializer::from_str(&serialized);
        let pk2 = PublicKey::<P::OWF>::deserialize(&mut de).expect("deserialize public key");
        assert_eq!(pk, pk2);
    }

    #[instantiate_tests(<FAEST128fParameters>)]
    mod faest_128f {}

    #[instantiate_tests(<FAEST128sParameters>)]
    mod faest_128s {}

    #[instantiate_tests(<FAEST192fParameters>)]
    mod faest_192f {}

    #[instantiate_tests(<FAEST192sParameters>)]
    mod faest_192s {}

    #[instantiate_tests(<FAEST256fParameters>)]
    mod faest_256f {}

    #[instantiate_tests(<FAEST256sParameters>)]
    mod faest_256s {}

    #[instantiate_tests(<FAESTEM128fParameters>)]
    mod faest_em_128f {}

    #[instantiate_tests(<FAESTEM128sParameters>)]
    mod faest_em_128s {}

    #[instantiate_tests(<FAESTEM192fParameters>)]
    mod faest_em_192f {}

    #[instantiate_tests(<FAESTEM192sParameters>)]
    mod faest_em_192s {}

    #[instantiate_tests(<FAESTEM256fParameters>)]
    mod faest_em_256f {}

    #[instantiate_tests(<FAESTEM256sParameters>)]
    mod faest_em_256s {}
}
