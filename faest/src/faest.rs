use std::{fmt, io::Write, iter::zip, marker::PhantomData};

use crate::{
    parameter::{BaseParameters, TauParameters, Variant, PARAM, PARAMOWF},
    prg::IV,
    random_oracles::{Hasher, RandomOracle},
    universal_hashing::{VoleHasherInit, VoleHasherProcess},
    utils::Reader,
    vc::VectorCommitment,
    vole::{volecommit, volereconstruct},
};

use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use rand_core::CryptoRngCore;
#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "zeroize")]
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub(crate) struct SecretKey<O>
where
    O: PARAMOWF,
{
    pub(crate) owf_key: GenericArray<u8, O::LAMBDABYTES>,
    pub(crate) owf_input: GenericArray<u8, O::InputSize>,
    pub(crate) owf_output: GenericArray<u8, O::OutputSize>,
}

impl<O> SecretKey<O>
where
    O: PARAMOWF,
{
    fn as_bytes(&self) -> GenericArray<u8, O::SK> {
        let mut buf = GenericArray::default();
        buf[..O::InputSize::USIZE].copy_from_slice(&self.owf_input);
        buf[O::InputSize::USIZE..].copy_from_slice(&self.owf_key);
        buf
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() == O::SK::USIZE {
            Ok(Self::from_bytes(GenericArray::from_slice(bytes)))
        } else {
            Err(())
        }
    }

    fn from_bytes(bytes: &GenericArray<u8, O::SK>) -> Self {
        let owf_input = GenericArray::from_slice(&bytes[..O::InputSize::USIZE]);
        let owf_key = GenericArray::from_slice(&bytes[O::InputSize::USIZE..]);
        let mut owf_output = GenericArray::default();
        O::evaluate_owf(owf_key, owf_input, &mut owf_output);
        Self {
            owf_key: owf_key.clone(),
            owf_input: owf_input.clone(),
            owf_output,
        }
    }

    pub(crate) fn as_public_key(&self) -> PublicKey<O> {
        PublicKey {
            owf_input: self.owf_input.clone(),
            owf_output: self.owf_output.clone(),
        }
    }
}

#[cfg(feature = "serde")]
impl<O> Serialize for SecretKey<O>
where
    O: PARAMOWF,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.as_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'de, O> Deserialize<'de> for SecretKey<O>
where
    O: PARAMOWF,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor<O>(PhantomData<O>)
        where
            O: PARAMOWF;

        impl<'de, O> Visitor<'de> for BytesVisitor<O>
        where
            O: PARAMOWF,
        {
            type Value = SecretKey<O>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(&format!("a byte array of length {}", O::SK::USIZE))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                SecretKey::<O>::try_from_bytes(v)
                    .map_err(|_| E::invalid_length(O::SK::USIZE, &self))
            }
        }

        deserializer.deserialize_bytes(BytesVisitor(PhantomData))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicKey<O>
where
    O: PARAMOWF,
{
    pub(crate) owf_input: GenericArray<u8, O::InputSize>,
    pub(crate) owf_output: GenericArray<u8, O::OutputSize>,
}

impl<O> PublicKey<O>
where
    O: PARAMOWF,
{
    fn as_bytes(&self) -> GenericArray<u8, O::PK> {
        let mut buf = GenericArray::default();
        buf[..O::InputSize::USIZE].copy_from_slice(&self.owf_input);
        buf[O::InputSize::USIZE..].copy_from_slice(&self.owf_output);
        buf
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() == O::PK::USIZE {
            Ok(Self::from_bytes(GenericArray::from_slice(bytes)))
        } else {
            Err(())
        }
    }

    fn from_bytes(bytes: &GenericArray<u8, O::PK>) -> Self {
        let owf_input = GenericArray::from_slice(&bytes[..O::InputSize::USIZE]);
        let owf_output = GenericArray::from_slice(&bytes[O::InputSize::USIZE..]);
        Self {
            owf_input: owf_input.clone(),
            owf_output: owf_output.clone(),
        }
    }
}

#[cfg(feature = "serde")]
impl<O> Serialize for PublicKey<O>
where
    O: PARAMOWF,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.as_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'de, O> Deserialize<'de> for PublicKey<O>
where
    O: PARAMOWF,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor<O>(PhantomData<O>)
        where
            O: PARAMOWF;

        impl<'de, O> Visitor<'de> for BytesVisitor<O>
        where
            O: PARAMOWF,
        {
            type Value = PublicKey<O>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(&format!("a byte array of length {}", O::SK::USIZE))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                PublicKey::<O>::try_from_bytes(v)
                    .map_err(|_| E::invalid_length(O::SK::USIZE, &self))
            }
        }

        deserializer.deserialize_bytes(BytesVisitor(PhantomData))
    }
}

type RO<P> = <<<P as PARAM>::OWF as PARAMOWF>::BaseParams as BaseParameters>::RandomOracle;

fn hash_mu<R>(mu: &mut [u8], input: &[u8], output: &[u8], msg: &[u8])
where
    R: RandomOracle,
{
    let mut h1_hasher = R::h1_init();
    h1_hasher.update(input);
    h1_hasher.update(output);
    h1_hasher.update(msg);
    h1_hasher.finish().read(mu);
}

fn hash_r_iv<R>(r: &mut [u8], iv: &mut IV, key: &[u8], mu: &[u8], rho: &[u8])
where
    R: RandomOracle,
{
    let mut h3_hasher = R::h3_init();
    h3_hasher.update(key);
    h3_hasher.update(mu);
    h3_hasher.update(rho);

    let mut h3_reader = h3_hasher.finish();
    h3_reader.read(r);
    h3_reader.read(iv);
}

fn hash_challange_2<R>(chall2: &mut [u8], chall1: &[u8], u_t: &[u8], hv: &[u8], d: &[u8])
where
    R: RandomOracle,
{
    let mut h2_hasher = R::h2_init();
    h2_hasher.update(chall1);
    h2_hasher.update(u_t);
    h2_hasher.update(hv);
    h2_hasher.update(d);
    h2_hasher.finish().read(chall2);
}

fn hash_challenge_3<R>(chall3: &mut [u8], chall2: &[u8], a_t: &[u8], b_t: &[u8])
where
    R: RandomOracle,
{
    let mut h2_hasher = R::h2_init();
    h2_hasher.update(chall2);
    h2_hasher.update(a_t);
    h2_hasher.update(b_t);
    h2_hasher.finish().read(chall3);
}

#[inline]
pub(crate) fn faest_keygen<P, R>(rng: R) -> SecretKey<P::OWF>
where
    P: PARAM,
    R: CryptoRngCore,
{
    P::Cypher::keygen_with_rng(rng)
}

///input : Message (an array of bytes), sk : secret key, pk : public key, rho : lambda bits
///
///output : correction string (tau - 1 * (l_hat bits)), Hash of VOLE sceet (LAMBDA + 16 bits), Commitment to the witness (l bits)
///
/// Quicksilver proof (Lambda), Partial decommitment (Tau * (t0 * k0*lambda + t1 * k1*lambda  +  2Lambda) bits),
///
///last challenge (lambda bits), initialisation vector
#[allow(clippy::type_complexity)]
pub(crate) fn faest_sign<P, O>(
    msg: &[u8],
    sk: &SecretKey<O>,
    rho: &[u8],
    signature: &mut GenericArray<u8, P::SIG>,
) where
    P: PARAM<OWF = O>,
    O: PARAMOWF,
{
    let mut mu =
        GenericArray::<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2>::default();
    hash_mu::<RO<P>>(&mut mu, &sk.owf_input, &sk.owf_output, msg);

    let mut r = GenericArray::<u8, O::LAMBDABYTES>::default();
    let mut iv = IV::default();
    hash_r_iv::<RO<P>>(&mut r, &mut iv, &sk.owf_key, &mu, rho);

    let (hcom, decom, c, u, gv) =
        volecommit::<<O::BaseParams as BaseParameters>::VC, P::Tau, P::LH>(&r, &iv);
    let mut h2_hasher = RO::<P>::h2_init();
    h2_hasher.update(&mu);
    h2_hasher.update(&hcom);
    c.iter().for_each(|buf| h2_hasher.update(buf));
    h2_hasher.update(&iv);
    let mut chall1: Box<GenericArray<u8, O::CHALL1>> = GenericArray::default_boxed();
    h2_hasher.finish().read(&mut chall1);

    let vole_hasher = O::VoleHasher::new_vole_hasher(&chall1);
    let u_t = vole_hasher.process(&u);

    let mut h1_hasher = RO::<P>::h1_init();
    for v in gv.iter() {
        v.iter()
            .for_each(|v| h1_hasher.update(&vole_hasher.process(v)));
    }
    let mut hv: GenericArray<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
        GenericArray::default();
    h1_hasher.finish().read(&mut hv);

    let w = P::Cypher::witness(&sk.owf_key, &sk.owf_input);
    let d = GenericArray::<u8, O::LBYTES>::from_iter(
        zip(w.iter(), &u[..O::LBYTES::USIZE]).map(|(w, u)| w ^ *u),
    );

    let mut chall2: GenericArray<u8, O::CHALL> = GenericArray::default();
    hash_challange_2::<RO<P>>(&mut chall2, &chall1, &u_t, &hv, &d);

    let new_u = GenericArray::from_slice(&u[..O::LBYTES::USIZE + O::LAMBDABYTES::USIZE]);
    let new_gv = Box::new(
        gv.iter()
            .flat_map(|x| {
                x.iter()
                    .map(|y| {
                        y.iter()
                            .take(O::LBYTES::USIZE + O::LAMBDABYTES::USIZE)
                            .copied()
                            .collect::<GenericArray<u8, O::LAMBDALBYTES>>()
                    })
                    .collect::<Vec<GenericArray<u8, O::LAMBDALBYTES>>>()
            })
            .collect::<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>(),
    );

    let (a_t, b_t) = P::Cypher::prove(&w, new_u, &new_gv, &sk.owf_input, &sk.owf_output, &chall2);

    let mut chall3 = GenericArray::<u8, O::LAMBDABYTES>::default();
    hash_challenge_3::<RO<P>>(&mut chall3, &chall2, &a_t, &b_t);

    sigma_to_signature(
        c.iter().map(|value| value.as_ref()),
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
    )
}

#[allow(clippy::type_complexity)]
pub(crate) fn faest_verify<P, O>(msg: &[u8], pk: &PublicKey<O>, sigma: &[u8]) -> bool
where
    P: PARAM<OWF = O>,
    O: PARAMOWF,
{
    let chall3 = GenericArray::from_slice(
        &sigma[P::SIG::USIZE - (16 + O::LAMBDABYTES::USIZE)..P::SIG::USIZE - 16],
    );
    let iv = &sigma[P::SIG::USIZE - 16..];

    let mut mu: GenericArray<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
        GenericArray::default();
    hash_mu::<RO<P>>(&mut mu, &pk.owf_input, &pk.owf_output, msg);

    let (hcom, gq_p) = volereconstruct::<<O::BaseParams as BaseParameters>::VC, P::Tau, P::LH>(
        chall3,
        &sigma[(O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1))
            + (2 * O::LAMBDABYTES::USIZE)
            + O::LBYTES::USIZE
            + 2..P::SIG::USIZE - (16 + O::LAMBDABYTES::USIZE)],
        &iv.try_into().unwrap(),
    );

    let mut chall1: Box<GenericArray<u8, O::CHALL1>> = GenericArray::default_boxed();
    let mut h2_hasher = RO::<P>::h2_init();
    h2_hasher.update(&mu);
    h2_hasher.update(&hcom);
    let c = &sigma[..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)];

    h2_hasher.update(c);
    h2_hasher.update(iv);
    let mut reader = h2_hasher.finish();
    reader.read(&mut chall1);

    let vole_hasher = O::VoleHasher::new_vole_hasher(&chall1);
    let def = GenericArray::default();
    let def2 = GenericArray::default();
    let mut gq: Box<
        GenericArray<Vec<GenericArray<u8, <P as PARAM>::LH>>, <P::Tau as TauParameters>::Tau>,
    > = GenericArray::default_boxed();
    let mut gd_t: Box<GenericArray<Vec<&GenericArray<u8, O::LAMBDAPLUS2>>, O::LAMBDALBYTES>> =
        GenericArray::default_boxed();
    gq[0] = gq_p[0].clone();
    let delta0 = P::Tau::decode_challenge(chall3, 0);
    let u_t = &sigma[O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
        ..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
            + O::LAMBDABYTES::USIZE
            + 2];
    gd_t[0] = delta0
        .iter()
        .map(|d| {
            if *d == 1 {
                GenericArray::from_slice(u_t)
            } else {
                &def
            }
        })
        .collect();
    for i in 1..<P::Tau as TauParameters>::Tau::USIZE {
        /* ok */
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
            .collect::<Vec<_>>();
        gq[i] = gq_p[i]
            .iter()
            .zip(delta.iter().map(|d| {
                if *d == 1 {
                    GenericArray::<u8, P::LH>::from_slice(
                        &c[O::LHATBYTES::USIZE * (i - 1)..O::LHATBYTES::USIZE * i],
                    )
                } else {
                    &def2
                }
            }))
            .map(|(q, d)| {
                zip(q, d)
                    .map(|(q, d)| (q ^ d))
                    .collect::<GenericArray<u8, P::LH>>()
            })
            .collect::<Vec<GenericArray<u8, <P as PARAM>::LH>>>();
    }
    let gq_t = gq
        .iter()
        .flat_map(|q| q.iter().map(|q| vole_hasher.process(q)));

    let mut h1_hasher = RO::<P>::h1_init();
    zip(gq_t, gd_t.into_iter().flatten())
        .flat_map(|(q, d)| zip(q, d).map(|(q, d)| q ^ d))
        .for_each(|v| h1_hasher.update(&[v]));
    let mut hv: GenericArray<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
        GenericArray::default();
    h1_hasher.finish().read(&mut hv);

    let d = &sigma[O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
        + O::LAMBDABYTES::USIZE
        + 2
        ..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
            + O::LAMBDABYTES::USIZE
            + 2
            + O::LBYTES::USIZE];
    let mut chall2 = GenericArray::<u8, O::CHALL>::default();
    hash_challange_2::<RO<P>>(&mut chall2, &chall1, u_t, &hv, d);

    let a_t = &sigma[O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
        + O::LAMBDABYTES::USIZE
        + 2
        + O::LBYTES::USIZE
        ..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
            + 2 * O::LAMBDABYTES::USIZE
            + 2
            + O::LBYTES::USIZE];
    let b_t = P::Cypher::verify::<P::Tau>(
        GenericArray::from_slice(d),
        Box::<GenericArray<_, _>>::from_iter(gq.iter().flat_map(|x| {
            x.iter()
                .map(|y| {
                    y.into_iter()
                        .take(O::LBYTES::USIZE + O::LAMBDABYTES::USIZE)
                        .copied()
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
    hash_challenge_3::<RO<P>>(&mut chall3_p, &chall2, a_t, &b_t);
    *chall3 == chall3_p
}

fn sigma_to_signature<'a, Lambda>(
    c: impl Iterator<Item = &'a [u8]>,
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
    c.for_each(|x| {
        signature.write_all(x).unwrap();
    });
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
mod test {
    use super::*;

    use generic_array::GenericArray;
    use nist_pqc_seeded_rng::NistPqcAes256CtrRng;
    use rand::RngCore;

    use crate::parameter::{
        PARAM, PARAM128F, PARAM128FEM, PARAM128S, PARAM128SEM, PARAM192F, PARAM192FEM, PARAM192S,
        PARAM192SEM, PARAM256F, PARAM256FEM, PARAM256S, PARAM256SEM, PARAMOWF,
    };

    const RUNS: usize = 10;

    fn random_message(mut rng: impl RngCore) -> Vec<u8> {
        let mut length = [0];
        while length[0] == 0 {
            rng.fill_bytes(&mut length);
        }
        let mut ret = vec![0; length[0] as usize];
        rng.fill_bytes(&mut ret);
        ret
    }

    fn run_faest_test<P: PARAM>() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let sk = P::Cypher::keygen_with_rng(&mut rng);
            let msg = random_message(&mut rng);
            let mut sigma = GenericArray::default_boxed();
            faest_sign::<P, P::OWF>(&msg, &sk, &[], &mut sigma);
            let pk = sk.as_public_key();
            let res_true = faest_verify::<P, P::OWF>(&msg, &pk, &sigma);
            assert!(res_true);
        }
    }

    #[test]
    fn faest_aes_test_128f() {
        run_faest_test::<PARAM128F>();
    }

    #[test]
    fn faest_aes_test_128s() {
        run_faest_test::<PARAM128S>();
    }

    #[test]
    fn faest_aes_test_192f() {
        run_faest_test::<PARAM192F>();
    }

    #[test]
    fn faest_aes_test_192s() {
        run_faest_test::<PARAM192S>();
    }

    #[test]
    fn faest_aes_test_256s() {
        run_faest_test::<PARAM256S>();
    }

    #[test]
    fn faest_aes_test_256f() {
        run_faest_test::<PARAM256F>();
    }

    #[test]
    fn faest_em_test_128s() {
        run_faest_test::<PARAM128SEM>();
    }

    #[test]
    fn faest_em_test_128f() {
        run_faest_test::<PARAM128FEM>();
    }

    #[test]
    fn faest_em_test_192f() {
        run_faest_test::<PARAM192FEM>();
    }

    #[test]
    fn faest_em_test_192s() {
        run_faest_test::<PARAM192SEM>();
    }

    #[test]
    fn faest_em_test_256s() {
        run_faest_test::<PARAM256SEM>();
    }

    #[test]
    fn faest_em_test_256f() {
        run_faest_test::<PARAM256FEM>();
    }

    ///NIST tests
    #[derive(Default, Clone)]
    struct TestVector {
        seed: Vec<u8>,
        message: Vec<u8>,
        pk: Vec<u8>,
        sk: Vec<u8>,
        sm: Vec<u8>,
    }

    fn parse_hex(value: &str) -> Vec<u8> {
        hex::decode(value).expect("hex value")
    }

    fn read_kats(kats: &str) -> Vec<TestVector> {
        let mut ret = Vec::new();

        let mut kat = TestVector::default();
        for line in kats.lines() {
            // skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (kind, value) = line.split_once(" = ").expect("kind = value");
            match kind {
                // ignore count, message and signature lenghts, and seed
                "count" | "mlen" | "smlen" => {}
                "seed" => {
                    kat.seed = parse_hex(value);
                }
                "sk" => {
                    kat.sk = parse_hex(value);
                }
                "pk" => {
                    kat.pk = parse_hex(value);
                }
                "msg" => {
                    kat.message = parse_hex(value);
                }
                "sm" => {
                    kat.sm = parse_hex(value);
                    assert!(
                        !kat.sk.is_empty()
                            && !kat.pk.is_empty()
                            && !kat.message.is_empty()
                            && !kat.sm.is_empty()
                    );
                    ret.push(kat);
                    kat = TestVector::default();
                }
                _ => {
                    unreachable!("unknown kind");
                }
            }
        }
        ret
    }

    fn test_nist<P: PARAM>(test_data: &str) {
        let datas = read_kats(test_data);
        for data in datas {
            let mut rng = NistPqcAes256CtrRng::try_from(data.seed.as_slice()).unwrap();
            let msg = data.message;
            let sig = data.sm;

            let sk = P::Cypher::keygen_with_rng(&mut rng);
            let pk = sk.as_public_key();
            assert_eq!(data.pk.as_slice(), pk.as_bytes().as_slice());
            assert_eq!(data.sk.as_slice(), sk.as_bytes().as_slice());

            let mut rho = GenericArray::<u8, <P::OWF as PARAMOWF>::LAMBDABYTES>::default();
            rng.fill_bytes(&mut rho);

            let mut signature = GenericArray::default_boxed();
            faest_sign::<P, P::OWF>(&msg, &sk, &rho, &mut signature);
            assert_eq!(&sig[..sig.len() - signature.len()], &msg);
            assert_eq!(&sig[sig.len() - signature.len()..], signature.as_slice());
            assert!(faest_verify::<P, P::OWF>(&msg, &pk, &signature));
        }
    }

    #[test]
    fn test_nist_faest_128s_aes() {
        test_nist::<PARAM128S>(include_str!("../tests/data/PQCsignKAT_faest_128s.rsp"));
    }

    #[test]
    fn test_nist_faest_128f_aes() {
        test_nist::<PARAM128F>(include_str!("../tests/data/PQCsignKAT_faest_128f.rsp"));
    }

    #[test]
    fn test_nist_faest_192s_aes() {
        test_nist::<PARAM192S>(include_str!("../tests/data/PQCsignKAT_faest_192s.rsp"));
    }

    #[test]
    fn test_nist_faest_192f_aes() {
        test_nist::<PARAM192F>(include_str!("../tests/data/PQCsignKAT_faest_192f.rsp"));
    }

    #[test]
    fn test_nist_faest_256s_aes() {
        test_nist::<PARAM256S>(include_str!("../tests/data/PQCsignKAT_faest_256s.rsp"));
    }

    #[test]
    fn test_nist_faest_256f_aes() {
        test_nist::<PARAM256F>(include_str!("../tests/data/PQCsignKAT_faest_256f.rsp"));
    }

    #[test]
    fn test_nist_faest_128s_em() {
        test_nist::<PARAM128SEM>(include_str!("../tests/data/PQCsignKAT_faest_em_128s.rsp"));
    }

    #[test]
    fn test_nist_faest_128f_em() {
        test_nist::<PARAM128FEM>(include_str!("../tests/data/PQCsignKAT_faest_em_128f.rsp"));
    }

    #[test]
    fn test_nist_faest_192s_em() {
        test_nist::<PARAM192SEM>(include_str!("../tests/data/PQCsignKAT_faest_em_192s.rsp"));
    }

    #[test]
    fn test_nist_faest192f_em() {
        test_nist::<PARAM192FEM>(include_str!("../tests/data/PQCsignKAT_faest_em_192f.rsp"));
    }

    #[test]
    fn test_nist_faest_256s_em() {
        test_nist::<PARAM256SEM>(include_str!("../tests/data/PQCsignKAT_faest_em_256s.rsp"));
    }

    #[test]
    fn test_nist_faest_256f_em() {
        test_nist::<PARAM256FEM>(include_str!("../tests/data/PQCsignKAT_faest_em_256f.rsp"));
    }
}
