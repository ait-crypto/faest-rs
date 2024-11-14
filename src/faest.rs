use std::{io::Write, iter::zip};

use crate::{
    internal_keys::{PublicKey, SecretKey},
    parameter::{BaseParameters, FAESTParameters, OWFParameters, TauParameters},
    prg::{IVSize, IV},
    random_oracles::{Hasher, RandomOracle},
    universal_hashing::{VoleHasherInit, VoleHasherProcess},
    utils::Reader,
    vc::VectorCommitment,
    vole::{volecommit, volereconstruct, VoleCommitmentCRef},
    Error,
};

use generic_array::{typenum::Unsigned, GenericArray};
use itertools::izip;
use rand_core::CryptoRngCore;

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

#[inline]
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
    let (signature, iv) = signature.split_at_mut(P::SignatureSize::USIZE - IVSize::USIZE);
    let iv = GenericArray::from_mut_slice(iv);
    RO::<P>::hash_r_iv(&mut r, iv, &sk.owf_key, &mu, rho);

    let (volecommit_cs, signature) =
        signature.split_at_mut(O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1));
    let (hcom, decom, u, gv) = volecommit::<
        <O::BaseParams as BaseParameters>::VC,
        P::Tau,
        O::LHATBYTES,
    >(VoleCommitmentCRef::new(volecommit_cs), &r, iv);
    let mut chall1 =
        GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall1>::default();
    RO::<P>::hash_challenge_1(&mut chall1, &mu, &hcom, volecommit_cs, iv);

    let (signature, u_t, hv) = {
        let vole_hasher = VoleHasher::<P>::new_vole_hasher(&chall1);
        let u_t = vole_hasher.process(&u);

        // write u_t to signature
        let (u_t_d, signature) = signature.split_at_mut(u_t.len());
        u_t_d.copy_from_slice(u_t.as_slice());

        let mut h1_hasher = RO::<P>::h1_init();
        for v in gv.iter() {
            h1_hasher.update(&vole_hasher.process(v));
        }

        let hv: GenericArray<_, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
            h1_hasher.finish().read_into();
        (signature, u_t_d, hv)
    };

    let w = P::OWF::witness(&sk.owf_key, &sk.pk.owf_input);
    // compute and write d to signature
    let (d, signature) = signature.split_at_mut(O::LBYTES::USIZE);
    for (dj, wj, uj) in izip!(d.iter_mut(), w.iter(), &u[..O::LBYTES::USIZE]) {
        *dj = wj ^ *uj;
    }

    let mut chall2 =
        GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>::default();
    RO::<P>::hash_challenge_2(&mut chall2, &chall1, u_t, &hv, d);

    // FIXME: this is only re-shapping gv
    let gv = Box::<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>::from_iter(
        gv.into_iter()
            .map(|x| GenericArray::from_slice(&x[..O::LAMBDALBYTES::USIZE]).clone()),
    );

    let (a_t, b_t) = P::OWF::prove(
        &w,
        GenericArray::from_slice(&u[..O::LBYTES::USIZE + O::LAMBDABYTES::USIZE]),
        &gv,
        &sk.pk.owf_input,
        &sk.pk.owf_output,
        &chall2,
    );

    let mut chall3 = GenericArray::<u8, O::LAMBDABYTES>::default();
    RO::<P>::hash_challenge_3(&mut chall3, &chall2, &a_t, &b_t);

    sigma_to_signature(
        &a_t,
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
        signature,
    );
}

fn sigma_to_signature<'a>(
    a_t: &[u8],
    pdecom: impl Iterator<Item = (Vec<&'a [u8]>, &'a [u8])>,
    chall3: &[u8],
    mut signature: &mut [u8],
) {
    signature.write_all(a_t).unwrap();
    pdecom.for_each(|x| {
        x.0.iter().for_each(|v| {
            signature.write_all(v).unwrap();
        });
        signature.write_all(x.1).unwrap();
    });
    signature.write_all(chall3).unwrap();
}

#[inline]
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
        &sigma[P::SignatureSize::USIZE - (IVSize::USIZE + O::LAMBDABYTES::USIZE)
            ..P::SignatureSize::USIZE - IVSize::USIZE],
    );
    let iv = IV::from_slice(&sigma[P::SignatureSize::USIZE - IVSize::USIZE..]);

    let mut mu: GenericArray<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
        GenericArray::default();
    RO::<P>::hash_mu(&mut mu, &pk.owf_input, &pk.owf_output, msg);

    let (hcom, mut gq) =
        volereconstruct::<<O::BaseParams as BaseParameters>::VC, P::Tau, O::LHATBYTES>(
            chall3,
            &sigma[(O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1))
                + (2 * O::LAMBDABYTES::USIZE)
                + O::LBYTES::USIZE
                + 2..P::SignatureSize::USIZE - (16 + O::LAMBDABYTES::USIZE)],
            iv,
        );

    let mut chall1 =
        GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall1>::default();
    let c = &sigma[..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)];
    RO::<P>::hash_challenge_1(&mut chall1, &mu, &hcom, c, iv);

    for (i, c_chunk) in c.chunks(O::LHATBYTES::USIZE).enumerate() {
        let (index, size) = <P::Tau as TauParameters>::convert_index_and_size(i + 1);
        for gq_i in zip(
            &mut gq[index..index + size],
            P::Tau::decode_challenge_as_iter(chall3, i + 1),
        )
        .filter_map(|(gq_i, d)| if d == 1 { Some(gq_i) } else { None })
        {
            for (t, r) in izip!(gq_i, c_chunk) {
                *t ^= r;
            }
        }
    }

    let u_t = &sigma[O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
        ..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
            + O::LAMBDABYTES::USIZE
            + 2];
    let mut h1_hasher = RO::<P>::h1_init();
    {
        let vole_hasher = VoleHasher::<P>::new_vole_hasher(&chall1);
        for (q, d) in zip(
            gq.iter(),
            (0..<P::Tau as TauParameters>::Tau::USIZE)
                .flat_map(|i| P::Tau::decode_challenge_as_iter(chall3, i)),
        ) {
            let mut q = vole_hasher.process(q);
            if d == 1 {
                for (qi, d) in zip(q.iter_mut(), u_t) {
                    *qi ^= d;
                }
            }
            h1_hasher.update(&q);
        }
    }
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
        Box::<GenericArray<_, _>>::from_iter(
            gq.into_iter()
                .map(|x| GenericArray::from_slice(&x[..O::LAMBDALBYTES::USIZE]).clone()),
        ),
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

#[cfg(test)]
#[generic_tests::define]
mod test {
    use super::*;

    use generic_array::GenericArray;
    use rand::RngCore;
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};

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
