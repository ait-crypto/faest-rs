use std::{io::Write, iter::zip};

use crate::{
    bavc::{BatchVectorCommitment, BavcOpenResult, BAVC},
    fields::Field,
    internal_keys::{PublicKey, SecretKey},
    parameter::{BaseParameters, FAESTParameters, OWFParameters, TauParameters},
    prg::{IVSize, PseudoRandomGenerator, IV},
    random_oracles::{Hasher, RandomOracle},
    universal_hashing::{VoleHasherInit, VoleHasherProcess},
    utils::{decode_all_chall_3, Reader},
    vole::{volecommit, volereconstruct, VoleCommitResult, VoleCommitmentCRef},
    zk_constraints::OWFField,
    Error,
};

use generic_array::{typenum::Unsigned, GenericArray};
use itertools::izip;
use rand_core::CryptoRngCore;
use signature::SignerMut;

type RO<P> =
    <<<P as FAESTParameters>::OWF as OWFParameters>::BaseParams as BaseParameters>::RandomOracle;
type VoleHasher<P> =
    <<<P as FAESTParameters>::OWF as OWFParameters>::BaseParams as BaseParameters>::VoleHasher;

/// Hashes required for FAEST implementation
trait FaestHash {
    /// Generate `µ`
    fn hash_mu(mu: &mut [u8], input: &[u8], output: &[u8], msg: &[u8]);
    /// Generate `r` and `iv_pre`
    fn hash_r_iv(r: &mut [u8], iv: &mut IV, key: &[u8], mu: &[u8], rho: &[u8]);
    /// Generate `iv`
    fn hash_iv(iv_pre: &mut IV);
    /// Generate first challange
    fn hash_challenge_1(chall1: &mut [u8], mu: &[u8], hcom: &[u8], c: &[u8], iv: &[u8]);
    /// Generate second challenge
    fn hash_challenge_2(chall2: &mut [u8], chall1: &[u8], u_t: &[u8], hv: &[u8], d: &[u8]);
    /// Generate third challenge
    fn hash_challenge_3(
        chall3: &mut [u8],
        chall2: &[u8],
        a0_t: &[u8],
        a1_t: &[u8],
        a2_t: &[u8],
        ctr: u32,
    );
}

impl<RO> FaestHash for RO
where
    RO: RandomOracle,
{
    fn hash_mu(mu: &mut [u8], input: &[u8], output: &[u8], msg: &[u8]) {
        // Step 3
        let mut h2_hasher = Self::h2_0_init();
        h2_hasher.update(input);
        h2_hasher.update(output);
        h2_hasher.update(msg);
        h2_hasher.finish().read(mu);
    }

    fn hash_r_iv(r: &mut [u8], iv: &mut IV, key: &[u8], mu: &[u8], rho: &[u8]) {
        // Step 4
        let mut h3_hasher = Self::h3_init();
        h3_hasher.update(key);
        h3_hasher.update(mu);
        h3_hasher.update(rho);

        let mut h3_reader = h3_hasher.finish();
        h3_reader.read(r);
        h3_reader.read(iv);
    }

    fn hash_iv(iv_pre: &mut IV) {
        // Step 5
        let mut h4_hasher = Self::h4_init();
        h4_hasher.update(&iv_pre);

        let h4_reader = h4_hasher.finish();
        *iv_pre = h4_reader.read_into();
    }

    fn hash_challenge_1(chall1: &mut [u8], mu: &[u8], hcom: &[u8], c: &[u8], iv: &[u8]) {
        let mut h2_hasher = Self::h2_1_init();
        h2_hasher.update(mu);
        h2_hasher.update(hcom);
        h2_hasher.update(c);
        h2_hasher.update(iv);
        h2_hasher.finish().read(chall1);
    }

    fn hash_challenge_2(chall2: &mut [u8], chall1: &[u8], u_t: &[u8], hv: &[u8], d: &[u8]) {
        let mut h2_hasher = Self::h2_2_init();
        h2_hasher.update(chall1);
        h2_hasher.update(u_t);
        h2_hasher.update(hv);
        h2_hasher.update(d);
        h2_hasher.finish().read(chall2);
    }

    fn hash_challenge_3(
        chall3: &mut [u8],
        chall2: &[u8],
        a0_t: &[u8],
        a1_t: &[u8],
        a2_t: &[u8],
        ctr: u32,
    ) {
        let mut h2_hasher = Self::h2_3_init();
        h2_hasher.update(chall2);
        h2_hasher.update(a0_t);
        h2_hasher.update(a1_t);
        h2_hasher.update(a2_t);
        h2_hasher.update(&ctr.to_le_bytes());
        h2_hasher.finish().read(chall3);
    }
}

// #[inline]
// pub(crate) fn faest_keygen<O, R>(rng: R) -> SecretKey<O>
// where
//     O: OWFParameters,
//     R: CryptoRngCore,
// {
//     O::keygen_with_rng(rng)
// }

// #[inline]
// pub(crate) fn faest_sign<P>(
//     msg: &[u8],
//     sk: &SecretKey<P::OWF>,
//     rho: &[u8],
//     signature: &mut GenericArray<u8, P::SignatureSize>,
// ) where
//     P: FAESTParameters,
// {
//     sign::<P, P::OWF>(msg, sk, rho, signature);
// }

fn transpose_matrix(m: &[&[u8]]) -> Vec<u8> {
    let mut m_trans = vec![vec![]; m[0].len()];
    for i in 0..m[0].len() {
        for j in 0..m.len() {
            m_trans[i].push(m[j][i]);
        }
    }
    m_trans.into_iter().flatten().collect()
}

fn check_challenge_3<O>(chall3: &[u8], w_grind: usize) -> bool
where
    O: OWFParameters,
{
    for i in O::LAMBDA::USIZE - w_grind..O::LAMBDA::USIZE {
        if (chall3[i / 8] >> (i % 8)) & 1 != 0 {
            return false;
        }
    }

    true
}

#[allow(unused)]
fn sign<P, O>(
    msg: &[u8],
    sk: &SecretKey<O>,
    rho: &[u8],
    signature: &mut GenericArray<u8, P::SignatureSize>,
) where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    // Step 3
    let mut mu =
        GenericArray::<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2>::default();
    RO::<P>::hash_mu(&mut mu, &sk.pk.owf_input, &sk.pk.owf_output, msg);

    // Step 4
    let mut r = GenericArray::<u8, O::LAMBDABYTES>::default();
    let (signature, ctr_s) = signature.split_at_mut(P::SignatureSize::USIZE - size_of::<u32>());
    let (signature, iv) =
        signature.split_at_mut(P::SignatureSize::USIZE - size_of::<u32>() - IVSize::USIZE);
    let mut iv_pre = GenericArray::from_mut_slice(iv);
    RO::<P>::hash_r_iv(&mut r, iv_pre, &sk.owf_key, &mu, rho);

    // Step 5
    let mut iv = GenericArray::from_slice(iv_pre).to_owned();
    RO::<P>::hash_iv(&mut iv);

    //Step 7
    let (volecommit_cs, signature) =
        signature.split_at_mut(O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1));

    let VoleCommitResult {
        com,
        decom,
        u,
        mut v,
    } = volecommit::<P::BAVC, O::LHATBYTES>(VoleCommitmentCRef::new(volecommit_cs), &r, &iv);

    let mut chall1 =
        GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall1>::default();
    RO::<P>::hash_challenge_1(&mut chall1, &mu, &com, volecommit_cs, iv.as_slice());

    let mut h2_hasher = RO::<P>::h2_2_init();
    h2_hasher.update(chall1.as_slice());

    let (signature, u_t) = {
        // Step 10
        let mut vole_hasher_u = VoleHasher::<P>::new_vole_hasher(&chall1);
        let mut vole_haher_v = vole_hasher_u.clone();
        let u_t = vole_hasher_u.process(&u);

        // write u_t to signature
        let (u_t_d, signature) = signature.split_at_mut(u_t.len());
        u_t_d.copy_from_slice(u_t.as_slice());

        // Step 11
        h2_hasher.update(u_t.as_slice());
        let v = transpose_matrix(&v.iter().map(|row| row.as_slice()).collect::<Vec<&[u8]>>());
        let row_len = O::LHATBYTES::USIZE;
        for i in 0..O::LAMBDA::USIZE {
            let hv = vole_haher_v.process(&v[i * row_len..i * row_len + row_len]);
            h2_hasher.update(hv.as_slice());
        }
        (signature, u_t_d)
    };

    // Step 12
    // TODO: compute once and store in SecretKey
    let w = P::OWF::witness(sk);

    // Step 13
    // compute and write d to signature
    let (d, signature) = signature.split_at_mut(O::LBYTES::USIZE);
    for (mut dj, wj, uj) in izip!(d.iter_mut(), w.iter(), &u[..O::LBYTES::USIZE]) {
        *dj = wj ^ *uj;
    }
    h2_hasher.update(d);

    // Step 14
    let mut chall2 =
        GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>::default();
    h2_hasher.finish().read(&mut chall2);

    // RO::<P>::hash_challenge_2(&mut chall2, &chall1, u_t, &hv, d);

    let (a0_t, a1_t, a2_t) = P::OWF::prove(
        &w,
        GenericArray::from_slice(&u[O::LBYTES::USIZE..O::LBYTES::USIZE + O::LAMBDABYTESTWO::USIZE]),
        GenericArray::from_slice(&v[..O::LAMBDALBYTES::USIZE]),
        &sk.pk,
        &chall2,
    );

    let (a1, signature) = signature.split_at_mut(O::LAMBDABYTES::USIZE);
    let (a2, signature) = signature.split_at_mut(O::LAMBDABYTES::USIZE);
    a1.copy_from_slice(&a1_t.as_bytes());
    a2.copy_from_slice(&a2_t.as_bytes());

    // let mut chall3 = GenericArray::<_, O::LAMBDABYTES>::default();
    let mut ctr = 0;
    let mut valid = false;

    let decom_size_1 = O::NLeafCommit::USIZE
        * O::LAMBDABYTES::USIZE
        * <<P as FAESTParameters>::Tau as TauParameters>::Tau::USIZE;
    let decom_size = decom_size_1
        + <<P as FAESTParameters>::Tau as TauParameters>::Topen::USIZE * O::LAMBDABYTES::USIZE;
    let (decom_i, signature) = signature.split_at_mut(decom_size);
    let (chall3, signature) = signature.split_at_mut(O::LAMBDABYTES::USIZE);

    loop {
        RO::<P>::hash_challenge_3(chall3, &chall2, &a0_t.as_bytes(), a1, &a2, ctr);

        // ::23
        if !check_challenge_3::<O>(chall3, P::WGRIND::USIZE) {
            ctr += 1;
            continue;
        }

        let i_delta = decode_all_chall_3::<P::Tau>(&chall3);

        // ::27
        if let Some(BavcOpenResult { coms, nodes }) =
            <P as FAESTParameters>::BAVC::open(&decom, &i_delta)
        {
            decom_i[..decom_size_1].copy_from_slice(
                &coms
                    .into_iter()
                    .flat_map(|v| v.to_owned())
                    .collect::<Vec<_>>(),
            );
            let v2 = nodes
                .into_iter()
                .flat_map(|v| v.to_owned())
                .collect::<Vec<_>>();
            decom_i[decom_size_1..decom_size_1 + v2.len()].copy_from_slice(&v2);
            break;
        } else {
            ctr += 1;
            continue;
        }
    }

    ctr_s.copy_from_slice(&ctr.to_le_bytes());
}

// opening_to_signature(
//     (0..<P::Tau as TauParameters>::Tau::USIZE).map(|i| {
//         let s = P::Tau::decode_challenge(chall3, i);
//         if i < <P::Tau as TauParameters>::Tau0::USIZE {
//             <O::BaseParams as BaseParameters>::VC::open::<
//                 P::POWK0,
//                 <P::Tau as TauParameters>::K0,
//                 P::N0,
//             >(&decom[i], GenericArray::from_slice(&s))
//         } else {
//             <O::BaseParams as BaseParameters>::VC::open::<
//                 P::POWK1,
//                 <P::Tau as TauParameters>::K1,
//                 P::N1,
//             >(&decom[i], GenericArray::from_slice(&s))
//         }
//     }),
//     signature,
// );

fn opening_to_signature<'a>(
    pdecom: impl Iterator<Item = (Vec<&'a [u8]>, &'a [u8])>,
    mut signature: &mut [u8],
) {
    pdecom.for_each(|x| {
        x.0.iter().for_each(|v| {
            signature.write_all(v).unwrap();
        });
        signature.write_all(x.1).unwrap();
    });
}

// #[inline]
// pub(crate) fn faest_verify<P>(
//     msg: &[u8],
//     pk: &PublicKey<P::OWF>,
//     sigma: &GenericArray<u8, P::SignatureSize>,
// ) -> Result<(), Error>
// where
//     P: FAESTParameters,
// {
//     verify::<P, P::OWF>(msg, pk, sigma)
// }

// fn verify<P, O>(
//     msg: &[u8],
//     pk: &PublicKey<O>,
//     sigma: &GenericArray<u8, P::SignatureSize>,
// ) -> Result<(), Error>
// where
//     P: FAESTParameters<OWF = O>,
//     O: OWFParameters,
// {
//     let chall3 = GenericArray::from_slice(
//         &sigma[P::SignatureSize::USIZE - (IVSize::USIZE + O::LAMBDABYTES::USIZE)
//             ..P::SignatureSize::USIZE - IVSize::USIZE],
//     );
//     let iv = IV::from_slice(&sigma[P::SignatureSize::USIZE - IVSize::USIZE..]);

//     let mut mu: GenericArray<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
//         GenericArray::default();
//     RO::<P>::hash_mu(&mut mu, &pk.owf_input, &pk.owf_output, msg);

//     let (hcom, mut gq) =
//         volereconstruct::<<O::BaseParams as BaseParameters>::VC, P::Tau, O::LHATBYTES>(
//             chall3,
//             &sigma[(O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1))
//                 + (2 * O::LAMBDABYTES::USIZE)
//                 + O::LBYTES::USIZE
//                 + 2..P::SignatureSize::USIZE - (16 + O::LAMBDABYTES::USIZE)],
//             iv,
//         );

//     let mut chall1 =
//         GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall1>::default();
//     let c = &sigma[..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)];
//     RO::<P>::hash_challenge_1(&mut chall1, &mu, &hcom, c, iv);

//     for (i, c_chunk) in c.chunks(O::LHATBYTES::USIZE).enumerate() {
//         let (index, size) = <P::Tau as TauParameters>::convert_index_and_size(i + 1);
//         for gq_i in zip(
//             &mut gq[index..index + size],
//             P::Tau::decode_challenge_as_iter(chall3, i + 1),
//         )
//         .filter_map(|(gq_i, d)| if d == 1 { Some(gq_i) } else { None })
//         {
//             for (t, r) in izip!(gq_i, c_chunk) {
//                 *t ^= r;
//             }
//         }
//     }

//     let u_t = &sigma[O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
//         ..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
//             + O::LAMBDABYTES::USIZE
//             + 2];
//     let mut h1_hasher = RO::<P>::h1_init();
//     {
//         let vole_hasher = VoleHasher::<P>::new_vole_hasher(&chall1);
//         for (q, d) in zip(
//             gq.iter(),
//             (0..<P::Tau as TauParameters>::Tau::USIZE)
//                 .flat_map(|i| P::Tau::decode_challenge_as_iter(chall3, i)),
//         ) {
//             let mut q = vole_hasher.process(q);
//             if d == 1 {
//                 for (qi, d) in zip(q.iter_mut(), u_t) {
//                     *qi ^= d;
//                 }
//             }
//             h1_hasher.update(&q);
//         }
//     }
//     let hv: GenericArray<_, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
//         h1_hasher.finish().read_into();

//     let d = &sigma[O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
//         + O::LAMBDABYTES::USIZE
//         + 2
//         ..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
//             + O::LAMBDABYTES::USIZE
//             + 2
//             + O::LBYTES::USIZE];
//     let mut chall2 =
//         GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>::default();
//     RO::<P>::hash_challenge_2(&mut chall2, &chall1, u_t, &hv, d);

//     let a_t = &sigma[O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
//         + O::LAMBDABYTES::USIZE
//         + 2
//         + O::LBYTES::USIZE
//         ..O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1)
//             + 2 * O::LAMBDABYTES::USIZE
//             + 2
//             + O::LBYTES::USIZE];
//     let b_t = P::OWF::verify::<P::Tau>(
//         GenericArray::from_slice(d),
//         Box::<GenericArray<_, _>>::from_iter(
//             gq.into_iter()
//                 .map(|x| GenericArray::from_slice(&x[..O::LAMBDALBYTES::USIZE]).clone()),
//         ),
//         GenericArray::from_slice(a_t),
//         &chall2,
//         chall3,
//         pk,
//     );

//     let mut chall3_p = GenericArray::default();
//     RO::<P>::hash_challenge_3(&mut chall3_p, &chall2, a_t, &b_t);
//     if *chall3 == chall3_p {
//         Ok(())
//     } else {
//         Err(Error::new())
//     }
// }

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        parameter::{
            FAEST128fParameters, FAEST128sParameters, FAEST192fParameters, FAEST192sParameters,
            FAEST256fParameters, FAEST256sParameters, FAESTEM128fParameters, FAESTEM128sParameters,
            FAESTEM192fParameters, FAESTEM192sParameters, FAESTEM256fParameters,
            FAESTEM256sParameters, FAESTParameters, OWF128,
        },
        utils::test::hash_array,
    };

    #[test]
    fn sign_128s_test() {
        let msg = [
            0x54, 0x68, 0x69, 0x73, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x20,
            0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20,
            0x73, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x65, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x46, 0x41, 0x45, 0x53, 0x54, 0x20, 0x64, 0x69, 0x67, 0x69, 0x74, 0x61, 0x6c, 0x20,
            0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x67, 0x6f,
            0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e,
        ];

        let sk_bytes = [
            0xc1, 0xa3, 0xc0, 0x22, 0xe7, 0x18, 0x93, 0x5f, 0x46, 0x63, 0x03, 0x86, 0xaf, 0xa3,
            0xd3, 0xf2, 0xc0, 0x72, 0x0b, 0x10, 0xbf, 0x26, 0x6c, 0x19, 0x24, 0x18, 0x87, 0x72,
            0xc5, 0x1f, 0xbe, 0x52,
        ];

        let rho = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        let hashed_sig = [
            113, 174, 23, 230, 230, 128, 4, 161, 247, 71, 199, 153, 69, 241, 28, 169, 87, 176, 165,
            35, 117, 118, 50, 226, 193, 86, 182, 117, 26, 101, 165, 119, 90, 38, 21, 209, 48, 99,
            0, 144, 95, 216, 227, 245, 8, 215, 117, 211, 213, 91, 154, 4, 155, 238, 61, 64, 39,
            255, 183, 22, 225, 155, 164, 52,
        ];

        let sk = SecretKey::<OWF128>::try_from(sk_bytes.as_slice()).unwrap();

        let mut signature = GenericArray::default();
        sign::<FAEST128sParameters, OWF128>(&msg, &sk, &rho, &mut signature);

        assert_eq!(hashed_sig, hash_array(signature.as_slice()).as_slice());
    }
}

// #[cfg(test)]
// #[generic_tests::define]
// mod test {
//     use super::*;

//     use generic_array::GenericArray;
//     use rand::RngCore;
//     #[cfg(feature = "serde")]
//     use serde::{Deserialize, Serialize};

//     use crate::parameter::{
//         FAEST128fParameters, FAEST128sParameters, FAEST192fParameters, FAEST192sParameters,
//         FAEST256fParameters, FAEST256sParameters, FAESTEM128fParameters, FAESTEM128sParameters,
//         FAESTEM192fParameters, FAESTEM192sParameters, FAESTEM256fParameters, FAESTEM256sParameters,
//         FAESTParameters,
//     };

//     const RUNS: usize = 3;

//     fn random_message(mut rng: impl RngCore) -> Vec<u8> {
//         let mut length = [0];
//         while length[0] == 0 {
//             rng.fill_bytes(&mut length);
//         }
//         let mut ret = vec![0; length[0] as usize];
//         rng.fill_bytes(&mut ret);
//         ret
//     }

//     #[test]
//     fn sign_and_verify<P: FAESTParameters>() {
//         let mut rng = rand::thread_rng();
//         for _i in 0..RUNS {
//             let sk = P::OWF::keygen_with_rng(&mut rng);
//             let msg = random_message(&mut rng);
//             let mut sigma = GenericArray::default_boxed();
//             faest_sign::<P>(&msg, &sk, &[], &mut sigma);
//             let pk = sk.as_public_key();
//             let res = faest_verify::<P>(&msg, &pk, &sigma);
//             assert!(res.is_ok());
//         }
//     }

//     #[cfg(feature = "serde")]
//     #[test]
//     fn serialize<P: FAESTParameters>() {
//         let mut rng = rand::thread_rng();
//         let sk = P::OWF::keygen_with_rng(&mut rng);

//         let mut out = vec![];
//         let mut ser = serde_json::Serializer::new(&mut out);

//         sk.serialize(&mut ser).expect("serialize key pair");
//         let serialized = String::from_utf8(out).expect("serialize to string");

//         let mut de = serde_json::Deserializer::from_str(&serialized);
//         let sk2 = SecretKey::<P::OWF>::deserialize(&mut de).expect("deserialize secret key");
//         assert_eq!(sk, sk2);

//         let pk = sk.as_public_key();
//         let mut out = vec![];
//         let mut ser = serde_json::Serializer::new(&mut out);

//         pk.serialize(&mut ser).expect("serialize key pair");
//         let serialized = String::from_utf8(out).expect("serialize to string");

//         let mut de = serde_json::Deserializer::from_str(&serialized);
//         let pk2 = PublicKey::<P::OWF>::deserialize(&mut de).expect("deserialize public key");
//         assert_eq!(pk, pk2);
//     }

//     #[instantiate_tests(<FAEST128fParameters>)]
//     mod faest_128f {}

//     #[instantiate_tests(<FAEST128sParameters>)]
//     mod faest_128s {}

//     #[instantiate_tests(<FAEST192fParameters>)]
//     mod faest_192f {}

//     #[instantiate_tests(<FAEST192sParameters>)]
//     mod faest_192s {}

//     #[instantiate_tests(<FAEST256fParameters>)]
//     mod faest_256f {}

//     #[instantiate_tests(<FAEST256sParameters>)]
//     mod faest_256s {}

//     #[instantiate_tests(<FAESTEM128fParameters>)]
//     mod faest_em_128f {}

//     #[instantiate_tests(<FAESTEM128sParameters>)]
//     mod faest_em_128s {}

//     #[instantiate_tests(<FAESTEM192fParameters>)]
//     mod faest_em_192f {}

//     #[instantiate_tests(<FAESTEM192sParameters>)]
//     mod faest_em_192s {}

//     #[instantiate_tests(<FAESTEM256fParameters>)]
//     mod faest_em_256f {}

//     #[instantiate_tests(<FAESTEM256sParameters>)]
//     mod faest_em_256s {}
// }
