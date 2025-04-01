use std::{io::Write, iter::zip};

use crate::{
    bavc::{BatchVectorCommitment, BavcDecommitment, BavcOpenResult, BAVC},
    fields::Field,
    internal_keys::{PublicKey, SecretKey},
    parameter::{BaseParameters, FAESTParameters, OWFParameters, TauParameters, OWFField},
    prg::{IVSize, PseudoRandomGenerator, IV},
    random_oracles::{Hasher, RandomOracle},
    universal_hashing::{VoleHasherInit, VoleHasherProcess},
    utils::{decode_all_chall_3, Reader},
    vole::{volecommit, volereconstruct, VoleCommitResult, VoleCommitmentCRef},
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
trait FaestHash: RandomOracle {
    /// Generate `µ`
    fn hash_mu(mu: &mut [u8], input: &[u8], output: &[u8], msg: &[u8]);
    /// Generate `r` and `iv_pre`
    fn hash_r_iv(r: &mut [u8], iv: &mut IV, key: &[u8], mu: &[u8], rho: &[u8]);
    /// Generate `iv`
    fn hash_iv(iv_pre: &mut IV);
    /// Generate first challange
    fn hash_challenge_1(chall1: &mut [u8], mu: &[u8], hcom: &[u8], c: &[u8], iv: &[u8]);
    /// Generate second challenge in an init-update-finalize style
    fn hash_challenge_2_init(chall1: &[u8], u_t: &[u8]) -> <Self as RandomOracle>::Hasher<10>;
    fn hash_challenge_2_update(hasher: &mut <Self as RandomOracle>::Hasher<10>, v_row: &[u8]);
    fn hash_challenge_2_finalize(
        hasher: <Self as RandomOracle>::Hasher<10>,
        chall2: &mut [u8],
        d: &[u8],
    );
    /// Generate third challenge in an init-finalize style
    fn hash_challenge_3_init(
        chall2: &[u8],
        a0_t: &[u8],
        a1_t: &[u8],
        a2_t: &[u8],
    ) -> <Self as RandomOracle>::Hasher<11>;
    fn hash_challenge_3_finalize(
        hasher: &<Self as RandomOracle>::Hasher<11>,
        chall3: &mut [u8],
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

    fn hash_challenge_2_init(chall1: &[u8], u_t: &[u8]) -> Self::Hasher<10> {
        let mut h2_hasher = Self::h2_2_init();
        h2_hasher.update(chall1);
        h2_hasher.update(u_t);
        h2_hasher
    }

    fn hash_challenge_2_update(hasher: &mut <Self as RandomOracle>::Hasher<10>, v_col: &[u8]) {
        hasher.update(v_col);
    }
    fn hash_challenge_2_finalize(
        mut hasher: <Self as RandomOracle>::Hasher<10>,
        chall2: &mut [u8],
        d: &[u8],
    ) {
        hasher.update(d);
        hasher.finish().read(chall2);
    }

    fn hash_challenge_3_init(
        chall2: &[u8],
        a0_t: &[u8],
        a1_t: &[u8],
        a2_t: &[u8],
    ) -> <Self as RandomOracle>::Hasher<11> {
        let mut h2_hasher = Self::h2_3_init();
        h2_hasher.update(chall2);
        h2_hasher.update(a0_t);
        h2_hasher.update(a1_t);
        h2_hasher.update(a2_t);
        h2_hasher
    }

    fn hash_challenge_3_finalize(
        hasher: &<Self as RandomOracle>::Hasher<11>,
        chall3: &mut [u8],
        ctr: u32,
    ) {
        let mut hasher = (*hasher).clone();
        hasher.update(&ctr.to_le_bytes());
        hasher.finish().read(chall3);
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

fn get_column<O>(
    m: &GenericArray<GenericArray<u8, O::LAMBDA>, O::LHATBYTES>,
    column: usize,
) -> Vec<u8>
where
    O: OWFParameters,
{
    (0..m.len()).map(|row| m[row][column]).collect()
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

fn save_decom_and_ctr(
    decom_sig: &mut [u8],
    ctr_sig: &mut [u8],
    decom_i: &BavcOpenResult,
    ctr: u32,
) {
    let BavcOpenResult { coms, nodes } = decom_i;

    // Save decom_i
    let mut offset = 0;
    for slice in coms.into_iter().chain(nodes.into_iter()) {
        decom_sig[offset..offset + slice.len()].copy_from_slice(slice);
        offset += slice.len();
    }

    // Save ctr
    ctr_sig.copy_from_slice(&ctr.to_le_bytes());
}

fn save_zk_constraints<'a>(
    signature: &'a mut [u8],
    a1_tilde: &[u8],
    a2_tilde: &[u8],
) -> &'a mut [u8] {
    let (a1, signature) = signature.split_at_mut(a1_tilde.len());
    let (a2, signature) = signature.split_at_mut(a2_tilde.len());

    a1.copy_from_slice(a1_tilde);
    a2.copy_from_slice(a2_tilde);

    signature
}

fn mask_witness<'a>(d: &'a mut [u8], w: &[u8], u: &[u8]) {
    for (dj, wj, uj) in izip!(d, w, u) {
        *dj = wj ^ *uj;
    }
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
    // ::1
    let (signature, ctr_s) = signature.split_at_mut(P::SignatureSize::USIZE - size_of::<u32>());

    // ::3
    let mut mu =
        GenericArray::<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2>::default();
    RO::<P>::hash_mu(&mut mu, &sk.pk.owf_input, &sk.pk.owf_output, msg);

    // ::4
    let mut r = GenericArray::<u8, O::LAMBDABYTES>::default();
    let (signature, iv) = signature.split_at_mut(signature.len() - IVSize::USIZE);
    let mut iv_pre = GenericArray::from_mut_slice(iv);
    RO::<P>::hash_r_iv(&mut r, iv_pre, &sk.owf_key, &mu, rho);

    // ::5
    let mut iv = GenericArray::from_slice(iv_pre).to_owned();
    RO::<P>::hash_iv(&mut iv);

    // ::7
    let (volecommit_cs, signature) =
        signature.split_at_mut(O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1));
    let VoleCommitResult {
        com,
        decom,
        u,
        mut v,
    } = volecommit::<P::BAVC, O::LHATBYTES>(VoleCommitmentCRef::new(volecommit_cs), &r, &iv);

    // ::8
    let mut chall1 =
        GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall1>::default();
    //Contrarly to specification, faest-ref uses iv instead of iv_pre
    RO::<P>::hash_challenge_1(&mut chall1, &mu, &com, volecommit_cs, iv.as_slice());

    // ::10
    let mut vole_hasher_u = VoleHasher::<P>::new_vole_hasher(&chall1);
    let mut vole_haher_v = vole_hasher_u.clone();
    // write u_t to signature
    let (u_t, signature) = signature.split_at_mut(
        <<O as OWFParameters>::BaseParams as BaseParameters>::VoleHasherOutputLength::USIZE,
    );
    u_t.copy_from_slice(vole_hasher_u.process(&u).as_slice());

    // ::11
    let mut h2_hasher = RO::<P>::hash_challenge_2_init(&chall1.as_slice(), u_t);
    {
        let row_len = O::LHATBYTES::USIZE;
        for i in 0..O::LAMBDA::USIZE {
            // Hash column-wise
            let v_col = get_column::<O>(&v, i);
            RO::<P>::hash_challenge_2_update(
                &mut h2_hasher,
                vole_haher_v.process(&v_col).as_slice(),
            );
        }
    }

    // ::12
    // TODO: compute once and store in SecretKey
    let w = P::OWF::witness(sk);

    // ::13
    // compute and write masked witness 'd' in signature
    let (d, signature) = signature.split_at_mut(O::LBYTES::USIZE);
    mask_witness(d, &w, &u[..<O as OWFParameters>::LBYTES::USIZE]);

    // ::14
    let mut chall2 =
        GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>::default();
    RO::<P>::hash_challenge_2_finalize(h2_hasher, &mut chall2, d);

    // Free space
    (d);

    // ::18
    let (a0_tilde, a1_tilde, a2_tilde) = P::OWF::prove(
        &w,
        // ::16
        GenericArray::from_slice(&u[O::LBYTES::USIZE..O::LBYTES::USIZE + O::LAMBDABYTESTWO::USIZE]),
        // ::17
        GenericArray::from_slice(&v[..O::LAMBDALBYTES::USIZE]),
        &sk.pk,
        &chall2,
    );
    // Save a1_tilde, a2_tilde in signature
    let signature = save_zk_constraints(signature, &a1_tilde.as_bytes(), &a2_tilde.as_bytes());

    // ::19
    let (decom_i_sig, chall3) = signature.split_at_mut(P::get_decom_size());
    let hasher = RO::<P>::hash_challenge_3_init(
        &chall2,
        &a0_tilde.as_bytes(),
        &a1_tilde.as_bytes(),
        &a2_tilde.as_bytes(),
    );
    for ctr in 0u32.. {
        // ::20
        RO::<P>::hash_challenge_3_finalize(&hasher, chall3, ctr);
        // ::21
        if check_challenge_3::<O>(chall3, P::WGRIND::USIZE) {
            // ::24
            let i_delta = decode_all_chall_3::<P::Tau>(&chall3);

            // ::26
            if let Some(decom_i) = <P as FAESTParameters>::BAVC::open(&decom, &i_delta) {
                // Save decom_i and ctr bits
                save_decom_and_ctr(decom_i_sig, ctr_s, &decom_i, ctr);
                break;
            }
        }
    }
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
            FAESTEM256sParameters, FAESTParameters, OWF128, OWF128EM, OWF192, OWF192EM, OWF256,
            OWF256EM,
        },
        utils::test::{hash_array, read_test_data},
    };
    use core::hash;
    use serde::Deserialize;

    const MSG: [u8; 76] = [
        0x54, 0x68, 0x69, 0x73, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x64,
        0x65, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x73, 0x70,
        0x65, 0x63, 0x69, 0x66, 0x69, 0x65, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x46, 0x41, 0x45,
        0x53, 0x54, 0x20, 0x64, 0x69, 0x67, 0x69, 0x74, 0x61, 0x6c, 0x20, 0x73, 0x69, 0x67, 0x6e,
        0x61, 0x74, 0x75, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d,
        0x2e,
    ];

    const RHO: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FaestProveData {
        lambda: u16,
        em: bool,
        sk: Vec<u8>,
        hashed_sig_s: Vec<u8>,
        hashed_sig_f: Vec<u8>,
    }
    impl FaestProveData {
        fn try_signing<P: FAESTParameters<OWF = O>, O: OWFParameters>(
            sk: &SecretKey<O>,
            hashed_sig: &[u8],
        ) {
            let mut signature = GenericArray::default();
            sign::<P, O>(&MSG, &sk, &RHO, &mut signature);
            assert_eq!(hashed_sig, hash_array(signature.as_slice()).as_slice());
        }

        fn test_signature_em(&self) {
            match self.lambda {
                128 => {
                    let sk = SecretKey::<OWF128EM>::try_from(self.sk.as_slice()).unwrap();

                    println!("FAEST-EM-128s - testing FAEST.sign..");
                    Self::try_signing::<FAESTEM128sParameters, OWF128EM>(&sk, &self.hashed_sig_s);

                    println!("FAEST-EM-128f - testing FAEST.sign..");
                    Self::try_signing::<FAESTEM128fParameters, OWF128EM>(&sk, &self.hashed_sig_f);
                }

                192 => {
                    let sk = SecretKey::<OWF192EM>::try_from(self.sk.as_slice()).unwrap();

                    println!("FAEST-EM-192s - testing FAEST.sign..");
                    Self::try_signing::<FAESTEM192sParameters, OWF192EM>(&sk, &self.hashed_sig_s);

                    println!("FAEST-EM-192f - testing FAEST.sign..");
                    Self::try_signing::<FAESTEM192fParameters, OWF192EM>(&sk, &self.hashed_sig_f);
                }

                _ => {
                    let sk = SecretKey::<OWF256EM>::try_from(self.sk.as_slice()).unwrap();

                    println!("FAEST-EM-256s - testing FAEST.sign..");
                    Self::try_signing::<FAESTEM256sParameters, OWF256EM>(&sk, &self.hashed_sig_s);

                    println!("FAEST-EM-256f - testing FAEST.sign..");
                    Self::try_signing::<FAESTEM256fParameters, OWF256EM>(&sk, &self.hashed_sig_f);
                }
            }
        }

        fn test_signature_aes(&self) {
            match self.lambda {
                128 => {
                    let sk = SecretKey::<OWF128>::try_from(self.sk.as_slice()).unwrap();

                    println!("FAEST-128s - testing FAEST.sign..");
                    Self::try_signing::<FAEST128sParameters, OWF128>(&sk, &self.hashed_sig_s);

                    println!("FAEST-128f - testing FAEST.sign..");
                    Self::try_signing::<FAEST128fParameters, OWF128>(&sk, &self.hashed_sig_f);
                }

                192 => {
                    let sk = SecretKey::<OWF192>::try_from(self.sk.as_slice()).unwrap();

                    println!("FAEST-192s - testing FAEST.sign..");
                    Self::try_signing::<FAEST192sParameters, OWF192>(&sk, &self.hashed_sig_s);

                    println!("FAEST-192f - testing FAEST.sign..");
                    Self::try_signing::<FAEST192fParameters, OWF192>(&sk, &self.hashed_sig_f);
                }

                _ => {
                    let sk = SecretKey::<OWF256>::try_from(self.sk.as_slice()).unwrap();

                    println!("FAEST-256s - testing FAEST.sign..");
                    Self::try_signing::<FAEST256sParameters, OWF256>(&sk, &self.hashed_sig_s);

                    println!("FAEST-256f - testing FAEST.sign..");
                    Self::try_signing::<FAEST256fParameters, OWF256>(&sk, &self.hashed_sig_f);
                }
            }
        }

        pub fn test_signature(&self) {
            if self.em {
                self.test_signature_em();
            } else {
                self.test_signature_aes();
            }
        }
    }

    #[test]
    fn faest_sign_test() {
        let database: Vec<FaestProveData> = read_test_data("FaestProve.json");
        for data in database {
            data.test_signature();
        }
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
