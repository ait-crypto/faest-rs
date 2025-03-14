use std::{io::Write, iter::zip};

use crate::{
    bavc::BAVC,
    internal_keys::{PublicKey, SecretKey},
    parameter::{BaseParameters, FAESTParameters, OWFParameters, TauParameters},
    prg::{IVSize, PseudoRandomGenerator, IV},
    random_oracles::{Hasher, RandomOracle},
    universal_hashing::{VoleHasherInit, VoleHasherProcess},
    utils::Reader,
    vole::{volecommit, volereconstruct, VoleCommitResult, VoleCommitmentCRef},
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
    let ctr = 0;

    // Step 3
    let mut mu =
        GenericArray::<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2>::default();
    RO::<P>::hash_mu(&mut mu, &sk.pk.owf_input, &sk.pk.owf_output, msg);

    // Step 4
    let mut r = GenericArray::<u8, O::LAMBDABYTES>::default();
    let (signature, iv) = signature.split_at_mut(P::SignatureSize::USIZE - IVSize::USIZE);
    let mut iv = GenericArray::from_mut_slice(iv);
    RO::<P>::hash_r_iv(&mut r, iv, &sk.owf_key, &mu, rho);

    // Step 5
    RO::<P>::hash_iv(&mut iv);

    //Step 7
    let (volecommit_cs, signature) =
        signature.split_at_mut(O::LHATBYTES::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1));
    let VoleCommitResult {
        com,
        decom,
        u,
        mut v,
    } = volecommit::<P::BAVC, O::LHATBYTES>(VoleCommitmentCRef::new(volecommit_cs), &r, iv);

    debug_assert!(volecommit_cs == exp_cs.as_slice());

    let mut chall1 =
        GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall1>::default();
    RO::<P>::hash_challenge_1(&mut chall1, &mu, &com, volecommit_cs, iv);

    let (signature, u_t, h_t) = {
        // Step 10
        let mut vole_hasher_u = VoleHasher::<P>::new_vole_hasher(&chall1);
        let mut vole_haher_v = vole_hasher_u.clone();
        let u_t = vole_hasher_u.process(&u);

        // write u_t to signature
        let (u_t_d, signature) = signature.split_at_mut(u_t.len());
        u_t_d.copy_from_slice(u_t.as_slice());

        // Step 11
        let h_t = vole_haher_v.process(&v.clone().into_iter().flatten().collect::<Vec<u8>>());

        (signature, u_t_d, h_t)
    };
    debug_assert!(u_t == exp_ut.as_slice());

    // Step 12
    // TODO: compute once and store in SecretKey
    let w = P::OWF::witness(sk);

    // Step 13
    // compute and write d to signature
    let (d, signature) = signature.split_at_mut(O::LBYTES::USIZE);
    for (mut dj, wj, uj) in izip!(d.iter_mut(), w.iter(), &u[..O::LBYTES::USIZE]) {
        *dj = wj ^ *uj;
    }
    debug_assert_eq!(d, exp_d.as_slice());

    // Step 14
    let mut chall2 =
        GenericArray::<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>::default();
    RO::<P>::hash_challenge_2(&mut chall2, &chall1, u_t, &h_t, d);

    let proof = P::OWF::prove(
        &w,
        GenericArray::from_slice(&u[O::LBYTES::USIZE..O::LBYTES::USIZE + O::LAMBDABYTESTWO::USIZE]),
        GenericArray::from_slice(&v[..O::LAMBDALBYTES::USIZE]),
        &sk.pk,
        &chall2,
    );

    // let (a_t_d, signature) = signature.split_at_mut(O::LAMBDABYTES::USIZE);
    // a_t_d.copy_from_slice(&a_t);

    // let (signature, chall3) = signature.split_at_mut(signature.len() - O::LAMBDABYTES::USIZE);
    // let chall3 = GenericArray::<_, O::LAMBDABYTES>::from_mut_slice(chall3);
    // RO::<P>::hash_challenge_3(chall3, &chall2, &a_t, &b_t);
    // (signature, chall3)

    todo!("Finish implementation")
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
const exp_cs: [u8; 2100] = [
    234, 63, 134, 226, 101, 25, 103, 116, 190, 161, 153, 13, 228, 224, 4, 133, 140, 146, 155, 180,
    30, 70, 224, 132, 112, 140, 159, 236, 125, 217, 60, 147, 57, 59, 149, 240, 219, 1, 125, 124,
    20, 205, 20, 104, 174, 55, 215, 57, 247, 0, 135, 177, 130, 83, 211, 3, 207, 101, 139, 102, 191,
    6, 166, 122, 54, 152, 108, 97, 77, 19, 51, 138, 28, 19, 248, 155, 184, 22, 102, 234, 21, 17,
    63, 81, 254, 135, 125, 68, 17, 229, 87, 152, 145, 102, 38, 253, 60, 45, 133, 115, 204, 146,
    219, 139, 168, 211, 202, 223, 94, 249, 46, 40, 1, 211, 22, 2, 184, 235, 150, 85, 93, 40, 176,
    39, 36, 35, 181, 251, 2, 228, 152, 164, 122, 39, 115, 239, 181, 51, 235, 185, 144, 65, 100,
    129, 55, 197, 106, 228, 143, 43, 22, 166, 191, 152, 144, 141, 142, 18, 206, 229, 137, 178, 84,
    156, 105, 215, 224, 75, 51, 244, 246, 223, 193, 182, 69, 131, 80, 32, 126, 61, 3, 102, 75, 140,
    236, 222, 6, 222, 13, 24, 54, 151, 127, 39, 172, 78, 181, 217, 43, 97, 228, 22, 249, 250, 254,
    168, 130, 227, 133, 73, 16, 180, 156, 92, 80, 220, 28, 173, 33, 215, 138, 135, 42, 238, 253,
    23, 4, 203, 50, 56, 10, 221, 129, 83, 85, 72, 54, 38, 2, 238, 1, 14, 255, 175, 226, 0, 202,
    215, 88, 77, 81, 75, 132, 15, 117, 216, 52, 42, 83, 171, 250, 253, 89, 15, 93, 133, 82, 150,
    93, 172, 7, 205, 239, 218, 236, 226, 171, 212, 251, 27, 188, 93, 53, 184, 49, 147, 3, 52, 70,
    9, 202, 229, 27, 113, 5, 166, 117, 36, 232, 122, 199, 156, 34, 228, 223, 63, 244, 74, 111, 196,
    24, 6, 209, 2, 14, 138, 213, 222, 203, 80, 43, 232, 222, 247, 20, 20, 82, 18, 78, 125, 86, 222,
    80, 13, 255, 121, 194, 132, 95, 4, 103, 228, 45, 59, 196, 215, 123, 70, 202, 72, 53, 135, 53,
    156, 81, 56, 55, 203, 68, 5, 6, 207, 146, 131, 96, 7, 174, 181, 195, 2, 131, 36, 221, 101, 99,
    13, 167, 109, 82, 119, 181, 28, 140, 181, 255, 17, 218, 253, 55, 179, 34, 40, 19, 224, 91, 104,
    48, 155, 232, 81, 19, 235, 9, 27, 222, 238, 25, 144, 189, 146, 25, 17, 4, 68, 20, 166, 132, 65,
    118, 49, 181, 16, 76, 255, 191, 171, 57, 195, 134, 65, 232, 171, 78, 21, 248, 134, 36, 46, 81,
    37, 46, 5, 154, 243, 95, 117, 173, 134, 33, 97, 141, 195, 235, 246, 249, 186, 14, 154, 187,
    179, 30, 254, 107, 25, 235, 124, 6, 0, 65, 196, 76, 140, 158, 177, 133, 125, 136, 69, 171, 163,
    210, 86, 69, 250, 124, 250, 142, 19, 217, 210, 206, 18, 102, 196, 197, 110, 76, 16, 50, 147,
    219, 207, 189, 197, 180, 115, 9, 241, 186, 14, 167, 182, 17, 65, 67, 124, 33, 184, 163, 69,
    200, 67, 142, 114, 144, 88, 255, 145, 84, 122, 45, 107, 0, 205, 176, 253, 150, 109, 14, 179,
    12, 85, 200, 76, 144, 63, 91, 195, 209, 91, 156, 205, 104, 75, 171, 98, 105, 7, 216, 114, 128,
    29, 192, 16, 20, 239, 82, 8, 49, 92, 92, 40, 55, 128, 147, 126, 160, 18, 93, 240, 183, 113, 97,
    83, 28, 20, 223, 105, 114, 173, 23, 101, 27, 147, 192, 168, 199, 151, 224, 130, 186, 96, 233,
    159, 46, 20, 63, 41, 145, 67, 103, 236, 161, 207, 14, 231, 194, 150, 170, 87, 221, 147, 23,
    140, 194, 195, 73, 243, 37, 234, 126, 105, 176, 27, 203, 151, 62, 21, 162, 160, 70, 93, 250,
    233, 120, 179, 215, 196, 227, 136, 229, 240, 238, 9, 219, 57, 45, 217, 86, 51, 123, 83, 16, 64,
    151, 74, 207, 213, 110, 249, 108, 179, 182, 4, 53, 216, 82, 211, 143, 122, 148, 160, 228, 211,
    80, 55, 148, 138, 89, 158, 118, 82, 82, 40, 183, 94, 81, 36, 127, 73, 158, 136, 241, 165, 110,
    135, 94, 202, 189, 65, 159, 88, 163, 111, 79, 235, 42, 169, 96, 141, 172, 173, 170, 177, 255,
    19, 195, 155, 245, 86, 133, 34, 208, 189, 156, 125, 94, 12, 252, 120, 15, 170, 164, 224, 150,
    168, 35, 38, 148, 117, 77, 101, 234, 214, 217, 103, 214, 112, 63, 189, 133, 228, 100, 246, 102,
    222, 44, 253, 178, 81, 37, 91, 49, 123, 177, 98, 114, 0, 21, 47, 150, 72, 99, 142, 117, 231,
    73, 214, 50, 172, 35, 233, 136, 32, 183, 189, 252, 75, 188, 235, 120, 150, 132, 148, 20, 4,
    122, 130, 185, 228, 33, 2, 130, 216, 46, 65, 217, 157, 146, 144, 29, 173, 71, 138, 97, 133,
    226, 143, 155, 45, 228, 124, 32, 208, 142, 137, 106, 11, 48, 79, 5, 170, 226, 126, 46, 228,
    223, 242, 4, 106, 104, 73, 212, 61, 130, 43, 137, 180, 117, 183, 29, 8, 116, 93, 66, 79, 26,
    218, 215, 193, 104, 86, 45, 2, 122, 103, 29, 20, 139, 185, 109, 216, 200, 22, 55, 31, 22, 183,
    43, 5, 226, 189, 158, 220, 160, 52, 118, 97, 39, 34, 48, 202, 224, 67, 9, 10, 185, 196, 20,
    203, 36, 101, 142, 219, 249, 98, 20, 247, 181, 196, 195, 50, 211, 108, 88, 123, 118, 94, 25,
    27, 180, 9, 255, 226, 75, 151, 155, 125, 111, 105, 182, 151, 108, 197, 49, 59, 160, 29, 61,
    119, 101, 138, 101, 152, 225, 169, 38, 193, 205, 157, 146, 28, 251, 160, 239, 158, 153, 170,
    148, 59, 93, 11, 38, 209, 208, 185, 248, 221, 61, 105, 26, 143, 65, 116, 90, 121, 196, 139, 61,
    70, 219, 17, 123, 58, 118, 29, 26, 220, 163, 9, 139, 68, 125, 48, 147, 163, 157, 79, 65, 155,
    208, 214, 89, 255, 75, 152, 175, 16, 45, 49, 45, 35, 49, 40, 198, 131, 53, 16, 178, 214, 223,
    7, 13, 254, 126, 250, 201, 96, 224, 219, 207, 197, 121, 31, 50, 203, 47, 80, 65, 201, 128, 104,
    234, 144, 47, 238, 178, 182, 101, 126, 59, 174, 36, 219, 94, 116, 10, 243, 169, 109, 73, 207,
    3, 39, 252, 250, 203, 216, 91, 160, 148, 76, 190, 115, 159, 125, 89, 128, 135, 151, 231, 212,
    74, 78, 109, 156, 157, 173, 184, 197, 123, 230, 100, 130, 227, 109, 51, 72, 67, 11, 156, 244,
    90, 79, 7, 5, 238, 17, 5, 209, 156, 14, 229, 199, 219, 168, 217, 86, 237, 103, 20, 26, 72, 7,
    254, 157, 83, 195, 99, 28, 15, 215, 247, 159, 178, 99, 11, 16, 98, 230, 145, 201, 87, 218, 97,
    120, 99, 43, 224, 28, 227, 39, 101, 51, 80, 234, 205, 83, 201, 57, 67, 181, 112, 151, 238, 170,
    78, 181, 103, 70, 207, 235, 194, 175, 142, 149, 187, 3, 13, 208, 213, 39, 243, 177, 21, 139,
    12, 153, 190, 131, 182, 106, 87, 18, 40, 28, 239, 63, 25, 82, 54, 209, 44, 32, 76, 244, 229,
    103, 203, 78, 19, 198, 240, 212, 233, 48, 126, 218, 117, 41, 139, 20, 193, 67, 38, 224, 210,
    200, 200, 209, 169, 127, 25, 9, 181, 245, 0, 71, 62, 162, 118, 167, 29, 69, 114, 204, 219, 247,
    180, 164, 85, 100, 146, 162, 121, 88, 47, 176, 51, 25, 76, 50, 8, 161, 48, 254, 235, 10, 69,
    230, 237, 199, 66, 208, 143, 93, 82, 61, 121, 141, 110, 203, 242, 1, 178, 65, 152, 165, 50,
    119, 247, 164, 100, 176, 92, 227, 109, 118, 161, 84, 152, 143, 247, 214, 152, 237, 110, 161,
    24, 190, 228, 140, 121, 243, 102, 41, 166, 248, 65, 52, 94, 72, 119, 44, 176, 83, 94, 74, 198,
    220, 8, 195, 101, 107, 143, 143, 157, 17, 87, 100, 99, 103, 147, 90, 84, 170, 88, 221, 141,
    198, 8, 161, 212, 175, 145, 102, 36, 205, 80, 236, 191, 53, 136, 212, 173, 8, 55, 61, 216, 109,
    44, 59, 41, 164, 235, 235, 66, 4, 13, 98, 111, 19, 25, 19, 93, 151, 173, 38, 136, 217, 81, 182,
    23, 232, 14, 68, 102, 218, 105, 223, 139, 129, 36, 143, 165, 181, 133, 207, 245, 114, 222, 93,
    9, 89, 25, 3, 129, 57, 222, 3, 76, 255, 81, 118, 68, 6, 58, 102, 108, 17, 16, 81, 160, 22, 141,
    48, 109, 167, 2, 234, 203, 113, 204, 191, 156, 174, 224, 119, 218, 27, 148, 47, 148, 121, 216,
    58, 235, 119, 226, 135, 197, 20, 38, 29, 55, 145, 86, 182, 142, 110, 154, 195, 100, 162, 18,
    103, 11, 14, 36, 112, 59, 182, 129, 110, 7, 200, 90, 178, 253, 232, 111, 123, 216, 181, 212,
    142, 31, 227, 135, 116, 42, 228, 247, 218, 2, 247, 218, 185, 77, 195, 51, 48, 86, 40, 74, 38,
    238, 15, 248, 102, 22, 225, 102, 188, 234, 13, 204, 113, 176, 28, 44, 118, 141, 12, 83, 12, 73,
    65, 166, 90, 135, 235, 76, 221, 4, 250, 186, 139, 249, 178, 223, 212, 9, 60, 195, 15, 197, 185,
    248, 132, 250, 88, 224, 194, 141, 36, 88, 117, 187, 29, 99, 54, 134, 107, 250, 160, 121, 225,
    233, 16, 156, 228, 243, 65, 124, 81, 43, 211, 33, 73, 151, 82, 199, 160, 60, 49, 2, 189, 133,
    215, 126, 229, 163, 23, 84, 45, 128, 119, 31, 243, 45, 102, 62, 159, 117, 248, 57, 42, 160, 6,
    125, 32, 162, 179, 144, 5, 40, 188, 22, 130, 113, 68, 82, 97, 193, 185, 28, 45, 198, 220, 44,
    132, 211, 192, 92, 24, 75, 223, 184, 90, 4, 7, 87, 128, 31, 101, 241, 163, 78, 187, 92, 61, 83,
    162, 180, 181, 109, 195, 206, 234, 22, 232, 64, 109, 73, 195, 233, 230, 7, 126, 29, 253, 125,
    224, 241, 98, 69, 68, 98, 87, 78, 14, 164, 14, 242, 154, 178, 127, 248, 235, 230, 200, 157,
    123, 120, 245, 216, 78, 225, 19, 206, 124, 216, 23, 153, 72, 11, 174, 106, 63, 107, 189, 114,
    155, 96, 178, 125, 97, 156, 116, 66, 159, 65, 16, 188, 193, 194, 65, 137, 218, 111, 46, 108, 5,
    251, 194, 232, 223, 16, 137, 90, 216, 112, 17, 210, 89, 226, 100, 44, 114, 191, 17, 180, 81,
    230, 13, 117, 100, 255, 61, 93, 171, 221, 62, 246, 189, 69, 230, 156, 68, 229, 198, 117, 83,
    108, 48, 89, 180, 209, 93, 238, 104, 129, 6, 98, 97, 211, 33, 240, 236, 52, 76, 203, 47, 234,
    21, 161, 156, 215, 135, 165, 139, 48, 34, 170, 135, 104, 148, 35, 14, 231, 38, 65, 230, 187,
    145, 81, 40, 61, 23, 33, 46, 41, 165, 60, 228, 102, 121, 188, 110, 237, 73, 154, 12, 226, 224,
    249, 234, 130, 131, 61, 12, 65, 239, 68, 169, 168, 148, 152, 24, 230, 61, 198, 240, 113, 126,
    178, 41, 162, 66, 48, 28, 2, 109, 239, 64, 214, 22, 221, 110, 240, 79, 254, 254, 18, 41, 89,
    202, 141, 65, 148, 148, 121, 38, 207, 132, 146, 168, 225, 36, 70, 60, 163, 88, 191, 27, 88, 59,
    214, 219, 3, 8, 59, 195, 102, 120, 169, 15, 198, 21, 60, 65, 238, 85, 235, 52, 93, 248, 182,
    147, 198, 108, 189, 135, 79, 25, 36, 105, 64, 70, 170, 191, 160, 255, 176, 151, 72, 112, 98,
    105, 121, 47, 140, 94, 75, 193, 209, 38, 42, 5, 2, 209, 238, 35, 121, 3, 176, 52, 227, 5, 30,
    177, 232, 17, 47, 138, 100, 186, 133, 118, 21, 107, 86, 227, 239, 228, 58, 195, 74, 163, 203,
    156, 48, 150, 1, 14, 133, 131, 134, 93, 65, 249, 220, 124, 128, 255, 14, 207, 177, 103, 172,
    201, 133, 229, 243, 59, 203, 37, 30, 119, 2, 203, 87, 143, 127, 102, 112, 46, 202, 89, 204,
    122, 95, 24, 10, 133, 218, 188, 29, 233, 67, 185, 109, 7, 214, 38, 244, 167, 31, 185, 177, 217,
    110, 76, 138, 198, 64, 155, 35, 214, 2, 106, 13, 10, 85, 187, 201, 145, 88, 242, 109, 190, 249,
    226, 61, 142, 5, 227, 194, 108, 251, 127, 147, 162, 65, 22, 221, 164, 83, 40,
];
const exp_ut: [u8; 18] = [
    113, 104, 82, 211, 229, 137, 166, 205, 240, 3, 155, 32, 74, 186, 118, 132, 79, 211,
];
const exp_d: [u8; 160] = [
    229, 254, 6, 110, 225, 100, 219, 74, 109, 148, 81, 171, 61, 71, 117, 173, 106, 127, 243, 21,
    13, 224, 19, 25, 198, 226, 220, 173, 121, 16, 19, 119, 231, 78, 121, 248, 250, 223, 24, 13,
    154, 75, 222, 77, 190, 226, 105, 110, 253, 159, 21, 29, 178, 71, 102, 130, 143, 193, 237, 253,
    139, 194, 245, 63, 213, 66, 131, 104, 37, 109, 234, 79, 127, 94, 18, 79, 172, 222, 117, 231,
    195, 151, 139, 112, 76, 161, 241, 25, 94, 55, 20, 127, 253, 140, 9, 199, 215, 11, 60, 124, 236,
    219, 209, 242, 145, 76, 109, 106, 175, 76, 19, 246, 219, 45, 3, 149, 133, 207, 22, 245, 118, 9,
    105, 42, 151, 215, 189, 241, 130, 227, 192, 201, 113, 134, 230, 134, 238, 123, 11, 166, 253,
    132, 190, 212, 134, 129, 182, 41, 148, 64, 174, 213, 94, 95, 166, 61, 130, 6, 37, 161,
];

#[cfg(test)]
mod test {
    use super::*;
    use crate::parameter::{
        FAEST128fParameters, FAEST128sParameters, FAEST192fParameters, FAEST192sParameters,
        FAEST256fParameters, FAEST256sParameters, FAESTEM128fParameters, FAESTEM128sParameters,
        FAESTEM192fParameters, FAESTEM192sParameters, FAESTEM256fParameters, FAESTEM256sParameters,
        FAESTParameters, OWF128,
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

        let sk = SecretKey::<OWF128>::try_from(sk_bytes.as_slice()).unwrap();
        let rho = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        // println!("{:?}", &exp_signature[2118..2118+160]);
        let mut signature = GenericArray::default();
        sign::<FAEST128sParameters, OWF128>(&msg, &sk, &rho, &mut signature);
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
