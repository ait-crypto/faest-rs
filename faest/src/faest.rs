use std::{io::Write, iter::zip};

use crate::{
     parameter::{self, BaseParameters, TauParameters, Variant, PARAM, PARAMOWF}, random_oracles::{Hasher, RandomOracle, Reader, IV}, universal_hashing::{VoleHasherInit, VoleHasherProcess}, vc::open, vole::{volecommit, volereconstruct}
};

use crate::parameter::{EmCypher, AesCypher};
use generic_array::{typenum::Unsigned, GenericArray};





type RO<O> = <<O as PARAMOWF>::BaseParams as BaseParameters>::RandomOracle;

///input : Message (an array of bytes), sk : secret key, pk : public key, rho : lambda bits
///
///output : correction string (tau - 1 * (l_hat bits)), Hash of VOLE sceet (LAMBDA + 16 bits), Commitment to the witness (l bits)
///
/// Quicksilver proof (Lambda), Partial decommitment (Tau * (t0 * k0*lambda + t1 * k1*lambda  +  2Lambda) bits),
///
///last challenge (lambda bits), initialisation vector
#[allow(clippy::needless_range_loop)]
#[allow(clippy::type_complexity)]
#[allow(clippy::unnecessary_to_owned)]
pub fn faest_sign<P, O>(
    msg: &[u8],
    sk: &GenericArray<u8, O::LAMBDABYTES>,
    pk: &GenericArray<u8, O::PK>,
    rho: &[u8],
) -> Box<GenericArray<u8, P::SIG>>
where
    P: PARAM,
    O: PARAMOWF + PARAMOWF<LAMBDABYTES = P::LAMBDABYTES> + PARAMOWF<PK = <<P as parameter::PARAM>::OWF as PARAMOWF>::PK> + PARAMOWF<LAMBDA = P::LAMBDA> + PARAMOWF<CHALL = <<P as parameter::PARAM>::OWF as PARAMOWF>::CHALL> + PARAMOWF<LAMBDALBYTES = <<P as parameter::PARAM>::OWF as PARAMOWF>::LAMBDALBYTES>,
{
    let lambda = <O::LAMBDA as Unsigned>::to_usize() / 8;
    let l = <P::L as Unsigned>::to_usize() / 8;
    let tau = <P::TAU as Unsigned>::to_usize();
    let t0 = <P::TAU0 as Unsigned>::to_usize();

    let mut h1_hasher = RO::<O>::h1_init();
    h1_hasher.update(pk);
    h1_hasher.update(msg);
    let mut mu: GenericArray<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
        GenericArray::default();
    h1_hasher.finish().read(&mut mu);

    let mut h3_hasher = RO::<O>::h3_init();
    h3_hasher.update(sk);
    h3_hasher.update(&mu);
    h3_hasher.update(rho);

    let mut r = GenericArray::<u8, O::LAMBDABYTES>::default();
    let mut iv = IV::default();
    let mut h3_reader = h3_hasher.finish();
    h3_reader.read(&mut r);
    h3_reader.read(&mut iv);

    let (hcom, decom, c, u, gv) = volecommit::<P, RO<O>>(&r, &iv);
    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&mu);
    h2_hasher.update(&hcom);
    c.iter().for_each(|buf| h2_hasher.update(buf));
    h2_hasher.update(&iv);
    let mut chall1: Box<GenericArray<u8, O::CHALL1>> = GenericArray::default_boxed();
    h2_hasher.finish().read(&mut chall1);

    let vole_hasher = O::VoleHasher::new_vole_hasher(&chall1);
    let u_t = vole_hasher.process(&u);

    let mut h1_hasher = RO::<O>::h1_init();
    for v in gv.iter() {
        v.iter()
            .for_each(|v| h1_hasher.update(&vole_hasher.process(v)));
    }
    let mut hv: GenericArray<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
        GenericArray::default();
    h1_hasher.finish().read(&mut hv);

    let w = P::Cypher::witness::<P>(sk, pk);
    let d = GenericArray::<u8, O::LBYTES>::from_iter(zip(w.iter(), &u[..l]).map(|(w, u)| w ^ *u));

    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&chall1);
    h2_hasher.update(&u_t);
    h2_hasher.update(&hv);
    h2_hasher.update(&d);
    // why is this boxed?
    let mut chall2: GenericArray<u8, O::CHALL> = GenericArray::default();
    h2_hasher.finish().read(&mut chall2);

    let new_u = GenericArray::from_slice(&u[..l + lambda]);
    let new_gv = Box::new(
        gv.iter()
            .flat_map(|x| {
                x.iter()
                    .map(|y| {
                        y.iter()
                            .take(l + lambda)
                            .copied()
                            .collect::<GenericArray<u8, O::LAMBDALBYTES>>()
                    })
                    .collect::<Vec<GenericArray<u8, O::LAMBDALBYTES>>>()
            })
            .collect::<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>())
    ;

    let (a_t, b_t) = P::Cypher::prove::<P>(&w, new_u, &new_gv, pk, &chall2);

    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&chall2);
    h2_hasher.update(&a_t);
    h2_hasher.update(&b_t);
    let mut chall3 = GenericArray::<u8, P::LAMBDABYTES>::default();
    h2_hasher.finish().read(&mut chall3);

    sigma_to_signature::<P, O>(
        c.iter().map(|value| value.as_ref()),
        &u_t,
        &d,
        a_t.as_slice(),
        (0..tau).map(|i| {
            let s = P::Tau::decode_challenge(&chall3, i);
            if i < t0 {
                open::<RO<O>, P::POWK0, P::K0, P::N0>(&decom[i], GenericArray::from_slice(&s))
            } else {
                open::<RO<O>, P::POWK1, P::K1, P::N1>(&decom[i], GenericArray::from_slice(&s))
            }
        }),
        &chall3,
        &iv,
    )
}

#[allow(unused_assignments)]
#[allow(clippy::type_complexity)]
pub fn faest_verify<P, O>(msg: &[u8], pk: GenericArray<u8, O::PK>, sigma: &[u8]) -> bool
where
    P: PARAM,
    O: PARAMOWF + PARAMOWF<CHALL = <<P as parameter::PARAM>::OWF as PARAMOWF>::CHALL> + PARAMOWF<PK = <<P as parameter::PARAM>::OWF as PARAMOWF>::PK>,
{
    let lhat = <O::LHATBYTES as Unsigned>::to_usize();
    let sig = <P::SIG as Unsigned>::to_usize();
    let lambda = <O::LAMBDA as Unsigned>::to_usize() / 8;
    let l = <P::L as Unsigned>::to_usize() / 8;
    let tau = <P::TAU as Unsigned>::to_usize();

    let chall3 = GenericArray::from_slice(&sigma[sig - (16 + lambda)..sig - 16]);
    let mut h1_hasher = RO::<O>::h1_init();
    h1_hasher.update(&pk);
    h1_hasher.update(msg);
    let mut mu: GenericArray<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
        GenericArray::default();
    h1_hasher.finish().read(&mut mu);
    let (hcom, gq_p) = volereconstruct::<RO<O>, P>(
        chall3,
        &sigma[(lhat * (tau - 1)) + (2 * lambda) + l + 2..sig - (16 + lambda)],
        &sigma[sig - 16..].try_into().unwrap(),
    );

    let mut chall1: Box<GenericArray<u8, O::CHALL1>> = GenericArray::default_boxed();
    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&mu);
    h2_hasher.update(&hcom);
    let c = &sigma[..lhat * (tau - 1)];

    h2_hasher.update(c);
    h2_hasher.update(&sigma[sig - 16..]);
    let mut reader = h2_hasher.finish();
    reader.read(&mut chall1);

    let vole_hasher = O::VoleHasher::new_vole_hasher(&chall1);
    let def = GenericArray::default();
    let def2 = GenericArray::default();
    let mut gq: Box<GenericArray<Vec<GenericArray<u8, <P as PARAM>::LH>>, P::TAU>> =
        GenericArray::default_boxed();
    let mut gd_t: Box<GenericArray<Vec<&GenericArray<u8, O::LAMBDAPLUS2>>, O::LAMBDALBYTES>> =
        GenericArray::default_boxed();
    gq[0] = gq_p[0].clone();
    let delta0 = P::Tau::decode_challenge(chall3, 0);
    let u_t = &sigma[lhat * (tau - 1)..lhat * (tau - 1) + lambda + 2];
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
    for i in 1..tau {
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
                    GenericArray::<u8, P::LH>::from_slice(&c[lhat * (i - 1)..lhat * i])
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

    let mut h1_hasher = RO::<O>::h1_init();
    zip(gq_t, gd_t.into_iter().flatten())
        .flat_map(|(q, d)| zip(q, d).map(|(q, d)| q ^ d))
        .for_each(|v| h1_hasher.update(&[v]));
    let mut hv: GenericArray<u8, <O::BaseParams as BaseParameters>::LambdaBytesTimes2> =
        GenericArray::default();
    h1_hasher.finish().read(&mut hv);

    let d = &sigma[lhat * (tau - 1) + lambda + 2..lhat * (tau - 1) + lambda + 2 + l];
    let mut chall2: GenericArray<u8, O::CHALL> = GenericArray::default();
    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&chall1);
    h2_hasher.update(u_t);
    h2_hasher.update(&hv);
    h2_hasher.update(d);
    h2_hasher.finish().read(&mut chall2);

    let a_t = &sigma[lhat * (tau - 1) + lambda + 2 + l..lhat * (tau - 1) + 2 * lambda + 2 + l];
    let b_t = P::Cypher::verify::<P>(
        GenericArray::from_slice(d),
        &gq.iter()
            .flat_map(|x| {
                x.iter()
                    .map(|y| {
                        y.clone()
                            .into_iter()
                            .take(l + lambda)
                            .collect::<GenericArray<u8, _>>()
                    })
                    .collect::<Vec<GenericArray<u8,  <<P as PARAM>::OWF as PARAMOWF>::LAMBDALBYTES>>>()
            })
            .collect::<GenericArray<GenericArray<u8, <<P as PARAM>::OWF as PARAMOWF>::LAMBDALBYTES>, P::LAMBDA>>(),
        GenericArray::from_slice(a_t),
        &chall2,
        chall3,
        &pk,
    );

    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&chall2);
    h2_hasher.update(a_t);
    h2_hasher.update(&b_t);
    let mut chall3_p: GenericArray<u8, P::LAMBDABYTES> = GenericArray::default();
    h2_hasher.finish().read(&mut chall3_p);
    *chall3 == chall3_p
}

fn sigma_to_signature<'a, P, O>(
    c: impl Iterator<Item = &'a [u8]>,
    u_t: &[u8],
    d: &[u8],
    a_t: &[u8],
    pdecom: impl Iterator<Item = (Vec<GenericArray<u8, O::LAMBDABYTES>>, Vec<u8>)>,
    chall3: &[u8],
    iv: &IV,
) -> Box<GenericArray<u8, P::SIG>>
where
    O: PARAMOWF,
    P: PARAM,
{
    let mut res = GenericArray::default_boxed();
    let mut signature = res.as_mut_slice();

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
    res
}

#[allow(clippy::type_complexity)]
pub fn signature_to_sigma<P, O>(
    signature: &[u8],
) -> (
    Box<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>>,
    &GenericArray<u8, O::LAMBDAPLUS2>,
    &GenericArray<u8, O::LBYTES>,
    &GenericArray<u8, O::LAMBDABYTES>,
    Box<GenericArray<(Vec<GenericArray<u8, O::LAMBDABYTES>>, Vec<u8>), P::TAU>>,
    &GenericArray<u8, P::LAMBDABYTES>,
    [u8; 16],
)
where
    P: PARAM,
    O: PARAMOWF,
{
    let mut index = 0;
    let tau = <P::TAU as Unsigned>::to_usize();
    let lambda = <P::LAMBDA as Unsigned>::to_usize() / 8;
    let l = <P::L as Unsigned>::to_usize() / 8;
    let k0 = <P::K0 as Unsigned>::to_usize();
    let k1 = <P::K1 as Unsigned>::to_usize();
    let tau0 = <P::TAU0 as Unsigned>::to_usize();
    let tau1 = <P::TAU1 as Unsigned>::to_usize();
    let l_b = l + 2 * lambda + 2;
    let mut c: Box<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>> =
        GenericArray::default_boxed();

    for i in c.iter_mut().take(tau - 1) {
        for (indice, j) in signature[index..index + l_b].iter().enumerate() {
            i[indice] = *j;
        }
        index += l_b;
    }

    let u_tilde = GenericArray::from_slice(&signature[index..index + lambda + 2]);
    index += lambda + 2;
    let d = GenericArray::from_slice(&signature[index..index + l]);
    index += l;
    let a_tilde = GenericArray::from_slice(&signature[index..index + lambda]);
    index += lambda;
    let mut pdecom: Box<GenericArray<(Vec<GenericArray<u8, O::LAMBDABYTES>>, Vec<u8>), P::TAU>> =
        GenericArray::default_boxed();
    for i in pdecom.iter_mut().take(tau0) {
        for _j in 0..k0 {
            i.0.push((GenericArray::from_slice(&signature[index..index + lambda])).clone());
            index += lambda;
        }
        i.1 = signature[index..index + 2 * lambda].to_vec();
        index += 2 * lambda;
    }
    for i in 0..tau1 {
        for _j in 0..k1 {
            pdecom[tau0 + i]
                .0
                .push(GenericArray::from_slice(&signature[index..index + lambda]).clone());
            index += lambda;
        }
        pdecom[tau0 + i]
            .1
            .append(&mut signature[index..index + 2 * lambda].to_vec());
        index += 2 * lambda;
    }
    let chall3 = GenericArray::from_slice(&signature[index..index + lambda]);
    index += lambda;
    let iv = signature[index..].try_into().unwrap();
    (c, u_tilde, d, a_tilde, pdecom, chall3, iv)
}

#[cfg(test)]
mod test {
    use super::*;

    use generic_array::GenericArray;
    use nist_pqc_seeded_rng::NistPqcAes256CtrRng;
    use rand::RngCore;

    use crate::parameter::{
        PARAM, PARAM128F, PARAM128FEM, PARAM128S, PARAM128SEM, PARAM192F, PARAM192FEM, PARAM192S,
        PARAM192SEM, PARAM256F, PARAM256FEM, PARAM256S, PARAM256SEM, PARAMOWF, PARAMOWF128,
        PARAMOWF128EM, PARAMOWF192, PARAMOWF192EM, PARAMOWF256, PARAMOWF256EM,
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

    #[test]
    fn faest_aes_test_128s() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = AesCypher::<PARAMOWF128>::keygen_with_rng::<PARAM128S>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<PARAM128S, PARAMOWF128>(
                &msg,
                GenericArray::from_slice(&sk[16..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<PARAM128S, PARAMOWF128>(
                &msg,
                (*GenericArray::from_slice(&pk)).clone(),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_aes_test_128f() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = AesCypher::<PARAMOWF128>::keygen_with_rng::<PARAM128F>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<PARAM128F, PARAMOWF128>(
                &msg,
                GenericArray::from_slice(&sk[16..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<PARAM128F, PARAMOWF128>(
                &msg,
                (*GenericArray::from_slice(&pk)).clone(),
                &sigma,
            );

            assert!(res_true);
        }
    }

    #[test]
    fn faest_aes_test_192s() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = AesCypher::<PARAMOWF192>::keygen_with_rng::<PARAM192S>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<PARAM192S, PARAMOWF192>(
                &msg,
                GenericArray::from_slice(&sk[32..56]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<PARAM192S, PARAMOWF192>(
                &msg,
                (*GenericArray::from_slice(&pk)).clone(),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_aes_test_192f() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = AesCypher::<PARAMOWF192>::keygen_with_rng::<PARAM192F>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<PARAM192F, PARAMOWF192>(
                &msg,
                GenericArray::from_slice(&sk[32..56]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<PARAM192F, PARAMOWF192>(
                &msg,
                (*GenericArray::from_slice(&pk)).clone(),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_aes_test_256s() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = AesCypher::<PARAMOWF256>::keygen_with_rng::<PARAM256S>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<PARAM256S, PARAMOWF256>(
                &msg,
                GenericArray::from_slice(&sk[32..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<PARAM256S, PARAMOWF256>(
                &msg,
                (*GenericArray::from_slice(&pk)).clone(),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_aes_test_256f() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = AesCypher::<PARAMOWF256>::keygen_with_rng::<PARAM256F>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<PARAM256F, PARAMOWF256>(
                &msg,
                GenericArray::from_slice(&sk[32..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<PARAM256F, PARAMOWF256>(
                &msg,
                (*GenericArray::from_slice(&pk)).clone(),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_em_test_128s() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = EmCypher::<PARAMOWF128EM>::keygen_with_rng::<PARAM128SEM>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<PARAM128SEM, PARAMOWF128EM>(
                &msg,
                GenericArray::from_slice(&sk[16..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<PARAM128SEM, PARAMOWF128EM>(
                &msg,
                (*GenericArray::from_slice(&pk)).clone(),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_em_test_128f() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = EmCypher::<PARAMOWF128EM>::keygen_with_rng::<PARAM128FEM>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<PARAM128FEM, PARAMOWF128EM>(
                &msg,
                GenericArray::from_slice(&sk[16..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<PARAM128FEM, PARAMOWF128EM>(
                &msg,
                (*GenericArray::from_slice(&pk)).clone(),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_em_test_192s() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = EmCypher::<PARAMOWF192EM>::keygen_with_rng::<PARAM192SEM>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<PARAM192SEM, PARAMOWF192EM>(
                &msg,
                GenericArray::from_slice(&sk[24..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<PARAM192SEM, PARAMOWF192EM>(
                &msg,
                (*GenericArray::from_slice(&pk)).clone(),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_em_test_192f() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = EmCypher::<PARAMOWF192EM>::keygen_with_rng::<PARAM192FEM>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<PARAM192FEM, PARAMOWF192EM>(
                &msg,
                GenericArray::from_slice(&sk[24..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<PARAM192FEM, PARAMOWF192EM>(
                &msg,
                (*GenericArray::from_slice(&pk)).clone(),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_em_test_256s() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = EmCypher::<PARAMOWF256EM>::keygen_with_rng::<PARAM256SEM>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<PARAM256SEM, PARAMOWF256EM>(
                &msg,
                GenericArray::from_slice(&sk[32..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<PARAM256SEM, PARAMOWF256EM>(
                &msg,
                (*GenericArray::from_slice(&pk)).clone(),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_em_test_256f() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = EmCypher::<PARAMOWF256EM>::keygen_with_rng::<PARAM256FEM>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<PARAM256FEM, PARAMOWF256EM>(
                &msg,
                GenericArray::from_slice(&sk[32..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<PARAM256FEM, PARAMOWF256EM>(
                &msg,
                (*GenericArray::from_slice(&pk)).clone(),
                &sigma,
            );
            assert!(res_true);
        }
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

    fn test_nist<P: PARAM>(
        test_data: &str,
        sk_offset: usize,
        sk_offset_2: usize,
    ) {
        let datas = read_kats(test_data);
        for data in datas {
            let mut rng = NistPqcAes256CtrRng::try_from(data.seed.as_slice()).unwrap();
            let pk = data.pk;
            let msg = data.message;
            let sig = data.sm;

            let keypair = P::Cypher::keygen_with_rng::<P>(&mut rng);
            assert_eq!(pk.as_slice(), keypair.0.as_slice());

            let mut rho = GenericArray::<u8, <<P as parameter::PARAM>::OWF as PARAMOWF>::LAMBDABYTES>::default();
            rng.fill_bytes(&mut rho);

            let signature = faest_sign::<P, P::OWF>(
                &msg,
                GenericArray::from_slice(&keypair.1[sk_offset..sk_offset_2]),
                GenericArray::from_slice(&pk),
                &rho,
            );
            assert_eq!(&sig[..sig.len() - signature.len()], &msg);
            assert_eq!(&sig[sig.len() - signature.len()..], signature.as_slice());
            assert!(faest_verify::<P, P::OWF>(
                &msg,
                (*GenericArray::from_slice(&pk)).clone(),
                &signature
            ));
        }
    }

    #[test]
    fn test_nist_faest_128s_aes() {
        test_nist::<PARAM128S>(
            include_str!("../PQCsignKAT_faest_128s.rsp"),
            16,
            32,
        );
    }

    #[test]
    fn test_nist_faest_128f_aes() {
        test_nist::<PARAM128F>(
            include_str!("../PQCsignKAT_faest_128f.rsp"),
            16,
            32,
        );
    }

    #[test]
    fn test_nist_faest_192s_aes() {
        test_nist::<PARAM192S>(
            include_str!("../PQCsignKAT_faest_192s.rsp"),
            32,
            56,
        );
    }

    #[test]
    fn test_nist_faest_192f_aes() {
        test_nist::<PARAM192F>(
            include_str!("../PQCsignKAT_faest_192f.rsp"),
            32,
            56,
        );
    }

    #[test]
    fn test_nist_faest_256s_aes() {
        test_nist::<PARAM256S>(
            include_str!("../PQCsignKAT_faest_256s.rsp"),
            32,
            64,
        );
    }

    #[test]
    fn test_nist_faest_256f_aes() {
        test_nist::<PARAM256F>(
            include_str!("../PQCsignKAT_faest_256f.rsp"),
            32,
            64,
        );
    }

    #[test]
    fn test_nist_faest_128s_em() {
        test_nist::<PARAM128SEM>(
            include_str!("../PQCsignKAT_faest_em_128s.rsp"),
            16,
            32,
        );
    }

    #[test]
    fn test_nist_faest_128f_em() {
        test_nist::<PARAM128FEM>(
            include_str!("../PQCsignKAT_faest_em_128f.rsp"),
            16,
            32,
        );
    }

    #[test]
    fn test_nist_faest_192s_em() {
        test_nist::<PARAM192SEM>(
            include_str!("../PQCsignKAT_faest_em_192s.rsp"),
            24,
            48,
        );
    }

    #[test]
    fn test_nist_faest192f_em() {
        test_nist::<PARAM192FEM>(
            include_str!("../PQCsignKAT_faest_em_192f.rsp"),
            24,
            48,
        );
    }

    #[test]
    fn test_nist_faest_256s_em() {
        test_nist::<PARAM256SEM>(
            include_str!("../PQCsignKAT_faest_em_256s.rsp"),
            32,
            64,
        );
    }

    #[test]
    fn test_nist_faest_256f_em() {
        test_nist::<PARAM256FEM>(
            include_str!("../PQCsignKAT_faest_em_256f.rsp"),
            32,
            64,
        );
    }
}
