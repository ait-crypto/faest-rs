use std::{io::Write, iter::zip};

use crate::{
    aes::{aes_extendedwitness, aes_prove, aes_verify},
    em::{em_extendedwitness, em_prove, em_verify},
    parameter::{BaseParameters, TauParameters, PARAM, PARAMOWF},
    random_oracles::{Hasher, RandomOracle, Reader, IV},
    universal_hashing::{VoleHasherInit, VoleHasherProcess},
    vc::open,
    vole::{volecommit, volereconstruct},
};

use aes::{
    cipher::{
        generic_array::GenericArray as GenericArray_0_14, BlockCipher, BlockEncrypt, KeyInit,
    },
    Aes128Enc, Aes192Enc, Aes256Enc,
};
use generic_array::{typenum::Unsigned, GenericArray};
use rand_core::RngCore;

type QSProof<O> = (
    Box<GenericArray<u8, <O as PARAMOWF>::LAMBDABYTES>>,
    Box<GenericArray<u8, <O as PARAMOWF>::LAMBDABYTES>>,
);
type Key<O> = (
    GenericArray<u8, <O as PARAMOWF>::PK>,
    GenericArray<u8, <O as PARAMOWF>::PK>,
);

pub trait Variant {
    ///input : key (len lambda, snd part of sk); public key
    ///output : witness of l bits
    fn witness<P, O>(
        k: &GenericArray<u8, O::LAMBDABYTES>,
        pk: &GenericArray<u8, O::PK>,
    ) -> Box<GenericArray<u8, O::LBYTES>>
    where
        P: PARAM,
        O: PARAMOWF;

    ///input : witness of l bits, masking values (l+lambda in aes, lambda in em), Vole tag ((l + lambda) *lambda bits), public key, chall(3lambda + 64)
    ///Output : QuickSilver response (Lambda bytes)
    fn prove<P, O>(
        w: &GenericArray<u8, O::LBYTES>,
        u: &GenericArray<u8, O::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        pk: &GenericArray<u8, O::PK>,
        chall: &GenericArray<u8, O::CHALL>,
    ) -> QSProof<O>
    where
        P: PARAM,
        O: PARAMOWF;

    ///input : Masked witness (l bits), Vole Key ((l + lambda) * Lambda bits), hash of constrints values (lambda bits), chall2 (3*lambda + 64 bits), chall3 (lambda bits), public key
    ///output q_tilde - delta * a_tilde (lambda bytes)
    fn verify<P, O>(
        d: &GenericArray<u8, O::LBYTES>,
        gq: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        a_t: &GenericArray<u8, O::LAMBDABYTES>,
        chall2: &GenericArray<u8, O::CHALL>,
        chall3: &GenericArray<u8, P::LAMBDABYTES>,
        pk: &GenericArray<u8, O::PK>,
    ) -> GenericArray<u8, O::LAMBDABYTES>
    where
        P: PARAM,
        O: PARAMOWF;

    ///input : a random number generator
    /// output = pk : input, output; sk : input, key
    fn keygen_with_rng<P, O>(rng: impl RngCore) -> Key<O>
    where
        P: PARAM,
        O: PARAMOWF;
}

pub struct AesCypher {}

impl Variant for AesCypher {
    fn witness<P, O>(
        k: &GenericArray<u8, O::LAMBDABYTES>,
        pk: &GenericArray<u8, O::PK>,
    ) -> Box<GenericArray<u8, O::LBYTES>>
    where
        P: PARAM,
        O: PARAMOWF,
    {
        aes_extendedwitness::<P, O>(k, pk).0
    }

    fn prove<P, O>(
        w: &GenericArray<u8, O::LBYTES>,
        u: &GenericArray<u8, O::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        pk: &GenericArray<u8, O::PK>,
        chall: &GenericArray<u8, O::CHALL>,
    ) -> (
        Box<GenericArray<u8, O::LAMBDABYTES>>,
        Box<GenericArray<u8, O::LAMBDABYTES>>,
    )
    where
        P: PARAM,
        O: PARAMOWF,
    {
        aes_prove::<P, O>(w, u, gv, pk, chall)
    }

    fn verify<P, O>(
        d: &GenericArray<u8, O::LBYTES>,
        gq: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        a_t: &GenericArray<u8, O::LAMBDABYTES>,
        chall2: &GenericArray<u8, O::CHALL>,
        chall3: &GenericArray<u8, P::LAMBDABYTES>,
        pk: &GenericArray<u8, O::PK>,
    ) -> GenericArray<u8, O::LAMBDABYTES>
    where
        P: PARAM,
        O: PARAMOWF,
    {
        aes_verify::<P, O>(d, gq, a_t, chall2, chall3, pk)
    }

    ///Input : the parameter of the faest protocol
    /// Output : sk : inputOWF||keyOWF, pk : inputOWF||outputOWF
    fn keygen_with_rng<P, O>(mut rng: impl RngCore) -> Key<O>
    where
        P: PARAM,
        O: PARAMOWF,
    {
        let pk_len = <O::PK as Unsigned>::to_usize() / 2;
        loop {
            // TODO: why is this O::PK?
            let mut sk: GenericArray<u8, O::PK> = GenericArray::default();
            rng.fill_bytes(&mut sk);

            let test = aes_extendedwitness::<P, O>(
                GenericArray::from_slice(&sk[pk_len..pk_len + O::LAMBDABYTES::USIZE]),
                GenericArray::from_slice(&sk),
            )
            .1;
            if !test {
                continue;
            }

            let mut res = GenericArray::default();
            res[..16 * O::BETA::USIZE].copy_from_slice(&sk[..16 * O::BETA::USIZE]);
            O::evaluate_owf(
                &sk[16 * O::BETA::USIZE..16 * O::BETA::USIZE + O::LAMBDABYTES::USIZE],
                &sk[..16 * O::BETA::USIZE],
                &mut res[16 * O::BETA::USIZE..],
            );

            return (res, sk);
        }
    }
}

pub struct EmCypher {}

impl Variant for EmCypher {
    fn witness<P, O>(
        k: &GenericArray<u8, O::LAMBDABYTES>,
        pk: &GenericArray<u8, O::PK>,
    ) -> Box<GenericArray<u8, O::LBYTES>>
    where
        P: PARAM,
        O: PARAMOWF,
    {
        em_extendedwitness::<P, O>(k, pk).0
    }

    fn prove<P, O>(
        w: &GenericArray<u8, O::LBYTES>,
        u: &GenericArray<u8, O::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        pk: &GenericArray<u8, O::PK>,
        chall: &GenericArray<u8, O::CHALL>,
    ) -> (
        Box<GenericArray<u8, O::LAMBDABYTES>>,
        Box<GenericArray<u8, O::LAMBDABYTES>>,
    )
    where
        P: PARAM,
        O: PARAMOWF,
    {
        em_prove::<P, O>(w, u, gv, pk, chall)
    }

    fn verify<P, O>(
        d: &GenericArray<u8, O::LBYTES>,
        gq: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        a_t: &GenericArray<u8, O::LAMBDABYTES>,
        chall2: &GenericArray<u8, O::CHALL>,
        chall3: &GenericArray<u8, P::LAMBDABYTES>,
        pk: &GenericArray<u8, O::PK>,
    ) -> GenericArray<u8, O::LAMBDABYTES>
    where
        P: PARAM,
        O: PARAMOWF,
    {
        em_verify::<P, O>(d, gq, a_t, chall2, chall3, pk)
    }

    fn keygen_with_rng<P, O>(mut rng: impl RngCore) -> Key<O>
    where
        P: PARAM,
        O: PARAMOWF,
    {
        let pk_len = <O::PK as Unsigned>::to_usize() / 2;
        loop {
            // TODO: why is this O::PK?
            let mut sk: GenericArray<u8, O::PK> = GenericArray::default();
            rng.fill_bytes(&mut sk);

            let test = em_extendedwitness::<P, O>(
                GenericArray::from_slice(&sk[O::LAMBDABYTES::USIZE..]),
                GenericArray::from_slice(&sk),
            )
            .1;
            if !test {
                continue;
            }

            let mut res = GenericArray::default();
            res[..O::LAMBDABYTES::USIZE].copy_from_slice(&sk[..O::LAMBDABYTES::USIZE]);
            O::evaluate_owf(
                &sk[O::LAMBDABYTES::USIZE..2 * O::LAMBDABYTES::USIZE],
                &sk[..O::LAMBDABYTES::USIZE],
                &mut res[O::LAMBDABYTES::USIZE..],
            );
            return (res, sk);
        }
    }
}

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
pub fn faest_sign<C, P, O>(
    msg: &[u8],
    sk: &GenericArray<u8, O::LAMBDABYTES>,
    pk: &GenericArray<u8, O::PK>,
    rho: &[u8],
) -> Box<GenericArray<u8, P::SIG>>
where
    C: Variant,
    P: PARAM,
    O: PARAMOWF,
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

    let w = C::witness::<P, O>(sk, pk);
    let d = GenericArray::<u8, O::LBYTES>::from_iter(zip(w.iter(), &u[..l]).map(|(w, u)| w ^ *u));

    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&chall1);
    h2_hasher.update(&u_t);
    h2_hasher.update(&hv);
    h2_hasher.update(&d);
    // why is this boxed?
    let mut chall2: Box<GenericArray<u8, O::CHALL>> = GenericArray::default_boxed();
    h2_hasher.finish().read(&mut chall2);

    let new_u = GenericArray::from_slice(&u[..l + lambda]);
    let new_gv: &Box<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>> = &Box::new(
        gv.iter()
            .flat_map(|x| {
                x.iter()
                    .map(|y| {
                        y.clone()
                            .into_iter()
                            .take(l + lambda)
                            .collect::<GenericArray<u8, O::LAMBDALBYTES>>()
                    })
                    .collect::<Vec<GenericArray<u8, O::LAMBDALBYTES>>>()
            })
            .collect::<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>(),
    );

    let (a_t, b_t) = C::prove::<P, O>(&w, new_u, new_gv, pk, &chall2);

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
pub fn faest_verify<C, P, O>(msg: &[u8], pk: &GenericArray<u8, O::PK>, sigma: &[u8]) -> bool
where
    C: Variant,
    P: PARAM,
    O: PARAMOWF,
{
    let lhat = <O::LHATBYTES as Unsigned>::to_usize();
    let sig = <P::SIG as Unsigned>::to_usize();
    let lambda = <O::LAMBDA as Unsigned>::to_usize() / 8;
    let l = <P::L as Unsigned>::to_usize() / 8;
    let tau = <P::TAU as Unsigned>::to_usize();

    let chall3 = GenericArray::from_slice(&sigma[sig - (16 + lambda)..sig - 16]);
    let mut h1_hasher = RO::<O>::h1_init();
    h1_hasher.update(pk);
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
    let def3 = GenericArray::default();
    let def4 = GenericArray::default();
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
    let mut temp: Vec<GenericArray<u8, P::LH>> = vec![def3];
    let mut dtemp = vec![def4];
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
        dtemp = delta
            .iter()
            .map(|d| {
                if *d == 1 {
                    GenericArray::from_slice(&c[lhat * (i - 1)..lhat * i]).clone()
                } else {
                    def2.clone()
                }
            })
            .collect::<Vec<GenericArray<u8, P::LH>>>();
        temp = gq_p[i]
            .iter()
            .zip(dtemp)
            .map(|(q, d)| {
                zip(q, d)
                    .map(|(q, d)| (q ^ d))
                    .collect::<GenericArray<u8, P::LH>>()
            })
            .collect::<Vec<GenericArray<u8, <P as PARAM>::LH>>>();
        gq[i] = temp;
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
    let mut chall2: Box<GenericArray<u8, O::CHALL>> = GenericArray::default_boxed();
    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&chall1);
    h2_hasher.update(u_t);
    h2_hasher.update(&hv);
    h2_hasher.update(d);
    h2_hasher.finish().read(&mut chall2);

    let a_t = &sigma[lhat * (tau - 1) + lambda + 2 + l..lhat * (tau - 1) + 2 * lambda + 2 + l];
    let b_t = C::verify::<P, O>(
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
                    .collect::<Vec<GenericArray<u8, O::LAMBDALBYTES>>>()
            })
            .collect::<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>(),
        GenericArray::from_slice(a_t),
        &chall2,
        chall3,
        pk,
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
            let (pk, sk) = AesCypher::keygen_with_rng::<PARAM128S, PARAMOWF128>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<AesCypher, PARAM128S, PARAMOWF128>(
                &msg,
                GenericArray::from_slice(&sk[16..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<AesCypher, PARAM128S, PARAMOWF128>(
                &msg,
                GenericArray::from_slice(&pk),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_aes_test_128f() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = AesCypher::keygen_with_rng::<PARAM128F, PARAMOWF128>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<AesCypher, PARAM128F, PARAMOWF128>(
                &msg,
                GenericArray::from_slice(&sk[16..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<AesCypher, PARAM128F, PARAMOWF128>(
                &msg,
                GenericArray::from_slice(&pk),
                &sigma,
            );

            assert!(res_true);
        }
    }

    #[test]
    fn faest_aes_test_192s() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = AesCypher::keygen_with_rng::<PARAM192S, PARAMOWF192>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<AesCypher, PARAM192S, PARAMOWF192>(
                &msg,
                GenericArray::from_slice(&sk[32..56]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<AesCypher, PARAM192S, PARAMOWF192>(
                &msg,
                GenericArray::from_slice(&pk),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_aes_test_192f() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = AesCypher::keygen_with_rng::<PARAM192F, PARAMOWF192>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<AesCypher, PARAM192F, PARAMOWF192>(
                &msg,
                GenericArray::from_slice(&sk[32..56]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<AesCypher, PARAM192F, PARAMOWF192>(
                &msg,
                GenericArray::from_slice(&pk),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_aes_test_256s() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = AesCypher::keygen_with_rng::<PARAM256S, PARAMOWF256>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<AesCypher, PARAM256S, PARAMOWF256>(
                &msg,
                GenericArray::from_slice(&sk[32..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<AesCypher, PARAM256S, PARAMOWF256>(
                &msg,
                GenericArray::from_slice(&pk),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_aes_test_256f() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = AesCypher::keygen_with_rng::<PARAM256F, PARAMOWF256>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<AesCypher, PARAM256F, PARAMOWF256>(
                &msg,
                GenericArray::from_slice(&sk[32..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<AesCypher, PARAM256F, PARAMOWF256>(
                &msg,
                GenericArray::from_slice(&pk),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_em_test_128s() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = EmCypher::keygen_with_rng::<PARAM128SEM, PARAMOWF128EM>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<EmCypher, PARAM128SEM, PARAMOWF128EM>(
                &msg,
                GenericArray::from_slice(&sk[16..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<EmCypher, PARAM128SEM, PARAMOWF128EM>(
                &msg,
                GenericArray::from_slice(&pk),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_em_test_128f() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = EmCypher::keygen_with_rng::<PARAM128FEM, PARAMOWF128EM>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<EmCypher, PARAM128FEM, PARAMOWF128EM>(
                &msg,
                GenericArray::from_slice(&sk[16..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<EmCypher, PARAM128FEM, PARAMOWF128EM>(
                &msg,
                GenericArray::from_slice(&pk),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_em_test_192s() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = EmCypher::keygen_with_rng::<PARAM192SEM, PARAMOWF192EM>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<EmCypher, PARAM192SEM, PARAMOWF192EM>(
                &msg,
                GenericArray::from_slice(&sk[24..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<EmCypher, PARAM192SEM, PARAMOWF192EM>(
                &msg,
                GenericArray::from_slice(&pk),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_em_test_192f() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = EmCypher::keygen_with_rng::<PARAM192FEM, PARAMOWF192EM>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<EmCypher, PARAM192FEM, PARAMOWF192EM>(
                &msg,
                GenericArray::from_slice(&sk[24..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<EmCypher, PARAM192FEM, PARAMOWF192EM>(
                &msg,
                GenericArray::from_slice(&pk),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_em_test_256s() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = EmCypher::keygen_with_rng::<PARAM256SEM, PARAMOWF256EM>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<EmCypher, PARAM256SEM, PARAMOWF256EM>(
                &msg,
                GenericArray::from_slice(&sk[32..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<EmCypher, PARAM256SEM, PARAMOWF256EM>(
                &msg,
                GenericArray::from_slice(&pk),
                &sigma,
            );
            assert!(res_true);
        }
    }

    #[test]
    fn faest_em_test_256f() {
        let mut rng = rand::thread_rng();
        for _i in 0..RUNS {
            let (pk, sk) = EmCypher::keygen_with_rng::<PARAM256FEM, PARAMOWF256EM>(&mut rng);
            let msg = random_message(&mut rng);
            let sigma = faest_sign::<EmCypher, PARAM256FEM, PARAMOWF256EM>(
                &msg,
                GenericArray::from_slice(&sk[32..]),
                GenericArray::from_slice(&pk),
                &[],
            );
            let res_true = faest_verify::<EmCypher, PARAM256FEM, PARAMOWF256EM>(
                &msg,
                GenericArray::from_slice(&pk),
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

    fn test_nist<P: PARAM, O: PARAMOWF, C: Variant>(
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

            let keypair = C::keygen_with_rng::<P, O>(&mut rng);
            assert_eq!(pk.as_slice(), keypair.0.as_slice());

            let mut rho = GenericArray::<u8, O::LAMBDABYTES>::default();
            rng.fill_bytes(&mut rho);

            let signature = faest_sign::<C, P, O>(
                &msg,
                GenericArray::from_slice(&keypair.1[sk_offset..sk_offset_2]),
                GenericArray::from_slice(&pk),
                &rho,
            );
            assert_eq!(&sig[..sig.len() - signature.len()], &msg);
            assert_eq!(&sig[sig.len() - signature.len()..], signature.as_slice());
            assert!(faest_verify::<C, P, O>(
                &msg,
                GenericArray::from_slice(&pk),
                &signature
            ));
        }
    }

    #[test]
    fn test_nist_faest_128s_aes() {
        test_nist::<PARAM128S, PARAMOWF128, AesCypher>(
            include_str!("../PQCsignKAT_faest_128s.rsp"),
            16,
            32,
        );
    }

    #[test]
    fn test_nist_faest_128f_aes() {
        test_nist::<PARAM128F, PARAMOWF128, AesCypher>(
            include_str!("../PQCsignKAT_faest_128f.rsp"),
            16,
            32,
        );
    }

    #[test]
    fn test_nist_faest_192s_aes() {
        test_nist::<PARAM192S, PARAMOWF192, AesCypher>(
            include_str!("../PQCsignKAT_faest_192s.rsp"),
            32,
            56,
        );
    }

    #[test]
    fn test_nist_faest_192f_aes() {
        test_nist::<PARAM192F, PARAMOWF192, AesCypher>(
            include_str!("../PQCsignKAT_faest_192f.rsp"),
            32,
            56,
        );
    }

    #[test]
    fn test_nist_faest_256s_aes() {
        test_nist::<PARAM256S, PARAMOWF256, AesCypher>(
            include_str!("../PQCsignKAT_faest_256s.rsp"),
            32,
            64,
        );
    }

    #[test]
    fn test_nist_faest_256f_aes() {
        test_nist::<PARAM256F, PARAMOWF256, AesCypher>(
            include_str!("../PQCsignKAT_faest_256f.rsp"),
            32,
            64,
        );
    }

    #[test]
    fn test_nist_faest_128s_em() {
        test_nist::<PARAM128SEM, PARAMOWF128EM, EmCypher>(
            include_str!("../PQCsignKAT_faest_em_128s.rsp"),
            16,
            32,
        );
    }

    #[test]
    fn test_nist_faest_128f_em() {
        test_nist::<PARAM128FEM, PARAMOWF128EM, EmCypher>(
            include_str!("../PQCsignKAT_faest_em_128f.rsp"),
            16,
            32,
        );
    }

    #[test]
    fn test_nist_faest_192s_em() {
        test_nist::<PARAM192SEM, PARAMOWF192EM, EmCypher>(
            include_str!("../PQCsignKAT_faest_em_192s.rsp"),
            24,
            48,
        );
    }

    #[test]
    fn test_nist_faest192f_em() {
        test_nist::<PARAM192FEM, PARAMOWF192EM, EmCypher>(
            include_str!("../PQCsignKAT_faest_em_192f.rsp"),
            24,
            48,
        );
    }

    #[test]
    fn test_nist_faest_256s_em() {
        test_nist::<PARAM256SEM, PARAMOWF256EM, EmCypher>(
            include_str!("../PQCsignKAT_faest_em_256s.rsp"),
            32,
            64,
        );
    }

    #[test]
    fn test_nist_faest_256f_em() {
        test_nist::<PARAM256FEM, PARAMOWF256EM, EmCypher>(
            include_str!("../PQCsignKAT_faest_em_256f.rsp"),
            32,
            64,
        );
    }
}
