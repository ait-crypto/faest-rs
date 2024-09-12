use std::iter::zip;

use crate::{
    aes::{aes_extendedwitness, aes_prove, aes_verify},
    em::{em_extendedwitness, em_prove, em_verify},
    parameter::{BaseParameters, PARAM, PARAMOWF},
    random_oracles::{Hasher, RandomOracle, Reader, IV},
    rijndael_32::{rijndael_encrypt, rijndael_key_schedule},
    universal_hashing::{VoleHasherInit, VoleHasherProcess},
    vc::open,
    vole::{chaldec, volecommit, volereconstruct},
};

type QSProof<O> = (
    Box<GenericArray<u8, <O as PARAMOWF>::LAMBDABYTES>>,
    Box<GenericArray<u8, <O as PARAMOWF>::LAMBDABYTES>>,
);
type Key<O> = (
    GenericArray<u8, <O as PARAMOWF>::PK>,
    Box<GenericArray<u8, <O as PARAMOWF>::PK>>,
    Box<GenericArray<u8, <O as PARAMOWF>::LAMBDABYTES>>,
);

use generic_array::{typenum::Unsigned, GenericArray};
use nist_pqc_seeded_rng::RngCore;

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
    /// output = pk : input, output; sk : input, key; rho (len = Lambda bytes)
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
    #[allow(clippy::never_loop)]
    fn keygen_with_rng<P, O>(
        mut rng: impl RngCore,
    ) -> (
        GenericArray<u8, O::PK>,
        Box<GenericArray<u8, O::PK>>,
        Box<GenericArray<u8, O::LAMBDABYTES>>,
    )
    where
        P: PARAM,
        O: PARAMOWF,
    {
        let nk = <O::NK as Unsigned>::to_u8();
        let lambda = <O::LAMBDABYTES as Unsigned>::to_usize();
        let r = <O::R as Unsigned>::to_u8();
        let beta = <P::BETA as Unsigned>::to_u8();
        let pk_len = <O::PK as Unsigned>::to_usize() / 2;
        'boucle: loop {
            let mut rho: Box<GenericArray<u8, O::LAMBDABYTES>> = GenericArray::default_boxed();
            let mut sk: Box<GenericArray<u8, O::PK>> = GenericArray::default_boxed();
            rng.fill_bytes(&mut sk);

            let test = aes_extendedwitness::<P, O>(
                GenericArray::from_slice(&sk[pk_len..pk_len + lambda]),
                GenericArray::from_slice(&sk),
            )
            .1;
            if !test {
                continue 'boucle;
            }
            let mut cypher: cipher::array::Array<
                aes::cipher::generic_array::GenericArray<u8, _>,
                _,
            >;
            let rk = rijndael_key_schedule(
                &sk[16 * <P::BETA as Unsigned>::to_usize()..],
                4,
                <O::NK as Unsigned>::to_u8(),
                <O::R as Unsigned>::to_u8(),
                <O::SKE as Unsigned>::to_u8(),
            )
            .0;
            let mut y: Box<GenericArray<u8, O::PK>> = GenericArray::default_boxed();
            let mut index = 0;
            if beta == 1 {
                cypher = rijndael_encrypt(&rk, &[&sk[..16], &[0u8; 16]].concat(), 4, nk, r);
                for i in cypher.into_iter().flatten().take(16).collect::<Vec<_>>() {
                    y[index] = i;
                    index += 1;
                }
            } else {
                cypher = rijndael_encrypt(&rk, &[&sk[..16], &[0u8; 16]].concat(), 4, nk, r);
                for i in cypher.into_iter().flatten().take(16).collect::<Vec<_>>() {
                    y[index] = i;
                    index += 1;
                }
                cypher = rijndael_encrypt(&rk, &[&sk[16..32], &[0u8; 16]].concat(), 4, nk, r);
                for i in cypher.into_iter().flatten().take(16).collect::<Vec<_>>() {
                    y[index] = i;
                    index += 1;
                }
            };
            rng.fill_bytes(&mut rho);
            return (
                (*GenericArray::from_slice(&[&sk[..16 * beta as usize], &y[..pk_len]].concat()))
                    .clone(),
                sk,
                rho,
            );
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

    fn keygen_with_rng<P, O>(
        mut rng: impl RngCore,
    ) -> (
        GenericArray<u8, O::PK>,
        Box<GenericArray<u8, O::PK>>,
        Box<GenericArray<u8, O::LAMBDABYTES>>,
    )
    where
        P: PARAM,
        O: PARAMOWF,
    {
        let lambda = <O::LAMBDA as Unsigned>::to_usize() / 8;
        let nk = <O::NK as Unsigned>::to_u8();
        let r = <O::R as Unsigned>::to_u8();
        let nst = <O::NST as Unsigned>::to_u8();
        'boucle: loop {
            let mut rho: Box<GenericArray<u8, O::LAMBDABYTES>> = GenericArray::default_boxed();
            let mut sk: Box<GenericArray<u8, O::PK>> = GenericArray::default_boxed();
            rng.fill_bytes(&mut sk);
            let test = em_extendedwitness::<P, O>(
                GenericArray::from_slice(&sk[lambda..]),
                GenericArray::from_slice(&sk),
            )
            .1;
            if !test {
                continue 'boucle;
            }

            let rk = rijndael_key_schedule(&sk[..lambda], nst, nk, r, 4 * (((r + 1) * nst) / nk));
            let cypher = rijndael_encrypt(
                &rk.0,
                &[&sk[lambda..], &vec![0u8; 32 - lambda]].concat(),
                nst,
                nk,
                r,
            );
            let y: GenericArray<u8, O::LAMBDABYTES> = cypher
                .into_iter()
                .flatten()
                .take(lambda)
                .zip(&sk[lambda..])
                .map(|(y, k)| y ^ k)
                .collect();
            rng.fill_bytes(&mut rho);
            return (
                (*GenericArray::from_slice(&[&sk[..lambda], &y[..]].concat())).clone(),
                sk,
                rho,
            );
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
#[allow(clippy::unnecessary_to_owned)]
pub fn faest_sign<C, P, O>(
    msg: &[u8],
    sk: &GenericArray<u8, O::LAMBDABYTES>,
    pk: &GenericArray<u8, O::PK>,
    rho: &GenericArray<u8, O::LAMBDABYTES>,
) -> (
    Box<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>>,
    GenericArray<u8, O::LAMBDAPLUS2>,
    GenericArray<u8, O::LBYTES>,
    GenericArray<u8, O::LAMBDABYTES>,
    Box<GenericArray<(Vec<GenericArray<u8, O::LAMBDABYTES>>, Vec<u8>), P::TAU>>,
    GenericArray<u8, P::LAMBDABYTES>,
    [u8; 16],
)
where
    C: Variant,
    P: PARAM,
    O: PARAMOWF,
{
    let lambda = <O::LAMBDA as Unsigned>::to_usize() / 8;
    let l = <P::L as Unsigned>::to_usize() / 8;
    let _b = <P::B as Unsigned>::to_usize() / 8;
    let tau = <P::TAU as Unsigned>::to_usize();
    let t0 = <P::TAU0 as Unsigned>::to_usize();
    let _k0 = <P::K0 as Unsigned>::to_u16();
    let _k1 = <P::K1 as Unsigned>::to_u16();

    let mut h1_hasher = RO::<O>::h1_init();
    h1_hasher.update(pk);
    h1_hasher.update(msg);
    // why is this Boxed?
    let mut mu: Box<GenericArray<u8, <RO<O> as RandomOracle>::PRODLAMBDA2>> =
        GenericArray::default_boxed();
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
    let mut chall1: Box<GenericArray<u8, O::CHALL1>> = GenericArray::default_boxed();
    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&mu);
    h2_hasher.update(&hcom);
    c.iter().for_each(|buf| h2_hasher.update(buf));
    h2_hasher.update(&iv);
    let mut reader = h2_hasher.finish();
    reader.read(&mut chall1);

    let vole_hasher = O::VoleHasher::new_vole_hasher(&chall1);
    let u_t = vole_hasher.process(&u);

    let mut h1_hasher = RO::<O>::h1_init();
    for v in gv.iter() {
        v.iter()
            .for_each(|v| h1_hasher.update(&vole_hasher.process(v)));
    }
    // why is this boxed?
    let mut hv: Box<GenericArray<u8, <RO<O> as RandomOracle>::PRODLAMBDA2>> =
        GenericArray::default_boxed();
    h1_hasher.finish().read(&mut hv);

    let w = C::witness::<P, O>(sk, pk);
    let d = GenericArray::from_iter(
        zip(
            // FIXME: remove collect
            w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>(),
            &u[..l],
        )
        .map(|(w, u)| w ^ *u),
    );

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

    let (a_t, b_t) = C::prove::<P, O>(
        GenericArray::from_slice(&w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>()),
        new_u,
        new_gv,
        pk,
        &chall2,
    );

    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&chall2);
    h2_hasher.update(&a_t);
    h2_hasher.update(&b_t);
    // why is this boxed?
    let mut chall3: Box<GenericArray<u8, P::LAMBDABYTES>> = GenericArray::default_boxed();
    h2_hasher.finish().read(&mut chall3);

    let mut pdecom: Box<GenericArray<(Vec<GenericArray<u8, O::LAMBDABYTES>>, Vec<u8>), P::TAU>> =
        GenericArray::default_boxed();
    for i in 0..tau {
        if i < t0 {
            let s = chaldec::<P>(&chall3, i as u16);
            pdecom[i] = open::<RO<O>, P::POWK0, P::K0, P::N0>(
                &decom[i],
                (*GenericArray::from_slice(&s)).clone(),
            );
        } else {
            let s = chaldec::<P>(&chall3, i as u16);
            pdecom[i] = open::<RO<O>, P::POWK1, P::K1, P::N1>(
                &decom[i],
                (*GenericArray::from_slice(&s)).clone(),
            );
        }
    }
    (
        Box::new(
            c.iter()
                .map(|x| (*GenericArray::from_slice(&x[..])).clone())
                .collect::<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>>(),
        ),
        u_t,
        d,
        *a_t,
        pdecom,
        (*GenericArray::from_slice(&chall3)).clone(),
        iv,
    )

    /* (Box::default(), GenericArray::default(),  GenericArray::default(), GenericArray::default(), Box::default(), GenericArray::default(), GenericArray::default()) */
}

#[allow(unused_assignments)]
#[allow(clippy::type_complexity)]
pub fn faest_verify<C, P, O>(
    msg: &[u8],
    pk: GenericArray<u8, O::PK>,
    sigma: (
        Box<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>>,
        GenericArray<u8, O::LAMBDAPLUS2>,
        GenericArray<u8, O::LBYTES>,
        GenericArray<u8, O::LAMBDABYTES>,
        Box<GenericArray<(Vec<GenericArray<u8, O::LAMBDABYTES>>, Vec<u8>), P::TAU>>,
        GenericArray<u8, P::LAMBDABYTES>,
        [u8; 16],
    ),
) -> bool
where
    C: Variant,
    P: PARAM,
    O: PARAMOWF,
{
    let lambda = <O::LAMBDA as Unsigned>::to_usize() / 8;
    let l = <P::L as Unsigned>::to_usize() / 8;
    let _b = <P::B as Unsigned>::to_usize() / 8;
    let tau = <P::TAU as Unsigned>::to_usize();
    let _k0 = <P::K0 as Unsigned>::to_u16();
    let _k1 = <P::K1 as Unsigned>::to_u16();
    let _t0 = <P::TAU0 as Unsigned>::to_u16();
    let _t1 = <P::TAU1 as Unsigned>::to_u16();
    let (c, u_t, d, a_t, pdecom, chall3, iv) = sigma;

    let mut h1_hasher = RO::<O>::h1_init();
    h1_hasher.update(&pk);
    h1_hasher.update(msg);
    // why is this boxed?
    let mut mu: Box<GenericArray<u8, <RO<O> as RandomOracle>::PRODLAMBDA2>> =
        GenericArray::default_boxed();
    h1_hasher.finish().read(&mut mu);

    let (hcom, gq_p) = volereconstruct::<RO<O>, P>(
        &chall3,
        &GenericArray::from_iter(
            (*pdecom)
                .into_iter()
                .map(|(l, r)| (l, GenericArray::from_slice(&r).clone())),
        ),
        iv,
    );

    let mut chall1: Box<GenericArray<u8, O::CHALL1>> = GenericArray::default_boxed();
    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&mu);
    h2_hasher.update(&hcom);
    c.iter().for_each(|buf| h2_hasher.update(buf));
    h2_hasher.update(&iv);
    let mut reader = h2_hasher.finish();
    reader.read(&mut chall1);

    let vole_hasher = O::VoleHasher::new_vole_hasher(&chall1);
    let mut gq: Box<GenericArray<Vec<GenericArray<u8, <P as PARAM>::LH>>, P::TAU>> =
        GenericArray::default_boxed();
    let mut gd_t: Box<GenericArray<Vec<GenericArray<u8, O::LAMBDAPLUS2>>, O::LAMBDALBYTES>> =
        GenericArray::default_boxed();
    gq[0] = gq_p[0].clone();
    let delta0 = chaldec::<P>(&chall3, 0);
    gd_t[0] = delta0
        .iter()
        .map(|d| {
            if *d == 1 {
                u_t.clone()
            } else {
                GenericArray::default()
            }
        })
        .collect();
    for i in 1..tau {
        /* ok */
        let delta = chaldec::<P>(&chall3, i as u16);
        gd_t[i] = delta
            .iter()
            .map(|d| {
                if *d == 1 {
                    u_t.clone()
                } else {
                    GenericArray::default()
                }
            })
            .collect::<Vec<_>>();
        let dtemp: Vec<GenericArray<u8, O::LHATBYTES>> = delta
            .into_iter()
            .map(|d| {
                if d == 1 {
                    c[i - 1].clone()
                } else {
                    GenericArray::default()
                }
            })
            .collect::<Vec<GenericArray<u8, O::LHATBYTES>>>();
        let mut temp: Vec<GenericArray<u8, P::LH>> = vec![GenericArray::default()];
        temp = zip(gq_p[i].clone(), dtemp)
            .map(|(q, d)| {
                (*GenericArray::from_slice(
                    &zip(q, d)
                        .map(|(q, d)| q ^ d)
                        .collect::<GenericArray<u8, P::LH>>(),
                ))
                .clone()
            })
            .collect();
        gq[i] = temp;
    }
    let gq_t: GenericArray<Box<GenericArray<u8, O::LAMBDAPLUS2>>, O::LAMBDA> = gq
        .iter()
        .flat_map(|q| {
            q.iter()
                .map(|q| Box::new(vole_hasher.process(q)))
                .collect::<Vec<Box<GenericArray<u8, O::LAMBDAPLUS2>>>>()
        })
        .collect();

    // why is this a box?
    let mut hv: Box<GenericArray<u8, <RO<O> as RandomOracle>::PRODLAMBDA2>> =
        GenericArray::default_boxed();
    let mut h1_hasher = RO::<O>::h1_init();
    // FIXME!
    h1_hasher.update(
        &zip(
            gq_t,
            gd_t.into_iter()
                .flatten()
                .collect::<Box<GenericArray<GenericArray<u8, O::LAMBDAPLUS2>, O::LAMBDA>>>(),
        )
        .flat_map(|(q, d)| zip(q, d).map(|(q, d)| q ^ d).collect::<Vec<u8>>())
        .collect::<Vec<u8>>(),
    );
    h1_hasher.finish().read(&mut hv);

    let mut chall2: Box<GenericArray<u8, O::CHALL>> = GenericArray::default_boxed();
    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&chall1);
    h2_hasher.update(&u_t);
    h2_hasher.update(&hv);
    h2_hasher.update(&d);
    h2_hasher.finish().read(&mut chall2);

    let b_t = C::verify::<P, O>(
        &d,
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
        &a_t,
        &chall2,
        &chall3,
        &pk,
    );

    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&chall2);
    h2_hasher.update(&a_t);
    h2_hasher.update(&b_t);
    let mut chall3_p: GenericArray<u8, P::LAMBDABYTES> = GenericArray::default();
    h2_hasher.finish().read(&mut chall3_p);
    chall3 == chall3_p
}

#[allow(clippy::type_complexity)]
pub fn sigma_to_signature<P, O>(
    sigma: (
        Box<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>>,
        GenericArray<u8, O::LAMBDAPLUS2>,
        GenericArray<u8, O::LBYTES>,
        GenericArray<u8, O::LAMBDABYTES>,
        Box<GenericArray<(Vec<GenericArray<u8, O::LAMBDABYTES>>, Vec<u8>), P::TAU>>,
        GenericArray<u8, P::LAMBDABYTES>,
        [u8; 16],
    ),
) -> GenericArray<u8, P::SIG>
where
    O: PARAMOWF,
    P: PARAM,
{
    let mut signature = sigma
        .0
        .into_iter()
        .flat_map(|x| x.to_vec())
        .collect::<Vec<u8>>();
    signature.append(&mut (*sigma.1).to_vec());
    signature.append(&mut (*sigma.2).to_vec());
    signature.append(&mut (*sigma.3).to_vec());
    signature.append(
        &mut sigma
            .4
            .into_iter()
            .flat_map(|x| [x.0.into_iter().flatten().collect::<Vec<u8>>(), x.1].concat())
            .collect::<Vec<u8>>(),
    );
    signature.append(&mut (*sigma.5).to_vec());
    signature.append(&mut (sigma.6).to_vec());

    return (*GenericArray::from_slice(&signature)).clone();
}

#[allow(clippy::type_complexity)]
pub fn signature_to_sigma<P, O>(
    signature: &[u8],
) -> (
    Box<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>>,
    GenericArray<u8, O::LAMBDAPLUS2>,
    GenericArray<u8, O::LBYTES>,
    GenericArray<u8, O::LAMBDABYTES>,
    Box<GenericArray<(Vec<GenericArray<u8, O::LAMBDABYTES>>, Vec<u8>), P::TAU>>,
    GenericArray<u8, P::LAMBDABYTES>,
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

    let u_tilde = (*GenericArray::from_slice(&signature[index..index + lambda + 2])).clone();
    index += lambda + 2;
    let d = (*GenericArray::from_slice(&signature[index..index + l])).clone();
    index += l;
    let a_tilde = (*GenericArray::from_slice(&signature[index..index + lambda])).clone();
    index += lambda;
    let mut pdecom: Box<GenericArray<(Vec<GenericArray<u8, O::LAMBDABYTES>>, Vec<u8>), P::TAU>> =
        GenericArray::default_boxed();
    for i in pdecom.iter_mut().take(tau0) {
        for _j in 0..k0 {
            i.0.push(GenericArray::from_slice(&signature[index..index + lambda]).clone());
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
    let chall3 = (*GenericArray::from_slice(&signature[index..index + lambda])).clone();
    index += lambda;
    let iv = signature[index..].try_into().unwrap();
    (c, u_tilde, d, a_tilde, pdecom, chall3, iv)
}
