use std::iter::zip;

use crate::{
     parameter::{self, BaseParameters, TauParameters, Variant, PARAM, PARAMOWF}, random_oracles::{Hasher, RandomOracle, Reader, IV}, universal_hashing::{VoleHasherInit, VoleHasherProcess}, vc::open, vole::{volecommit, volereconstruct}
};

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
) -> (
    Box<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>>,
    GenericArray<u8, O::LAMBDAPLUS2>,
    GenericArray<u8, O::LBYTES>,
    GenericArray<u8, O::LAMBDABYTES>,
    Box<GenericArray<(Vec<GenericArray<u8, O::LAMBDABYTES>>, Vec<u8>), P::TAU>>,
    GenericArray<u8, P::LAMBDABYTES>,
    IV,
)
where
    P: PARAM,
    O: PARAMOWF + PARAMOWF<LAMBDABYTES = P::LAMBDABYTES> + PARAMOWF<PK = <<P as parameter::PARAM>::OWF as PARAMOWF>::PK> + PARAMOWF<LAMBDA = P::LAMBDA> + PARAMOWF<CHALL = <<P as parameter::PARAM>::OWF as PARAMOWF>::CHALL> + PARAMOWF<LAMBDALBYTES = <<P as parameter::PARAM>::OWF as PARAMOWF>::LAMBDALBYTES>,
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
    let d = GenericArray::from_iter(zip(w.iter(), &u[..l]).map(|(w, u)| w ^ *u));

    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&chall1);
    h2_hasher.update(&u_t);
    h2_hasher.update(&hv);
    h2_hasher.update(&d);
    // why is this boxed?
    let mut chall2: GenericArray<u8, O::CHALL> = GenericArray::default();
    h2_hasher.finish().read(&mut chall2);

    let new_u = GenericArray::from_slice(&u[..l + lambda]);
    let new_gv: GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA> = 
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
            .collect::<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>()
    ;

    let (a_t, b_t) = P::Cypher::prove::<P>(&w, new_u, &new_gv, pk, &chall2);

    let mut h2_hasher = RO::<O>::h2_init();
    h2_hasher.update(&chall2);
    h2_hasher.update(&a_t);
    h2_hasher.update(&b_t);
    let mut chall3 = GenericArray::default();
    h2_hasher.finish().read(&mut chall3);

    let mut pdecom = GenericArray::default_boxed();
    for i in 0..tau {
        let s = P::Tau::decode_challenge(&chall3, i);
        if i < t0 {
            pdecom[i] =
                open::<RO<O>, P::POWK0, P::K0, P::N0>(&decom[i], GenericArray::from_slice(&s));
        } else {
            pdecom[i] =
                open::<RO<O>, P::POWK1, P::K1, P::N1>(&decom[i], GenericArray::from_slice(&s));
        }
    }
    (
        Box::new(
            c.iter()
                .map(|x| GenericArray::from_slice(&x[..]).clone())
                .collect::<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>>(),
        ),
        u_t,
        d,
        a_t,
        pdecom,
        chall3,
        iv,
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

#[allow(clippy::type_complexity)]
pub fn sigma_to_signature<P, O>(
    sigma: (
        Box<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>>,
        GenericArray<u8, O::LAMBDAPLUS2>,
        GenericArray<u8, O::LBYTES>,
        GenericArray<u8, O::LAMBDABYTES>,
        Box<GenericArray<(Vec<GenericArray<u8, O::LAMBDABYTES>>, Vec<u8>), P::TAU>>,
        GenericArray<u8, P::LAMBDABYTES>,
        IV,
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
    signature.extend_from_slice(&sigma.1);
    signature.extend_from_slice(&sigma.2);
    signature.extend_from_slice(&sigma.3);
    sigma.4.iter().for_each(|x| {
        x.0.iter().for_each(|v| signature.extend_from_slice(v));
        signature.extend_from_slice(&x.1);
    });
    signature.extend_from_slice(&sigma.5);
    signature.extend_from_slice(&sigma.6);

    let mut res = GenericArray::default();
    res.copy_from_slice(&signature);
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
