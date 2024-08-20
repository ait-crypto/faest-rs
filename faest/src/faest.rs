use cipher::Unsigned;
use rand::RngCore;
use typenum::{Quot, Sum, U16, U8};
use std::{iter::zip, ops::{Add, Div, Mul}};
use generic_array::{GenericArray, ArrayLength, sequence::GenericSequence};
use crate::{
    aes::{aes_extendedwitness, aes_prove, aes_verify, aes_witness_has0},
    em::{em_extendedwitness, em_prove, em_verify, em_witness_has0},
    fields::BigGaloisField,
    parameter::{self, PARAM, PARAMOWF},
    random_oracles::RandomOracle,
    rijndael_32::{rijndael_encrypt, rijndael_key_schedule},
    universal_hashing::volehash,
    vc::open,
    vole::{chaldec, volecommit, volereconstruct},
};


pub trait Variant {
    ///input : key (len lambda, snd part of sk); public key
    ///output : witness of l bits
    fn witness<P, O>(k: &GenericArray<u8, O::SK>, pk: &GenericArray<u8, O::PK>) -> GenericArray<u8, P::LBYTES>
    where
        P: PARAM,
        O: PARAMOWF;

    ///input : witness of l bits, masking values (l+lambda in aes, lambda in em), Vole tag ((l + lambda) *lambda bits), public key, chall(3lambda + 64)
    ///Output : QuickSilver response (Lambda bytes)
    fn prove<P, O, T>(
        w: &GenericArray<u8, P::LBYTES>,
        u: &GenericArray<u8, O::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, O::LAMBDABYTES>, O::LAMBDALBYTES>,
        pk: &GenericArray<u8, O::PK>,
        chall: &GenericArray<u8, O::CHALL2>
    ) -> (GenericArray<u8, O::LAMBDABYTES>, GenericArray<u8, O::LAMBDABYTES>)
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug;

    ///input : Masked witness (l bits), Vole Key ((l + lambda) * Lambda bits), hash of constrints values (lambda bits), chall2 (3*lambda + 64 bits), chall3 (lambda bits), public key
    ///output q_tilde - delta * a_tilde (lambda bytes)
    fn verify<P, O, T>(
        d: &GenericArray<u8, P::LBYTES>,
        gq: &GenericArray<GenericArray<u8, O::LAMBDABYTES>, O::LAMBDALBYTES>,
        a_t: &GenericArray<u8, O::LAMBDABYTES>,
        chall2: &GenericArray<u8, O::CHALL>,
        chall3: &GenericArray<u8, O::LAMBDABYTES>,
        pk: &GenericArray<u8, O::PK>,
    ) -> GenericArray<u8, O::LAMBDABYTES>
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug;

    ///input : a random number generator
    /// output = pk : input, output; sk : input, key; rho (len = Lambda bytes)
    fn keygen_with_rng<P, O>(rng: impl RngCore) -> (GenericArray<u8, O::PK>, GenericArray<u8, O::SK>, GenericArray<u8, O::LAMBDABYTES>)
    where
        P: PARAM,
        O: PARAMOWF;
}

pub struct AesCypher {}

impl Variant for AesCypher {
    fn witness<P, O>(k: &GenericArray<u8, O::LAMBDABYTES>, pk: &GenericArray<u8, O::PK>) -> GenericArray<u8, P::LBYTES>
    where
        P: PARAM,
        O: PARAMOWF,
    {
        aes_extendedwitness::<P, O>(k, pk)
    }

    fn prove<P, O, T>(
        w: &GenericArray<u8, P::LBYTES>,
        u: &GenericArray<u8, O::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, O::LAMBDABYTES>, O::LAMBDALBYTES>,
        pk: &GenericArray<u8, O::PK>,
        chall: &GenericArray<u8, O::CHALL>
    ) -> (GenericArray<u8, O::LAMBDALBYTES>, GenericArray<u8, O::LAMBDALBYTES>)
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug,
    {
        aes_prove::<T, P, O>(w, u, gv, pk, chall)
    }

    fn verify<P, O, T>(
        d: &GenericArray<u8, P::LBYTES>,
        gq: &GenericArray<GenericArray<u8, O::LAMBDABYTES>, O::LAMBDALBYTES>,
        a_t: &GenericArray<u8, O::LAMBDABYTES>,
        chall2: &GenericArray<u8, O::CHALL>,
        chall3: &GenericArray<u8, O::LAMBDABYTES>,
        pk: &GenericArray<u8, O::PK>,
    ) -> GenericArray<u8, O::LAMBDABYTES>
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug,
    {
        aes_verify::<T, P, O>(d, gq, a_t, chall2, chall3, pk)
    }

    ///Input : the parameter of the faest protocol
    /// Output : sk : inputOWF||keyOWF, pk : inputOWF||outputOWF
    #[allow(clippy::never_loop)]
    fn keygen_with_rng<P, O>(mut rng: impl RngCore) -> (GenericArray<u8, O::PK>, GenericArray<u8, O::SK>, GenericArray<u8, O::LAMBDABYTES>)
    where
        P: PARAM,
        O: PARAMOWF,
    {
        let nk = <O::NK as Unsigned>::to_u8();
        let r = <O::R as Unsigned>::to_u8();
        let beta = <P::BETA as Unsigned>::to_u8();
        'boucle: loop {
            let mut rho : GenericArray<u8, O::LAMBDABYTES> = GenericArray::generate(|i: usize| 0u8);
            let mut sk: GenericArray<u8, O::SK> = GenericArray::generate(|i: usize| 0u8);
            let mut y: Vec<u8>;
            rng.fill_bytes(&mut sk);
            // S'occupper de y#################################################################################333
            if beta == 1 {
                y = aes_witness_has0::<P, O>(&sk[16..], &sk[..16]);
            } else {
                y = aes_witness_has0::<P, O>(&sk[32..], &sk[..32]);
            };
            for elem in &mut y {
                if *elem == 0 {
                    continue 'boucle;
                }
            }
            let mut cypher: cipher::array::Array<
                aes::cipher::generic_array::GenericArray<u8, _>,
                _,
            >;
            let rk = rijndael_key_schedule(&sk[16 * <P::BETA as Unsigned>::to_usize()..], 4, <O::NK as Unsigned>::to_u8(), <O::R as Unsigned>::to_u8(), <O::SKE as Unsigned>::to_u8());
            if beta == 1 {
                cypher = rijndael_encrypt(&rk, &[&sk[..16], &[0u8; 16]].concat(), 4, nk, r);
                y = cypher.into_iter().flatten().take(16).collect();
            } else {
                cypher = rijndael_encrypt(&rk, &[&sk[..16], &[0u8; 16]].concat(), 4, nk, r);
                y = cypher.into_iter().flatten().take(16).collect();
                cypher = rijndael_encrypt(&rk, &[&sk[16..32], &[0u8; 16]].concat(), 4, nk, r);
                y.append(&mut cypher.into_iter().flatten().take(16).collect());
            };
            rng.fill_bytes(&mut rho);
            return (
                *GenericArray::from_slice(&[&sk[..16 * beta as usize], &y[..]].concat()),
                sk,
                rho,
            );
        }
    }
}

pub struct EmCypher {}

impl Variant for EmCypher {
    fn witness<P, O>(k: &GenericArray<u8, O::LAMBDABYTES>, pk: &GenericArray<u8, O::PK>) -> GenericArray<u8, P::LBYTES>
    where
        P: PARAM,
        O: PARAMOWF,
    {
        em_extendedwitness::<P, O>(k, pk)
    }

    fn prove<P, O, T>(
        w: &GenericArray<u8, P::LBYTES>,
        u: &GenericArray<u8, O::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, O::LAMBDABYTES>, O::LAMBDALBYTES>,
        pk: &GenericArray<u8, O::PK>,
        chall: &GenericArray<u8, O::CHALL>
    ) -> (GenericArray<u8, O::LAMBDALBYTES>, GenericArray<u8, O::LAMBDALBYTES>)
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug,
    {
        em_prove::<T, P, O>(w, u, gv, pk, chall)
    }

    fn verify<P, O, T>(
        d: &GenericArray<u8, P::LBYTES>,
        gq: &GenericArray<GenericArray<u8, O::LAMBDABYTES>, O::LAMBDALBYTES>,
        a_t: &GenericArray<u8, O::LAMBDABYTES>,
        chall2: &GenericArray<u8, O::CHALL>,
        chall3: &GenericArray<u8, O::LAMBDABYTES>,
        pk: &GenericArray<u8, O::PK>,
    ) -> GenericArray<u8, O::LAMBDABYTES>
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug,
    {
        em_verify::<T, P, O>(d, gq, a_t, chall2, chall3, pk)
    }

    fn keygen_with_rng<P, O>(mut rng: impl RngCore) -> (GenericArray<u8, O::PK>, GenericArray<u8, O::SK>, GenericArray<u8, O::LAMBDABYTES>)
    where
        P: PARAM,
        O: PARAMOWF,
    {
        let lambda = <O::LAMBDA as Unsigned>::to_usize() / 8;
        let nk = <O::NK as Unsigned>::to_u8();
        let r = <O::R as Unsigned>::to_u8();
        let nst = <O::NST as Unsigned>::to_u8();
        'boucle: loop {
            let mut rho : GenericArray<u8, O::LAMBDABYTES> = GenericArray::generate(|i: usize| 0u8);
            let mut sk :GenericArray<u8, O::SK> = GenericArray::generate(|i: usize| 0u8);
            rng.fill_bytes(&mut sk);
            let mut y = em_witness_has0::<P, O>(&sk[lambda..], &sk[..lambda]);
            for elem in &mut y {
                if *elem == 0 {
                    continue 'boucle;
                }
            }
            let rk = rijndael_key_schedule(&sk[..lambda], nst, nk, r, 4 * (((r + 1) * nst) / nk));
            let cypher = rijndael_encrypt(
                &rk,
                &[&sk[lambda..], &vec![0u8; 32 - lambda]].concat(),
                nst,
                nk,
                r,
            );
            y = cypher
                .into_iter()
                .flatten()
                .take(lambda)
                .zip(&sk[lambda..])
                .map(|(y, k)| y ^ k)
                .collect();
            rng.fill_bytes(&mut rho);
            return (*GenericArray::from_slice(&[&sk[..lambda], &y[..]].concat()), sk, rho);
        }
    }
}

///input : Message (an array of bytes), sk : secret key, pk : public key, rho : lambda bits
///output : correction string (tau - 1 * (l_hat bits)), Hash of VOLE sceet (LAMBDA + 16 bits), Commitment to the witness (l bits)
/// Quicksilver proof (Lambda), Partial decommitment (Tau * (t0 * k0*lambda + t1 * k1*lambda  +  2Lambda) bits), 
///last challenge (lambda bits), initialisation vector
#[allow(clippy::needless_range_loop)]
#[allow(clippy::type_complexity)]
#[allow(clippy::unnecessary_to_owned)]
pub fn faest_sign<T, R, C, P, O>(
    msg: &[u8],
    sk: &GenericArray<u8, O::SK>,
    pk: &GenericArray<u8, O::PK>,
    rho: &GenericArray<u8, O::LAMBDA>,
) -> (
    GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>,
    GenericArray<u8, O::LAMBDAPLUSTWO>,
    GenericArray<u8, O::LBYTES>,
    GenericArray<u8, O::LAMBDABYTES>,
    GenericArray<(GenericArray<Vec<u8>, P::TAU>, GenericArray<u8, O::LAMBDADOUBLE>), P::TAU>,
    GenericArray<u8, O::LAMBDABYTES>,
    GenericArray<u8, U16>,
)
where
    T: BigGaloisField + std::default::Default + std::fmt::Debug,
    C: Variant,
    R: RandomOracle,
    P: PARAM,
    O: PARAMOWF,
{
    let lambda = <O::LAMBDA as Unsigned>::to_usize() / 8;
    let l = (<P::L as Unsigned>::to_usize() / 8);
    let b = (<P::B as Unsigned>::to_usize() / 8);
    let tau = <P::TAU as Unsigned>::to_usize();
    let k0 = <P::K0 as Unsigned>::to_u16();
    let k1 = <P::K1 as Unsigned>::to_u16();
    let mut mu : GenericArray<u8, O::LAMBDADOUBLE> = GenericArray::generate(|i: usize| 0u8);
    R::h1(&[pk, msg].concat(), &mut mu);
    let mut riv : GenericArray<u8, O::LAMBDAPLUS16> = GenericArray::generate(|i: usize| 0u8);
    R::h3(&[sk.to_vec(), mu.to_vec(), rho.to_vec()].concat(), &mut riv);
    let (r, iv) = (GenericArray::from_slice(&riv[..lambda]), GenericArray::from_slice(&riv[lambda..]));
    let (hcom, decom, c, mut u, gv) = volecommit::<T, R>(
        r,
        u128::from_be_bytes(iv.into_array()),
        l + 2 * lambda + b,
        tau,
        k0,
        k1,
    );
    let mut chall1 : GenericArray<u8, O::CHALL1> = GenericArray::generate(|i: usize| 0u8);
    R::h2(
        &[
            mu.to_vec(),
            hcom.to_vec(),
            c.clone().into_iter().flatten().collect::<Vec<u8>>(),
            iv.to_vec(),
        ]
        .concat(),
        &mut chall1,
    );
    let u_t = volehash::<T>(
        &chall1,
        u[..l + lambda].to_vec(),
        &u[l + lambda..],
        l * 8,
        b,
    );
    let gv_t: Vec<Vec<Vec<u8>>> = gv
        .iter()
        .map(|v| {
            v.iter()
                .map(|v| {
                    volehash::<T>(
                        &chall1,
                        v[..l + lambda].to_vec(),
                        &v[l + lambda..],
                        l * 8,
                        b,
                    )
                })
                .collect()
        })
        .collect();
    let mut hv : GenericArray<u8, O::LAMBDADOUBLE> = GenericArray::generate(|i: usize| 0u8);
    R::h1(
        &gv_t.into_iter().flatten().flatten().collect::<Vec<u8>>()[..],
        &mut hv,
    );
    let w = C::witness::<P, O>(sk, pk);
    let d = GenericArray::from_slice(&zip(
        w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>(),
        &mut u[..l],
    )
    .map(|(w, u)| w ^ *u)
    .collect::<Vec<u8>>()[..]);
    let mut chall2 : GenericArray<u8, O::CHALL2> = GenericArray::generate(|i: usize| 0u8);
    R::h2(&[chall1.to_vec(), u_t.to_vec(), hv.to_vec(), d.to_vec()].concat(), &mut chall2);
    let new_u = GenericArray::from_slice(&u[..l + lambda]);
    let new_gv = gv
        .iter()
        .map(|x| {
            x.iter()
                .map(|y| y.clone().into_iter().take(l + lambda).collect::<Vec<u8>>())
                .collect::<Vec<Vec<u8>>>()
        })
        .collect::<Vec<Vec<Vec<u8>>>>();

    let (a_t, b_t) = C::prove::<P, O, T>(
        GenericArray::from_slice(&w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>()),
        new_u,
        &(new_gv.to_vec())
            .into_iter()
            .flatten()
            .collect::<Vec<Vec<u8>>>()[..],
        pk,
        &chall2,
    );
    let mut chall3 : GenericArray<u8, O::LAMBDABYTES> = GenericArray::generate(|i: usize| 0u8);
    R::h2(&[chall2.to_vec(), a_t.to_vec(), b_t.to_vec()].concat(), &mut chall3);
    let mut pdecom = Vec::with_capacity(tau);
    for i in 0..tau {
        let s = chaldec(
            &chall3.to_vec(),
            k0,
            <P::TAU0 as Unsigned>::to_u16().into(),
            k1,
            <P::TAU1>::to_u16().into(),
            i as u16,
        );
        pdecom.push(open(&decom[i], s));
    }
    (
        c,
        u_t,
        d,
        a_t,
        pdecom,
        chall3,
        *iv,
    )
}

#[allow(unused_assignments)]
#[allow(clippy::type_complexity)]
pub fn faest_verify<T, R, C, P, O>(
    msg: &[u8],
    pk: GenericArray<u8, O::PK>,
    sigma: (
        GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>,
        GenericArray<u8, O::LAMBDAPLUSTWO>,
        GenericArray<u8, O::LBYTES>,
        GenericArray<u8, O::LAMBDABYTES>,
        GenericArray<(GenericArray<Vec<u8>, P::TAU>, GenericArray<u8, O::LAMBDADOUBLE>), P::TAU>,
        GenericArray<u8, O::LAMBDABYTES>,
        GenericArray<u8, U16>,
    ),
) -> bool
where
    T: BigGaloisField + std::default::Default + std::fmt::Debug,
    R: RandomOracle,
    C: Variant,
    P: PARAM,
    O: PARAMOWF,
{
    let lambda = <O::LAMBDA as Unsigned>::to_usize() / 8;
    let l = (<P::L as Unsigned>::to_usize() / 8);
    let b = (<P::B as Unsigned>::to_usize() / 8);
    let tau = <P::TAU as Unsigned>::to_usize();
    let k0 = <P::K0 as Unsigned>::to_u16();
    let k1 = <P::K1 as Unsigned>::to_u16();
    let t0 = <P::TAU0 as Unsigned>::to_u16();
    let t1 = <P::TAU1 as Unsigned>::to_u16();
    let (c, u_t, d, a_t, pdecom, chall3, iv) = sigma;
    
    let mut mu : GenericArray<u8, O::LAMBDADOUBLE> = GenericArray::generate(|i: usize| 0u8);
    R::h1(&[pk.to_vec(), msg.to_vec()].concat(), &mut mu);
    let (hcom, gq_p) = volereconstruct::<T, R>(
        &chall3,
        pdecom,
        u128::from_be_bytes(iv),
        l + 2 * lambda + b,
        tau,
        t0,
        t1,
        k0,
        k1,
        lambda,
    );
    let mut chall1 : GenericArray<u8, O::CHALL1> = GenericArray::generate(|i: usize| 0u8);
    R::h2(
        &[
            mu,
            hcom,
            c.clone().into_iter().flatten().collect::<Vec<u8>>(),
            iv.to_vec(),
        ]
        .concat(),
        &mut chall1,
    );
    let mut gq = Vec::with_capacity(tau);
    let mut gd_t: Vec<Vec<Vec<u8>>> = Vec::with_capacity(tau);
    gq.push(gq_p[0].clone());
    let delta0 = chaldec(&chall3, k0, t0, k1, t1, 0);
    gd_t.push(
        delta0
            .iter()
            .map(|d| {
                if *d == 1 {
                    u_t.clone()
                } else {
                    vec![0; lambda + b]
                }
            })
            .collect(),
    );
    for i in 1..tau {
        /* ok */
        let delta = chaldec(&chall3, k0, t0, k1, t1, i as u16);
        gd_t.push(
            delta
                .iter()
                .map(|d| {
                    if *d == 1 {
                        u_t.clone()
                    } else {
                        vec![0; lambda + b]
                    }
                })
                .collect(),
        );
        let dtemp: Vec<Vec<u8>> = delta
            .iter()
            .map(|d| {
                if *d == 1 {
                    c[i - 1].clone()
                } else {
                    vec![0; l + 2 * lambda + 2]
                }
            })
            .collect();
        let mut temp = vec![vec![0u8]];
        temp = zip(gq_p[i].clone(), dtemp)
            .map(|(q, d)| zip(q, d).map(|(q, d)| q ^ d).collect())
            .collect();
        gq.push(temp);
    }
    let gq_t: Vec<Vec<Vec<u8>>> = gq
        .iter()
        .map(|q| {
            q.iter()
                .map(|q| {
                    volehash::<T>(
                        &chall1,
                        q[..l + lambda].to_vec(),
                        &q[l + lambda..],
                        l * 8,
                        b,
                    )
                })
                .collect()
        })
        .collect();
    let mut hv = vec![0; 2 * lambda];
    R::h1(
        &zip(
            gq_t.into_iter().flatten().collect::<Vec<Vec<u8>>>(),
            gd_t.into_iter().flatten().collect::<Vec<Vec<u8>>>(),
        )
        .flat_map(|(q, d)| zip(q, d).map(|(q, d)| q ^ d).collect::<Vec<u8>>())
        .collect::<Vec<u8>>(),
        &mut hv,
    );
    let mut chall2 = vec![0; 3 * lambda + 8];
    R::h2(&[chall1.clone(), u_t, hv, d.clone()].concat(), &mut chall2);
    let b_t = C::verify::<P, O, T>(
        &d,
        gq.iter()
            .flat_map(|x| {
                x.iter()
                    .map(|y| y.clone().into_iter().take(l + lambda).collect::<Vec<u8>>())
                    .collect::<Vec<Vec<u8>>>()
            })
            .collect::<Vec<Vec<u8>>>(),
        &a_t,
        &chall2,
        &chall3,
        &[pk.0, pk.1].concat(),
    );
    let mut chall3_p = vec![0; lambda];
    R::h2(&[chall2, a_t, b_t].concat(), &mut chall3_p);
    chall3 == chall3_p
}

#[allow(clippy::type_complexity)]
pub fn sigma_to_signature(
    mut sigma: (
        Vec<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<(Vec<Vec<u8>>, Vec<u8>)>,
        Vec<u8>,
        [u8; 16],
    ),
) -> Vec<u8> {
    let mut signature = sigma.0.into_iter().flatten().collect::<Vec<u8>>();
    signature.append(&mut sigma.1);
    signature.append(&mut sigma.2);
    signature.append(&mut sigma.3);
    signature.append(
        &mut sigma
            .4
            .into_iter()
            .flat_map(|x| [x.0.into_iter().flatten().collect::<Vec<u8>>(), x.1].concat())
            .collect::<Vec<u8>>(),
    );
    signature.append(&mut sigma.5);
    signature.append(&mut sigma.6.to_vec());

    signature
}

#[allow(clippy::type_complexity)]
pub fn signature_to_sigma<P, O>(
    signature: &[u8],
) -> (
    Vec<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<(Vec<Vec<u8>>, Vec<u8>)>,
    Vec<u8>,
    [u8; 16],
)
where
    P: PARAM,
    O: PARAMOWF,
{
    let mut index = 0;
    let tau = <P::TAU as Unsigned>::to_usize();
    let lambda = <P::LAMBDA as Unsigned>::to_usize() / 8;
    let l = (<P::L as Unsigned>::to_usize() / 8);
    let k0 = <P::K0 as Unsigned>::to_usize();
    let k1 = <P::K1 as Unsigned>::to_usize();
    let tau0 = <P::TAU0 as Unsigned>::to_usize();
    let tau1 = <P::TAU1 as Unsigned>::to_usize();
    let l_b = l + 2 * lambda + 2;
    let mut c = vec![Vec::with_capacity(l_b); tau - 1];
    for i in c.iter_mut().take(tau - 1) {
        i.append(&mut signature[index..index + l_b].to_vec());
        index += l_b;
    }
    let u_tilde = signature[index..index + lambda + 2].to_vec();
    index += lambda + 2;
    let d = signature[index..index + l].to_vec();
    index += l;
    let a_tilde = signature[index..index + lambda].to_vec();
    index += lambda;
    let mut pdecom: Vec<(Vec<Vec<u8>>, Vec<u8>)> = [
        vec![
            (
                vec![Vec::with_capacity(lambda); k0],
                Vec::with_capacity(lambda + 16)
            );
            tau0
        ],
        vec![
            (
                vec![Vec::with_capacity(lambda); k1],
                Vec::with_capacity(lambda + 16)
            );
            tau1
        ],
    ]
    .concat();
    for i in pdecom.iter_mut().take(tau0) {
        for j in 0..k0 {
            i.0[j].append(&mut signature[index..index + lambda].to_vec());
            index += lambda;
        }
        i.1.append(&mut signature[index..index + 2 * lambda].to_vec());
        index += 2 * lambda;
    }
    for i in 0..tau1 {
        for j in 0..k1 {
            pdecom[tau0 + i].0[j].append(&mut signature[index..index + lambda].to_vec());
            index += lambda;
        }
        pdecom[tau0 + i]
            .1
            .append(&mut signature[index..index + 2 * lambda].to_vec());
        index += 2 * lambda;
    }
    let chall3 = signature[index..index + lambda].to_vec();
    index += lambda;
    let iv: [u8; 16] = signature[index..].try_into().unwrap();
    (c, u_tilde, d, a_tilde, pdecom, chall3, iv)
}
