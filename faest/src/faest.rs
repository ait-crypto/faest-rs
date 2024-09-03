use cipher::Unsigned;
use typenum::{U16};
use nist_pqc_seeded_rng::RngCore;
use std::{iter::zip};
use generic_array::{GenericArray};
use crate::{
    aes::{aes_extendedwitness, aes_prove, aes_verify},
    em::{em_extendedwitness, em_prove, em_verify},
    fields::BigGaloisField,
    parameter::{PARAM, PARAMOWF},
    random_oracles::{RandomOracle},
    rijndael_32::{rijndael_encrypt, rijndael_key_schedule},
    universal_hashing::volehash,
    vc::open,
    vole::{chaldec, volecommit, volereconstruct},
};


pub trait Variant {
    ///input : key (len lambda, snd part of sk); public key
    ///output : witness of l bits
    fn witness<P, O, T>(k: &GenericArray<u8, O::LAMBDABYTES>, pk: &GenericArray<u8, O::PK>) -> Box<GenericArray<u8, O::LBYTES>>
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField;
       
    ///input : witness of l bits, masking values (l+lambda in aes, lambda in em), Vole tag ((l + lambda) *lambda bits), public key, chall(3lambda + 64)
    ///Output : QuickSilver response (Lambda bytes)
    fn prove<P, O, T>(
        w: &GenericArray<u8, O::L>,
        u: &GenericArray<u8, O::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        pk: &GenericArray<u8, O::PK>,
        chall: &GenericArray<u8, O::CHALL>
    ) -> (Box<GenericArray<u8, O::LAMBDABYTES>>, Box<GenericArray<u8, O::LAMBDABYTES>>)
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug;

    ///input : Masked witness (l bits), Vole Key ((l + lambda) * Lambda bits), hash of constrints values (lambda bits), chall2 (3*lambda + 64 bits), chall3 (lambda bits), public key
    ///output q_tilde - delta * a_tilde (lambda bytes)
    fn verify<P, O, T>(
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
        T: BigGaloisField + std::default::Default + std::fmt::Debug, 
        ;

    ///input : a random number generator
    /// output = pk : input, output; sk : input, key; rho (len = Lambda bytes)
    fn keygen_with_rng<P, O>(rng: impl RngCore) -> (GenericArray<u8, O::PK>, Box<GenericArray<u8, O::SK>>, Box<GenericArray<u8, O::LAMBDABYTES>>)
    where
        P: PARAM,
        O: PARAMOWF; 
}

pub struct AesCypher {}

impl Variant for AesCypher {
    fn witness<P, O, T>(k: &GenericArray<u8, O::LAMBDABYTES>, pk: &GenericArray<u8, O::PK>) -> Box<GenericArray<u8, O::LBYTES>>
    where
        P: PARAM,
        O: PARAMOWF, 
        T: BigGaloisField,
    {
        aes_extendedwitness::<P, O>(k, pk).0
    }

    fn prove<P, O, T>(
        w: &GenericArray<u8, O::L>,
        u: &GenericArray<u8, O::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        pk: &GenericArray<u8, O::PK>,
        chall: &GenericArray<u8, O::CHALL>
    ) -> (Box<GenericArray<u8, O::LAMBDABYTES>>, Box<GenericArray<u8, O::LAMBDABYTES>>)
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug, 
        
    {
        aes_prove::<T, P, O>(w, u, Box::new(gv), pk, chall)
    }

    fn verify<P, O, T>(
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
        T: BigGaloisField + std::default::Default + std::fmt::Debug, 
        
    {
        aes_verify::<T, P, O>(d, gq, a_t, chall2, chall3, pk)
    }

    ///Input : the parameter of the faest protocol
    /// Output : sk : inputOWF||keyOWF, pk : inputOWF||outputOWF
    #[allow(clippy::never_loop)]
    fn keygen_with_rng<P, O>(mut rng: impl RngCore) -> (GenericArray<u8, O::PK>, Box<GenericArray<u8, O::SK>>, Box<GenericArray<u8, O::LAMBDABYTES>>)
    where
        P: PARAM,
        O: PARAMOWF, 
    {
        let nk = <O::NK as Unsigned>::to_u8();
        let r = <O::R as Unsigned>::to_u8();
        let beta = <P::BETA as Unsigned>::to_u8();
        let pk_len = <O::PK as Unsigned>::to_usize()/2;
        'boucle: loop {
            let mut rho : Box<GenericArray<u8, O::LAMBDABYTES>> = GenericArray::default_boxed();
            let mut sk: Box<GenericArray<u8, O::SK>> = GenericArray::default_boxed();
            let test: bool;
            rng.fill_bytes(&mut sk);
            test = aes_extendedwitness::<P, O>(GenericArray::from_slice(&sk[pk_len..]), GenericArray::from_slice(&sk[..pk_len])).1;
            if test == false {
                continue 'boucle;
            }
            let mut cypher: cipher::array::Array<
                aes::cipher::generic_array::GenericArray<u8, _>,
                _,
            >;
            let rk = rijndael_key_schedule(&sk[16 * <P::BETA as Unsigned>::to_usize()..], 4, <O::NK as Unsigned>::to_u8(), <O::R as Unsigned>::to_u8(), <O::SKE as Unsigned>::to_u8()).0;
            let mut y : Box<GenericArray<u8, O::PK>> = GenericArray::default_boxed();
            let mut index = 0;
            if beta == 1 {
                cypher = rijndael_encrypt(&rk, &[&sk[..16], &[0u8; 16]].concat(), 4, nk, r);
                for i in cypher.into_iter().flatten().take(16).collect::<Vec<_>>(){
                    y[index] = i;
                    index+=1;
                }
            } else {
                cypher = rijndael_encrypt(&rk, &[&sk[..16], &[0u8; 16]].concat(), 4, nk, r);
                for i in cypher.into_iter().flatten().take(16).collect::<Vec<_>>(){
                    y[index] = i;
                    index+=1;
                }
                cypher = rijndael_encrypt(&rk, &[&sk[16..32], &[0u8; 16]].concat(), 4, nk, r);
                for i in cypher.into_iter().flatten().take(16).collect::<Vec<_>>(){
                    y[index] = i;
                    index+=1;
                }
            };
            rng.fill_bytes(&mut rho);
            return (
                (*GenericArray::from_slice(&[&sk[..16 * beta as usize], &y[..pk_len]].concat())).clone(),
                sk,
                rho,
            );
        }
    }
}

pub struct EmCypher {}

impl Variant for EmCypher {
    fn witness<P, O, T>(k: &GenericArray<u8, O::LAMBDABYTES>, pk: &GenericArray<u8, O::PK>) -> Box<GenericArray<u8, O::LBYTES>>
    where
        T: BigGaloisField,
        P: PARAM,
        O: PARAMOWF, 
        
    {
        em_extendedwitness::<P, O>(k, pk).0
    }

    fn prove<P, O, T>(
        w: &GenericArray<u8, O::L>,
        u: &GenericArray<u8, O::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        pk: &GenericArray<u8, O::PK>,
        chall: &GenericArray<u8, O::CHALL>
    ) -> (Box<GenericArray<u8, O::LAMBDABYTES>>, Box<GenericArray<u8, O::LAMBDABYTES>>)
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug, 
        
    {
        em_prove::<T, P, O>(w, u, gv, pk, chall)
    }

    fn verify<P, O, T>(
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
        T: BigGaloisField + std::default::Default + std::fmt::Debug, 
        
    {
        em_verify::<T, P, O>(d, gq, a_t, chall2, chall3, pk)
    }

    fn keygen_with_rng<P, O>(mut rng: impl RngCore) -> (GenericArray<u8, O::PK>, Box<GenericArray<u8, O::SK>>, Box<GenericArray<u8, O::LAMBDABYTES>>)
    where
        P: PARAM,
        O: PARAMOWF,
    {
        let lambda = <O::LAMBDA as Unsigned>::to_usize() / 8;
        let nk = <O::NK as Unsigned>::to_u8();
        let r = <O::R as Unsigned>::to_u8();
        let nst = <O::NST as Unsigned>::to_u8();
        'boucle: loop {
            let mut rho :Box<GenericArray<u8, O::LAMBDABYTES>> = GenericArray::default_boxed();
            let mut sk :Box<GenericArray<u8, O::SK>> = GenericArray::default_boxed();
            rng.fill_bytes(&mut sk);
            let test = em_extendedwitness::<P, O>(GenericArray::from_slice(&sk[lambda..]), GenericArray::from_slice(&sk[..lambda])).1;
            if test ==false {
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
            
            let y : GenericArray<u8, O::LAMBDA>= cypher
                .into_iter()
                .flatten()
                .take(lambda)
                .zip(&sk[lambda..])
                .map(|(y, k)| y ^ k)
                .collect();
            rng.fill_bytes(&mut rho);
            return ((*GenericArray::from_slice(&[&sk[..lambda], &y[..]].concat())).clone(), sk, rho);
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
    sk: &GenericArray<u8, O::LAMBDABYTES>,
    pk: &GenericArray<u8, O::PK>,
    rho: &GenericArray<u8, O::LAMBDA>,
) -> (
    Box<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>>,
    GenericArray<u8, O::LAMBDAPLUS2>,
    GenericArray<u8, O::LBYTES>,
    GenericArray<u8, O::LAMBDABYTES>,
    Box<GenericArray<(Vec<GenericArray<u8, R::LAMBDA>>, Vec<u8>), P::TAU>>,
    GenericArray<u8, P::LAMBDABYTES>,
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
    let l = <P::L as Unsigned>::to_usize() / 8;
    let _b = <P::B as Unsigned>::to_usize() / 8;
    let tau = <P::TAU as Unsigned>::to_usize();
    let t0 = <P::TAU0 as Unsigned>::to_usize();
    let _k0 = <P::K0 as Unsigned>::to_u16();
    let _k1 = <P::K1 as Unsigned>::to_u16();
    let mut mu : Box<GenericArray<u8, R::PRODLAMBDA2>> = GenericArray::default_boxed();
    R::h1(&[pk, msg].concat(), &mut mu);
    let mut riv : Box<GenericArray<u8, R::LAMBDA16>> = GenericArray::default_boxed();
    R::h3(&[sk.to_vec(), mu.to_vec(), rho.to_vec()].concat(), &mut riv);
    let (r, iv) = (GenericArray::from_slice(&riv[..lambda]), GenericArray::from_slice(&riv[lambda..]));
    let (hcom, decom, c, mut u, gv) = volecommit::<P, T, R>(
        r,
        u128::from_le_bytes(iv[..16].try_into().unwrap())
    );
    let mut chall1 : Box<GenericArray<u8, O::CHALL1>> = GenericArray::default_boxed();
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
    let u_t = volehash::<T, O>(
        &chall1,
        GenericArray::from_slice(&u[..l + lambda]),
        GenericArray::from_slice(&u[l + lambda..])
    );
    let gv_t: GenericArray<GenericArray<GenericArray<u8, O::LAMBDAPLUS2>, O::LAMBDA>, O::LAMBDALBYTES> = gv
        .iter()
        .map(|v| {
            v.iter()
                .map(|v| {
                    volehash::<T,O>(
                        &chall1,
                        GenericArray::from_slice(&v[..l + lambda]),
                        GenericArray::from_slice(&v[l + lambda..])
                    )
                })
                .collect()
        })
        .collect();
    let mut hv : Box<GenericArray<u8, R::PRODLAMBDA2>> = GenericArray::default_boxed();
    R::h1(
        &gv_t.into_iter().flatten().flatten().collect::<Vec<u8>>()[..],
        &mut hv,
    );
    let w = C::witness::<P, O, T>(sk, pk);
    let d = &zip(
        w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>(),
        &mut u[..l],
    )
    .map(|(w, u)| w ^ *u)
    .collect::<GenericArray<u8, O::LBYTES>>()[..];
    let mut chall2 : Box<GenericArray<u8, O::CHALL>> = GenericArray::default_boxed();
    R::h2(&[chall1.to_vec(), u_t.to_vec(), hv.to_vec(), d.to_vec()].concat(), &mut chall2);
    let new_u = GenericArray::from_slice(&u[..l + lambda]);
    let new_gv : &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA> = &gv
        .iter()
        .map(|x| {
            x.iter()
                .flat_map(|y| y.clone().into_iter().take(l + lambda).collect::<Vec<u8>>())
                .collect::<GenericArray<u8, _>>()
        })
        .collect::<GenericArray<GenericArray<u8, _>, _>>();

    let (a_t, b_t) = C::prove::<P, O, T>(
        GenericArray::from_slice(&w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>()),
        new_u,
        new_gv,
        pk,
        &chall2,
    );
    let mut chall3 : Box<GenericArray<u8, P::LAMBDABYTES>> = GenericArray::default_boxed();
    R::h2(&[chall2.to_vec(), a_t.to_vec(), b_t.to_vec()].concat(), &mut chall3);
    let mut pdecom : Box<GenericArray<(Vec<GenericArray<u8, R::LAMBDA>>, Vec<u8>), P::TAU>> = GenericArray::default_boxed();
    for i in 0..tau {
        if i < t0{
            let s = chaldec::<P>(
            &chall3,
            i as u16
        );
        pdecom[i] = open::<R, P::POWK0, P::K0, P::N0>(&decom[i], (*GenericArray::from_slice(&s)).clone());
        }
        else {
            let s = chaldec::<P>(
                &chall3,
                i as u16
            );
            pdecom[i] = open::<R, P::POWK1, P::K1, P::N1>(&decom[i], (*GenericArray::from_slice(&s)).clone());
        }
    }
    (
        Box::new(c.iter().map(|x| (*GenericArray::from_slice(&x[..])).clone()).collect::<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>> ()),
        u_t,
        (*GenericArray::from_slice(&d)).clone(),
        *a_t,
        pdecom,
        (*GenericArray::from_slice(&chall3)).clone(),
        *iv,
    )
}

#[allow(unused_assignments)]
#[allow(clippy::type_complexity)]
pub fn faest_verify<T, R, C, P, O>(
    msg: &[u8],
    pk: GenericArray<u8, O::PK>,
    sigma: (
        Box<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>>,
        GenericArray<u8, O::LAMBDAPLUS2>,
        GenericArray<u8, O::LBYTES>,
        GenericArray<u8, O::LAMBDABYTES>,
        Box<GenericArray<(Vec<GenericArray<u8, R::LAMBDA>>, Vec<u8>), P::TAU>>,
        GenericArray<u8, P::LAMBDABYTES>,
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
    let l = <P::L as Unsigned>::to_usize() / 8;
    let _b = <P::B as Unsigned>::to_usize() / 8;
    let tau = <P::TAU as Unsigned>::to_usize();
    let _k0 = <P::K0 as Unsigned>::to_u16();
    let _k1 = <P::K1 as Unsigned>::to_u16();
    let _t0 = <P::TAU0 as Unsigned>::to_u16();
    let _t1 = <P::TAU1 as Unsigned>::to_u16();
    let (c, u_t, d, a_t, pdecom, chall3, iv) = sigma;
    
    let mut mu : Box<GenericArray<u8, R::PRODLAMBDA2>> = GenericArray::default_boxed();
    R::h1(&[pk.to_vec(), msg.to_vec()].concat(), &mut mu);
    let (hcom, gq_p) = volereconstruct::<T, R, P>(
        &chall3,
        &pdecom.into_iter().map(|(x, y)| (x, (*GenericArray::from_slice(&y)).clone())).collect::<GenericArray<(Vec<GenericArray<u8, R::LAMBDA>>, GenericArray<u8, R::PRODLAMBDA2>), P::TAU>>(),
        u128::from_le_bytes(iv[..16].try_into().unwrap())
    );
    let mut chall1 : Box<GenericArray<u8, O::CHALL1>> = GenericArray::default_boxed();
    R::h2(
        &[
            mu.to_vec(),
            hcom.to_vec(),
            (c.clone()).into_iter().flatten().collect::<Vec<_>>(),
            iv.to_vec(),
        ]
        .concat(),
        &mut chall1,
    );
    let mut gq : Box<GenericArray<Vec<GenericArray<u8, <P as PARAM>::LH>>, P::TAU>> = GenericArray::default_boxed();
    let mut gd_t : Box<GenericArray<GenericArray<GenericArray<u8, O::LAMBDAPLUS2>, O::LAMBDA>, O::LAMBDALBYTES>> = GenericArray::default_boxed();
    gq[0] = gq_p[0].clone();
    let delta0 = chaldec::<P>(&chall3, 0);
    gd_t[0] = 
        delta0
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
        gd_t[i] =
            GenericArray::from_slice(&(delta
                .iter()
                .map(|d| {
                    if *d == 1 {
                        u_t.clone()
                    } else {
                        GenericArray::default()
                    }
                })
                .collect::<GenericArray<_,  <O as PARAMOWF>::LAMBDAPLUS2>>())[..]).clone()
        ;
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
        let mut temp : Vec<GenericArray<u8, P::LH>> = vec![GenericArray::default()];
        temp = zip(gq_p[i].clone(), dtemp)
            .map(|(q, d)| (*GenericArray::from_slice(&zip(q, d).map(|(q, d)| q ^ d).collect::<GenericArray<u8, P::LH>>())).clone())
            .collect();
        gq[i] = temp;
    }
    let gq_t: GenericArray<GenericArray<GenericArray<u8, O::LAMBDAPLUS2>, O::LAMBDA>, O::LAMBDALBYTES> = gq
        .iter()
        .map(|q| {
            q.iter()
                .map(|q| {
                    volehash::<T, O>(
                        GenericArray::from_slice(&chall1),
                        GenericArray::from_slice(&q[..l + lambda]),
                        GenericArray::from_slice(&q[l + lambda..])
                    )
                })
                .collect()
        })
        .collect();
    let mut hv : Box<GenericArray<u8, R::PRODLAMBDA2>> = GenericArray::default_boxed();
    R::h1(
        &zip(
            gq_t.into_iter().flatten().collect::<GenericArray<GenericArray<u8, O::LAMBDAPLUS2>, O::LAMBDALBYTESLAMBDA>>(),
            gd_t.into_iter().flatten().collect::<GenericArray<GenericArray<u8, O::LAMBDAPLUS2>, O::LAMBDALBYTESLAMBDA>>(),
        )
        .flat_map(|(q, d)| zip(q, d).map(|(q, d)| q ^ d).collect::<Vec<u8>>())
        .collect::<Vec<u8>>(),
        &mut hv,
    );
    let mut chall2 : Box<GenericArray<u8, O::CHALL>> = GenericArray::default_boxed();
    R::h2(&[chall1.to_vec(), u_t.to_vec(), hv.to_vec(), d.to_vec()].concat(), &mut chall2);
    let b_t = C::verify::<P, O, T>(
        &d,
        &gq.iter()
            .flat_map(|x| {
                x.iter()
                    .map(|y| y.clone().into_iter().take(l + lambda).collect::<GenericArray<u8, _>>())
                    .collect::<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>()
            }).collect::<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>(),
        &a_t,
        &chall2,
        &chall3,
        &pk,
    );
    let mut chall3_p: Box<GenericArray<u8, P::LAMBDABYTES>> = GenericArray::default_boxed();
    R::h2(&[chall2.to_vec(), a_t.to_vec(), b_t.to_vec()].concat(), &mut chall3_p);
    chall3 == *chall3_p
}

#[allow(clippy::type_complexity)]
pub fn sigma_to_signature<P, O, R>(
    sigma: (
    Box<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>>,
    GenericArray<u8, O::LAMBDAPLUS2>,
    GenericArray<u8, O::LBYTES>,
    GenericArray<u8, O::LAMBDABYTES>,
    Box<GenericArray<(Vec<GenericArray<u8, R::LAMBDA>>, Vec<u8>), P::TAU>>,
    GenericArray<u8, P::LAMBDABYTES>,
    GenericArray<u8, U16>,
    ),
) -> GenericArray<u8, P::SIG> where 
O:PARAMOWF,
P:PARAM,
R:RandomOracle{
    let mut signature = sigma.0.into_iter().flat_map(|x| x.to_vec()).collect::<Vec<u8>>();
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
    signature.append(&mut (*sigma.6).to_vec());

    return (*GenericArray::from_slice(&signature)).clone();
}

#[allow(clippy::type_complexity)]
pub fn signature_to_sigma<P, O, R>(
    signature: &[u8],
) -> (
    Box<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>>,
    GenericArray<u8, O::LAMBDAPLUS2>,
    GenericArray<u8, O::LBYTES>,
    GenericArray<u8, O::LAMBDABYTES>,
    Box<GenericArray<(Vec<GenericArray<u8, R::LAMBDA>>, Vec<u8>), P::TAU>>,
    GenericArray<u8, P::LAMBDABYTES>,
    GenericArray<u8, U16>,
)
where
    P: PARAM,
    O: PARAMOWF,
    R: RandomOracle,
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
    let mut c : Box<GenericArray<GenericArray<u8, O::LHATBYTES>, P::TAUMINUS>> = GenericArray::default_boxed();
    for i in c.iter_mut().take(tau - 1) {
        let indice = 0;
        for j in &signature[index..index + l_b] {
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
    let mut pdecom: Box<GenericArray<(Vec<GenericArray<u8, R::LAMBDA>>, Vec<u8>), P::TAU>> = GenericArray::default_boxed();/* [
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
    .concat(); */
    for i in pdecom.iter_mut().take(tau0) {
        for j in 0..k0 {
            i.0[j] = (*GenericArray::from_slice(&signature[index..index + lambda])).clone();
            index += lambda;
        }
        i.1 = signature[index..index + 2 * lambda].to_vec();
        index += 2 * lambda;
    }
    for i in 0..tau1 {
        for j in 0..k1 {
            pdecom[tau0 + i].0[j] = (*GenericArray::from_slice(&signature[index..index + lambda])).clone();
            index += lambda;
        }
        pdecom[tau0 + i]
            .1
            .append(&mut signature[index..index + 2 * lambda].to_vec());
        index += 2 * lambda;
    }
    let chall3 = (*GenericArray::from_slice(&signature[index..index + lambda])).clone();
    index += lambda;
    let iv: GenericArray<u8, U16> = *GenericArray::from_slice(&signature[index..]);
    (c, u_tilde, d, a_tilde, pdecom, chall3, iv)
}
