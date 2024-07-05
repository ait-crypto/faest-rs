use std::{backtrace, collections::VecDeque, iter::zip};

use rand::random;

use crate::{
    aes::{aes_extendedwitness, aes_prove, aes_verify},
    em::{em_extendedwitness, em_prove, em_verify},
    fields::BigGaloisField,
    parameter::{self, Param, ParamOWF},
    random_oracles::RandomOracle,
    rijndael_32::{rijndael_encrypt, rijndael_key_schedule},
    universal_hashing::volehash,
    vc::open,
    vole::{chaldec, volecommit, volereconstruct},
};

pub trait Variant {
    fn witness(k: &[u8], pk: &[u8], param: &Param, paramowf: &ParamOWF) -> Vec<u8>;

    fn prove<T>(
        w: &[u8],
        u: &[u8],
        gv: &[Vec<u8>],
        pk: &[u8],
        chall: &[u8],
        paramowf: &ParamOWF,
        param: &Param,
    ) -> (Vec<u8>, Vec<u8>)
    where
        T: BigGaloisField + std::default::Default + std::fmt::Debug;

    fn verify<T>(
        d: &[u8],
        gq: Vec<Vec<u8>>,
        a_t: &[u8],
        chall2: &[u8],
        chall3: &[u8],
        pk: &[u8],
        paramowf: &ParamOWF,
        param: &Param,
    ) -> Vec<u8>
    where
        T: BigGaloisField + std::default::Default + std::fmt::Debug;
}

pub struct AesCypher {}

impl Variant for AesCypher {
    fn witness(k: &[u8], pk: &[u8], param: &Param, paramowf: &ParamOWF) -> Vec<u8> {
        aes_extendedwitness(k, pk, &param, &paramowf)
    }

    fn prove<T>(
        w: &[u8],
        u: &[u8],
        gv: &[Vec<u8>],
        pk: &[u8],
        chall: &[u8],
        paramowf: &ParamOWF,
        param: &Param,
    ) -> (Vec<u8>, Vec<u8>)
    where
        T: BigGaloisField + std::default::Default + std::fmt::Debug,
    {
        aes_prove::<T>(w, u, gv, pk, chall, paramowf, param)
    }

    fn verify<T>(
        d: &[u8],
        gq: Vec<Vec<u8>>,
        a_t: &[u8],
        chall2: &[u8],
        chall3: &[u8],
        pk: &[u8],
        paramowf: &ParamOWF,
        param: &Param,
    ) -> Vec<u8>
    where
        T: BigGaloisField + std::default::Default + std::fmt::Debug,
    {
        aes_verify::<T>(d, gq, chall2, chall3, a_t, pk, paramowf, param)
    }
}

pub struct EmCypher {}

impl Variant for EmCypher {
    fn witness(k: &[u8], pk: &[u8], param: &Param, paramowf: &ParamOWF) -> Vec<u8> {
        em_extendedwitness(k, pk, param, paramowf)
    }

    fn prove<T>(
        w: &[u8],
        u: &[u8],
        gv: &[Vec<u8>],
        pk: &[u8],
        chall: &[u8],
        paramowf: &ParamOWF,
        param: &Param,
    ) -> (Vec<u8>, Vec<u8>)
    where
        T: BigGaloisField + std::default::Default + std::fmt::Debug,
    {
        em_prove::<T>(w, u, gv, pk, chall, paramowf, param)
    }

    fn verify<T>(
        d: &[u8],
        gq: Vec<Vec<u8>>,
        a_t: &[u8],
        chall2: &[u8],
        chall3: &[u8],
        pk: &[u8],
        paramowf: &ParamOWF,
        param: &Param,
    ) -> Vec<u8>
    where
        T: BigGaloisField + std::default::Default + std::fmt::Debug,
    {
        em_verify::<T>(d, gq, a_t, chall2, chall3, pk, paramowf, param)
    }
}

pub fn keygen<C>(param: &Param, paramowf: &ParamOWF) -> (Vec<u8>, (Vec<u8>, Vec<u8>))
where
    C: Variant,
{
    let mut zero = 0;
    let lambda = param.get_lambda() / 8;
    let mut x = if param.get_beta() == 1 {
        [random::<[u8; 16]>().to_vec(), vec![0u8; 16]].concat()
    } else {
        random::<[u8; 32]>().to_vec()
    };
    let mut k = random::<[u8; 32]>();
    while zero == 0 {
        x = if param.get_beta() == 1 {
            [random::<[u8; 16]>().to_vec(), vec![0u8; 16]].concat()
        } else {
            random::<[u8; 32]>().to_vec()
        };
        k = random::<[u8; 32]>();
        let mut y = C::witness(&k[..lambda as usize], &x[..], param, paramowf);
        let mut has_zero = 0;
        for elem in &mut y[paramowf.get_nk() as usize..] {
            if (*elem & 255) == 0 {
                has_zero = 1;
            }
        }
        zero = 1 - has_zero;
    }
    let rk = rijndael_key_schedule(&k, 4, (lambda / 4) as u8, (lambda / 4 + 4) as u8);
    let cypher = rijndael_encrypt(&rk, &x, 4, (lambda / 4 + 4) as u8);
    let y = cypher.into_iter().flatten().take(lambda as usize).collect();
    (k[..lambda as usize].to_vec(), (x.to_vec(), y))
}

///The input message is assumed to be a byte array
pub fn faest_sign<T, R, C>(
    msg: &[u8],
    sk: &[u8],
    pk: &[u8],
    prg: &dyn Fn(&[u8], u128, usize) -> Vec<u8>,
    param: &Param,
    paramowf: &ParamOWF, /* , rho : Vec<u8> */
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
    T: BigGaloisField + std::default::Default + std::fmt::Debug,
    C: Variant,
    R: RandomOracle,
{
    let lambda = (param.get_lambda() / 8) as usize;
    let l = (param.get_l() / 8) as usize;
    let b = (param.get_b() / 8) as usize;
    let tau = param.get_tau() as usize;
    let k0 = param.get_k0() as u16;
    let k1 = param.get_k1() as u16;
    let rho = &random::<[u8; 32]>()[..lambda];
    let mut mu = vec![0; 2 * lambda];
    R::h1(&[pk, msg].concat(), &mut mu);
    let mut riv = vec![0; lambda + 16];
    R::h3(&[sk, &mu, &rho].concat(), &mut riv);
    let (r, iv) = (&riv[..lambda], &riv[lambda..]);
    let (hcom, decom, c, mut u, gv) = volecommit::<T, R>(
        r,
        u128::from_le_bytes(iv.try_into().unwrap()),
        l + 2 * lambda + b,
        tau,
        prg,
        k0,
        k1,
    );
    let mut chall1 = vec![0; 5 * lambda + 8];
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
    let u_t = volehash::<T>(&chall1, u[..l + lambda].to_vec(), &u[l + lambda..], l, b);
    let mut gv_t: Vec<Vec<Vec<u8>>> = gv
        .iter()
        .map(|v| {
            v.iter()
                .map(|v| volehash::<T>(&chall1, v[..l + lambda].to_vec(), &v[l + lambda..], l, b))
                .collect()
        })
        .collect();
    let mut hv = vec![0; 2 * lambda];
    R::h1(
        &gv_t.into_iter().flatten().flatten().collect::<Vec<u8>>()[..],
        &mut hv,
    );
    let w = C::witness(sk, pk, param, paramowf);
    let d = &zip(
        w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>(),
        &mut u[..l],
    )
    .map(|(w, u)| w ^ *u)
    .collect::<Vec<u8>>()[..];
    // OK println!("chall1 : {:?}", chall1);
     // OK println!("u_t : {:?}", u_t);
     // OK println!("d : {:?}", d);
    let mut chall2 = vec![0; 3 * lambda + 8];
    R::h2(&[chall1, u_t.clone(), hv, d.to_vec()].concat(), &mut chall2);
    let new_u = &u[..l + lambda];
    let new_gv = gv
        .iter()
        .map(|x| {
            x.iter()
                .map(|y| y.clone().into_iter().take(l + lambda).collect::<Vec<u8>>())
                .collect::<Vec<Vec<u8>>>()
        })
        .collect::<Vec<Vec<Vec<u8>>>>();
    let (a_t, b_t) = C::prove::<T>(
        &w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>(),
        &new_u,
        &(new_gv.to_vec())
            .into_iter()
            .flatten()
            .collect::<Vec<Vec<u8>>>()[..],
        &pk,
        &chall2,
        paramowf,
        param,
    );
    let mut chall3 = vec![0; lambda];
    // OK println!("chall2 : {:?}", chall2);
    // OK println!("a_t : {:?}", a_t);
    println!("b_t : {:?}", b_t);
    R::h2(&[chall2, a_t.clone(), b_t].concat(), &mut chall3);
    let mut pdecom = Vec::with_capacity(tau);
    for i in 0..tau {
        let s = chaldec(
            &chall3.to_vec(),
            k0,
            param.get_tau0().into(),
            k1,
            param.get_tau1().into(),
            i as u16,
        );
        pdecom.push(open(&decom[i], s));
    }
    (
        c,
        u_t,
        d.to_vec(),
        a_t,
        pdecom,
        chall3.to_vec(),
        iv.try_into().unwrap(),
    )
}

pub fn faest_verify<T, R, C>(
    msg: &[u8],
    pk: (&[u8], &[u8]),
    sigma: (
        Vec<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<(Vec<Vec<u8>>, Vec<u8>)>,
        Vec<u8>,
        [u8; 16],
    ),
    prg: &dyn Fn(&[u8], u128, usize) -> Vec<u8>,
    param: &Param,
    paramowf: &ParamOWF,
) -> bool
where
    T: BigGaloisField + std::default::Default + std::fmt::Debug,
    R: RandomOracle,
    C: Variant,
{
    let lambda = (param.get_lambda() / 8) as usize;
    let l = (param.get_l() / 8) as usize;
    let b = (param.get_b() / 8) as usize;
    let tau = param.get_tau() as usize;
    let k0 = param.get_k0() as u16;
    let k1 = param.get_k1() as u16;
    let t0 = param.get_tau0() as u16;
    let t1 = param.get_tau1() as u16;
    let (c, u_t, d, a_t, pdecom, chall3, iv) = sigma;
    /*     println!("{:?}", c.len());
    println!("{:?}", tau); */
    let mut mu = vec![0; 2 * lambda];
    R::h1(&[pk.0, pk.1, msg].concat(), &mut mu);
    let (hcom, gq_p) = volereconstruct::<T, R>(
        &chall3,
        pdecom,
        u128::from_le_bytes(iv),
        l + 2 * lambda + b,
        tau,
        t0,
        t1,
        k0,
        k1,
        prg,
        lambda,
    );
    let mut chall1 = vec![0; 5 * lambda + 8];
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
    let delta0 = chaldec(&chall3, k0 as u16, t0, k1 as u16, t1, 0);
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
    let mut temp = vec![vec![0u8]];
    for i in 1..tau {
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
        temp = (zip(gq_p[i].clone(), delta)
            .map(|(q, d)| zip(q, c[i - 1].clone()).map(|(q, c)| q ^ (d * c)).collect())
            .collect::<Vec<Vec<u8>>>());
        gq.push(temp);
    }
    let gq_t: Vec<Vec<u8>> = gq
        .iter()
        .map(|q| {
            q.iter()
                .flat_map(|q| {
                    volehash::<T>(&chall1, q[..l + lambda].to_vec(), &q[l + lambda..], l, b)
                })
                .collect::<Vec<u8>>()
        })
        .collect();
    let mut hv = vec![0; 2 * lambda];
    R::h1(
        &zip(
            gq_t,
            gd_t.into_iter()
                .map(|x| x.clone().into_iter().flatten().collect::<Vec<u8>>())
                .collect::<Vec<Vec<u8>>>(),
        )
        .map(|(q, d)| zip(q, d).map(|(q, d)| q ^ d).collect::<Vec<u8>>())
        .flatten()
        .collect::<Vec<u8>>(),
        &mut hv,
    );
    let mut chall2 = vec![0; 3 * lambda + 8];
    println!("chall3 len : {:?}", chall3.len());
     // OK println!("chall1 : {:?}", chall1);
     // OK println!("u_t : {:?}", u_t);
     // OK println!("d : {:?}", d);
    R::h2(&[chall1.clone(), u_t, hv, d.clone()].concat(), &mut chall2);
    let b_t = C::verify::<T>(
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
        paramowf,
        param,
    );
    let mut chall3_p = vec![0; lambda];
    // OK println!("chall2 : {:?}", chall2);
    // OK println!("a_t : {:?}", a_t);
    println!("b_t : {:?}", b_t);
    R::h2(&[chall2, a_t, b_t].concat(), &mut chall3_p);
    println!("original : {:?}", chall3);
    println!("new : {:?}", chall3_p);
    chall3 == chall3_p
}
