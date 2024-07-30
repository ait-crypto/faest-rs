use rand::RngCore;
use std::iter::zip;

use crate::{
    aes::{aes_extendedwitness, aes_prove, aes_verify, aes_witness_has0},
    em::{em_extendedwitness, em_prove, em_verify, em_witness_has0},
    fields::BigGaloisField,
    parameter::{PARAM, PARAMOWF},
    random_oracles::RandomOracle,
    rijndael_32::{rijndael_encrypt, rijndael_key_schedule},
    universal_hashing::volehash,
    vc::open,
    vole::{chaldec, volecommit, volereconstruct},
};

pub trait Variant {
    fn witness<P, O>(k: &[u8], pk: &[u8]) -> Vec<u8>
    where
        P: PARAM,
        O: PARAMOWF;

    fn prove<P, O, T>(
        w: &[u8],
        u: &[u8],
        gv: &[Vec<u8>],
        pk: &[u8],
        chall: &[u8],
    ) -> (Vec<u8>, Vec<u8>)
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug;

    fn verify<T, P, O>(
        d: &[u8],
        gq: Vec<Vec<u8>>,
        a_t: &[u8],
        chall2: &[u8],
        chall3: &[u8],
        pk: &[u8],
    ) -> Vec<u8>
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug;

    fn keygen_with_rng<P, O>(rng: impl RngCore) -> (Vec<u8>, Vec<u8>, Vec<u8>)
    where
        P: PARAM,
        O: PARAMOWF;
}

pub struct AesCypher {}

impl Variant for AesCypher {
    fn witness<P, O>(k: &[u8], pk: &[u8]) -> Vec<u8>
    where
        P: PARAM,
        O: PARAMOWF,
    {
        aes_extendedwitness::<P, O>(k, pk)
    }

    fn prove<P, O, T>(
        w: &[u8],
        u: &[u8],
        gv: &[Vec<u8>],
        pk: &[u8],
        chall: &[u8],
    ) -> (Vec<u8>, Vec<u8>)
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug,
    {
        aes_prove::<T, P, O>(w, u, gv, pk, chall)
    }

    fn verify<T, P, O>(
        d: &[u8],
        gq: Vec<Vec<u8>>,
        a_t: &[u8],
        chall2: &[u8],
        chall3: &[u8],
        pk: &[u8],
    ) -> Vec<u8>
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
    fn keygen_with_rng<P, O>(mut rng: impl RngCore) -> (Vec<u8>, Vec<u8>, Vec<u8>)
    where
        P: PARAM,
        O: PARAMOWF,
    {
        let nk = O::NK;
        let r = O::R;
        'boucle: loop {
            let mut rho = [0u8; 32];
            let mut sk: Vec<u8>;
            let mut y: Vec<u8>;
            if P::BETA == 1 {
                sk = vec![0u8; 32];
                rng.fill_bytes(&mut sk);
                
                y = aes_witness_has0::<P, O>(&sk[16..], &sk[..16]);
            } else {
                sk = vec![0u8; 32 + P::LAMBDA / 8];
                rng.fill_bytes(&mut sk);
                println!(" ");
                println!(" New_sk");
                for i in &sk {
                    print!("{:x}, ", i);
                }
                println!(" ");
                
                y = aes_witness_has0::<P, O>(&sk[32..], &sk[..32]);
            };
            println!(" ");
            for elem in &mut y {
                print!("{:?}, ", elem);
                if *elem == 0 {
                    //println!("yolo ??");
                    continue 'boucle;
                }
            }
            println!(" ");

            let mut cypher: cipher::array::Array<
                aes::cipher::generic_array::GenericArray<u8, _>,
                _,
            >;
            let rk = rijndael_key_schedule(&sk[16 * P::BETA as usize..], 4, O::NK, O::R, O::SKE);
            if P::BETA == 1 {
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
                sk.to_vec(),
                [&sk[..16 * O::BETA as usize], &y[..]].concat(),
                rho.to_vec(),
            );
        }
    }
}

pub struct EmCypher {}

impl Variant for EmCypher {
    fn witness<P, O>(k: &[u8], pk: &[u8]) -> Vec<u8>
    where
        P: PARAM,
        O: PARAMOWF,
    {
        em_extendedwitness::<P, O>(k, pk)
    }

    fn prove<P, O, T>(
        w: &[u8],
        u: &[u8],
        gv: &[Vec<u8>],
        pk: &[u8],
        chall: &[u8],
    ) -> (Vec<u8>, Vec<u8>)
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug,
    {
        em_prove::<T, P, O>(w, u, gv, pk, chall)
    }

    fn verify<T, P, O>(
        d: &[u8],
        gq: Vec<Vec<u8>>,
        a_t: &[u8],
        chall2: &[u8],
        chall3: &[u8],
        pk: &[u8],
    ) -> Vec<u8>
    where
        P: PARAM,
        O: PARAMOWF,
        T: BigGaloisField + std::default::Default + std::fmt::Debug,
    {
        em_verify::<T, P, O>(d, gq, a_t, chall2, chall3, pk)
    }

    fn keygen_with_rng<P, O>(mut rng: impl RngCore) -> (Vec<u8>, Vec<u8>, Vec<u8>)
    where
        P: PARAM,
        O: PARAMOWF,
    {
        let lambda = P::LAMBDA / 8;
        let nk = O::NK;
        let r = O::R;
        let nst = O::NST.unwrap();
        'boucle: loop {
            let mut rho = [0u8; 32];
            let mut sk = vec![0u8; 2 * lambda];
            rng.fill_bytes(&mut sk);
            let mut y = em_witness_has0::<P, O>(&sk[lambda..], &sk[..lambda]);
            //println!(" ");
            for elem in &mut y {
                //print!("{:?}, ", elem);
                if *elem == 0 {
                    continue 'boucle;
                }
            }
            //println!(" ");
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
            return (sk.to_vec(), [&sk[..lambda], &y[..]].concat(), rho.to_vec());
        }
    }
}

///The input message is assumed to be a byte array
#[allow(clippy::needless_range_loop)]
#[allow(clippy::type_complexity)]
#[allow(clippy::unnecessary_to_owned)]
pub fn faest_sign<T, R, C, P, O>(
    msg: &[u8],
    sk: &[u8],
    pk: &[u8],
    rho: Vec<u8>,
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
    P: PARAM,
    O: PARAMOWF,
{
    let lambda = P::LAMBDA / 8;
    let l = (P::L / 8) as usize;
    let b = (P::B / 8) as usize;
    let tau = P::TAU as usize;
    let k0 = P::K0 as u16;
    let k1 = P::K1 as u16;
    let mut mu = vec![0; 2 * lambda];
    R::h1(&[pk, msg].concat(), &mut mu);
    let mut riv = vec![0; lambda + 16];
    R::h3(&[sk, &mu, &rho].concat(), &mut riv);
    let (r, iv) = (&riv[..lambda], &riv[lambda..]);
    let (hcom, decom, c, mut u, gv) = volecommit::<T, R>(
        r,
        u128::from_be_bytes(iv.try_into().unwrap()),
        l + 2 * lambda + b,
        tau,
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
    let mut hv = vec![0; 2 * lambda];
    R::h1(
        &gv_t.into_iter().flatten().flatten().collect::<Vec<u8>>()[..],
        &mut hv,
    );
    let w = C::witness::<P, O>(sk, pk);
    let d = &zip(
        w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>(),
        &mut u[..l],
    )
    .map(|(w, u)| w ^ *u)
    .collect::<Vec<u8>>()[..];
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

    let (a_t, b_t) = C::prove::<P, O, T>(
        &w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>(),
        new_u,
        &(new_gv.to_vec())
            .into_iter()
            .flatten()
            .collect::<Vec<Vec<u8>>>()[..],
        pk,
        &chall2,
    );
    let mut chall3 = vec![0; lambda];
    //println!("chall2 : {:?}", chall2);
    //println!("a_t : {:?}", a_t);
    //println!("b_t : {:?}", b_t);
    R::h2(&[chall2, a_t.clone(), b_t].concat(), &mut chall3);
    let mut pdecom = Vec::with_capacity(tau);
    for i in 0..tau {
        let s = chaldec(
            &chall3.to_vec(),
            k0,
            P::TAU0.into(),
            k1,
            P::TAU1.into(),
            i as u16,
        );
        pdecom.push(open(&decom[i], s));
    }
    /* println!(" ");
    for v in &a_t {
        print!("{:x}, ", v);
        /* for i in v {
            print!("{:x}, ", i);
        } */
    }
    println!(" "); */
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

#[allow(unused_assignments)]
#[allow(clippy::type_complexity)]
pub fn faest_verify<T, R, C, P, O>(
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
) -> bool
where
    T: BigGaloisField + std::default::Default + std::fmt::Debug,
    R: RandomOracle,
    C: Variant,
    P: PARAM,
    O: PARAMOWF,
{
    let lambda = P::LAMBDA / 8;
    let l = (P::L / 8) as usize;
    let b = (P::B / 8) as usize;
    let tau = P::TAU as usize;
    let k0 = P::K0 as u16;
    let k1 = P::K1 as u16;
    let t0 = P::TAU0 as u16;
    let t1 = P::TAU1 as u16;
    let (c, u_t, d, a_t, pdecom, chall3, iv) = sigma;
    /* ok */
    let mut mu = vec![0; 2 * lambda];
    R::h1(&[pk.0, pk.1, msg].concat(), &mut mu);
    /*  hcom : ok */
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
    /* ok */
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
    let b_t = C::verify::<T, P, O>(
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
    let tau = P::TAU as usize;
    let lambda = P::LAMBDA / 8;
    let l = (P::L / 8) as usize;
    let k0 = P::K0 as usize;
    let k1 = P::K1 as usize;
    let tau0 = P::TAU0 as usize;
    let tau1 = P::TAU1 as usize;
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
