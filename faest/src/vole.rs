use cipher::Unsigned;

use generic_array::{ArrayLength, GenericArray};

use crate::parameter::{PARAM};
use crate::random_oracles::{Hasher};
use crate::vc;
use crate::{fields::BigGaloisField, random_oracles::RandomOracle, vc::commit};

#[allow(clippy::type_complexity)]
pub fn convert_to_vole<R, LH>(
    sd: &Vec<Option<GenericArray<u8, R::LAMBDA>>>,
    iv: u128,
) -> (GenericArray<u8, LH>, Vec<GenericArray<u8, LH>>) 
where R : RandomOracle,
    LH: ArrayLength
    {
    let n = sd.len();
    let d = (128 - (n as u128).leading_zeros() - 1) as usize;
    let mut r : Vec<Vec<GenericArray<u8, LH>>> = vec![vec![GenericArray::default();n];d+1];
    match &sd[0] {
        None => (),
        Some(sd0) => r[0][0] = R::prg::<LH>(sd0.clone(), iv,),
    }
    for (i, _) in sd.iter().enumerate().skip(1).take(n) {
        r[0][i] = R::prg::<LH>(
            sd[i].as_ref().unwrap().clone(),
            iv,
        );
    }
    let mut v : Vec<GenericArray<u8, LH>> = vec![GenericArray::default(); d];
    for j in 0..d {
        for i in 0..n / (1_usize << (j + 1)) {
            v[j] = (*GenericArray::from_slice(&v[j]
                .iter()
                .zip(r[j][2 * i + 1].iter())
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect::<GenericArray<u8, LH>>())).clone();
            r[j + 1][i] = (*GenericArray::from_slice(&r[j][2 * i]
                .iter()
                .zip(r[j][2 * i + 1].iter())
                .map(|(&x1, x2)| x1 ^ x2)
                .collect::<GenericArray<u8, LH>>())).clone();
        }
    }
    for j in 0..d {
        for _i in 0..n / (1_usize << (d - j - 1)) {}
    }
    let u = (*GenericArray::from_slice(&r[d][0].clone())).clone();
    (u, v)
}

//constant time checking the value of i : if i is not correct, then the output will be an empty vec
//K = k0 if i < tau0 else k1
pub fn chaldec<P>(chal: &GenericArray<u8, P::LAMBDABYTES>, i: u16) -> Vec<u8>
where P: PARAM,
{
    let mut lo = 1_u16;
    let mut hi = 0_u16;
    let t0 = <P::TAU0 as Unsigned>::to_u16();
    let t1 = <P::TAU1 as Unsigned>::to_u16();
    let k0 = <P::K0 as Unsigned>::to_u16();
    let k1 = <P::K1 as Unsigned>::to_u16();
    if i < t0 {
        lo = i * k0;
        hi = (i + 1) * k0 - 1;
    } else if i < t0 + t1 {
        let t = i - t0;
        lo = t0 * k0 + t * k1;
        hi = t0 * k0 + (t + 1) * k1 - 1;
    }
    let mut res:Vec<u8> = vec![0u8; if i < t0 {k0.into()} else {k1.into()}];
    res[0] = (chal[(lo / 8) as usize] >> (lo % 8)) & 1;
    for j in 1..hi - lo + 1 {
        res[j as usize] = (chal[((lo + j) / 8) as usize] >> ((lo + j) % 8)) & 1;
    }
    res
}

#[allow(clippy::type_complexity)]
pub fn volecommit<P, T, R>(
    r: &GenericArray<u8, <R as RandomOracle>::LAMBDA>,
    iv: u128,
) -> (
    GenericArray<u8, R::PRODLAMBDA2>,
    //Here decom can have two diferent length, depending on if it's a i < t0 or > 0 so we use vectors
    GenericArray<(Vec<GenericArray<u8, R::LAMBDA>>, Vec<GenericArray<u8, R::PRODLAMBDA2>>), P::TAU>,
    GenericArray<GenericArray<u8, P::LH>, P::TAUMINUS>,
    GenericArray<u8, P::LH>,
    GenericArray<Vec<GenericArray<u8, P::LH>>, P::TAU>,
)
where
    P: PARAM,

    T: BigGaloisField + std::default::Default,
    R: RandomOracle,
{
    let tau = <P::TAU as Unsigned>::to_usize();
    let k0 = <P::K0 as Unsigned>::to_u16();
    let k1 = <P::K1 as Unsigned>::to_u16();
    let _t1 = <P::TAU1 as Unsigned>::to_u16();
    let tau_res = R::prg::<P::PRODLAMBDATAU>(r.clone(), iv);
    let mut r : GenericArray<T, P::TAU> = GenericArray::default();
    let mut com : GenericArray<GenericArray<u8, R::PRODLAMBDA2>, P::TAU> = GenericArray::default();
    let mut decom : GenericArray<(Vec::<GenericArray<u8, R::LAMBDA>>, Vec::<GenericArray<u8, R::PRODLAMBDA2>>), P::TAU> = GenericArray::default();
    let mut sd : GenericArray<Vec::<Option<GenericArray<u8, R::LAMBDA>>>, P::TAU> = GenericArray::default();
    let mut u : GenericArray<GenericArray<u8, P::LH>, P::TAU> = GenericArray::default();
    let mut v : GenericArray<Vec<GenericArray<u8, P::LH>>, P::TAU> = GenericArray::default();
    let mut c : GenericArray<GenericArray<u8, P::LH>, P::TAUMINUS> = GenericArray::default();
    for i in 0..tau {
        r[i] = T::from(&tau_res[i * (T::LENGTH / 8) as usize..(i + 1) * (T::LENGTH / 8) as usize]);
    }
    let tau_0 = T::LENGTH % tau;
    let mut hasher = R::h1_init();
    for i in 0..tau {
        let b = 1 - (i < tau_0.try_into().unwrap()) as u16;
        let k = ((1 - b) * k0) + b * k1;
        (com[i], decom[i], sd[i]) = commit::<T, R>(r[i], iv, 1u32 << k);
        hasher.update(&com[i]);
        (u[i], v[i]) = convert_to_vole::<R, P::LH>(&sd[i], iv);
    }
    for i in 1..tau {
        c[i - 1] = u[0]
            .iter()
            .zip(u[i].iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
    }
    let mut hcom : GenericArray<u8, R::PRODLAMBDA2> = GenericArray::default();
    hasher.finish();
    (hcom, decom, c, u[0].clone(), v)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn volereconstruct<T, R, P>(
    chal: &GenericArray<u8, P::LAMBDABYTES>,
    pdecom: &GenericArray<(Vec<GenericArray<u8, R::LAMBDA>>, GenericArray<u8, R::PRODLAMBDA2>), P::TAU>,
    iv: u128,
) -> (GenericArray<u8, R::PRODLAMBDA2>, GenericArray<Vec<GenericArray<u8, P::LH>>, P::TAU>)
where
    T: BigGaloisField + std::default::Default + std::fmt::Debug,
    R: RandomOracle,
    P: PARAM,

    {
    let tau = <P::TAU as Unsigned>::to_usize();
    let k0 = <P::K0 as Unsigned>::to_u16();
    let k1 = <P::K1 as Unsigned>::to_u16();
    let _t1 = <P::TAU1 as Unsigned>::to_u16();
    let t0 = <P::TAU0 as Unsigned>::to_u16();
    let mut com : GenericArray<GenericArray<u8, R::PRODLAMBDA2>, P::TAU> = GenericArray::default();
    let mut s : GenericArray<Vec<GenericArray<u8, R::LAMBDA>>, P::TAU> = GenericArray::default();
    let mut sd : GenericArray<Vec<Option<GenericArray<u8, R::LAMBDA>>>, P::TAU> = GenericArray::default();
    let mut delta : GenericArray<u32, P::TAU> = GenericArray::default();
    let mut q : GenericArray<Vec<GenericArray<u8, P::LH>>, P::TAU> = GenericArray::default();
    let mut hasher = R::h1_init();
    for i in 0..tau {
        let b: u16 = (i < t0.into()).into();
        let k = b * k0 + (1 - b) * k1;
        let delta_p : Vec<u8> = chaldec::<P>(&chal, i.try_into().unwrap());
        #[allow(clippy::needless_range_loop)]
        for j in 0..delta_p.len() {
            delta[i] += (delta_p[j] as u32) << j;
        }
        (com[i], s[i]) = vc::reconstruct::<T, R>(&pdecom[i], delta_p.to_vec(), iv);
        hasher.update(&com[i]);
        for j in 0..(1_u16 << (k)) as usize {
            sd[i].push(Some(s[i][j ^ delta[i] as usize].clone()));
        }
        sd[i][0] = None;
        
        (_, q[i]) = convert_to_vole::<R, P::LH>(&sd[i], iv);
        
    }
    let mut hcom : GenericArray<u8, R::PRODLAMBDA2> = GenericArray::default();
    hasher.finish();
    (hcom, q)
}
