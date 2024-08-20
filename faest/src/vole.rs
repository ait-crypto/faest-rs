use cipher::Unsigned;
use generic_array::sequence::GenericSequence;
use generic_array::{ArrayLength, GenericArray};

use crate::parameter::{self, PARAM};
use crate::random_oracles::{self, Hasher};
use crate::vc;
use crate::{fields::BigGaloisField, random_oracles::RandomOracle, vc::commit};

#[allow(clippy::type_complexity)]
pub fn convert_to_vole<R, LH>(
    sd: Vec<Option<GenericArray<u8, R::LAMBDA>>>,
    iv: u128,
) -> (GenericArray<u8, LH>, Vec<GenericArray<u8, LH>>) 
where R : RandomOracle,
    LH: ArrayLength<u8>
    {
    let a = 0;
    let a = 1;
    let n = sd.len();
    let d = (128 - (n as u128).leading_zeros() - 1) as usize;
    let lh = <LH as Unsigned>::to_u16();
    let mut r : Vec<Vec<GenericArray<u8, LH>>> = vec![vec![GenericArray::generate(|k:usize| 0u8);n];d];
    match &sd[0] {
        None => (),
        Some(sd0) => r[0][0] = R::prg::<LH>(*sd0, iv,),
    }
    for (i, _) in sd.iter().enumerate().skip(1).take(n) {
        r[0][i] = R::prg::<LH>(
            sd[i].unwrap(),
            iv,
        );
    }
    let mut v : Vec<GenericArray<u8, LH>> = vec![GenericArray::generate(|k:usize| 0u8); d];
    for j in 0..d {
        for i in 0..n / (1_usize << (j + 1)) {
            v[j] = *GenericArray::from_slice(&v[j]
                .iter()
                .zip(r[j][2 * i + 1].iter())
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect::<GenericArray<u8, LH>>());
            r[j + 1][i] = *GenericArray::from_slice(&r[j][2 * i]
                .iter()
                .zip(r[j][2 * i + 1].iter())
                .map(|(&x1, x2)| x1 ^ x2)
                .collect::<GenericArray<u8, LH>>());
        }
    }
    for j in 0..d {
        for _i in 0..n / (1_usize << (d - j - 1)) {}
    }
    let u = *GenericArray::from_slice(&r[d][0].clone());
    (u, v)
}

//constant time checking the value of i : if i is not correct, then the output will be an empty vec
//K = k0 if i < tau0 else k1
pub fn chaldec<P, K>(chal: GenericArray<u8, P::LAMBDA>, i: u16) -> GenericArray<u8, K> 
where P: PARAM,
K: ArrayLength<u8>{
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
    let mut res:GenericArray<u8, K> = GenericArray::generate(|i:usize| 0u8);
    for j in 1..hi - lo + 1 {
        res[j as usize - 1] = ((chal[((lo + j) / 8) as usize] >> ((lo + j) % 8)) & 1);
    }
    res
}

#[allow(clippy::type_complexity)]
pub fn volecommit<P, T, R, LH>(
    r: GenericArray<u8, <R as RandomOracle>::LAMBDA>,
    iv: u128,
) -> (
    GenericArray<u8, R::PRODLAMBDA2>,
    //Here decom can have two diferent length, depending on if it's a i < t0 or > 0 so we use vectors
    GenericArray<(Vec<GenericArray<u8, R::LAMBDA>>, Vec<GenericArray<u8, R::PRODLAMBDA2>>), P::TAU>,
    GenericArray<GenericArray<u8, LH>, P::TAUMINUS>,
    GenericArray<u8, LH>,
    GenericArray<Vec<GenericArray<u8, LH>>, P::TAU>,
)
where
    P: PARAM,
    <P as parameter::PARAM>::POWK0: ArrayLength<GenericArray<u8, R::LAMBDA>>,
    <P as parameter::PARAM>::POWK1: ArrayLength<GenericArray<u8, R::LAMBDA>>,
    <P as parameter::PARAM>::N0: ArrayLength<Option<GenericArray<u8, R::LAMBDA>>> + ArrayLength<GenericArray<u8, R::PRODLAMBDA2>>,
    <P as parameter::PARAM>::N1: ArrayLength<Option<GenericArray<u8, R::LAMBDA>>> + ArrayLength<GenericArray<u8, R::PRODLAMBDA2>>,
    <P as parameter::PARAM>::TAU: ArrayLength<Vec<GenericArray<u8, LH>>> + ArrayLength<Vec::<Option<GenericArray<u8, R::LAMBDA>>>> + ArrayLength<GenericArray<u8, R::PRODLAMBDA2>> + ArrayLength<T> + ArrayLength<GenericArray<u8, LH>> + ArrayLength<(Vec<GenericArray<u8, R::LAMBDA>>, Vec<GenericArray<u8, R::PRODLAMBDA2>>)>,
    <P as parameter::PARAM>::TAUMINUS: ArrayLength<GenericArray<u8, LH>>,
    T: BigGaloisField + std::default::Default,
    R: RandomOracle,
    LH: generic_array::ArrayLength<u8>,
{
    let tau = <P::TAU as Unsigned>::to_usize();
    let k0 = <P::K0 as Unsigned>::to_u16();
    let k1 = <P::K1 as Unsigned>::to_u16();
    let t1 = <P::TAU1 as Unsigned>::to_u16();
    let tau_res = R::prg::<P::PRODLAMBDATAU>(r, iv);
    let mut r : GenericArray<T, P::TAU> = GenericArray::generate(|i:usize| T::default());
    let mut com : GenericArray<GenericArray<u8, R::PRODLAMBDA2>, P::TAU> = GenericArray::generate(|j:usize|GenericArray::generate(|k:usize| 0u8));
    let mut decom : GenericArray<(Vec::<GenericArray<u8, R::LAMBDA>>, Vec::<GenericArray<u8, R::PRODLAMBDA2>>), P::TAU> = GenericArray::generate(|i:usize| (vec![GenericArray::generate(|j:usize| 0u8)], vec![GenericArray::generate(|j:usize| 0u8)]));
    let mut sd : GenericArray<Vec::<Option<GenericArray<u8, R::LAMBDA>>>, P::TAU> = GenericArray::generate(|i:usize| vec![Some(GenericArray::generate(|j:usize| 0u8))]);
    let mut u : GenericArray<GenericArray<u8, LH>, P::TAU> = GenericArray::generate(|j:usize|GenericArray::generate(|k:usize| 0u8));
    let mut v : GenericArray<Vec<GenericArray<u8, LH>>, P::TAU> = GenericArray::generate(|i:usize| vec![GenericArray::generate(|j:usize| 0u8)]);
    let mut c : GenericArray<GenericArray<u8, LH>, P::TAUMINUS> = GenericArray::generate(|j:usize|GenericArray::generate(|k:usize| 0u8));
    for i in 0..tau {
        r[i] = T::from(&tau_res[i * (T::LENGTH / 8) as usize..(i + 1) * (T::LENGTH / 8) as usize]);
    }
    let tau_0 = T::LENGTH % (tau as u32);
    let mut hasher = R::h1_init();
    for i in 0..tau {
        let b = 1 - (i < tau_0.try_into().unwrap()) as u16;
        let k = ((1 - b) * k0) + b * k1;
        (com[i], decom[i], sd[i]) = commit::<T, R>(r[i], iv, 1u32 << k);
        hasher.h1_update(&com[i]);
        (u[i], v[i]) = convert_to_vole::<R, LH>(sd[i], iv);
    }
    for i in 1..tau {
        c[i - 1] = u[0]
            .iter()
            .zip(u[i].iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
    }
    let mut hcom : GenericArray<u8, R::PRODLAMBDA2> = GenericArray::generate(|i:usize| 0u8);
    hasher.h1_finish(&mut hcom);
    (hcom, decom, c, u[0].clone(), v)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn volereconstruct<T, R, P>(
    chal: &[u8],
    pdecom: Vec<(Vec<Vec<u8>>, Vec<u8>)>,
    iv: u128,
    lh: usize,
    tau: usize,
    tau0: u16,
    tau1: u16,
    k0: u16,
    k1: u16,
    lambdabytes: usize,
) -> (Vec<u8>, Vec<Vec<Vec<u8>>>)
where
    T: BigGaloisField + std::default::Default + std::fmt::Debug,
    R: RandomOracle,
    P: PARAM
{
    let mut com = vec![vec![0; lambdabytes]; tau];
    let mut s = vec![Vec::new(); tau];
    let mut sd = vec![Vec::new(); tau];
    let mut delta = vec![0_u32; tau];
    let mut q = vec![Vec::new(); tau];
    let mut hasher = R::h1_init();
    for i in 0..tau {
        let b: u16 = (i < tau0.into()).into();
        let k = b * k0 + (1 - b) * k1;
        let delta_p = chaldec(chal, i.try_into().unwrap());
        #[allow(clippy::needless_range_loop)]
        for j in 0..delta_p.len() {
            delta[i] += (delta_p[j] as u32) << j;
        }
        (com[i], s[i]) = vc::reconstruct::<T, R>(pdecom[i].clone(), delta_p.clone(), iv);
        hasher.h1_update(&com[i]);
        for j in 0..(1_u16 << (k)) as usize {
            sd[i].push(Some(s[i][j ^ delta[i] as usize].clone()));
        }
        sd[i][0] = None;
        (_, q[i]) = convert_to_vole::<R>(&sd[i], iv, lh);
        
    }
    let mut hcom = vec![0; 2 * lambdabytes];
    hasher.h1_finish(&mut hcom);
    (hcom, q)
}
