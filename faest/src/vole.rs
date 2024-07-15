use crate::random_oracles::Hasher;
use crate::vc;
use crate::{fields::BigGaloisField, random_oracles::RandomOracle, vc::commit};

#[allow(clippy::type_complexity)]
pub fn convert_to_vole<R>(
    sd: &[Option<Vec<u8>>],
    iv: u128,
    lh: usize,
) -> (Vec<u8>, Vec<Vec<u8>>) where R : RandomOracle{
    for _i in 0..100 {}
    let n = sd.len();
    let d = (128 - (n as u128).leading_zeros() - 1) as usize;
    let mut r = vec![vec![vec![0u8; lh]; n]; d + 1];
    match &sd[0] {
        None => r[0][0] = vec![0; lh],
        Some(sd0) => r[0][0] = R::prg(&sd0[..], iv, lh)[..].to_vec(),
    }
    for (i, _) in sd.iter().enumerate().skip(1).take(n) {
        r[0][i] = R::prg(
            &<std::option::Option<std::vec::Vec<u8>> as Clone>::clone(&sd[i]).unwrap(),
            iv,
            lh,
        );
    }
    let mut v = vec![vec![0u8; lh]; d];
    for j in 0..d {
        for i in 0..n / (1_usize << (j + 1)) {
            v[j] = v[j]
                .iter()
                .zip(r[j][2 * i + 1].iter())
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect();
            r[j + 1][i] = r[j][2 * i]
                .iter()
                .zip(r[j][2 * i + 1].iter())
                .map(|(&x1, x2)| x1 ^ x2)
                .collect();
        }
    }
    for j in 0..d {
        for _i in 0..n / (1_usize << (d - j - 1)) {}
    }
    let u = r[d][0].clone().to_vec();
    (u, v)
}

//constant time checking the value of i : if i is not correct, then the output will be an empty vec
pub fn chaldec(chal: &[u8], k0: u16, t0: u16, k1: u16, t1: u16, i: u16) -> Vec<u8> {
    let mut lo = 1_u16;
    let mut hi = 0_u16;
    if i < t0 {
        lo = i * k0;
        hi = (i + 1) * k0 - 1;
    } else if i < t0 + t1 {
        let t = i - t0;
        lo = t0 * k0 + t * k1;
        hi = t0 * k0 + (t + 1) * k1 - 1;
    }
    let mut res = vec![(chal[(lo / 8) as usize] >> (lo % 8)) & 1];
    for j in 1..hi - lo + 1 {
        res.push((chal[((lo + j) / 8) as usize] >> ((lo + j) % 8)) & 1)
    }
    res
}

#[allow(clippy::type_complexity)]
pub fn volecommit<T, R>(
    r: &[u8],
    iv: u128,
    lh: usize,
    tau: usize,
    k0: u16,
    k1: u16,
) -> (
    Vec<u8>,
    Vec<(Vec<Vec<u8>>, Vec<Vec<u8>>)>,
    Vec<Vec<u8>>,
    Vec<u8>,
    Vec<Vec<Vec<u8>>>,
)
where
    T: BigGaloisField + std::default::Default,
    R: RandomOracle,
{
    /* ok */let tau_res = R::prg(r, iv, tau * ((T::LENGTH)/8) as usize);
    let mut r = vec![T::default(); tau];
    let mut com = vec![Vec::new(); tau];
    let mut decom = vec![(vec![Vec::new()], vec![Vec::new()]); tau];
    let mut sd = vec![Vec::new(); tau];
    let mut u = vec![vec![0; lh]; tau];
    let mut v = vec![Vec::new(); tau];
    let mut c = vec![vec![0; lh]; tau - 1];
    for i in 0..tau {
        r[i] = T::from(&tau_res[i * (T::LENGTH / 8) as usize..(i + 1) * (T::LENGTH / 8) as usize]);
        /* println!("ri = {:?}", r[i]); */
    }
    let tau_0 = T::LENGTH % (tau as u32);
    let mut hasher = R::h1_init();
    for i in 0..tau {
        let b = 1 - (i < tau_0.try_into().unwrap()) as u16;
        let k = ((1 - b) * k0) + b * k1;
        (com[i], decom[i], sd[i]) = commit::<T, R>(r[i], iv, 1u32 << k);
        hasher.h1_update(&com[i]);
        v[i] = vec![vec![0; lh]; k.into()];
        (u[i], v[i]) = convert_to_vole::<R>(&sd[i], iv, lh);
        /* println!(" ");
        println!(" ");
        println!("ui");
        for un in &u[i] {
            print!("0x{:02x}, ", un);
        }
        println!(" "); */
        /* println!("vi");
        for un in &v[i] {
            for deux in un{
                print!("0x{:02x}, ", deux);
            }
        }
        println!(" ");
        println!(" "); */
    }
    for i in 1..tau {
        c[i - 1] = u[0]
            .iter()
            .zip(u[i].iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
    }
    let mut hcom = vec![0; (T::LENGTH / 4).try_into().unwrap()];
    hasher.h1_finish(&mut hcom);
    (hcom, decom, c, u[0].clone(), v)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn volereconstruct<T, R>(
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
        let delta_p = chaldec(chal, k0, tau0, k1, tau1, i.try_into().unwrap());
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
