use std::vec;

use crate::fields::BigGaloisField;
use crate::random_oracles::RandomOracle;

fn prg(mut k: Vec<u8>, _iv: u8,_ll: u32) -> Vec<u8> {
    let mut res = k.clone();
    res.append(&mut k);
    res
}

#[allow(clippy::type_complexity)]
pub fn commit<T, R>(r: T, iv: u8, n: u32) -> (Vec<u8>, (Vec<Vec<u8>>, Vec<Vec<u8>>), Vec<Vec<u8>>)
where
    T: BigGaloisField,
    R: RandomOracle,
{
    let length = T::LENGTH as usize / 8;
    let mut k = vec![vec![0u8]; 2 * (n as usize) - 1];
    //step 2..3
    k[0] = r.get_value().0.to_le_bytes().to_vec();
    k[0].append(&mut r.get_value().1.to_le_bytes()[..length - 16_usize].to_vec());
    for i in 0..n - 1 {
        let new_ks = prg(k[i as usize].clone(), iv, T::LENGTH * 2);
        (k[((2 * i) + 1) as usize], k[((2 * i) + 2) as usize]) =
            (new_ks[..length].to_vec(), new_ks[length..].to_vec());
    }
    //step 4..5
    let mut sd = vec![Vec::new(); n.try_into().unwrap()];
    let mut com = vec![Vec::new(); n.try_into().unwrap()];
    let mut pre_h = Vec::new();
    for j in 0..(n) as usize {
        let mut seed = k[(n-1) as usize + j].clone();
        seed.append(&mut vec![iv]);
        let mut hash = vec![0u8; 3 * length];
        R::h0(&seed, &mut hash[..]);
        sd[j] = hash[..length].to_vec();
        com[j] = hash[length..].to_vec();
        pre_h.append(&mut com[j].to_vec());
    }
    //step 6
    let mut h = vec![0u8; 2 * length];
    R::h1(&pre_h, &mut h[..]);
    (h, (k, com), sd)
}

fn numrec(b: &[u8]) -> u32 {
    let mut res = 0u32;
    for (i, _) in b.iter().enumerate().take(4) {
        res += (b[i] as u32) << (8 * i);
    }
    res
}

pub fn open(decom: (Vec<Vec<u8>>, Vec<Vec<u8>>), b: Vec<u8>) -> (Vec<Vec<u8>>, Vec<u8>) {
    let js = numrec(&b);
    let mut a = 0;
    let d = (usize::BITS - decom.0.len().leading_zeros() - 1) as usize;
    let mut cop = vec![Vec::new(); d];
    //step 4
    for i in 0..d {
        let b_d_i = ((b[(d - i) / 8]) as u32 >> (d - i % 8)) & 1;
        cop[i] = decom.0[(2u32.pow(i.try_into().unwrap()) + 2 * a + (1 - b_d_i)
            - 1) as usize]
            .clone();
        a = 2 * a + b_d_i;
    }
    (cop, decom.1[js as usize].clone())
}

fn reconstruct<T, R>(
    mut pdecom: (Vec<Vec<u8>>, Vec<u8>),
    b: Vec<u8>,
    iv: u8,
) -> (Vec<u8>, Vec<Vec<u8>>)
where
    R: RandomOracle,
    T: BigGaloisField,
{
    let length = T::LENGTH as usize / 8;
    let mut a = 0;
    let d = pdecom.0.len() as u32 + 1;
    let mut k = vec![Option::<Vec<u8>>::None; (1 << (d)) - 1];
    k[0] = None;
    //step 4
    for i in 1..d {
        let b_d_i = ((b[((d - i) / 8) as usize] >> ((d - i) % 8)) & 1) as u32;
        k[((1 << (i)) - 1 + (2 * a) + (1 - b_d_i)) as usize] =
            Some(pdecom.0[(i - 1) as usize].clone());
        k[((1 << (i)) - 1 + (2 * a) + b_d_i) as usize] = None;
        //step 7
        for j in 0..1 << (i - 1) {
            if j != a {
                let rank = (1 << (i - 1)) - 1 + j;
                let new_ks = prg(k[rank as usize].clone().unwrap(), iv, T::LENGTH * 2);
                (k[(rank * 2 + 1) as usize], k[(rank * 2 + 2) as usize]) = (
                    Some(new_ks[..length].to_vec()),
                    Some(new_ks[length..].to_vec()),
                );
            }
        }
        a = 2 * a + b_d_i;
    }

    let mut sd = vec![Vec::new(); 1 << (d - 1)];
    let mut com = vec![Vec::new(); 1 << (d - 1)];
    let mut pre_h = Vec::new();
    //step 11
    for j in 0..(1 << (d - 1)) {
        if j != a {
            let mut seed: Vec<u8> = k[(1 << (d - 1)) - 1 + j as usize].clone().unwrap();
            seed.append(&mut vec![iv]);
            let mut hash = vec![0u8; 3 * length];
            R::h0(&seed, &mut hash[..]);
            sd[j as usize] = hash[..length].to_vec();
            com[j as usize] = hash[length..].to_vec();
            pre_h.append(&mut com[j as usize].to_vec());
        } else {
            pre_h.append(&mut pdecom.1)
        }
    }
    let mut h = vec![0u8; 2 * length];
    R::h1(&pre_h, &mut h[..]);
    (h, sd)
}

pub fn verify<T, R>(com: Vec<u8>, pdecom: (Vec<Vec<u8>>, Vec<u8>), b: Vec<u8>, iv: u8) -> u8
where
    R: RandomOracle,
    T: BigGaloisField,
{
    let (com_b, _sd) = reconstruct::<T, R>(pdecom, b, iv);
    if com_b == com {
        1
    } else {
        0
    }
}
