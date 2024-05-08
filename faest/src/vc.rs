use std::vec;

use crate::fields::BigGaloisField;
use crate::random_oracles::RandomOracle;

#[allow(clippy::type_complexity)]
pub fn commit<T, R>(
    r: T,
    iv: u128,
    n: u32,
    prg: &dyn Fn(&[u8], u128, usize) -> Vec<u8>,
) -> (Vec<u8>, (Vec<Vec<u8>>, Vec<Vec<u8>>), Vec<Option<Vec<u8>>>)
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
        let new_ks = prg(&k[i as usize], iv, length * 2);
        (k[((2 * i) + 1) as usize], k[((2 * i) + 2) as usize]) =
            (new_ks[..length].to_vec(), new_ks[length..].to_vec());
    }
    //step 4..5
    let mut sd = vec![Some(Vec::new()); n.try_into().unwrap()];
    let mut com = vec![Vec::new(); n.try_into().unwrap()];
    let mut pre_h = Vec::new();
    for j in 0..n as usize {
        let mut seed = k[(n - 1) as usize + j].clone();
        seed.append(&mut iv.to_be_bytes().to_vec());
        let mut hash = vec![0u8; 3 * length];
        R::h0(&seed, &mut hash[..]);
        sd[j] = Some(hash[..length].to_vec());
        com[j] = hash[length..].to_vec();
        pre_h.append(&mut com[j].to_vec());
    }
    //step 6
    let mut h = vec![0u8; 2 * length];
    R::h1(&pre_h, &mut h[..]);
    (h, (k, com), sd)
}

pub fn open(decom: (Vec<Vec<u8>>, Vec<Vec<u8>>), b: Vec<u8>) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut a = 0;
    let d = (usize::BITS - decom.0.len().leading_zeros() - 1) as usize;
    let mut cop = vec![Vec::new(); d];
    //step 4

    for i in 0..d {
        cop[i] =
            decom.0[((1_u32 << (i + 1)) + 2 * a + (1 - b[d - i - 1]) as u32 - 1) as usize].clone();
        a = 2 * a + b[d - i - 1] as u32;
    }
    (cop, decom.1[a as usize].clone())
}

#[allow(clippy::type_complexity)]
pub fn reconstruct<T, R>(
    mut pdecom: (Vec<Vec<u8>>, Vec<u8>),
    b: Vec<u8>,
    iv: u128,
    prg: &dyn Fn(&[u8], u128, usize) -> Vec<u8>,
) -> (Vec<u8>, Vec<Vec<u8>>)
where
    R: RandomOracle,
    T: BigGaloisField,
{
    let length = T::LENGTH as usize / 8;
    let mut a = 0;
    let d = pdecom.0.len() as u32;
    let mut k = vec![Option::<Vec<u8>>::None; (1 << (d + 1)) - 1];
    k[0] = None;
    //step 4
    for i in 1..d + 1 {
        let b_d_i = b[(d - i) as usize] as u16;
        k[((1_u16 << (i)) - 1 + (2 * a) + (1_u16 - b_d_i)) as usize] =
            Some(pdecom.0[(i - 1) as usize].clone());
        k[((1_u16 << (i)) - 1 + (2 * a) + b_d_i) as usize] = None;
        //step 7
        for j in 0..1 << (i - 1) {
            if j != a {
                let rank = (1 << (i - 1)) - 1 + j;
                let new_ks = prg(&k[rank as usize].as_ref().unwrap()[..], iv, length * 2);
                (k[(rank * 2 + 1) as usize], k[(rank * 2 + 2) as usize]) = (
                    Some(new_ks[..length].to_vec()),
                    Some(new_ks[length..].to_vec()),
                );
            }
        }
        a = 2 * a + b_d_i;
    }
    let mut sd = vec![Vec::new(); 1 << d];
    let mut com = vec![Vec::new(); 1 << d];
    let mut pre_h = Vec::new();
    //step 11
    for j in 0..(1_u16 << d) {
        if j != a {
            let mut seed: Vec<u8> = k[(1 << d) - 1 + j as usize].clone().unwrap();
            seed.append(&mut iv.to_be_bytes().to_vec());
            let mut hash = vec![0u8; 3 * length];
            R::h0(&seed, &mut hash[..]);
            sd[j as usize] = hash[..length].to_vec();
            com[j as usize] = hash[length..].to_vec();
            pre_h.append(&mut com[j as usize].to_vec());
        } else {
            pre_h.append(&mut pdecom.1);
        }
    }
    let mut h = vec![0u8; 2 * length];
    R::h1(&pre_h, &mut h[..]);
    (h, sd)
}

#[allow(clippy::type_complexity)]
pub fn verify<T, R>(
    com: Vec<u8>,
    pdecom: (Vec<Vec<u8>>, Vec<u8>),
    b: Vec<u8>,
    iv: u128,
    prg: &dyn Fn(&[u8], u128, usize) -> Vec<u8>,
) -> u8
where
    R: RandomOracle,
    T: BigGaloisField,
{
    let (com_b, _sd) = reconstruct::<T, R>(pdecom, b, iv, prg);
    if com_b == com {
        1
    } else {
        0
    }
}

//reconstruct is tested in the integration_test_vc test_commitment_and_decomitment() function.
