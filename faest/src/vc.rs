use std::vec;

use cipher::Unsigned;

use generic_array::{GenericArray};

use crate::fields::BigGaloisField;

use crate::random_oracles::RandomOracle;

#[allow(clippy::type_complexity)]
pub fn commit<T, R>(
    r: T,
    iv: u128,
    n: u32,
) -> (GenericArray<u8, R::PRODLAMBDA2>, (Vec<GenericArray<u8, R::LAMBDA>>, Vec<GenericArray<u8, R::PRODLAMBDA2>>), Vec<Option<GenericArray<u8, R::LAMBDA>>>)
where
    T: BigGaloisField,
    R: RandomOracle, 
    
{
    let length = T::LENGTH as usize / 8;
    let mut k : Vec<GenericArray<u8, R::LAMBDA>> = vec![GenericArray::default(); 2 * (n as usize) - 1];
    //step 2..3
    k[0] = (*GenericArray::from_slice(&[&r.get_value().0.to_le_bytes(), &r.get_value().1.to_le_bytes()[..length - 16_usize]].concat())).clone();
    
    for i in 0..n - 1 {
        let new_ks = &R::prg::<R::PRODLAMBDA2>(&k[i as usize].clone(), iv);
        (k[((2 * i) + 1) as usize], k[((2 * i) + 2) as usize]) =
            ((*GenericArray::from_slice(&new_ks[..length])).clone(), (*GenericArray::from_slice(&new_ks[length..])).clone());
    }
    //step 4..5
    let mut sd : Vec<Option<GenericArray<u8, R::LAMBDA>>> = vec![Some(GenericArray::default()); n as usize];
    let mut com : Vec<GenericArray<u8, R::PRODLAMBDA2>> = vec![GenericArray::default(); n as usize];
    let mut pre_h = Vec::new();
    for j in 0..n as usize {
        let seed = (*GenericArray::from_slice(&[k[(n - 1) as usize + j].clone().to_vec(), iv.to_be_bytes().to_vec()].concat())).clone();
        let mut hash : GenericArray<u8, R::PRODLAMBDA3> = GenericArray::default();
        R::h0(seed, &mut hash);
        sd[j] = Some((*GenericArray::from_slice(&hash[..length])).clone());
        com[j] = (*GenericArray::from_slice(&hash[length..])).clone();
        pre_h.append(&mut com[j].to_vec());
    }
    //step 6
    let mut h : GenericArray<u8, R::PRODLAMBDA2> = GenericArray::default();
    R::h1(&pre_h, &mut h);
    (h, (k, com), sd)
}

pub fn open<R, DPOW /*2N - 1 */, D, N>(decom: &(Vec<GenericArray<u8, R::LAMBDA>>, Vec<GenericArray<u8, R::PRODLAMBDA2>>), b: GenericArray<u8, D>) -> (Vec<GenericArray<u8, R::LAMBDA>>, Vec<u8>) 
where 
R: RandomOracle, 
D: generic_array::ArrayLength,

{
    let mut a = 0;
    let d = (usize::BITS - decom.0.len().leading_zeros() - 1) as usize;
    let mut cop :GenericArray<GenericArray<u8, <R as RandomOracle>::LAMBDA>, D> = GenericArray::default();
    //step 4

    for i in 0..d {
        cop[i] =
            decom.0[((1_u32 << (i + 1)) + 2 * a + (1 - b[d - i - 1]) as u32 - 1) as usize].clone();
        
        a = 2 * a + b[d - i - 1] as u32;
    }
    (cop.to_vec(), decom.1[a as usize].clone().to_vec())
}

#[allow(clippy::type_complexity)]
pub fn reconstruct<T, R>(
    pdecom: &(Vec<GenericArray<u8, R::LAMBDA>>, GenericArray<u8, R::PRODLAMBDA2>),
    b: Vec<u8>,
    iv: u128,
) -> (GenericArray<u8, R::PRODLAMBDA2>, Vec<GenericArray<u8, R::LAMBDA>>)
where
    R: RandomOracle,
    T: BigGaloisField,
{
    let length = <R::LAMBDA as Unsigned>::to_usize();
    let mut a = 0;
    let d = b.len() as u32;
    let mut k : Vec<Option::<GenericArray<u8, R::LAMBDA>>> = vec![Some(GenericArray::default()); (1 << (d + 1)) - 1];
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
                let new_ks = R::prg::<R::PRODLAMBDA2>(&k[rank as usize].clone().unwrap(), iv);
                (k[(rank * 2 + 1) as usize], k[(rank * 2 + 2) as usize]) = (
                    Some((*GenericArray::from_slice(&new_ks[..length])).clone()),
                    Some((*GenericArray::from_slice(&new_ks[length..])).clone()),
                );
            }
        }
        a = 2 * a + b_d_i;
    }
    let mut sd : Vec<GenericArray<u8, R::LAMBDA>> = vec![GenericArray::default(); 1<<d];
    let mut com : Vec<GenericArray<u8, R::PRODLAMBDA2>> = vec![GenericArray::default(); 1<<d];
    let mut pre_h = Vec::new();
    //step 11
    for j in 0..(1_u16 << d) {
        if j != a {
            let seed: GenericArray<u8, <R as RandomOracle>::LAMBDA16> = (*GenericArray::from_slice(&[k[(1 << d) - 1 + j as usize].clone().unwrap().to_vec(), iv.to_be_bytes().to_vec()].concat())).clone();
            let mut hash : GenericArray<u8, R::PRODLAMBDA3> = GenericArray::default();
            R::h0(seed, &mut hash);
            sd[j as usize] = (*GenericArray::from_slice(&hash[..length])).clone();
            com[j as usize] = (*GenericArray::from_slice(&hash[length..])).clone();
            pre_h.append(&mut com[j as usize].to_vec());
        } else {
            pre_h.append(&mut pdecom.1.to_vec());
        }
    }
    let mut h: GenericArray<u8, R::PRODLAMBDA2> = GenericArray::default();
    R::h1(&pre_h, &mut h);
    (h, sd)
}

#[allow(clippy::type_complexity)]
pub fn verify<T, R, D, POWD, N>(
    com: GenericArray<u8, R::PRODLAMBDA2>,
    pdecom: (Vec<GenericArray<u8, R::LAMBDA>>, GenericArray<u8, R::PRODLAMBDA2>),
    b: GenericArray<u8, D>,
    iv: u128,
) -> u8
where
    R: RandomOracle, 
    D: generic_array::ArrayLength,
    T: BigGaloisField,

{
    let (com_b, _sd) = reconstruct::<T, R>(&pdecom, b.to_vec(), iv);
    if com_b == com {
        1
    } else {
        0
    }
}

//reconstruct is tested in the integration_test_vc test_commitment_and_decomitment() function.
