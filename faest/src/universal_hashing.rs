use crate::{fields::{self, Field, GaloisField, GF64}, parameter::PARAMOWF};
use cipher::Unsigned;

use generic_array::{sequence::GenericSequence, GenericArray};



#[allow(dead_code)]
pub fn volehash<T, O>(sd: &GenericArray<u8, O::CHALL1>, x0: &GenericArray<u8, O::LAMBDALBYTES>, x1: &GenericArray<u8, O::LAMBDAPLUS2>) ->  GenericArray<u8, O::LAMBDAPLUS2>
where
    T: fields::BigGaloisField + std::fmt::Debug,
    O: PARAMOWF,

{
    let l =  <O::L as Unsigned>::to_usize()/ 8;
    let lambda = (T::LENGTH as usize) / 8; 
    let l_p : usize = lambda * 8 * (l + lambda * 8).div_ceil(lambda * 8);
    let mut r: [T; 4] = [T::new(0u128, 0u128); 4];
    for i in 0..4 {
        r[i] = T::to_field(&sd[i * lambda..(i + 1) * lambda])[0];
    }
    
    let s = T::to_field(&sd[4 * lambda..5 * lambda])[0];
    
    let t = &GF64::to_field(&sd[5 * lambda..(5 * lambda) + 8])[0];
    
    let x0 : GenericArray<u8, O::LPRIMEBYTE> = GenericArray::generate(|i : usize| if i < lambda + l {x0[i]} else {0u8});
    
    //use resize to get rid of the vec
    let y_h = T::to_field(&x0.clone());
    
    let y_b = GF64::to_field(&x0);
    
    let mut h0 = T::new(0u128, 0u128);
    let mut s_add = T::ONE;
    for i in 0..l_p/(lambda*8) {
        h0 += s_add * y_h[(l_p/(lambda*8)) - 1 - i];
        s_add *= s;
    }
    let mut h1 = GF64::default();
    let mut t_add = GF64::ONE;
    for i in 0..(l_p / 64) {
        h1 += t_add * y_b[(l_p / 64) - 1 - i];
        t_add *= *t;
    }

    let (h2, h3) = ((r[0] * h0) + (r[1] * h1), ((r[2] * h0) + (r[3] * h1)));
    let mut h = h2.get_value().0.to_le_bytes().to_vec();
    h.append(&mut h2.get_value().1.to_le_bytes()[..(lambda) - 16].to_vec());
    //taking the B first bytes of h3
    h.append(&mut h3.get_value().0.to_le_bytes()[..2].to_vec());
    h.iter_mut().zip(x1.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    (*GenericArray::from_slice(&h)).clone()
}

#[allow(dead_code)]
pub fn zkhash<T, O>(sd: &GenericArray<u8, O::CHALL>, x0: &GenericArray<T, O::C>, x1: T) -> GenericArray<u8, O::LAMBDABYTES>
where
    T: fields::BigGaloisField + std::default::Default + std::fmt::Debug,
    O: PARAMOWF, 

{
    let l: usize = x0.len();
    let lambda = T::LENGTH as usize / 8;
    let r0 = T::to_field(&sd[..lambda])[0];
   
    let r1 = T::to_field(&sd[lambda..2 * lambda])[0];
    
    let s = T::to_field(&sd[2 * lambda..3 * lambda])[0];
    
    let mut t_vec = sd[3 * lambda..].to_vec();  
    t_vec.append(&mut vec![0u8; lambda - 8]);
    
    let t = T::to_field(&t_vec)[0];
    
    let mut h0 = T::default();
    let mut s_add = T::ONE;
    for i in 0..l {
        h0 += x0[l - 1 - i] * s_add;
        s_add *= s;
    }
    
    let mut h1 = T::default();
    let mut t_add = T::ONE;
    for i in 0..l {
        h1 += x0[l - 1 - i] * t_add;
        t_add *= t;
    }

    let gf_h = ((r0 * h0) + (r1 * h1)) + x1;
    let mut h = gf_h.get_value().0.to_le_bytes().to_vec();
    h.append(&mut gf_h.get_value().1.to_le_bytes()[..lambda - 16].to_vec());
    (*GenericArray::from_slice(&h)).clone()
}

#[cfg(test)]
mod test {
    use super::*;

    use generic_array::GenericArray;
    use serde::{de::DeserializeOwned, Deserialize};

    use crate::fields::{GF128, GF192, GF256};
    use crate::parameter::{PARAMOWF128, PARAMOWF192, PARAMOWF256};

    #[derive(Debug, Deserialize)]
    #[serde(bound = "F: DeserializeOwned")]
    struct ZKHashDatabaseEntry<F> {
        sd: Vec<u8>,
        x0: Vec<F>,
        x1: F,
        h: Vec<u8>,
    }

    #[derive(Debug, Deserialize)]
    struct VoleHashDatabaseEntry {
        sd: Vec<u8>,
        x0: Vec<u8>,
        x1: Vec<u8>,
        h: Vec<u8>,
    }

    #[test]
    fn test_volehash_128() {
        let database: Vec<VoleHashDatabaseEntry> =
            serde_json::from_str(include_str!("../tests/data/volehash_128.json")).unwrap();

        for data in database {
            let sd = GenericArray::from_slice(&data.sd);
            let x0 = GenericArray::from_slice(&data.x0);
            let x1 = GenericArray::from_slice(&data.x1);
            let h = *GenericArray::from_slice(&data.h);
            let res = volehash::<GF128, PARAMOWF128>(sd, x0, x1);
            assert_eq!(h, res);
        }
    }

    #[test]
    fn test_volehash_192() {
        let database: Vec<VoleHashDatabaseEntry> =
            serde_json::from_str(include_str!("../tests/data/volehash_192.json")).unwrap();

        for data in database {
            let sd = GenericArray::from_slice(&data.sd);
            let x0 = GenericArray::from_slice(&data.x0);
            let x1 = GenericArray::from_slice(&data.x1);
            let h = *GenericArray::from_slice(&data.h);
            let res = volehash::<GF192, PARAMOWF192>(sd, x0, x1);
            assert_eq!(h, res);
        }
    }

    #[test]
    fn test_volehash_256() {
        let database: Vec<VoleHashDatabaseEntry> =
            serde_json::from_str(include_str!("../tests/data/volehash_256.json")).unwrap();

        for data in database {
            let sd = GenericArray::from_slice(&data.sd);
            let x0 = GenericArray::from_slice(&data.x0);
            let x1 = GenericArray::from_slice(&data.x1);
            let h = *GenericArray::from_slice(&data.h);
            let res = volehash::<GF256, PARAMOWF256>(sd, x0, x1);
            assert_eq!(h, res);
        }
    }

    #[test]
    fn test_zkhash_128() {
        //starting with zkhash128
        //We get the data from the reference implementation
        let database: Vec<ZKHashDatabaseEntry<GF128>> =
            serde_json::from_str(include_str!("../tests/data/zkhash_128.json")).unwrap();

        for data in database {
            let sd = GenericArray::from_slice(&data.sd);
            let x0 = GenericArray::from_slice(&data.x0);
            let x1 = data.x1;
            let h = GenericArray::from_slice(&data.h);
            let res = zkhash::<GF128, PARAMOWF128>(sd, x0, x1);
            assert_eq!(*h, res);
        }
    }

    #[test]
    fn test_zkhash_192() {
        //starting with zkhash192
        //We get the data from the reference implementation
        let database: Vec<ZKHashDatabaseEntry<GF192>> =
            serde_json::from_str(include_str!("../tests/data/zkhash_192.json")).unwrap();

        for data in database {
            let sd = GenericArray::from_slice(&data.sd);
            let x0 = GenericArray::from_slice(&data.x0);
            let x1 = data.x1;
            let h = GenericArray::from_slice(&data.h);
            let res = zkhash::<GF192, PARAMOWF192>(sd, x0, x1);
            assert_eq!(*h, res);
        }
    }

    #[test]
    fn test_zkhash_256() {
        //starting with zkhash192
        //We get the data from the reference implementation
        let database: Vec<ZKHashDatabaseEntry<GF256>> =
            serde_json::from_str(include_str!("../tests/data/zkhash_256.json")).unwrap();

        for data in database {
            let sd = GenericArray::from_slice(&data.sd);
            let x0 = GenericArray::from_slice(&data.x0);
            let x1 = data.x1;
            let h = GenericArray::from_slice(&data.h);
            let res = zkhash::<GF256, PARAMOWF256>(sd, x0, x1);
            assert_eq!(*h, res);
        }
    }
}
