
use sha3::{
    digest::{core_api::CoreWrapper, ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
};
use cipher::Unsigned;
use std::ops::{Add, Sub};
use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
use typenum::{Prod, U128, U16, U192, U24, U256, U3, U32, U40, U48, U64, U72, U96};

use aes::cipher::{KeyIvInit, StreamCipher};
type Aes128Ctr128BE = ctr::Ctr128BE<aes::Aes128>;
type Aes192Ctr128BE = ctr::Ctr128BE<aes::Aes192>;
type Aes256Ctr128BE = ctr::Ctr128BE<aes::Aes256>;

use crate::random_oracles;

pub trait RandomOracle{
    type Hasher: Hasher;
    type LAMBDA : ArrayLength<u8>;
    type LAMBDA16 : ArrayLength<u8>;
    type PRODLAMBDA3 : ArrayLength<u8>;
    type PRODLAMBDA2 : ArrayLength<u8>;

    fn prg<LH>(k: GenericArray<u8, Self::LAMBDA>, iv: u128,) -> GenericArray<u8, LH> where LH : ArrayLength<u8>;

    fn h0(data: GenericArray<u8, Self::LAMBDA16>, dest: &mut GenericArray<u8, Self::PRODLAMBDA3>) {
        let mut hasher = Self::h0_init();
        hasher.h0_update(&data);
        hasher.h0_finish(dest);
    }

    fn h1(data: &[u8], dest: &mut GenericArray<u8, Self::PRODLAMBDA2>) {
        let mut hasher = Self::h1_init();
        hasher.h1_update(&data);
        hasher.h1_finish(dest);
    }

    fn h2(data: &[u8], dest: &mut [u8]) {
        let mut hasher = Self::h2_init();
        hasher.h2_update(data);
        hasher.h2_finish(dest);
    }

    fn h3(data: &[u8], mut dest: GenericArray<u8, Self::LAMBDA16>) {
        let mut hasher = Self::h3_init();
        hasher.h3_update(data);
        hasher.h3_finish(&mut dest);
    }

    fn h0_init() -> Self::Hasher;

    fn h1_init() -> Self::Hasher;

    fn h2_init() -> Self::Hasher;

    fn h3_init() -> Self::Hasher;
}

pub trait Hasher {
    fn h0_update(&mut self, data: &[u8]);

    fn h1_update(&mut self, data: &[u8]);

    fn h2_update(&mut self, data: &[u8]);

    fn h3_update(&mut self, data: &[u8]);

    fn h0_finish(&mut self, dest: &mut [u8]);

    fn h1_finish(&mut self, dest: &mut [u8]);

    fn h2_finish(&mut self, dest: &mut [u8]);

    fn h3_finish(&mut self, dest: &mut [u8]);
}

pub struct RandomOracleShake128 {}

pub struct Hasher128 {
    hasher: CoreWrapper<sha3::Shake128Core>,
}

impl RandomOracle for RandomOracleShake128 {
    type Hasher = Hasher128;

    fn h0_init() -> random_oracles::Hasher128 {
        Hasher128 {
            hasher: Shake128::default(),
        }
    }

    fn h1_init() -> random_oracles::Hasher128 {
        Hasher128 {
            hasher: Shake128::default(),
        }
    }

    fn h2_init() -> random_oracles::Hasher128 {
        Hasher128 {
            hasher: Shake128::default(),
        }
    }

    fn h3_init() -> random_oracles::Hasher128 {
        Hasher128 {
            hasher: Shake128::default(),
        }
    }

    fn prg<LH>(k: GenericArray<u8, Self::LAMBDA>, iv: u128) -> GenericArray<u8, LH> where LH : ArrayLength<u8>{
        let mut buf = GenericArray::generate(|i : usize| 0u8);
        let mut cipher = Aes128Ctr128BE::new(&k, &iv.to_be_bytes().into());
        cipher.apply_keystream(&mut buf);
        buf
    }
    
    type LAMBDA = U16;
    
    type LAMBDA16 = U32;
    
    type PRODLAMBDA3 = U48;
    
    type PRODLAMBDA2 = U32;
}

impl Hasher for Hasher128 {
    fn h0_update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn h1_update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn h2_update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn h3_update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn h0_finish(&mut self, dest: &mut [u8]) {
        self.hasher.update(&[0u8]);
        let mut reader =
            <sha3::digest::core_api::CoreWrapper<sha3::Shake128Core> as Clone>::clone(&self.hasher)
                .finalize_xof();
        reader.read(dest);
    }

    fn h1_finish(&mut self, dest: &mut [u8]) {
        self.hasher.update(&[1u8]);
        let mut reader =
            <sha3::digest::core_api::CoreWrapper<sha3::Shake128Core> as Clone>::clone(&self.hasher)
                .finalize_xof();
        reader.read(dest);
    }

    fn h2_finish(&mut self, dest: &mut [u8]) {
        self.hasher.update(&[2u8]);
        let mut reader =
            <sha3::digest::core_api::CoreWrapper<sha3::Shake128Core> as Clone>::clone(&self.hasher)
                .finalize_xof();
        reader.read(dest);
    }

    fn h3_finish(&mut self, dest: &mut [u8]) {
        self.hasher.update(&[3u8]);
        let mut reader =
            <sha3::digest::core_api::CoreWrapper<sha3::Shake128Core> as Clone>::clone(&self.hasher)
                .finalize_xof();
        reader.read(dest);
    }
}

pub struct RandomOracleShake192 {}

impl RandomOracle for RandomOracleShake192 {
    type Hasher = Hasher256;

    fn h0_init() -> random_oracles::Hasher256 {
        Hasher256 {
            hasher: Shake256::default(),
        }
    }

    fn h1_init() -> random_oracles::Hasher256 {
        Hasher256 {
            hasher: Shake256::default(),
        }
    }

    fn h2_init() -> random_oracles::Hasher256 {
        Hasher256 {
            hasher: Shake256::default(),
        }
    }

    fn h3_init() -> random_oracles::Hasher256 {
        Hasher256 {
            hasher: Shake256::default(),
        }
    }

    fn prg<LH>(k: GenericArray<u8, Self::LAMBDA>, iv: u128) -> GenericArray<u8, LH> where LH : ArrayLength<u8>{
        let mut buf = GenericArray::generate(|i:usize|0u8);
        let mut cipher = Aes192Ctr128BE::new(&k, &iv.to_be_bytes().into());
        cipher.apply_keystream(&mut buf);
        buf
    }
    
    type LAMBDA = U24;
    
    type LAMBDA16 = U40;
    
    type PRODLAMBDA3 = U72;
    
    type PRODLAMBDA2 = U48;
}

impl Hasher for Hasher256 {
    fn h0_update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn h1_update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn h2_update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn h3_update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn h0_finish(&mut self, dest: &mut [u8]) {
        self.hasher.update(&[0u8]);
        let mut reader =
            <sha3::digest::core_api::CoreWrapper<sha3::Shake256Core> as Clone>::clone(&self.hasher)
                .finalize_xof();
        reader.read(dest);
    }

    fn h1_finish(&mut self, dest: &mut [u8]) {
        self.hasher.update(&[1u8]);
        let mut reader =
            <sha3::digest::core_api::CoreWrapper<sha3::Shake256Core> as Clone>::clone(&self.hasher)
                .finalize_xof();
        reader.read(dest);
    }

    fn h2_finish(&mut self, dest: &mut [u8]) {
        self.hasher.update(&[2u8]);
        let mut reader =
            <sha3::digest::core_api::CoreWrapper<sha3::Shake256Core> as Clone>::clone(&self.hasher)
                .finalize_xof();
        reader.read(dest);
    }

    fn h3_finish(&mut self, dest: &mut [u8]) {
        self.hasher.update(&[3u8]);
        let mut reader =
            <sha3::digest::core_api::CoreWrapper<sha3::Shake256Core> as Clone>::clone(&self.hasher)
                .finalize_xof();
        reader.read(dest);
    }
}

pub struct RandomOracleShake256 {}

pub struct Hasher256 {
    hasher: CoreWrapper<sha3::Shake256Core>,
}

impl RandomOracle for RandomOracleShake256 {
    type Hasher = Hasher256;

    fn h0_init() -> random_oracles::Hasher256 {
        Hasher256 {
            hasher: Shake256::default(),
        }
    }

    fn h1_init() -> random_oracles::Hasher256 {
        Hasher256 {
            hasher: Shake256::default(),
        }
    }

    fn h2_init() -> random_oracles::Hasher256 {
        Hasher256 {
            hasher: Shake256::default(),
        }
    }

    fn h3_init() -> random_oracles::Hasher256 {
        Hasher256 {
            hasher: Shake256::default(),
        }
    }

    fn prg<LH>(k: GenericArray<u8, Self::LAMBDA>, iv: u128) -> GenericArray<u8, LH> where LH : ArrayLength<u8>{
        let mut buf = GenericArray::generate(|i:usize| 0u8);
        let mut cipher = Aes256Ctr128BE::new(&k, &iv.to_be_bytes().into());
        cipher.apply_keystream(&mut buf);
        buf
    }
    
    type LAMBDA = U32;
    
    type LAMBDA16 = U48;
    
    type PRODLAMBDA3 = U96;
    
    type PRODLAMBDA2 = U64;
}
