use sha3::{
    digest::{core_api::CoreWrapper, ExtendableOutput, Update, XofReader}, Shake128, Shake256
};

use crate::random_oracles;

pub trait RandomOracle {

    type Hasher : Hasher;

    fn h0(data: &[u8], dest : &mut[u8]) {
        let mut hasher = Self::h0_init();
        hasher.h0_update(data);
        hasher.h0_finish(dest);
    }

    fn h1(data: &[u8], dest : &mut[u8]) {
        let mut hasher = Self::h1_init();
        hasher.h1_update(data);
        hasher.h1_finish(dest);
    }
    
    fn h2(data: &[u8], dest : &mut[u8]) {
        let mut hasher = Self::h2_init();
        hasher.h2_update(data);
        hasher.h2_finish(dest);
    }

    fn h3(data: &[u8], dest : &mut[u8]) {
        let mut hasher = Self::h3_init();
        hasher.h3_update(data);
        hasher.h3_finish(dest);
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

    fn h0_finish(&mut self, dest : &mut[u8]);

    fn h1_finish(&mut self, dest : &mut[u8]);

    fn h2_finish(&mut self, dest : &mut[u8]);

    fn h3_finish(&mut self, dest : &mut[u8]);
}

pub struct RandomOracleShake128 {}

pub struct Hasher128 {
    hasher : CoreWrapper<sha3::Shake128Core>
}

impl RandomOracle for RandomOracleShake128 {
    type Hasher = Hasher128; 

    fn h0_init() -> random_oracles::Hasher128 {
        Hasher128 {hasher : Shake128::default()}
    }

    fn h1_init() -> random_oracles::Hasher128 {
        Hasher128 {hasher : Shake128::default()}
    }

    fn h2_init() -> random_oracles::Hasher128 {
        Hasher128 {hasher : Shake128::default()}
    }

    fn h3_init() -> random_oracles::Hasher128 {
        Hasher128 {hasher : Shake128::default()}
    }
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

    fn h0_finish(&mut self, dest : &mut[u8]) {
        self.hasher.update(&[0u8]);
        let mut reader = <sha3::digest::core_api::CoreWrapper<sha3::Shake128Core> as Clone>::clone(&self.hasher).finalize_xof();
        reader.read(dest);
    }

    fn h1_finish(&mut self, dest : &mut[u8]) {
        self.hasher.update(&[1u8]);
        let mut reader = <sha3::digest::core_api::CoreWrapper<sha3::Shake128Core> as Clone>::clone(&self.hasher).finalize_xof();
        reader.read(dest);
    }

    fn h2_finish(&mut self, dest : &mut[u8]) {
        self.hasher.update(&[2u8]);
        let mut reader = <sha3::digest::core_api::CoreWrapper<sha3::Shake128Core> as Clone>::clone(&self.hasher).finalize_xof();
        reader.read(dest);
    }

    fn h3_finish(&mut self, dest : &mut[u8]) {
        self.hasher.update(&[3u8]);
        let mut reader = <sha3::digest::core_api::CoreWrapper<sha3::Shake128Core> as Clone>::clone(&self.hasher).finalize_xof();
        reader.read(dest);
    }
}


pub struct RandomOracleShake256 {}

pub struct Hasher256 {
    hasher : CoreWrapper<sha3::Shake256Core>
}

impl RandomOracle for RandomOracleShake256 {
    type Hasher = Hasher256; 

    fn h0_init() -> random_oracles::Hasher256 {
        Hasher256 {hasher : Shake256::default()}
    }

    fn h1_init() -> random_oracles::Hasher256 {
        Hasher256 {hasher : Shake256::default()}
    }

    fn h2_init() -> random_oracles::Hasher256 {
        Hasher256 {hasher : Shake256::default()}
    }

    fn h3_init() -> random_oracles::Hasher256 {
        Hasher256 {hasher : Shake256::default()}
    }
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

    fn h0_finish(&mut self, dest : &mut[u8]) {
        self.hasher.update(&[0u8]);
        let mut reader = <sha3::digest::core_api::CoreWrapper<sha3::Shake256Core> as Clone>::clone(&self.hasher).finalize_xof();
        reader.read(dest);
    }

    fn h1_finish(&mut self, dest : &mut[u8]) {
        self.hasher.update(&[1u8]);
        let mut reader = <sha3::digest::core_api::CoreWrapper<sha3::Shake256Core> as Clone>::clone(&self.hasher).finalize_xof();
        reader.read(dest);
    }

    fn h2_finish(&mut self, dest : &mut[u8]) {
        self.hasher.update(&[2u8]);
        let mut reader = <sha3::digest::core_api::CoreWrapper<sha3::Shake256Core> as Clone>::clone(&self.hasher).finalize_xof();
        reader.read(dest);
    }

    fn h3_finish(&mut self, dest : &mut[u8]) {
        self.hasher.update(&[3u8]);
        let mut reader = <sha3::digest::core_api::CoreWrapper<sha3::Shake256Core> as Clone>::clone(&self.hasher).finalize_xof();
        reader.read(dest);
    }
}
