use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
};
pub struct Oracle {
    pub gen: fn(u32, Vec<u8>, u32) -> Vec<u8>,
}

pub trait RandomOracle {
    fn get_fn(&self) -> impl Fn(u32, Vec<u8>, u32) -> Vec<u8>;

    fn h0(&self, lambda: u32, mut sd: Vec<u8>) -> Vec<u8> {
        sd.push(0u8);
        self.get_fn()(lambda, sd, 3 * lambda / 8)
    }

    fn h1(&self, lambda: u32, mut sd: Vec<u8>) -> Vec<u8> {
        sd.push(1u8);
        self.get_fn()(lambda, sd, 2 * lambda / 8)
    }

    //---------------------------------------------------------------------------------------------------------------------------------------------------------
    //check the length
    //---------------------------------------------------------------------------------------------------------------------------------------------------------
    fn h2<const J: u8>(&self, lambda: u32, mut sd: Vec<u8>) -> Vec<u8> {
        sd.push(2u8);
        self.get_fn()(lambda, sd, 6)
    }

    fn h3(&self, lambda: u32, mut sd: Vec<u8>) -> Vec<u8> {
        sd.push(3u8);
        self.get_fn()(lambda, sd, lambda / 8 + 16)
    }
}

#[allow(dead_code)]
pub fn shake(lambda: u32, sd: Vec<u8>, l: u32) -> Vec<u8> {
    if lambda == 128 {
        let mut hasher = Shake128::default();
        hasher.update(&sd);
        let mut reader = hasher.finalize_xof();
        let mut res = vec![0u8; l as usize];
        reader.read(&mut res);
        res
    } else {
        let mut hasher = Shake256::default();
        hasher.update(&sd);
        let mut reader = hasher.finalize_xof();
        let mut res = vec![0u8; l as usize];
        reader.read(&mut res);
        res
    }
}

impl RandomOracle for Oracle {
    fn get_fn(&self) -> fn(u32, Vec<u8>, u32) -> Vec<u8> {
        self.gen
    }
}
