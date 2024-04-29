use aes::cipher::{KeyIvInit, StreamCipher};
type Aes128Ctr128BE = ctr::Ctr128BE<aes::Aes128>;
type Aes192Ctr128BE = ctr::Ctr128BE<aes::Aes192>;
type Aes256Ctr128BE = ctr::Ctr128BE<aes::Aes256>;

pub fn prg_128(k: &[u8], iv: u128, ll: usize) -> Vec<u8> {
    let mut buf = vec![0u8; ll];
    let mut cipher = Aes128Ctr128BE::new(k.into(), &iv.to_be_bytes().into());
    cipher.apply_keystream(&mut buf);
    buf
}

pub fn prg_192(k: &[u8], iv: u128, ll: usize) -> Vec<u8> {
    let mut buf = vec![0; ll];
    let mut cipher = Aes192Ctr128BE::new(k.into(), &iv.to_be_bytes().into());
    cipher.apply_keystream(&mut buf);
    buf
}

pub fn prg_256(k: &[u8], iv: u128, ll: usize) -> Vec<u8> {
    let mut buf = vec![0; ll];
    let mut cipher = Aes256Ctr128BE::new(k.into(), &iv.to_be_bytes().into());
    cipher.apply_keystream(&mut buf);
    buf
}
