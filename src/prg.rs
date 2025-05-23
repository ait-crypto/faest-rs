//! Implementation of the PRGs for security levels 128, 192 and 256

use aes::cipher::{KeyIvInit, StreamCipher, generic_array::GenericArray as GenericArray_0_14};
use generic_array::{
    ArrayLength, GenericArray,
    typenum::{U16, U24, U32},
};
#[cfg(feature = "zeroize")]
use zeroize::ZeroizeOnDrop;

use crate::utils::Reader;

type Aes128Ctr32LE = ctr::Ctr32LE<aes::Aes128>;
type Aes192Ctr32LE = ctr::Ctr32LE<aes::Aes192>;
type Aes256Ctr32LE = ctr::Ctr32LE<aes::Aes256>;

/// Size of the IV
pub(crate) type IVSize = U16;
/// IV of the PRG
pub(crate) type IV = GenericArray<u8, IVSize>;
/// TWEAK of the PRG
pub(crate) type Twk = u32;

/// Add tweak to the IV
fn add_tweak(iv: &IV, tweak: Twk) -> GenericArray_0_14<u8, IVSize> {
    let mut iv = GenericArray_0_14::from_slice(iv.as_slice()).to_owned();
    let tweaked_word = u32::from_le_bytes([iv[12], iv[13], iv[14], iv[15]]).wrapping_add(tweak);
    iv[12..].copy_from_slice(&tweaked_word.to_le_bytes());
    iv
}

fn read_from_stream<S: StreamCipher>(stream: &mut S, dst: &mut [u8]) {
    /*
    This is acutally the safe variants of this function. But since we are always reading into destinatinations that are all-0, we can just call apply_keystream

    let mut iter = dst.chunks_exact_mut(16);
    let buf = [0u8; 16];
    for chunk in iter.by_ref() {
        stream.apply_keystream_inout(InOutBuf::new(&buf, chunk).unwrap());
    }

    let rem = iter.into_remainder();
    if !rem.is_empty() {
        stream.apply_keystream_inout(InOutBuf::new(&buf[..rem.len()], rem).unwrap());
    }
    */
    stream.apply_keystream(dst);
}

/// Interface for the PRG
pub(crate) trait PseudoRandomGenerator: Sized + Reader {
    /// Size of the PRG key
    type KeySize: ArrayLength;

    /// Instantiate new PRG instance
    fn new_prg(k: &GenericArray<u8, Self::KeySize>, iv: &IV, tweak: Twk) -> Self;
}

#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub(crate) struct PRG128(Aes128Ctr32LE);

impl PseudoRandomGenerator for PRG128 {
    type KeySize = U16;

    fn new_prg(k: &GenericArray<u8, Self::KeySize>, iv: &IV, tweak: Twk) -> Self {
        Self(Aes128Ctr32LE::new(
            GenericArray_0_14::from_slice(k.as_slice()),
            &add_tweak(iv, tweak),
        ))
    }
}

impl Reader for PRG128 {
    fn read(&mut self, dst: &mut [u8]) {
        read_from_stream(&mut self.0, dst);
    }
}

#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub(crate) struct PRG192(Aes192Ctr32LE);

impl PseudoRandomGenerator for PRG192 {
    type KeySize = U24;

    fn new_prg(k: &GenericArray<u8, Self::KeySize>, iv: &IV, tweak: Twk) -> Self {
        Self(Aes192Ctr32LE::new(
            GenericArray_0_14::from_slice(k.as_slice()),
            &add_tweak(iv, tweak),
        ))
    }
}

impl Reader for PRG192 {
    fn read(&mut self, dst: &mut [u8]) {
        read_from_stream(&mut self.0, dst);
    }
}

#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
pub(crate) struct PRG256(Aes256Ctr32LE);

impl PseudoRandomGenerator for PRG256 {
    type KeySize = U32;

    fn new_prg(k: &GenericArray<u8, Self::KeySize>, iv: &IV, tweak: Twk) -> Self {
        Self(Aes256Ctr32LE::new(
            GenericArray_0_14::from_slice(k.as_slice()),
            &add_tweak(iv, tweak),
        ))
    }
}

impl Reader for PRG256 {
    fn read(&mut self, dst: &mut [u8]) {
        read_from_stream(&mut self.0, dst);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_prg128() {
        let key = GenericArray::from_array([
            0xe1, 0x52, 0x3a, 0x89, 0x80, 0xc1, 0x62, 0x83, 0xcb, 0xc8, 0x5e, 0x71, 0x70, 0x3a,
            0x04, 0xd1,
        ]);
        let iv = IV::from_array([
            0xd2, 0x33, 0x1c, 0x8b, 0xd9, 0x1b, 0x1e, 0x01, 0x56, 0x59, 0x09, 0x44, 0x47, 0x2d,
            0x2d, 0xd3,
        ]);
        let tweak = 1180718807;
        let output = [
            0x94, 0xc4, 0xa8, 0xf5, 0x92, 0xd2, 0x43, 0x1c, 0x94, 0x62, 0xb8, 0x81, 0xed, 0x17,
            0x91, 0xdb, 0x1a, 0x91, 0xf4, 0x82, 0xf0, 0xe0, 0xa0, 0x77, 0x30, 0xad, 0xa8, 0xd9,
            0xb4, 0x90, 0x87, 0xfb, 0x4d, 0x55, 0x65, 0xc2, 0x80, 0xdf, 0x8b, 0x56, 0x1d, 0x98,
            0xa3, 0x04, 0xf4, 0xa7, 0x13, 0xe7, 0x1b, 0xa1, 0xae, 0x37, 0xfa, 0xc5, 0x91, 0x2d,
            0x7c, 0x7d, 0xf3, 0x13, 0xd8, 0x12, 0xa1, 0xa1, 0x71, 0x58, 0xaa, 0xa4, 0x57, 0x83,
            0x3e, 0x4d, 0xbc, 0x86, 0x73, 0x79, 0xc4, 0x44, 0xb2, 0xe6, 0xa2, 0x70, 0xc0, 0x45,
            0x4f, 0x06, 0xb6, 0x76, 0x5e, 0x06, 0x27, 0x23, 0x36, 0x78, 0x3f, 0x89, 0x7c, 0x35,
            0xd8, 0x2f, 0x81, 0xe7, 0xd9, 0xc1, 0x92, 0x95, 0xeb, 0xdc, 0xed, 0x0f, 0xdb, 0x19,
            0x8d, 0xc4, 0x4d, 0x57, 0xbf, 0xa4, 0x29, 0x6d, 0x80, 0xda, 0x88, 0x27, 0x6c, 0xe4,
            0x46, 0xa4, 0x7a, 0xee, 0xce, 0x14, 0x5f, 0x58, 0x14, 0x2c, 0x5a, 0xfe, 0x0e, 0xc5,
            0x54, 0xc7, 0x13, 0xac, 0x70, 0x7c, 0x7f, 0x37, 0xb1, 0xf6, 0xe3, 0x6c, 0x72, 0x8b,
            0x4d, 0xa4, 0x14, 0xa6, 0x25, 0xbf, 0xcb, 0x11, 0xda, 0x53, 0x10, 0xad, 0x14, 0xd0,
            0xf6, 0xf9, 0x3b, 0x7e, 0x4b, 0x5a, 0xbd, 0xd0, 0x0a, 0xd8, 0xd4, 0x6f, 0x45, 0xc8,
            0x92, 0x2c, 0x27, 0x30, 0x58, 0x07, 0x11, 0x4b, 0x0b, 0xd6, 0xd4, 0xcc, 0xe5, 0x56,
            0x2b, 0x0a, 0x93, 0x34, 0x7b, 0x87, 0x36, 0xca, 0x48, 0x96, 0xa4, 0x6b, 0x63, 0x66,
            0xeb, 0xbc, 0xf8, 0xf7, 0xef, 0x50, 0x38, 0x15, 0x3f, 0x59, 0x05, 0x95, 0xc5, 0x6f,
            0xba, 0x3b, 0xa7, 0x5f, 0xfe, 0xf8, 0x26, 0xf7,
        ];

        let mut prg = PRG128::new_prg(&key, &iv, tweak);
        let mut res = [0; 232];
        prg.read(&mut res);
        assert_eq!(res, output);
    }

    #[test]
    fn test_prg192() {
        let key = GenericArray::from_array([
            0x2c, 0x15, 0x0b, 0x96, 0xcb, 0x0e, 0xc4, 0x07, 0x1a, 0x05, 0x46, 0x74, 0xcd, 0x35,
            0x2e, 0xd4, 0xda, 0x35, 0x33, 0x8b, 0xea, 0x59, 0xad, 0x66,
        ]);
        let iv = IV::from_array([
            0x06, 0x08, 0xc1, 0x2f, 0x86, 0xe8, 0xeb, 0x59, 0x47, 0x75, 0xa7, 0x31, 0xdf, 0x92,
            0x8c, 0x81,
        ]);
        let tweak = 2615172839;
        let output = [
            0x0e, 0x58, 0x96, 0xbe, 0x5b, 0x55, 0x7e, 0xc3, 0x38, 0xa7, 0x90, 0x1b, 0x47, 0xd8,
            0x37, 0xe5, 0x9a, 0x6a, 0x31, 0xbb, 0xf7, 0xa4, 0x8f, 0x2a, 0x6a, 0x66, 0x8c, 0x54,
            0x16, 0xdb, 0x91, 0xae, 0xee, 0xac, 0x13, 0x50, 0x7b, 0x8f, 0xf9, 0x23, 0x7a, 0x77,
            0x4a, 0xd1, 0x99, 0x95, 0xa7, 0x96, 0x47, 0x0d, 0x6e, 0x1f, 0x43, 0x88, 0x0e, 0x83,
            0xef, 0x8c, 0x1c, 0xf3, 0x4f, 0xd4, 0x1a, 0x31, 0xa9, 0x33, 0x35, 0x5c, 0x65, 0x53,
            0x2c, 0x7c, 0x64, 0x4d, 0xdd, 0xf8, 0xc2, 0x8d, 0x9f, 0xf5, 0x81, 0x81, 0xe8, 0x4d,
            0x82, 0xbc, 0x13, 0xd2, 0x7c, 0x16, 0xe7, 0x21, 0xab, 0xde, 0x71, 0x7d, 0x60, 0x42,
            0xb2, 0x6e, 0xaf, 0x34, 0xd7, 0xf1, 0x01, 0x33, 0xc3, 0x37, 0xe0, 0x09, 0x34, 0xb3,
            0x5c, 0xcf, 0xf6, 0x5b, 0xec, 0x3a, 0x97, 0x14, 0x0e, 0xb5, 0x36, 0xb0, 0x8a, 0x0a,
            0x68, 0x18, 0xda, 0x75, 0x68, 0xed, 0x37, 0x07, 0x27, 0x86, 0x82, 0xf6, 0x58, 0xc6,
            0xe0, 0x81, 0x0e, 0x3b, 0x59, 0x0b, 0x59, 0xd1, 0x9d, 0xe0, 0xde, 0xb2, 0xdf, 0x90,
            0xea, 0x74, 0x4b, 0xcb, 0x00, 0xb9, 0x14, 0x93, 0xe7, 0x65, 0x9b, 0xab, 0x45, 0x3c,
            0x6e, 0xbd, 0xa6, 0x68, 0xf5, 0x6b, 0x8e, 0x48, 0x71, 0xbd, 0x43, 0x44, 0x01, 0xb8,
            0xb7, 0x53, 0x70, 0x29, 0x9e, 0xf0, 0xaa, 0x8c, 0x6e, 0x2f, 0x38, 0x67, 0x23, 0xd1,
            0xd1, 0x34, 0x4c, 0xae, 0x82, 0x75, 0x11, 0x07, 0xd7, 0x50, 0x8e, 0x23, 0x81, 0x88,
            0x08, 0x1c, 0xd3, 0x41, 0x58, 0xed, 0x6d, 0xca, 0x04, 0x09, 0xd7, 0xca, 0x21, 0x1c,
            0x69, 0x77, 0x19, 0x39, 0x1d, 0xab, 0x81, 0xb6,
        ];

        let mut prg = PRG192::new_prg(&key, &iv, tweak);
        let mut res = [0; 232];
        prg.read(&mut res);
        assert_eq!(res, output);
    }

    #[test]
    fn test_prg256() {
        let key = GenericArray::from_array([
            0x2d, 0x2a, 0xe2, 0xd8, 0x95, 0x9c, 0x2a, 0x52, 0xca, 0x6f, 0x92, 0xb7, 0xb1, 0x8e,
            0x4c, 0x58, 0x01, 0xda, 0x83, 0xd0, 0x6d, 0x44, 0x1a, 0x84, 0x89, 0xec, 0xb9, 0xb9,
            0xe0, 0xb0, 0xd2, 0xe1,
        ]);
        let iv = IV::from_array([
            0x15, 0x79, 0x77, 0x10, 0x74, 0xf1, 0xab, 0x33, 0x81, 0x46, 0x57, 0xc2, 0xb4, 0x39,
            0x53, 0x43,
        ]);
        let tweak = 4046638322;
        let output = [
            0x59, 0x4a, 0x97, 0x85, 0xc6, 0x88, 0xae, 0x2a, 0x1f, 0x53, 0x5b, 0x2d, 0x33, 0xe8,
            0x98, 0xe9, 0xae, 0x3b, 0x00, 0x66, 0x52, 0xe5, 0x62, 0x7f, 0xfe, 0xf9, 0x67, 0x6f,
            0xe4, 0x79, 0x8f, 0x4b, 0xbb, 0x2d, 0x7d, 0x96, 0xb3, 0x5a, 0x22, 0xcd, 0xdb, 0xcf,
            0x9e, 0xa8, 0x8d, 0x2a, 0x67, 0x4f, 0x55, 0x29, 0x0c, 0x9c, 0xdd, 0x8d, 0x7a, 0x25,
            0xc8, 0x6b, 0xbb, 0x23, 0x11, 0xe3, 0x84, 0xe3, 0xbf, 0x91, 0x48, 0x40, 0x5c, 0xc3,
            0x85, 0x9b, 0x59, 0xb8, 0x82, 0xf9, 0x5c, 0x59, 0xf7, 0x14, 0x3c, 0xb0, 0xfb, 0xc0,
            0xb4, 0x7d, 0xb9, 0xb3, 0x0e, 0xf2, 0xd8, 0x86, 0xfe, 0xcd, 0x3e, 0xad, 0xd1, 0x4d,
            0xbd, 0x16, 0x2b, 0xa5, 0xd9, 0xcb, 0x2c, 0xaa, 0xbd, 0xea, 0xd3, 0x90, 0x13, 0x81,
            0x8b, 0x21, 0xa1, 0xa3, 0xc4, 0xa6, 0x4d, 0x48, 0xa2, 0x04, 0xf1, 0x0e, 0x8a, 0xd3,
            0x4a, 0xe8, 0xcd, 0xaf, 0x6b, 0xea, 0x49, 0x80, 0x61, 0xd8, 0xf0, 0x2c, 0x6f, 0x77,
            0x7d, 0xc5, 0x5f, 0x42, 0x0d, 0xae, 0xd4, 0xb4, 0xbe, 0xb0, 0x14, 0x40, 0x33, 0x5b,
            0xa6, 0xc3, 0x2b, 0x9f, 0x28, 0x16, 0xcb, 0xcc, 0x15, 0x0c, 0xd6, 0x75, 0x7b, 0xf7,
            0xa9, 0x79, 0x21, 0xae, 0x02, 0x68, 0x9f, 0x90, 0x04, 0xea, 0x46, 0x7a, 0x71, 0x52,
            0x01, 0x11, 0xf0, 0xa8, 0x10, 0xf7, 0xfe, 0x98, 0x7a, 0x43, 0xe2, 0x93, 0x3c, 0xbe,
            0x2d, 0x81, 0x3a, 0x0b, 0xeb, 0x45, 0x5a, 0x03, 0x95, 0x4a, 0x92, 0x11, 0x41, 0x62,
            0xa9, 0x89, 0xce, 0x78, 0xf9, 0xdd, 0xdc, 0xc7, 0xf3, 0x93, 0xbd, 0x47, 0xb5, 0x89,
            0x65, 0x5b, 0xb1, 0x7a, 0xbf, 0xee, 0x1c, 0x45,
        ];

        let mut prg = PRG256::new_prg(&key, &iv, tweak);
        let mut res = [0; 232];
        prg.read(&mut res);
        assert_eq!(res, output);
    }
}
