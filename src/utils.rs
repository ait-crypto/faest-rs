use std::{array, f32::consts::TAU, io::Read, iter::zip};

use bitvec::prelude::*;
use bitvec::{order::Lsb0, slice::BitSlice, view::BitView};
use generic_array::typenum::bit;
use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use itertools::iproduct;

use crate::{
    fields::ByteCombine,
    parameter::TauParameters,
    // parameter::{BaseParameters, OWFParameters, TauParameters},
};

/// Reader interface for PRGs and random oracles
pub(crate) trait Reader {
    /// Read bytes from PRG/random oracle
    fn read(&mut self, dst: &mut [u8]);

    /// Read into array and consume the reader
    fn read_into<Length: ArrayLength>(mut self) -> GenericArray<u8, Length>
    where
        Self: Sized,
    {
        let mut dst = GenericArray::default();
        self.read(&mut dst);
        dst
    }
}

fn chall_to_u16(chall: &[u8], start_bit: usize, mut k: usize) -> u16 {
    let mut result = 0u16;

    let byte_idx = start_bit / 8;
    let bit_off = start_bit % 8;

    // Take bits from lo to end of first byte
    let taken = std::cmp::min(k, 8 - bit_off);
    let mask = (1 << taken) - 1;
    result |= (chall[byte_idx] as u16 >> bit_off) & mask;
    k -= taken;

    // Take bits from next byte
    if k != 0 {
        let taken = std::cmp::min(k, 8);
        let mask = (1 << taken) - 1;
        result |= (chall[byte_idx + 1] as u16 & mask) << 8 - bit_off;
        k -= taken;
    }

    if k != 0 {
        let mask = (1 << k) - 1;
        result |= (chall[byte_idx + 2] as u16 & mask) << 16 - bit_off;
    }

    result
}

pub(crate) fn decode_all_chall_3<TAU: TauParameters>(chall: &[u8]) -> GenericArray<u16, TAU::Tau> {
    let k = TAU::K::USIZE;

    (0..TAU::Tau1::USIZE)
        .map(|i| chall_to_u16(chall, TAU::tau1_offset_unchecked(i), k))
        .chain(
            (TAU::Tau1::USIZE..TAU::Tau::USIZE)
                .map(|i| chall_to_u16(chall, TAU::tau0_offset_unchecked(i), k - 1)),
        )
        .collect()
}

// pub(crate) type Field<O> = <<O as OWFParameters>::BaseParams as BaseParameters>::Field;

// pub(crate) fn transpose_and_into_field<O>(
//     gv: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
// ) -> Box<GenericArray<Field<O>, O::LAMBDAL>>
// where
//     O: OWFParameters,
// {
//     Box::<GenericArray<_, O::LAMBDAL>>::from_iter(
//         iproduct!(0..O::LBYTES::USIZE + O::LAMBDABYTES::USIZE, 0..8,).map(|(i, k)| {
//             Field::<O>::from(&GenericArray::<_, O::LAMBDABYTES>::from_iter(
//                 (0..O::LAMBDABYTES::USIZE)
//                     .map(|j| (0..8).fold(0, |a, l| a ^ (((gv[j * 8 + l][i] >> k) & 1) << l))),
//             ))
//         }),
//     )
// }0x48, 0xb0, 0xcd, 0x3a, 0x03, 0x76, 0x84, 0x7b,

// #[allow(clippy::boxed_local)]
// pub(crate) fn convert_gq<O, Tau>(
//     d: &GenericArray<u8, O::LBYTES>,
//     mut gq: Box<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>,
//     chall3: &GenericArray<u8, O::LAMBDABYTES>,
// ) -> Box<GenericArray<Field<O>, O::LAMBDAL>>
// where
//     O: OWFParameters,
//     Tau: TauParameters,
// {
//     for index in (0..Tau::Tau::USIZE).flat_map(|i| {
//         let converted_index = Tau::convert_index(i);
//         Tau::decode_challenge_as_iter(chall3, i)
//             .enumerate()
//             .filter_map(move |(j, delta_j)| {
//                 if delta_j != 0 {
//                     Some(converted_index + j)
//                 } else {
//                     None
//                 }
//             })
//     }) {
//         for (gq_k, d_k) in zip(gq[index].iter_mut(), d) {
//             *gq_k ^= d_k;
//         }
//     }

//     transpose_and_into_field::<O>(&gq)
// }

// pub(crate) fn bit_combine_with_delta<O>(x: u8, delta: &Field<O>) -> Field<O>
// where
//     O: OWFParameters,
// {
//     let tmp = array::from_fn(|index| *delta * ((x >> (index % 8)) & 1));
//     Field::<O>::byte_combine(&tmp)
// }

// /// Check for `0` in buffers for key validity.
// ///
// /// This function does not need to be constant time. It may only return early
// /// during key generation. During witness extension it always returns `false`
// /// and iterates over all bytes of the buffer.
// pub(crate) fn contains_zeros(buf: &[u8]) -> bool {
//     buf.contains(&0)
// }

#[cfg(test)]
pub(crate) mod test {
    use std::{fs::File, path::Path};

    use generic_array::GenericArray;
    use serde::de::DeserializeOwned;

    use crate::parameter::{Tau128Fast, Tau128Small};

    pub(crate) fn read_test_data<T: DeserializeOwned>(path: &str) -> Vec<T> {
        File::open(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/data")
                .join(path),
        )
        .map_or_else(
            |_| {
                println!("Test file {} is not available. Skipping test.", path);
                Ok(Vec::new())
            },
            serde_json::from_reader,
        )
        .unwrap_or_else(|_| panic!("Failed to read JSON test data from {}", path))
    }

    #[test]
    pub fn test_chall() {
        let chal = GenericArray::from_array([
            0x71, 0x55, 0xb8, 0xf0, 0xde, 0x65, 0xbe, 0xd1, 0x93, 0xb8, 0x61, 0x5b, 0xcd, 0xe6,
            0x89, 0x00,
        ]);

        let i_delta = super::decode_all_chall_3::<Tau128Fast>(chal.as_slice());
        println!("{:?}", i_delta);
    }
}
