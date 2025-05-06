use generic_array::{ArrayLength, GenericArray, typenum::Unsigned};
use itertools::izip;

use crate::{fields::Square, parameter::TauParameters};

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

#[inline]
const fn extract_k_bits_first_byte(
    chall: &[u8],
    first_byte: usize,
    bit_off: usize,
    k: usize,
) -> u16 {
    let mask = (1 << k) - 1;
    (chall[first_byte] as u16 >> bit_off) & mask
}

#[inline]
const fn extract_k_bits_next_bytes(chall: &[u8], byte_idx: usize, k: usize) -> u16 {
    let mask = (1 << k) - 1;
    chall[byte_idx] as u16 & mask
}

/// Directly convert `chal[start_bit...start_bit+k]` into a 16-bit integer
const fn chall_to_u16(chall: &[u8], start_bit: usize, k: usize) -> u16 {
    // As by current specification, we assume k<16
    debug_assert!(k < 16);
    debug_assert!(chall.len() >= k);

    // Starting byte and offset within byte
    let byte_idx = start_bit / 8;
    let bit_off = start_bit % 8;

    // Number of bits available from first byte
    let nbits_first_byte = 8 - bit_off;

    // Only consider first byte
    if k <= nbits_first_byte {
        // Take k bits from first byte
        return extract_k_bits_first_byte(chall, byte_idx, bit_off, k);
    }

    // Only consider first two bytes
    if k <= 8 + nbits_first_byte {
        // Take all bits from first byte
        let res = extract_k_bits_first_byte(chall, byte_idx, bit_off, nbits_first_byte);
        // Take remaining bits from second byte
        return res
            | extract_k_bits_next_bytes(chall, byte_idx + 1, k - nbits_first_byte)
                << nbits_first_byte;
    }

    // Take all bits from first byte
    let mut res = extract_k_bits_first_byte(chall, byte_idx, bit_off, nbits_first_byte);
    // Take all bits from second byte
    res |= extract_k_bits_next_bytes(chall, byte_idx + 1, 8) << nbits_first_byte;
    // Take remaining bits from third byte
    res | extract_k_bits_next_bytes(chall, byte_idx + 2, k - nbits_first_byte - 8)
        << (nbits_first_byte + 8)
}

pub(crate) fn decode_all_chall_3<TAU: TauParameters>(chall: &[u8]) -> GenericArray<u16, TAU::Tau> {
    let k = TAU::K::USIZE;

    // Compute Delta_i[0...Tau1)
    let first_half =
        (0..TAU::Tau1::USIZE).map(|i| chall_to_u16(chall, TAU::tau1_offset_unchecked(i), k));

    // Compute Delta_i[Tau1..Tau)
    let second_half = (TAU::Tau1::USIZE..TAU::Tau::USIZE)
        .map(|i| chall_to_u16(chall, TAU::tau0_offset_unchecked(i), k - 1));

    first_half.chain(second_half).collect()
}

/// Xors the input slices and retuns an iterator over the resulting elements.
///
/// The length of the resulting iterator is equal to the length of the shortest input slice.
pub(crate) fn xor_arrays<'a>(lhs: &'a [u8], rhs: &'a [u8]) -> impl Iterator<Item = u8> + use<'a> {
    izip!(lhs, rhs).map(|(lhs, rhs)| lhs ^ rhs)
}

/// Xors the input slices overwriting the first slice with the resulting elements.
pub(crate) fn xor_arrays_inplace(lhs: &mut [u8], rhs: &[u8]) {
    izip!(lhs.iter_mut(), rhs).for_each(|(lhs, rhs)| *lhs ^= rhs);
}

/// Returns the bit at the given index in the input byte array.
///
/// Panics if the index is out of bounds.
#[inline]
pub(crate) const fn get_bit(input: &[u8], index: usize) -> u8 {
    let byte_index = index / 8;
    let bit_offset = index % 8;
    (input[byte_index] >> bit_offset) & 1
}

/// Squares every the element of the input array.
///
/// Returns a new array of squared elements.
#[inline]
pub(crate) fn square_array<T, L>(
    key_bytes: &GenericArray<T, L>,
) -> GenericArray<<T as Square>::Output, L>
where
    T: Clone + Square,
    L: ArrayLength,
{
    key_bytes.iter().cloned().map(|x| x.square()).collect()
}

#[cfg(test)]
pub(crate) mod test {
    use std::{fs::File, path::Path};

    use serde::de::DeserializeOwned;

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

    pub(crate) fn hash_array(data: &[u8]) -> Vec<u8> {
        use sha3::digest::{ExtendableOutput, Update, XofReader};

        let mut hasher = sha3::Shake256::default();
        hasher.update(data);
        let mut reader = hasher.finalize_xof();
        let mut ret = [0u8; 64];

        reader.read(&mut ret);
        ret.to_vec()
    }
}
