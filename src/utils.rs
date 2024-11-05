use std::{array, iter::zip};

use generic_array::{typenum::Unsigned, GenericArray};
use itertools::iproduct;

use crate::{
    fields::ByteCombine,
    parameter::{BaseParameters, OWFParameters, TauParameters},
};

/// Reader interface for PRGs and random oracles
pub(crate) trait Reader {
    /// Read bytes from PRG/random oracle
    fn read(&mut self, dst: &mut [u8]);
}

pub(crate) type Field<O> = <<O as OWFParameters>::BaseParams as BaseParameters>::Field;

pub(crate) fn transpose_and_into_field<O>(
    gv: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
) -> Box<GenericArray<Field<O>, O::LAMBDAL>>
where
    O: OWFParameters,
{
    Box::<GenericArray<_, O::LAMBDAL>>::from_iter(
        iproduct!(0..O::LBYTES::USIZE + O::LAMBDABYTES::USIZE, 0..8,).map(|(i, k)| {
            Field::<O>::from(&GenericArray::<_, O::LAMBDABYTES>::from_iter(
                (0..O::LAMBDABYTES::USIZE)
                    .map(|j| (0..8).map(|l| ((gv[j * 8 + l][i] >> k) & 1) << l).sum()),
            ))
        }),
    )
}

#[allow(clippy::boxed_local)]
pub(crate) fn convert_gq<O, Tau>(
    d: &GenericArray<u8, O::LBYTES>,
    mut gq: Box<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>,
    chall3: &GenericArray<u8, O::LAMBDABYTES>,
) -> Box<GenericArray<Field<O>, O::LAMBDAL>>
where
    O: OWFParameters,
    Tau: TauParameters,
{
    for i in 0..Tau::Tau0::USIZE {
        for (j, delta_j) in Tau::decode_challenge_as_iter(chall3, i).enumerate() {
            if delta_j != 0 {
                for (gq_k, d_k) in
                    zip(gq[Tau::K0::USIZE * i + j].iter_mut(), d).take(O::L::USIZE / 8)
                {
                    *gq_k ^= d_k;
                }
            }
        }
    }
    for i in 0..Tau::Tau1::USIZE {
        for (j, delta_j) in Tau::decode_challenge_as_iter(chall3, Tau::Tau0::USIZE + i).enumerate()
        {
            if delta_j != 0 {
                for (gq_k, d_k) in zip(
                    gq[Tau::Tau0::USIZE * Tau::K0::USIZE + Tau::K1::USIZE * i + j].iter_mut(),
                    d,
                )
                .take(O::L::USIZE / 8)
                {
                    *gq_k ^= d_k;
                }
            }
        }
    }

    transpose_and_into_field::<O>(&gq)
}

pub(crate) fn bit_combine_with_delta<O>(x: u8, delta: &Field<O>) -> Field<O>
where
    O: OWFParameters,
{
    let tmp = array::from_fn(|index| *delta * ((x >> (index % 8)) & 1));
    Field::<O>::byte_combine(&tmp)
}

pub(crate) fn contains_zeros(buf: &[u8]) -> bool {
    buf.contains(&0)
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
        .expect(&format!("Failed to read JSON test data from {}", path))
    }
}
