use std::iter::zip;

use generic_array::{typenum::Unsigned, GenericArray};

use crate::parameter::{BaseParameters, OWFParameters, TauParameters};

/// Reader interface for PRGs and random oracles
pub(crate) trait Reader {
    /// Read bytes from PRG/random oracle
    fn read(&mut self, dst: &mut [u8]);
}

#[allow(clippy::boxed_local)]
pub(crate) fn convert_gq<O, Tau>(
    d: &GenericArray<u8, O::LBYTES>,
    mut gq: Box<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>,
    chall3: &GenericArray<u8, O::LAMBDABYTES>,
) -> Box<GenericArray<<O::BaseParams as BaseParameters>::Field, O::LAMBDAL>>
where
    O: OWFParameters,
    Tau: TauParameters,
{
    for i in 0..Tau::Tau0::USIZE {
        let sdelta = Tau::decode_challenge(chall3, i);
        for j in 0..Tau::K0::USIZE {
            if sdelta[j] != 0 {
                for (gq_k, d_k) in
                    zip(gq[Tau::K0::USIZE * i + j].iter_mut(), d).take(O::L::USIZE / 8)
                {
                    *gq_k ^= d_k;
                }
            }
        }
    }
    for i in 0..Tau::Tau1::USIZE {
        let sdelta = Tau::decode_challenge(chall3, Tau::Tau0::USIZE + i);
        for j in 0..Tau::K1::USIZE {
            if sdelta[j] != 0 {
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

    let mut temp_q: Box<GenericArray<u8, O::LAMBDALBYTESLAMBDA>> = GenericArray::default_boxed();
    for i in 0..(O::L::USIZE + O::LAMBDA::USIZE) / 8 {
        for k in 0..8 {
            for j in 0..O::LAMBDABYTES::USIZE {
                temp_q[i * O::LAMBDA::USIZE + k * O::LAMBDA::USIZE / 8 + j] =
                    (0..8).map(|l| ((gq[(j * 8) + l][i] >> k) & 1) << l).sum();
            }
        }
    }

    Box::<GenericArray<_, _>>::from_iter(temp_q.chunks(O::LAMBDABYTES::USIZE).map(From::from))
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
