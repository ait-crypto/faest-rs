use std::{
    iter::zip,
    marker::PhantomData,
    ops::{Index, IndexMut},
};

use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

use crate::{
    parameter::TauParameters,
    prg::{PseudoRandomGenerator, IV},
    random_oracles::{Hasher, RandomOracle},
    utils::Reader,
    vc::VectorCommitment,
};

#[allow(clippy::type_complexity)]
fn convert_to_vole<'a, PRG, LH>(
    v: &mut [GenericArray<u8, LH>],
    sd_0: Option<&GenericArray<u8, PRG::KeySize>>,
    sd: impl ExactSizeIterator<Item = &'a GenericArray<u8, PRG::KeySize>>,
    iv: &IV,
) -> GenericArray<u8, LH>
where
    PRG: PseudoRandomGenerator,
    LH: ArrayLength,
{
    // these parameters are known upfront!
    let n = sd.len() + 1;
    let d = 64 - (n.leading_zeros() as usize) - 1;
    let mut r = vec![0; LH::USIZE * n * 2];
    if let Some(sd0) = sd_0 {
        PRG::new_prg(sd0, iv).read(&mut r[0..LH::USIZE]);
    }
    for (ri, sdi) in zip(r[LH::USIZE..].chunks_exact_mut(LH::USIZE), sd) {
        PRG::new_prg(sdi, iv).read(ri);
    }

    // FIXME
    for (j, item) in v.iter_mut().enumerate() {
        let j_offset = (j % 2) * n;
        let j1_offset = ((j + 1) % 2) * n;
        for i in 0..n / (1 << (j + 1)) {
            let j_offset = j_offset + 2 * i;
            let j1_offset = j1_offset + i;
            for k in 0..LH::USIZE {
                item[k] ^= r[(j_offset + 1) * LH::USIZE + k];
                r[j1_offset * LH::USIZE + k] =
                    r[j_offset * LH::USIZE + k] ^ r[(j_offset + 1) * LH::USIZE + k];
            }
        }
    }
    GenericArray::from_slice(&r[(d % 2) * n * LH::USIZE..((d % 2) * n + 1) * LH::USIZE]).clone()
}

/// Reference to storage area in signature for all `c`s.
pub(crate) struct VoleCommitmentCRef<'a, LH>(&'a mut [u8], PhantomData<LH>);

impl<LH> Index<usize> for VoleCommitmentCRef<'_, LH>
where
    LH: ArrayLength,
{
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index * LH::USIZE..(index + 1) * LH::USIZE]
    }
}

impl<LH> IndexMut<usize> for VoleCommitmentCRef<'_, LH>
where
    LH: ArrayLength,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index * LH::USIZE..(index + 1) * LH::USIZE]
    }
}

impl<'a, LH> VoleCommitmentCRef<'a, LH>
where
    LH: ArrayLength,
{
    pub(crate) fn new(buffer: &'a mut [u8]) -> Self {
        Self(buffer, PhantomData)
    }
}

#[allow(clippy::type_complexity)]
pub fn volecommit<VC, Tau, LH>(
    mut c: VoleCommitmentCRef<LH>,
    r: &GenericArray<u8, VC::LambdaBytes>,
    iv: &IV,
) -> (
    GenericArray<u8, VC::LambdaBytesTimes2>,
    //Here decom can have two diferent length, depending on if it's a i < t0 or > 0 so we use vectors
    Box<
        GenericArray<
            (
                Vec<GenericArray<u8, VC::LambdaBytes>>,
                Vec<GenericArray<u8, VC::LambdaBytesTimes2>>,
            ),
            Tau::Tau,
        >,
    >,
    Box<GenericArray<u8, LH>>,
    Box<GenericArray<GenericArray<u8, LH>, VC::Lambda>>,
)
where
    Tau: TauParameters,
    VC: VectorCommitment,
    LH: ArrayLength,
{
    let mut prg = VC::PRG::new_prg(r, iv);
    let mut decom = GenericArray::default_boxed();
    let mut u0 = GenericArray::<u8, LH>::default_boxed();
    let mut v = GenericArray::default_boxed();

    let mut hasher = VC::RO::h1_init();
    for i in 0..Tau::Tau::USIZE {
        let b = usize::from(i < Tau::Tau0::USIZE);
        let k = b * Tau::K0::USIZE + (1 - b) * Tau::K1::USIZE;
        let mut r_i = GenericArray::default();
        prg.read(&mut r_i);
        let (com_i, decom_i, sd_i) = VC::commit(&r_i, iv, 1 << k);
        decom[i] = decom_i;
        hasher.update(&com_i);
        let ui = convert_to_vole::<VC::PRG, _>(
            {
                let (index, size) = Tau::convert_index_and_size(i);
                &mut v[index..index + size]
            },
            Some(&sd_i[0]),
            sd_i.iter().skip(1),
            iv,
        );

        if i == 0 {
            *u0 = ui;
        } else {
            for (c, (u0, ui)) in zip(c[i - 1].iter_mut(), zip(u0.iter(), ui.into_iter())) {
                *c = u0 ^ ui;
            }
        }
    }

    (hasher.finish().read_into(), decom, u0, v)
}

#[allow(clippy::type_complexity)]
pub fn volereconstruct<VC, Tau, LH>(
    chal: &[u8],
    pdecom: &[u8],
    iv: &IV,
) -> (
    GenericArray<u8, VC::LambdaBytesTimes2>,
    Box<GenericArray<GenericArray<u8, LH>, VC::Lambda>>,
)
where
    Tau: TauParameters,
    VC: VectorCommitment,
    LH: ArrayLength,
{
    let mut hasher = VC::RO::h1_init();
    let q = Box::from_iter((0..Tau::Tau::USIZE).flat_map(|i| {
        let delta_p = Tau::decode_challenge(chal, i);
        let pdecom = if i < Tau::Tau0::USIZE {
            let start =
                Tau::K0::USIZE * i * VC::LambdaBytes::USIZE + i * 2 * VC::LambdaBytes::USIZE;
            &pdecom[start
                ..start + Tau::K0::USIZE * VC::LambdaBytes::USIZE + 2 * VC::LambdaBytes::USIZE]
        } else {
            let start = (Tau::K0::USIZE * Tau::Tau0::USIZE
                + (i - Tau::Tau0::USIZE) * Tau::K1::USIZE)
                * VC::LambdaBytes::USIZE
                + i * 2 * VC::LambdaBytes::USIZE;
            &pdecom[start
                ..start + Tau::K1::USIZE * VC::LambdaBytes::USIZE + 2 * VC::LambdaBytes::USIZE]
        };
        let (com_i, s_i) = VC::reconstruct(pdecom, &delta_p, iv);
        hasher.update(&com_i);

        let delta: usize = delta_p
            .into_iter()
            .enumerate()
            .fold(0, |a, (j, d)| a ^ (usize::from(d) << j));

        let k = if i < Tau::Tau0::USIZE {
            Tau::K0::USIZE
        } else {
            Tau::K1::USIZE
        };

        let mut buf = vec![GenericArray::default(); k];
        convert_to_vole::<VC::PRG, _>(
            buf.as_mut_slice(),
            None,
            (1..(1 << k)).map(|j| &s_i[j ^ delta]),
            iv,
        );
        buf.into_iter()
    }));
    (hasher.finish().read_into(), q)
}

#[cfg(test)]
mod test {
    use super::*;

    use generic_array::{sequence::GenericSequence, GenericArray};
    use serde::Deserialize;

    use crate::{
        parameter::{
            BaseParameters, FAEST128fParameters, FAEST128sParameters, FAEST192fParameters,
            FAEST192sParameters, FAEST256fParameters, FAEST256sParameters, FAESTEM128fParameters,
            FAESTEM128sParameters, FAESTEM192fParameters, FAESTEM192sParameters,
            FAESTEM256fParameters, FAESTEM256sParameters, FAESTParameters, OWFParameters,
        },
        utils::test::read_test_data,
    };

    type VC<P> = <<<P as FAESTParameters>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC;
    type Tau<P> = <P as FAESTParameters>::Tau;
    type LH<P> = <<P as FAESTParameters>::OWF as OWFParameters>::LHATBYTES;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataVoleCommit {
        lambdabytes: [u16; 1],
        k0: [u8; 1],
        hcom: Vec<u8>,
        u: Vec<u8>,
    }

    fn volecommit<VC, Tau, LH>(
        r: &GenericArray<u8, VC::LambdaBytes>,
        iv: &IV,
    ) -> (
        GenericArray<u8, VC::LambdaBytesTimes2>,
        Box<GenericArray<u8, LH>>,
    )
    where
        Tau: TauParameters,
        VC: VectorCommitment,
        LH: ArrayLength,
    {
        let mut c = vec![0; LH::USIZE * (Tau::Tau::USIZE - 1)];
        let ret =
            super::volecommit::<VC, Tau, LH>(VoleCommitmentCRef::new(c.as_mut_slice()), r, iv);
        (ret.0, ret.2)
    }

    #[test]
    fn volecommit_test() {
        let database: Vec<DataVoleCommit> = read_test_data("DataVoleCommit.json");
        for data in database {
            if data.lambdabytes[0] == 16 {
                if data.u.len() == 234 {
                    if data.k0[0] == 12 {
                        let res = volecommit::<
                            VC<FAEST128sParameters>,
                            Tau<FAEST128sParameters>,
                            LH<FAEST128sParameters>,
                        >(
                            &GenericArray::generate(|idx| idx as u8), &IV::default()
                        );
                        assert_eq!(res.0.as_slice(), &data.hcom);
                        assert_eq!(res.1.as_slice(), &data.u);
                    } else {
                        let res = volecommit::<
                            VC<FAEST128fParameters>,
                            Tau<FAEST128fParameters>,
                            LH<FAEST128fParameters>,
                        >(
                            &GenericArray::generate(|idx| idx as u8), &IV::default()
                        );
                        assert_eq!(res.0.as_slice(), &data.hcom);
                        assert_eq!(res.1.as_slice(), &data.u);
                    }
                } else if data.k0[0] == 12 {
                    let res = volecommit::<
                        VC<FAESTEM128sParameters>,
                        Tau<FAESTEM128sParameters>,
                        LH<FAESTEM128sParameters>,
                    >(
                        &GenericArray::generate(|idx| idx as u8), &IV::default()
                    );
                    assert_eq!(res.0.as_slice(), &data.hcom);
                    assert_eq!(res.1.as_slice(), &data.u);
                } else {
                    let res = volecommit::<
                        VC<FAESTEM128fParameters>,
                        Tau<FAESTEM128fParameters>,
                        LH<FAESTEM128fParameters>,
                    >(
                        &GenericArray::generate(|idx| idx as u8), &IV::default()
                    );
                    assert_eq!(res.0.as_slice(), &data.hcom);
                    assert_eq!(res.1.as_slice(), &data.u);
                }
            } else if data.lambdabytes[0] == 24 {
                if data.u.len() == 458 {
                    if data.k0[0] == 12 {
                        let res = volecommit::<
                            VC<FAEST192sParameters>,
                            Tau<FAEST192sParameters>,
                            LH<FAEST192sParameters>,
                        >(
                            &GenericArray::generate(|idx| idx as u8), &IV::default()
                        );
                        assert_eq!(res.0.as_slice(), &data.hcom);
                        assert_eq!(res.1.as_slice(), &data.u);
                    } else {
                        let res = volecommit::<
                            VC<FAEST192fParameters>,
                            Tau<FAEST192fParameters>,
                            LH<FAEST192fParameters>,
                        >(
                            &GenericArray::generate(|idx| idx as u8), &IV::default()
                        );
                        assert_eq!(res.0.as_slice(), &data.hcom);
                        assert_eq!(res.1.as_slice(), &data.u);
                    }
                } else if data.k0[0] == 12 {
                    let res = volecommit::<
                        VC<FAESTEM192sParameters>,
                        Tau<FAESTEM192sParameters>,
                        LH<FAESTEM192sParameters>,
                    >(
                        &GenericArray::generate(|idx| idx as u8), &IV::default()
                    );
                    assert_eq!(res.0.as_slice(), &data.hcom);
                    assert_eq!(res.1.as_slice(), &data.u);
                } else {
                    let res = volecommit::<
                        VC<FAESTEM192fParameters>,
                        Tau<FAESTEM192fParameters>,
                        LH<FAESTEM192fParameters>,
                    >(
                        &GenericArray::generate(|idx| idx as u8), &IV::default()
                    );
                    assert_eq!(res.0.as_slice(), &data.hcom);
                    assert_eq!(res.1.as_slice(), &data.u);
                }
            } else if data.u.len() == 566 {
                if data.k0[0] == 12 {
                    let res = volecommit::<
                        VC<FAEST256sParameters>,
                        Tau<FAEST256sParameters>,
                        LH<FAEST256sParameters>,
                    >(
                        &GenericArray::generate(|idx| idx as u8), &IV::default()
                    );
                    assert_eq!(res.0.as_slice(), &data.hcom);
                    assert_eq!(res.1.as_slice(), &data.u);
                } else {
                    let res = volecommit::<
                        VC<FAEST256fParameters>,
                        Tau<FAEST256fParameters>,
                        LH<FAEST256fParameters>,
                    >(
                        &GenericArray::generate(|idx| idx as u8), &IV::default()
                    );
                    assert_eq!(res.0.as_slice(), &data.hcom);
                    assert_eq!(res.1.as_slice(), &data.u);
                }
            } else if data.k0[0] == 12 {
                let res =
                    volecommit::<
                        VC<FAESTEM256sParameters>,
                        Tau<FAESTEM256sParameters>,
                        LH<FAESTEM256sParameters>,
                    >(&GenericArray::generate(|idx| idx as u8), &IV::default());
                assert_eq!(res.0.as_slice(), &data.hcom);
                assert_eq!(res.1.as_slice(), &data.u);
            } else {
                let res =
                    volecommit::<
                        VC<FAESTEM256fParameters>,
                        Tau<FAESTEM256fParameters>,
                        LH<FAESTEM256fParameters>,
                    >(&GenericArray::generate(|idx| idx as u8), &IV::default());
                assert_eq!(res.0.as_slice(), &data.hcom);
                assert_eq!(res.1.as_slice(), &data.u);
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataVoleReconstruct {
        chal: Vec<u8>,
        pdec: Vec<Vec<Vec<u8>>>,
        com: Vec<Vec<u8>>,
        hcom: Vec<u8>,
        q: Vec<Vec<Vec<u8>>>,
    }

    #[test]
    fn volereconstruct_test() {
        let database: Vec<DataVoleReconstruct> = read_test_data("DataVoleReconstruct.json");
        for data in database {
            if data.chal.len() == 16 {
                if data.q[0].len() == 8 {
                    let pdecom = &data
                        .pdec
                        .into_iter()
                        .zip(&data.com)
                        .flat_map(|(x, y)| {
                            [x.into_iter().flatten().collect::<Vec<u8>>(), y.to_vec()].concat()
                        })
                        .collect::<Vec<u8>>();
                    let res = volereconstruct::<
                        VC<FAEST128fParameters>,
                        Tau<FAEST128fParameters>,
                        LH<FAEST128fParameters>,
                    >(&data.chal, pdecom, &IV::default());
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                } else {
                    let pdecom = &data
                        .pdec
                        .into_iter()
                        .zip(&data.com)
                        .flat_map(|(x, y)| {
                            [x.into_iter().flatten().collect::<Vec<u8>>(), y.to_vec()].concat()
                        })
                        .collect::<Vec<u8>>();
                    let res = volereconstruct::<
                        VC<FAEST128sParameters>,
                        Tau<FAEST128sParameters>,
                        LH<FAEST128sParameters>,
                    >(&data.chal, pdecom, &IV::default());
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                }
            } else if data.chal.len() == 24 {
                if data.q[0].len() == 8 {
                    let pdecom = &data
                        .pdec
                        .into_iter()
                        .zip(&data.com)
                        .flat_map(|(x, y)| {
                            [x.into_iter().flatten().collect::<Vec<u8>>(), y.to_vec()].concat()
                        })
                        .collect::<Vec<u8>>();
                    let res = volereconstruct::<
                        VC<FAEST192fParameters>,
                        Tau<FAEST192fParameters>,
                        LH<FAEST192fParameters>,
                    >(&data.chal, pdecom, &IV::default());
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                } else {
                    let pdecom = &data
                        .pdec
                        .into_iter()
                        .zip(&data.com)
                        .flat_map(|(x, y)| {
                            [x.into_iter().flatten().collect::<Vec<u8>>(), y.to_vec()].concat()
                        })
                        .collect::<Vec<u8>>();
                    let res = volereconstruct::<
                        VC<FAEST192sParameters>,
                        Tau<FAEST192sParameters>,
                        LH<FAEST192sParameters>,
                    >(&data.chal, pdecom, &IV::default());
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                }
            } else if data.q[0].len() == 8 {
                let pdecom = &data
                    .pdec
                    .into_iter()
                    .zip(&data.com)
                    .flat_map(|(x, y)| {
                        [x.into_iter().flatten().collect::<Vec<u8>>(), y.to_vec()].concat()
                    })
                    .collect::<Vec<u8>>();
                let res = volereconstruct::<
                    VC<FAEST256fParameters>,
                    Tau<FAEST256fParameters>,
                    LH<FAEST256fParameters>,
                >(&data.chal, pdecom, &IV::default());
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
            } else {
                let pdecom = &data
                    .pdec
                    .into_iter()
                    .zip(&data.com)
                    .flat_map(|(x, y)| {
                        [x.into_iter().flatten().collect::<Vec<u8>>(), y.to_vec()].concat()
                    })
                    .collect::<Vec<u8>>();
                let res = volereconstruct::<
                    VC<FAEST256sParameters>,
                    Tau<FAEST256sParameters>,
                    LH<FAEST256sParameters>,
                >(&data.chal, pdecom, &IV::default());
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
            }
        }
    }
}
