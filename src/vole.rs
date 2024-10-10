use std::iter::zip;

use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

use crate::{
    parameter::TauParameters,
    prg::{PseudoRandomGenerator, IV},
    random_oracles::{Hasher, RandomOracle},
    utils::Reader,
    vc::VectorCommitment,
};

#[allow(clippy::type_complexity)]
fn to_vole_convert<'a, PRG, LH>(
    sd_0: Option<&GenericArray<u8, PRG::Lambda>>,
    sd: impl ExactSizeIterator<Item = &'a GenericArray<u8, PRG::Lambda>>,
    iv: &IV,
) -> (GenericArray<u8, LH>, Vec<GenericArray<u8, LH>>)
where
    PRG: PseudoRandomGenerator,
    LH: ArrayLength,
{
    // this parameters are known upfront!
    let n = sd.len() + 1;
    let d = (64 - (n as u64).leading_zeros() - 1) as usize;
    let mut r = vec![GenericArray::<u8, LH>::default(); n * 2];
    if let Some(sd0) = sd_0 {
        let mut prg = PRG::new_prg(sd0, iv);
        prg.read(&mut r[0]);
    }
    for (i, sdi) in sd.enumerate() {
        let mut prg = PRG::new_prg(sdi, iv);
        prg.read(&mut r[i + 1]);
    }

    // FIXME
    let mut v = vec![GenericArray::default(); d];
    for (j, item) in v.iter_mut().enumerate() {
        let j_offset = (j % 2) * n;
        let j1_offset = ((j + 1) % 2) * n;
        for i in 0..n / (1 << (j + 1)) {
            let j_offset = j_offset + 2 * i;
            let j1_offset = j1_offset + i;
            for k in 0..LH::USIZE {
                item[k] ^= r[j_offset + 1][k];
                r[j1_offset][k] = r[j_offset][k] ^ r[j_offset + 1][k];
            }
        }
    }
    (r[(d % 2) * n].clone(), v)
}

#[allow(clippy::type_complexity, clippy::many_single_char_names)]
pub fn volecommit<VC, Tau, LH>(
    r: &GenericArray<u8, VC::Lambda>,
    iv: &IV,
) -> (
    GenericArray<u8, VC::LambdaTimes2>,
    //Here decom can have two diferent length, depending on if it's a i < t0 or > 0 so we use vectors
    Box<
        GenericArray<
            (
                Vec<GenericArray<u8, VC::Lambda>>,
                Vec<GenericArray<u8, VC::LambdaTimes2>>,
            ),
            Tau::Tau,
        >,
    >,
    Box<GenericArray<GenericArray<u8, LH>, Tau::TauMinus1>>,
    Box<GenericArray<u8, LH>>,
    Box<GenericArray<Vec<GenericArray<u8, LH>>, Tau::Tau>>,
)
where
    Tau: TauParameters,
    VC: VectorCommitment,
    LH: ArrayLength,
{
    let mut prg = VC::PRG::new_prg(r, iv);
    let mut decom = GenericArray::default_boxed();
    let mut u = GenericArray::<GenericArray<u8, LH>, Tau::Tau>::default_boxed();
    let mut v = GenericArray::default_boxed();
    let mut c = GenericArray::<GenericArray<u8, LH>, Tau::TauMinus1>::default_boxed();

    let mut hasher = VC::RO::h1_init();
    for i in 0..Tau::Tau::USIZE {
        let b = usize::from(i < Tau::Tau0::USIZE);
        let k = b * Tau::K0::USIZE + (1 - b) * Tau::K1::USIZE;
        let mut r_i = GenericArray::default();
        prg.read(&mut r_i);
        let (com_i, decom_i, sd_i) = VC::commit(&r_i, iv, 1 << k);
        decom[i] = decom_i;
        hasher.update(&com_i);
        (u[i], v[i]) = to_vole_convert::<VC::PRG, _>(Some(&sd_i[0]), sd_i.iter().skip(1), iv);
    }
    for i in 1..Tau::Tau::USIZE {
        for (c, (u0, ui)) in zip(c[i - 1].iter_mut(), zip(&u[0], &u[i])) {
            *c = u0 ^ ui;
        }
    }
    let mut hcom = GenericArray::default();
    hasher.finish().read(&mut hcom);
    (hcom, decom, c, Box::new(u[0].clone()), v)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
///# Panics
///
/// if i is too big for being a u16
pub fn volereconstruct<VC, Tau, LH>(
    chal: &[u8],
    pdecom: &[u8],
    iv: &IV,
) -> (
    GenericArray<u8, VC::LambdaTimes2>,
    Box<GenericArray<Vec<GenericArray<u8, LH>>, Tau::Tau>>,
)
where
    Tau: TauParameters,
    VC: VectorCommitment,
    LH: ArrayLength,
{
    let mut q = GenericArray::default_boxed();
    let mut hasher = VC::RO::h1_init();
    for i in 0..Tau::Tau::USIZE {
        let b = usize::from(i < Tau::Tau0::USIZE);
        let k = b * Tau::K0::USIZE + (1 - b) * Tau::K1::USIZE;
        let pad = b * (Tau::K0::USIZE * i)
            + (1 - b)
                * (Tau::K0::USIZE * Tau::Tau0::USIZE
                    + (i - Tau::Tau0::USIZE * (1 - b)) * Tau::K1::USIZE);
        let delta_p: Vec<u8> = Tau::decode_challenge(chal, i);

        let (com_i, s_i) = VC::reconstruct(
            &pdecom[pad * VC::Lambda::USIZE + i * 2 * VC::Lambda::USIZE
                ..(b * (Tau::K0::USIZE * (i + 1))
                    + (1 - b)
                        * (Tau::K0::USIZE * Tau::Tau0::USIZE
                            + ((i + 1) - Tau::Tau0::USIZE * (1 - b)) * Tau::K1::USIZE))
                    * VC::Lambda::USIZE
                    + (i + 1) * 2 * VC::Lambda::USIZE],
            &delta_p,
            iv,
        );
        hasher.update(&com_i);

        let delta: usize = delta_p
            .into_iter()
            .enumerate()
            .map(|(j, d)| usize::from(d) << j)
            .sum();

        (_, q[i]) = to_vole_convert::<VC::PRG, _>(None, (1..(1 << k)).map(|j| &s_i[j ^ delta]), iv);
    }
    let mut hcom = GenericArray::default();
    hasher.finish().read(&mut hcom);
    (hcom, q)
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
                        assert_eq!(res.3.as_slice(), &data.u);
                    } else {
                        let res = volecommit::<
                            VC<FAEST128fParameters>,
                            Tau<FAEST128fParameters>,
                            LH<FAEST128fParameters>,
                        >(
                            &GenericArray::generate(|idx| idx as u8), &IV::default()
                        );
                        assert_eq!(res.0.as_slice(), &data.hcom);
                        assert_eq!(res.3.as_slice(), &data.u);
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
                    assert_eq!(res.3.as_slice(), &data.u);
                } else {
                    let res = volecommit::<
                        VC<FAESTEM128fParameters>,
                        Tau<FAESTEM128fParameters>,
                        LH<FAESTEM128fParameters>,
                    >(
                        &GenericArray::generate(|idx| idx as u8), &IV::default()
                    );
                    assert_eq!(res.0.as_slice(), &data.hcom);
                    assert_eq!(res.3.as_slice(), &data.u);
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
                        assert_eq!(res.3.as_slice(), &data.u);
                    } else {
                        let res = volecommit::<
                            VC<FAEST192fParameters>,
                            Tau<FAEST192fParameters>,
                            LH<FAEST192fParameters>,
                        >(
                            &GenericArray::generate(|idx| idx as u8), &IV::default()
                        );
                        assert_eq!(res.0.as_slice(), &data.hcom);
                        assert_eq!(res.3.as_slice(), &data.u);
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
                    assert_eq!(res.3.as_slice(), &data.u);
                } else {
                    let res = volecommit::<
                        VC<FAESTEM192fParameters>,
                        Tau<FAESTEM192fParameters>,
                        LH<FAESTEM192fParameters>,
                    >(
                        &GenericArray::generate(|idx| idx as u8), &IV::default()
                    );
                    assert_eq!(res.0.as_slice(), &data.hcom);
                    assert_eq!(res.3.as_slice(), &data.u);
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
                    assert_eq!(res.3.as_slice(), &data.u);
                } else {
                    let res = volecommit::<
                        VC<FAEST256fParameters>,
                        Tau<FAEST256fParameters>,
                        LH<FAEST256fParameters>,
                    >(
                        &GenericArray::generate(|idx| idx as u8), &IV::default()
                    );
                    assert_eq!(res.0.as_slice(), &data.hcom);
                    assert_eq!(res.3.as_slice(), &data.u);
                }
            } else if data.k0[0] == 12 {
                let res =
                    volecommit::<
                        VC<FAESTEM256sParameters>,
                        Tau<FAESTEM256sParameters>,
                        LH<FAESTEM256sParameters>,
                    >(&GenericArray::generate(|idx| idx as u8), &IV::default());
                assert_eq!(res.0.as_slice(), &data.hcom);
                assert_eq!(res.3.as_slice(), &data.u);
            } else {
                let res =
                    volecommit::<
                        VC<FAESTEM256fParameters>,
                        Tau<FAESTEM256fParameters>,
                        LH<FAESTEM256fParameters>,
                    >(&GenericArray::generate(|idx| idx as u8), &IV::default());
                assert_eq!(res.0.as_slice(), &data.hcom);
                assert_eq!(res.3.as_slice(), &data.u);
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
                    for i in 0..res.1.len() {
                        assert_eq!(res.1[i].len(), data.q[i].len());
                    }
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
                    for i in 0..res.1.len() {
                        assert_eq!(res.1[i].len(), data.q[i].len());
                    }
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
                    for i in 0..res.1.len() {
                        assert_eq!(res.1[i].len(), data.q[i].len());
                    }
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
                    for i in 0..res.1.len() {
                        assert_eq!(res.1[i].len(), data.q[i].len());
                    }
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
                for i in 0..res.1.len() {
                    assert_eq!(res.1[i].len(), data.q[i].len());
                }
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
                for i in 0..res.1.len() {
                    assert_eq!(res.1[i].len(), data.q[i].len());
                }
            }
        }
    }
}
