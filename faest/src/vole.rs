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
    let d = (128 - (n as u128).leading_zeros() - 1) as usize;
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
    GenericArray<u8, LH>,
    Box<GenericArray<Vec<GenericArray<u8, LH>>, Tau::Tau>>,
)
where
    Tau: TauParameters,
    VC: VectorCommitment,
    LH: ArrayLength,
{
    let mut prg = VC::PRG::new_prg(r, iv);
    let mut decom = GenericArray::default_boxed();
    let mut u: GenericArray<GenericArray<u8, LH>, Tau::Tau> = GenericArray::default();
    let mut v: Box<GenericArray<Vec<GenericArray<u8, LH>>, Tau::Tau>> =
        GenericArray::default_boxed();
    let mut c: Box<GenericArray<GenericArray<u8, LH>, Tau::TauMinus1>> =
        GenericArray::default_boxed();

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
        c[i - 1] = u[0]
            .iter()
            .zip(u[i].iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
    }
    let mut hcom = GenericArray::default();
    hasher.finish().read(&mut hcom);
    (hcom, decom, c, u[0].clone(), v)
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
    GenericArray<Vec<GenericArray<u8, LH>>, Tau::Tau>,
)
where
    Tau: TauParameters,
    VC: VectorCommitment,
    LH: ArrayLength,
{
    let mut q: GenericArray<Vec<GenericArray<u8, LH>>, Tau::Tau> = GenericArray::default();
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

    use generic_array::GenericArray;
    use serde::Deserialize;

    use crate::parameter::{
        BaseParameters, OWFParameters, PARAM, PARAM128F, PARAM128FEM, PARAM128S, PARAM128SEM,
        PARAM192F, PARAM192FEM, PARAM192S, PARAM192SEM, PARAM256F, PARAM256FEM, PARAM256S,
        PARAM256SEM,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataVoleCommit {
        r: Vec<u8>,
        iv: [u8; 16],
        lambdabytes: [u16; 1],
        k0: [u8; 1],
        hcom: Vec<u8>,
        k: Vec<Vec<Vec<u8>>>,
        com: Vec<Vec<Vec<u8>>>,
        c: Vec<Vec<u8>>,
        u: Vec<u8>,
        v: Vec<Vec<Vec<u8>>>,
    }

    #[test]
    fn volecommit_test() {
        let database: Vec<DataVoleCommit> =
            serde_json::from_str(include_str!("../tests/data/DataVoleCommit.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.lambdabytes[0] == 16 {
                if data.u.len() == 234 {
                    if data.k0[0] == 12 {
                        let res = volecommit::<
                            <<<PARAM128S as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
                            <PARAM128S as PARAM>::Tau,
                            <PARAM128S as PARAM>::LH,
                        >(
                            GenericArray::from_slice(&data.r), &data.iv
                        );
                        assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                        for i in 0..res.1.len() {
                            assert_eq!(
                                res.1[i],
                                (
                                    data.k[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone(),
                                    data.com[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone()
                                )
                            );
                        }
                        for i in 0..data.com.len() {
                            assert_eq!(
                                res.1[i],
                                (
                                    data.k[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone(),
                                    data.com[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone()
                                )
                            );
                        }
                        assert_eq!(
                            res.2,
                            data.c
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect()
                        );
                        assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                        assert_eq!(
                            res.4,
                            data.v
                                .iter()
                                .map(|x| x.iter().map(|y| *GenericArray::from_slice(y)).collect())
                                .collect()
                        );
                    } else {
                        let res = volecommit::<<<<PARAM128F as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
                            <PARAM128F as PARAM>::Tau,
                            <PARAM128F as PARAM>::LH>(
                            GenericArray::from_slice(&data.r),
                            &data.iv,
                        );
                        assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                        for i in 0..res.1.len() {
                            assert_eq!(
                                res.1[i],
                                (
                                    data.k[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone(),
                                    data.com[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone()
                                )
                            );
                        }
                        for i in 0..data.com.len() {
                            assert_eq!(
                                res.1[i],
                                (
                                    data.k[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone(),
                                    data.com[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone()
                                )
                            );
                        }
                        assert_eq!(
                            res.2,
                            data.c
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect()
                        );
                        assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                        assert_eq!(
                            res.4,
                            data.v
                                .iter()
                                .map(|x| x.iter().map(|y| *GenericArray::from_slice(y)).collect())
                                .collect()
                        );
                    }
                } else if data.k0[0] == 12 {
                    let res = volecommit::<<<<PARAM128SEM as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
                            <PARAM128SEM as PARAM>::Tau,
                            <PARAM128SEM as PARAM>::LH>(
                        GenericArray::from_slice(&data.r),
                        &data.iv,
                    );
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                    for i in 0..res.1.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    for i in 0..data.com.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    assert_eq!(
                        res.2,
                        data.c
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect()
                    );
                    assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                    assert_eq!(
                        res.4,
                        data.v
                            .iter()
                            .map(|x| x.iter().map(|y| *GenericArray::from_slice(y)).collect())
                            .collect()
                    );
                } else {
                    let res =
                        volecommit::<<<<PARAM128FEM as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC, <PARAM128FEM as PARAM>::Tau, <PARAM128FEM as PARAM>::LH>(GenericArray::from_slice(&data.r), &data.iv);
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                    for i in 0..res.1.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    for i in 0..data.com.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    assert_eq!(
                        res.2,
                        data.c
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect()
                    );
                    assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                    assert_eq!(
                        res.4,
                        data.v
                            .iter()
                            .map(|x| x.iter().map(|y| *GenericArray::from_slice(y)).collect())
                            .collect()
                    );
                }
            } else if data.lambdabytes[0] == 24 {
                if data.u.len() == 458 {
                    if data.k0[0] == 12 {
                        let res =
                            volecommit::<<<<PARAM192S as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC, <PARAM192S as PARAM>::Tau, <PARAM192S as PARAM>::LH>(GenericArray::from_slice(&data.r), &data.iv);
                        assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                        for i in 0..res.1.len() {
                            assert_eq!(
                                res.1[i],
                                (
                                    data.k[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone(),
                                    data.com[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone()
                                )
                            );
                        }
                        for i in 0..data.com.len() {
                            assert_eq!(
                                res.1[i],
                                (
                                    data.k[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone(),
                                    data.com[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone()
                                )
                            );
                        }
                        assert_eq!(
                            res.2,
                            data.c
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect()
                        );
                        assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                        assert_eq!(
                            res.4,
                            data.v
                                .iter()
                                .map(|x| x.iter().map(|y| *GenericArray::from_slice(y)).collect())
                                .collect()
                        );
                    } else {
                        let res =
                            volecommit::<<<<PARAM192F as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC, <PARAM192F as PARAM>::Tau, <PARAM192F as PARAM>::LH>(GenericArray::from_slice(&data.r), &data.iv);
                        assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                        for i in 0..res.1.len() {
                            assert_eq!(
                                res.1[i],
                                (
                                    data.k[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone(),
                                    data.com[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone()
                                )
                            );
                        }
                        for i in 0..data.com.len() {
                            assert_eq!(
                                res.1[i],
                                (
                                    data.k[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone(),
                                    data.com[i]
                                        .iter()
                                        .map(|x| *GenericArray::from_slice(x))
                                        .collect::<Vec<GenericArray<u8, _>>>()
                                        .clone()
                                )
                            );
                        }
                        assert_eq!(
                            res.2,
                            data.c
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect()
                        );
                        assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                        assert_eq!(
                            res.4,
                            data.v
                                .iter()
                                .map(|x| x.iter().map(|y| *GenericArray::from_slice(y)).collect())
                                .collect()
                        );
                    }
                } else if data.k0[0] == 12 {
                    let res =
                        volecommit::<<<<PARAM192SEM as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC, <PARAM192SEM as PARAM>::Tau, <PARAM192SEM as PARAM>::LH>(GenericArray::from_slice(&data.r), &data.iv);
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                    for i in 0..res.1.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    for i in 0..data.com.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    assert_eq!(
                        res.2,
                        data.c
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect()
                    );
                    assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                    assert_eq!(
                        res.4,
                        data.v
                            .iter()
                            .map(|x| x.iter().map(|y| *GenericArray::from_slice(y)).collect())
                            .collect()
                    );
                } else {
                    let res =
                        volecommit::<<<<PARAM192FEM as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC, <PARAM192FEM as PARAM>::Tau, <PARAM192FEM as PARAM>::LH>(GenericArray::from_slice(&data.r), &data.iv);
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                    for i in 0..res.1.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    for i in 0..data.com.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    assert_eq!(
                        res.2,
                        data.c
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect()
                    );
                    assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                    assert_eq!(
                        res.4,
                        data.v
                            .iter()
                            .map(|x| x.iter().map(|y| *GenericArray::from_slice(y)).collect())
                            .collect()
                    );
                }
            } else if data.u.len() == 566 {
                if data.k0[0] == 12 {
                    let res = volecommit::<
                        <<<PARAM256S as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
                        <PARAM256S as PARAM>::Tau,
                        <PARAM256S as PARAM>::LH,
                    >(GenericArray::from_slice(&data.r), &data.iv);
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                    for i in 0..res.1.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    for i in 0..data.com.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    assert_eq!(
                        res.2,
                        data.c
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect()
                    );
                    assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                    assert_eq!(
                        res.4,
                        data.v
                            .iter()
                            .map(|x| x.iter().map(|y| *GenericArray::from_slice(y)).collect())
                            .collect()
                    );
                } else {
                    let res = volecommit::<
                        <<<PARAM256F as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
                        <PARAM256F as PARAM>::Tau,
                        <PARAM256F as PARAM>::LH,
                    >(GenericArray::from_slice(&data.r), &data.iv);
                    assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                    for i in 0..res.1.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    for i in 0..data.com.len() {
                        assert_eq!(
                            res.1[i],
                            (
                                data.k[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone(),
                                data.com[i]
                                    .iter()
                                    .map(|x| *GenericArray::from_slice(x))
                                    .collect::<Vec<GenericArray<u8, _>>>()
                                    .clone()
                            )
                        );
                    }
                    assert_eq!(
                        res.2,
                        data.c
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect()
                    );
                    assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                    assert_eq!(
                        res.4,
                        data.v
                            .iter()
                            .map(|x| x.iter().map(|y| *GenericArray::from_slice(y)).collect())
                            .collect()
                    );
                }
            } else if data.k0[0] == 12 {
                let res = volecommit::<
                    <<<PARAM256SEM as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
                    <PARAM256SEM as PARAM>::Tau,
                    <PARAM256SEM as PARAM>::LH,
                >(GenericArray::from_slice(&data.r), &data.iv);
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                for i in 0..data.com.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                assert_eq!(
                    res.2,
                    data.c
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect()
                );
                assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                assert_eq!(
                    res.4,
                    data.v
                        .iter()
                        .map(|x| x.iter().map(|y| *GenericArray::from_slice(y)).collect())
                        .collect()
                );
            } else {
                let res = volecommit::<
                    <<<PARAM256FEM as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
                    <PARAM256FEM as PARAM>::Tau,
                    <PARAM256FEM as PARAM>::LH,
                >(GenericArray::from_slice(&data.r), &data.iv);
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                for i in 0..data.com.len() {
                    assert_eq!(
                        res.1[i],
                        (
                            data.k[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone(),
                            data.com[i]
                                .iter()
                                .map(|x| *GenericArray::from_slice(x))
                                .collect::<Vec<GenericArray<u8, _>>>()
                                .clone()
                        )
                    );
                }
                assert_eq!(
                    res.2,
                    data.c
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect()
                );
                assert_eq!(res.3, *GenericArray::from_slice(&data.u));
                assert_eq!(
                    res.4,
                    data.v
                        .iter()
                        .map(|x| x.iter().map(|y| *GenericArray::from_slice(y)).collect())
                        .collect()
                );
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataVoleReconstruct {
        chal: Vec<u8>,
        pdec: Vec<Vec<Vec<u8>>>,
        com: Vec<Vec<u8>>,
        iv: [u8; 16],
        hcom: Vec<u8>,
        q: Vec<Vec<Vec<u8>>>,
    }

    #[test]
    fn volereconstruct_test() {
        let database: Vec<DataVoleReconstruct> =
            serde_json::from_str(include_str!("../tests/data/DataVoleReconstruct.json"))
                .expect("error while reading or parsing");
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
                        <<<PARAM128F as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
                        <PARAM128F as PARAM>::Tau,
                        <PARAM128F as PARAM>::LH,
                    >(&data.chal, pdecom, &data.iv);
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
                        <<<PARAM128S as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
                        <PARAM128S as PARAM>::Tau,
                        <PARAM128S as PARAM>::LH,
                    >(&data.chal, pdecom, &data.iv);
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
                        <<<PARAM192F as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
                        <PARAM192F as PARAM>::Tau,
                        <PARAM192F as PARAM>::LH,
                    >(&data.chal, pdecom, &data.iv);
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
                        <<<PARAM192S as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
                        <PARAM192S as PARAM>::Tau,
                        <PARAM192S as PARAM>::LH,
                    >(&data.chal, pdecom, &data.iv);
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
                    <<<PARAM256F as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
                    <PARAM256F as PARAM>::Tau,
                    <PARAM256F as PARAM>::LH,
                >(&data.chal, pdecom, &data.iv);
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
                    <<<PARAM256S as PARAM>::OWF as OWFParameters>::BaseParams as BaseParameters>::VC,
                    <PARAM256S as PARAM>::Tau,
                    <PARAM256S as PARAM>::LH,
                >(&data.chal, pdecom, &data.iv);
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(res.1[i].len(), data.q[i].len());
                }
            }
        }
    }
}
