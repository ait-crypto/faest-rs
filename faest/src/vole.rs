use std::cmp::max;

use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

use crate::{
    parameter::{TauParameters, PARAM},
    prg::{PseudoRandomGenerator, IV},
    random_oracles::{Hasher, RandomOracle},
    utils::Reader,
    vc::{commit, reconstruct},
};

#[allow(clippy::type_complexity)]
///# Panics
///
///If sdi is an None Option
fn to_vole_convert<PRG, LH>(
    sd: &[Option<GenericArray<u8, PRG::Lambda>>],
    iv: &IV,
) -> (GenericArray<u8, LH>, Vec<GenericArray<u8, LH>>)
where
    PRG: PseudoRandomGenerator,
    LH: ArrayLength,
{
    // this parameters are known upfront!
    let n = sd.len();
    let d = (128 - (n as u128).leading_zeros() - 1) as usize;
    let mut r = vec![GenericArray::<u8, LH>::default(); n * 2];
    if let Some(ref sd0) = sd[0] {
        let mut prg = PRG::new_prg(sd0, iv);
        prg.read(&mut r[0]);
    }
    for (i, sdi) in sd.iter().enumerate().skip(1).take(n) {
        let mut prg = PRG::new_prg(sdi.as_ref().unwrap(), iv);
        prg.read(&mut r[i]);
    }

    // FIXME
    let mut v = vec![GenericArray::<u8, LH>::default(); d];
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
pub fn volecommit<P, R>(
    r: &GenericArray<u8, <R as RandomOracle>::LAMBDA>,
    iv: &IV,
) -> (
    GenericArray<u8, R::PRODLAMBDA2>,
    //Here decom can have two diferent length, depending on if it's a i < t0 or > 0 so we use vectors
    Box<
        GenericArray<
            (
                Vec<GenericArray<u8, R::LAMBDA>>,
                Vec<GenericArray<u8, R::PRODLAMBDA2>>,
            ),
            P::TAU,
        >,
    >,
    Box<GenericArray<GenericArray<u8, P::LH>, P::TAUMINUS>>,
    GenericArray<u8, P::LH>,
    Box<GenericArray<Vec<GenericArray<u8, P::LH>>, P::TAU>>,
)
where
    P: PARAM,
    R: RandomOracle,
{
    let mut prg = R::PRG::new_prg(r, iv);
    let mut decom = GenericArray::default_boxed();
    let mut u: GenericArray<GenericArray<u8, P::LH>, P::TAU> = GenericArray::default();
    let mut v: Box<GenericArray<Vec<GenericArray<u8, P::LH>>, P::TAU>> =
        GenericArray::default_boxed();
    let mut c: Box<GenericArray<GenericArray<u8, P::LH>, P::TAUMINUS>> =
        GenericArray::default_boxed();

    let mut hasher = R::h1_init();
    for i in 0..P::TAU::USIZE {
        let b = usize::from(i < P::TAU0::USIZE);
        let k = b * P::K0::USIZE + (1 - b) * P::K1::USIZE;
        let mut r_i = GenericArray::default();
        prg.read(&mut r_i);
        let (com_i, decom_i, sd_i) = commit::<R>(&r_i, iv, 1 << k);
        decom[i] = decom_i;
        hasher.update(&com_i);
        (u[i], v[i]) = to_vole_convert::<R::PRG, _>(&sd_i, iv);
    }
    for i in 1..P::TAU::USIZE {
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
pub fn volereconstruct<R, P>(
    chal: &GenericArray<u8, P::LAMBDABYTES>,
    pdecom: &[u8],
    iv: &IV,
) -> (
    GenericArray<u8, R::PRODLAMBDA2>,
    GenericArray<Vec<GenericArray<u8, P::LH>>, P::TAU>,
)
where
    R: RandomOracle,
    P: PARAM,
{
    let lambda = <R::LAMBDA as Unsigned>::to_usize();
    let tau = <P::TAU as Unsigned>::to_usize();
    let k0 = <P::K0 as Unsigned>::to_usize();
    let k1 = <P::K1 as Unsigned>::to_usize();
    let t0 = <P::TAU0 as Unsigned>::to_usize();

    let mut sd = vec![None; 1 << max(P::K0::USIZE, P::K1::USIZE)];
    let mut q: GenericArray<Vec<GenericArray<u8, P::LH>>, P::TAU> = GenericArray::default();
    let mut hasher = R::h1_init();
    for i in 0..tau {
        let b = usize::from(i < t0);
        let k = b * k0 + (1 - b) * k1;
        let pad = b * (k0 * i) + (1 - b) * (k0 * t0 + (i - t0 * (1 - b)) * k1);
        let delta_p: Vec<u8> = P::Tau::decode_challenge(chal, i);

        let (com_i, s_i) = reconstruct::<R>(
            &pdecom[pad * lambda + i * 2 * lambda
                ..(b * (k0 * (i + 1)) + (1 - b) * (k0 * t0 + ((i + 1) - t0 * (1 - b)) * k1))
                    * lambda
                    + (i + 1) * 2 * lambda],
            &delta_p,
            iv,
        );
        hasher.update(&com_i);

        let delta: usize = delta_p
            .into_iter()
            .enumerate()
            .map(|(j, d)| usize::from(d) << j)
            .sum();
        for j in 1..(1 << k) {
            sd[j] = Some(s_i[j ^ delta].clone());
        }
        (_, q[i]) = to_vole_convert::<R::PRG, _>(&sd[..1 << k], iv);
    }
    let mut hcom = GenericArray::default();
    hasher.finish().read(&mut hcom);
    (hcom, q)
}

#[cfg(test)]
mod test {
    use super::*;

    use generic_array::{
        typenum::{U16, U234, U24, U32, U458, U566},
        GenericArray,
    };
    use serde::Deserialize;

    use crate::{
        parameter::{
            PARAM128F, PARAM128FEM, PARAM128S, PARAM128SEM, PARAM192F, PARAM192FEM, PARAM192S,
            PARAM192SEM, PARAM256F, PARAM256FEM, PARAM256S, PARAM256SEM,
        },
        prg::{PRG128, PRG192, PRG256},
        random_oracles::{RandomOracleShake128, RandomOracleShake192, RandomOracleShake256},
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataConvertToVole {
        sd: Vec<Vec<u8>>,
        iv: IV,
        lambdabytes: [u8; 1],
        sd0: [u8; 1],
        u: Vec<u8>,
        v: Vec<Vec<u8>>,
    }

    #[test]
    fn convert_to_vole_test() {
        let data = include_str!("../tests/data/DataConvertToVole.json");
        let database: Vec<DataConvertToVole> =
            serde_json::from_str(data).expect("error while reading or parsing");
        for data in database {
            if data.lambdabytes[0] == 16 {
                let mut opt_sd: Vec<Option<GenericArray<u8, U16>>> = data
                    .sd
                    .iter()
                    .cloned()
                    .map(|x| Some(*GenericArray::from_slice(&x)))
                    .collect::<Vec<Option<GenericArray<u8, U16>>>>();
                if data.sd0[0] == 1 {
                    opt_sd[0] = None;
                }
                type LH = U234;
                let res = to_vole_convert::<PRG128, LH>(&opt_sd, &data.iv);
                assert_eq!(res.0, *GenericArray::from_slice(&data.u));
                assert_eq!(
                    res.1,
                    data.v
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec<GenericArray<u8, LH>>>()
                );
            } else if data.lambdabytes[0] == 24 {
                let mut opt_sd: Vec<Option<GenericArray<u8, U24>>> = Vec::default();
                if data.sd0[0] == 1 {
                    opt_sd[0] = None;
                }
                type LH = U458;
                let res = to_vole_convert::<PRG192, LH>(&opt_sd, &data.iv);
                assert_eq!(res.0, *GenericArray::from_slice(&data.u));
                assert_eq!(
                    res.1,
                    data.v
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec<GenericArray<u8, LH>>>()
                );
            } else {
                let mut opt_sd: Vec<Option<GenericArray<u8, U32>>> = Vec::default();
                if data.sd0[0] == 1 {
                    opt_sd[0] = None;
                }
                type LH = U566;
                let res = to_vole_convert::<PRG256, LH>(&opt_sd, &data.iv);
                assert_eq!(res.0, *GenericArray::from_slice(&data.u));
                assert_eq!(
                    res.1,
                    data.v
                        .iter()
                        .map(|x| *GenericArray::from_slice(x))
                        .collect::<Vec<GenericArray<u8, LH>>>()
                );
            }
        }
    }

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
                        let res = volecommit::<PARAM128S, RandomOracleShake128>(
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
                        let res = volecommit::<PARAM128F, RandomOracleShake128>(
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
                    let res = volecommit::<PARAM128SEM, RandomOracleShake128>(
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
                    let res = volecommit::<PARAM128FEM, RandomOracleShake128>(
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
            } else if data.lambdabytes[0] == 24 {
                if data.u.len() == 458 {
                    if data.k0[0] == 12 {
                        let res = volecommit::<PARAM192S, RandomOracleShake192>(
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
                        let res = volecommit::<PARAM192F, RandomOracleShake192>(
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
                    let res = volecommit::<PARAM192SEM, RandomOracleShake192>(
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
                    let res = volecommit::<PARAM192FEM, RandomOracleShake192>(
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
            } else if data.u.len() == 566 {
                if data.k0[0] == 12 {
                    let res = volecommit::<PARAM256S, RandomOracleShake256>(
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
                    let res = volecommit::<PARAM256F, RandomOracleShake256>(
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
                let res = volecommit::<PARAM256SEM, RandomOracleShake256>(
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
                let res = volecommit::<PARAM256FEM, RandomOracleShake256>(
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
                    let res = volereconstruct::<RandomOracleShake128, PARAM128F>(
                        GenericArray::from_slice(&data.chal),
                        pdecom,
                        &data.iv,
                    );
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
                    let res = volereconstruct::<RandomOracleShake128, PARAM128S>(
                        GenericArray::from_slice(&data.chal),
                        pdecom,
                        &data.iv,
                    );
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
                    let res = volereconstruct::<RandomOracleShake192, PARAM192F>(
                        GenericArray::from_slice(&data.chal),
                        pdecom,
                        &data.iv,
                    );
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
                    let res = volereconstruct::<RandomOracleShake192, PARAM192S>(
                        GenericArray::from_slice(&data.chal),
                        pdecom,
                        &data.iv,
                    );
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
                let res = volereconstruct::<RandomOracleShake256, PARAM256F>(
                    GenericArray::from_slice(&data.chal),
                    pdecom,
                    &data.iv,
                );
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
                let res = volereconstruct::<RandomOracleShake256, PARAM256S>(
                    GenericArray::from_slice(&data.chal),
                    pdecom,
                    &data.iv,
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.hcom));
                for i in 0..res.1.len() {
                    assert_eq!(res.1[i].len(), data.q[i].len());
                }
            }
        }
    }
}
