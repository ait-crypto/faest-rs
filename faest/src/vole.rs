use std::iter::zip;

use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

use crate::{
    parameter::{TauParameters, PARAM},
    random_oracles::{Hasher, Reader, IV},
    random_oracles::{PseudoRandomGenerator, RandomOracle},
    vc::{commit, reconstruct},
};

#[allow(clippy::type_complexity)]
///# Panics
///
///If sdi is an None Option
fn to_vole_convert<R, LH>(
    sd: &[Option<GenericArray<u8, R::LAMBDA>>],
    iv: &[u8],
) -> (GenericArray<u8, LH>, Vec<GenericArray<u8, LH>>)
where
    R: RandomOracle,
    LH: ArrayLength,
{
    // this parameters are known upfront!
    let n = sd.len();
    let d = (128 - (n as u128).leading_zeros() - 1) as usize;
    let mut r = vec![GenericArray::<u8, LH>::default(); n * 2];
    if let Some(ref sd0) = sd[0] {
        let mut prg = R::PRG::new_prg(sd0, iv.try_into().unwrap());
        prg.read(&mut r[0]);
    }
    for (i, sdi) in sd.iter().enumerate().skip(1).take(n) {
        let mut prg = R::PRG::new_prg(sdi.as_ref().unwrap(), iv.try_into().unwrap());
        prg.read(&mut r[i]);
    }

    // FIXME
    let mut v: Vec<GenericArray<u8, LH>> = vec![GenericArray::default(); d];
    for (j, item) in v.iter_mut().enumerate().take(d) {
        let j_offset = (j % 2) * n;
        let j1_offset = ((j + 1) % 2) * n;
        for i in 0..n / (1 << (j + 1)) {
            zip((*item).as_mut_slice().iter_mut(), &r[j_offset + 2 * i + 1])
                .for_each(|(vj, rj)| *vj ^= rj);
            r[j1_offset + i] = zip(&r[j_offset + 2 * i], &r[j_offset + 2 * i + 1])
                .map(|(x, y)| x ^ y)
                .collect::<GenericArray<u8, LH>>();
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
    let tau = <P::TAU as Unsigned>::to_usize();
    let k0 = <P::K0 as Unsigned>::to_u16();
    let k1 = <P::K1 as Unsigned>::to_u16();
    let _t1 = <P::TAU1 as Unsigned>::to_u16();

    let mut prg = R::PRG::new_prg(r, iv);

    let mut r: GenericArray<GenericArray<u8, R::LAMBDA>, P::TAU> = GenericArray::default();
    let mut com: GenericArray<GenericArray<u8, R::PRODLAMBDA2>, P::TAU> = GenericArray::default();
    let mut decom: Box<
        GenericArray<
            (
                Vec<GenericArray<u8, R::LAMBDA>>,
                Vec<GenericArray<u8, R::PRODLAMBDA2>>,
            ),
            P::TAU,
        >,
    > = GenericArray::default_boxed();
    let mut sd: GenericArray<Vec<Option<GenericArray<u8, R::LAMBDA>>>, P::TAU> =
        GenericArray::default();
    let mut u: GenericArray<GenericArray<u8, P::LH>, P::TAU> = GenericArray::default();
    let mut v: Box<GenericArray<Vec<GenericArray<u8, P::LH>>, P::TAU>> =
        GenericArray::default_boxed();
    let mut c: Box<GenericArray<GenericArray<u8, P::LH>, P::TAUMINUS>> =
        GenericArray::default_boxed();
    for i in 0..tau {
        prg.read(&mut r[i]);
    }
    let tau_0 = (R::LAMBDA::USIZE * 8) % tau;
    let mut hasher = R::h1_init();
    for i in 0..tau {
        let b = 1 - u16::from(i < tau_0);
        let k = ((1 - b) * k0) + b * k1;
        (com[i], decom[i], sd[i]) = commit::<R>(&r[i], iv, 1 << k);
        hasher.update(&com[i]);
        (u[i], v[i]) = to_vole_convert::<R, P::LH>(&sd[i], iv);
    }
    for i in 1..tau {
        c[i - 1] = u[0]
            .iter()
            .zip(u[i].iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
    }
    let mut hcom: GenericArray<u8, R::PRODLAMBDA2> = GenericArray::default();
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
    let mut com: GenericArray<GenericArray<u8, R::PRODLAMBDA2>, P::TAU> = GenericArray::default();
    let mut s: GenericArray<Vec<GenericArray<u8, R::LAMBDA>>, P::TAU> = GenericArray::default();
    let mut sd: GenericArray<Vec<Option<GenericArray<u8, R::LAMBDA>>>, P::TAU> =
        GenericArray::default();
    let mut delta: GenericArray<u32, P::TAU> = GenericArray::default();
    let mut q: GenericArray<Vec<GenericArray<u8, P::LH>>, P::TAU> = GenericArray::default();
    let mut hasher = R::h1_init();
    for i in 0..tau {
        let b: usize = (i < t0).into();
        let k = b * k0 + (1 - b) * k1;
        let pad = b * (k0 * i) + (1 - b) * (k0 * t0 + (i - t0 * (1 - b)) * k1);
        let delta_p: Vec<u8> = P::Tau::decode_challenge(chal, i);
        #[allow(clippy::needless_range_loop)]
        for j in 0..delta_p.len() {
            delta[i] += u32::from(delta_p[j]) << j;
        }
        (com[i], s[i]) = reconstruct::<R>(
            &pdecom[pad * lambda + i * 2 * lambda
                ..(b * (k0 * (i + 1)) + (1 - b) * (k0 * t0 + ((i + 1) - t0 * (1 - b)) * k1))
                    * lambda
                    + (i + 1) * 2 * lambda],
            &delta_p,
            iv,
        );
        hasher.update(&com[i]);
        for j in 0..(1_u16 << (k)) as usize {
            sd[i].push(Some(s[i][j ^ delta[i] as usize].clone()));
        }
        sd[i][0] = None;

        (_, q[i]) = to_vole_convert::<R, P::LH>(&sd[i], iv);
    }
    let mut hcom: GenericArray<u8, R::PRODLAMBDA2> = GenericArray::default();
    hasher.finish().read(&mut hcom);
    (hcom, q)
}

#[cfg(test)]
mod test {
    use super::*;

    use std::fs::File;

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
        let data = include_str!("../DataConvertToVole.json");
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
                let res = to_vole_convert::<RandomOracleShake128, LH>(&opt_sd, &data.iv);
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
                let res = to_vole_convert::<RandomOracleShake192, LH>(&opt_sd, &data.iv);
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
                let res = to_vole_convert::<RandomOracleShake256, LH>(&opt_sd, &data.iv);
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
        let file = File::open("DataVoleCommit.json").unwrap();
        let database: Vec<DataVoleCommit> =
            serde_json::from_reader(file).expect("error while reading or parsing");
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
        let file = File::open("DataVoleReconstruct.json").unwrap();
        let database: Vec<DataVoleReconstruct> =
            serde_json::from_reader(file).expect("error while reading or parsing");
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
