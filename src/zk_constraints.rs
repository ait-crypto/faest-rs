use aes::cipher::KeyInit;
use generic_array::{
    functional::FunctionalSequence,
    typenum::{Prod, Quot, Unsigned, U1, U10, U2, U3, U32, U4, U8},
    ArrayLength, GenericArray,
};
use itertools::multiunzip;
use itertools::{iproduct, izip};
use std::{
    array, default,
    mem::size_of,
    ops::{Add, Mul, Sub},
};

use crate::{
    fields::{
        large_fields::{Betas, ByteCombineSquared, FromBit, SquareBytes},
        small_fields::{GF8, GF8_INV_NORM},
        BigGaloisField, ByteCombine, ByteCombineConstants, Field,
        Square, SumPoly
    },
    internal_keys::PublicKey,
    parameter::{BaseParameters, Lambda, OWFField, OWFParameters, QSProof, TauParameters},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, rijndael_sub_bytes, sub_bytes,
        sub_bytes_nots, State, RCON_TABLE,
    },
    universal_hashing::{ZKHasher, ZKHasherInit, ZKHasherProcess, ZKProofHasher, ZKVerifyHasher},
    utils::{xor_arrays, get_bit},
    prover::byte_commitments::ByteCommitsRef,
    verifier::{VoleCommits, VoleCommitsRef},
    prover,
    verifier,
};

// use key_expansion::{key_exp_bkwd, key_exp_cstrnts, key_exp_fwd};

pub(crate) type KeyCstrnts<O> = (
    Box<GenericArray<u8, <O as OWFParameters>::PRODRUN128Bytes>>,
    Box<GenericArray<OWFField<O>, <O as OWFParameters>::PRODRUN128>>,
);

pub(crate) type CstrntsVal<'a, O> = &'a GenericArray<
    GenericArray<u8, <O as OWFParameters>::LAMBDA>,
    <O as OWFParameters>::LAMBDALBYTES,
>;

// Reshapes a matrix of size (l_hat/8) x lambda into a matrix of size l_hat x (lambda/8).
// Then, it converts all rows in the interval [row_start, rowstart + nrows) to field elements.
pub(crate) fn reshape_and_to_field<O: OWFParameters>(
    m: CstrntsVal<O>,
) -> Vec<OWFField<O>> {
    (0 .. O::LBYTES::USIZE + O::LAMBDABYTESTWO::USIZE)
        .flat_map(|row| {
            let mut ret = vec![GenericArray::<u8, O::LAMBDABYTES>::default(); 8];

            (0..O::LAMBDA::USIZE).for_each(|col| {
                for i in 0..8 {
                    ret[i][col / 8] |= get_bit(&[m[row][col]] ,i) << (col % 8);
                }
            });

            ret.into_iter()
                .map(|r_i| OWFField::<O>::from(r_i.as_slice()))
        })
        .collect()
}

pub(crate) fn aes_prove<O>(
    w: &GenericArray<u8, O::LBYTES>,
    u: &GenericArray<u8, O::LAMBDABYTESTWO>,
    v: CstrntsVal<O>,
    pk: &PublicKey<O>,
    chall_2: &GenericArray<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>,
) -> QSProof<O>
where
    O: OWFParameters,
{
    let mut zk_hasher =
        <<O as OWFParameters>::BaseParams as BaseParameters>::ZKHasher::new_zk_proof_hasher(
            chall_2,
        );

    // ::1
    let v = reshape_and_to_field::<O>(v);

    // ::7
    let u0_star = OWFField::<O>::sum_poly_bits(&u[..O::LAMBDABYTES::USIZE]);
    let u1_star = OWFField::<O>::sum_poly_bits(&u[O::LAMBDABYTES::USIZE..]);

    // ::8
    let v0_star = OWFField::<O>::sum_poly(&v[O::L::USIZE .. O::L::USIZE + O::LAMBDA::USIZE]);
    let v1_star = OWFField::<O>::sum_poly(&v[O::L::USIZE + O::LAMBDA::USIZE ..]);

    // ::12
    prover::owf_constraints::<O>(
        &mut zk_hasher,
        ByteCommitsRef::new(w, GenericArray::from_slice(&v[..O::L::USIZE])),
        pk,
    );

    // ::13-18
    zk_hasher.finalize(&v0_star, &(u0_star + &v1_star), &u1_star)
}


pub(crate) fn aes_verify<O>(
    q: CstrntsVal<O>,
    d: &GenericArray<u8, O::LBYTES>,
    pk: &PublicKey<O>,
    chall_2: &GenericArray<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>,
    chall_3: &GenericArray<u8, O::LAMBDABYTES>,
    a1_tilde: &OWFField<O>,
    a2_tilde: &OWFField<O>,
) -> OWFField<O>
where
    O: OWFParameters,
{
    // ::1
    let delta = OWFField::<O>::from(chall_3.as_slice());

    // ::2-5
    let mut q = reshape_and_to_field::<O>(q);

    // Convert first L elements to VOLE
    for i in 0..O::L::USIZE {
        if get_bit(d, i) != 0 {
            q[i] += delta;
        }
    }
    let w = VoleCommitsRef {
        scalars: GenericArray::from_slice(&q[..O::L::USIZE]),
        delta: &delta,
    };

    // ::7
    let q0_star = OWFField::<O>::sum_poly(&q[O::L::USIZE..O::L::USIZE + O::LAMBDA::USIZE]);
    let q1_star = OWFField::<O>::sum_poly(
        &q[O::L::USIZE + O::LAMBDA::USIZE..O::L::USIZE + O::LAMBDA::USIZE * 2],
    );

    // ::10
    let q_star = delta * &q1_star + &q0_star;

    let mut zk_hasher =
        <<O as OWFParameters>::BaseParams as BaseParameters>::ZKHasher::new_zk_verify_hasher(
            &chall_2, delta,
        );

    // ::12
    verifier::owf_constraints::<O>(&mut zk_hasher, w, &delta, pk);

    // ::14
    let q_tilde = zk_hasher.finalize(&q_star);

    q_tilde - delta * a1_tilde - delta.square() * a2_tilde
}

// #[cfg(test)]
// mod test {
//     #![allow(clippy::needless_range_loop)]

//     use super::key_expansion::{key_exp_bkwd, key_exp_fwd};
//     use super::*;
//     use crate::{
//         fields::{GF128, GF192, GF256},
//         parameter::{Lambda, OWFParameters, OWF128, OWF128EM, OWF192, OWF192EM, OWF256, OWF256EM},
//         utils::test::read_test_data,
//     };

//     use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
//     use serde::Deserialize;

    // #[test]
    // fn aes_enc_fwd_prover_128_test() {
    //     let w: GenericArray<u8, _> = GenericArray::from_array([
    //         17, 114, 181, 111, 55, 1, 111, 109, 39, 0, 190, 122, 209, 86, 174, 250, 161, 150, 152,
    //         81, 219, 2, 253, 129, 241, 75, 93, 95, 57, 172, 5, 217, 225, 238, 21, 13, 45, 134, 80,
    //         97, 15, 126, 161, 50, 27, 253, 118, 137, 35, 0, 176, 94, 230, 199, 184, 147
    //     ]);

    //     let exp_k: GenericArray<u8, _> = GenericArray::from_array([
    //         17, 114, 181, 111, 55, 1, 111, 109, 39, 0, 190, 122, 209, 86, 174, 250, 161, 150, 152,
    //         81, 150, 151, 247, 60, 177, 151, 73, 70, 96, 193, 231, 188, 219, 2, 253, 129, 77, 149,
    //         10, 189, 252, 2, 67, 251, 156, 195, 164, 71, 241, 75, 93, 95, 188, 222, 87, 226, 64,
    //         220, 20, 25, 220, 31, 176, 94, 57, 172, 5, 217, 133, 114, 82, 59, 197, 174, 70, 34, 25,
    //         177, 246, 124, 225, 238, 21, 13, 100, 156, 71, 54, 161, 50, 1, 20, 184, 131, 247, 104,
    //         45, 134, 80, 97, 73, 26, 23, 87, 232, 40, 22, 67, 80, 171, 225, 43, 15, 126, 161, 50,
    //         70, 100, 182, 101, 174, 76, 160, 38, 254, 231, 65, 13, 27, 253, 118, 137, 93, 153, 192,
    //         236, 243, 213, 96, 202, 13, 50, 33, 199, 35, 0, 176, 94, 126, 153, 112, 178, 141, 76,
    //         16, 120, 128, 126, 49, 191, 230, 199, 184, 147, 152, 94, 200, 33, 21, 18, 216, 89, 149,
    //         108, 233, 230,
    //     ]);

    //     let tags = GenericArray::default();

    //     let res = aes_key_exp_fwd::<OWF128>(BitCommitsRef { keys: &w, tags: &tags });

    //     assert!(*res.keys == exp_k);
    // }

//     #[test]
//     fn aes_enc_bkwd_prover_128_test() {
//         let w: GenericArray<u8, _> = GenericArray::from_array([
//             168, 233, 176, 51, 172, 6, 233, 110, 215, 248, 209, 67, 11, 234, 191, 117, 60, 3, 82,
//             31, 53, 103, 128, 235, 3, 122, 147, 230, 113, 159, 193, 47, 11, 201, 121, 202, 159,
//             209, 193, 112,
//         ]);

//         let k: GenericArray<u8, _> = GenericArray::from_array([
//             188, 126, 253, 108, 122, 171, 208, 78, 219, 200, 132, 13, 132, 47, 133, 101, 168, 233,
//             176, 51, 210, 66, 96, 125, 9, 138, 228, 112, 141, 165, 97, 21, 172, 6, 233, 110, 126,
//             68, 137, 19, 119, 206, 109, 99, 250, 107, 12, 118, 215, 248, 209, 67, 169, 188, 88, 80,
//             222, 114, 53, 51, 36, 25, 57, 69, 11, 234, 191, 117, 162, 86, 231, 37, 124, 36, 210,
//             22, 88, 61, 235, 83, 60, 3, 82, 31, 158, 85, 181, 58, 226, 113, 103, 44, 186, 76, 140,
//             127, 53, 103, 128, 235, 171, 50, 53, 209, 73, 67, 82, 253, 243, 15, 222, 130, 3, 122,
//             147, 230, 168, 72, 166, 55, 225, 11, 244, 202, 18, 4, 42, 72, 113, 159, 193, 47, 217,
//             215, 103, 24, 56, 220, 147, 210, 42, 216, 185, 154, 11, 201, 121, 202, 210, 30, 30,
//             210, 234, 194, 141, 0, 192, 26, 52, 154, 159, 209, 193, 112, 77, 207, 223, 162, 167,
//             13, 82, 162, 103, 23, 102, 56,
//         ]);

//         let exp = GenericArray::from_array([
//             194, 115, 166, 150, 184, 94, 43, 2, 223, 176, 186, 125, 63, 53, 49, 85, 187, 227, 202,
//             24, 84, 247, 130, 118, 199, 144, 127, 52, 203, 152, 167, 170, 148, 142, 159, 152, 253,
//             243, 159, 11,
//         ]);
//         let w_tags = GenericArray::default();
//         let k_tags = GenericArray::default();

//         let res = key_exp_bkwd::<OWF128>(
//             ByteCommitsRef::new(&w, &w_tags),
//             ByteCommitsRef::new(&k, &k_tags),
//         );

//         assert_eq!(exp, *res.keys);
//     }

//     #[test]
//     fn test_keycnstr() {
//         let w = GenericArray::from_array([
//             0xc0, 0x72, 0x0b, 0x10, 0xbf, 0x26, 0x6c, 0x19, 0x24, 0x18, 0x87, 0x72, 0xc5, 0x1f,
//             0xbe, 0x52, 0x01, 0xdc, 0x0b, 0xb6, 0x57, 0x84, 0x78, 0x79, 0xbc, 0xb6, 0x27, 0x08,
//             0x22, 0x85, 0xf6, 0x6f, 0x43, 0x2d, 0x60, 0x56, 0x9f, 0xc5, 0x2e, 0xe4, 0x78, 0x1a,
//             0x2b, 0x68, 0x7f, 0xe1, 0xea, 0x3d, 0x6a, 0x05, 0x3a, 0x77, 0x94, 0xa8, 0x8a, 0x86,
//             0x81, 0x4d, 0xe7, 0x6b, 0x58, 0x35, 0xcd, 0xba, 0x3d, 0xd5, 0x16, 0x1c, 0x47, 0x99,
//             0x22, 0xf2, 0x75, 0x6f, 0x09, 0xd6, 0xe7, 0x1d, 0xc7, 0x42, 0x22, 0xd7, 0x54, 0x35,
//             0xc2, 0xa6, 0x73, 0x11, 0xaa, 0x32, 0x99, 0xc3, 0x3f, 0x42, 0x84, 0x1c, 0xfd, 0x5b,
//             0xdf, 0xba, 0x0c, 0x93, 0x83, 0xe8, 0x4c, 0xce, 0xde, 0xa5, 0x84, 0x3f, 0x25, 0xc9,
//             0x15, 0x5a, 0x7e, 0x0c, 0x7a, 0x29, 0xd6, 0xa0, 0x2a, 0x93, 0xb7, 0xf2, 0xeb, 0x6d,
//             0xad, 0x50, 0x54, 0x32, 0x5a, 0x4d, 0xe9, 0xc9, 0xcb, 0xac, 0x5d, 0x90, 0x10, 0x0f,
//             0x9a, 0x45, 0x54, 0xee, 0x84, 0x1a, 0xed, 0x05, 0x02, 0x96, 0x78, 0x82, 0x79, 0x22,
//             0x57, 0x1a, 0xea, 0x65, 0x19, 0xce,
//         ]);

//         let lke = <OWF128 as OWFParameters>::LKEBytes::USIZE;
//         let hasher = ZKHasher::<GF128>::new_zk_hasher(&GenericArray::default());
//         let mut hasher = ZKProofHasher::<GF128>::new(hasher.clone(), hasher.clone(), hasher);

//         key_exp_cstrnts::<OWF128>(
//             &mut hasher,
//             ByteCommitsRef::new(
//                 &GenericArray::from_slice(&w[..lke]),
//                 &GenericArray::default(),
//             ),
//         );
//     }
// }
//     #[derive(Debug, Deserialize)]
//     #[serde(rename_all = "camelCase")]
//     struct AesProve {
//         lambda: u16,
//         w: Vec<u8>,
//         input: Vec<u8>,
//         output: Vec<u8>,
//         at: Vec<u8>,
//         bt: Vec<u8>,
//     }

//     impl AesProve {
//         fn as_pk<O>(&self) -> PublicKey<O>
//         where
//             O: OWFParameters,
//         {
//             PublicKey {
//                 owf_input: GenericArray::from_slice(&self.input).clone(),
//                 owf_output: GenericArray::from_slice(&self.output).clone(),
//             }
//         }
//     }

//     #[test]
//     fn aes_prove_test() {
//         let database: Vec<AesProve> = read_test_data("AesProve.json");
//         for data in database {
//             if data.lambda == 128 {
//                 let res = aes_prove::<OWF128>(
//                     GenericArray::from_slice(&data.w),
//                     &GenericArray::generate(|_| 19),
//                     &GenericArray::generate(|_| GenericArray::generate(|_| 55)),
//                     &data.as_pk(),
//                     &GenericArray::generate(|_| 47),
//                 );
//                 assert_eq!(res.0.as_slice(), &data.at);
//                 assert_eq!(res.1.as_slice(), &data.bt);
//             } else if data.lambda == 192 {
//                 let res = aes_prove::<OWF192>(
//                     GenericArray::from_slice(&data.w),
//                     &GenericArray::generate(|_| 19),
//                     &GenericArray::generate(|_| GenericArray::generate(|_| 55)),
//                     &data.as_pk(),
//                     &GenericArray::generate(|_| 47),
//                 );
//                 assert_eq!(res.0.as_slice(), &data.at);
//                 assert_eq!(res.1.as_slice(), &data.bt);
//             } else {
//                 let res = aes_prove::<OWF256>(
//                     GenericArray::from_slice(&data.w),
//                     &GenericArray::generate(|_| 19),
//                     &GenericArray::generate(|_| GenericArray::generate(|_| 55)),
//                     &data.as_pk(),
//                     &GenericArray::generate(|_| 47),
//                 );
//                 assert_eq!(res.0.as_slice(), &data.at);
//                 assert_eq!(res.1.as_slice(), &data.bt);
//             }
//         }
//     }

//     #[derive(Debug, Deserialize)]
//     #[serde(rename_all = "camelCase")]
//     struct AesVerify {
//         lambda: u16,
//         gq: Vec<Vec<u8>>,
//         d: Vec<u8>,
//         chall2: Vec<u8>,
//         chall3: Vec<u8>,
//         at: Vec<u8>,
//         input: Vec<u8>,
//         output: Vec<u8>,
//         res: Vec<u64>,
//     }

//     impl AesVerify {
//         fn res_as_u8(&self) -> Vec<u8> {
//             self.res.iter().flat_map(|x| x.to_le_bytes()).collect()
//         }

//         fn as_pk<O>(&self) -> PublicKey<O>
//         where
//             O: OWFParameters,
//         {
//             PublicKey {
//                 owf_input: GenericArray::from_slice(&self.input).clone(),
//                 owf_output: GenericArray::from_slice(&self.output).clone(),
//             }
//         }

//         fn as_gq<LHI, LHO>(&self) -> GenericArray<GenericArray<u8, LHI>, LHO>
//         where
//             LHI: ArrayLength,
//             LHO: ArrayLength,
//         {
//             self.gq
//                 .iter()
//                 .map(|x| GenericArray::from_slice(x).clone())
//                 .collect()
//         }
//     }

//     fn aes_verify<O, Tau>(
//         d: &GenericArray<u8, O::LBYTES>,
//         gq: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
//         a_t: &GenericArray<u8, O::LAMBDABYTES>,
//         chall2: &GenericArray<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>,
//         chall3: &GenericArray<u8, O::LAMBDABYTES>,
//         pk: &PublicKey<O>,
//     ) -> GenericArray<u8, O::LAMBDABYTES>
//     where
//         O: OWFParameters,
//         Tau: TauParameters,
//     {
//         super::aes_verify::<O, Tau>(
//             d,
//             Box::<GenericArray<_, _>>::from_iter(gq.iter().cloned()),
//             a_t,
//             chall2,
//             chall3,
//             pk,
//         )
//     }

//     #[test]
//     fn aes_verify_test() {
//         let database: Vec<AesVerify> = read_test_data("AesVerify.json");
//         for data in database {
//             if data.lambda == 128 {
//                 let out = aes_verify::<OWF128, <FAEST128sParameters as FAESTParameters>::Tau>(
//                     GenericArray::from_slice(&data.d[..]),
//                     &data.as_gq(),
//                     GenericArray::from_slice(&data.at),
//                     GenericArray::from_slice(&data.chall2[..]),
//                     GenericArray::from_slice(&data.chall3[..]),
//                     &data.as_pk(),
//                 );
//                 assert_eq!(
//                     GF128::from(&data.res_as_u8()[..16]),
//                     GF128::from(out.as_slice())
//                 );
//             } else if data.lambda == 192 {
//                 let out = aes_verify::<OWF192, <FAEST192sParameters as FAESTParameters>::Tau>(
//                     GenericArray::from_slice(&data.d[..]),
//                     &data.as_gq(),
//                     GenericArray::from_slice(&data.at),
//                     GenericArray::from_slice(&data.chall2[..]),
//                     GenericArray::from_slice(&data.chall3[..]),
//                     &data.as_pk(),
//                 );
//                 assert_eq!(
//                     GF192::from(&data.res_as_u8()[..24]),
//                     GF192::from(out.as_slice())
//                 );
//             } else {
//                 let out = aes_verify::<OWF256, <FAEST256sParameters as FAESTParameters>::Tau>(
//                     GenericArray::from_slice(&data.d[..]),
//                     &data.as_gq(),
//                     GenericArray::from_slice(&data.at),
//                     GenericArray::from_slice(&data.chall2[..]),
//                     GenericArray::from_slice(&data.chall3[..]),
//                     &data.as_pk(),
//                 );
//                 assert_eq!(
//                     GF256::from(&data.res_as_u8()[..32]),
//                     GF256::from(out.as_slice())
//                 );
//             }
//         }
//     }
// }

// fn mul_deg_1_commits<F, L>(
//     lhs: &GenericArray<F, L>,
//     lhs_tag: &GenericArray<F, L>,
//     rhs: &GenericArray<F, L>,
//     rhs_tag: &GenericArray<F, L>,
// ) -> (GenericArray<F, L>, GenericArray<F, L>, GenericArray<F, L>)
// where
//     F: crate::fields::Field,
//     for<'a> &'a F: Mul<&'a F, Output = F>,
//     L: ArrayLength,
// {
//     let mut res_tag0 = GenericArray::default();
//     let mut res_tag1 = GenericArray::default();
//     let mut res = GenericArray::default();

//     for (i, (l, ltag, r, rtag)) in izip!(lhs, lhs_tag, rhs, rhs_tag).enumerate() {
//         res_tag0[i] = ltag * rtag;
//         res_tag1[i] = ltag * r + rtag * l;
//         res[i] = l * r;
//     }

//     (res_tag0, res_tag1, res)
// }

// fn diff_deg_2_deg_1_commits<F, L>(
//     lhs: &GenericArray<F, L>,
//     lhs_tag1: &GenericArray<F, L>,
//     lhs_tag0: &GenericArray<F, L>,
//     rhs: &GenericArray<F, L>,
//     rhs_tag: &GenericArray<F, L>,
// ) -> (GenericArray<F, L>, GenericArray<F, L>, GenericArray<F, L>)
// where
//     F: Clone + crate::fields::Field,
//     for<'a> &'a F: Sub<&'a F, Output = F>,
//     L: ArrayLength,
// {
//     let res_tag0= (*lhs_tag0).clone();
//     let mut res_tag1 = GenericArray::default();
//     let mut res = GenericArray::default();

//     for (i, (l, ltag, r, rtag)) in izip!(lhs, lhs_tag1, rhs, rhs_tag).enumerate() {
//         res_tag1[i] = ltag - rtag;
//         res[i] = l-r;
//     }

//     (res_tag0, res_tag1, res)
// }
