use aes::cipher::KeyInit;
use generic_array::{
    functional::FunctionalSequence,
    typenum::{Prod, Unsigned, U1, U2, U10, U3, U32, U4, U8},
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
    aes::{state_to_bytes, CommittedStateBytes, CommittedStateBytesSquared},
    fields::{
        field_commitment::{
            BitCommits, BitCommitsRef, FieldCommitDegOne, FieldCommitDegThree, FieldCommitDegTwo,
        },
        large_fields::{Betas, ByteCombineSquared, SquareBytes},
        small_fields::{GF8, GF8_INV_NORM},
        BigGaloisField, ByteCombine, ByteCombineConstants, Field, Square, SumPoly,
    },
    internal_keys::PublicKey,
    parameter::{BaseParameters, OWFParameters, QSProof, TauParameters},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, rijndael_sub_bytes, sub_bytes,
        sub_bytes_nots, State, RCON_TABLE,
    },
    universal_hashing::{ZKHasher, ZKHasherInit, ZKHasherProcess, ZKProofHasher, ZKVerifyHasher},
    utils::contains_zeros,
};

use key_expansion::{aes_key_exp_bkwd, aes_key_exp_cstrnts, aes_key_exp_fwd};

pub(crate) type KeyCstrnts<O> = (
    Box<GenericArray<u8, <O as OWFParameters>::PRODRUN128Bytes>>,
    Box<GenericArray<OWFField<O>, <O as OWFParameters>::PRODRUN128>>,
);

pub(crate) type CstrntsVal<'a, O> = &'a GenericArray<
    GenericArray<u8, <O as OWFParameters>::LAMBDA>,
    <O as OWFParameters>::LAMBDALBYTES,
>;

pub(crate) type OWFField<O> = <<O as OWFParameters>::BaseParams as BaseParameters>::Field;

#[allow(unused)]
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

    // ::1:
    // TODO: modify vole to return V as a LHAT * LAMBDABYTES instead of LHATBYTES * LAMBDA
    let w_tag: GenericArray<OWFField<O>, O::L> = (0..O::LBYTES::USIZE)
        .flat_map(|row| {
            let mut ret = vec![GenericArray::<u8, O::LAMBDABYTES>::default(); 8];

            (0..O::LAMBDA::USIZE).for_each(|col| {
                for i in 0..8 {
                    ret[i][col/8] |= (((v[row][col] >> i) & 1) << (col % 8));
                }
            });

            ret.into_iter()
                .map(|r_i| OWFField::<O>::from(r_i.as_slice()))
        })
        .collect();

    let v: GenericArray<OWFField<O>, Prod<O::LAMBDA, U2>> = (O::LBYTES::USIZE .. O::LBYTES::USIZE + O::LAMBDABYTESTWO::USIZE)
        .flat_map(|row| {

            let mut ret = vec![GenericArray::<u8, O::LAMBDABYTES>::default(); 8];

            (0..O::LAMBDA::USIZE).for_each(|col| {
                for i in 0..8 {
                    ret[i][col/8] |= (((v[row][col] >> i) & 1) << (col % 8));
                }
            });

            ret.into_iter()
                .map(|r_i| OWFField::<O>::from(r_i.as_slice()))
        })
        .collect();

    // ::7
    let u0_star = OWFField::<O>::sum_poly_bits(&u[..O::LAMBDABYTES::USIZE]);
    let u1_star = OWFField::<O>::sum_poly_bits(&u[O::LAMBDABYTES::USIZE..]);
    // println!("u0: {:?}", u0_star);
    // println!("u0: {:?}", u1_star);
    

    // ::8
    let v0_star = OWFField::<O>::sum_poly(&v[..O::LAMBDA::USIZE]);
    let v1_star = OWFField::<O>::sum_poly(&v[O::LAMBDA::USIZE..O::LAMBDA::USIZE * 2]);
    // println!("v0: {:?}", v0_star);
    // println!("v1: {:?}", v1_star);



    // ::12
    println!("before: {:?}\n", zk_hasher);
    owf_constraints::<O>(&mut zk_hasher, w, &w_tag, pk);
    println!("after: {:?}", zk_hasher);


    // ::13-18
    zk_hasher.finalize(&u0_star, &(v0_star + &u1_star), &v1_star)

}

#[allow(unused)]
fn owf_constraints<O>(
    zk_hasher: &mut ZKProofHasher<OWFField<O>>,
    w: &GenericArray<u8, O::LBYTES>,
    w_tag: &GenericArray<OWFField<O>, O::L>,
    pk: &PublicKey<O>,
) where
    O: OWFParameters,
    <<O as OWFParameters>::BaseParams as BaseParameters>::Field: PartialEq,
{

    if (O::LAMBDA::USIZE != 128 || O::is_em()){
        todo!("AES verison not yet supported");
    }

    let PublicKey {
        owf_input,
        owf_output,
    } = pk;

    let in_keys = owf_input.clone();


    let (k, k_tag) = aes_key_exp_cstrnts::<O>(
        zk_hasher,
        GenericArray::from_slice(&w[..O::LKEBytes::USIZE]),
        GenericArray::from_slice(&w_tag[..O::LKE::USIZE]),
    );


    let mut w_tilde_keys =
        GenericArray::from_slice(&w[O::LKEBytes::USIZE..O::LKEBytes::USIZE + O::LENCBytes::USIZE]);
    let mut w_tilde_tags =
        GenericArray::from_slice(&w_tag[O::LKE::USIZE..O::LKE::USIZE + O::LENC::USIZE]);

    encryption::aes_enc_cstrnts::<O>(
        zk_hasher,
        owf_input,
        owf_output,
        BitCommitsRef {
            keys: w_tilde_keys,
            tags: w_tilde_tags,
        },
        BitCommitsRef {
            keys: &k,
            tags: &k_tag,
        },
    );

}

fn invnorm_to_conjugates_prover<O>(
    x_val: u8,
    x_tag: &[OWFField<O>],
) -> GenericArray<FieldCommitDegOne<OWFField<O>>, U4>
where
    O: OWFParameters,
{
    let mut y: GenericArray<FieldCommitDegOne<OWFField<O>>, _> = GenericArray::default();

    let x_bits = [
        x_val & 1,
        (x_val & 0b10) >> 1,
        (x_val & 0b100) >> 2,
        (x_val & 0b1000) >> 3,
    ];

    for j in 0..4 {
        y[j].key = if x_bits[0] == 1 {
            OWFField::<O>::ONE
        } else {
            OWFField::<O>::ZERO
        };

        y[j].key += OWFField::<O>::BETA_SQUARES[j] * x_bits[1]
            + OWFField::<O>::BETA_SQUARES[j + 1] * x_bits[2]
            + OWFField::<O>::BETA_CUBES[j] * x_bits[3];

        y[j].tag = x_tag[0]
            + OWFField::<O>::BETA_SQUARES[j] * x_tag[1]
            + OWFField::<O>::BETA_SQUARES[j + 1] * x_tag[2]
            + OWFField::<O>::BETA_CUBES[j] * x_tag[3];
    }

    y
}

fn inverse_affine_byte<O>(
    x: u8,
    x_0: &GenericArray<OWFField<O>, U8>,
    y: &mut u8,
    y_0: &mut [OWFField<O>],
) where
    O: OWFParameters,
{
    *y = x.rotate_right(7) ^ x.rotate_right(5) ^ x.rotate_right(2) ^ 0x5;

    for i in 0..8 {
        y_0[i] = x_0[(i + 8 - 1) % 8] + x_0[(i + 8 - 3) % 8] + x_0[(i + 8 - 6) % 8];
    }
}

pub(crate) fn f256_f2_conjugates<O>(
    state: &BitCommits<OWFField<O>, O::NSTBytes>,
) -> Box<GenericArray<FieldCommitDegOne<OWFField<O>>, O::NSTBits>>
where
    O: OWFParameters,
{
    (0..O::NSTBytes::USIZE)
        .flat_map(|i| {
            let mut x0_key = state.keys[i];
            let mut x0_tags: GenericArray<_, U8> =
                GenericArray::from_slice(&state.tags[8 * i..8 * i + 8]).to_owned();
            // ::4-8
            let mut y: GenericArray<FieldCommitDegOne<OWFField<O>>, U8> = GenericArray::default();

            for i in 0..8 {
                y[i] = FieldCommitDegOne {
                    key: OWFField::<O>::byte_combine_bits(x0_key),
                    tag: OWFField::<O>::byte_combine_slice(&x0_tags),
                };

                if i != 7 {
                    GF8::square_bits_inplace(&mut x0_key);
                    OWFField::<O>::square_byte_inplace(&mut x0_tags);
                }
            }
            y
        })
        .collect()
}

pub(crate) mod key_expansion {
    use super::*;

    pub(crate) fn aes_key_exp_fwd<O>(
        w: &GenericArray<u8, O::LKEBytes>,
        w_0: &GenericArray<OWFField<O>, O::LKE>,
    ) -> (
        Box<GenericArray<u8, O::PRODRUN128Bytes>>,
        Box<GenericArray<OWFField<O>, O::PRODRUN128>>,
    )
    where
        O: OWFParameters,
    {
        // ::1
        let mut y = GenericArray::default_boxed();
        let mut y_0 = GenericArray::default_boxed();
        y[..O::LAMBDABYTES::USIZE].copy_from_slice(&w[..O::LAMBDABYTES::USIZE]);
        y_0[..O::LAMBDA::USIZE].copy_from_slice(&w_0[..O::LAMBDA::USIZE]);

        // ::2
        let mut i_wd = O::LAMBDA::USIZE;

        for j in O::NK::USIZE..(4 * (O::R::USIZE + 1)) {
            // ::5
            if (j % O::NK::USIZE == 0) || ((O::NK::USIZE > 6) && (j % O::NK::USIZE == 4)) {
                // ::6
                y[4 * j..4 * j + 4].copy_from_slice(&w[i_wd / 8..i_wd / 8 + 4]);
                y_0[32 * j..32 * j + 32].copy_from_slice(&w_0[i_wd..i_wd + 32]);

                // ::7
                i_wd += 32;
            } else {
                // ::9-10
                for i in 0..4 {
                    y[4 * j + i] = y[4 * (j - O::NK::USIZE) + i] ^ y[4 * (j - 1) + i];

                    for i_0 in 8 * i..8 * i + 8 {
                        y_0[32 * j + i_0] =
                            y_0[32 * (j - O::NK::USIZE) + i_0] + y_0[32 * (j - 1) + i_0];
                    }
                }
            }
        }

        (y, y_0)
    }

    pub(crate) fn aes_key_exp_bkwd<O>(
        x: &GenericArray<u8, O::DIFFLKELAMBDABytes>,
        x_tag: &GenericArray<OWFField<O>, O::DIFFLKELAMBDA>,
        xk: &GenericArray<u8, O::PRODRUN128Bytes>,
        xk_tag: &GenericArray<OWFField<O>, O::PRODRUN128>,
    ) -> (
        Box<GenericArray<u8, O::SKE>>,
        Box<GenericArray<OWFField<O>, Prod<O::SKE, U8>>>,
    )
    where
        O: OWFParameters,
    {
        let mut y = GenericArray::default_boxed();
        let mut y_tag = GenericArray::default_boxed();

        let mut iwd = 0;

        let rcon_evry = 4 * (O::LAMBDA::USIZE / 128);

        for j in 0..O::SKE::USIZE {
            // ::7
            let mut x_tilde = x[j] ^ xk[iwd / 8 + (j % 4)];

            let xt_0: GenericArray<OWFField<O>, U8> = (0..8)
                .map(|i| x_tag[8 * j + i] + xk_tag[iwd + 8 * (j % 4) + i])
                .collect();

            // ::8
            if j % rcon_evry == 0 {
                x_tilde ^= RCON_TABLE[j / rcon_evry];
            }

            inverse_affine_byte::<O>(x_tilde, &xt_0, &mut y[j], &mut y_tag[8 * j..8 * j + 8]);

            // ::12
            if j % 4 == 3 {
                if O::LAMBDA::USIZE != 256 {
                    iwd += O::LAMBDA::USIZE;
                } else {
                    iwd += 128;
                }
            }
        }

        (y, y_tag)
    }

    pub(crate) fn aes_key_exp_cstrnts<O>(
        zk_hasher: &mut ZKProofHasher<OWFField<O>>,
        w: &GenericArray<u8, O::LKEBytes>,
        w_tag: &GenericArray<OWFField<O>, O::LKE>,
    ) -> (
        Box<GenericArray<u8, O::PRODRUN128Bytes>>,
        Box<GenericArray<OWFField<O>, O::PRODRUN128>>,
    )
    where
        O: OWFParameters,
        OWFField<O>: BigGaloisField + ByteCombine,
        <<O as OWFParameters>::BaseParams as BaseParameters>::Field: PartialEq,
    {
        // ::1-2
        let (k, k_tag) = aes_key_exp_fwd::<O>(w, w_tag);
        let (w_flat, w_flat_tag) = aes_key_exp_bkwd::<O>(
            GenericArray::from_slice(&w[O::LAMBDABYTES::USIZE..]),
            GenericArray::from_slice(&w_tag[O::LAMBDA::USIZE..]),
            &k,
            &k_tag,
        );

        let mut iwd = 32 * (O::NK::USIZE - 1);

        let mut do_rot_word = true;

        // ::7
        // TODO: is it really more efficient than initializing 4 GenericArrays and copying values?
        let (k_hat, k_hat_sq, w_hat, w_hat_sq): (Vec<_>, Vec<_>, Vec<_>, Vec<_>) =
            multiunzip(iproduct!(0..O::SKE::USIZE / 4, 0..4).map(|(j, r)| {
                // ::11
                let r_prime_inv = if do_rot_word { (4 + r - 3) % 4 } else { r };

                // ::12
                // k_hat[(r+3) mod 3] = k[r] <=> k_hat[r] = k[(r-3) mod 3]
                let k_hat = FieldCommitDegOne {
                    key: OWFField::<O>::byte_combine_bits(k[iwd / 8 + r_prime_inv]),
                    tag: OWFField::<O>::byte_combine_slice(
                        &k_tag[iwd + 8 * r_prime_inv..iwd + 8 * r_prime_inv + 8],
                    ),
                };

                // ::13
                let k_hat_sq = FieldCommitDegOne {
                    key: OWFField::<O>::byte_combine_bits_sq(k[iwd / 8 + r_prime_inv]),
                    tag: OWFField::<O>::byte_combine_sq(
                        &k_tag[iwd + 8 * r_prime_inv..iwd + 8 * r_prime_inv + 8],
                    ),
                };

                // ::14
                let w_hat = FieldCommitDegOne {
                    key: OWFField::<O>::byte_combine_bits(w_flat[4 * j + r]),
                    tag: OWFField::<O>::byte_combine_slice(
                        &w_flat_tag[32 * j + 8 * r..32 * j + 8 * r + 8],
                    ),
                };

                // ::15
                let w_hat_sq = FieldCommitDegOne {
                    key: OWFField::<O>::byte_combine_bits_sq(w_flat[4 * j + r]),
                    tag: OWFField::<O>::byte_combine_sq(
                        &w_flat_tag[32 * j + 8 * r..32 * j + 8 * r + 8],
                    ),
                };

                if r == 3 {
                    // ::16
                    if O::LAMBDA::USIZE == 256 {
                        do_rot_word = !do_rot_word;
                    }

                    // ::21
                    if O::LAMBDA::USIZE == 192 {
                        iwd += 192;
                    } else {
                        iwd += 128;
                    }
                }

                (k_hat, k_hat_sq, w_hat, w_hat_sq)
            }));

        // ::s 19-20 (directly update zk_hahser with constraints)
        
        zk_hasher.lift_and_process(
            k_hat.into_iter(),
            k_hat_sq.into_iter(),
            w_hat.into_iter(),
            w_hat_sq.into_iter(),
        );

        (k, k_tag)
    }
}

pub(crate) mod encryption {
    use std::ops::AddAssign;

    use crate::aes::{
        add_round_key, add_round_key_bytes, bytewise_mix_columns, inverse_affine,
        inverse_shift_rows, mix_columns, s_box_affine, shift_rows, CommittedStateBits,
        CommittedStateBitsSquared,
    };

    use super::*;

    pub(crate) fn aes_enc_cstrnts<O>(
        zk_hasher: &mut ZKProofHasher<OWFField<O>>,
        input: &GenericArray<u8, O::InputSize>,
        output: &GenericArray<u8, O::InputSize>,
        w: BitCommitsRef<OWFField<O>, O::LENCBytes>,
        extended_key: BitCommitsRef<OWFField<O>, O::PRODRUN128Bytes>,
    ) where
        O: OWFParameters,
    {
        // debug_assert!(extended_key.len() == O::R::USIZE + 1);

        // ::1
        let mut state = BitCommits {
            keys: input
                .iter()
                .zip(&extended_key.keys[..O::NSTBytes::USIZE])
                .map(|(x, k)| x ^ k)
                .collect(),
            tags: Box::<GenericArray<OWFField<O>, O::NSTBits>>::from_iter(
                extended_key.tags[..O::NSTBits::USIZE].to_owned(),
            ),
        };

        // ::2
        for r in 0..O::R::USIZE / 2 {

            // ::4
            let state_conj = f256_f2_conjugates::<O>(&state);

            // ::6
            let n_key_off = 3 * O::NSTBytes::USIZE * r / 2;
            let n_tag_off = 3 * O::NSTBits::USIZE * r / 2;

            let mut state_prime = CommittedStateBitsSquared::<O>::default();

            // ::7
            for i in 0..O::NSTBytes::USIZE {
                // ::9
                let ys = invnorm_to_conjugates_prover::<O>(
                    (w.keys[n_key_off + i / 2] >> ((i % 2) * 4)) & 0xf,
                    &w.tags[n_tag_off + 4 * i..n_tag_off + 4 * i + 4],
                );

                // ::11
                aes_inv_norm_constraints_prover::<O>(
                    zk_hasher,
                    GenericArray::from_slice(&state_conj[8 * i..8 * i + 8]),
                    &ys[0],
                );

                // ::12
                for j in 0..8 {
                    state_prime[i * 8 + j] = state_conj[8 * i + (j + 4) % 8].clone() * &ys[j % 4];
                }
            }

            // ::16-17
            let round_key =
                extended_key.get_commits_ref::<O::NSTBytes>((2 * r + 1) * O::NSTBytes::USIZE);
            let round_key = state_to_bytes::<O>(round_key);
            let round_key_sq = round_key
                .iter()
                .map(|commit| commit.clone().square())
                .collect::<CommittedStateBytesSquared<O>>();

            // ::18-22
            let st_0 =
                aes_round::<O, FieldCommitDegOne<OWFField<O>>>(&state_prime, &round_key, false);
            let st_1 =
                aes_round::<O, FieldCommitDegTwo<OWFField<O>>>(&state_prime, &round_key_sq, true);

            
            let round_key = extended_key
                .get_commits_ref::<O::NSTBytes>((2 * r + 2) * O::NSTBytes::USIZE);

            if r != O::R::USIZE / 2 - 1 {
                // ::25
                let s_tilde = w.get_commits_ref::<O::NSTBytes>(
                    O::NSTBytes::USIZE / 2 + 3 * O::NSTBytes::USIZE * r / 2,
                );

                // ::29-38
                odd_round_cnstrnts::<O>(zk_hasher, s_tilde, &st_0, &st_1);

                // ::40
                state = bytewise_mix_columns::<O>(s_tilde);
                
                // ::41
                add_round_key::<O>(&mut state, round_key)
            } else {

                let s_tilde_keys: GenericArray<u8, O::NSTBytes> = output
                    .iter()
                    .zip(round_key.keys)
                    .map(|(x, k)| x ^ k)
                    .collect();

                let s_tilde = BitCommitsRef {
                    keys: &s_tilde_keys,
                    tags: round_key.tags
                };

                // ::29-38
                odd_round_cnstrnts::<O>(zk_hasher, s_tilde, &st_0, &st_1);

            }
        }
    }

    fn odd_round_cnstrnts<O>(zk_hasher: &mut ZKProofHasher<OWFField<O>>, s_tilde: BitCommitsRef<OWFField<O>, O::NSTBytes>, st_0: &CommittedStateBytesSquared<O>, st_1: &CommittedStateBytesSquared<O>)
    where O: OWFParameters{

        // ::29-30
        let mut s = inverse_shift_rows::<O>(s_tilde);
        inverse_affine::<O>(&mut s);

        for i in 0..O::NSTBytes::USIZE {
            let si = FieldCommitDegOne {
                key: OWFField::<O>::byte_combine_bits(s.keys[i]),
                tag: OWFField::<O>::byte_combine_slice(&s.tags[i * 8..i * 8 + 8]),
            };

            let si_sq = FieldCommitDegOne {
                key: OWFField::<O>::byte_combine_bits_sq(s.keys[i]),
                tag: OWFField::<O>::byte_combine_sq(&s.tags[i * 8..i * 8 + 8]),
            };

            zk_hasher.update(&(si_sq * &st_0[i] + &si));
            zk_hasher.update(&(si * &st_1[i] + &st_0[i]));
        }
    }

    fn aes_round<O, T>(
        state: &CommittedStateBitsSquared<O>,
        key_bytes: &GenericArray<T, O::NSTBytes>,
        sq: bool,
    ) -> CommittedStateBytesSquared<O>
    where
        O: OWFParameters,
        for<'a> FieldCommitDegTwo<OWFField<O>>: AddAssign<&'a T>,
    {
        // ::19
        let mut st = s_box_affine::<O>(state, sq);

        // ::20
        shift_rows::<O>(&mut st);

        // ::21
        mix_columns::<O>(&mut st, sq);

        // ::22
        add_round_key_bytes::<O, T>(&mut st, key_bytes);

        st
    }

    fn aes_inv_norm_constraints_prover<O>(
        hasher: &mut ZKProofHasher<OWFField<O>>,
        conjugates: &GenericArray<FieldCommitDegOne<OWFField<O>>, U8>,
        y: &FieldCommitDegOne<OWFField<O>>,
    ) where
        O: OWFParameters,
    {
        let z = y.clone() * &conjugates[1] * &conjugates[4] + &conjugates[0];
        hasher.update(&z);
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::needless_range_loop)]

    use super::key_expansion::{aes_key_exp_bkwd, aes_key_exp_fwd};
    use super::*;
    use crate::{
        fields::{GF128, GF192, GF256},
        parameter::{Lambda, OWFParameters, OWF128, OWF128EM, OWF192, OWF192EM, OWF256, OWF256EM},
        utils::test::read_test_data,
    };

    use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
    use serde::Deserialize;

    #[test]
    fn aes_enc_fwd_prover_128_test() {
        let w: GenericArray<u8, _> = GenericArray::from_array([
            17, 114, 181, 111, 55, 1, 111, 109, 39, 0, 190, 122, 209, 86, 174, 250, 161, 150, 152,
            81, 219, 2, 253, 129, 241, 75, 93, 95, 57, 172, 5, 217, 225, 238, 21, 13, 45, 134, 80,
            97, 15, 126, 161, 50, 27, 253, 118, 137, 35, 0, 176, 94, 230, 199, 184, 147,
        ]);

        let exp_k: GenericArray<u8, _> = GenericArray::from_array([
            17, 114, 181, 111, 55, 1, 111, 109, 39, 0, 190, 122, 209, 86, 174, 250, 161, 150, 152,
            81, 150, 151, 247, 60, 177, 151, 73, 70, 96, 193, 231, 188, 219, 2, 253, 129, 77, 149,
            10, 189, 252, 2, 67, 251, 156, 195, 164, 71, 241, 75, 93, 95, 188, 222, 87, 226, 64,
            220, 20, 25, 220, 31, 176, 94, 57, 172, 5, 217, 133, 114, 82, 59, 197, 174, 70, 34, 25,
            177, 246, 124, 225, 238, 21, 13, 100, 156, 71, 54, 161, 50, 1, 20, 184, 131, 247, 104,
            45, 134, 80, 97, 73, 26, 23, 87, 232, 40, 22, 67, 80, 171, 225, 43, 15, 126, 161, 50,
            70, 100, 182, 101, 174, 76, 160, 38, 254, 231, 65, 13, 27, 253, 118, 137, 93, 153, 192,
            236, 243, 213, 96, 202, 13, 50, 33, 199, 35, 0, 176, 94, 126, 153, 112, 178, 141, 76,
            16, 120, 128, 126, 49, 191, 230, 199, 184, 147, 152, 94, 200, 33, 21, 18, 216, 89, 149,
            108, 233, 230,
        ]);

        let tags = GenericArray::default();

        let res = aes_key_exp_fwd::<OWF128>(&w, &tags);

        assert!(*res.0 == exp_k);
    }

    #[test]
    fn aes_enc_bkwd_prover_128_test() {
        let w: GenericArray<u8, _> = GenericArray::from_array([
            168, 233, 176, 51, 172, 6, 233, 110, 215, 248, 209, 67, 11, 234, 191, 117, 60, 3, 82,
            31, 53, 103, 128, 235, 3, 122, 147, 230, 113, 159, 193, 47, 11, 201, 121, 202, 159,
            209, 193, 112,
        ]);

        let k: GenericArray<u8, _> = GenericArray::from_array([
            188, 126, 253, 108, 122, 171, 208, 78, 219, 200, 132, 13, 132, 47, 133, 101, 168, 233,
            176, 51, 210, 66, 96, 125, 9, 138, 228, 112, 141, 165, 97, 21, 172, 6, 233, 110, 126,
            68, 137, 19, 119, 206, 109, 99, 250, 107, 12, 118, 215, 248, 209, 67, 169, 188, 88, 80,
            222, 114, 53, 51, 36, 25, 57, 69, 11, 234, 191, 117, 162, 86, 231, 37, 124, 36, 210,
            22, 88, 61, 235, 83, 60, 3, 82, 31, 158, 85, 181, 58, 226, 113, 103, 44, 186, 76, 140,
            127, 53, 103, 128, 235, 171, 50, 53, 209, 73, 67, 82, 253, 243, 15, 222, 130, 3, 122,
            147, 230, 168, 72, 166, 55, 225, 11, 244, 202, 18, 4, 42, 72, 113, 159, 193, 47, 217,
            215, 103, 24, 56, 220, 147, 210, 42, 216, 185, 154, 11, 201, 121, 202, 210, 30, 30,
            210, 234, 194, 141, 0, 192, 26, 52, 154, 159, 209, 193, 112, 77, 207, 223, 162, 167,
            13, 82, 162, 103, 23, 102, 56,
        ]);

        let exp = GenericArray::from_array([
            194, 115, 166, 150, 184, 94, 43, 2, 223, 176, 186, 125, 63, 53, 49, 85, 187, 227, 202,
            24, 84, 247, 130, 118, 199, 144, 127, 52, 203, 152, 167, 170, 148, 142, 159, 152, 253,
            243, 159, 11,
        ]);
        let w_tags = GenericArray::default();
        let k_tags = GenericArray::default();

        let res = aes_key_exp_bkwd::<OWF128>(&w, &w_tags, &k, &k_tags);

        assert_eq!(exp, *res.0);
    }

    #[test]
    fn test_keycnstr() {
        let w = GenericArray::from_array([
            0xc0, 0x72, 0x0b, 0x10, 0xbf, 0x26, 0x6c, 0x19, 0x24, 0x18, 0x87, 0x72, 0xc5, 0x1f,
            0xbe, 0x52, 0x01, 0xdc, 0x0b, 0xb6, 0x57, 0x84, 0x78, 0x79, 0xbc, 0xb6, 0x27, 0x08,
            0x22, 0x85, 0xf6, 0x6f, 0x43, 0x2d, 0x60, 0x56, 0x9f, 0xc5, 0x2e, 0xe4, 0x78, 0x1a,
            0x2b, 0x68, 0x7f, 0xe1, 0xea, 0x3d, 0x6a, 0x05, 0x3a, 0x77, 0x94, 0xa8, 0x8a, 0x86,
            0x81, 0x4d, 0xe7, 0x6b, 0x58, 0x35, 0xcd, 0xba, 0x3d, 0xd5, 0x16, 0x1c, 0x47, 0x99,
            0x22, 0xf2, 0x75, 0x6f, 0x09, 0xd6, 0xe7, 0x1d, 0xc7, 0x42, 0x22, 0xd7, 0x54, 0x35,
            0xc2, 0xa6, 0x73, 0x11, 0xaa, 0x32, 0x99, 0xc3, 0x3f, 0x42, 0x84, 0x1c, 0xfd, 0x5b,
            0xdf, 0xba, 0x0c, 0x93, 0x83, 0xe8, 0x4c, 0xce, 0xde, 0xa5, 0x84, 0x3f, 0x25, 0xc9,
            0x15, 0x5a, 0x7e, 0x0c, 0x7a, 0x29, 0xd6, 0xa0, 0x2a, 0x93, 0xb7, 0xf2, 0xeb, 0x6d,
            0xad, 0x50, 0x54, 0x32, 0x5a, 0x4d, 0xe9, 0xc9, 0xcb, 0xac, 0x5d, 0x90, 0x10, 0x0f,
            0x9a, 0x45, 0x54, 0xee, 0x84, 0x1a, 0xed, 0x05, 0x02, 0x96, 0x78, 0x82, 0x79, 0x22,
            0x57, 0x1a, 0xea, 0x65, 0x19, 0xce,
        ]);

        let lke = <OWF128 as OWFParameters>::LKEBytes::USIZE;
        let hasher = ZKHasher::<GF128>::new_zk_hasher(&GenericArray::default());
        let mut hasher = ZKProofHasher::<GF128>::new(hasher.clone(), hasher.clone(), hasher);
        aes_key_exp_cstrnts::<OWF128>(
            &mut hasher,
            GenericArray::from_slice(&w[..lke]),
            &GenericArray::default(),
        );
    }
}
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
