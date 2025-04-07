use super::{
    aes::{
        add_round_key_bytes, bytewise_mix_columns, inverse_affine, inverse_shift_rows, mix_columns,
        s_box_affine, shift_rows,
    },
    ScalarCommits, ScalarCommitsRef,
};
use crate::{
    aes::{
        AddRoundKey, AddRoundKeyAssign, StateBitsCommits, StateBitsSquaredCommits,
        StateBytesCommits, StateBytesSquaredCommits, StateToBytes,
    },
    fields::{
        large_fields::{Betas, ByteCombineSquared, SquareBytes},
        ByteCombine, ByteCommitment, ByteCommits, ByteCommitsRef, Sigmas, Square,
    },
    parameter::{OWFField, OWFParameters},
    universal_hashing::ZKVerifyHasher,
};
use generic_array::{
    typenum::{Quot, Unsigned, U2, U4, U8},
    ArrayLength, GenericArray,
};
use std::ops::{AddAssign, Deref, Index};
use std::{convert::AsRef, process::Output};

pub(crate) fn enc_cstrnts<O>(
    zk_hasher: &mut ZKVerifyHasher<OWFField<O>>,
    input: impl for<'a> AddRoundKey<
        &'a GenericArray<OWFField<O>, O::NSTBits>,
        Output = ScalarCommits<OWFField<O>, O::NSTBits>,
    >,
    output: impl for<'a> AddRoundKey<
        &'a GenericArray<OWFField<O>, O::NSTBits>,
        Output = ScalarCommits<OWFField<O>, O::NSTBits>,
    >,
    w: ScalarCommitsRef<OWFField<O>, O::LENC>,
    extended_key: &[GenericArray<OWFField<O>, O::NSTBits>],
    delta: &OWFField<O>,
) where
    O: OWFParameters,
    // K: StateToBytes<O>,
    // ScalarCommits<OWFField<O>, O::NSTBytes>: for<'a> AddRoundKeyAssign<&'a K>,
{
    // // ::1
    let mut state = input.add_round_key(&extended_key[0]);
    // println!("state: {:?}", &state.scalars);

    // ::2
    for r in 0..O::R::USIZE / 2 {
        // ::3-15
        let state_prime = enc_cstrnts_even::<O>(
            zk_hasher,
            &state.scalars,
            GenericArray::from_slice(
                &w.scalars[3 * O::NSTBits::USIZE * r / 2
                    ..3 * O::NSTBits::USIZE * r / 2 + O::NSTBits::USIZE / 2],
            ),
        );

        // ::16-17
        // if r == 0 {println!("key: {:?}", &extended_key[2 * r + 1]);}
        let round_key = state_to_bytes::<O>(&extended_key[2 * r + 1]);
        let round_key_sq = square_key::<O>(&round_key);
        // if r == 0 {println!("round_key: {:?}", &round_key[0..3]);}

        // ::18-22
        let st_0 = aes_round::<O>(&state_prime, &round_key, delta, false);
        let st_1 = aes_round::<O>(&state_prime, &round_key_sq, delta, true);

        let round_key = &extended_key[2 * r + 2];

        if r != O::R::USIZE / 2 - 1 {
            let s_tilde = w.get_commits_ref::<O::NSTBits>(
                O::NSTBits::USIZE / 2 + 3 * O::NSTBits::USIZE * r / 2,
            );

            // ::29-38
            // println!("before odd round: {:?}, {:?}", zk_hasher.b_hasher.h0, zk_hasher.b_hasher.h1);
            odd_round_cnstrnts::<O>(zk_hasher, s_tilde, &st_0, &st_1);
            // println!("after odd round: {:?}, {:?}", zk_hasher.b_hasher.h0, zk_hasher.b_hasher.h1);

            // ::39-40
            next_round_state::<O>(&mut state, s_tilde, round_key);
        } else {
            let s_tilde = output.add_round_key(round_key);

            //::29-38
            odd_round_cnstrnts::<O>(zk_hasher, s_tilde.as_ref(), &st_0, &st_1);
        }
    }
}

fn state_to_bytes<O>(
    state: &GenericArray<OWFField<O>, O::NSTBits>,
) -> GenericArray<OWFField<O>, O::NSTBytes>
where
    O: OWFParameters,
{
    (0..O::NSTBytes::USIZE)
        .map(|i| OWFField::<O>::byte_combine_slice(&state[8 * i..8 * i + 8]))
        .collect()
}

fn aes_round<O>(
    state: &GenericArray<OWFField<O>, O::NSTBits>,
    key_bytes: &GenericArray<OWFField<O>, O::NSTBytes>,
    delta: &OWFField<O>,
    sq: bool,
) -> GenericArray<OWFField<O>, O::NSTBytes>
where
    O: OWFParameters,
{
    // ::19-22
    let mut st = s_box_affine::<O>(state, &delta.square(), sq);
    // if sq == false {println!("st0 - sbox: {:?}", &st[0..2]);}

    shift_rows::<O>(&mut st);
    // if sq == false {println!("st0 - shr: {:?}", &st[0..2]);}

    mix_columns::<O>(&mut st, sq);
    // if sq == false {println!("st0 - mxc: {:?}", &st[0..2]);}

    add_round_key_bytes::<O>(&mut st, key_bytes, delta, sq);
    // if sq == false {println!("st0 - rk: {:?}", &st[0..2]);}

    st
}

fn square_key<O>(
    key: &GenericArray<OWFField<O>, O::NSTBytes>,
) -> GenericArray<OWFField<O>, O::NSTBytes>
where
    O: OWFParameters,
{
    key.iter().map(|ki| ki.square()).collect()
}

fn enc_cstrnts_even<O>(
    zk_hasher: &mut ZKVerifyHasher<OWFField<O>>,
    state: &GenericArray<OWFField<O>, O::NSTBits>,
    w: &GenericArray<OWFField<O>, Quot<O::NSTBits, U2>>,
) -> GenericArray<OWFField<O>, O::NSTBits>
where
    O: OWFParameters,
{
    // ::4
    let state_conj = f256_f2_conjugates::<O>(state);

    let mut state_prime = GenericArray::default();

    // ::7
    for i in 0..O::NSTBytes::USIZE {
        // ::9
        // if i==0 {
        //     println!("state_conj: {:?}", &state_conj[8 * i..8 * i + 8]);
        // }
        let ys = invnorm_to_conjugates::<O>(&w[4 * i..4 * i + 4]);

        // ::11
        // println!("before inv_norm_cstr: {:?}, {:?}", zk_hasher.b_hasher.h0, zk_hasher.b_hasher.h1);
        // if i==0 {println!("ys[0]: {:?}", ys[0]);}
        zk_hasher.inv_norm_constraints(&state_conj[8 * i..8 * i + 8], &ys[0]);
        // if i==0 {println!("after inv_norm_cstr: {:?}, {:?}", zk_hasher.b_hasher.h0, zk_hasher.b_hasher.h1);}

        // ::12
        for j in 0..8 {
            state_prime[i * 8 + j] = state_conj[8 * i + (j + 4) % 8] * &ys[j % 4];
        }
    }

    state_prime
}

fn next_round_state<O>(
    state: &mut ScalarCommits<OWFField<O>, O::NSTBits>,
    s_tilde: ScalarCommitsRef<OWFField<O>, O::NSTBits>,
    round_key: &GenericArray<OWFField<O>, O::NSTBits>,
) where
    O: OWFParameters,
    // ScalarCommits<OWFField<O>, O::NSTBytes>: AddRoundKeyAssign<K>,
{
    *state = bytewise_mix_columns::<O>(s_tilde);

    state.add_round_key_assign(round_key);
}

fn odd_round_cnstrnts<O>(
    zk_hasher: &mut ZKVerifyHasher<OWFField<O>>,
    s_tilde: ScalarCommitsRef<OWFField<O>, O::NSTBits>,
    st_0: &GenericArray<OWFField<O>, O::NSTBytes>,
    st_1: &GenericArray<OWFField<O>, O::NSTBytes>,
) where
    O: OWFParameters,
{
    let delta = zk_hasher.delta;
    let delta_sq = zk_hasher.delta_squared;

    // ::29-30
    let mut s = inverse_shift_rows::<O>(s_tilde);
    inverse_affine::<O>(&mut s);

    // ::31-37
    for byte_i in 0..O::NSTBytes::USIZE {
        let s_i = OWFField::<O>::byte_combine_slice(&s.scalars[8 * byte_i..8 * byte_i + 8]);
        let s_i_sq = OWFField::<O>::byte_combine_sq_slice(&s.scalars[8 * byte_i..8 * byte_i + 8]);

        zk_hasher.update(&(s_i_sq * &st_0[byte_i] + delta_sq * &s_i));
        zk_hasher.update(&(s_i * &st_1[byte_i] + delta * &st_0[byte_i]));
    }
}

fn invnorm_to_conjugates<O>(x: &[OWFField<O>]) -> GenericArray<OWFField<O>, U4>
where
    O: OWFParameters,
{
    (0..4)
        .map(|j| {
            let tag = x[0]
                + OWFField::<O>::BETA_SQUARES[j] * x[1]
                + OWFField::<O>::BETA_SQUARES[j + 1] * x[2]
                + OWFField::<O>::BETA_CUBES[j] * x[3];
            tag
        })
        .collect()
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
    state: &GenericArray<OWFField<O>, O::NSTBits>,
) -> GenericArray<OWFField<O>, O::NSTBits>
where
    O: OWFParameters,
{
    (0..O::NSTBytes::USIZE)
        .flat_map(|i| {
            let mut x0: GenericArray<OWFField<O>, U8> =
                GenericArray::from_slice(&state[8 * i..8 * i + 8]).to_owned();

            // ::4-8
            let mut y: GenericArray<OWFField<O>, U8> = GenericArray::default();

            for j in 0..7 {
                y[j] = OWFField::<O>::byte_combine_slice(&x0);

                OWFField::<O>::square_byte_inplace(&mut x0);
            }

            y[7] = OWFField::<O>::byte_combine_slice(&x0);

            y
        })
        .collect()
}
