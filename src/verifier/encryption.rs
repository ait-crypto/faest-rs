use super::vole_commitments::{VoleCommits, VoleCommitsRef};
use crate::{
    aes::{
        AddRoundKey, AddRoundKeyAssign, AddRoundKeyBytes, BytewiseMixColumns, InverseAffine,
        InverseShiftRows, MixColumns, SBoxAffine, ShiftRows, StateToBytes,
    },
    fields::{
        ByteCombine, Sigmas, Square,
        large_fields::{Betas, ByteCombineSquared, SquareBytes},
    },
    parameter::{OWFField, OWFParameters},
    universal_hashing::ZKVerifyHasher,
};
use generic_array::{
    ArrayLength, GenericArray,
    typenum::{Quot, U2, U4, U8, Unsigned},
};
use itertools::izip;
use std::ops::{AddAssign, Deref, Index};
use std::{convert::AsRef, process::Output};

pub(crate) fn enc_cstrnts<'a, O, K>(
    zk_hasher: &mut ZKVerifyHasher<OWFField<O>>,
    input: impl AddRoundKey<&'a K, Output = VoleCommits<'a, OWFField<O>, O::NSTBits>>,
    output: impl AddRoundKey<&'a K, Output = VoleCommits<'a, OWFField<O>, O::NSTBits>>,
    w: VoleCommitsRef<'a, OWFField<O>, O::LENC>,
    extended_key: &'a [K],
) where
    O: OWFParameters,
    K: StateToBytes<O, Output = GenericArray<OWFField<O>, O::NSTBytes>>,
    VoleCommits<'a, OWFField<O>, O::NSTBits>: AddRoundKeyAssign<&'a K>,
{
    // // ::1
    let mut state = input.add_round_key(&extended_key[0]);

    // ::2
    for r in 0..O::R::USIZE / 2 {
        // ::3-15
        let state_prime = enc_cstrnts_even::<O>(
            zk_hasher,
            &state,
            w.get_commits_ref::<Quot<O::NSTBits, U2>>(3 * O::NSTBits::USIZE * r / 2),
        );

        // ::16-17
        let round_key = extended_key[2 * r + 1].state_to_bytes();
        let round_key_sq = square_key::<O>(&round_key);

        // ::18-22
        let st_0 = aes_round::<O>(&state_prime, &round_key, false);
        let st_1 = aes_round::<O>(&state_prime, &round_key_sq, true);

        let round_key = &extended_key[2 * r + 2];

        if r != O::R::USIZE / 2 - 1 {
            let s_tilde = w.get_commits_ref::<O::NSTBits>(
                O::NSTBits::USIZE / 2 + 3 * O::NSTBits::USIZE * r / 2,
            );

            // ::29-38
            odd_round_cnstrnts::<O>(zk_hasher, s_tilde, &st_0, &st_1);

            // ::39-40
            next_round_state::<O, _>(&mut state, s_tilde, round_key);
        } else {
            let s_tilde = output.add_round_key(round_key);

            //::29-38

            odd_round_cnstrnts::<O>(zk_hasher, &s_tilde, &st_0, &st_1);
        }
    }
}

fn aes_round<'a, O>(
    state: &VoleCommits<'a, OWFField<O>, O::NSTBits>,
    key_bytes: &GenericArray<OWFField<O>, O::NSTBytes>,
    sq: bool,
) -> VoleCommits<'a, OWFField<O>, O::NSTBytes>
where
    O: OWFParameters,
    VoleCommits<'a, OWFField<O>, O::NSTBits>:
        SBoxAffine<O, Output = VoleCommits<'a, OWFField<O>, O::NSTBytes>>,
    VoleCommits<'a, OWFField<O>, O::NSTBytes>: MixColumns<O>,
{
    // ::19-22
    let mut st = state.s_box_affine(sq);

    st.shift_rows();

    st.mix_columns(sq);

    st.add_round_key_bytes(key_bytes, sq);

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

fn enc_cstrnts_even<'a, O>(
    zk_hasher: &mut ZKVerifyHasher<OWFField<O>>,
    state: &VoleCommits<'a, OWFField<O>, O::NSTBits>,
    w: VoleCommitsRef<'_, OWFField<O>, Quot<O::NSTBits, U2>>,
) -> VoleCommits<'a, OWFField<O>, O::NSTBits>
where
    O: OWFParameters,
{
    // ::4
    let state_conj = f256_f2_conjugates::<O>(&state.scalars);

    let mut state_prime = GenericArray::default_boxed();

    // ::7
    for i in 0..O::NSTBytes::USIZE {
        // ::9
        let ys = invnorm_to_conjugates::<O>(&w[4 * i..4 * i + 4]);

        // ::11
        zk_hasher.inv_norm_constraints(&state_conj[8 * i..8 * i + 8], &ys[0]);

        // ::12
        for j in 0..8 {
            state_prime[i * 8 + j] = state_conj[8 * i + (j + 4) % 8] * ys[j % 4];
        }
    }

    VoleCommits {
        scalars: state_prime,
        delta: state.delta,
    }
}

fn next_round_state<'a, O, K>(
    state: &mut VoleCommits<'a, OWFField<O>, O::NSTBits>,
    s_tilde: VoleCommitsRef<'a, OWFField<O>, O::NSTBits>,
    round_key: &'a K,
) where
    O: OWFParameters,
    K: StateToBytes<O, Output = GenericArray<OWFField<O>, O::NSTBytes>>,
    VoleCommitsRef<'a, OWFField<O>, O::NSTBits>:
        BytewiseMixColumns<O, Output = VoleCommits<'a, OWFField<O>, O::NSTBits>>,
    VoleCommits<'a, OWFField<O>, O::NSTBits>: AddRoundKeyAssign<&'a K>,
{
    *state = s_tilde.bytewise_mix_columns();

    state.add_round_key_assign(round_key);
}

fn odd_round_cnstrnts<'a, O>(
    zk_hasher: &mut ZKVerifyHasher<OWFField<O>>,
    s_tilde: impl InverseShiftRows<O, Output = VoleCommits<'a, OWFField<O>, O::NSTBits>>,
    st_0: &VoleCommits<'a, OWFField<O>, O::NSTBytes>,
    st_1: &VoleCommits<'a, OWFField<O>, O::NSTBytes>,
) where
    O: OWFParameters,
{
    let delta = zk_hasher.delta;
    let delta_sq = zk_hasher.delta_squared;

    // ::29-30
    let mut s = s_tilde.inverse_shift_rows();
    s.inverse_affine();

    // ::31-37
    for (byte_i, (st0, st1)) in izip!(st_0.scalars.iter(), st_1.scalars.iter()).enumerate() {
        let s_i = OWFField::<O>::byte_combine_slice(&s.scalars[8 * byte_i..8 * byte_i + 8]);
        let s_i_sq = OWFField::<O>::byte_combine_sq_slice(&s.scalars[8 * byte_i..8 * byte_i + 8]);

        zk_hasher.update(&(s_i_sq * st0 + delta_sq * s_i));
        zk_hasher.update(&(s_i * st1 + delta * st0));
    }
}

fn invnorm_to_conjugates<O>(x: &[OWFField<O>]) -> GenericArray<OWFField<O>, U4>
where
    O: OWFParameters,
{
    (0..4)
        .map(|j| {
            x[0] + OWFField::<O>::BETA_SQUARES[j] * x[1]
                + OWFField::<O>::BETA_SQUARES[j + 1] * x[2]
                + OWFField::<O>::BETA_CUBES[j] * x[3]
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
