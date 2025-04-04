use crate::{
    fields::{
        large_fields::{ByteCombineConstants, ByteCombineSquared, ByteCombineSquaredConstants},
        ByteCombine, Sigmas,
    },
    parameter::{BaseParameters, OWFField, OWFParameters},
};
use generic_array::{
    typenum::{Unsigned, U4, U8},
    GenericArray,
};
use itertools::izip;

use super::{ScalarCommits, ScalarCommitsRef};

pub(crate) fn s_box_affine<O>(
    state: &GenericArray<OWFField<O>, O::NSTBits>,
    delta_sq: &OWFField<O>,
    sq: bool,
) -> GenericArray<OWFField<O>, O::NSTBytes>
where
    O: OWFParameters,
{
    let sigmas = if sq {
        &OWFField::<O>::SIGMA_SQUARES
    } else {
        &OWFField::<O>::SIGMA
    };

    let t = sq as usize;

    // :: 8-10
    (0..O::NSTBytes::USIZE)
        .map(|i| {
            // :: 9
            let mut y_i = sigmas[8] * delta_sq;

            for sigma_idx in 0..8 {
                y_i += state[i * 8 + (sigma_idx + t) % 8].clone() * &sigmas[sigma_idx];
            }

            y_i
        })
        .collect()
}

pub(crate) fn shift_rows<O>(state: &mut GenericArray<OWFField<O>, O::NSTBytes>)
where
    O: OWFParameters,
{
    // TODO: Copy row by row instead of entire state
    let mut tmp = state.clone();

    for r in 0..4 {
        for c in 0..O::NST::USIZE {
            let off = if (O::NST::USIZE != 8) || (r <= 1) {
                0
            } else {
                1
            };
            std::mem::swap(
                &mut state[4 * c + r],
                &mut tmp[4 * ((c + r + off) % O::NST::USIZE) + r],
            );
        }
    }
}

pub(crate) fn mix_columns<O>(state: &mut GenericArray<OWFField<O>, O::NSTBytes>, sq: bool)
where
    O: OWFParameters,
{
    let (v2, v3) = if sq {
        (
            OWFField::<O>::BYTE_COMBINE_SQ_2,
            OWFField::<O>::BYTE_COMBINE_SQ_3,
        )
    } else {
        (OWFField::<O>::BYTE_COMBINE_2, OWFField::<O>::BYTE_COMBINE_3)
    };

    for c in 0..O::NST::USIZE {
        // Save the 4 state's columns that will be modified in this round
        let tmp = GenericArray::<_, U4>::from_slice(&state[4 * c..4 * c + 4]).to_owned();

        let i0 = 4 * c;
        let i1 = 4 * c + 1;
        let i2 = 4 * c + 2;
        let i3 = 4 * c + 3;

        // ::7
        state[i0] = tmp[0] * &v2 + tmp[1] * &v3 + &tmp[2] + &tmp[3];

        // ::8
        state[i1] = tmp[1] * &v2 + tmp[2] * &v3 + &tmp[0] + &tmp[3];

        // ::9
        state[i2] = tmp[2] * &v2 + tmp[3] * &v3 + &tmp[0] + &tmp[1];

        // ::10
        // SAFETY: tmp has length 4, hence unwrapping the first 4 elements is safe
        let mut tmp = tmp.into_iter();
        let tmp0 = tmp.next().unwrap();
        let tmp1 = tmp.next().unwrap();
        let tmp2 = tmp.next().unwrap();
        let tmp3 = tmp.next().unwrap();

        state[i3] = tmp0 * &v3 + tmp3 * &v2 + &tmp1 + &tmp2;
    }
}

pub(crate) fn inverse_affine<O>(state: &mut ScalarCommits<OWFField<O>, O::NSTBits>)
where
    O: OWFParameters,
{
    for i in 0..O::NSTBytes::USIZE {
        let xi_tags: GenericArray<_, U8> =
            GenericArray::from_slice(&state.scalars[8 * i..8 * i + 8]).to_owned();
        for bit_i in 0..8 {
            // ::6
            state.scalars[8 * i + bit_i] = xi_tags[(bit_i + 8 - 1) % 8]
                + &xi_tags[(bit_i + 8 - 3) % 8]
                + &xi_tags[(bit_i + 8 - 6) % 8];

            if bit_i == 0 || bit_i == 2 {
                state.scalars[8 * i + bit_i] += &state.vole_challenge;
            }
        }
    }
}

pub(crate) fn add_round_key_bytes<O>(
    state: &mut GenericArray<OWFField<O>, O::NSTBytes>,
    key_bytes: &GenericArray<OWFField<O>, O::NSTBytes>,
    delta: &OWFField<O>,
    sq: bool,
) where
    O: OWFParameters,
{
    if !sq {
        for (st, k) in izip!(state.iter_mut(), key_bytes) {
            (*st) += k;
        }
    } else {
        for (st, k) in izip!(state.iter_mut(), key_bytes) {
            (*st) += *k * delta;
        }
    }
}

pub(crate) fn bytewise_mix_columns<O>(
    state: ScalarCommitsRef<OWFField<O>, O::NSTBits>,
) -> ScalarCommits<OWFField<O>, O::NSTBits>
where
    O: OWFParameters,
{
    let mut o = GenericArray::<_, O::NSTBits>::default_boxed();

    for c in 0..O::NST::USIZE {
        for r in 0..4 {
            // ::4
            let a_key = &state.scalars[32 * c + 8 * r..32 * c + 8 * r + 8];

            // ::5
            let b_key = [
                a_key[7],
                a_key[0] + a_key[7],
                a_key[1],
                a_key[2] + a_key[7],
                a_key[3] + a_key[7],
                a_key[4],
                a_key[5],
                a_key[6],
            ];

            // ::6..10
            for j in 0..2 {
                let off = 32 * c + 8 * ((4 + r - j) % 4);
                o[off..off + 8]
                    .iter_mut()
                    .zip(b_key.iter())
                    .for_each(|(o, b)| {
                        *o += b;
                    });
            }

            for j in 1..4 {
                let off = 32 * c + 8 * ((r + j) % 4);

                o[off .. off + 8]
                    .iter_mut()
                    .zip(a_key.iter())
                    .for_each(|(o, a)| {
                        *o += a;
                    });
            }
        }
    }

    ScalarCommits { scalars: o, vole_challenge: *state.vole_challenge }
}

pub(crate) fn inverse_shift_rows<O>(
    state: ScalarCommitsRef<OWFField<O>, O::NSTBits>,
) -> ScalarCommits<OWFField<O>, O::NSTBits>
where
    O: OWFParameters,
{
    let mut state_prime = GenericArray::default_boxed();

    for r in 0..4 {
        for c in 0..O::NST::USIZE {
            // :: 3-6
            let i = if (O::NST::USIZE != 8) || (r <= 1) {
                4 * ((O::NST::USIZE + c - r) % O::NST::USIZE) + r
            } else {
                4 * ((O::NST::USIZE + c - r - 1) % O::NST::USIZE) + r
            };

            // :: 7
            state_prime[8 * (4 * c + r)..8 * (4 * c + r) + 8]
                .copy_from_slice(&state.scalars[8 * i..8 * i + 8]);
        }
    }

    ScalarCommits { scalars: state_prime, vole_challenge: *state.vole_challenge }
}