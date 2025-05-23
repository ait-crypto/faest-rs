use generic_array::{
    GenericArray,
    typenum::{Prod, U8, Unsigned},
};
use itertools::iproduct;

use super::vole_commitments::{VoleCommits, VoleCommitsRef};
use crate::{
    fields::{ByteCombine, large_fields::ByteCombineSquared},
    parameter::{OWFField, OWFParameters},
    rijndael_32::RCON_TABLE,
    universal_hashing::ZKVerifyHasher,
    utils::get_bit,
};

pub(crate) fn key_exp_fwd<O>(
    w: VoleCommitsRef<OWFField<O>, O::LKe>,
) -> VoleCommits<OWFField<O>, O::R1Times128>
where
    O: OWFParameters,
{
    // ::1
    let mut y_tags = GenericArray::default_boxed();
    y_tags[..O::Lambda::USIZE].copy_from_slice(&w.scalars[..O::Lambda::USIZE]);

    // ::2
    let mut i_wd = O::Lambda::USIZE;

    for j in O::NK::USIZE..(4 * (O::R::USIZE + 1)) {
        // ::5
        if (j % O::NK::USIZE == 0) || ((O::NK::USIZE > 6) && (j % O::NK::USIZE == 4)) {
            // ::6
            y_tags[32 * j..32 * j + 32].copy_from_slice(&w.scalars[i_wd..i_wd + 32]);

            // ::7
            i_wd += 32;
        } else {
            // ::9-10
            for i in 0..32 {
                y_tags[32 * j + i] = y_tags[32 * (j - O::NK::USIZE) + i] + y_tags[32 * (j - 1) + i];
            }
        }
    }

    VoleCommits {
        scalars: y_tags,
        delta: w.delta,
    }
}

pub(crate) fn key_exp_bkwd<'a, O>(
    x: VoleCommitsRef<'a, OWFField<O>, O::LKeMinusLambda>,
    xk: VoleCommitsRef<'a, OWFField<O>, O::R1Times128>,
) -> VoleCommits<'a, OWFField<O>, Prod<O::SKe, U8>>
where
    O: OWFParameters,
{
    let mut y_tag = GenericArray::default_boxed();

    let mut iwd = 0;

    let rcon_evry = 4 * (O::Lambda::USIZE / 128);

    for j in 0..O::SKe::USIZE {
        // ::7

        let xt_tag: GenericArray<OWFField<O>, U8> = (0..8)
            .map(|i| {
                let mut x_tilde_i = x.scalars[8 * j + i] + xk.scalars[iwd + 8 * (j % 4) + i];

                // ::8
                if j % rcon_evry == 0 && get_bit(&[RCON_TABLE[j / rcon_evry]], i) != 0 {
                    x_tilde_i += x.delta;
                }

                x_tilde_i
            })
            .collect();

        inverse_affine_byte::<O>(&mut y_tag[8 * j..8 * j + 8], &xt_tag, x.delta);

        // ::12
        if j % 4 == 3 {
            if O::Lambda::USIZE != 256 {
                iwd += O::Lambda::USIZE;
            } else {
                iwd += 128;
            }
        }
    }

    VoleCommits {
        scalars: y_tag,
        delta: x.delta,
    }
}

pub fn inverse_affine_byte<O>(
    y_tag: &mut [OWFField<O>],
    x_tag: &GenericArray<OWFField<O>, U8>,
    delta: &OWFField<O>,
) where
    O: OWFParameters,
{
    for i in 0..8 {
        y_tag[i] = x_tag[(i + 8 - 1) % 8] + x_tag[(i + 8 - 3) % 8] + x_tag[(i + 8 - 6) % 8];
    }

    y_tag[0] += delta;
    y_tag[2] += delta;
}

pub(crate) fn key_exp_cstrnts<'a, O>(
    zk_hasher: &mut ZKVerifyHasher<OWFField<O>>,
    w: VoleCommitsRef<'a, OWFField<O>, O::LKe>,
) -> VoleCommits<'a, OWFField<O>, O::R1Times128>
where
    O: OWFParameters,
{
    // ::1
    let k = key_exp_fwd::<O>(w);

    // ::2
    let w_flat = key_exp_bkwd::<O>(
        w.get_commits_ref::<O::LKeMinusLambda>(O::Lambda::USIZE),
        k.to_ref(),
    );

    let mut iwd = 32 * (O::NK::USIZE - 1);

    let mut do_rot_word = true;

    // ::7
    for (j, r) in iproduct!(0..O::SKe::USIZE / 4, 0..4) {
        // ::11
        let r_prime_inv = if do_rot_word { (4 + r - 3) % 4 } else { r };

        // ::12-13
        let k_hat =
            OWFField::<O>::byte_combine_slice(&k[iwd + 8 * r_prime_inv..iwd + 8 * r_prime_inv + 8]);
        let k_hat_sq = OWFField::<O>::byte_combine_sq_slice(
            &k[iwd + 8 * r_prime_inv..iwd + 8 * r_prime_inv + 8],
        );

        // ::14-15
        let w_hat = OWFField::<O>::byte_combine_slice(&w_flat[32 * j + 8 * r..32 * j + 8 * r + 8]);
        let w_hat_sq =
            OWFField::<O>::byte_combine_sq_slice(&w_flat[32 * j + 8 * r..32 * j + 8 * r + 8]);

        // :: 19-20 (directly update zk_hahser with constraints)
        zk_hasher.lift_and_process(&k_hat, &k_hat_sq, &w_hat, &w_hat_sq);

        if r == 3 {
            // ::16
            if O::Lambda::USIZE == 256 {
                do_rot_word = !do_rot_word;
            }

            // ::21
            if O::Lambda::USIZE == 192 {
                iwd += 192;
            } else {
                iwd += 128;
            }
        }
    }

    k
}
