use super::{ByteCommits, ByteCommitsRef, algebra::Lift, hashing::ConstraintHasher};
use hybrid_array::{
    Array,
    typenum::{U8, Unsigned},
};
use itertools::iproduct;

use crate::{
    fields::{BigGaloisField, ByteCombine},
    parameter::{OWFField, OWFParameters},
    rijndael_32::RCON_TABLE,
};

pub(super) fn key_exp_cstrnts<O>(
    zk_hasher: &mut impl ConstraintHasher<OWFField<O>>,
    w: ByteCommitsRef<OWFField<O>, O::LKeBytes>,
) -> ByteCommits<OWFField<O>, O::R1Times128Bytes>
where
    O: OWFParameters,
    OWFField<O>: BigGaloisField + ByteCombine,
{
    // line 1
    let k = key_exp_fwd::<O>(w);

    // line 2
    let w_flat = key_exp_bkwd::<O>(
        w.get_commits_ref::<O::LKeMinusLambdaBytes>(O::LambdaBytes::USIZE),
        k.to_ref(),
    );

    let algebra = *zk_hasher.algebra();
    let mut iwd = 32 * (O::NK::USIZE - 1);
    let mut do_rot_word = true;

    for (j, r) in iproduct!(0..O::SKe::USIZE / 4, 0..4) {
        // lines 10-11
        let r_prime_inv = if do_rot_word { (4 + r - 3) % 4 } else { r };

        // lines 12-13
        let k_hat = k.get_field_commit(&algebra, iwd / 8 + r_prime_inv);
        let k_hat_sq = k.get_field_commit_sq(&algebra, iwd / 8 + r_prime_inv);

        // lines 14-15
        let w_hat = w_flat.get_field_commit(&algebra, 4 * j + r);
        let w_hat_sq = w_flat.get_field_commit_sq(&algebra, 4 * j + r);

        // lines 19-20 (directly update zk_hahser with constraints)
        let first = k_hat_sq * w_hat + k_hat.lift(&algebra);
        let second = k_hat * w_hat_sq + w_hat.lift(&algebra);
        zk_hasher.hash_constraint(first.lift(&algebra));
        zk_hasher.hash_constraint(second.lift(&algebra));

        if r == 3 {
            // line 16
            if O::Lambda::USIZE == 256 {
                do_rot_word = !do_rot_word;
            }

            // line 21
            if O::Lambda::USIZE == 192 {
                iwd += 192;
            } else {
                iwd += 128;
            }
        }
    }

    k
}

fn key_exp_fwd<O>(
    w: ByteCommitsRef<OWFField<O>, O::LKeBytes>,
) -> ByteCommits<OWFField<O>, O::R1Times128Bytes>
where
    O: OWFParameters,
{
    let mut y = ByteCommits::default();

    // line 1-2
    y.keys[..O::LambdaBytes::USIZE].copy_from_slice(&w.keys[..O::LambdaBytes::USIZE]);
    y.tags[..O::Lambda::USIZE].copy_from_slice(&w.tags[..O::Lambda::USIZE]);

    // line 3
    let mut i_wd = O::Lambda::USIZE;

    for j in O::NK::USIZE..(4 * (O::R::USIZE + 1)) {
        // line 5
        if (j % O::NK::USIZE == 0) || ((O::NK::USIZE > 6) && (j % O::NK::USIZE == 4)) {
            // line 6
            y.keys[4 * j..4 * j + 4].copy_from_slice(&w.keys[i_wd / 8..i_wd / 8 + 4]);
            y.tags[32 * j..32 * j + 32].copy_from_slice(&w.tags[i_wd..i_wd + 32]);

            // line 7
            i_wd += 32;
        } else {
            // line 9-10
            for i in 0..4 {
                y.keys[4 * j + i] = y.keys[4 * (j - O::NK::USIZE) + i] ^ y.keys[4 * (j - 1) + i];

                for i_0 in 8 * i..8 * i + 8 {
                    y.tags[32 * j + i_0] =
                        y.tags[32 * (j - O::NK::USIZE) + i_0] + y.tags[32 * (j - 1) + i_0];
                }
            }
        }
    }

    y
}

/// FAEST v3 Figure 7.15.
fn key_exp_bkwd<O>(
    x: ByteCommitsRef<OWFField<O>, O::LKeMinusLambdaBytes>,
    xk: ByteCommitsRef<OWFField<O>, O::R1Times128Bytes>,
) -> ByteCommits<OWFField<O>, O::SKe>
where
    O: OWFParameters,
{
    let mut y = ByteCommits::default();

    let mut iwd = 0;

    let rcon_evry = 4 * (O::Lambda::USIZE / 128);

    for j in 0..O::SKe::USIZE {
        // line 7
        let mut x_tilde = x.keys[j] ^ xk.keys[iwd / 8 + (j % 4)];

        let xt_0: Array<_, U8> = (0..8)
            .map(|i| x.tags[8 * j + i] + xk.tags[iwd + 8 * (j % 4) + i])
            .collect();

        // lines 8-10
        if j % rcon_evry == 0 {
            x_tilde ^= RCON_TABLE[j / rcon_evry];
        }

        // line 11
        inverse_affine_byte(
            x_tilde,
            &xt_0,
            &mut y.keys[j],
            &mut y.tags[8 * j..8 * j + 8],
        );

        // lines 12-14
        if j % 4 == 3 {
            if O::Lambda::USIZE != 256 {
                iwd += O::Lambda::USIZE;
            } else {
                iwd += 128;
            }
        }
    }

    y
}

fn inverse_affine_byte<F>(x: u8, x_0: &Array<F, U8>, y: &mut u8, y_0: &mut [F])
where
    F: BigGaloisField,
{
    *y = x.rotate_right(7) ^ x.rotate_right(5) ^ x.rotate_right(2) ^ 0x5;

    for i in 0..8 {
        y_0[i] = x_0[(i + 8 - 1) % 8] + x_0[(i + 8 - 3) % 8] + x_0[(i + 8 - 6) % 8];
    }
}
