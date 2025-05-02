use generic_array::{
    GenericArray,
    typenum::{U8, Unsigned},
};
use itertools::iproduct;

use crate::{
    fields::{BigGaloisField, ByteCombine},
    parameter::{BaseParameters, OWFField, OWFParameters},
    prover::{ByteCommits, ByteCommitsRef},
    rijndael_32::RCON_TABLE,
    universal_hashing::ZKProofHasher,
};

pub(super) fn key_exp_cstrnts<O>(
    zk_hasher: &mut ZKProofHasher<OWFField<O>>,
    w: ByteCommitsRef<OWFField<O>, O::LKEBytes>,
) -> ByteCommits<OWFField<O>, O::PRODRUN128Bytes>
where
    O: OWFParameters,
    OWFField<O>: BigGaloisField + ByteCombine,
    <<O as OWFParameters>::BaseParams as BaseParameters>::Field: PartialEq,
{
    // ::1
    let k = key_exp_fwd::<O>(w);

    // ::2
    let w_flat = key_exp_bkwd::<O>(
        w.get_commits_ref::<O::DIFFLKELAMBDABytes>(O::LAMBDABYTES::USIZE),
        k.to_ref(),
    );

    let mut iwd = 32 * (O::NK::USIZE - 1);

    let mut do_rot_word = true;

    // ::7
    iproduct!(0..O::SKE::USIZE / 4, 0..4).for_each(|(j, r)| {
        // ::11
        let r_prime_inv = if do_rot_word { (4 + r - 3) % 4 } else { r };

        // ::12-13
        let k_hat = k.get_field_commit(iwd / 8 + r_prime_inv);
        let k_hat_sq = k.get_field_commit_sq(iwd / 8 + r_prime_inv);

        // ::14-15
        let w_hat = w_flat.get_field_commit(4 * j + r);
        let w_hat_sq = w_flat.get_field_commit_sq(4 * j + r);

        // :: 19-20 (directly update zk_hahser with constraints)
        zk_hasher.lift_and_process(&k_hat, &k_hat_sq, &w_hat, &w_hat_sq);

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
    });

    k
}

fn key_exp_fwd<O>(
    w: ByteCommitsRef<OWFField<O>, O::LKEBytes>,
) -> ByteCommits<OWFField<O>, O::PRODRUN128Bytes>
where
    O: OWFParameters,
{
    let mut y = ByteCommits::default();

    // ::1
    y.keys[..O::LAMBDABYTES::USIZE].copy_from_slice(&w.keys[..O::LAMBDABYTES::USIZE]);
    y.tags[..O::LAMBDA::USIZE].copy_from_slice(&w.tags[..O::LAMBDA::USIZE]);

    // ::2
    let mut i_wd = O::LAMBDA::USIZE;

    for j in O::NK::USIZE..(4 * (O::R::USIZE + 1)) {
        // ::5
        if (j % O::NK::USIZE == 0) || ((O::NK::USIZE > 6) && (j % O::NK::USIZE == 4)) {
            // ::6
            y.keys[4 * j..4 * j + 4].copy_from_slice(&w.keys[i_wd / 8..i_wd / 8 + 4]);
            y.tags[32 * j..32 * j + 32].copy_from_slice(&w.tags[i_wd..i_wd + 32]);

            // ::7
            i_wd += 32;
        } else {
            // ::9-10
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

fn key_exp_bkwd<O>(
    x: ByteCommitsRef<OWFField<O>, O::DIFFLKELAMBDABytes>,
    xk: ByteCommitsRef<OWFField<O>, O::PRODRUN128Bytes>,
) -> ByteCommits<OWFField<O>, O::SKE>
where
    O: OWFParameters,
{
    let mut y = ByteCommits::default();

    let mut iwd = 0;

    let rcon_evry = 4 * (O::LAMBDA::USIZE / 128);

    for j in 0..O::SKE::USIZE {
        // ::7
        let mut x_tilde = x.keys[j] ^ xk.keys[iwd / 8 + (j % 4)];

        let xt_0: GenericArray<OWFField<O>, U8> = (0..8)
            .map(|i| x.tags[8 * j + i] + xk.tags[iwd + 8 * (j % 4) + i])
            .collect();

        // ::8
        if j % rcon_evry == 0 {
            x_tilde ^= RCON_TABLE[j / rcon_evry];
        }

        inverse_affine_byte::<O>(
            x_tilde,
            &xt_0,
            &mut y.keys[j],
            &mut y.tags[8 * j..8 * j + 8],
        );

        // ::12
        if j % 4 == 3 {
            if O::LAMBDA::USIZE != 256 {
                iwd += O::LAMBDA::USIZE;
            } else {
                iwd += 128;
            }
        }
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
