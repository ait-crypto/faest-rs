use hybrid_array::{
    Array,
    typenum::{U8, Unsigned},
};
use itertools::iproduct;

use crate::{
    fields::{BigGaloisField, ByteCombine},
    parameter::{OWFField, OWFParameters},
    prover::{
        ByteCommits, ByteCommitsRef, polynomial::Polynomial,
    },
    rijndael_32::RCON_TABLE,
    zk_constraints::ConstraintHasher,
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

    let mut iwd = 32 * (O::NK::USIZE - 1);
    let mut do_rot_word = true;

    for (j, r) in iproduct!(0..O::SKe::USIZE / 4, 0..4) {
        // lines 10-11
        let r_prime_inv = if do_rot_word { (4 + r - 3) % 4 } else { r };

        // lines 12-13
        let k_hat = k.get_field_commit(iwd / 8 + r_prime_inv);
        let k_hat_sq = k.get_field_commit_sq(iwd / 8 + r_prime_inv);

        // lines 14-15
        let w_hat = w_flat.get_field_commit(4 * j + r);
        let w_hat_sq = w_flat.get_field_commit_sq(4 * j + r);

        // lines 19-20 (directly update zk_hahser with constraints)
        lift_and_process(zk_hasher, &k_hat, &k_hat_sq, &w_hat, &w_hat_sq);

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

fn lift_and_process<F: BigGaloisField>(
    hasher: &mut impl ConstraintHasher<F>,
    a: &Polynomial<F>,
    a_sq: &Polynomial<F>,
    b: &Polynomial<F>,
    b_sq: &Polynomial<F>,
) {
    // lines 19-20,
    let second_product = a * b_sq;
    hasher.hash_constraint((a_sq * b + a.lift(2)).lift(7));
    hasher.hash_constraint((second_product + b.lift(2)).lift(7));
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        fields::{Field, FromBit},
        parameter::{OWF128, OWF192, OWF256},
        zk_constraints::test::{fixture, public_key},
    };
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

    // Independent scalar AES field arithmetic, reduced modulo x^8+x^4+x^3+x+1.
    fn multiply(mut a: u8, mut b: u8) -> u8 {
        let mut out = 0;
        for _ in 0..8 {
            if b & 1 != 0 {
                out ^= a;
            }
            a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
            b >>= 1;
        }
        out
    }

    fn inverse(x: u8) -> u8 {
        (0..254).fold(1, |acc, _| multiply(acc, x))
    }

    fn check<O: OWFParameters>(variant: usize) {
        for sample in 0..2 {
            let (key, pk) = public_key::<O>(variant, sample);
            let witness = O::extendwitness(&key, &pk.owf_input);
            // Tags contain the witness bits themselves, so every linear map can
            // also be checked on tags independently of the polynomial keys.
            let tags: Vec<_> = (0..O::LKe::USIZE)
                .map(|i| OWFField::<O>::from_bit((witness[i / 8] >> (i % 8)) & 1))
                .collect();
            let w = ByteCommitsRef::from_slices(&witness[..O::LKeBytes::USIZE], &tags);
            let expanded = key_exp_fwd::<O>(w);
            let reference = fixture(variant, sample);
            assert_eq!(
                hex::encode(expanded.keys.as_slice()),
                reference["expanded"].as_str().unwrap()
            );
            for (i, &byte) in expanded.keys.iter().enumerate() {
                for j in 0..8 {
                    assert_eq!(
                        expanded.tags[8 * i + j],
                        OWFField::<O>::from_bit((byte >> j) & 1)
                    );
                }
            }
            let backward = key_exp_bkwd::<O>(
                w.get_commits_ref::<O::LKeMinusLambdaBytes>(O::LambdaBytes::USIZE),
                expanded.to_ref(),
            );
            let mut saw_zero = false;
            for j in 0..O::SKe::USIZE / 4 {
                let word = O::NK::USIZE - 1 + j * if O::NK::USIZE == 6 { 6 } else { 4 };
                let rotate = O::NK::USIZE != 8 || j % 2 == 0;
                for r in 0..4 {
                    let input = expanded.keys[4 * word + if rotate { (r + 1) % 4 } else { r }];
                    saw_zero |= input == 0;
                    let expected = inverse(input);
                    assert_eq!(backward.keys[4 * j + r], expected, "S-box {j}, byte {r}");
                    let stride = if O::NK::USIZE == 6 { 6 } else { 4 };
                    let raw = witness[O::LambdaBytes::USIZE + 4 * j + r]
                        ^ expanded.keys[4 * j * stride + r];
                    // Rcon and the affine offset affect keys, not tags.
                    let linear = raw.rotate_left(1) ^ raw.rotate_left(3) ^ raw.rotate_left(6);
                    for bit in 0..8 {
                        assert_eq!(
                            backward.tags[8 * (4 * j + r) + bit],
                            OWFField::<O>::from_bit((linear >> bit) & 1)
                        );
                    }
                }
            }
            if sample == 0 {
                assert!(saw_zero);
            }
        }
    }

    #[test]
    fn independent_aes128() {
        check::<OWF128>(0);
    }
    #[test]
    fn independent_aes192() {
        check::<OWF192>(1);
    }
    #[test]
    fn independent_aes256_both_rotations() {
        check::<OWF256>(2);
    }

    #[test]
    fn inverse_affine_all_bytes() {
        use crate::fields::GF128;
        for byte in 0..=255u8 {
            let affine = byte
                ^ byte.rotate_left(1)
                ^ byte.rotate_left(2)
                ^ byte.rotate_left(3)
                ^ byte.rotate_left(4)
                ^ 0x63;
            let tags =
                core::array::from_fn::<_, 8, _>(|i| GF128::from_bit((affine >> i) & 1)).into();
            let mut key = 0;
            let mut out = [GF128::ZERO; 8];
            // ::11
            inverse_affine_byte(affine, &tags, &mut key, &mut out);
            assert_eq!(key, byte);
            // Affine constants are represented in the polynomial's key.
            for i in 0..8 {
                assert_eq!(
                    out[i] + GF128::from_bit(((0x05u8) >> i) & 1),
                    GF128::from_bit((byte >> i) & 1)
                );
            }
        }
    }
}
