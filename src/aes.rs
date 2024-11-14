use std::{array, mem::size_of};

use generic_array::{
    typenum::{Unsigned, U3, U4},
    GenericArray,
};
use itertools::iproduct;

use crate::{
    fields::{ByteCombine, ByteCombineConstants, Field as _, SumPoly},
    parameter::{BaseParameters, OWFParameters, QSProof, TauParameters},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, sub_bytes, sub_bytes_nots, State, RCON_TABLE,
    },
    universal_hashing::{ZKHasherInit, ZKProofHasher, ZKVerifyHasher},
    utils::{bit_combine_with_delta, contains_zeros, convert_gq, transpose_and_into_field, Field},
};

type KeyCstrnts<O> = (
    Box<GenericArray<u8, <O as OWFParameters>::PRODRUN128Bytes>>,
    Box<GenericArray<Field<O>, <O as OWFParameters>::PRODRUN128>>,
);

type CstrntsVal<'a, O> = &'a GenericArray<
    GenericArray<u8, <O as OWFParameters>::LAMBDALBYTES>,
    <O as OWFParameters>::LAMBDA,
>;

const fn inverse_rotate_word(r: usize, rotate: bool) -> usize {
    if rotate {
        // equivalent to (r - 3) % 4
        (r + 1) % 4
    } else {
        r
    }
}

pub(crate) fn aes_extendedwitness<O>(
    owf_key: &GenericArray<u8, O::LAMBDABYTES>,
    owf_input: &GenericArray<u8, O::InputSize>,
) -> Option<Box<GenericArray<u8, O::LBYTES>>>
where
    O: OWFParameters,
{
    let mut input = [0u8; 32];
    // Step 0
    input[..O::InputSize::USIZE].clone_from_slice(owf_input);
    let mut witness = GenericArray::default_boxed();
    let mut index = 0;
    // Step 3
    let (kb, mut zeros) = rijndael_key_schedule::<U4, O::NK, O::R>(owf_key, O::SKE::USIZE);
    // Step 4
    for i in convert_from_batchblocks(inv_bitslice(&kb[..8])).take(4) {
        witness[index..index + size_of::<u32>()].copy_from_slice(&i);
        index += size_of::<u32>();
    }
    for i in convert_from_batchblocks(inv_bitslice(&kb[8..16]))
        .take(O::NK::USIZE / 2 - (4 - (O::NK::USIZE / 2)))
    {
        witness[index..index + size_of::<u32>()].copy_from_slice(&i);
        index += size_of::<u32>();
    }
    for j in 1 + (O::NK::USIZE / 8)
        ..1 + (O::NK::USIZE / 8)
            + (O::SKE::USIZE * ((2 - (O::NK::USIZE % 4)) * 2 + (O::NK::USIZE % 4) * 3)) / 16
    {
        let inside = GenericArray::<_, U3>::from_iter(
            convert_from_batchblocks(inv_bitslice(&kb[8 * j..8 * (j + 1)])).take(3),
        );
        if O::NK::USIZE == 6 {
            if j % 3 == 1 {
                witness[index..index + size_of::<u32>()].copy_from_slice(&inside[2]);
                index += size_of::<u32>();
            } else if j % 3 == 0 {
                witness[index..index + size_of::<u32>()].copy_from_slice(&inside[0]);
                index += size_of::<u32>();
            }
        } else {
            witness[index..index + size_of::<u32>()].copy_from_slice(&inside[0]);
            index += size_of::<u32>();
        }
    }
    // Step 5
    zeros |= round_with_save(&input[..16], &kb, O::R::U8, &mut witness, &mut index);
    if O::LAMBDA::USIZE > 128 {
        zeros |= round_with_save(&input[16..], &kb, O::R::U8, &mut witness, &mut index);
    }
    if zeros {
        None
    } else {
        Some(witness)
    }
}

#[allow(clippy::too_many_arguments)]
fn round_with_save(
    input1: &[u8],
    kb: &[u32],
    r: u8,
    witness: &mut [u8],
    index: &mut usize,
) -> bool {
    let mut zeros = false;
    let mut state = State::default();
    bitslice(&mut state, input1, &[]);
    rijndael_add_round_key(&mut state, &kb[..8]);
    for j in 1..r as usize {
        zeros |= contains_zeros(&inv_bitslice(&state)[0]);
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);
        rijndael_shift_rows_1::<U4>(&mut state);
        for i in convert_from_batchblocks(inv_bitslice(&state)).take(4) {
            witness[*index..*index + size_of::<u32>()].copy_from_slice(&i);
            *index += size_of::<u32>();
        }
        mix_columns_0(&mut state);
        rijndael_add_round_key(&mut state, &kb[8 * j..8 * (j + 1)]);
    }
    zeros | contains_zeros(&inv_bitslice(&state)[0])
}

fn aes_key_exp_fwd_1<O>(
    x: &GenericArray<u8, O::LKEBytes>,
) -> Box<GenericArray<u8, O::PRODRUN128Bytes>>
where
    O: OWFParameters,
{
    let mut out = GenericArray::default_boxed();
    out[..O::LAMBDABYTES::USIZE].copy_from_slice(&x[..O::LAMBDABYTES::USIZE]);
    let mut index = O::LAMBDABYTES::USIZE;
    let mut x_index = O::LAMBDABYTES::USIZE;
    for j in O::NK::USIZE..(4 * (O::R::USIZE + 1)) {
        if (j % O::NK::USIZE == 0) || ((O::NK::USIZE > 6) && (j % O::NK::USIZE == 4)) {
            out[index..index + 32 / 8].copy_from_slice(&x[x_index..x_index + 32 / 8]);
            index += 32 / 8;
            x_index += 32 / 8;
        } else {
            for i in 0..4 {
                out[index] = out[(32 * (j - O::NK::USIZE)) / 8 + i] ^ out[(32 * (j - 1)) / 8 + i];
                index += 1;
            }
        }
    }
    out
}

fn aes_key_exp_fwd<O>(
    x: &GenericArray<Field<O>, O::LKE>,
) -> Box<GenericArray<Field<O>, O::PRODRUN128>>
where
    O: OWFParameters,
{
    // Step 1 is ok by construction
    let mut out = GenericArray::default_boxed();
    out[..O::LAMBDA::USIZE].copy_from_slice(&x[..O::LAMBDA::USIZE]);
    let mut index = O::LAMBDA::USIZE;
    let mut x_index = O::LAMBDA::USIZE;
    for j in O::NK::USIZE..(4 * (O::R::USIZE + 1)) {
        if (j % O::NK::USIZE == 0) || ((O::NK::USIZE > 6) && (j % O::NK::USIZE == 4)) {
            out[index..index + 32].copy_from_slice(&x[x_index..x_index + 32]);
            index += 32;
            x_index += 32;
        } else {
            for i in 0..32 {
                out[index] = out[(32 * (j - O::NK::USIZE)) + i] + out[(32 * (j - 1)) + i];
                index += 1;
            }
        }
    }
    out
}

fn aes_key_exp_bwd_mtag0_mkey0<'a, O>(
    x: &'a GenericArray<u8, O::LKEBytes>,
    xk: &'a GenericArray<u8, O::PRODRUN128Bytes>,
) -> impl Iterator<Item = Field<O>> + 'a
where
    O: OWFParameters,
{
    let mut indice = 0;
    let mut c = 0;
    let mut rmvrcon = true;
    let mut ircon = 0;
    // Step 6
    (0..O::SKE::USIZE).map(move |j| {
        // Step 7
        let mut x_tilde = xk[indice + c] ^ x[j + O::LAMBDABYTES::USIZE];
        // Step 8
        if rmvrcon && (c == 0) {
            let rcon = RCON_TABLE[ircon];
            ircon += 1;
            // Step 11
            x_tilde ^= rcon;
        }

        c += 1;
        // Step 21
        if c == 4 {
            c = 0;
            if O::LAMBDA::USIZE == 192 {
                indice += 192 / 8;
            } else {
                indice += 128 / 8;
                if O::LAMBDA::USIZE == 256 {
                    rmvrcon = !rmvrcon;
                }
            }
        }

        Field::<O>::byte_combine_bits(
            x_tilde.rotate_right(7) ^ x_tilde.rotate_right(5) ^ x_tilde.rotate_right(2) ^ 0x5,
        )
    })
}

fn aes_key_exp_bwd_mtag1_mkey0<'a, O>(
    x: &'a [Field<O>],
    xk: &'a GenericArray<Field<O>, O::PRODRUN128>,
) -> impl Iterator<Item = Field<O>> + 'a
where
    O: OWFParameters,
{
    let mut indice = 0;
    let mut c = 0;
    let mut rmvrcon = true;
    // Step 6
    (0..O::SKE::USIZE).map(move |j| {
        // Step 7
        let x_tilde: [_; 8] = array::from_fn(|i| x[8 * j + i] + xk[indice + 8 * c + i]);
        // Step 15
        let y_tilde =
            array::from_fn(|i| x_tilde[(i + 7) % 8] + x_tilde[(i + 5) % 8] + x_tilde[(i + 2) % 8]);
        c += 1;
        // Step 21
        if c == 4 {
            c = 0;
            if O::LAMBDA::USIZE == 192 {
                indice += 192;
            } else {
                indice += 128;
                if O::LAMBDA::USIZE == 256 {
                    rmvrcon = !rmvrcon;
                }
            }
        }
        Field::<O>::byte_combine(&y_tilde)
    })
}

fn aes_key_exp_bwd_mtag0_mkey1<'a, O>(
    x: &'a GenericArray<Field<O>, O::LKE>,
    xk: &'a GenericArray<Field<O>, O::PRODRUN128>,
    delta: &'a Field<O>,
) -> impl Iterator<Item = Field<O>> + 'a
where
    O: OWFParameters,
{
    let mut indice = 0;
    let mut c = 0;
    let mut rmvrcon = true;
    let mut ircon = 0;
    // Step 6
    (0..O::SKE::USIZE).map(move |j| {
        // Step 7
        let mut x_tilde: [_; 8] =
            array::from_fn(|i| x[8 * j + i + O::LAMBDA::USIZE] + xk[indice + 8 * c + i]);
        // Step 8
        if rmvrcon && (c == 0) {
            let rcon = RCON_TABLE[ircon];
            ircon += 1;
            // Step 11
            for (i, x) in x_tilde.iter_mut().enumerate() {
                *x += *delta * ((rcon >> i) & 1);
            }
        }
        // Step 15
        let mut y_tilde =
            array::from_fn(|i| x_tilde[(i + 7) % 8] + x_tilde[(i + 5) % 8] + x_tilde[(i + 2) % 8]);
        y_tilde[0] += delta;
        y_tilde[2] += delta;
        c += 1;
        // Step 21
        if c == 4 {
            c = 0;
            if O::LAMBDA::USIZE == 192 {
                indice += 192;
            } else {
                indice += 128;
                if O::LAMBDA::USIZE == 256 {
                    rmvrcon = !rmvrcon;
                }
            }
        }
        Field::<O>::byte_combine(&y_tilde)
    })
}

fn aes_key_exp_cstrnts_mkey0<O>(
    zk_hasher: &mut ZKProofHasher<Field<O>>,
    w: &GenericArray<u8, O::LKEBytes>,
    v: &GenericArray<Field<O>, O::LKE>,
) -> KeyCstrnts<O>
where
    O: OWFParameters,
{
    let k = aes_key_exp_fwd_1::<O>(w);
    let vk = aes_key_exp_fwd::<O>(v);
    let w_b = aes_key_exp_bwd_mtag0_mkey0::<O>(w, &k);
    let v_w_b = aes_key_exp_bwd_mtag1_mkey0::<O>(&v[O::LAMBDA::USIZE..], &vk);

    zk_hasher.process(
        iproduct!(0..O::SKE::USIZE / 4, 0..4).map(|(j, r)| {
            let iwd = 32 * (O::NK::USIZE - 1) + j * if O::LAMBDA::USIZE == 192 { 192 } else { 128 };
            let dorotword = !(O::LAMBDA::USIZE == 256 && j % 2 == 1);
            Field::<O>::byte_combine_bits(k[iwd / 8 + inverse_rotate_word(r, dorotword)])
        }),
        iproduct!(0..O::SKE::USIZE / 4, 0..4).map(|(j, r)| {
            let iwd = 32 * (O::NK::USIZE - 1) + j * if O::LAMBDA::USIZE == 192 { 192 } else { 128 };
            let dorotword = !(O::LAMBDA::USIZE == 256 && j % 2 == 1);
            let r = inverse_rotate_word(r, dorotword);
            Field::<O>::byte_combine_slice(&vk[iwd + (8 * r)..iwd + (8 * r) + 8])
        }),
        w_b,
        v_w_b,
    );

    (k, vk)
}

fn aes_key_exp_cstrnts_mkey1<O>(
    zk_hasher: &mut ZKVerifyHasher<Field<O>>,
    q: &GenericArray<Field<O>, O::LKE>,
    delta: &Field<O>,
) -> Box<GenericArray<Field<O>, <O as OWFParameters>::PRODRUN128>>
where
    O: OWFParameters,
{
    let q_k = aes_key_exp_fwd::<O>(q);
    let q_w_b = aes_key_exp_bwd_mtag0_mkey1::<O>(q, &q_k, delta);

    zk_hasher.process(
        q_w_b,
        iproduct!(0..O::SKE::USIZE / 4, 0..4).map(|(j, r)| {
            let iwd = 32 * (O::NK::USIZE - 1) + j * if O::LAMBDA::USIZE == 192 { 192 } else { 128 };
            let dorotword = !(O::LAMBDA::USIZE == 256 && j % 2 == 1);
            let rotated_r = inverse_rotate_word(r, dorotword);
            Field::<O>::byte_combine_slice(&q_k[iwd + (8 * rotated_r)..iwd + (8 * rotated_r) + 8])
        }),
    );

    q_k
}

fn aes_enc_fwd_mkey0_mtag0<'a, O>(
    x: &'a GenericArray<u8, O::QUOTLENC8>,
    xk: &'a GenericArray<u8, O::PRODRUN128Bytes>,
    input: &'a [u8; 16],
) -> impl Iterator<Item = Field<O>> + 'a
where
    O: OWFParameters,
{
    (0..16)
        .map(|i| {
            // Step 2-5
            Field::<O>::byte_combine_bits(input[i]) + Field::<O>::byte_combine_bits(xk[i])
        })
        .chain(
            iproduct!(1..O::R::USIZE, 0..4)
                .map(move |(j, c)| {
                    // Step 6
                    let ix: usize = 128 * (j - 1) + 32 * c;
                    let ik: usize = 128 * j + 32 * c;
                    let x_hat: [_; 4] =
                        array::from_fn(|r| Field::<O>::byte_combine_bits(x[ix / 8 + r]));
                    let mut res: [_; 4] =
                        array::from_fn(|r| Field::<O>::byte_combine_bits(xk[ik / 8 + r]));

                    // Step 16
                    res[0] += x_hat[0] * Field::<O>::BYTE_COMBINE_2
                        + x_hat[1] * Field::<O>::BYTE_COMBINE_3
                        + x_hat[2]
                        + x_hat[3];
                    res[1] += x_hat[0]
                        + x_hat[1] * Field::<O>::BYTE_COMBINE_2
                        + x_hat[2] * Field::<O>::BYTE_COMBINE_3
                        + x_hat[3];
                    res[2] += x_hat[0]
                        + x_hat[1]
                        + x_hat[2] * Field::<O>::BYTE_COMBINE_2
                        + x_hat[3] * Field::<O>::BYTE_COMBINE_3;
                    res[3] += x_hat[0] * Field::<O>::BYTE_COMBINE_3
                        + x_hat[1]
                        + x_hat[2]
                        + x_hat[3] * Field::<O>::BYTE_COMBINE_2;
                    res
                })
                .flatten(),
        )
}

fn aes_enc_fwd_mkey1_mtag0<'a, O>(
    x: &'a GenericArray<Field<O>, O::LENC>,
    xk: &'a GenericArray<Field<O>, O::PRODRUN128>,
    input: &'a [u8; 16],
    delta: &'a Field<O>,
) -> impl Iterator<Item = Field<O>> + 'a
where
    O: OWFParameters,
{
    (0..16)
        .map(|i| {
            // Step 2-5
            bit_combine_with_delta::<O>(input[i], delta)
                + Field::<O>::byte_combine_slice(&xk[8 * i..(8 * i) + 8])
        })
        .chain(
            iproduct!(1..O::R::USIZE, 0..4)
                .map(move |(j, c)| {
                    // Step 6
                    let ix: usize = 128 * (j - 1) + 32 * c;
                    let ik: usize = 128 * j + 32 * c;
                    let x_hat: [_; 4] = array::from_fn(|r| {
                        Field::<O>::byte_combine_slice(&x[ix + 8 * r..ix + 8 * r + 8])
                    });
                    let mut res: [_; 4] = array::from_fn(|r| {
                        Field::<O>::byte_combine_slice(&xk[ik + 8 * r..ik + 8 * r + 8])
                    });

                    // Step 16
                    res[0] += x_hat[0] * Field::<O>::BYTE_COMBINE_2
                        + x_hat[1] * Field::<O>::BYTE_COMBINE_3
                        + x_hat[2]
                        + x_hat[3];
                    res[1] += x_hat[0]
                        + x_hat[1] * Field::<O>::BYTE_COMBINE_2
                        + x_hat[2] * Field::<O>::BYTE_COMBINE_3
                        + x_hat[3];
                    res[2] += x_hat[0]
                        + x_hat[1]
                        + x_hat[2] * Field::<O>::BYTE_COMBINE_2
                        + x_hat[3] * Field::<O>::BYTE_COMBINE_3;
                    res[3] += x_hat[0] * Field::<O>::BYTE_COMBINE_3
                        + x_hat[1]
                        + x_hat[2]
                        + x_hat[3] * Field::<O>::BYTE_COMBINE_2;
                    res
                })
                .flatten(),
        )
}

fn aes_enc_fwd_mkey0_mtag1<'a, O>(
    x: &'a GenericArray<Field<O>, O::LENC>,
    xk: &'a GenericArray<Field<O>, O::PRODRUN128>,
) -> impl Iterator<Item = Field<O>> + 'a
where
    O: OWFParameters,
{
    (0..16)
        .map(|i| {
            // Step 2-5
            Field::<O>::byte_combine_slice(&xk[8 * i..(8 * i) + 8])
        })
        .chain(
            iproduct!(1..O::R::USIZE, 0..4)
                .map(move |(j, c)| {
                    // Step 6
                    let ix: usize = 128 * (j - 1) + 32 * c;
                    let ik: usize = 128 * j + 32 * c;
                    let x_hat: [_; 4] = array::from_fn(|r| {
                        Field::<O>::byte_combine_slice(&x[ix + 8 * r..ix + 8 * r + 8])
                    });
                    let mut res: [_; 4] = array::from_fn(|r| {
                        Field::<O>::byte_combine_slice(&xk[ik + 8 * r..ik + 8 * r + 8])
                    });

                    // Step 16
                    res[0] += x_hat[0] * Field::<O>::BYTE_COMBINE_2
                        + x_hat[1] * Field::<O>::BYTE_COMBINE_3
                        + x_hat[2]
                        + x_hat[3];
                    res[1] += x_hat[0]
                        + x_hat[1] * Field::<O>::BYTE_COMBINE_2
                        + x_hat[2] * Field::<O>::BYTE_COMBINE_3
                        + x_hat[3];
                    res[2] += x_hat[0]
                        + x_hat[1]
                        + x_hat[2] * Field::<O>::BYTE_COMBINE_2
                        + x_hat[3] * Field::<O>::BYTE_COMBINE_3;
                    res[3] += x_hat[0] * Field::<O>::BYTE_COMBINE_3
                        + x_hat[1]
                        + x_hat[2]
                        + x_hat[3] * Field::<O>::BYTE_COMBINE_2;
                    res
                })
                .flatten(),
        )
}

fn aes_enc_bkwd_mkey0_mtag0<'a, O>(
    x: &'a GenericArray<u8, O::QUOTLENC8>,
    xk: &'a GenericArray<u8, O::PRODRUN128Bytes>,
    out: &'a [u8; 16],
) -> impl Iterator<Item = Field<O>> + 'a
where
    O: OWFParameters,
{
    // Step 2
    iproduct!(0..O::R::USIZE, 0..4, 0..4).map(move |(j, c, k)| {
        // Step 4
        let ird = 128 * j + 32 * ((c + 4 - k) % 4) + 8 * k;
        let x_t = if j < O::R::USIZE - 1 {
            x[ird / 8]
        } else {
            let x_out = out[(ird - 128 * j) / 8];
            x_out ^ xk[(128 + ird) / 8]
        };
        let y_t = x_t.rotate_right(7) ^ x_t.rotate_right(5) ^ x_t.rotate_right(2) ^ 0x5;
        Field::<O>::byte_combine_bits(y_t)
    })
}

fn aes_enc_bkwd_mkey1_mtag0<'a, O>(
    x: &'a GenericArray<Field<O>, O::LENC>,
    xk: &'a GenericArray<Field<O>, O::PRODRUN128>,
    out: &'a [u8; 16],
    delta: &'a Field<O>,
) -> impl Iterator<Item = Field<O>> + 'a
where
    O: OWFParameters,
{
    // Step 2
    iproduct!(0..O::R::USIZE, 0..4, 0..4).map(move |(j, c, k)| {
        // Step 4
        let ird = 128 * j + 32 * ((c + 4 - k) % 4) + 8 * k;
        let x_t: [_; 8] = if j < O::R::USIZE - 1 {
            array::from_fn(|i| x[ird + i])
        } else {
            array::from_fn(|i| {
                *delta * ((out[(ird - 128 * j + i) / 8] >> ((ird - 128 * j + i) % 8)) & 1)
                    + xk[128 + ird + i]
            })
        };
        let mut y_t = array::from_fn(|i| x_t[(i + 7) % 8] + x_t[(i + 5) % 8] + x_t[(i + 2) % 8]);
        y_t[0] += delta;
        y_t[2] += delta;
        Field::<O>::byte_combine(&y_t)
    })
}

fn aes_enc_bkwd_mkey0_mtag1<'a, O>(
    x: &'a GenericArray<Field<O>, O::LENC>,
    xk: &'a GenericArray<Field<O>, O::PRODRUN128>,
) -> impl Iterator<Item = Field<O>> + 'a
where
    O: OWFParameters,
{
    // Step 2
    iproduct!(0..O::R::USIZE, 0..4, 0..4).map(move |(j, c, k)| {
        // Step 4
        let ird = 128 * j + 32 * ((c + 4 - k) % 4) + 8 * k;
        let x_t = if j < O::R::USIZE - 1 {
            &x[ird..ird + 8]
        } else {
            &xk[128 + ird..136 + ird]
        };
        let y_t = array::from_fn(|i| x_t[(i + 7) % 8] + x_t[(i + 5) % 8] + x_t[(i + 2) % 8]);
        Field::<O>::byte_combine(&y_t)
    })
}

fn aes_enc_cstrnts_mkey0<O>(
    zk_hasher: &mut ZKProofHasher<Field<O>>,
    input: &[u8; 16],
    output: &[u8; 16],
    w: &GenericArray<u8, O::QUOTLENC8>,
    v: &GenericArray<Field<O>, O::LENC>,
    k: &GenericArray<u8, O::PRODRUN128Bytes>,
    vk: &GenericArray<Field<O>, O::PRODRUN128>,
) where
    O: OWFParameters,
{
    let s = aes_enc_fwd_mkey0_mtag0::<O>(w, k, input);
    let vs = aes_enc_fwd_mkey0_mtag1::<O>(v, vk);
    let s_b = aes_enc_bkwd_mkey0_mtag0::<O>(w, k, output);
    let v_s_b = aes_enc_bkwd_mkey0_mtag1::<O>(v, vk);
    zk_hasher.process(s, vs, s_b, v_s_b);
}

fn aes_enc_cstrnts_mkey1<O>(
    zk_hasher: &mut ZKVerifyHasher<Field<O>>,
    input: &[u8; 16],
    output: &[u8; 16],
    q: &GenericArray<Field<O>, O::LENC>,
    qk: &GenericArray<Field<O>, O::PRODRUN128>,
    delta: &Field<O>,
) where
    O: OWFParameters,
{
    let qs = aes_enc_fwd_mkey1_mtag0::<O>(q, qk, input, delta);
    let q_s_b = aes_enc_bkwd_mkey1_mtag0::<O>(q, qk, output, delta);
    zk_hasher.process(qs, q_s_b);
}

// Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
pub(crate) fn aes_prove<O>(
    w: &GenericArray<u8, O::LBYTES>,
    u: &GenericArray<u8, O::LAMBDALBYTES>,
    gv: CstrntsVal<O>,
    owf_input: &GenericArray<u8, O::InputSize>,
    owf_output: &GenericArray<u8, O::InputSize>,
    chall: &GenericArray<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>,
) -> QSProof<O>
where
    O: OWFParameters,
{
    let new_v = transpose_and_into_field::<O>(gv);

    let mut zk_hasher =
        <<O as OWFParameters>::BaseParams as BaseParameters>::ZKHasher::new_zk_proof_hasher(chall);

    let (k, vk) = aes_key_exp_cstrnts_mkey0::<O>(
        &mut zk_hasher,
        GenericArray::from_slice(&w[..O::LKE::USIZE / 8]),
        GenericArray::from_slice(&new_v[..O::LKE::USIZE]),
    );

    aes_enc_cstrnts_mkey0::<O>(
        &mut zk_hasher,
        owf_input[..16].try_into().unwrap(),
        owf_output[..16].try_into().unwrap(),
        GenericArray::from_slice(&w[O::LKE::USIZE / 8..(O::LKE::USIZE + O::LENC::USIZE) / 8]),
        GenericArray::from_slice(&new_v[O::LKE::USIZE..O::LKE::USIZE + O::LENC::USIZE]),
        &k,
        &vk,
    );

    if O::LAMBDA::USIZE > 128 {
        aes_enc_cstrnts_mkey0::<O>(
            &mut zk_hasher,
            owf_input[16..].try_into().unwrap(),
            owf_output[16..].try_into().unwrap(),
            GenericArray::from_slice(&w[(O::LKE::USIZE + O::LENC::USIZE) / 8..O::LBYTES::USIZE]),
            GenericArray::from_slice(&new_v[(O::LKE::USIZE + O::LENC::USIZE)..O::L::USIZE]),
            &k,
            &vk,
        );
    }

    let u_s = Field::<O>::from(&u[O::LBYTES::USIZE..]);
    let v_s = Field::<O>::sum_poly(&new_v[O::L::USIZE..O::L::USIZE + O::LAMBDA::USIZE]);
    let (a_t, b_t) = zk_hasher.finalize(&u_s, &v_s);

    (a_t.as_bytes(), b_t.as_bytes())
}

// Bits are represented as bytes : each times we manipulate bit data, we divide length by 8
#[allow(clippy::too_many_arguments)]
pub(crate) fn aes_verify<O, Tau>(
    d: &GenericArray<u8, O::LBYTES>,
    gq: Box<GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>>,
    a_t: &GenericArray<u8, O::LAMBDABYTES>,
    chall2: &GenericArray<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>,
    chall3: &GenericArray<u8, O::LAMBDABYTES>,
    owf_input: &GenericArray<u8, O::InputSize>,
    owf_output: &GenericArray<u8, O::InputSize>,
) -> GenericArray<u8, O::LAMBDABYTES>
where
    O: OWFParameters,
    Tau: TauParameters,
{
    let delta = Field::<O>::from(chall3);
    let new_q = convert_gq::<O, Tau>(d, gq, chall3);
    let mut zk_hasher =
        <<O as OWFParameters>::BaseParams as BaseParameters>::ZKHasher::new_zk_verify_hasher(
            chall2, delta,
        );

    let qk = aes_key_exp_cstrnts_mkey1::<O>(
        &mut zk_hasher,
        GenericArray::from_slice(&new_q[..O::LKE::USIZE]),
        &delta,
    );

    aes_enc_cstrnts_mkey1::<O>(
        &mut zk_hasher,
        owf_input[..16].try_into().unwrap(),
        owf_output[..16].try_into().unwrap(),
        GenericArray::from_slice(&new_q[O::LKE::USIZE..(O::LKE::USIZE + O::LENC::USIZE)]),
        &qk,
        &delta,
    );
    if O::LAMBDA::USIZE > 128 {
        aes_enc_cstrnts_mkey1::<O>(
            &mut zk_hasher,
            owf_input[16..].try_into().unwrap(),
            owf_output[16..].try_into().unwrap(),
            GenericArray::from_slice(&new_q[O::LKE::USIZE + O::LENC::USIZE..O::L::USIZE]),
            &qk,
            &delta,
        );
    }

    let q_s = Field::<O>::sum_poly(&new_q[O::L::USIZE..O::L::USIZE + O::LAMBDA::USIZE]);
    (zk_hasher.finalize(&q_s) + Field::<O>::from(a_t) * delta).as_bytes()
}

#[cfg(test)]
mod test {
    #![allow(clippy::needless_range_loop)]

    use super::*;

    use crate::{
        fields::{large_fields::NewFromU128, GF128, GF192, GF256},
        parameter::{
            FAEST128sParameters, FAEST192sParameters, FAEST256sParameters, FAESTParameters,
            OWFParameters, OWF128, OWF192, OWF256,
        },
        utils::test::read_test_data,
    };

    use generic_array::{sequence::GenericSequence, GenericArray};
    use serde::Deserialize;

    type ZkHash256 = GenericArray<u8, <OWF256 as OWFParameters>::LAMBDABYTES>;
    type ZkHash192 = GenericArray<u8, <OWF192 as OWFParameters>::LAMBDABYTES>;
    type ZkHash128 = GenericArray<u8, <OWF128 as OWFParameters>::LAMBDABYTES>;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesExtendedWitness {
        lambda: u16,
        key: Vec<u8>,
        input: Vec<u8>,
        w: Vec<u8>,
    }

    #[test]
    fn aes_extended_witness_test() {
        let database: Vec<AesExtendedWitness> = read_test_data("AesExtendedWitness.json");
        for data in database {
            if data.lambda == 128 {
                let res = aes_extendedwitness::<OWF128>(
                    GenericArray::from_slice(&data.key),
                    GenericArray::from_slice(
                        &data.input[..<OWF128 as OWFParameters>::InputSize::USIZE],
                    ),
                );
                assert_eq!(res.unwrap(), Box::new(*GenericArray::from_slice(&data.w)));
            } else if data.lambda == 192 {
                let res = aes_extendedwitness::<OWF192>(
                    GenericArray::from_slice(&data.key),
                    GenericArray::from_slice(
                        &data.input[..<OWF192 as OWFParameters>::InputSize::USIZE],
                    ),
                );
                assert_eq!(res.unwrap(), Box::new(*GenericArray::from_slice(&data.w)));
            } else {
                let res = aes_extendedwitness::<OWF256>(
                    GenericArray::from_slice(&data.key),
                    GenericArray::from_slice(
                        &data.input[..<OWF256 as OWFParameters>::InputSize::USIZE],
                    ),
                );
                assert_eq!(res.unwrap(), Box::new(*GenericArray::from_slice(&data.w)));
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesProve {
        lambda: u16,
        w: Vec<u8>,
        input: Vec<u8>,
        output: Vec<u8>,
        at: Vec<u8>,
        bt: Vec<u8>,
    }

    #[test]
    fn aes_prove_test() {
        let database: Vec<AesProve> = read_test_data("AesProve.json");
        for data in database {
            if data.lambda == 128 {
                let res: (ZkHash128, ZkHash128) = aes_prove::<OWF128>(
                    GenericArray::from_slice(&data.w),
                    &GenericArray::generate(|_| 19),
                    &GenericArray::generate(|_| GenericArray::generate(|_| 55)),
                    GenericArray::from_slice(&data.input),
                    GenericArray::from_slice(&data.output),
                    &GenericArray::generate(|_| 47),
                );

                assert_eq!((res).0, *GenericArray::from_slice(&data.at));
                assert_eq!((res).1, *GenericArray::from_slice(&data.bt));
            } else if data.lambda == 192 {
                let mut bitw: Vec<u8> = vec![0; 3264];
                for i in 0..data.w.len() {
                    for j in 0..8 {
                        bitw[8 * i + j] = (data.w[i] >> j) & 1;
                    }
                }
                let res: (ZkHash192, ZkHash192) = aes_prove::<OWF192>(
                    GenericArray::from_slice(&data.w),
                    &GenericArray::generate(|_| 19),
                    &GenericArray::generate(|_| GenericArray::generate(|_| 55)),
                    GenericArray::from_slice(&data.input),
                    GenericArray::from_slice(&data.output),
                    &GenericArray::generate(|_| 47),
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.at));
                assert_eq!(res.1, *GenericArray::from_slice(&data.bt));
            } else {
                let mut bitw: Vec<u8> = vec![0; 4000];
                for i in 0..data.w.len() {
                    for j in 0..8 {
                        bitw[8 * i + j] = (data.w[i] >> j) & 1;
                    }
                }
                let res: (ZkHash256, ZkHash256) = aes_prove::<OWF256>(
                    GenericArray::from_slice(&data.w),
                    &GenericArray::generate(|_| 19),
                    &GenericArray::generate(|_| GenericArray::generate(|_| 55)),
                    GenericArray::from_slice(&data.input),
                    GenericArray::from_slice(&data.output),
                    &GenericArray::generate(|_| 47),
                );
                assert_eq!(res.0, *GenericArray::from_slice(&data.at));
                assert_eq!(res.1, *GenericArray::from_slice(&data.bt));
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AesVerify {
        lambda: u16,
        gq: Vec<Vec<u8>>,
        d: Vec<u8>,
        chall2: Vec<u8>,
        chall3: Vec<u8>,
        at: Vec<u8>,
        input: Vec<u8>,
        output: Vec<u8>,
        res: Vec<u64>,
    }

    fn aes_verify<O, Tau>(
        d: &GenericArray<u8, O::LBYTES>,
        gq: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        a_t: &GenericArray<u8, O::LAMBDABYTES>,
        chall2: &GenericArray<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>,
        chall3: &GenericArray<u8, O::LAMBDABYTES>,
        owf_input: &GenericArray<u8, O::InputSize>,
        owf_output: &GenericArray<u8, O::InputSize>,
    ) -> GenericArray<u8, O::LAMBDABYTES>
    where
        O: OWFParameters,
        Tau: TauParameters,
    {
        super::aes_verify::<O, Tau>(
            d,
            Box::<GenericArray<_, _>>::from_iter(gq.iter().cloned()),
            a_t,
            chall2,
            chall3,
            owf_input,
            owf_output,
        )
    }

    #[test]
    fn aes_verify_test() {
        let database: Vec<AesVerify> = read_test_data("AesVerify.json");
        for data in database {
            if data.lambda == 128 {
                let out = aes_verify::<OWF128, <FAEST128sParameters as FAESTParameters>::Tau>(
                    GenericArray::from_slice(&data.d[..]),
                    GenericArray::from_slice(
                        &data
                            .gq
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.at),
                    GenericArray::from_slice(&data.chall2[..]),
                    GenericArray::from_slice(&data.chall3[..]),
                    GenericArray::from_slice(&data.input),
                    GenericArray::from_slice(&data.output),
                );
                assert_eq!(
                    GF128::new(data.res[0] as u128 + ((data.res[1] as u128) << 64), 0),
                    GF128::from(&out[..])
                );
            } else if data.lambda == 192 {
                let out = aes_verify::<OWF192, <FAEST192sParameters as FAESTParameters>::Tau>(
                    GenericArray::from_slice(&data.d[..]),
                    GenericArray::from_slice(
                        &data
                            .gq
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.at),
                    GenericArray::from_slice(&data.chall2[..]),
                    GenericArray::from_slice(&data.chall3[..]),
                    GenericArray::from_slice(&data.input),
                    GenericArray::from_slice(&data.output),
                );
                assert_eq!(
                    GF192::new(
                        data.res[0] as u128 + ((data.res[1] as u128) << 64),
                        data.res[2] as u128
                    ),
                    GF192::from(&out[..])
                );
            } else {
                let out = aes_verify::<OWF256, <FAEST256sParameters as FAESTParameters>::Tau>(
                    GenericArray::from_slice(&data.d[..]),
                    GenericArray::from_slice(
                        &data
                            .gq
                            .iter()
                            .map(|x| *GenericArray::from_slice(x))
                            .collect::<Vec<GenericArray<u8, _>>>(),
                    ),
                    GenericArray::from_slice(&data.at),
                    GenericArray::from_slice(&data.chall2[..]),
                    GenericArray::from_slice(&data.chall3[..]),
                    GenericArray::from_slice(&data.input),
                    GenericArray::from_slice(&data.output),
                );
                assert_eq!(
                    GF256::new(
                        data.res[0] as u128 + ((data.res[1] as u128) << 64),
                        data.res[2] as u128 + ((data.res[3] as u128) << 64)
                    ),
                    GF256::from(&out[..])
                );
            }
        }
    }
}
