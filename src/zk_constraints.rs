use generic_array::{GenericArray, typenum::Unsigned};

use crate::{
    fields::{Square, SumPoly},
    internal_keys::PublicKey,
    parameter::{BaseParameters, OWFField, OWFParameters, QSProof},
    prover::{self, byte_commitments::ByteCommitsRef},
    universal_hashing::ZKHasherInit,
    utils::get_bit,
    verifier::{self, VoleCommitsRef},
};

pub(crate) type CstrntsVal<'a, O> = &'a GenericArray<
    GenericArray<u8, <O as OWFParameters>::LHatBytes>,
    <O as OWFParameters>::Lambda,
>;

// // Reshapes a matrix of size (l_hat/8) x lambda into a matrix of size l_hat x (lambda/8).
// // Then, it converts all rows in the interval [row_start, rowstart + nrows) to field elements.
fn reshape_and_to_field<O: OWFParameters>(m: CstrntsVal<O>) -> Vec<OWFField<O>> {
    (0..O::LBytes::USIZE + O::LambdaBytesTimes2::USIZE)
        .flat_map(|col| {
            let mut ret = vec![GenericArray::<u8, O::LambdaBytes>::default(); 8];
            for row in 0..O::Lambda::USIZE {
                for (i, ret_i) in ret.iter_mut().enumerate() {
                    ret_i[row / 8] |= get_bit(&[m[row][col]], i) << (row % 8);
                }
            }

            ret.into_iter()
                .map(|r_i| OWFField::<O>::from(r_i.as_slice()))
        })
        .collect()
}

pub(crate) fn aes_prove<O>(
    w: &GenericArray<u8, O::LBytes>,
    u: &GenericArray<u8, O::LambdaBytesTimes2>,
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
    let u0_star = OWFField::<O>::sum_poly_bits(&u[..O::LambdaBytes::USIZE]);
    let u1_star = OWFField::<O>::sum_poly_bits(&u[O::LambdaBytes::USIZE..]);

    // ::8
    let v0_star = OWFField::<O>::sum_poly(&v[O::L::USIZE..O::L::USIZE + O::Lambda::USIZE]);
    let v1_star = OWFField::<O>::sum_poly(&v[O::L::USIZE + O::Lambda::USIZE..]);

    // ::12
    prover::owf_constraints::<O>(
        &mut zk_hasher,
        ByteCommitsRef::from_slices(w, &v[..O::L::USIZE]),
        pk,
    );

    // ::13-18
    zk_hasher.finalize(&v0_star, &(u0_star + v1_star), &u1_star)
}

pub(crate) fn aes_verify<O>(
    q: CstrntsVal<O>,
    d: &GenericArray<u8, O::LBytes>,
    pk: &PublicKey<O>,
    chall_2: &GenericArray<u8, <<O as OWFParameters>::BaseParams as BaseParameters>::Chall>,
    chall_3: &GenericArray<u8, O::LambdaBytes>,
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
    for (i, q_i) in q.iter_mut().take(O::L::USIZE).enumerate() {
        if get_bit(d, i) != 0 {
            *q_i += delta;
        }
    }
    let w = VoleCommitsRef {
        scalars: GenericArray::from_slice(&q[..O::L::USIZE]),
        delta: &delta,
    };

    // ::7
    let q0_star = OWFField::<O>::sum_poly(&q[O::L::USIZE..O::L::USIZE + O::Lambda::USIZE]);
    let q1_star = OWFField::<O>::sum_poly(
        &q[O::L::USIZE + O::Lambda::USIZE..O::L::USIZE + O::Lambda::USIZE * 2],
    );

    // ::10
    let q_star = delta * q1_star + q0_star;

    let mut zk_hasher =
        <<O as OWFParameters>::BaseParams as BaseParameters>::ZKHasher::new_zk_verify_hasher(
            chall_2, delta,
        );

    // ::12
    verifier::owf_constraints::<O>(&mut zk_hasher, w, &delta, pk);

    // ::14
    let q_tilde = zk_hasher.finalize(&q_star);

    q_tilde - delta * a1_tilde - delta.square() * a2_tilde
}
