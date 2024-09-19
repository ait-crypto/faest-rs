use ::faest::{
    faest::{faest_sign, faest_verify, sigma_to_signature, AesCypher, EmCypher, Variant},
    parameter::{
        PARAM, PARAM128F, PARAM128FEM, PARAM128S, PARAM128SEM, PARAM192F, PARAM192FEM, PARAM192S,
        PARAM192SEM, PARAM256F, PARAM256FEM, PARAM256S, PARAM256SEM, PARAMOWF, PARAMOWF128,
        PARAMOWF128EM, PARAMOWF192, PARAMOWF192EM, PARAMOWF256, PARAMOWF256EM,
    },
};
use cipher::Unsigned;
use criterion::{criterion_group, criterion_main, Criterion};
use faest::faest;
use generic_array::GenericArray;
use nist_pqc_seeded_rng::NistPqcAes256CtrRng;
use rand::random;

type Signature<P> = GenericArray<u8, <P as PARAM>::SIG>;

type KeyInput<O> = (
    Vec<u8>,
    GenericArray<u8, <O as PARAMOWF>::LAMBDABYTES>,
    GenericArray<u8, <O as PARAMOWF>::PK>,
);

fn generate_rng() -> NistPqcAes256CtrRng {
    let seed: [u8; 48] = [rand::random::<[u8; 32]>(), rand::random::<[u8; 32]>()].concat()[..48]
        .try_into()
        .unwrap();
    NistPqcAes256CtrRng::from(seed)
}

fn generate_sign_input_aes<C, P, O>() -> KeyInput<O>
where
    P: PARAM,
    O: PARAMOWF,
    C: Variant,
{
    let rng = generate_rng();
    let (sk, pk) = C::keygen_with_rng::<P, O>(rng);
    let length: u8 = random();
    let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
    (
        msg.to_vec(),
        (*GenericArray::from_slice(
            &sk[<O::PK as Unsigned>::to_usize() / 2
                ..<O::LAMBDABYTES as Unsigned>::to_usize() + (<O::PK as Unsigned>::to_usize() / 2)],
        ))
        .clone(),
        (*GenericArray::from_slice(&pk[..<O::PK as Unsigned>::to_usize()])).clone(),
    )
}

fn generate_sign_input_em<C, P, O>() -> KeyInput<O>
where
    P: PARAM,
    O: PARAMOWF,
    C: Variant,
{
    let rng = generate_rng();
    let (sk, pk) = C::keygen_with_rng::<P, O>(rng);
    let length: u8 = random();
    let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
    (
        msg.to_vec(),
        (*GenericArray::from_slice(&sk[<P::LAMBDA as Unsigned>::to_usize() / 8..])).clone(),
        (*GenericArray::from_slice(&pk)).clone(),
    )
}

fn bench_sign<C, P, O>(input: KeyInput<O>) -> Signature<P>
where
    C: Variant,
    P: PARAM,
    O: PARAMOWF,
{
    sigma_to_signature::<P, O>(faest_sign::<C, P, O>(&input.0, &input.1, &input.2, &[]))
}

fn generate_verify_input_aes<C, P, O>() -> (Vec<u8>, GenericArray<u8, O::PK>, Signature<P>)
where
    C: Variant,
    P: PARAM,
    O: PARAMOWF,
{
    let rng = generate_rng();
    let (sk, pk) = C::keygen_with_rng::<P, O>(rng);
    let length: u8 = random();
    let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
    let sign = faest_sign::<C, P, O>(
        msg,
        GenericArray::from_slice(
            &sk[<O::PK as Unsigned>::to_usize() - <O::LAMBDABYTES as Unsigned>::to_usize()..],
        ),
        GenericArray::from_slice(&pk),
        &[],
    );
    (msg.to_vec(), *pk, sigma_to_signature::<P, O>(sign))
}

fn generate_verify_input_em<C, P, O>() -> (Vec<u8>, GenericArray<u8, O::PK>, Signature<P>)
where
    C: Variant,
    P: PARAM,
    O: PARAMOWF,
{
    let rng = generate_rng();
    let (sk, pk) = C::keygen_with_rng::<P, O>(rng);
    let length: u8 = random();
    let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
    let sign = faest_sign::<C, P, O>(
        msg,
        GenericArray::from_slice(&sk[<P::LAMBDA as Unsigned>::to_usize() / 8..]),
        GenericArray::from_slice(&pk),
        &[],
    );
    (
        msg.to_vec(),
        (*GenericArray::from_slice(&pk)).clone(),
        sigma_to_signature::<P, O>(sign),
    )
}

fn bench_verify_aes<C, P, O>(input: (Vec<u8>, GenericArray<u8, O::PK>, Signature<P>))
where
    C: Variant,
    P: PARAM,
    O: PARAMOWF,
{
    faest_verify::<C, P, O>(&input.0, input.1, &input.2);
}

fn bench_verify_em<C, P, O>(input: (Vec<u8>, GenericArray<u8, O::PK>, Signature<P>))
where
    C: Variant,
    P: PARAM,
    O: PARAMOWF,
{
    faest_verify::<C, P, O>(&input.0, input.1, &input.2);
}

pub fn faest_benchmark(c: &mut Criterion) {
    c.bench_function("Keygen aes 128s", |b| {
        b.iter(|| faest::AesCypher::keygen_with_rng::<PARAM128S, PARAMOWF128>(generate_rng()))
    });
    c.bench_function("Keygen aes 128f", |b| {
        b.iter(|| faest::AesCypher::keygen_with_rng::<PARAM128S, PARAMOWF128>(generate_rng()))
    });
    c.bench_function("Keygen aes 192s", |b| {
        b.iter(|| faest::AesCypher::keygen_with_rng::<PARAM192F, PARAMOWF192>(generate_rng()))
    });
    c.bench_function("Keygen aes 192f", |b| {
        b.iter(|| faest::AesCypher::keygen_with_rng::<PARAM192S, PARAMOWF192>(generate_rng()))
    });
    c.bench_function("Keygen aes 256s", |b| {
        b.iter(|| faest::AesCypher::keygen_with_rng::<PARAM256F, PARAMOWF256>(generate_rng()))
    });
    c.bench_function("Keygen aes 256f", |b| {
        b.iter(|| faest::AesCypher::keygen_with_rng::<PARAM256S, PARAMOWF256>(generate_rng()))
    });
    c.bench_function("Keygen em 128s", |b| {
        b.iter(|| faest::EmCypher::keygen_with_rng::<PARAM128SEM, PARAMOWF128EM>(generate_rng()))
    });
    c.bench_function("Keygen em 128f", |b| {
        b.iter(|| faest::EmCypher::keygen_with_rng::<PARAM128FEM, PARAMOWF128EM>(generate_rng()))
    });
    c.bench_function("Keygen em 192s", |b| {
        b.iter(|| faest::EmCypher::keygen_with_rng::<PARAM192SEM, PARAMOWF192EM>(generate_rng()))
    });
    c.bench_function("Keygen em 192f", |b| {
        b.iter(|| faest::EmCypher::keygen_with_rng::<PARAM192FEM, PARAMOWF192EM>(generate_rng()))
    });
    c.bench_function("Keygen em 256s", |b| {
        b.iter(|| faest::EmCypher::keygen_with_rng::<PARAM256SEM, PARAMOWF256EM>(generate_rng()))
    });
    c.bench_function("Keygen em 256f", |b| {
        b.iter(|| faest::EmCypher::keygen_with_rng::<PARAM256FEM, PARAMOWF256EM>(generate_rng()))
    });
    c.bench_function("Sign aes 128s", |b| {
        let input = generate_sign_input_aes::<AesCypher, PARAM128S, PARAMOWF128>();
        b.iter(|| bench_sign::<AesCypher, PARAM128S, PARAMOWF128>(input.clone()))
    });
    c.bench_function("Sign aes 128f", |b| {
        let input = generate_sign_input_aes::<AesCypher, PARAM128F, PARAMOWF128>();
        b.iter(|| bench_sign::<AesCypher, PARAM128F, PARAMOWF128>(input.clone()))
    });
    c.bench_function("Sign aes 192s", |b| {
        let input = generate_sign_input_aes::<AesCypher, PARAM192S, PARAMOWF192>();
        b.iter(|| bench_sign::<AesCypher, PARAM192S, PARAMOWF192>(input.clone()))
    });
    c.bench_function("Sign aes 192f", |b| {
        let input = generate_sign_input_aes::<AesCypher, PARAM192F, PARAMOWF192>();
        b.iter(|| bench_sign::<AesCypher, PARAM192F, PARAMOWF192>(input.clone()))
    });
    c.bench_function("Sign aes 256s", |b| {
        let input = generate_sign_input_aes::<AesCypher, PARAM256S, PARAMOWF256>();
        b.iter(|| bench_sign::<AesCypher, PARAM256S, PARAMOWF256>(input.clone()))
    });
    c.bench_function("Sign aes 256f", |b| {
        let input = generate_sign_input_aes::<AesCypher, PARAM256F, PARAMOWF256>();
        b.iter(|| bench_sign::<AesCypher, PARAM256F, PARAMOWF256>(input.clone()))
    });
    c.bench_function("Sign em 128s", |b| {
        let input = generate_sign_input_em::<EmCypher, PARAM128SEM, PARAMOWF128EM>();
        b.iter(|| bench_sign::<EmCypher, PARAM128SEM, PARAMOWF128EM>(input.clone()))
    });
    c.bench_function("Sign em 128f", |b| {
        let input = generate_sign_input_em::<EmCypher, PARAM128FEM, PARAMOWF128EM>();
        b.iter(|| bench_sign::<EmCypher, PARAM128FEM, PARAMOWF128EM>(input.clone()))
    });
    c.bench_function("Sign em 192s", |b| {
        let input = generate_sign_input_em::<EmCypher, PARAM192SEM, PARAMOWF192EM>();
        b.iter(|| bench_sign::<EmCypher, PARAM192SEM, PARAMOWF192EM>(input.clone()))
    });
    c.bench_function("Sign em 192f", |b| {
        let input = generate_sign_input_em::<EmCypher, PARAM192FEM, PARAMOWF192EM>();
        b.iter(|| bench_sign::<EmCypher, PARAM192FEM, PARAMOWF192EM>(input.clone()))
    });
    c.bench_function("Sign em 256s", |b| {
        let input = generate_sign_input_em::<EmCypher, PARAM256SEM, PARAMOWF256EM>();
        b.iter(|| bench_sign::<EmCypher, PARAM256SEM, PARAMOWF256EM>(input.clone()))
    });
    c.bench_function("Sign em 256f", |b| {
        let input = generate_sign_input_em::<EmCypher, PARAM256FEM, PARAMOWF256EM>();
        b.iter(|| bench_sign::<EmCypher, PARAM256FEM, PARAMOWF256EM>(input.clone()))
    });
    c.bench_function("Verify aes 128s", |b| {
        let input = generate_verify_input_aes::<AesCypher, PARAM128S, PARAMOWF128>();
        b.iter(|| bench_verify_aes::<AesCypher, PARAM128S, PARAMOWF128>(input.clone()))
    });
    c.bench_function("Verify aes 128f", |b| {
        let input = generate_verify_input_aes::<AesCypher, PARAM128F, PARAMOWF128>();
        b.iter(|| bench_verify_aes::<AesCypher, PARAM128F, PARAMOWF128>(input.clone()))
    });
    c.bench_function("Verify aes 192s", |b| {
        let input = generate_verify_input_aes::<AesCypher, PARAM192S, PARAMOWF192>();
        b.iter(|| bench_verify_aes::<AesCypher, PARAM192S, PARAMOWF192>(input.clone()))
    });
    c.bench_function("Verify aes 192f", |b| {
        let input = generate_verify_input_aes::<AesCypher, PARAM192F, PARAMOWF192>();
        b.iter(|| bench_verify_aes::<AesCypher, PARAM192F, PARAMOWF192>(input.clone()))
    });
    c.bench_function("Verify aes 256s", |b| {
        let input = generate_verify_input_aes::<AesCypher, PARAM256S, PARAMOWF256>();
        b.iter(|| bench_verify_aes::<AesCypher, PARAM256S, PARAMOWF256>(input.clone()))
    });
    c.bench_function("Verify aes 256f", |b| {
        let input = generate_verify_input_aes::<AesCypher, PARAM256F, PARAMOWF256>();
        b.iter(|| bench_verify_aes::<AesCypher, PARAM256F, PARAMOWF256>(input.clone()))
    });
    c.bench_function("Verify em 128s", |b| {
        let input = generate_verify_input_em::<EmCypher, PARAM128SEM, PARAMOWF128EM>();
        b.iter(|| bench_verify_em::<EmCypher, PARAM128SEM, PARAMOWF128EM>(input.clone()))
    });
    c.bench_function("Verify em 128f", |b| {
        let input = generate_verify_input_em::<EmCypher, PARAM128FEM, PARAMOWF128EM>();
        b.iter(|| bench_verify_em::<EmCypher, PARAM128FEM, PARAMOWF128EM>(input.clone()))
    });
    c.bench_function("Verify em 192s", |b| {
        let input = generate_verify_input_em::<EmCypher, PARAM192SEM, PARAMOWF192EM>();
        b.iter(|| bench_verify_em::<EmCypher, PARAM192SEM, PARAMOWF192EM>(input.clone()))
    });
    c.bench_function("Verify em 192f", |b| {
        let input = generate_verify_input_em::<EmCypher, PARAM192FEM, PARAMOWF192EM>();
        b.iter(|| bench_verify_em::<EmCypher, PARAM192FEM, PARAMOWF192EM>(input.clone()))
    });
    c.bench_function("Verify em 256s", |b| {
        let input = generate_verify_input_em::<EmCypher, PARAM256SEM, PARAMOWF256EM>();
        b.iter(|| bench_verify_em::<EmCypher, PARAM256SEM, PARAMOWF256EM>(input.clone()))
    });
    c.bench_function("Verify em 256f", |b| {
        let input = generate_verify_input_em::<EmCypher, PARAM256FEM, PARAMOWF256EM>();
        b.iter(|| bench_verify_em::<EmCypher, PARAM256FEM, PARAMOWF256EM>(input.clone()))
    });
}

criterion_group!(benches, faest_benchmark);
criterion_main!(benches);
