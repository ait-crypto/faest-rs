use ::faest::{
    faest::{faest_sign, faest_verify, sigma_to_signature},
    parameter::{
        self, PARAM, PARAM128F, PARAM128FEM, PARAM128S, PARAM128SEM, PARAM192F, PARAM192FEM,
        PARAM192S, PARAM192SEM, PARAM256F, PARAM256FEM, PARAM256S, PARAM256SEM, PARAMOWF,
        PARAMOWF128, PARAMOWF128EM, PARAMOWF192, PARAMOWF192EM, PARAMOWF256, PARAMOWF256EM,
    },
};
use cipher::Unsigned;
use criterion::{criterion_group, criterion_main, Criterion};
use generic_array::GenericArray;
use nist_pqc_seeded_rng::NistPqcAes256CtrRng;
use parameter::{AesCypher, EmCypher, Variant};
use rand::random;

type Signature<P> = GenericArray<u8, <P as PARAM>::SIG>;

type KeyInput<O> = (
    Vec<u8>,
    GenericArray<u8, <O as PARAMOWF>::LAMBDABYTES>,
    GenericArray<u8, <O as PARAMOWF>::PK>,
    GenericArray<u8, <O as PARAMOWF>::LAMBDABYTES>,
);

/* type Key<O> = (
    GenericArray<u8, <O as PARAMOWF>::PK>,
    Box<GenericArray<u8, <O as PARAMOWF>::PK>>,
); */

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
    C: Variant<O>,
{
    let rng = generate_rng();
    let (sk, pk) = C::keygen_with_rng::<P>(rng);
    let rho: [u8; 32] = random();
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
        (*GenericArray::from_slice(&rho[..<O::LAMBDABYTES as Unsigned>::to_usize()])).clone(),
    )
}

fn generate_sign_input_em<C, P, O>() -> KeyInput<O>
where
    P: PARAM,
    O: PARAMOWF
        + PARAMOWF<LAMBDABYTES = P::LAMBDABYTES>
        + PARAMOWF<PK = <<P as parameter::PARAM>::OWF as PARAMOWF>::PK>
        + PARAMOWF<LAMBDA = P::LAMBDA>
        + PARAMOWF<CHALL = <<P as parameter::PARAM>::OWF as PARAMOWF>::CHALL>
        + PARAMOWF<LAMBDALBYTES = <<P as parameter::PARAM>::OWF as PARAMOWF>::LAMBDALBYTES>,

    C: Variant<O>,
{
    let rng = generate_rng();
    let (sk, pk) = C::keygen_with_rng::<P>(rng);
    let rho: [u8; 32] = random();
    let length: u8 = random();
    let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
    (
        msg.to_vec(),
        (*GenericArray::from_slice(&sk[<P::LAMBDA as Unsigned>::to_usize() / 8..])).clone(),
        (*GenericArray::from_slice(&pk)).clone(),
        (*GenericArray::from_slice(&rho[..<P::LAMBDA as Unsigned>::to_usize() / 8])).clone(),
    )
}

fn bench_sign<C, P, O>(input: KeyInput<O>) -> Signature<P>
where
    P: PARAM,
    O: PARAMOWF
        + PARAMOWF<LAMBDABYTES = P::LAMBDABYTES>
        + PARAMOWF<PK = <<P as parameter::PARAM>::OWF as PARAMOWF>::PK>
        + PARAMOWF<LAMBDA = P::LAMBDA>
        + PARAMOWF<CHALL = <<P as parameter::PARAM>::OWF as PARAMOWF>::CHALL>
        + PARAMOWF<LAMBDALBYTES = <<P as parameter::PARAM>::OWF as PARAMOWF>::LAMBDALBYTES>,

    C: Variant<O>,
{
    sigma_to_signature::<P, O>(faest_sign::<P, O>(&input.0, &input.1, &input.2, &input.3))
}

fn generate_verify_input_aes<C, P, O>() -> (Vec<u8>, GenericArray<u8, O::PK>, Signature<P>)
where
    P: PARAM,
    O: PARAMOWF
        + PARAMOWF<LAMBDABYTES = P::LAMBDABYTES>
        + PARAMOWF<PK = <<P as parameter::PARAM>::OWF as PARAMOWF>::PK>
        + PARAMOWF<LAMBDA = P::LAMBDA>
        + PARAMOWF<CHALL = <<P as parameter::PARAM>::OWF as PARAMOWF>::CHALL>
        + PARAMOWF<LAMBDALBYTES = <<P as parameter::PARAM>::OWF as PARAMOWF>::LAMBDALBYTES>,

    C: Variant<O>,
{
    let rng = generate_rng();
    let (sk, pk) = C::keygen_with_rng::<P>(rng);
    let rho: [u8; 32] = random();
    let length: u8 = random();
    let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
    let sign = faest_sign::<P, O>(
        msg,
        GenericArray::from_slice(
            &sk[<O::PK as Unsigned>::to_usize() - <O::LAMBDABYTES as Unsigned>::to_usize()..],
        ),
        GenericArray::from_slice(&pk),
        &rho[..<O::LAMBDABYTES as Unsigned>::to_usize()],
    );
    (msg.to_vec(), *pk, sigma_to_signature::<P, O>(sign))
}

fn generate_verify_input_em<C, P, O>() -> (Vec<u8>, GenericArray<u8, O::PK>, Signature<P>)
where
    P: PARAM,
    O: PARAMOWF
        + PARAMOWF<LAMBDABYTES = P::LAMBDABYTES>
        + PARAMOWF<PK = <<P as parameter::PARAM>::OWF as PARAMOWF>::PK>
        + PARAMOWF<LAMBDA = P::LAMBDA>
        + PARAMOWF<CHALL = <<P as parameter::PARAM>::OWF as PARAMOWF>::CHALL>
        + PARAMOWF<LAMBDALBYTES = <<P as parameter::PARAM>::OWF as PARAMOWF>::LAMBDALBYTES>,

    C: Variant<O>,
{
    let rng = generate_rng();
    let (sk, pk) = C::keygen_with_rng::<P>(rng);
    let rho: [u8; 32] = random();
    let length: u8 = random();
    let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
    let sign = faest_sign::<P, O>(
        msg,
        GenericArray::from_slice(&sk[<P::LAMBDA as Unsigned>::to_usize() / 8..]),
        GenericArray::from_slice(&pk),
        &rho[..<P::LAMBDA as Unsigned>::to_usize() / 8],
    );
    (
        msg.to_vec(),
        (*GenericArray::from_slice(&pk)).clone(),
        sigma_to_signature::<P, O>(sign),
    )
}

fn bench_verify_aes<C, P, O>(input: (Vec<u8>, GenericArray<u8, O::PK>, Signature<P>))
where
    P: PARAM,
    O: PARAMOWF
        + PARAMOWF<LAMBDABYTES = P::LAMBDABYTES>
        + PARAMOWF<PK = <<P as parameter::PARAM>::OWF as PARAMOWF>::PK>
        + PARAMOWF<LAMBDA = P::LAMBDA>
        + PARAMOWF<CHALL = <<P as parameter::PARAM>::OWF as PARAMOWF>::CHALL>
        + PARAMOWF<LAMBDALBYTES = <<P as parameter::PARAM>::OWF as PARAMOWF>::LAMBDALBYTES>,

    C: Variant<O>,
{
    faest_verify::<P, O>(&input.0, input.1, &input.2);
}

fn bench_verify_em<C, P, O>(input: (Vec<u8>, GenericArray<u8, O::PK>, Signature<P>))
where
    P: PARAM,
    O: PARAMOWF
        + PARAMOWF<LAMBDABYTES = P::LAMBDABYTES>
        + PARAMOWF<PK = <<P as parameter::PARAM>::OWF as PARAMOWF>::PK>
        + PARAMOWF<LAMBDA = P::LAMBDA>
        + PARAMOWF<CHALL = <<P as parameter::PARAM>::OWF as PARAMOWF>::CHALL>
        + PARAMOWF<LAMBDALBYTES = <<P as parameter::PARAM>::OWF as PARAMOWF>::LAMBDALBYTES>,

    C: Variant<O>,
{
    faest_verify::<P, O>(&input.0, input.1, &input.2);
}

pub fn faest_benchmark(c: &mut Criterion) {
    c.bench_function("Keygen aes 128s", |b| {
        b.iter(|| {
            <crate::parameter::PARAM128S as PARAM>::Cypher::keygen_with_rng::<PARAM128S>(
                generate_rng(),
            )
        })
    });
    c.bench_function("Keygen aes 128f", |b| {
        b.iter(|| {
            <crate::parameter::PARAM128F as PARAM>::Cypher::keygen_with_rng::<PARAM128F>(
                generate_rng(),
            )
        })
    });
    c.bench_function("Keygen aes 192s", |b| {
        b.iter(|| {
            <crate::parameter::PARAM192S as PARAM>::Cypher::keygen_with_rng::<PARAM192S>(
                generate_rng(),
            )
        })
    });
    c.bench_function("Keygen aes 192f", |b| {
        b.iter(|| {
            <crate::parameter::PARAM192F as PARAM>::Cypher::keygen_with_rng::<PARAM192F>(
                generate_rng(),
            )
        })
    });
    c.bench_function("Keygen aes 256s", |b| {
        b.iter(|| {
            <crate::parameter::PARAM256S as PARAM>::Cypher::keygen_with_rng::<PARAM256S>(
                generate_rng(),
            )
        })
    });
    c.bench_function("Keygen aes 256f", |b| {
        b.iter(|| {
            <crate::parameter::PARAM256F as PARAM>::Cypher::keygen_with_rng::<PARAM256F>(
                generate_rng(),
            )
        })
    });
    c.bench_function("Keygen em 128s", |b| {
        b.iter(|| {
            <crate::parameter::PARAM128SEM as PARAM>::Cypher::keygen_with_rng::<PARAM128SEM>(
                generate_rng(),
            )
        })
    });
    c.bench_function("Keygen em 128f", |b| {
        b.iter(|| {
            <crate::parameter::PARAM128FEM as PARAM>::Cypher::keygen_with_rng::<PARAM128FEM>(
                generate_rng(),
            )
        })
    });
    c.bench_function("Keygen em 192s", |b| {
        b.iter(|| {
            <crate::parameter::PARAM192SEM as PARAM>::Cypher::keygen_with_rng::<PARAM192SEM>(
                generate_rng(),
            )
        })
    });
    c.bench_function("Keygen em 192f", |b| {
        b.iter(|| {
            <crate::parameter::PARAM192FEM as PARAM>::Cypher::keygen_with_rng::<PARAM192FEM>(
                generate_rng(),
            )
        })
    });
    c.bench_function("Keygen em 256s", |b| {
        b.iter(|| {
            <crate::parameter::PARAM256SEM as PARAM>::Cypher::keygen_with_rng::<PARAM256SEM>(
                generate_rng(),
            )
        })
    });
    c.bench_function("Keygen em 256f", |b| {
        b.iter(|| {
            <crate::parameter::PARAM256FEM as PARAM>::Cypher::keygen_with_rng::<PARAM256FEM>(
                generate_rng(),
            )
        })
    });
    c.bench_function("Sign aes 128s", |b| {
        let input = generate_sign_input_aes::<AesCypher<PARAMOWF128>, PARAM128S, PARAMOWF128>();
        b.iter(|| bench_sign::<AesCypher<PARAMOWF128>, PARAM128S, PARAMOWF128>(input.clone()))
    });
    c.bench_function("Sign aes 128f", |b| {
        let input = generate_sign_input_aes::<AesCypher<PARAMOWF128>, PARAM128F, PARAMOWF128>();
        b.iter(|| bench_sign::<AesCypher<PARAMOWF128>, PARAM128F, PARAMOWF128>(input.clone()))
    });
    c.bench_function("Sign aes 192s", |b| {
        let input = generate_sign_input_aes::<AesCypher<PARAMOWF192>, PARAM192S, PARAMOWF192>();
        b.iter(|| bench_sign::<AesCypher<PARAMOWF192>, PARAM192S, PARAMOWF192>(input.clone()))
    });
    c.bench_function("Sign aes 192f", |b| {
        let input = generate_sign_input_aes::<AesCypher<PARAMOWF192>, PARAM192F, PARAMOWF192>();
        b.iter(|| bench_sign::<AesCypher<PARAMOWF192>, PARAM192F, PARAMOWF192>(input.clone()))
    });
    c.bench_function("Sign aes 256s", |b| {
        let input = generate_sign_input_aes::<AesCypher<PARAMOWF256>, PARAM256S, PARAMOWF256>();
        b.iter(|| bench_sign::<AesCypher<PARAMOWF256>, PARAM256S, PARAMOWF256>(input.clone()))
    });
    c.bench_function("Sign aes 256f", |b| {
        let input = generate_sign_input_aes::<AesCypher<PARAMOWF256>, PARAM256F, PARAMOWF256>();
        b.iter(|| bench_sign::<AesCypher<PARAMOWF256>, PARAM256F, PARAMOWF256>(input.clone()))
    });
    c.bench_function("Sign em 128s", |b| {
        let input = generate_sign_input_em::<EmCypher<PARAMOWF128EM>, PARAM128SEM, PARAMOWF128EM>();
        b.iter(|| bench_sign::<EmCypher<PARAMOWF128EM>, PARAM128SEM, PARAMOWF128EM>(input.clone()))
    });
    c.bench_function("Sign em 128f", |b| {
        let input = generate_sign_input_em::<EmCypher<PARAMOWF128EM>, PARAM128FEM, PARAMOWF128EM>();
        b.iter(|| bench_sign::<EmCypher<PARAMOWF128EM>, PARAM128FEM, PARAMOWF128EM>(input.clone()))
    });
    c.bench_function("Sign em 192s", |b| {
        let input = generate_sign_input_em::<EmCypher<PARAMOWF192EM>, PARAM192SEM, PARAMOWF192EM>();
        b.iter(|| bench_sign::<EmCypher<PARAMOWF192EM>, PARAM192SEM, PARAMOWF192EM>(input.clone()))
    });
    c.bench_function("Sign em 192f", |b| {
        let input = generate_sign_input_em::<EmCypher<PARAMOWF192EM>, PARAM192FEM, PARAMOWF192EM>();
        b.iter(|| bench_sign::<EmCypher<PARAMOWF192EM>, PARAM192FEM, PARAMOWF192EM>(input.clone()))
    });
    c.bench_function("Sign em 256s", |b| {
        let input = generate_sign_input_em::<EmCypher<PARAMOWF256EM>, PARAM256SEM, PARAMOWF256EM>();
        b.iter(|| bench_sign::<EmCypher<PARAMOWF256EM>, PARAM256SEM, PARAMOWF256EM>(input.clone()))
    });
    c.bench_function("Sign em 256f", |b| {
        let input = generate_sign_input_em::<EmCypher<PARAMOWF256EM>, PARAM256FEM, PARAMOWF256EM>();
        b.iter(|| bench_sign::<EmCypher<PARAMOWF256EM>, PARAM256FEM, PARAMOWF256EM>(input.clone()))
    });
    c.bench_function("Verify aes 128s", |b| {
        let input = generate_verify_input_aes::<AesCypher<PARAMOWF128>, PARAM128S, PARAMOWF128>();
        b.iter(|| bench_verify_aes::<AesCypher<PARAMOWF128>, PARAM128S, PARAMOWF128>(input.clone()))
    });
    c.bench_function("Verify aes 128f", |b| {
        let input = generate_verify_input_aes::<AesCypher<PARAMOWF128>, PARAM128F, PARAMOWF128>();
        b.iter(|| bench_verify_aes::<AesCypher<PARAMOWF128>, PARAM128F, PARAMOWF128>(input.clone()))
    });
    c.bench_function("Verify aes 192s", |b| {
        let input = generate_verify_input_aes::<AesCypher<PARAMOWF192>, PARAM192S, PARAMOWF192>();
        b.iter(|| bench_verify_aes::<AesCypher<PARAMOWF192>, PARAM192S, PARAMOWF192>(input.clone()))
    });
    c.bench_function("Verify aes 192f", |b| {
        let input = generate_verify_input_aes::<AesCypher<PARAMOWF192>, PARAM192F, PARAMOWF192>();
        b.iter(|| bench_verify_aes::<AesCypher<PARAMOWF192>, PARAM192F, PARAMOWF192>(input.clone()))
    });
    c.bench_function("Verify aes 256s", |b| {
        let input = generate_verify_input_aes::<AesCypher<PARAMOWF256>, PARAM256S, PARAMOWF256>();
        b.iter(|| bench_verify_aes::<AesCypher<PARAMOWF256>, PARAM256S, PARAMOWF256>(input.clone()))
    });
    c.bench_function("Verify aes 256f", |b| {
        let input = generate_verify_input_aes::<AesCypher<PARAMOWF256>, PARAM256F, PARAMOWF256>();
        b.iter(|| bench_verify_aes::<AesCypher<PARAMOWF256>, PARAM256F, PARAMOWF256>(input.clone()))
    });
    c.bench_function("Verify em 128s", |b| {
        let input =
            generate_verify_input_em::<EmCypher<PARAMOWF128EM>, PARAM128SEM, PARAMOWF128EM>();
        b.iter(|| {
            bench_verify_em::<EmCypher<PARAMOWF128EM>, PARAM128SEM, PARAMOWF128EM>(input.clone())
        })
    });
    c.bench_function("Verify em 128f", |b| {
        let input =
            generate_verify_input_em::<EmCypher<PARAMOWF128EM>, PARAM128FEM, PARAMOWF128EM>();
        b.iter(|| {
            bench_verify_em::<EmCypher<PARAMOWF128EM>, PARAM128FEM, PARAMOWF128EM>(input.clone())
        })
    });
    c.bench_function("Verify em 192s", |b| {
        let input =
            generate_verify_input_em::<EmCypher<PARAMOWF192EM>, PARAM192SEM, PARAMOWF192EM>();
        b.iter(|| {
            bench_verify_em::<EmCypher<PARAMOWF192EM>, PARAM192SEM, PARAMOWF192EM>(input.clone())
        })
    });
    c.bench_function("Verify em 192f", |b| {
        let input =
            generate_verify_input_em::<EmCypher<PARAMOWF192EM>, PARAM192FEM, PARAMOWF192EM>();
        b.iter(|| {
            bench_verify_em::<EmCypher<PARAMOWF192EM>, PARAM192FEM, PARAMOWF192EM>(input.clone())
        })
    });
    c.bench_function("Verify em 256s", |b| {
        let input =
            generate_verify_input_em::<EmCypher<PARAMOWF256EM>, PARAM256SEM, PARAMOWF256EM>();
        b.iter(|| {
            bench_verify_em::<EmCypher<PARAMOWF256EM>, PARAM256SEM, PARAMOWF256EM>(input.clone())
        })
    });
    c.bench_function("Verify em 256f", |b| {
        let input =
            generate_verify_input_em::<EmCypher<PARAMOWF256EM>, PARAM256FEM, PARAMOWF256EM>();
        b.iter(|| {
            bench_verify_em::<EmCypher<PARAMOWF256EM>, PARAM256FEM, PARAMOWF256EM>(input.clone())
        })
    });
}

criterion_group!(benches, faest_benchmark);
criterion_main!(benches);
