use cipher::Unsigned;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use faest::faest;
use ::faest::{faest::{faest_sign, faest_verify, AesCypher, EmCypher, Variant}, fields::{BigGaloisField, GF128, GF192, GF256}, parameter::{PARAM, PARAM128F, PARAM128FEM, PARAM128S, PARAM128SEM, PARAM192F, PARAM192FEM, PARAM192S, PARAM192SEM, PARAM256F, PARAM256FEM, PARAM256S, PARAM256SEM, PARAMOWF, PARAMOWF128, PARAMOWF128EM, PARAMOWF192, PARAMOWF192EM, PARAMOWF256, PARAMOWF256EM}, random_oracles::{RandomOracle, RandomOracleShake128, RandomOracleShake192, RandomOracleShake256}};
use nist_pqc_seeded_rng::NistPqcAes256CtrRng;
use rand::random;

fn generate_rng() -> NistPqcAes256CtrRng {
    let seed: [u8; 48] = [rand::random::<[u8; 32]>(), rand::random::<[u8; 32]>()].concat()[..48].try_into().unwrap();
    NistPqcAes256CtrRng::from(seed)
}

fn generate_sign_input_aes<C, P, O>() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) where P: PARAM, O:PARAMOWF, C:Variant{
    let rng = generate_rng();
    let (sk, pk, rho) = C::keygen_with_rng::<P, O>(rng);
    let length: u8 = random();
    let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
    (msg.to_vec(), sk[<O::BETA as Unsigned>::to_usize()* 16..].to_vec(), pk, rho[..<P::LAMBDA as Unsigned>::to_usize()/8].to_vec())
}

fn generate_sign_input_em<C, P, O>() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) where P: PARAM, O:PARAMOWF, C:Variant{
    let rng = generate_rng();
    let (sk, pk, rho) = C::keygen_with_rng::<P, O>(rng);
    let length: u8 = random();
    let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
    (msg.to_vec(), sk[<P::LAMBDA as Unsigned>::to_usize()/8..].to_vec(), pk, rho[..<P::LAMBDA as Unsigned>::to_usize()/8].to_vec())
}

fn bench_sign<T, R, C, P, O>(input : (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)) -> (
    Vec<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<(Vec<Vec<u8>>, Vec<u8>)>,
    Vec<u8>,
    [u8; 16],
) 
where
    T: BigGaloisField + std::default::Default + std::fmt::Debug,
    C: Variant,
    R: RandomOracle,
    P: PARAM,
    O: PARAMOWF,
{
    faest_sign::<T, R, C, P, O>(&input.0, &input.1, &input.2, input.3)
}

fn generate_verify_input_aes<T, R, C, P, O>() -> (Vec<u8>, Vec<u8>, (
    Vec<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<(Vec<Vec<u8>>, Vec<u8>)>,
    Vec<u8>,
    [u8; 16],
)) where T: BigGaloisField + std::default::Default + std::fmt::Debug, R: RandomOracle,
C: Variant, P: PARAM, O:PARAMOWF, C:Variant{
    let rng = generate_rng();
    let (sk, pk, rho) = C::keygen_with_rng::<P, O>(rng);
    let length: u8 = random();
    let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
    let sign = faest_sign::<T, R, C, P, O>(msg, &sk[<O::BETA as Unsigned>::to_usize() * 16..], &pk, rho[..<P::LAMBDA as Unsigned>::to_usize()/8].to_vec());
    (msg.to_vec(), pk, sign)
}

fn generate_verify_input_em<T, R, C, P, O>() -> (Vec<u8>, Vec<u8>, (
    Vec<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<(Vec<Vec<u8>>, Vec<u8>)>,
    Vec<u8>,
    [u8; 16],
)) where T: BigGaloisField + std::default::Default + std::fmt::Debug, R: RandomOracle,
C: Variant, P: PARAM, O:PARAMOWF, C:Variant{
    let rng = generate_rng();
    let (sk, pk, rho) = C::keygen_with_rng::<P, O>(rng);
    let length: u8 = random();
    let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
    let sign = faest_sign::<T, R, C, P, O>(msg, &sk[<P::LAMBDA as Unsigned>::to_usize()/8..], &pk, rho[..<P::LAMBDA as Unsigned>::to_usize()/8].to_vec());
    (msg.to_vec(), pk, sign)
}


fn becnh_verify_aes<T, R, C, P, O>(input: (Vec<u8>, Vec<u8>, (
    Vec<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<(Vec<Vec<u8>>, Vec<u8>)>,
    Vec<u8>,
    [u8; 16],
))) where
T: BigGaloisField + std::default::Default + std::fmt::Debug,
C: Variant,
R: RandomOracle,
P: PARAM,
O: PARAMOWF,{
    faest_verify::<T, R, C, P, O>(&input.0, (&input.1[..2*<O::BETA as Unsigned>::to_usize()], &input.1[2*<O::BETA as Unsigned>::to_usize()..]), input.2);
}

fn becnh_verify_em<T, R, C, P, O>(input: (Vec<u8>, Vec<u8>, (
    Vec<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<(Vec<Vec<u8>>, Vec<u8>)>,
    Vec<u8>,
    [u8; 16],
))) where
T: BigGaloisField + std::default::Default + std::fmt::Debug,
C: Variant,
R: RandomOracle,
P: PARAM,
O: PARAMOWF,{
    faest_verify::<T, R, C, P, O>(&input.0, (&input.1[..<P::LAMBDA as Unsigned>::to_usize()/8], &input.1[<P::LAMBDA as Unsigned>::to_usize()/8..]), input.2);
}


pub fn faest_benchmark(c : &mut Criterion) {
    c.bench_function("Keygen aes 128s", |b| b.iter(|| faest::AesCypher::keygen_with_rng::<PARAM128S, PARAMOWF128>(generate_rng())));
    c.bench_function("Keygen aes 128f", |b| b.iter(|| faest::AesCypher::keygen_with_rng::<PARAM128S, PARAMOWF128>(generate_rng())));
    c.bench_function("Keygen aes 192s", |b| b.iter(|| faest::AesCypher::keygen_with_rng::<PARAM192F, PARAMOWF192>(generate_rng())));
    c.bench_function("Keygen aes 192f", |b| b.iter(|| faest::AesCypher::keygen_with_rng::<PARAM192S, PARAMOWF192>(generate_rng())));
    c.bench_function("Keygen aes 256s", |b| b.iter(|| faest::AesCypher::keygen_with_rng::<PARAM256F, PARAMOWF256>(generate_rng())));
    c.bench_function("Keygen aes 256f", |b| b.iter(|| faest::AesCypher::keygen_with_rng::<PARAM256S, PARAMOWF256>(generate_rng())));
    c.bench_function("Keygen em 128s", |b| b.iter(|| faest::EmCypher::keygen_with_rng::<PARAM128SEM, PARAMOWF128EM>(generate_rng())));
    c.bench_function("Keygen em 128f", |b| b.iter(|| faest::EmCypher::keygen_with_rng::<PARAM128FEM, PARAMOWF128EM>(generate_rng())));
    c.bench_function("Keygen em 192s", |b| b.iter(|| faest::EmCypher::keygen_with_rng::<PARAM192SEM, PARAMOWF192EM>(generate_rng())));
    c.bench_function("Keygen em 192f", |b| b.iter(|| faest::EmCypher::keygen_with_rng::<PARAM192FEM, PARAMOWF192EM>(generate_rng())));
    c.bench_function("Keygen em 256s", |b| b.iter(|| faest::EmCypher::keygen_with_rng::<PARAM256SEM, PARAMOWF256EM>(generate_rng())));
    c.bench_function("Keygen em 256f", |b| b.iter(|| faest::EmCypher::keygen_with_rng::<PARAM256FEM, PARAMOWF256EM>(generate_rng())));
    c.bench_function("Sign aes 128s", |b| b.iter(|| bench_sign::<GF128, RandomOracleShake128, AesCypher, PARAM128S, PARAMOWF128>(generate_sign_input_aes::<AesCypher, PARAM128S, PARAMOWF128>())));
    c.bench_function("Sign aes 128f", |b| b.iter(|| bench_sign::<GF128, RandomOracleShake128, AesCypher, PARAM128F, PARAMOWF128>(generate_sign_input_aes::<AesCypher, PARAM128F, PARAMOWF128>())));
    c.bench_function("Sign aes 192s", |b| b.iter(|| bench_sign::<GF192, RandomOracleShake192, AesCypher, PARAM192S, PARAMOWF192>(generate_sign_input_aes::<AesCypher, PARAM192S, PARAMOWF192>())));
    c.bench_function("Sign aes 192f", |b| b.iter(|| bench_sign::<GF192, RandomOracleShake192, AesCypher, PARAM192F, PARAMOWF192>(generate_sign_input_aes::<AesCypher, PARAM192F, PARAMOWF192>())));
    c.bench_function("Sign aes 256s", |b| b.iter(|| bench_sign::<GF256, RandomOracleShake256, AesCypher, PARAM256S, PARAMOWF256>(generate_sign_input_aes::<AesCypher, PARAM256S, PARAMOWF256>())));
    c.bench_function("Sign aes 256f", |b| b.iter(|| bench_sign::<GF256, RandomOracleShake256, AesCypher, PARAM256F, PARAMOWF256>(generate_sign_input_aes::<AesCypher, PARAM256F, PARAMOWF256>())));
    c.bench_function("Sign em 128s", |b| b.iter(|| bench_sign::<GF128, RandomOracleShake128, EmCypher, PARAM128SEM, PARAMOWF128EM>(generate_sign_input_em::<EmCypher, PARAM128SEM, PARAMOWF128EM>())));
    c.bench_function("Sign em 128f", |b| b.iter(|| bench_sign::<GF128, RandomOracleShake128, EmCypher, PARAM128FEM, PARAMOWF128EM>(generate_sign_input_em::<EmCypher, PARAM128FEM, PARAMOWF128EM>())));
    c.bench_function("Sign em 192s", |b| b.iter(|| bench_sign::<GF192, RandomOracleShake192, EmCypher, PARAM192SEM, PARAMOWF192EM>(generate_sign_input_em::<EmCypher, PARAM192SEM, PARAMOWF192EM>())));
    c.bench_function("Sign em 192f", |b| b.iter(|| bench_sign::<GF192, RandomOracleShake192, EmCypher, PARAM192FEM, PARAMOWF192EM>(generate_sign_input_em::<EmCypher, PARAM192FEM, PARAMOWF192EM>())));
    c.bench_function("Sign em 256s", |b| b.iter(|| bench_sign::<GF256, RandomOracleShake256, EmCypher, PARAM256SEM, PARAMOWF256EM>(generate_sign_input_em::<EmCypher, PARAM256SEM, PARAMOWF256EM>())));
    c.bench_function("Sign em 256f", |b| b.iter(|| bench_sign::<GF256, RandomOracleShake256, EmCypher, PARAM256FEM, PARAMOWF256EM>(generate_sign_input_em::<EmCypher, PARAM256FEM, PARAMOWF256EM>())));
    c.bench_function("Verify aes 128s", |b| b.iter(|| becnh_verify_aes::<GF128, RandomOracleShake128, AesCypher, PARAM128S, PARAMOWF128>(generate_verify_input_aes::<GF128, RandomOracleShake128, AesCypher, PARAM128S, PARAMOWF128>())));
    c.bench_function("Verify aes 128f", |b| b.iter(|| becnh_verify_aes::<GF128, RandomOracleShake128, AesCypher, PARAM128F, PARAMOWF128>(generate_verify_input_aes::<GF128, RandomOracleShake128, AesCypher, PARAM128F, PARAMOWF128>())));
    c.bench_function("Verify aes 192s", |b| b.iter(|| becnh_verify_aes::<GF192, RandomOracleShake192, AesCypher, PARAM192S, PARAMOWF192>(generate_verify_input_aes::<GF192, RandomOracleShake192, AesCypher, PARAM192S, PARAMOWF192>())));
    c.bench_function("Verify aes 192f", |b| b.iter(|| becnh_verify_aes::<GF192, RandomOracleShake192, AesCypher, PARAM192F, PARAMOWF192>(generate_verify_input_aes::<GF192, RandomOracleShake192, AesCypher, PARAM192F, PARAMOWF192>())));
    c.bench_function("Verify aes 256s", |b| b.iter(|| becnh_verify_aes::<GF256, RandomOracleShake256, AesCypher, PARAM256S, PARAMOWF256>(generate_verify_input_aes::<GF256, RandomOracleShake256, AesCypher, PARAM256S, PARAMOWF256>())));
    c.bench_function("Verify aes 256f", |b| b.iter(|| becnh_verify_aes::<GF256, RandomOracleShake256, AesCypher, PARAM256F, PARAMOWF256>(generate_verify_input_aes::<GF256, RandomOracleShake256, AesCypher, PARAM256F, PARAMOWF256>())));
    c.bench_function("Verify em 128s", |b| b.iter(|| becnh_verify_em::<GF128, RandomOracleShake128, EmCypher, PARAM128SEM, PARAMOWF128EM>(generate_verify_input_em::<GF128, RandomOracleShake128, EmCypher, PARAM128SEM, PARAMOWF128EM>())));
    c.bench_function("Verify em 128f", |b| b.iter(|| becnh_verify_em::<GF128, RandomOracleShake128, EmCypher, PARAM128FEM, PARAMOWF128EM>(generate_verify_input_em::<GF128, RandomOracleShake128, EmCypher, PARAM128FEM, PARAMOWF128EM>())));
    c.bench_function("Verify em 192s", |b| b.iter(|| becnh_verify_em::<GF192, RandomOracleShake192, EmCypher, PARAM192SEM, PARAMOWF192EM>(generate_verify_input_em::<GF192, RandomOracleShake192, EmCypher, PARAM192SEM, PARAMOWF192EM>())));
    c.bench_function("Verify em 192f", |b| b.iter(|| becnh_verify_em::<GF192, RandomOracleShake192, EmCypher, PARAM192FEM, PARAMOWF192EM>(generate_verify_input_em::<GF192, RandomOracleShake192, EmCypher, PARAM192FEM, PARAMOWF192EM>())));
    c.bench_function("Verify em 256s", |b| b.iter(|| becnh_verify_em::<GF256, RandomOracleShake256, EmCypher, PARAM256SEM, PARAMOWF256EM>(generate_verify_input_em::<GF256, RandomOracleShake256, EmCypher, PARAM256SEM, PARAMOWF256EM>())));
    c.bench_function("Verify em 256f", |b| b.iter(|| becnh_verify_em::<GF256, RandomOracleShake256, EmCypher, PARAM256FEM, PARAMOWF256EM>(generate_verify_input_em::<GF256, RandomOracleShake256, EmCypher, PARAM256FEM, PARAMOWF256EM>())));








}

criterion_group!(benches, faest_benchmark);
criterion_main!(benches);
