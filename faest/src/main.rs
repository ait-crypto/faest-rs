use cipher::Unsigned;
//use faest::{faest::{faest_sign, faest_verify, AesCypher, Variant}, fields::{BigGaloisField, GF128}, parameter::{PARAM, PARAM128S, PARAMOWF, PARAMOWF128}, random_oracles::{RandomOracle, RandomOracleShake128}};
use nist_pqc_seeded_rng::NistPqcAes256CtrRng;
use rand::random;

mod fields;

fn main() {
    //let _ = bench_sign::<GF128, RandomOracleShake128, AesCypher, PARAM128S, PARAMOWF128>(generate_sign_input_aes::<AesCypher, PARAM128S, PARAMOWF128>());
    //let res = bench_verify_aes::<GF128, RandomOracleShake128, AesCypher, PARAM128S, PARAMOWF128>(generate_verify_input_aes::<GF128, RandomOracleShake128, AesCypher, PARAM128S, PARAMOWF128>());

}


fn generate_rng() -> NistPqcAes256CtrRng {
    let seed: [u8; 48] = [rand::random::<[u8; 32]>(), rand::random::<[u8; 32]>()].concat()[..48].try_into().unwrap();
    NistPqcAes256CtrRng::from(seed)
}

/* fn generate_sign_input_aes<C, P, O>() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) where P: PARAM, O:PARAMOWF, C:Variant{
    let rng = generate_rng();
    let (sk, pk, rho) = C::keygen_with_rng::<P, O>(rng);
    let length: u8 = random();
    let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
    (msg.to_vec(), sk[<O::BETA as Unsigned>::to_usize() * 16..].to_vec(), pk, rho[..<P::LAMBDA as Unsigned>::to_usize()/8].to_vec())
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


fn bench_verify_aes<T, R, C, P, O>(input: (Vec<u8>, Vec<u8>, (
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
} */