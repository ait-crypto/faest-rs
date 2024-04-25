use faest::fields::{BigGaloisField, GF128};
use faest::random_oracles::RandomOracleShake128;
use rand::random;

#[test]
fn test_commitment_and_decomitment() {
    //for GF128
    for _i in 0..100 {
        let iv: u8 = random();
        let n = 2u32.pow(8);
        let r = faest::fields::GF128::rand();
        let (com, decom, _sd) = faest::vc::commit::<GF128, RandomOracleShake128>(r, iv, n);
        let mut b_val: Vec<u8> = vec![random()];
        b_val.append(&mut vec![0u8, 0u8, 0u8]);
        let pdecom = faest::vc::open(decom, b_val.clone());
        let res = faest::vc::verify::<GF128, RandomOracleShake128>(com, pdecom, b_val, iv);
        assert_eq!(res, 1);
    }
}
