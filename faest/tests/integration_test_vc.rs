use faest::fields::{BigGaloisField, GF128, GF192, GF256};
use faest::prg::{prg_128, prg_192, prg_256};
use faest::random_oracles::{RandomOracleShake128, RandomOracleShake256};
use rand::random;

#[test]
fn test_commitment_and_decomitment() {
    //for GF128
    for _i in 0..100 {
        let iv: u128 = random();
        let n = 2u32.pow(8);
        let r = faest::fields::GF128::rand();
        let (com, decom, _sd) =
            faest::vc::commit::<GF128, RandomOracleShake128>(r, iv, n, &prg_128);
        let mut b: Vec<u8> = vec![];
        for _i in 0..8 {
            b.append(&mut vec![random::<u8>() & 1]);
        }
        let pdecom = faest::vc::open(&decom, b.clone());
        let res = faest::vc::verify::<GF128, RandomOracleShake128>(com, pdecom, b, iv, &prg_128);
        assert_eq!(res, 1);
    }
    //for GF192
    for _i in 0..100 {
        let iv: u128 = random();
        let n = 2u32.pow(8);
        let r = faest::fields::GF192::rand();
        let (com, decom, _sd) =
            faest::vc::commit::<GF192, RandomOracleShake256>(r, iv, n, &prg_192);
        let mut b: Vec<u8> = vec![];
        for _i in 0..8 {
            b.append(&mut vec![random::<u8>() & 1]);
        }
        let pdecom = faest::vc::open(&decom, b.clone());
        let res = faest::vc::verify::<GF192, RandomOracleShake256>(com, pdecom, b, iv, &prg_192);
        assert_eq!(res, 1);
    }
    //for GF256
    for _i in 0..100 {
        let iv: u128 = random();
        let n = 2u32.pow(8);
        let r = faest::fields::GF256::rand();
        let (com, decom, _sd) =
            faest::vc::commit::<GF256, RandomOracleShake256>(r, iv, n, &prg_256);
        let mut b: Vec<u8> = vec![];
        for _i in 0..8 {
            b.append(&mut vec![random::<u8>() & 1]);
        }
        let pdecom = faest::vc::open(&decom, b.clone());
        let res = faest::vc::verify::<GF256, RandomOracleShake256>(com, pdecom, b, iv, &prg_256);
        assert_eq!(res, 1);
    }
}
