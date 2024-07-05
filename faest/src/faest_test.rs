use std::{fs::File, iter::zip};

use rand::random;
use serde::Deserialize;

#[cfg(test)]
use crate::parameter::Param;
use crate::{
    aes::aes_extendedwitness,
    faest::{faest_sign, faest_verify, keygen, AesCypher, EmCypher, Variant},
    fields::{GF128, GF192, GF256},
    parameter::{
        ParamOWF, PARAM128F, PARAM128S, PARAM192F, PARAM192S, PARAM256F, PARAM256S, PARAMOWF128,
        PARAMOWF128EM, PARAMOWF192, PARAMOWF192EM, PARAMOWF256, PARAMOWF256EM,
    },
    prg::{prg_128, prg_192, prg_256},
    random_oracles::{RandomOracleShake128, RandomOracleShake256},
};

#[test]
fn keygen_test() {
    //128-s-aes
    for i in 0..500 {
        let param = PARAM128S;
        let paramowf = PARAMOWF128;
        let (sk, pk) = keygen::<AesCypher>(&param, &paramowf);
        let mut w = AesCypher::witness(&sk, &pk.0, &param, &paramowf);
        for elem in &mut w[paramowf.get_nk() as usize..] {
            if (*elem & 255) == 0 {
                assert_eq!(true, false);
            }
        }
    }
    //128-f-aes
    for i in 0..500 {
        let param = PARAM128F;
        let paramowf = PARAMOWF128;
        let (sk, pk) = keygen::<AesCypher>(&param, &paramowf);
        let mut w = AesCypher::witness(&sk, &pk.0, &param, &paramowf);
        for elem in &mut w[paramowf.get_nk() as usize..] {
            if (*elem & 255) == 0 {
                assert_eq!(true, false);
            }
        }
    }
    //192-s-aes
    for i in 0..500 {
        let param = PARAM192S;
        let paramowf = PARAMOWF192;
        let (sk, pk) = keygen::<AesCypher>(&param, &paramowf);
        let mut w = AesCypher::witness(&sk, &pk.0, &param, &paramowf);
        for elem in &mut w[paramowf.get_nk() as usize..] {
            if (*elem & 255) == 0 {
                assert_eq!(true, false);
            }
        }
    }
    //192-f-aes
    for i in 0..500 {
        let param = PARAM192F;
        let paramowf = PARAMOWF192;
        let (sk, pk) = keygen::<AesCypher>(&param, &paramowf);
        let mut w = AesCypher::witness(&sk, &pk.0, &param, &paramowf);
        for elem in &mut w[paramowf.get_nk() as usize..] {
            if (*elem & 255) == 0 {
                assert_eq!(true, false);
            }
        }
    }
    //256-s-aes
    for i in 0..500 {
        let param = PARAM256S;
        let paramowf = PARAMOWF256;
        let (sk, pk) = keygen::<AesCypher>(&param, &paramowf);
        let mut w = AesCypher::witness(&sk, &pk.0, &param, &paramowf);
        for elem in &mut w[paramowf.get_nk() as usize..] {
            if (*elem & 255) == 0 {
                assert_eq!(true, false);
            }
        }
    }
    //256-f-aes
    for i in 0..500 {
        let param = PARAM256F;
        let paramowf = PARAMOWF256;
        let (sk, pk) = keygen::<AesCypher>(&param, &paramowf);
        let mut w = AesCypher::witness(&sk, &pk.0, &param, &paramowf);
        for elem in &mut w[paramowf.get_nk() as usize..] {
            if (*elem & 255) == 0 {
                assert_eq!(true, false);
            }
        }
    }
}

#[test]
fn faest_aes_test() {
    //128-s
    for i in 0..500 {
        let param = Param::set_param(128, 1600, 11, 12, 11, 7, 4, 16, 1);
        let paramowf = ParamOWF::set_paramowf(4, 10, 40, 160, 1600, 448, 1152, 1, 200, None);
        let (sk, pk) = keygen::<AesCypher>(&param, &paramowf);
        let length: u8 = random();
        let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
        let sigma = faest_sign::<GF128, RandomOracleShake128, AesCypher>(
            msg,
            &sk,
            &[pk.0.clone(), pk.1.clone()].concat(),
            &prg_128,
            &param,
            &paramowf,
        );
        let res_true = faest_verify::<GF128, RandomOracleShake128, AesCypher>(
            msg,
            (&pk.0, &pk.1),
            sigma.clone(),
            &prg_128,
            &param,
            &paramowf,
        );
        /* let mut msg_false = msg.to_vec().clone();
        msg_false = msg_false.iter().map(|x| x.wrapping_add(1)).collect::<Vec<u8>>();
        let res_false = faest_verify::<GF128, RandomOracleShake128>(&msg_false, (&pk.0, &pk.1), sigma, &prg_128, &param, &paramowf); */
        assert!(res_true);
        //assert!(!res_false);
    }

    //128-f
    for i in 0..500 {
        let param = Param::set_param(128, 1600, 16, 8, 8, 8, 8, 16, 1);
        let paramowf = ParamOWF::set_paramowf(4, 10, 40, 160, 1600, 448, 1152, 1, 200, None);
        let (sk, pk) = keygen::<AesCypher>(&param, &paramowf);
        let length: u8 = random();
        let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
        let sigma = faest_sign::<GF128, RandomOracleShake128, AesCypher>(
            msg,
            &sk,
            &[pk.0.clone(), pk.1.clone()].concat(),
            &prg_128,
            &param,
            &paramowf,
        );
        let res_true = faest_verify::<GF128, RandomOracleShake128, AesCypher>(
            msg,
            (&pk.0, &pk.1),
            sigma.clone(),
            &prg_128,
            &param,
            &paramowf,
        );
        let mut msg_false = msg.to_vec().clone();
        msg_false = msg_false
            .iter()
            .map(|x| x.wrapping_add(1))
            .collect::<Vec<u8>>();
        let res_false = faest_verify::<GF128, RandomOracleShake128, AesCypher>(
            &msg_false,
            (&pk.0, &pk.1),
            sigma,
            &prg_128,
            &param,
            &paramowf,
        );
        assert!(res_true);
        //assert!(!res_false);
    }

    //192-s
    for i in 0..500 {
        let param = Param::set_param(192, 3264, 16, 12, 12, 8, 8, 16, 2);
        let paramowf = ParamOWF::set_paramowf(6, 12, 32, 192, 3264, 448, 1408, 2, 416, None);
        let (sk, pk) = keygen::<AesCypher>(&param, &paramowf);
        let length: u8 = random();
        let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
        let sigma = faest_sign::<GF192, RandomOracleShake256, AesCypher>(
            msg,
            &sk,
            &[pk.0.clone(), pk.1.clone()].concat(),
            &prg_192,
            &param,
            &paramowf,
        );
        let res_true = faest_verify::<GF192, RandomOracleShake256, AesCypher>(
            msg,
            (&pk.0, &pk.1),
            sigma.clone(),
            &prg_192,
            &param,
            &paramowf,
        );
        let mut msg_false = msg.to_vec().clone();
        msg_false = msg_false
            .iter()
            .map(|x| x.wrapping_add(1))
            .collect::<Vec<u8>>();
        let res_false = faest_verify::<GF192, RandomOracleShake256, AesCypher>(
            &msg_false,
            (&pk.0, &pk.1),
            sigma,
            &prg_192,
            &param,
            &paramowf,
        );
        assert!(res_true);
        //assert!(!res_false);
    }

    //192-f
    for i in 0..500 {
        let param = Param::set_param(192, 3264, 24, 8, 8, 12, 12, 16, 2);
        let paramowf = ParamOWF::set_paramowf(6, 12, 32, 192, 3264, 448, 1408, 2, 416, None);
        let (sk, pk) = keygen::<AesCypher>(&param, &paramowf);
        let length: u8 = random();
        let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
        let sigma = faest_sign::<GF192, RandomOracleShake256, AesCypher>(
            msg,
            &sk,
            &[pk.0.clone(), pk.1.clone()].concat(),
            &prg_192,
            &param,
            &paramowf,
        );
        let res_true = faest_verify::<GF192, RandomOracleShake256, AesCypher>(
            msg,
            (&pk.0, &pk.1),
            sigma.clone(),
            &prg_192,
            &param,
            &paramowf,
        );
        let mut msg_false = msg.to_vec().clone();
        msg_false = msg_false
            .iter()
            .map(|x| x.wrapping_add(1))
            .collect::<Vec<u8>>();
        let res_false = faest_verify::<GF192, RandomOracleShake256, AesCypher>(
            &msg_false,
            (&pk.0, &pk.1),
            sigma,
            &prg_192,
            &param,
            &paramowf,
        );
        assert!(res_true);
        //assert!(!res_false);
    }

    //256-s
    for i in 0..500 {
        let param = Param::set_param(256, 4000, 22, 12, 11, 14, 8, 16, 2);
        let paramowf = ParamOWF::set_paramowf(8, 14, 52, 224, 4000, 672, 1664, 2, 500, None);
        let (sk, pk) = keygen::<AesCypher>(&param, &paramowf);
        let length: u8 = random();
        let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
        let sigma = faest_sign::<GF256, RandomOracleShake256, AesCypher>(
            msg,
            &sk,
            &[pk.0.clone(), pk.1.clone()].concat(),
            &prg_256,
            &param,
            &paramowf,
        );
        let res_true = faest_verify::<GF256, RandomOracleShake256, AesCypher>(
            msg,
            (&pk.0, &pk.1),
            sigma.clone(),
            &prg_256,
            &param,
            &paramowf,
        );
        let mut msg_false = msg.to_vec().clone();
        msg_false = msg_false
            .iter()
            .map(|x| x.wrapping_add(1))
            .collect::<Vec<u8>>();
        let res_false = faest_verify::<GF256, RandomOracleShake256, AesCypher>(
            &msg_false,
            (&pk.0, &pk.1),
            sigma,
            &prg_256,
            &param,
            &paramowf,
        );
        assert!(res_true);
        //assert!(!res_false);
    }

    //256-f
    for i in 0..500 {
        let param = Param::set_param(256, 4000, 32, 8, 8, 16, 16, 16, 2);
        let paramowf = ParamOWF::set_paramowf(8, 14, 52, 224, 4000, 672, 1664, 2, 500, None);
        let (sk, pk) = keygen::<AesCypher>(&param, &paramowf);
        let length: u8 = random();
        let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
        let sigma = faest_sign::<GF256, RandomOracleShake256, AesCypher>(
            msg,
            &sk,
            &[pk.0.clone(), pk.1.clone()].concat(),
            &prg_256,
            &param,
            &paramowf,
        );
        let res_true = faest_verify::<GF256, RandomOracleShake256, AesCypher>(
            msg,
            (&pk.0, &pk.1),
            sigma.clone(),
            &prg_256,
            &param,
            &paramowf,
        );
        let mut msg_false = msg.to_vec().clone();
        msg_false = msg_false
            .iter()
            .map(|x| x.wrapping_add(1))
            .collect::<Vec<u8>>();
        let res_false = faest_verify::<GF256, RandomOracleShake256, AesCypher>(
            &msg_false,
            (&pk.0, &pk.1),
            sigma,
            &prg_256,
            &param,
            &paramowf,
        );
        assert!(res_true);
        //assert!(!res_false);
    }
}

#[test]
fn faest_em_test() {
    //128-s
    for i in 0..500 {
        let param = PARAM128S;
        let paramowf = PARAMOWF128EM;
        let (sk, pk) = keygen::<EmCypher>(&param, &paramowf);
        let length: u8 = random();
        let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
        let sigma = faest_sign::<GF128, RandomOracleShake128, EmCypher>(
            msg,
            &sk,
            &[pk.0.clone(), pk.1.clone()].concat(),
            &prg_128,
            &param,
            &paramowf,
        );
        let res_true = faest_verify::<GF128, RandomOracleShake128, EmCypher>(
            msg,
            (&pk.0, &pk.1),
            sigma.clone(),
            &prg_128,
            &param,
            &paramowf,
        );
        /* let mut msg_false = msg.to_vec().clone();
        msg_false = msg_false.iter().map(|x| x.wrapping_add(1)).collect::<Vec<u8>>();
        let res_false = faest_verify::<GF128, RandomOracleShake128>(&msg_false, (&pk.0, &pk.1), sigma, &prg_128, &param, &paramowf); */
        assert!(res_true);
        //assert!(!res_false);
    }

    //128-f
    for i in 0..500 {
        let param = PARAM128F;
        let paramowf = PARAMOWF128EM;
        let (sk, pk) = keygen::<EmCypher>(&param, &paramowf);
        let length: u8 = random();
        let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
        let sigma = faest_sign::<GF128, RandomOracleShake128, EmCypher>(
            msg,
            &sk,
            &[pk.0.clone(), pk.1.clone()].concat(),
            &prg_128,
            &param,
            &paramowf,
        );
        let res_true = faest_verify::<GF128, RandomOracleShake128, EmCypher>(
            msg,
            (&pk.0, &pk.1),
            sigma.clone(),
            &prg_128,
            &param,
            &paramowf,
        );
        let mut msg_false = msg.to_vec().clone();
        msg_false = msg_false
            .iter()
            .map(|x| x.wrapping_add(1))
            .collect::<Vec<u8>>();
        let res_false = faest_verify::<GF128, RandomOracleShake128, EmCypher>(
            &msg_false,
            (&pk.0, &pk.1),
            sigma,
            &prg_128,
            &param,
            &paramowf,
        );
        assert!(res_true);
        //assert!(!res_false);
    }

    //192-s
    for i in 0..500 {
        let param = PARAM192S;
        let paramowf = PARAMOWF192EM;
        let (sk, pk) = keygen::<EmCypher>(&param, &paramowf);
        let length: u8 = random();
        let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
        let sigma = faest_sign::<GF192, RandomOracleShake256, EmCypher>(
            msg,
            &sk,
            &[pk.0.clone(), pk.1.clone()].concat(),
            &prg_192,
            &param,
            &paramowf,
        );
        let res_true = faest_verify::<GF192, RandomOracleShake256, EmCypher>(
            msg,
            (&pk.0, &pk.1),
            sigma.clone(),
            &prg_192,
            &param,
            &paramowf,
        );
        let mut msg_false = msg.to_vec().clone();
        msg_false = msg_false
            .iter()
            .map(|x| x.wrapping_add(1))
            .collect::<Vec<u8>>();
        let res_false = faest_verify::<GF192, RandomOracleShake256, EmCypher>(
            &msg_false,
            (&pk.0, &pk.1),
            sigma,
            &prg_192,
            &param,
            &paramowf,
        );
        assert!(res_true);
        //assert!(!res_false);
    }

    //192-f
    for i in 0..500 {
        let param = PARAM192F;
        let paramowf = PARAMOWF192EM;
        let (sk, pk) = keygen::<EmCypher>(&param, &paramowf);
        let length: u8 = random();
        let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
        let sigma = faest_sign::<GF192, RandomOracleShake256, EmCypher>(
            msg,
            &sk,
            &[pk.0.clone(), pk.1.clone()].concat(),
            &prg_192,
            &param,
            &paramowf,
        );
        let res_true = faest_verify::<GF192, RandomOracleShake256, EmCypher>(
            msg,
            (&pk.0, &pk.1),
            sigma.clone(),
            &prg_192,
            &param,
            &paramowf,
        );
        let mut msg_false = msg.to_vec().clone();
        msg_false = msg_false
            .iter()
            .map(|x| x.wrapping_add(1))
            .collect::<Vec<u8>>();
        let res_false = faest_verify::<GF192, RandomOracleShake256, EmCypher>(
            &msg_false,
            (&pk.0, &pk.1),
            sigma,
            &prg_192,
            &param,
            &paramowf,
        );
        assert!(res_true);
        //assert!(!res_false);
    }

    //256-s
    for i in 0..500 {
        let param = PARAM256S;
        let paramowf = PARAMOWF256EM;
        let (sk, pk) = keygen::<EmCypher>(&param, &paramowf);
        let length: u8 = random();
        let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
        let sigma = faest_sign::<GF256, RandomOracleShake256, EmCypher>(
            msg,
            &sk,
            &[pk.0.clone(), pk.1.clone()].concat(),
            &prg_256,
            &param,
            &paramowf,
        );
        let res_true = faest_verify::<GF256, RandomOracleShake256, EmCypher>(
            msg,
            (&pk.0, &pk.1),
            sigma.clone(),
            &prg_256,
            &param,
            &paramowf,
        );
        let mut msg_false = msg.to_vec().clone();
        msg_false = msg_false
            .iter()
            .map(|x| x.wrapping_add(1))
            .collect::<Vec<u8>>();
        let res_false = faest_verify::<GF256, RandomOracleShake256, EmCypher>(
            &msg_false,
            (&pk.0, &pk.1),
            sigma,
            &prg_256,
            &param,
            &paramowf,
        );
        assert!(res_true);
        //assert!(!res_false);
    }

    //256-f
    for i in 0..500 {
        let param = PARAM256F;
        let paramowf = PARAMOWF256EM;
        let (sk, pk) = keygen::<EmCypher>(&param, &paramowf);
        let length: u8 = random();
        let msg = &(0..length).map(|_| random::<u8>()).collect::<Vec<u8>>()[..];
        let sigma = faest_sign::<GF256, RandomOracleShake256, EmCypher>(
            msg,
            &sk,
            &[pk.0.clone(), pk.1.clone()].concat(),
            &prg_256,
            &param,
            &paramowf,
        );
        let res_true = faest_verify::<GF256, RandomOracleShake256, EmCypher>(
            msg,
            (&pk.0, &pk.1),
            sigma.clone(),
            &prg_256,
            &param,
            &paramowf,
        );
        let mut msg_false = msg.to_vec().clone();
        msg_false = msg_false
            .iter()
            .map(|x| x.wrapping_add(1))
            .collect::<Vec<u8>>();
        let res_false = faest_verify::<GF256, RandomOracleShake256, EmCypher>(
            &msg_false,
            (&pk.0, &pk.1),
            sigma,
            &prg_256,
            &param,
            &paramowf,
        );
        assert!(res_true);
        //assert!(!res_false);
    }
}


#[test]

fn calcul() {
    let a = [178, 224, 83, 249, 111, 78, 194, 6, 231, 139, 111, 250, 169, 194, 18, 129];
    let b = [11, 205, 53, 131, 101, 10, 174, 146, 247, 85, 54, 216, 191, 97, 14, 190];
    let c = [210, 140, 160, 247, 193, 80, 130, 4, 65, 141, 4, 87, 225, 17, 100, 229];
    let res : Vec<u8> = zip(a, b).map(|(a,b)| a^b).collect();
    let aut : Vec<u8> = zip(c, b).map(|(c,b)| c^b).collect();
    println!("wanted : {:?}", res);
    println!("obtained : {:?}", aut);
}

//a_t : [209, 99, 42, 133, 59, 167, 12, 252, 11, 195, 149, 83, 53, 193, 24, 80]