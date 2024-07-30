use faest::{
    fields::{BigGaloisField, GF128, GF192, GF256},
    random_oracles::{RandomOracleShake128, RandomOracleShake192, RandomOracleShake256},
    vc::open,
    vole::{chaldec, volecommit, volereconstruct},
};
use rand::{random, thread_rng, Rng};

#[test]
fn test_commitment_and_construction() {
    //GF128
    for _i in 0..1 {
        let lambdabytes = 16_usize;
        let lh = 234;
        let iv: u128 = random();
        let mut rng = thread_rng();
        let choice = rng.gen_range(0..2);
        let mut tau = 11 * choice + (1 - choice) * 16;
        let mut tau0 = lambdabytes * 8 % tau;
        if tau0 == 0 {
            tau += 1;
            tau0 = lambdabytes * 8 % tau;
        }
        let k1 = (lambdabytes * 8 / tau) as u16;
        let tau1 = tau - tau0;
        let k0 = ((lambdabytes * 8 - (k1 as usize) * tau1) / tau0) as u16;
        let rl = GF128::rand();
        let mut r = rl.get_value().0.to_le_bytes().to_vec();
        r.append(&mut rl.get_value().1.to_le_bytes().to_vec()[..lambdabytes - 16].to_vec());
        let chall = GF128::rand();
        let mut chal = chall.get_value().0.to_le_bytes().to_vec();
        chal.append(&mut chall.get_value().1.to_le_bytes().to_vec()[..lambdabytes - 16].to_vec());
        let (h1, decom, _c, _u, _v) =
            volecommit::<GF128, RandomOracleShake128>(&r, iv, lh, tau, k0, k1);
        let mut pdecom = vec![(Vec::new(), Vec::new()); tau];
        for i in 0..tau {
            let b = chaldec(
                &chal.clone(),
                k0,
                tau0.try_into().unwrap(),
                k1,
                tau1.try_into().unwrap(),
                i.try_into().unwrap(),
            );
            pdecom[i] = open(&decom[i].clone(), b);
        }
        let (h2, _q) = volereconstruct::<GF128, RandomOracleShake128>(
            &chal,
            pdecom,
            iv,
            lh,
            tau,
            tau0.try_into().unwrap(),
            tau1.try_into().unwrap(),
            k0,
            k1,
            lambdabytes,
        );
        assert_eq!(h1, h2);
    }
    //GF192
    for _i in 0..1 {
        let lambdabytes = 24_usize;
        let lh = 458;
        let iv: u128 = random();
        let mut rng = thread_rng();
        let choice = rng.gen_range(0..2);
        let mut tau = 16 * choice + (1 - choice) * 24;
        let mut tau0 = lambdabytes * 8 % tau;
        if tau0 == 0 {
            tau += 1;
            tau0 = lambdabytes * 8 % tau;
        }
        let k1 = (lambdabytes * 8 / tau) as u16;
        let tau1 = tau - tau0;
        let k0 = ((lambdabytes * 8 - (k1 as usize) * tau1) / tau0) as u16;
        let rl = GF192::rand();
        let mut r = rl.get_value().0.to_le_bytes().to_vec();
        r.append(&mut rl.get_value().1.to_le_bytes().to_vec()[..lambdabytes - 16].to_vec());
        let chall = GF192::rand();
        let mut chal = chall.get_value().0.to_le_bytes().to_vec();
        chal.append(&mut chall.get_value().1.to_le_bytes().to_vec()[..lambdabytes - 16].to_vec());
        let (h1, decom, _c, _u, _v) =
            volecommit::<GF192, RandomOracleShake192>(&r, iv, lh, tau, k0, k1);
        let mut pdecom = vec![(Vec::new(), Vec::new()); tau];
        for i in 0..tau {
            let b = chaldec(
                &chal.clone(),
                k0,
                tau0.try_into().unwrap(),
                k1,
                tau1.try_into().unwrap(),
                i.try_into().unwrap(),
            );
            pdecom[i] = open(&decom[i].clone(), b);
        }
        let (h2, _q) = volereconstruct::<GF192, RandomOracleShake192>(
            &chal,
            pdecom,
            iv,
            lh,
            tau,
            tau0.try_into().unwrap(),
            tau1.try_into().unwrap(),
            k0,
            k1,
            lambdabytes,
        );
        assert_eq!(h1, h2);
    }
    //GF256
    for _i in 0..1 {
        let lambdabytes = 32_usize;
        let lh = 566;
        let iv: u128 = random();
        let mut rng = thread_rng();
        let choice = rng.gen_range(0..2);
        let mut tau = 22 * choice + (1 - choice) * 32;
        let mut tau0 = lambdabytes * 8 % tau;
        if tau0 == 0 {
            tau += 1;
            tau0 = lambdabytes * 8 % tau;
        }
        let k1 = (lambdabytes * 8 / tau) as u16;
        let tau1 = tau - tau0;
        let k0 = ((lambdabytes * 8 - (k1 as usize) * tau1) / tau0) as u16;
        let rl = GF256::rand();
        let mut r = rl.get_value().0.to_le_bytes().to_vec();
        r.append(&mut rl.get_value().1.to_le_bytes().to_vec()[..lambdabytes - 16].to_vec());
        let chall = GF256::rand();
        let mut chal = chall.get_value().0.to_le_bytes().to_vec();
        chal.append(&mut chall.get_value().1.to_le_bytes().to_vec()[..lambdabytes - 16].to_vec());
        let (h1, decom, _c, _u, _v) =
            volecommit::<GF256, RandomOracleShake256>(&r, iv, lh, tau, k0, k1);
        let mut pdecom = vec![(Vec::new(), Vec::new()); tau];
        for i in 0..tau {
            let b = chaldec(
                &chal.clone(),
                k0,
                tau0.try_into().unwrap(),
                k1,
                tau1.try_into().unwrap(),
                i.try_into().unwrap(),
            );
            pdecom[i] = open(&decom[i].clone(), b);
        }
        let (h2, _q) = volereconstruct::<GF256, RandomOracleShake256>(
            &chal,
            pdecom,
            iv,
            lh,
            tau,
            tau0.try_into().unwrap(),
            tau1.try_into().unwrap(),
            k0,
            k1,
            lambdabytes,
        );
        assert_eq!(h1, h2);
    }
}
