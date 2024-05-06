#[allow(clippy::type_complexity)]
pub fn convert_to_vole(
    sd: &[Option<Vec<u8>>],
    iv: u128,
    lh: usize,
    prg: &dyn Fn(&[u8], u128, usize) -> Vec<u8>,
) -> (Vec<u8>, Vec<Vec<u8>>) {
    let n = sd.len();
    let d = (u128::BITS - (n as u128).leading_zeros() - 1) as usize;
    let mut r = vec![vec![vec![0u8; lh]; n]; d + 1];
    match &sd[0] {
        None => r[0][0] = vec![0; lh],
        Some(sd0) => r[0][0] = prg(&sd0[..], iv, lh)[..].to_vec(),
    }
    for (i, _) in sd.iter().enumerate().skip(1).take(n) {
        r[0][i] = prg(
            &<std::option::Option<std::vec::Vec<u8>> as Clone>::clone(&sd[i]).unwrap(),
            iv,
            lh,
        );
    }
    let mut v = vec![vec![0u8; lh]; d];
    for j in 0..d {
        for i in 0..n / (1_usize << (j + 1)) {
            v[j] = v[j]
                .iter()
                .zip(r[j][2 * i + 1].iter())
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect();
            r[j + 1][i] = r[j][2 * i]
                .iter()
                .zip(r[j][2 * i + 1].clone())
                .map(|(&x1, x2)| x1 ^ x2)
                .collect();
        }
    }
    for j in 0..d {
        for _i in 0..n / (1_usize << (d - j - 1)) {}
    }
    let u = r[d][0].clone().to_vec();
    (u, v)
}

//constant time checking the value of i : if i is not correct, then the output will be an empty vec
pub fn chaldec(chal: Vec<u8>, k0: u16, t0: u16, k1: u16, t1: u16, i: u16) -> Vec<u8> {
    let mut lo = 1_u16;
    let mut hi = 0_u16;
    if i < t0 {
        lo = i * k0;
        hi = (i + 1) * k0 - 1;
    } else if i < t0 + t1 {
        let t = i - t0;
        lo = t0 * k0 + t * k1;
        hi = t0 * k0 + (t + 1) * k1 - 1;
    }
    let mut res = vec![(chal[(lo / 8) as usize] >> (lo % 8)) & 1];
    for j in 1..hi - lo + 1 {
        res.push((chal[((lo + j) / 8) as usize] >> ((lo + j) % 8)) & 1)
    }
    res
}
