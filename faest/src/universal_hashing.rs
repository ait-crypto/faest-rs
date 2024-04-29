use crate::fields::{self, GaloisField, GF64};

#[allow(dead_code)]
pub fn volehash<const L: usize, const B: usize, T>(sd: &[u8], mut x0: Vec<u8>, x1: &[u8]) -> T
where
    T: fields::BigGaloisField,
{
    let mut r: [T; 4] = [T::new(0u128, 0u128); 4];
    for i in 0..4 {
        r[i] =
            T::to_field(&sd[i * (T::LENGTH as usize) / 8..(i + 1) * (T::LENGTH as usize) / 8])[0];
    }
    let s = T::to_field(&sd[4 * (T::LENGTH as usize) / 8..5 * (T::LENGTH as usize) / 8])[0];
    let t =
        &GF64::to_field(&sd[5 * (T::LENGTH as usize) / 8..(5 * (T::LENGTH as usize) / 8) + 8])[0];
    let l_p = (T::LENGTH as usize) * (L + (T::LENGTH as usize)).div_ceil(T::LENGTH as usize);
    for _i in 1..(l_p - (L + (T::LENGTH as usize))) {
        x0.push(0u8);
    }
    //use resize to get rid of the vec
    let y_h = T::to_field(&x0.clone());
    let y_b = GF64::to_field(&x0);

    let mut h0 = T::new(0u128, 0u128);
    let mut s_add = T::ONE;
    for i in 0..(l_p / (T::LENGTH as usize)) {
        h0 += s_add * y_h[(l_p / (T::LENGTH as usize)) - 1 - i];
        s_add *= s;
    }

    let mut h1 = GF64::new(0u64);
    let mut t_add = GF64::new(1u64);
    for i in 0..(l_p / 64) {
        h1.set_value(h1.get_value() ^ (GF64::mul(&t_add, &y_b[(l_p / 64) - 1 - i])).get_value());
        t_add = GF64::mul(&t_add, t);
    }

    let h1_p = T::new(h1.get_value() as u128, 0u128);

    let (h2, h3) = ((r[0] * h0) + (r[1] * h1_p), ((r[2] * h0) + (r[3] * h1_p)));

    let mut h = h2.get_value().0.to_le_bytes().to_vec();
    h.append(&mut h2.get_value().1.to_le_bytes()[..((T::LENGTH as usize) / 8) - 16].to_vec());
    //taking the B first bytes of h3
    h.append(
        &mut h3.get_value().0.to_le_bytes()[..16 * (B / 16) + (1 - B / 16) * (B % 16)].to_vec(),
    );
    h.append(&mut h3.get_value().1.to_le_bytes()[..(B / 16) * (B % 16)].to_vec());
    h.iter_mut().zip(x1.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    T::to_field(&h)[0]
}

#[allow(dead_code)]
pub fn zkhash<const L: usize, T>(sd: &[u8], x0: &[T], x1: T) -> Vec<u8>
where
    T: fields::BigGaloisField,
{
    let r0 = T::to_field(&sd[..(T::LENGTH as usize) / 8])[0];
    let r1 = T::to_field(&sd[(T::LENGTH as usize) / 8..2 * ((T::LENGTH as usize) / 8)])[0];
    let s = T::to_field(&sd[2 * ((T::LENGTH as usize) / 8)..3 * ((T::LENGTH as usize) / 8)])[0];
    let mut t_vec = sd[3 * ((T::LENGTH as usize) / 8)..].to_vec();
    t_vec.append(&mut vec![0u8; ((T::LENGTH as usize) / 8) - 8]);
    let t = T::to_field(&t_vec)[0];
    let mut h0 = T::new(0u128, 0u128);
    let mut s_add = T::ONE;
    for i in 0..L {
        h0 += x0[L - 1 - i] * s_add;
        s_add *= s;
    }

    let mut h1 = T::new(0u128, 0u128);
    let mut t_add = T::ONE;
    for i in 0..L {
        h1 += x0[L - 1 - i] * t_add;
        t_add *= t;
    }

    let gf_h = ((r0 * h0) + (r1 * h1)) + x1;
    let mut h = gf_h.get_value().0.to_le_bytes().to_vec();
    h.append(&mut gf_h.get_value().1.to_le_bytes()[..((T::LENGTH as usize) / 8) - 16].to_vec());
    h
}
