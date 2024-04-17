use crate::fields::{self, GalloisField, GF64};

#[allow(dead_code)]
pub fn volehash<const LAMBDA: usize, const L: usize, const B: usize, T>(
    sd: Vec<u8>,
    mut x0: Vec<u8>,
    x1: Vec<u8>,
) -> Vec<u8>
where
    T: fields::BigGalloisField,
{
    let mut r: [T; 4] = [T::new(0u128, 0u128); 4];
    for i in 0..4 {
        r[i] = T::to_field(sd[i * LAMBDA / 8..(i + 1) * LAMBDA / 8].to_vec())[0];
    }
    let s = T::to_field(sd[4 * LAMBDA / 8..5 * LAMBDA / 8].to_vec())[0];
    let t = &GF64::to_field(sd[5 * LAMBDA / 8..(5 * LAMBDA / 8) + 8].to_vec())[0];
    let l_p = LAMBDA * (L + LAMBDA).div_ceil(LAMBDA);
    for _i in 1..(l_p - (L + LAMBDA)) {
        x0.push(0u8);
    }
    let y_h = T::to_field(x0.clone());
    let y_b = GF64::to_field(x0);

    let mut h0 = T::new(0u128, 0u128);
    let mut s_add = T::ONE;
    for i in 0..(l_p / LAMBDA) {
        h0 = T::xor(&h0, &T::mul(&s_add, &y_h[(l_p / LAMBDA) - 1 - i]));
        s_add = T::mul(&s_add, &s);
    }

    let mut h1 = GF64::new(0u64);
    let mut t_add = GF64::new(1u64);
    for i in 0..(l_p / 64) {
        h1.set_value(h1.get_value() ^ (GF64::mul(&t_add, &y_b[(l_p / 64) - 1 - i])).get_value());
        t_add = GF64::mul(&t_add, t);
    }

    let h1_p = T::new(h1.get_value() as u128, 0u128);

    let (h2, h3) = (
        T::xor(&T::mul(&r[0], &h0), &T::mul(&r[1], &h1_p)),
        T::xor(&T::mul(&r[2], &h0), &T::mul(&r[3], &h1_p)),
    );

    let mut h = h2.get_value().0.to_le_bytes().to_vec();
    h.append(&mut h2.get_value().1.to_le_bytes()[..(LAMBDA / 8) - 16].to_vec());
    //taking the B first bytes of h3
    h.append(
        &mut h3.get_value().0.to_le_bytes()[..16 * (B / 16) + (1 - B / 16) * (B % 16)].to_vec(),
    );
    h.append(&mut h3.get_value().1.to_le_bytes()[..(B / 16) * (B % 16)].to_vec());
    h.iter_mut().zip(x1.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    h
}
