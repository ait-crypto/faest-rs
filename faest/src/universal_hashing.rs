use crate::fields::{GalloisField, GF64};



fn volehash<const LAMBDA: usize, const L: usize, const B: usize, T>(sd : Vec<u8>, mut x0 : Vec<u8>, x1 : Vec<u8>) -> Vec<u8> {
    let r = [T;4];
    for i in 0..4 {
        r[i] = T::to_field(sd[i*LAMBDA/8..(i+1)*LAMBDA/8]);
    }
    s = T::to_field(sd[4*LAMBDA/8..5*LAMBDA/8]);
    t = GF64::to_field(sd[5*LAMBDA/8..(5*LAMBDA/8)+8]);
    let l_p = LAMBDA * (L + LAMBDA).div_ceil(LAMBDA);
    //------------------------------------------------------------------------------------------------------------------------
    //In constant time ?
    //------------------------------------------------------------------------------------------------------------------------
    for i in 1..(l_p - (L + LAMBDA)) {
        x0.push(0u8);
    }
    let y_h = T::to_field(x0);
    let y_b = GF64::to_field(x0);

    let mut h0 = T::new(0u128, 0u128);
    let mut s_add = T::ONE;
    for i in 0..(l_p/LAMBDA) {
        h_0 = T::add(&h_0, T::mul(&s_add, y_h[(l_p/LAMBDA) - 1 - i]));
        s_add = T::mul(s_add, s);
    }

    let mut h1 = GF64::new(0u64);
    let mut t_add = GF64::ONE;
    for i in 0..(l_p/64) {
        h_1 = T::add(&h_1, T::mul(&t_add, y_h[(l_p/64) - 1 - i]));
        t_add = T::mul(t_add, t);
    }

    let h_1_p = T::new(h_1.get_value() as u128, 0u128);

    (h_2, h_3) = (T::xor(T::mul(&r[0], &h0), T::mul(&r[1], &h_1_p)), T::xor(T::mul(&r[2], h0), T::mul(&r[3], h_1_p)));

    let h = 

}