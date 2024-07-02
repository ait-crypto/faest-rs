use crate::{
    fields::BigGaloisField,
    parameter::{Param, ParamOWF},
    rijndael_32::{
        bitslice, convert_from_batchblocks, inv_bitslice, mix_columns_0, rijndael_add_round_key,
        rijndael_key_schedule, rijndael_shift_rows_1, sub_bytes, sub_bytes_nots, State,
    },
};

pub fn extendedwitness(k: &[u8], pk: (&[u8], &[u8]), param: Param, paramowf: ParamOWF) -> Vec<u8> {
    let lambda = (param.get_lambda() / 8) as usize;
    let nst = paramowf.get_nst() as usize;
    let r = paramowf.get_r() as usize;
    let kc = paramowf.get_nk();
    let input = &pk.0[..lambda];
    let mut res = Vec::with_capacity((paramowf.get_l() / 8) as usize);
    let x = rijndael_key_schedule(input, nst as u8, kc, r as u8);
    res.append(&mut k.to_vec());
    let mut state = State::default();
    bitslice(
        &mut state,
        &k[..16],
        &[k[16..].to_vec(), vec![0u8; 32 - lambda]].concat(),
    );
    rijndael_add_round_key(&mut state, &x[..8]);
    for j in 1..r {
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);
        rijndael_shift_rows_1(&mut state, nst as u8);
        res.append(
            &mut convert_from_batchblocks(inv_bitslice(&state))[..kc as usize][..kc as usize]
                .to_vec()
                .iter()
                .flat_map(|x| x.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        mix_columns_0(&mut state);
        rijndael_add_round_key(&mut state, &x[8 * j..8 * (j + 1)]);
    }
    res
}

///Choice is made to treat bits as element of GFlambda (that is, m=lambda anyway, while in the paper we can have m = 1),
///since the set {GFlambda::0, GFlambda::1} is stable with the operations used on it in the program and that is much more convenient to write
///One of the first path to optimize the code could be to do the distinction
pub fn em_key_enc_fwd<T>(z: &[T], x: &[T], paramowf: &ParamOWF) -> Vec<T>
where
    T: BigGaloisField
        + std::default::Default
        + std::marker::Sized
        + std::fmt::Debug
        + std::ops::Add<T>,
{
    let mut res = Vec::with_capacity(paramowf.get_senc().into());
    let nst = paramowf.get_nst() as usize;
    //Step 2-3
    for j in 0..4 * nst {
        res.push(
            T::byte_combine(z[8 * j..8 * (j + 1)].try_into().unwrap())
                + T::byte_combine(x[8 * j..8 * (j + 1)].try_into().unwrap()),
        );
    }
    //Step 4
    for j in 1..paramowf.get_r() as usize {
        for c in 0..nst {
            let i: usize = 32 * nst * j + 32 * c;
            let mut z_hat: [T; 4] = [T::default(); 4];
            let mut x_hat: [T; 4] = [T::default(); 4];
            for r in 0..4 {
                z_hat[r] = T::byte_combine(z[i + 8 * r..i + 8 * r + 8].try_into().unwrap());
                x_hat[r] = T::byte_combine(x[i + 8 * r..i + 8 * r + 8].try_into().unwrap());
            }
            let (a, b, c) = (
                T::ONE,
                T::byte_combine([
                    T::default(),
                    T::ONE,
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                ]),
                T::byte_combine([
                    T::ONE,
                    T::ONE,
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                    T::default(),
                ]),
            );
            //Step 16
            res.push(z_hat[0] * b + z_hat[1] * c + z_hat[2] * a + z_hat[3] * a + x_hat[0]);
            res.push(z_hat[0] * a + z_hat[1] * b + z_hat[2] * c + z_hat[3] * a + x_hat[1]);
            res.push(z_hat[0] * a + z_hat[1] * a + z_hat[2] * b + z_hat[3] * c + x_hat[2]);
            res.push(z_hat[0] * c + z_hat[1] * a + z_hat[2] * a + z_hat[3] * b + x_hat[3]);
        }
    }
    res
}
