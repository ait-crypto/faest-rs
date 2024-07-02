use crate::{
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
