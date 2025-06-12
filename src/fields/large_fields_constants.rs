use crate::fields::{
    Field,
    large_fields::{
        Alphas, Betas, BigGF, ByteCombineConstants, ByteCombineSquaredConstants, GF128, GF192,
        GF256, Sigmas,
    },
};

// GF128 constants

impl Alphas for GF128 {
    const ALPHA: [Self; 7] = [
        Self([0x053d8555a9979a1ca13fe8ac5560ce0du128]),
        Self([0x4cf4b7439cbfbb84ec7759ca3488aee1u128]),
        Self([0x35ad604f7d51d2c6bfcf02ae363946a8u128]),
        Self([0x0dcb364640a222fe6b8330483c2e9849u128]),
        Self([0x549810e11a88dea5252b49277b1b82b4u128]),
        Self([0xd681a5686c0c1f75c72bf2ef2521ff22u128]),
        Self([0x0950311a4fb78fe07a7a8e94e136f9bcu128]),
    ];
}

impl Betas for GF128 {
    const BETA_SQUARES: [Self; 5] = [
        Self([0xdb4a932e2cae3d8baca8c2a7190f676bu128]),
        Self([0x500317bd159d73bb34d2f7fba603e341u128]),
        Self([0xf210539fd8dd2772cbc26e38bdbd6c62u128]),
        Self([0x7959d70ce1ee694253b85b6402b1e849u128]),
        Self([0xdb4a932e2cae3d8baca8c2a7190f676bu128]),
    ];

    const BETA_CUBES: [Self; 4] = [
        Self([0x7959d70ce1ee694253b85b6402b1e849u128]),
        Self([0xdb4a932e2cae3d8baca8c2a7190f676bu128]),
        Self([0x500317bd159d73bb34d2f7fba603e341u128]),
        Self([0xf210539fd8dd2772cbc26e38bdbd6c62u128]),
    ];
}

impl Sigmas for GF128 {
    const SIGMA: [Self; 9] = [
        Self([0x4cf4b7439cbfbb84ec7759ca3488aee0u128]),
        Self([0x35ad604f7d51d2c6bfcf02ae363946a9u128]),
        Self([0xb32fd29a04c0be084c3607bab51b5acau128]),
        Self([0x186ca7a286376521c95c10ed4f932c54u128]),
        Self([0xca760596e52ed74a1f8e5cdeb7aab282u128]),
        Self([0x00000000000000000000000000000001u128]),
        Self([0x1cf7a0fe8922c83fd8a5ae31928b4da1u128]),
        Self([0x7534634307ce7cbe88fd3d5cb6e7dff9u128]),
        Self([0x872430dcdf135bcc433f53640b5ab39au128]),
    ];

    const SIGMA_SQUARES: [Self; 9] = [
        Self([0x0dcb364640a222fe6b8330483c2e9848u128]),
        Self([0xd681a5686c0c1f75c72bf2ef2521ff23u128]),
        Self([0x49c93216352821984d48b16661e860edu128]),
        Self([0xf68b54c3d7c88a6cda3bd0e460a50d97u128]),
        Self([0x9283a13819861c13e1e073c178e70787u128]),
        Self([0x00000000000000000000000000000001u128]),
        Self([0xffdb65d9987f058ca0415e708193f42au128]),
        Self([0xa3b5c62b6bc263cb4fd6cfb393c620dbu128]),
        Self([0xdaec11278a2c0a891c6e94d79177c893u128]),
    ];
}

impl ByteCombineSquaredConstants for BigGF<u128, 1, 128> {
    const BYTE_COMBINE_SQ_2: Self = Self::ALPHA[1];
    const BYTE_COMBINE_SQ_3: Self = Self([Self::ALPHA[1].0[0] ^ Self::ONE.0[0]]);
}

// GF192 constants

impl Alphas for GF192 {
    const ALPHA: [Self; 7] = [
        Self([
            0xe665d76c966ebdeaccc8a3d56f389763u128,
            0x310bc8140e6b3662u128,
        ]),
        Self([
            0x7bf61f19d5633f26b233619e7cf450bbu128,
            0xda933726d491db34u128,
        ]),
        Self([
            0x8232e37706328d199c6d2c13f5398a0du128,
            0x0c3b0d703c754ef6u128,
        ]),
        Self([
            0x7a5542ab0058d22edd20747cbd2bf75du128,
            0x45ec519c94bc1251u128,
        ]),
        Self([
            0x08168cb767debe84d8d50ce28ace2bf8u128,
            0xd67d146a4ba67045u128,
        ]),
        Self([
            0xf3eaf7ae5fd72048970f9c76eed5e1bau128,
            0x29a6bd5f696cea43u128,
        ]),
        Self([
            0x6019fd623906e9d3f5945dc265068571u128,
            0xc77c56540f87c4b0u128,
        ]),
    ];
}

impl Betas for GF192 {
    const BETA_SQUARES: [Self; 5] = [
        Self([
            0x89bfb5055f8ff2664a2fe80a53fe16e7u128,
            0x6c4aecc3fdd0f812u128,
        ]),
        Self([
            0x125a337e5e808579f061255c52e359d4u128,
            0x54ed13a2d09da6a4u128,
        ]),
        Self([
            0x62217a15d25ec520941080db88d09584u128,
            0xee0fc537c5a9cb74u128,
        ]),
        Self([
            0xf9c4fc6ed351b23f2e5e4d8d89cddab6u128,
            0xd6a83a56e8e495c2u128,
        ]),
        Self([
            0x89bfb5055f8ff2664a2fe80a53fe16e7u128,
            0x6c4aecc3fdd0f812u128,
        ]),
    ];

    const BETA_CUBES: [Self; 4] = [
        Self([
            0xf9c4fc6ed351b23f2e5e4d8d89cddab6u128,
            0xd6a83a56e8e495c2u128,
        ]),
        Self([
            0x89bfb5055f8ff2664a2fe80a53fe16e7u128,
            0x6c4aecc3fdd0f812u128,
        ]),
        Self([
            0x125a337e5e808579f061255c52e359d4u128,
            0x54ed13a2d09da6a4u128,
        ]),
        Self([
            0x62217a15d25ec520941080db88d09584u128,
            0xee0fc537c5a9cb74u128,
        ]),
    ];
}

impl Sigmas for GF192 {
    const SIGMA: [Self; 9] = [
        Self([
            0x7bf61f19d5633f26b233619e7cf450bau128,
            0xda933726d491db34u128,
        ]),
        Self([
            0x8232e37706328d199c6d2c13f5398a0cu128,
            0x0c3b0d703c754ef6u128,
        ]),
        Self([
            0x638227a707652828fb039539490f3262u128,
            0x7170a38d85840211u128,
        ]),
        Self([
            0x73e093aeb2bd81a26ae66d7cf63a7b42u128,
            0x0cee234c9f37ab71u128,
        ]),
        Self([
            0x9a46dbc9d4349a17d55dd8b4c0c2e8d5u128,
            0xa7d899db6d6097d3u128,
        ]),
        Self([
            0x00000000000000000000000000000001u128,
            0x0000000000000000u128,
        ]),
        Self([
            0x69ac2c678be3ba5f425244c22e17096eu128,
            0x8e7e2484040c7d90u128,
        ]),
        Self([
            0x7fb8d6607c39e6061702b39a83f3c8a5u128,
            0x20dfa416e9086710u128,
        ]),
        Self([
            0x1d99ac75ae672326831233410b235d20u128,
            0xced061212ca1ac64u128,
        ]),
    ];
    const SIGMA_SQUARES: [Self; 9] = [
        Self([
            0x7a5542ab0058d22edd20747cbd2bf75cu128,
            0x45ec519c94bc1251u128,
        ]),
        Self([
            0xf3eaf7ae5fd72048970f9c76eed5e1bbu128,
            0x29a6bd5f696cea43u128,
        ]),
        Self([
            0x9d93c875430d82cc7efbc24b13ccc7d9u128,
            0xeb98ff32dafaed56u128,
        ]),
        Self([
            0x786dc5dceb00feddbca4a96550fde7a8u128,
            0x6c9fc2ff5e921d95u128,
        ]),
        Self([
            0x142c7d701c8270aa34d42a414032d13fu128,
            0x87d213f1272a1544u128,
        ]),
        Self([
            0x00000000000000000000000000000001u128,
            0x0000000000000000u128,
        ]),
        Self([
            0x187438bed206170e4930f4a735fb62d8u128,
            0xabe394ab5115d925u128,
        ]),
        Self([
            0x8c5221ce23eec64e800d2fec6d26291fu128,
            0x0979194980648d53u128,
        ]),
        Self([
            0x7596dda0f0bf7471ae536261e4ebf3a8u128,
            0xdfd1231f68801891u128,
        ]),
    ];
}

impl ByteCombineConstants for GF192 {
    const BYTE_COMBINE_2: Self = Self::ALPHA[0];
    const BYTE_COMBINE_3: Self = Self([
        Self::ALPHA[0].0[0] ^ Self::ONE.0[0],
        Self::ALPHA[0].0[1] ^ Self::ONE.0[1],
    ]);
}

impl ByteCombineSquaredConstants for GF192 {
    const BYTE_COMBINE_SQ_2: Self = Self::ALPHA[1];
    const BYTE_COMBINE_SQ_3: Self = Self([
        Self::ALPHA[1].0[0] ^ Self::ONE.0[0],
        Self::ALPHA[1].0[1] ^ Self::ONE.0[1],
    ]);
}

// GF256 constants

impl Alphas for BigGF<u128, 2, 256> {
    const ALPHA: [Self; 7] = [
        Self([
            0xbed68d38a0474e67969788420bdefee7u128,
            0x04c9a8cf20c95833df229845f8f1e16au128,
        ]),
        Self([
            0x2ba5c48d2c42072fa95af52ad52289c1u128,
            0x064e4d699c5b4af1d14a0d376c00b0eau128,
        ]),
        Self([
            0x1771831e533b0f5755dab3833f809d1du128,
            0x6195e3db7011f68dfb96573fad3fac10u128,
        ]),
        Self([
            0x752758911a30e3f6de010519b01bcdd5u128,
            0x56c24fd64f7688382a0778b6489ea03fu128,
        ]),
        Self([
            0x1bc4dbd440f1848298c2f529e98a30b6u128,
            0x22270b6d71574ffc2fbe09947d49a981u128,
        ]),
        Self([
            0xaced66c666f1afbc9e75afb9de44670bu128,
            0xc03d372fd1fa29f3f001253ff2991f7eu128,
        ]),
        Self([
            0x5237c4d625b86f0dba43b698b332e88bu128,
            0x133eea09d26b7bb82f652b2af4e81545u128,
        ]),
    ];
}

impl Betas for GF256 {
    const BETA_SQUARES: [Self; 5] = [
        Self([
            0xd9ca3e577cc14c4a4074aaa06e5faadeu128,
            0x96ff78f99e8ca1cbda065d89ba07bf41u128,
        ]),
        Self([
            0x3cd447937f790879fc8046a8eaa315e8u128,
            0x67dbaeb2ec4abc7c2adc5a08c13f1cfbu128,
        ]),
        Self([
            0xd9ca3e577cc14c4b4074aaa16e5eabebu128,
            0x96ff78f99e8ca1cbda065d89ba07bf40u128,
        ]),
        Self([
            0x3cd447937f790878fc8046a9eaa214dcu128,
            0x67dbaeb2ec4abc7c2adc5a08c13f1cfau128,
        ]),
        Self([
            0xd9ca3e577cc14c4a4074aaa06e5faadeu128,
            0x96ff78f99e8ca1cbda065d89ba07bf41u128,
        ]),
    ];
    const BETA_CUBES: [Self; 4] = [
        Self([
            0x3cd447937f790878fc8046a9eaa214dcu128,
            0x67dbaeb2ec4abc7c2adc5a08c13f1cfau128,
        ]),
        Self([
            0xd9ca3e577cc14c4a4074aaa06e5faadeu128,
            0x96ff78f99e8ca1cbda065d89ba07bf41u128,
        ]),
        Self([
            0x3cd447937f790879fc8046a8eaa315e8u128,
            0x67dbaeb2ec4abc7c2adc5a08c13f1cfbu128,
        ]),
        Self([
            0xd9ca3e577cc14c4b4074aaa16e5eabebu128,
            0x96ff78f99e8ca1cbda065d89ba07bf40u128,
        ]),
    ];
}

impl Sigmas for GF256 {
    const SIGMA: [Self; 9] = [
        Self([
            0x2ba5c48d2c42072fa95af52ad52289c0,
            0x064e4d699c5b4af1d14a0d376c00b0ea,
        ]),
        Self([
            0x1771831e533b0f5755dab3833f809d1c,
            0x6195e3db7011f68dfb96573fad3fac10,
        ]),
        Self([
            0x8748a24b4ab3a892372f5a920b67efff,
            0xc6737a464da16302214b28089e99af95,
        ]),
        Self([
            0x30611f596cb383ad319800033ca8b976,
            0x24694604ed0c050dfef404a31149196b,
        ]),
        Self([
            0xbb9ce5d835caa0eacbaf1c3be1c5fb22,
            0xa1a8d4f4a1ebdf7e0b9772005fa6b36f,
        ]),
        Self([
            0x00000000000000000000000000000001,
            0x00000000000000000000000000000000,
        ]),
        Self([
            0x1771831e533b0f5655dab3823f819c28,
            0x6195e3db7011f68dfb96573fad3fac11,
        ]),
        Self([
            0xd0350e7dfa862912d0547873524e02b1,
            0x702cec741ee89ff7da9be967cd26e8d5,
        ]),
        Self([
            0x09ff302a864765599020d2d23c10a95b,
            0xe6d3948d80643e3c009db4ee77215795,
        ]),
    ];
    const SIGMA_SQUARES: [Self; 9] = [
        Self([
            0x752758911a30e3f6de010519b01bcdd4,
            0x56c24fd64f7688382a0778b6489ea03f,
        ]),
        Self([
            0xaced66c666f1afbc9e75afb9de44670a,
            0xc03d372fd1fa29f3f001253ff2991f7e,
        ]),
        Self([
            0x957349b58c0549483fcd7d68defc7727,
            0x0287e5a6bc9212c20e68957294f15180,
        ]),
        Self([
            0xfedaa2104349c0b0243619206d778eb5,
            0xd303dd260391524bdf640e1506710a3a,
        ]),
        Self([
            0x4cb977e2f0c405027fb9d7c8b0a3ddf8,
            0x94789d5f221eb309d46ec8fb2ef6eec1,
        ]),
        Self([
            0x00000000000000000000000000000001,
            0x00000000000000000000000000000000,
        ]),
        Self([
            0xaced66c666f1afbd9e75afb8de45663f,
            0xc03d372fd1fa29f3f001253ff2991f7f,
        ]),
        Self([
            0x7cd868bb9c7786ae4e21d7ca8c0a65ba,
            0xb011db5bcf12b6042a9acc583fbff7ab,
        ]),
        Self([
            0x400c2f28e30e8ed6b2a1916366a87167,
            0xd7ca75e923580a7800469650fe80eb51,
        ]),
    ];
}

impl ByteCombineConstants for BigGF<u128, 2, 256> {
    const BYTE_COMBINE_2: Self = Self::ALPHA[0];
    const BYTE_COMBINE_3: Self = Self([
        Self::ALPHA[0].0[0] ^ Self::ONE.0[0],
        Self::ALPHA[0].0[1] ^ Self::ONE.0[1],
    ]);
}

impl ByteCombineSquaredConstants for BigGF<u128, 2, 256> {
    const BYTE_COMBINE_SQ_2: Self = Self::ALPHA[1];
    const BYTE_COMBINE_SQ_3: Self = Self([
        Self::ALPHA[1].0[0] ^ Self::ONE.0[0],
        Self::ALPHA[1].0[1] ^ Self::ONE.0[1],
    ]);
}
