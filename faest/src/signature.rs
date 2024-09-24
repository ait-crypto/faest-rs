use signature::{Signer, Verifier};

use crate::{
    faest::{faest_sign, faest_verify, keygen, AesCypher, EmCypher, Variant},
    fields::{BigGaloisField, GF128, GF192, GF256},
    parameter::{
        PARAM128F, PARAM128S, PARAM192F, PARAM192S, PARAM256F, PARAM256S, PARAMOWF128,
        PARAMOWF128EM, PARAMOWF192, PARAMOWF192EM, PARAMOWF256, PARAMOWF256EM,
    },
    random_oracles::{RandomOracleShake128, RandomOracleShake192, RandomOracleShake256},
};

struct Signature {
    c: Vec<Vec<u8>>,
    u_t: Vec<u8>,
    d: Vec<u8>,
    a_t: Vec<u8>,
    pdecom: Vec<(Vec<Vec<u8>>, Vec<u8>)>,
    chall3: Vec<u8>,
    iv: [u8; 16],
}

impl Signature {
    fn signature_setter(
        (c, u_t, d, a_t, pdecom, chall3, iv): (
            Vec<Vec<u8>>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<(Vec<Vec<u8>>, Vec<u8>)>,
            Vec<u8>,
            [u8; 16],
        ),
    ) -> Self {
        Signature {
            c,
            u_t,
            d,
            a_t,
            pdecom,
            chall3,
            iv,
        }
    }

    fn signature_getter(
        &self,
    ) -> (
        Vec<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<(Vec<Vec<u8>>, Vec<u8>)>,
        Vec<u8>,
        [u8; 16],
    ) {
        (
            self.c.clone(),
            self.u_t.clone(),
            self.d.clone(),
            self.a_t.clone(),
            self.pdecom.clone(),
            self.chall3.clone(),
            self.iv,
        )
    }
}

pub struct Faest<'a> {
    //false for AES, true for EM
    variant: bool,
    sec_lvl: u16,
    //false for short, true for fast
    sign_len: bool,
    sk: Option<&'a [u8]>,
    pk: (Vec<u8>, Vec<u8>),
}

struct Faest128SParameters;

trait FaestParameters {
    const SK_SIZE: usize;

    type RO: RandomOracle;
}

impl FaestParameters for Faest128SParameters {
    const SK_SIZE: usize = 16;

    type RO = RandomOracleShake128;
}

struct FaestSigner<P>
where
    P: FaestParameters,
{
    owf_key: [u8; P::SK_SIZE],
}

impl Faest<'_> {
    pub fn faest_setter<'a>(
        variant: bool,
        sec_lvl: u16,
        sign_len: bool,
        sk: Option<&'a [u8]>,
        pk: (Vec<u8>, Vec<u8>),
    ) -> Faest<'a> {
        Faest {
            variant,
            sec_lvl,
            sign_len,
            sk,
            pk,
        }
    }

    pub fn faest_set_variant(&mut self, variant: bool) {
        self.variant = variant
    }

    pub fn faest_set_sec_lvl(&mut self, sec_lvl: u16) {
        self.sec_lvl = sec_lvl
    }

    pub fn faest_set_sign_len(&mut self, sign_len: bool) {
        self.sign_len = sign_len
    }

    pub fn faest_set_sk(&mut self, sk: Option<&'static [u8]>) {
        self.sk = sk
    }

    pub fn faest_set_pk(&mut self, pk: (Vec<u8>, Vec<u8>)) {
        self.pk = pk
    }

    pub fn faest_getter(&mut self) -> (bool, u16, bool, Option<&[u8]>, (Vec<u8>, Vec<u8>)) {
        (
            self.variant,
            self.sec_lvl,
            self.sign_len,
            self.sk,
            self.pk.clone(),
        )
    }

    pub fn faest_get_variant(&self) -> bool {
        self.variant
    }

    pub fn faest_get_sec_lvl(&self) -> u16 {
        self.sec_lvl
    }

    pub fn faest_get_sign_len(&self) -> bool {
        self.sign_len
    }

    pub fn faest_get_sk(&self) -> Option<&[u8]> {
        self.sk
    }

    pub fn faest_get_pk(&self) -> (Vec<u8>, Vec<u8>) {
        self.pk.clone()
    }
}

impl Signer<Signature> for Faest<'_> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        let lvl = self.faest_get_sec_lvl();
        let mut sigma: (
            Vec<Vec<u8>>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<(Vec<Vec<u8>>, Vec<u8>)>,
            Vec<u8>,
            [u8; 16],
        ) = (vec![], vec![], vec![], vec![], vec![], vec![], [0; 16]);
        if lvl == 128 {
            if self.faest_get_variant() {
                if self.faest_get_sign_len() {
                    let pk = self.faest_get_pk();
                    sigma = faest_sign::<GF128, RandomOracleShake128, EmCypher>(
                        msg,
                        self.faest_get_sk().expect("signature operation failed"),
                        &[pk.0, pk.1].concat(),
                        &PARAM128F,
                        &PARAMOWF128EM,
                    )
                } else {
                    let pk = self.faest_get_pk();
                    sigma = faest_sign::<GF128, RandomOracleShake128, EmCypher>(
                        msg,
                        self.faest_get_sk().expect("signature operation failed"),
                        &[pk.0, pk.1].concat(),
                        &PARAM128S,
                        &PARAMOWF128EM,
                    );
                }
            } else if self.faest_get_sign_len() {
                let pk = self.faest_get_pk();
                sigma = faest_sign::<GF128, RandomOracleShake128, AesCypher>(
                    msg,
                    self.faest_get_sk().expect("signature operation failed"),
                    &[pk.0, pk.1].concat(),
                    &PARAM128F,
                    &PARAMOWF128,
                );
            } else {
                let pk = self.faest_get_pk();
                sigma = faest_sign::<GF128, RandomOracleShake128, AesCypher>(
                    msg,
                    self.faest_get_sk().expect("signature operation failed"),
                    &[pk.0, pk.1].concat(),
                    &PARAM128S,
                    &PARAMOWF128,
                );
            }
        } else if lvl == 192 {
            if self.faest_get_variant() {
                if self.faest_get_sign_len() {
                    let pk = self.faest_get_pk();
                    sigma = faest_sign::<GF192, RandomOracleShake192, EmCypher>(
                        msg,
                        self.faest_get_sk().expect("signature operation failed"),
                        &[pk.0, pk.1].concat(),
                        &PARAM192F,
                        &PARAMOWF192EM,
                    );
                } else {
                    let pk = self.faest_get_pk();
                    sigma = faest_sign::<GF192, RandomOracleShake192, EmCypher>(
                        msg,
                        self.faest_get_sk().expect("signature operation failed"),
                        &[pk.0, pk.1].concat(),
                        &PARAM192S,
                        &PARAMOWF192EM,
                    );
                }
            } else if self.faest_get_sign_len() {
                let pk = self.faest_get_pk();
                sigma = faest_sign::<GF192, RandomOracleShake192, AesCypher>(
                    msg,
                    self.faest_get_sk().expect("signature operation failed"),
                    &[pk.0, pk.1].concat(),
                    &PARAM192F,
                    &PARAMOWF192,
                );
            } else {
                let pk = self.faest_get_pk();
                sigma = faest_sign::<GF192, RandomOracleShake192, AesCypher>(
                    msg,
                    self.faest_get_sk().expect("signature operation failed"),
                    &[pk.0, pk.1].concat(),
                    &PARAM192S,
                    &PARAMOWF192,
                );
            }
        } else if lvl == 256 {
            if self.faest_get_variant() {
                if self.faest_get_sign_len() {
                    let pk = self.faest_get_pk();
                    sigma = faest_sign::<GF256, RandomOracleShake256, EmCypher>(
                        msg,
                        self.faest_get_sk().expect("signature operation failed"),
                        &[pk.0, pk.1].concat(),
                        &PARAM256F,
                        &PARAMOWF256EM,
                    );
                } else {
                    let pk = self.faest_get_pk();
                    sigma = faest_sign::<GF256, RandomOracleShake256, EmCypher>(
                        msg,
                        self.faest_get_sk().expect("signature operation failed"),
                        &[pk.0, pk.1].concat(),
                        &PARAM256S,
                        &PARAMOWF256EM,
                    );
                }
            } else if self.faest_get_sign_len() {
                let pk = self.faest_get_pk();
                sigma = faest_sign::<GF256, RandomOracleShake256, AesCypher>(
                    msg,
                    self.faest_get_sk().expect("signature operation failed"),
                    &[pk.0, pk.1].concat(),
                    &PARAM256F,
                    &PARAMOWF256,
                );
            } else {
                let pk = self.faest_get_pk();
                sigma = faest_sign::<GF256, RandomOracleShake256, AesCypher>(
                    msg,
                    self.faest_get_sk().expect("signature operation failed"),
                    &[pk.0, pk.1].concat(),
                    &PARAM256S,
                    &PARAMOWF256,
                );
            }
        } else {
            return (Err(signature::Error::new()));
        }
        Ok(Signature::signature_setter(sigma))
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        self.try_sign(msg).expect("signature operation failed")
    }
}

impl Verifier<Signature> for Faest<'_> {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        let lvl = self.faest_get_sec_lvl();
        if lvl == 128 {
            if self.faest_get_variant() {
                if self.faest_get_sign_len() {
                    let pk = self.faest_get_pk();
                    return (if faest_verify::<GF128, RandomOracleShake128, EmCypher>(
                        msg,
                        (&pk.0, &pk.1),
                        Signature::signature_getter(signature),
                        &PARAM128F,
                        &PARAMOWF128EM,
                    ) {
                        Ok(())
                    } else {
                        Err(signature::Error::new())
                    });
                } else {
                    let pk = self.faest_get_pk();
                    return (if faest_verify::<GF128, RandomOracleShake128, EmCypher>(
                        msg,
                        (&pk.0, &pk.1),
                        Signature::signature_getter(signature),
                        &PARAM128S,
                        &PARAMOWF128EM,
                    ) {
                        Ok(())
                    } else {
                        Err(signature::Error::new())
                    });
                }
            } else if self.faest_get_sign_len() {
                let pk = self.faest_get_pk();
                return (if faest_verify::<GF128, RandomOracleShake128, EmCypher>(
                    msg,
                    (&pk.0, &pk.1),
                    Signature::signature_getter(signature),
                    &PARAM128F,
                    &PARAMOWF128,
                ) {
                    Ok(())
                } else {
                    Err(signature::Error::new())
                });
            } else {
                let pk = self.faest_get_pk();
                return (if faest_verify::<GF128, RandomOracleShake128, EmCypher>(
                    msg,
                    (&pk.0, &pk.1),
                    Signature::signature_getter(signature),
                    &PARAM128S,
                    &PARAMOWF128,
                ) {
                    Ok(())
                } else {
                    Err(signature::Error::new())
                });
            }
        } else if lvl == 192 {
            if self.faest_get_variant() {
                if self.faest_get_sign_len() {
                    let pk = self.faest_get_pk();
                    return (if faest_verify::<GF192, RandomOracleShake192, EmCypher>(
                        msg,
                        (&pk.0, &pk.1),
                        Signature::signature_getter(signature),
                        &PARAM192F,
                        &PARAMOWF192EM,
                    ) {
                        Ok(())
                    } else {
                        Err(signature::Error::new())
                    });
                } else {
                    let pk = self.faest_get_pk();
                    return (if faest_verify::<GF192, RandomOracleShake192, EmCypher>(
                        msg,
                        (&pk.0, &pk.1),
                        Signature::signature_getter(signature),
                        &PARAM192S,
                        &PARAMOWF192EM,
                    ) {
                        Ok(())
                    } else {
                        Err(signature::Error::new())
                    });
                }
            } else if self.faest_get_sign_len() {
                let pk = self.faest_get_pk();
                return (if faest_verify::<GF192, RandomOracleShake192, EmCypher>(
                    msg,
                    (&pk.0, &pk.1),
                    Signature::signature_getter(signature),
                    &PARAM192F,
                    &PARAMOWF192,
                ) {
                    Ok(())
                } else {
                    Err(signature::Error::new())
                });
            } else {
                let pk = self.faest_get_pk();
                return (if faest_verify::<GF192, RandomOracleShake192, EmCypher>(
                    msg,
                    (&pk.0, &pk.1),
                    Signature::signature_getter(signature),
                    &PARAM192S,
                    &PARAMOWF192,
                ) {
                    Ok(())
                } else {
                    Err(signature::Error::new())
                });
            }
        } else if lvl == 256 {
            if self.faest_get_variant() {
                if self.faest_get_sign_len() {
                    //false for shelf.faest_get_pk();
                    return (if faest_verify::<GF256, RandomOracleShake256, AesCypher>(
                        msg,
                        (&pk.0, &pk.1),
                        Signature::signature_getter(signature),
                        &PARAM256F,
                        &PARAMOWF256EM,
                    ) {
                        Ok(())
                    } else {
                        Err(signature::Error::new())
                    });
                } else {
                    let pk = self.faest_get_pk();
                    return (if faest_verify::<GF256, RandomOracleShake256, AesCypher>(
                        msg,
                        (&pk.0, &pk.1),
                        Signature::signature_getter(signature),
                        &PARAM256S,
                        &PARAMOWF256EM,
                    ) {
                        Ok(())
                    } else {
                        Err(signature::Error::new())
                    });
                }
            } else if self.faest_get_sign_len() {
                let pk = self.faest_get_pk();
                return (if faest_verify::<GF256, RandomOracleShake256, AesCypher>(
                    msg,
                    (&pk.0, &pk.1),
                    Signature::signature_getter(signature),
                    &PARAM256F,
                    &PARAMOWF256,
                ) {
                    Ok(())
                } else {
                    Err(signature::Error::new())
                });
            } else {
                let pk = self.faest_get_pk();
                return (if faest_verify::<GF256, RandomOracleShake256, AesCypher>(
                    msg,
                    (&pk.0, &pk.1),
                    Signature::signature_getter(signature),
                    &PARAM256S,
                    &PARAMOWF256,
                ) {
                    Ok(())
                } else {
                    Err(signature::Error::new())
                });
            }
        } else {
            return (Err(signature::Error::new()));
        }
    }
}
