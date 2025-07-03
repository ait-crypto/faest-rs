use std::marker::PhantomData;

use generic_array::{GenericArray, typenum::Unsigned};
use rand_core::CryptoRngCore;

use crate::{
    Error, UnpackedSecretKey,
    bavc::{BatchVectorCommitment, BavcOpenResult},
    fields::Field,
    internal_keys::{PublicKey, SecretKey},
    parameter::{BaseParameters, FAESTParameters, OWFParameters, TauParameters, Witness},
    prg::{IV, IVSize},
    random_oracles::{Hasher, RandomOracle},
    utils::{Reader, decode_all_chall_3, xor_arrays_into},
    vole::{
        VoleCommitResult, VoleCommitmentCRef, VoleCommitmentCRefMut, VoleReconstructResult,
        volecommit, volereconstruct,
    },
};

type RO<P> =
    <<<P as FAESTParameters>::OWF as OWFParameters>::BaseParams as BaseParameters>::RandomOracle;

/// Wraps the prover's signature.
///
/// It is used by [`sign`] to write the signature into a byte-array.
struct SignatureRefMut<'a, P, O>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    cs: &'a mut [u8],
    u_tilde: &'a mut [u8],
    d: &'a mut [u8],
    a1_tilde: &'a mut [u8],
    a2_tilde: &'a mut [u8],
    decom_i: &'a mut [u8],
    chall3: &'a mut [u8],
    iv_pre: &'a mut [u8],
    ctr: &'a mut [u8],
    pd: PhantomData<(P, O)>,
}

impl<'a, P, O> From<&'a mut GenericArray<u8, P::SignatureSize>> for SignatureRefMut<'a, P, O>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    fn from(value: &'a mut GenericArray<u8, P::SignatureSize>) -> Self {
        let (cs, value) =
            value.split_at_mut(O::LHatBytes::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1));
        let (u_tilde, value) =
            value.split_at_mut(<O::BaseParams as BaseParameters>::VoleHasherOutputLength::USIZE);
        let (d, value) = value.split_at_mut(O::LBytes::USIZE);
        let (a1_tilde, value) = value.split_at_mut(O::LambdaBytes::USIZE);
        let (a2_tilde, value) = value.split_at_mut(O::LambdaBytes::USIZE);
        let (decom_i, value) = value.split_at_mut(P::get_decom_size());
        let (chall3, value) = value.split_at_mut(O::LambdaBytes::USIZE);
        let (iv_pre, ctr) = value.split_at_mut(IVSize::USIZE);

        Self {
            cs,
            u_tilde,
            d,
            a1_tilde,
            a2_tilde,
            decom_i,
            chall3,
            iv_pre,
            ctr,
            pd: PhantomData,
        }
    }
}

impl<P, O> SignatureRefMut<'_, P, O>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    fn save_zk_constraints(&mut self, a1_tilde: &[u8], a2_tilde: &[u8]) {
        self.a1_tilde.copy_from_slice(a1_tilde);
        self.a2_tilde.copy_from_slice(a2_tilde);
    }

    fn mask_witness(&mut self, w: &[u8], u: &[u8]) {
        xor_arrays_into(self.d, w, u);
    }

    fn save_decom_and_ctr(&mut self, decom_i: &BavcOpenResult, ctr: u32) {
        let BavcOpenResult { coms, nodes } = decom_i;

        // Save decom_i
        let mut offset = 0;
        for slice in coms.iter().chain(nodes) {
            self.decom_i[offset..offset + slice.len()].copy_from_slice(slice);
            offset += slice.len();
        }

        // Save ctr
        self.ctr.copy_from_slice(&ctr.to_le_bytes());
    }
}

/// Wraps the signature received by the verifier.
///
/// It is used by [`verify`] to verify the byte array containing the prover's signature.
struct SignatureRef<'a, P, O>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    cs: &'a [u8],
    u_tilde: &'a [u8],
    d: &'a [u8],
    a1_tilde: &'a [u8],
    a2_tilde: &'a [u8],
    decom_i: &'a [u8],
    chall3: &'a [u8],
    iv_pre: &'a [u8],
    ctr: &'a [u8],
    pd: PhantomData<(P, O)>,
}

impl<'a, P, O> TryFrom<&'a GenericArray<u8, P::SignatureSize>> for SignatureRef<'a, P, O>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    type Error = Error;

    fn try_from(value: &'a GenericArray<u8, P::SignatureSize>) -> Result<Self, Self::Error> {
        let (cs, value) =
            value.split_at(O::LHatBytes::USIZE * (<P::Tau as TauParameters>::Tau::USIZE - 1));
        let (u_tilde, value) =
            value.split_at(<O::BaseParams as BaseParameters>::VoleHasherOutputLength::USIZE);
        let (d, value) = value.split_at(O::LBytes::USIZE);
        let (a1_tilde, value) = value.split_at(O::LambdaBytes::USIZE);
        let (a2_tilde, value) = value.split_at(O::LambdaBytes::USIZE);
        let (decom_i, value) = value.split_at(P::get_decom_size());
        let (chall3, value) = value.split_at(O::LambdaBytes::USIZE);
        let (iv_pre, ctr) = value.split_at(IVSize::USIZE);

        // ::4
        if !check_challenge_3::<P, O>(chall3) {
            return Err(Error::new());
        }

        Ok(Self {
            cs,
            u_tilde,
            d,
            a1_tilde,
            a2_tilde,
            decom_i,
            chall3,
            iv_pre,
            ctr,
            pd: PhantomData,
        })
    }
}

impl<'a, P, O> SignatureRef<'a, P, O>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    fn parse_decom(&self) -> BavcOpenResult<'a> {
        let node_size = O::LambdaBytes::USIZE;
        let n_coms = <P::Tau as TauParameters>::Tau::USIZE;
        let com_size = O::NLeafCommit::USIZE * O::LambdaBytes::USIZE;

        let (commits, nodes) = self.decom_i.split_at(n_coms * com_size);
        let coms = commits.chunks_exact(com_size).collect();
        let nodes = nodes.chunks_exact(node_size).collect();

        BavcOpenResult { coms, nodes }
    }

    fn parse_ctr(&self) -> u32 {
        u32::from_le_bytes(self.ctr.try_into().unwrap())
    }
}

/// Hashes required for FAEST implementation
trait FaestHash: RandomOracle {
    /// Generate `µ`
    fn hash_mu(mu: &mut [u8], input: &[u8], output: &[u8], msg: &[u8]);
    /// Generate `r` and `iv_pre`
    fn hash_r_iv(r: &mut [u8], iv_pre: &mut IV, key: &[u8], mu: &[u8], rho: &[u8]);
    /// Generate `iv`
    fn hash_iv(iv: &mut IV);
    /// Generate first challenge
    fn hash_challenge_1(chall1: &mut [u8], mu: &[u8], hcom: &[u8], c: &[u8], iv: &[u8]);
    /// Generate second challenge in an init-update-finalize style
    fn hash_challenge_2_init(chall1: &[u8], u_t: &[u8]) -> <Self as RandomOracle>::Hasher<10>;
    fn hash_challenge_2_finalize(
        hasher: <Self as RandomOracle>::Hasher<10>,
        chall2: &mut [u8],
        d: &[u8],
    );
    /// Generate third challenge
    fn hash_challenge_3(
        chall3: &mut [u8],
        chall2: &[u8],
        a0_t: &[u8],
        a1_t: &[u8],
        a2_t: &[u8],
        ctr: u32,
    );
    /// Generate third challenge in an init-finalize style
    fn hash_challenge_3_init(
        chall2: &[u8],
        a0_t: &[u8],
        a1_t: &[u8],
        a2_t: &[u8],
    ) -> <Self as RandomOracle>::Hasher<11>;
    fn hash_challenge_3_finalize(
        hasher: &<Self as RandomOracle>::Hasher<11>,
        chall3: &mut [u8],
        ctr: u32,
    );
}

impl<RO> FaestHash for RO
where
    RO: RandomOracle,
{
    fn hash_mu(mu: &mut [u8], input: &[u8], output: &[u8], msg: &[u8]) {
        // Step 3
        let mut h2_hasher = Self::h2_0_init();
        h2_hasher.update(input);
        h2_hasher.update(output);
        h2_hasher.update(msg);
        h2_hasher.finish().read(mu);
    }

    fn hash_r_iv(r: &mut [u8], iv: &mut IV, key: &[u8], mu: &[u8], rho: &[u8]) {
        // Step 4
        let mut h3_hasher = Self::h3_init();
        h3_hasher.update(key);
        h3_hasher.update(mu);
        h3_hasher.update(rho);

        let mut h3_reader = h3_hasher.finish();
        h3_reader.read(r);
        h3_reader.read(iv);
    }

    fn hash_iv(iv_pre: &mut IV) {
        // Step 5
        let mut h4_hasher = Self::h4_init();
        h4_hasher.update(iv_pre);

        let h4_reader = h4_hasher.finish();
        *iv_pre = h4_reader.read_into();
    }

    fn hash_challenge_1(chall1: &mut [u8], mu: &[u8], hcom: &[u8], c: &[u8], iv: &[u8]) {
        let mut h2_hasher = Self::h2_1_init();
        h2_hasher.update(mu);
        h2_hasher.update(hcom);
        h2_hasher.update(c);
        h2_hasher.update(iv);
        h2_hasher.finish().read(chall1);
    }

    fn hash_challenge_2_init(chall1: &[u8], u_t: &[u8]) -> Self::Hasher<10> {
        let mut h2_hasher = Self::h2_2_init();
        h2_hasher.update(chall1);
        h2_hasher.update(u_t);
        h2_hasher
    }

    fn hash_challenge_2_finalize(
        mut hasher: <Self as RandomOracle>::Hasher<10>,
        chall2: &mut [u8],
        d: &[u8],
    ) {
        hasher.update(d);
        hasher.finish().read(chall2);
    }

    fn hash_challenge_3_init(
        chall2: &[u8],
        a0_t: &[u8],
        a1_t: &[u8],
        a2_t: &[u8],
    ) -> <Self as RandomOracle>::Hasher<11> {
        let mut h2_hasher = Self::h2_3_init();
        h2_hasher.update(chall2);
        h2_hasher.update(a0_t);
        h2_hasher.update(a1_t);
        h2_hasher.update(a2_t);
        h2_hasher
    }

    fn hash_challenge_3_finalize(
        hasher: &<Self as RandomOracle>::Hasher<11>,
        chall3: &mut [u8],
        ctr: u32,
    ) {
        let mut hasher = hasher.to_owned();
        hasher.update(&ctr.to_le_bytes());
        hasher.finish().read(chall3);
    }

    fn hash_challenge_3(
        chall3: &mut [u8],
        chall2: &[u8],
        a0_t: &[u8],
        a1_t: &[u8],
        a2_t: &[u8],
        ctr: u32,
    ) {
        let mut h2_hasher = Self::h2_3_init();
        h2_hasher.update(chall2);
        h2_hasher.update(a0_t);
        h2_hasher.update(a1_t);
        h2_hasher.update(a2_t);
        h2_hasher.update(&ctr.to_le_bytes());
        h2_hasher.finish().read(chall3)
    }
}

#[inline]
pub(crate) fn faest_keygen<O, R>(rng: R) -> SecretKey<O>
where
    O: OWFParameters,
    R: CryptoRngCore,
{
    O::keygen_with_rng(rng)
}

fn check_challenge_3<P, O>(chall3: &[u8]) -> bool
where
    P: FAESTParameters,
    O: OWFParameters,
{
    let start_byte = (O::Lambda::USIZE - P::WGRIND::USIZE) / 8;

    // Discard all bits before position "lambda - w_grind"
    let start_byte_0s = chall3[start_byte] >> ((O::Lambda::USIZE - P::WGRIND::USIZE) % 8);
    if start_byte_0s != 0 {
        return false;
    }

    // Check that all the following bytes are 0s
    chall3.iter().skip(start_byte + 1).all(|b| *b == 0)
}

#[inline]
pub(crate) fn faest_sign<P>(
    msg: &[u8],
    sk: &SecretKey<P::OWF>,
    rho: &[u8],
    signature: &mut GenericArray<u8, P::SignatureSize>,
) -> Result<(), Error>
where
    P: FAESTParameters,
{
    // ::0
    let signature = SignatureRefMut::<P, P::OWF>::from(signature);
    // ::12
    let w = P::OWF::witness(sk);

    sign(msg, sk, &w, rho, signature)
}

#[inline]
pub(crate) fn faest_unpacked_sign<P>(
    msg: &[u8],
    sk_unpacked: &UnpackedSecretKey<P::OWF>,
    rho: &[u8],
    signature: &mut GenericArray<u8, P::SignatureSize>,
) -> Result<(), Error>
where
    P: FAESTParameters,
{
    // ::0
    let signature = SignatureRefMut::<P, P::OWF>::from(signature);
    sign(msg, &sk_unpacked.sk, &sk_unpacked.wit, rho, signature)
}

fn sign<P, O>(
    msg: &[u8],
    sk: &SecretKey<O>,
    witness: &Witness<O>,
    rho: &[u8],
    mut signature: SignatureRefMut<P, O>,
) -> Result<(), Error>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    // ::3
    let mut mu = GenericArray::<u8, O::LambdaBytesTimes2>::default();
    RO::<P>::hash_mu(&mut mu, &sk.pk.owf_input, &sk.pk.owf_output, msg);

    // ::4
    let mut r = GenericArray::<u8, O::LambdaBytes>::default();
    let iv_pre = GenericArray::from_mut_slice(signature.iv_pre);
    RO::<P>::hash_r_iv(&mut r, iv_pre, &sk.owf_key, &mu, rho);

    // ::5
    let mut iv = GenericArray::from_slice(iv_pre).to_owned();
    RO::<P>::hash_iv(&mut iv);

    // ::7
    let VoleCommitResult { com, decom, u, v } =
        volecommit::<P::BAVC, O::LHatBytes>(VoleCommitmentCRefMut::new(signature.cs), &r, &iv);

    // ::8
    //Contrarly to specification, faest-ref uses iv instead of iv_pre
    let mut chall1 = GenericArray::default();
    RO::<P>::hash_challenge_1(&mut chall1, &mu, &com, signature.cs, iv.as_slice());

    // ::10
    // hash u and write the result (i.e., u_tilde) into signature
    O::BaseParams::hash_u_vector(signature.u_tilde, &u, &chall1);

    // ::11
    // hash v row by row and update h2_hasher with the row hashes
    let mut h2_hasher = RO::<P>::hash_challenge_2_init(chall1.as_slice(), signature.u_tilde);
    O::BaseParams::hash_v_matrix(&mut h2_hasher, v.as_slice(), &chall1);

    // ::13
    // compute and write masked witness 'd' in signature
    signature.mask_witness(witness, &u[..<O as OWFParameters>::LBytes::USIZE]);

    // ::14
    let mut chall2 = GenericArray::default();
    RO::<P>::hash_challenge_2_finalize(h2_hasher, &mut chall2, signature.d);
    // ::18
    let (a0_tilde, a1_tilde, a2_tilde) = P::OWF::prove(
        witness,
        // ::16
        GenericArray::from_slice(
            &u[O::LBytes::USIZE..O::LBytes::USIZE + O::LambdaBytesTimes2::USIZE],
        ),
        &v,
        &sk.pk,
        &chall2,
    );

    // Save a1_tilde, a2_tilde in signature
    signature.save_zk_constraints(&a1_tilde.as_bytes(), &a2_tilde.as_bytes());

    // ::19
    let hasher = RO::<P>::hash_challenge_3_init(
        &chall2,
        &a0_tilde.as_bytes(),
        signature.a1_tilde,
        signature.a2_tilde,
    );

    for ctr in 0u32.. {
        // ::20
        RO::<P>::hash_challenge_3_finalize(&hasher, signature.chall3, ctr);
        // ::21
        if check_challenge_3::<P, O>(signature.chall3) {
            // ::24
            let i_delta = decode_all_chall_3::<P::Tau>(signature.chall3);

            // ::26
            if let Some(decom_i) = <P as FAESTParameters>::BAVC::open(&decom, &i_delta) {
                // Save decom_i and ctr bits
                signature.save_decom_and_ctr(&decom_i, ctr);
                return Ok(());
            }
        }
    }

    Err(Error::new())
}

#[inline]
pub(crate) fn faest_verify<P>(
    msg: &[u8],
    pk: &PublicKey<P::OWF>,
    signature: &GenericArray<u8, P::SignatureSize>,
) -> Result<(), Error>
where
    P: FAESTParameters,
{
    //::1-4
    let signature = SignatureRef::<P, P::OWF>::try_from(signature)?;

    verify::<P, P::OWF>(msg, pk, signature)
}

fn verify<P, O>(msg: &[u8], pk: &PublicKey<O>, signature: SignatureRef<P, O>) -> Result<(), Error>
where
    P: FAESTParameters<OWF = O>,
    O: OWFParameters,
{
    let ctr = signature.parse_ctr();

    // ::2
    let mut mu = GenericArray::<u8, O::LambdaBytesTimes2>::default();
    RO::<P>::hash_mu(&mut mu, &pk.owf_input, &pk.owf_output, msg);

    // ::3
    let mut iv = GenericArray::from_slice(signature.iv_pre).to_owned();
    RO::<P>::hash_iv(&mut iv);

    // ::7-8
    let chall3: &GenericArray<u8, O::LambdaBytes> = GenericArray::from_slice(signature.chall3);
    let decom_i = signature.parse_decom();
    let c = VoleCommitmentCRef::<O::LHatBytes>::new(signature.cs);
    let VoleReconstructResult { com, q } =
        volereconstruct::<P::BAVC, O::LHatBytes>(chall3, &decom_i, c, &iv).ok_or(Error::new())?;

    // ::10
    let mut chall1 = GenericArray::default();
    RO::<P>::hash_challenge_1(&mut chall1, &mu, com.as_slice(), c.as_slice(), &iv);

    let mut h2_hasher = RO::<P>::hash_challenge_2_init(chall1.as_slice(), signature.u_tilde);

    // ::12-14
    O::BaseParams::hash_q_matrix(
        &mut h2_hasher,
        q.as_slice(),
        signature.u_tilde,
        &chall1,
        P::decode_challenge_as_iter(chall3),
    );

    // ::15
    let mut chall2 = GenericArray::default();
    RO::<P>::hash_challenge_2_finalize(h2_hasher, &mut chall2, signature.d);

    // ::17
    let a0_tilde = P::OWF::verify(
        &q,
        GenericArray::from_slice(signature.d),
        pk,
        &chall2,
        chall3,
        GenericArray::from_slice(signature.a1_tilde),
        GenericArray::from_slice(signature.a2_tilde),
    );

    // ::18
    let mut chall3_prime = GenericArray::default();
    RO::<P>::hash_challenge_3(
        &mut chall3_prime,
        &chall2,
        a0_tilde.as_bytes().as_slice(),
        signature.a1_tilde,
        signature.a2_tilde,
        ctr,
    );

    // ::19
    if *chall3 == chall3_prime {
        Ok(())
    } else {
        Err(Error::new())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use generic_array::GenericArray;
    use rand::RngCore;
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};

    use crate::parameter::{
        FAEST128fParameters, FAEST128sParameters, FAEST192fParameters, FAEST192sParameters,
        FAEST256fParameters, FAEST256sParameters, FAESTEM128fParameters, FAESTEM128sParameters,
        FAESTEM192fParameters, FAESTEM192sParameters, FAESTEM256fParameters, FAESTEM256sParameters,
        FAESTParameters,
    };

    const RUNS: usize = 3;

    #[generic_tests::define]
    mod faest {
        use super::*;

        fn random_message(mut rng: impl RngCore) -> Vec<u8> {
            let mut length = [0];
            while length[0] == 0 {
                rng.fill_bytes(&mut length);
            }
            let mut ret = vec![0; length[0] as usize];
            rng.fill_bytes(&mut ret);
            ret
        }

        #[test]
        fn sign_and_verify<P: FAESTParameters>() {
            let mut rng = rand::thread_rng();
            for _i in 0..RUNS {
                let sk = P::OWF::keygen_with_rng(&mut rng);
                let msg = random_message(&mut rng);
                let mut sigma = GenericArray::default_boxed();
                assert!(faest_sign::<P>(&msg, &sk, &[], &mut sigma).is_ok());
                let pk = sk.as_public_key();
                let res = faest_verify::<P>(&msg, &pk, &sigma);
                assert!(res.is_ok());
            }
        }

        #[cfg(feature = "serde")]
        #[test]
        fn serialize<P: FAESTParameters>() {
            let mut rng = rand::thread_rng();
            let sk = P::OWF::keygen_with_rng(&mut rng);

            let mut out = vec![];
            let mut ser = serde_json::Serializer::new(&mut out);

            sk.serialize(&mut ser).expect("serialize key pair");
            let serialized = String::from_utf8(out).expect("serialize to string");

            let mut de = serde_json::Deserializer::from_str(&serialized);
            let sk2 = SecretKey::<P::OWF>::deserialize(&mut de).expect("deserialize secret key");
            assert_eq!(sk, sk2);

            let pk = sk.as_public_key();
            let mut out = vec![];
            let mut ser = serde_json::Serializer::new(&mut out);

            pk.serialize(&mut ser).expect("serialize key pair");
            let serialized = String::from_utf8(out).expect("serialize to string");

            let mut de = serde_json::Deserializer::from_str(&serialized);
            let pk2 = PublicKey::<P::OWF>::deserialize(&mut de).expect("deserialize public key");
            assert_eq!(pk, pk2);
        }

        #[instantiate_tests(<FAEST128fParameters>)]
        mod faest_128f {}

        #[instantiate_tests(<FAEST128sParameters>)]
        mod faest_128s {}

        #[instantiate_tests(<FAEST192fParameters>)]
        mod faest_192f {}

        #[instantiate_tests(<FAEST192sParameters>)]
        mod faest_192s {}

        #[instantiate_tests(<FAEST256fParameters>)]
        mod faest_256f {}

        #[instantiate_tests(<FAEST256sParameters>)]
        mod faest_256s {}

        #[instantiate_tests(<FAESTEM128fParameters>)]
        mod faest_em_128f {}

        #[instantiate_tests(<FAESTEM128sParameters>)]
        mod faest_em_128s {}

        #[instantiate_tests(<FAESTEM192fParameters>)]
        mod faest_em_192f {}

        #[instantiate_tests(<FAESTEM192sParameters>)]
        mod faest_em_192s {}

        #[instantiate_tests(<FAESTEM256fParameters>)]
        mod faest_em_256f {}

        #[instantiate_tests(<FAESTEM256sParameters>)]
        mod faest_em_256s {}
    }

    // Test signature against TVs and verify
    #[generic_tests::define]
    mod faest_tvs {
        use super::*;
        use crate::utils::test::{hash_array, read_test_data};

        use serde::Deserialize;

        const MSG: [u8; 76] = [
            0x54, 0x68, 0x69, 0x73, 0x20, 0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x20,
            0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20,
            0x73, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x65, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x46, 0x41, 0x45, 0x53, 0x54, 0x20, 0x64, 0x69, 0x67, 0x69, 0x74, 0x61, 0x6c, 0x20,
            0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x67, 0x6f,
            0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e,
        ];

        const RHO: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];

        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct FaestProveData {
            lambda: usize,
            em: bool,
            sk: Vec<u8>,
            hashed_sig_s: Vec<u8>,
            hashed_sig_f: Vec<u8>,
        }

        #[test]
        fn sign_and_verify_tvs<
            FAESTSmall: FAESTParameters,
            FAESTFast: FAESTParameters<OWF = FAESTSmall::OWF>,
        >() {
            let database: Vec<FaestProveData> = read_test_data("FaestProve.json")
                .into_iter()
                .filter(|data: &FaestProveData| {
                    (data.em == FAESTSmall::OWF::IS_EM)
                        && (data.lambda == <FAESTSmall::OWF as OWFParameters>::Lambda::USIZE)
                })
                .collect();

            for data in database {
                let sk = SecretKey::<FAESTSmall::OWF>::try_from(data.sk.as_slice()).unwrap();
                let pk = sk.as_public_key();

                // Sign and compare with tvs
                let mut signature_s = GenericArray::default_boxed();
                assert!(faest_sign::<FAESTSmall>(&MSG, &sk, &RHO, &mut signature_s).is_ok());
                assert_eq!(
                    data.hashed_sig_s,
                    hash_array(signature_s.as_slice()).as_slice()
                );

                let mut signature_f = GenericArray::default_boxed();
                assert!(faest_sign::<FAESTFast>(&MSG, &sk, &RHO, &mut signature_f).is_ok());
                assert_eq!(
                    data.hashed_sig_f,
                    hash_array(signature_f.as_slice()).as_slice()
                );

                // verify
                assert!(faest_verify::<FAESTSmall>(&MSG, &pk, &signature_s).is_ok());
                assert!(faest_verify::<FAESTFast>(&MSG, &pk, &signature_f).is_ok());
            }
        }

        #[instantiate_tests(<FAEST128sParameters, FAEST128fParameters>)]
        mod faest_128 {}

        #[instantiate_tests(<FAEST192sParameters, FAEST192fParameters>)]
        mod faest_192 {}

        #[instantiate_tests(<FAEST256sParameters, FAEST256fParameters>)]
        mod faest_256 {}

        #[instantiate_tests(<FAESTEM128sParameters, FAESTEM128fParameters>)]
        mod faest_em_128 {}

        #[instantiate_tests(<FAESTEM192sParameters, FAESTEM192fParameters>)]
        mod faest_em_192 {}

        #[instantiate_tests(<FAESTEM256sParameters, FAESTEM256fParameters>)]
        mod faest_em_256 {}
    }
}
