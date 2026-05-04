use core::{
    iter::{repeat_n, zip},
    marker::PhantomData,
    ops::{Add, Div, Mul, Sub},
};

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box};

use crate::{
    bavc::{BatchVectorCommitment, Bavc, BavcEm},
    fields::{BaseField, BigGaloisField, GF128, GF192, GF256},
    internal_keys::{PublicKey, SecretKey},
    prg::{PRG128, PRG192, PRG256, PseudoRandomGenerator},
    random_oracles::{Hasher, RandomOracle, RandomOracleShake128, RandomOracleShake256},
    rijndael_32::{Rijndael192, Rijndael256},
    universal_hashing::{
        B, LeafHasher128, LeafHasher192, LeafHasher256, VoleHasher, VoleHasherInit,
        VoleHasherProcess, ZKHasher, ZKHasherInit,
    },
    utils::{array_mut, array_ref, xor_arrays_inplace},
    witness::aes_extendedwitness,
    zk_constraints::{CstrntsVal, aes_prove, aes_verify},
};
use aes::{
    Aes128Enc, Aes192Enc, Aes256Enc,
    cipher::{BlockCipherEncrypt, KeyInit},
};
use hybrid_array::{
    Array, ArraySize,
    typenum::{
        Diff, Prod, Quot, Sum, U0, U1, U2, U3, U4, U5, U6, U7, U8, U10, U11, U12, U14, U16, U22,
        U24, U32, U40, U48, U52, U60, U64, U102, U103, U110, U112, U120, U128, U160, U162, U163,
        U176, U192, U216, U218, U234, U245, U246, U256, U312, U336, U384, U388, U448, U512, U672,
        U832, U1024, U2048, Unsigned,
    },
};
use rand_core::Rng;

#[cfg(all(
    feature = "opt-simd",
    any(target_arch = "x86", target_arch = "x86_64"),
    not(all(target_feature = "avx2", target_feature = "pclmulqdq"))
))]
pub(crate) mod x86_simd {
    use crate::fields::{
        // AVX2-optimized field implementatons
        x86_simd_large_fields::{GF128, GF192, GF256},
    };

    pub(crate) type FAEST128fParameters = super::FAEST128fParameters<GF128>;
    pub(crate) type FAEST128sParameters = super::FAEST128sParameters<GF128>;

    pub(crate) type FAESTEM128fParameters = super::FAESTEM128fParameters<GF128>;
    pub(crate) type FAESTEM128sParameters = super::FAESTEM128sParameters<GF128>;

    pub(crate) type FAEST192fParameters = super::FAEST192fParameters<GF192>;
    pub(crate) type FAEST192sParameters = super::FAEST192sParameters<GF192>;

    pub(crate) type FAESTEM192fParameters = super::FAESTEM192fParameters<GF192>;
    pub(crate) type FAESTEM192sParameters = super::FAESTEM192sParameters<GF192>;

    pub(crate) type FAEST256fParameters = super::FAEST256fParameters<GF256>;
    pub(crate) type FAEST256sParameters = super::FAEST256sParameters<GF256>;

    pub(crate) type FAESTEM256fParameters = super::FAESTEM256fParameters<GF256>;
    pub(crate) type FAESTEM256sParameters = super::FAESTEM256sParameters<GF256>;
}

// OWF L_Enc size
type U1216 = Sum<U1024, U192>;
type U2432 = Sum<U2048, U384>;

// l_hat = l + 3*lambda + B
type LHatBytes<LBytes, LambdaBytes, B> = Sum<LBytes, Sum<Prod<U3, LambdaBytes>, Quot<B, U8>>>;

/// Extract base field from OWF parameters
pub(crate) type OWFField<O> = <<O as OWFParameters>::BaseParams as BaseParameters>::Field;

/// The QuickSilver proof message
pub(crate) type QSProof<O> = (OWFField<O>, OWFField<O>, OWFField<O>);

/// Witness for the secret key
pub(crate) type Witness<O> = Box<Array<u8, <O as OWFParameters>::LBytes>>;
pub(crate) trait SecurityParameter:
    ArraySize
    + Add<Self, Output: ArraySize>
    + Mul<U2, Output: ArraySize>
    + Mul<U3, Output: ArraySize>
    + Mul<U4, Output: ArraySize>
    + Mul<U8, Output: ArraySize>
    + PartialEq
{
}

impl SecurityParameter for U16 {}
impl SecurityParameter for U24 {}
impl SecurityParameter for U32 {}

/// Base parameters per security level
pub(crate) trait BaseParameters {
    /// The field that is of size `2^λ` which is defined as [`Self::Lambda`]
    type Field: BigGaloisField<Length = Self::LambdaBytes>;
    /// Hasher implementation of `ZKHash`
    type ZKHasher: ZKHasherInit<Self::Field, SDLength = Self::Chall>;
    /// Hasher implementation of `VOLEHash`
    type VoleHasher: VoleHasherInit<
            Self::Field,
            SDLength = Self::Chall1,
            OutputLength = Self::VoleHasherOutputLength,
        >;
    /// Associated random oracle
    type RandomOracle: RandomOracle;
    /// Associated PRG
    type PRG: PseudoRandomGenerator<KeySize = Self::LambdaBytes>;
    /// Security parameter (in bits)
    type Lambda: ArraySize;
    /// Security parameter (in bytes)
    type LambdaBytes: SecurityParameter;
    /// Two times the security parameter (in bytes)
    type LambdaBytesTimes2: ArraySize;
    type Chall: ArraySize;
    type Chall1: ArraySize;
    type VoleHasherOutputLength: ArraySize;
    /// Hash `v` row by row using [`Self::ZKHasher`] and update `h2_hasher` with the results
    fn hash_v_matrix(
        h2_hasher: &mut impl Hasher,
        v: &[Array<u8, impl ArraySize>],
        chall1: &Array<u8, Self::Chall1>,
    ) {
        let vole_hasher = Self::VoleHasher::new_vole_hasher(chall1);
        for vi in v {
            // Hash column-wise
            h2_hasher.update(VoleHasherProcess::process(&vole_hasher, vi).as_slice());
        }
    }
    /// Hash `u` using [`Self::ZKHasher`] and write the result into `signature_u`
    fn hash_u_vector(
        signature_u: &mut [u8],
        u: &Array<u8, impl ArraySize>,
        chall1: &Array<u8, Self::Chall1>,
    ) {
        let vole_hasher_u = Self::VoleHasher::new_vole_hasher(chall1);
        signature_u.copy_from_slice(vole_hasher_u.process(u).as_slice());
    }
    /// Hash `q` row by row using [`Self::ZKHasher`] and update `h2_hasher` with the results
    fn hash_q_matrix(
        h2_hasher: &mut impl Hasher,
        q: &[Array<u8, impl ArraySize>],
        u_tilde_sig: &[u8],
        chall1: &Array<u8, Self::Chall1>,
        decoded_chall3_iter: impl Iterator<Item = u8>,
    ) {
        let vole_hasher = Self::VoleHasher::new_vole_hasher(chall1);
        for (q_i, d_i) in zip(q, decoded_chall3_iter) {
            // ::12
            let mut q_tilde = vole_hasher.process(q_i);
            // ::14
            if d_i == 1 {
                xor_arrays_inplace(&mut q_tilde, u_tilde_sig);
            }
            // ::15
            h2_hasher.update(&q_tilde);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BaseParams128<F>(PhantomData<F>)
where
    F: BigGaloisField;

impl<F> BaseParameters for BaseParams128<F>
where
    F: BigGaloisField<Length = U16>,
{
    type Field = F;
    type ZKHasher = ZKHasher<Self::Field>;
    type VoleHasher = VoleHasher<Self::Field>;
    type RandomOracle = RandomOracleShake128;
    type PRG = PRG128;

    type Lambda = U128;
    type LambdaBytes = U16;
    type LambdaBytesTimes2 = U32;

    type Chall = Sum<U8, Prod<U3, Self::LambdaBytes>>;
    type Chall1 = Sum<U8, Prod<U5, Self::LambdaBytes>>;
    type VoleHasherOutputLength = Sum<Self::LambdaBytes, B>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BaseParams192<F = GF192>(PhantomData<F>);

impl<F> BaseParameters for BaseParams192<F>
where
    F: BigGaloisField<Length = U24>,
{
    type Field = F;
    type ZKHasher = ZKHasher<Self::Field>;
    type VoleHasher = VoleHasher<Self::Field>;
    type RandomOracle = RandomOracleShake256;
    type PRG = PRG192;

    type Lambda = U192;
    type LambdaBytes = U24;
    type LambdaBytesTimes2 = U48;

    type Chall = Sum<U8, Prod<U3, Self::LambdaBytes>>;
    type Chall1 = Sum<U8, Prod<U5, Self::LambdaBytes>>;
    type VoleHasherOutputLength = Sum<Self::LambdaBytes, B>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BaseParams256<F = GF256>(PhantomData<F>);

impl<F> BaseParameters for BaseParams256<F>
where
    F: BigGaloisField<Length = U32>,
{
    type Field = F;
    type ZKHasher = ZKHasher<Self::Field>;
    type VoleHasher = VoleHasher<Self::Field>;
    type RandomOracle = RandomOracleShake256;
    type PRG = PRG256;

    type Lambda = U256;
    type LambdaBytes = U32;
    type LambdaBytesTimes2 = U64;

    type Chall = Sum<U8, Prod<U3, Self::LambdaBytes>>;
    type Chall1 = Sum<U8, Prod<U5, Self::LambdaBytes>>;
    type VoleHasherOutputLength = Sum<Self::LambdaBytes, B>;
}

pub(crate) trait OWFParameters: Sized {
    // Base parameters of the OWF
    type BaseParams: BaseParameters<Lambda = Self::Lambda, LambdaBytes = Self::LambdaBytes>;
    /// Length of secret key (in bytes)
    type SK: ArraySize;
    /// Length of public key (in bytes)
    type PK: ArraySize;
    /// The input size of the OWF (in bytes)
    type InputSize: ArraySize + Mul<U8, Output: ArraySize>;
    /// The output size of the OWF (in bytes)
    type OutputSize: ArraySize + Mul<U8, Output: ArraySize>;
    /// Security parameter (in bits)
    type Lambda: ArraySize + Mul<U2, Output: ArraySize>;
    /// Security parameter (in bytes)
    type LambdaBytes: SecurityParameter
        + Mul<Self::NLeafCommit, Output: ArraySize>
        + Mul<U2, Output = Self::LambdaBytesTimes2>
        + Mul<U8, Output = Self::Lambda>;
    /// Two times the security parameter (in bytes)
    type LambdaBytesTimes2: ArraySize + Add<Self::LBytes, Output = Self::LProdLambdaBytes>;
    /// Extra length padding for the VOLE check
    type B: ArraySize;
    /// Witness length for the zk proof (in bytes)
    type LBytes: ArraySize + Mul<U8, Output = Self::L>;
    /// Witness length for the zk proof (in bits)
    type L: ArraySize;
    /// Witness length plus extra randomness for VOLE + ZK checks
    type LHatBytes: ArraySize + Mul<U8, Output: ArraySize>;
    /// Number of message blocks
    type Beta: ArraySize;
    /// Number of 32-bit words in key
    type NK: ArraySize;
    /// Number of encryption rounds
    type R: ArraySize;
    /// Number of S-boxes in key schedule
    type SKe: ArraySize + Mul<U8, Output: ArraySize>;
    /// Number of witness bits for key schedule (in bits)
    type LKe: ArraySize;
    /// Number of witness bits for key schedule (in bytes)
    type LKeBytes: ArraySize + Mul<U8, Output = Self::LKe>;
    /// Number of witness bits for encryption (in bits)
    type LEnc: ArraySize;
    /// Number of witness bits for encryption (in bytes)
    type LEncBytes: ArraySize + Mul<U8, Output: ArraySize>;
    /// Block size (in 32-bit words)
    type NSt: ArraySize + Mul<U4, Output = Self::NStBytes>;
    /// Block size (in bytes)
    type NStBytes: SecurityParameter
        + Mul<U8, Output = Self::NStBits>
        + Div<U2, Output: ArraySize + Mul<U8, Output: ArraySize>>;
    /// Block size (in bits)
    type NStBits: ArraySize
        + Mul<U4, Output: ArraySize>
        + Div<U2, Output: ArraySize + Mul<U8, Output: ArraySize>>;
    /// Number of Lambda-bit blocks in each leaf commitment
    type NLeafCommit: ArraySize;
    /// Result of [`Self::L`] * [`Self::Lambda`] (in bytes)
    type LProdLambdaBytes: ArraySize + Mul<U8, Output: ArraySize>;
    /// Result of ([`Self::R`] + 1) * 128 (in bytes)
    type R1Times128Bytes: ArraySize
        + Mul<U8, Output = Self::R1Times128>
        + Sub<Self::LKeBytes, Output: ArraySize>;
    /// Result of ([`Self::R`] + 1) * 128 (in bits)
    type R1Times128: ArraySize + Sub<Self::LKe, Output: ArraySize>;
    /// Result of [`Self::LKe`] - [`Self::Lambda`] (in bytes)
    type LKeMinusLambdaBytes: ArraySize + Mul<U8, Output: ArraySize>;
    /// Result of [`Self::LKe`] - [`Self::Lambda`] (in bits)
    type LKeMinusLambda: ArraySize;

    /// Returns whether the OWF is used in EM mode
    const IS_EM: bool;

    /// Applies the OWF using the secret key `key` to `input` and writes the result in the `output` slice
    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]);

    /// Compute the extended witness from `owf_key` and `owf_input`
    fn extendwitness(
        owf_key: &Array<u8, Self::LambdaBytes>,
        owf_input: &Array<u8, Self::InputSize>,
    ) -> Box<Array<u8, Self::LBytes>>;

    /// Compute the extended witness using the secret key `sk`
    fn witness(sk: &SecretKey<Self>) -> Box<Array<u8, Self::LBytes>> {
        Self::extendwitness(&sk.owf_key, &sk.pk.owf_input)
    }

    /// Generates the prover's Quicksilver constraints
    fn prove(
        w: &Array<u8, Self::LBytes>,
        u: &Array<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall: &Array<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, v, pk, chall)
    }

    /// Derives the prover's challenge that can be used to verify the Quicksilver constraints
    fn verify(
        q: CstrntsVal<Self>,
        d: &Array<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &Array<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &Array<u8, Self::LambdaBytes>,
        a1_tilde: &Array<u8, Self::LambdaBytes>,
        a2_tilde: &Array<u8, Self::LambdaBytes>,
    ) -> OWFField<Self> {
        aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
    }

    /// Generates the prover's secret key using the input generator
    fn keygen_with_rng<R: Rng + ?Sized>(rng: &mut R) -> SecretKey<Self> {
        let mut owf_key = Array::default();

        loop {
            rng.fill_bytes(&mut owf_key);
            if owf_key[0] & 0b11 != 0b11 {
                break;
            }
        }

        let mut owf_input = Array::default();
        rng.fill_bytes(&mut owf_input);

        let mut owf_output = Array::default();
        Self::evaluate_owf(&owf_key, &owf_input, &mut owf_output);

        SecretKey {
            owf_key,
            pk: PublicKey {
                owf_input,
                owf_output,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF128<F = GF128>(PhantomData<F>);

impl<F> OWFParameters for OWF128<F>
where
    F: BigGaloisField<Length = U16>,
{
    type BaseParams = BaseParams128<F>;
    type InputSize = U16;
    type OutputSize = U16;

    type B = U16;
    type Lambda = U128;
    type LambdaBytes = U16;
    type LambdaBytesTimes2 = Prod<Self::LambdaBytes, U2>;
    type LBytes = U160;
    type L = Prod<Self::LBytes, U8>;
    type LHatBytes = LHatBytes<Self::LBytes, Self::LambdaBytes, Self::B>;

    type NK = U4;
    type R = U10;
    type SKe = U40;
    type Beta = U1;
    type LKe = U448;
    type LKeBytes = Quot<Self::LKe, U8>;
    type LEnc = U832;
    type LEncBytes = Quot<Self::LEnc, U8>;
    type NSt = U4;
    type NStBytes = Prod<Self::NSt, U4>;
    type NStBits = Prod<Self::NStBytes, U8>;
    type NLeafCommit = U3;
    type LProdLambdaBytes = Sum<Self::LambdaBytesTimes2, Self::LBytes>;

    type R1Times128 = Prod<Sum<Self::R, U1>, U128>;
    type R1Times128Bytes = Quot<Self::R1Times128, U8>;

    type LKeMinusLambda = Diff<Self::LKe, Self::Lambda>;
    type LKeMinusLambdaBytes = Quot<Self::LKeMinusLambda, U8>;

    type SK = U32;
    type PK = U32;

    const IS_EM: bool = false;

    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]) {
        let aes = Aes128Enc::new(array_ref(key));
        aes.encrypt_block_b2b(array_ref(input), array_mut(output));
    }

    #[inline]
    fn extendwitness(
        owf_key: &Array<u8, Self::LambdaBytes>,
        owf_input: &Array<u8, Self::InputSize>,
    ) -> Box<Array<u8, Self::LBytes>> {
        aes_extendedwitness::<Self>(owf_key, owf_input)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF192<F = GF192>(PhantomData<F>);

impl<F> OWFParameters for OWF192<F>
where
    F: BigGaloisField<Length = U24>,
{
    type BaseParams = BaseParams192<F>;
    type InputSize = U16;
    type OutputSize = U32;

    type B = U16;
    type Lambda = U192;
    type LambdaBytes = U24;
    type LambdaBytesTimes2 = Prod<Self::LambdaBytes, U2>;
    type LBytes = U312;
    type L = Prod<Self::LBytes, U8>;
    type LHatBytes = LHatBytes<Self::LBytes, Self::LambdaBytes, Self::B>;
    type LProdLambdaBytes = Sum<Self::LambdaBytesTimes2, Self::LBytes>;

    type NK = U6;
    type R = U12;
    type SKe = U32;
    type Beta = U2;
    type LKe = U448;
    type LKeBytes = Quot<Self::LKe, U8>;
    type LEnc = U1024;
    type LEncBytes = Quot<Self::LEnc, U8>;
    type NSt = U4;
    type NStBytes = Prod<Self::NSt, U4>;
    type NStBits = Prod<Self::NStBytes, U8>;
    type NLeafCommit = U3;

    type R1Times128 = Prod<Sum<Self::R, U1>, U128>;
    type R1Times128Bytes = Quot<Self::R1Times128, U8>;

    type LKeMinusLambda = Diff<Self::LKe, Self::Lambda>;
    type LKeMinusLambdaBytes = Quot<Self::LKeMinusLambda, U8>;

    type SK = U40;
    type PK = U48;

    const IS_EM: bool = false;

    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]) {
        let aes = Aes192Enc::new(array_ref(key));
        aes.encrypt_block_b2b(array_ref(input), array_mut(&mut output[..16]));

        let mut input = array_ref(input).to_owned();
        input[0] ^= 1;

        aes.encrypt_block_b2b(&input, array_mut(&mut output[16..]));
    }

    #[inline]
    fn extendwitness(
        owf_key: &Array<u8, Self::LambdaBytes>,
        owf_input: &Array<u8, Self::InputSize>,
    ) -> Box<Array<u8, Self::LBytes>> {
        aes_extendedwitness::<Self>(owf_key, owf_input)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF256<F = GF256>(PhantomData<F>);

impl<F> OWFParameters for OWF256<F>
where
    F: BigGaloisField<Length = U32>,
{
    type BaseParams = BaseParams256<F>;
    type InputSize = U16;
    type OutputSize = U32;

    type B = U16;
    type Lambda = U256;
    type LambdaBytes = U32;
    type LambdaBytesTimes2 = Prod<Self::LambdaBytes, U2>;
    type LBytes = U388;
    type L = Prod<Self::LBytes, U8>;
    type LHatBytes = LHatBytes<Self::LBytes, Self::LambdaBytes, Self::B>;
    type LProdLambdaBytes = Sum<Self::LambdaBytesTimes2, Self::LBytes>;

    type NK = U8;
    type R = U14;
    type SKe = U52;
    type Beta = U2;
    type LKe = U672;
    type LKeBytes = Quot<Self::LKe, U8>;
    type LEnc = U1216;
    type LEncBytes = Quot<Self::LEnc, U8>;
    type NSt = U4;
    type NStBytes = Prod<Self::NSt, U4>;
    type NStBits = Prod<Self::NStBytes, U8>;
    type NLeafCommit = U3;

    type R1Times128 = Prod<Sum<Self::R, U1>, U128>;
    type R1Times128Bytes = Quot<Self::R1Times128, U8>;

    type LKeMinusLambda = Diff<Self::LKe, Self::Lambda>;
    type LKeMinusLambdaBytes = Quot<Self::LKeMinusLambda, U8>;

    type SK = U48;
    type PK = U48;

    const IS_EM: bool = false;

    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]) {
        let aes = Aes256Enc::new(array_ref(key));
        aes.encrypt_block_b2b(array_ref(input), array_mut(&mut output[..16]));

        let mut input = array_ref(input).to_owned();
        input[0] ^= 1;

        aes.encrypt_block_b2b(&input, array_mut(&mut output[16..]));
    }

    #[inline]
    fn extendwitness(
        owf_key: &Array<u8, Self::LambdaBytes>,
        owf_input: &Array<u8, Self::InputSize>,
    ) -> Box<Array<u8, Self::LBytes>> {
        aes_extendedwitness::<Self>(owf_key, owf_input)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF128EM<F = GF128>(PhantomData<F>);

impl<F> OWFParameters for OWF128EM<F>
where
    F: BigGaloisField<Length = U16>,
{
    type BaseParams = BaseParams128<F>;
    type InputSize = U16;
    type OutputSize = U16;

    type B = U16;
    type Lambda = U128;
    type LambdaBytes = U16;
    type LambdaBytesTimes2 = Prod<Self::LambdaBytes, U2>;
    type LBytes = U120;
    type L = Prod<Self::LBytes, U8>;
    type LHatBytes = LHatBytes<Self::LBytes, Self::LambdaBytes, Self::B>;
    type LProdLambdaBytes = Sum<Self::LambdaBytesTimes2, Self::LBytes>;

    type NK = U4;
    type NSt = U4;
    type NStBytes = Prod<Self::NSt, U4>;
    type NStBits = Prod<Self::NStBytes, U8>;
    type R = U10;
    type SKe = U40;
    type Beta = U1;
    type LKe = U128;
    type LKeBytes = Quot<Self::LKe, U8>;
    type LEnc = U832;
    type LEncBytes = Quot<Self::LEnc, U8>;
    type NLeafCommit = U2;

    type R1Times128 = Prod<Sum<Self::R, U1>, U128>;
    type R1Times128Bytes = Quot<Self::R1Times128, U8>;

    type LKeMinusLambda = Diff<Self::LKe, Self::Lambda>;
    type LKeMinusLambdaBytes = Quot<Self::LKeMinusLambda, U8>;

    type SK = U32;
    type PK = U32;

    const IS_EM: bool = true;

    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]) {
        let aes = Aes128Enc::new(array_ref(input));
        aes.encrypt_block_b2b(array_ref(key), array_mut(output));
        for idx in 0..Self::InputSize::USIZE {
            output[idx] ^= key[idx];
        }
    }

    #[inline]
    fn extendwitness(
        owf_key: &Array<u8, Self::LambdaBytes>,
        owf_input: &Array<u8, Self::InputSize>,
    ) -> Box<Array<u8, Self::LBytes>> {
        aes_extendedwitness::<Self>(owf_input, owf_key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF192EM<F = GF192>(PhantomData<F>)
where
    F: BigGaloisField<Length = U24>;

type U1536 = Sum<U1024, U512>;

impl<F> OWFParameters for OWF192EM<F>
where
    F: BigGaloisField<Length = U24>,
{
    type BaseParams = BaseParams192<F>;
    type InputSize = U24;
    type OutputSize = U24;

    type B = U16;
    type Lambda = U192;
    type LambdaBytes = U24;
    type LambdaBytesTimes2 = Prod<Self::LambdaBytes, U2>;
    type LBytes = U216;
    type L = Prod<Self::LBytes, U8>;
    type LHatBytes = LHatBytes<Self::LBytes, Self::LambdaBytes, Self::B>;
    type LProdLambdaBytes = Sum<Self::LambdaBytesTimes2, Self::LBytes>;

    type NK = U6;
    type NSt = U6;
    type NStBytes = Prod<Self::NSt, U4>;
    type NStBits = Prod<Self::NStBytes, U8>;
    type Beta = U1;
    type R = U12;
    type SKe = U52;
    type LKe = U192;
    type LKeBytes = Quot<Self::LKe, U8>;
    type LEnc = U1536;
    type LEncBytes = Quot<Self::LEnc, U8>;
    type NLeafCommit = U2;

    type R1Times128 = Prod<Sum<Self::R, U1>, Self::Lambda>;
    type R1Times128Bytes = Quot<Self::R1Times128, U8>;

    type LKeMinusLambda = Diff<Self::LKe, Self::Lambda>;
    type LKeMinusLambdaBytes = Quot<Self::LKeMinusLambda, U8>;

    type SK = U48;
    type PK = U48;

    const IS_EM: bool = true;

    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]) {
        let aes = Rijndael192::new(array_ref(input));
        aes.encrypt_block_b2b(array_ref(key), array_mut(output));
        for idx in 0..Self::InputSize::USIZE {
            output[idx] ^= key[idx];
        }
    }

    #[inline]
    fn extendwitness(
        owf_key: &Array<u8, Self::LambdaBytes>,
        owf_input: &Array<u8, Self::InputSize>,
    ) -> Box<Array<u8, Self::LBytes>> {
        aes_extendedwitness::<Self>(owf_input, owf_key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF256EM<F = GF256>(PhantomData<F>)
where
    F: BigGaloisField<Length = U32>;

impl<F> OWFParameters for OWF256EM<F>
where
    F: BigGaloisField<Length = U32>,
{
    type BaseParams = BaseParams256<F>;
    type InputSize = U32;
    type OutputSize = U32;

    type B = U16;
    type Lambda = U256;
    type LambdaBytes = U32;
    type LambdaBytesTimes2 = Prod<Self::LambdaBytes, U2>;
    type LBytes = U336;
    type L = Prod<Self::LBytes, U8>;
    type LHatBytes = LHatBytes<Self::LBytes, Self::LambdaBytes, Self::B>;
    type LProdLambdaBytes = Sum<Self::LambdaBytesTimes2, Self::LBytes>;

    type NK = U8;
    type NSt = U8;
    type NStBytes = Prod<Self::NSt, U4>;
    type NStBits = Prod<Self::NStBytes, U8>;
    type Beta = U1;
    type R = U14;
    type SKe = U60;
    type LKe = U256;
    type LKeBytes = Quot<Self::LKe, U8>;
    type LEnc = U2432;
    type LEncBytes = Quot<Self::LEnc, U8>;
    type NLeafCommit = U2;

    type R1Times128 = Prod<Sum<Self::R, U1>, Self::Lambda>;
    type R1Times128Bytes = Quot<Self::R1Times128, U8>;

    type LKeMinusLambda = Diff<Self::LKe, Self::Lambda>;
    type LKeMinusLambdaBytes = Quot<Self::LKeMinusLambda, U8>;

    type SK = U64;
    type PK = U64;

    const IS_EM: bool = true;

    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]) {
        let aes = Rijndael256::new(array_ref(input));
        aes.encrypt_block_b2b(array_ref(key), array_mut(output));
        for idx in 0..Self::InputSize::USIZE {
            output[idx] ^= key[idx];
        }
    }

    #[inline]
    fn extendwitness(
        owf_key: &Array<u8, Self::LambdaBytes>,
        owf_input: &Array<u8, Self::InputSize>,
    ) -> Box<Array<u8, Self::LBytes>> {
        aes_extendedwitness::<Self>(owf_input, owf_key)
    }
}

pub(crate) trait TauParameters {
    /// Number of small-VOLE instances
    type Tau: ArraySize;
    /// Bit-length of the larger small-VOLE instances (the smaller small-VOLE instances have length K-1)
    type K: ArraySize;
    /// Number of smaller small-VOLE instances
    type Tau0: ArraySize;
    /// Number of larger small-VOLE instances
    type Tau1: ArraySize;
    /// Number of leaves of the GGM tree
    const L: usize;
    /// Threshold for the maximum opening size of the GGM tree
    type Topen: ArraySize;

    #[inline]
    fn tau1_offset_unchecked(i: usize) -> usize {
        Self::K::USIZE * i
    }

    #[inline]
    fn tau0_offset_unchecked(i: usize) -> usize {
        Self::Tau1::USIZE * (Self::K::USIZE) + (Self::K::USIZE - 1) * (i - Self::Tau1::USIZE)
    }

    /// Retuns leaf offset of the i-th small-VOLE instance within the GGM tree
    fn bavc_index_offset(i: usize) -> usize {
        if i < Self::Tau1::USIZE {
            return (1 << Self::K::USIZE) * i;
        }
        Self::Tau1::USIZE * (1 << Self::K::USIZE)
            + (1 << (Self::K::USIZE - 1)) * (i - Self::Tau1::USIZE)
    }

    /// Returns the maximum depth of the i-th small-VOLE instance
    fn bavc_max_node_depth(i: usize) -> usize {
        if i < Self::Tau1::USIZE {
            Self::K::USIZE
        } else {
            Self::K::USIZE - 1
        }
    }

    /// Returns the maximum node index of the i-th small-VOLE instance
    fn bavc_max_node_index(i: usize) -> usize {
        1usize << Self::bavc_max_node_depth(i)
    }

    /// Maps the j-th entry of the i-th small-VOLE instance to the corresponding leaf in the GGM tree
    fn pos_in_tree(i: usize, j: usize) -> usize {
        let tmp = 1usize << (Self::K::USIZE - 1);

        if j < tmp {
            return Self::L - 1 + Self::Tau::USIZE * j + i;
        }

        // Applying mod 2^(k-1) is same as taking the k-2 LSB
        let mask = tmp - 1;
        Self::L - 1 + Self::Tau::USIZE * tmp + Self::Tau1::USIZE * (j & mask) + i
    }

    /// Returns the required array length for generating the vole correlations in [`crate::vole::convert_to_vole`]
    fn vole_array_length(i: usize) -> usize {
        let n = Self::bavc_max_node_index(i);
        n / 2
            - (2..Self::bavc_max_node_depth(i))
                .map(|d| n / (1 << d) - 1)
                .sum::<usize>()
    }
}

// FAEST
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau128Small;

impl TauParameters for Tau128Small {
    type Tau = U11;
    type K = U12;
    const L: usize = 22528;
    type Tau0 = U11;
    type Tau1 = U0;
    type Topen = U102;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau128Fast;

impl TauParameters for Tau128Fast {
    type Tau = U16;
    type K = U8;
    const L: usize = 3072;
    type Tau0 = U8;
    type Tau1 = U8;
    type Topen = U110;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau192Small;

impl TauParameters for Tau192Small {
    type Tau = U16;
    type K = U12;
    const L: usize = 40960;
    type Tau0 = U12;
    type Tau1 = U4;
    type Topen = U162;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau192Fast;

impl TauParameters for Tau192Fast {
    type Tau = U24;
    type K = U8;
    const L: usize = 5120;
    type Tau0 = U8;
    type Tau1 = U16;
    type Topen = U163;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau256Small;

impl TauParameters for Tau256Small {
    type Tau = U22;
    type K = U12;
    const L: usize = 61440;
    type Tau0 = U14;
    type Tau1 = U8;
    type Topen = U245;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau256Fast;

impl TauParameters for Tau256Fast {
    type Tau = U32;
    type K = U8;
    const L: usize = 7168;
    type Tau0 = U8;
    type Tau1 = U24;
    type Topen = U246;
}

// FAEST-EM
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau128SmallEM;

impl TauParameters for Tau128SmallEM {
    type Tau = U11;
    type K = U12;
    const L: usize = 22528;
    type Tau0 = U11;
    type Tau1 = U0;
    type Topen = U103;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau128FastEM;

impl TauParameters for Tau128FastEM {
    type Tau = U16;
    type K = U8;
    const L: usize = 3072;
    type Tau0 = U8;
    type Tau1 = U8;
    type Topen = U112;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau192SmallEM;

impl TauParameters for Tau192SmallEM {
    type Tau = U16;
    type K = U12;
    const L: usize = 49152;
    type Tau0 = U8;
    type Tau1 = U8;
    type Topen = U162;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau192FastEM;

impl TauParameters for Tau192FastEM {
    type Tau = U24;
    type K = U8;
    const L: usize = 5120;
    type Tau0 = U8;
    type Tau1 = U16;
    type Topen = U176;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau256SmallEM;

impl TauParameters for Tau256SmallEM {
    type Tau = U22;
    type K = U12;
    const L: usize = 61440;
    type Tau0 = U14;
    type Tau1 = U8;
    type Topen = U218;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau256FastEM;

impl TauParameters for Tau256FastEM {
    type Tau = U32;
    type K = U8;
    const L: usize = 7168;
    type Tau0 = U8;
    type Tau1 = U24;
    type Topen = U234;
}

pub(crate) trait FAESTParameters {
    /// Associated [`OWFParameters`] type
    type OWF: OWFParameters;
    /// Associated [`TauParameters`] type
    type Tau: TauParameters<Tau = <<Self as FAESTParameters>::BAVC as BatchVectorCommitment>::Tau>;
    /// Associated [`BatchVectorCommitment`] type
    type BAVC: BatchVectorCommitment<
            RO = <<Self::OWF as OWFParameters>::BaseParams as BaseParameters>::RandomOracle,
            PRG = <<Self::OWF as OWFParameters>::BaseParams as BaseParameters>::PRG,
            TAU = Self::Tau,
            LambdaBytes = <<Self::OWF as OWFParameters>::BaseParams as BaseParameters>::LambdaBytes,
            NLeafCommit = <Self::OWF as OWFParameters>::NLeafCommit,
        >;
    /// Grinding parameter specifying how many upperbits of the Fiat-Shamir challenge must be set to 0
    type WGRIND: ArraySize;
    /// Size of the signature (in bytes)
    const SIGNATURE_SIZE: usize;

    #[inline]
    fn get_decom_size() -> usize {
        // coms
        <<Self as FAESTParameters>::OWF as OWFParameters>::NLeafCommit::USIZE
            * <<Self as FAESTParameters>::OWF as OWFParameters>::LambdaBytes::USIZE
            * <<Self as FAESTParameters>::Tau as TauParameters>::Tau::USIZE
            +
            // nodes
            <<Self as FAESTParameters>::Tau as TauParameters>::Topen::USIZE
                * <<Self as FAESTParameters>::OWF as OWFParameters>::LambdaBytes::USIZE
    }

    /// Returns an iterator over the individual bits of the i-th VOLE sub-challenge (i.e., the one associated to the i-th small-vole instance)
    fn decode_challenge_as_iter(chal: &[u8]) -> impl Iterator<Item = u8> + '_ {
        (0..<Self::Tau as TauParameters>::Tau1::USIZE + <Self::Tau as TauParameters>::Tau0::USIZE)
            .flat_map(|i| {
                let lo = <Self::Tau as TauParameters>::bavc_index_offset(i);
                let hi = <Self::Tau as TauParameters>::bavc_index_offset(i + 1);
                (lo..hi).map(|j| (chal[j / 8] >> (j % 8)) & 1)
            })
            .chain(repeat_n(0, Self::WGRIND::USIZE))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST128sParameters<F = GF128>(PhantomData<F>);

impl<F> FAESTParameters for FAEST128sParameters<F>
where
    F: BigGaloisField<Length = U16> + BaseField,
{
    type OWF = OWF128<F>;
    type Tau = Tau128Small;
    type BAVC = BAVC128Small<F>;
    type WGRIND = U7;
    const SIGNATURE_SIZE: usize = 4506;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST128fParameters<F = GF128>(PhantomData<F>);

impl<F> FAESTParameters for FAEST128fParameters<F>
where
    F: BigGaloisField<Length = U16> + BaseField,
{
    type OWF = OWF128<F>;
    type Tau = Tau128Fast;
    type BAVC = BAVC128Fast<F>;
    type WGRIND = U8;
    const SIGNATURE_SIZE: usize = 5924;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST192sParameters<F = GF192>(PhantomData<F>);

impl<F> FAESTParameters for FAEST192sParameters<F>
where
    F: BigGaloisField<Length = U24> + BaseField,
{
    type OWF = OWF192<F>;
    type Tau = Tau192Small;
    type BAVC = BAVC192Small<F>;
    type WGRIND = U12;
    const SIGNATURE_SIZE: usize = 11260;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST192fParameters<F = GF192>(PhantomData<F>);

impl<F> FAESTParameters for FAEST192fParameters<F>
where
    F: BigGaloisField<Length = U24> + BaseField,
{
    type OWF = OWF192<F>;
    type Tau = Tau192Fast;
    type BAVC = BAVC192Fast<F>;
    type WGRIND = U8;
    const SIGNATURE_SIZE: usize = 14948;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST256sParameters<F = GF256>(PhantomData<F>);

impl<F> FAESTParameters for FAEST256sParameters<F>
where
    F: BigGaloisField<Length = U32> + BaseField,
{
    type OWF = OWF256<F>;
    type Tau = Tau256Small;
    type BAVC = BAVC256Small<F>;
    type WGRIND = U6;
    const SIGNATURE_SIZE: usize = 20696;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST256fParameters<F = GF256>(PhantomData<F>);

impl<F> FAESTParameters for FAEST256fParameters<F>
where
    F: BigGaloisField<Length = U32> + BaseField,
{
    type OWF = OWF256<F>;
    type Tau = Tau256Fast;
    type BAVC = BAVC256Fast<F>;
    type WGRIND = U8;
    const SIGNATURE_SIZE: usize = 26548;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM128sParameters<F = GF128>(PhantomData<F>);

impl<F> FAESTParameters for FAESTEM128sParameters<F>
where
    F: BigGaloisField<Length = U16> + BaseField,
{
    type OWF = OWF128EM<F>;
    type Tau = Tau128SmallEM;
    type BAVC = BAVC128SmallEM<F>;
    type WGRIND = U7;
    const SIGNATURE_SIZE: usize = 3906;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM128fParameters<F = GF128>(PhantomData<F>);

impl<F> FAESTParameters for FAESTEM128fParameters<F>
where
    F: BigGaloisField<Length = U16> + BaseField,
{
    type OWF = OWF128EM<F>;
    type Tau = Tau128FastEM;
    type BAVC = BAVC128FastEM<F>;
    type WGRIND = U8;
    const SIGNATURE_SIZE: usize = 5060;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM192sParameters<F = GF192>(PhantomData<F>);

impl<F> FAESTParameters for FAESTEM192sParameters<F>
where
    F: BigGaloisField<Length = U24> + BaseField,
{
    type OWF = OWF192EM<F>;
    type Tau = Tau192SmallEM;
    type BAVC = BAVC192SmallEM<F>;
    type WGRIND = U8;
    const SIGNATURE_SIZE: usize = 9340;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM192fParameters<F = GF192>(PhantomData<F>);

impl<F> FAESTParameters for FAESTEM192fParameters<F>
where
    F: BigGaloisField<Length = U24> + BaseField,
{
    type OWF = OWF192EM<F>;
    type Tau = Tau192FastEM;
    type BAVC = BAVC192FastEM<F>;
    type WGRIND = U8;
    const SIGNATURE_SIZE: usize = 12380;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM256sParameters<F = GF256>(PhantomData<F>);

impl<F> FAESTParameters for FAESTEM256sParameters<F>
where
    F: BigGaloisField<Length = U32> + BaseField,
{
    type OWF = OWF256EM<F>;
    type Tau = Tau256SmallEM;
    type BAVC = BAVC256SmallEM<F>;
    type WGRIND = U6;
    const SIGNATURE_SIZE: usize = 17984;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM256fParameters<F = GF256>(PhantomData<F>);

impl<F> FAESTParameters for FAESTEM256fParameters<F>
where
    F: BigGaloisField<Length = U32> + BaseField,
{
    type OWF = OWF256EM<F>;
    type Tau = Tau256FastEM;
    type BAVC = BAVC256FastEM<F>;
    type WGRIND = U8;
    const SIGNATURE_SIZE: usize = 23476;
}

pub(crate) type BAVC128Small<F> = Bavc<RandomOracleShake128, PRG128, LeafHasher128<F>, Tau128Small>;
pub(crate) type BAVC128Fast<F> = Bavc<RandomOracleShake128, PRG128, LeafHasher128<F>, Tau128Fast>;
pub(crate) type BAVC192Small<F> = Bavc<RandomOracleShake256, PRG192, LeafHasher192<F>, Tau192Small>;
pub(crate) type BAVC192Fast<F> = Bavc<RandomOracleShake256, PRG192, LeafHasher192<F>, Tau192Fast>;
pub(crate) type BAVC256Small<F> = Bavc<RandomOracleShake256, PRG256, LeafHasher256<F>, Tau256Small>;
pub(crate) type BAVC256Fast<F> = Bavc<RandomOracleShake256, PRG256, LeafHasher256<F>, Tau256Fast>;

pub(crate) type BAVC128SmallEM<F> =
    BavcEm<RandomOracleShake128, PRG128, LeafHasher128<F>, Tau128SmallEM>;
pub(crate) type BAVC128FastEM<F> =
    BavcEm<RandomOracleShake128, PRG128, LeafHasher128<F>, Tau128FastEM>;
pub(crate) type BAVC192SmallEM<F> =
    BavcEm<RandomOracleShake256, PRG192, LeafHasher192<F>, Tau192SmallEM>;
pub(crate) type BAVC192FastEM<F> =
    BavcEm<RandomOracleShake256, PRG192, LeafHasher192<F>, Tau192FastEM>;
pub(crate) type BAVC256SmallEM<F> =
    BavcEm<RandomOracleShake256, PRG256, LeafHasher256<F>, Tau256SmallEM>;
pub(crate) type BAVC256FastEM<F> =
    BavcEm<RandomOracleShake256, PRG256, LeafHasher256<F>, Tau256FastEM>;

#[cfg(test)]
mod test {
    use super::*;

    #[generic_tests::define]
    mod owf_parameters {
        use super::*;

        #[test]
        fn lambda<O: OWFParameters>() {
            assert!(O::Lambda::USIZE == 128 || O::Lambda::USIZE == 192 || O::Lambda::USIZE == 256);
            assert_eq!(O::LambdaBytes::USIZE * 8, O::Lambda::USIZE);
        }

        #[test]
        fn pk_sk_size<O: OWFParameters>() {
            assert_eq!(O::SK::USIZE, O::InputSize::USIZE + O::LambdaBytes::USIZE);
            assert_eq!(O::PK::USIZE, O::InputSize::USIZE + O::OutputSize::USIZE);
        }

        #[test]
        fn owf_parameters<O: OWFParameters>() {
            assert_eq!(O::LKe::USIZE % 8, 0);
            assert_eq!(O::LKeBytes::USIZE * 8, O::LKe::USIZE);
            assert_eq!(O::LEnc::USIZE % 8, 0);
            assert_eq!(O::L::USIZE % 8, 0);
            assert_eq!(O::LBytes::USIZE * 8, O::L::USIZE);
        }

        #[instantiate_tests(<OWF128>)]
        mod owf_128 {}

        #[instantiate_tests(<OWF192>)]
        mod owf_192 {}

        #[instantiate_tests(<OWF256>)]
        mod owf_256 {}

        #[instantiate_tests(<OWF128EM>)]
        mod owf_em_128 {}

        #[instantiate_tests(<OWF192EM>)]
        mod owf_em_192 {}

        #[instantiate_tests(<OWF256EM>)]
        mod owf_em_256 {}
    }

    #[generic_tests::define]
    mod faest_parameters {
        use super::*;

        #[test]
        fn tau_config<P: FAESTParameters>() {
            assert_eq!(
                <P::OWF as OWFParameters>::Lambda::USIZE,
                <P::Tau as TauParameters>::Tau1::USIZE * <P::Tau as TauParameters>::K::USIZE
                    + <P::Tau as TauParameters>::Tau0::USIZE
                        * (<P::Tau as TauParameters>::K::USIZE - 1)
                    + P::WGRIND::USIZE
            );
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
}
