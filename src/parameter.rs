use std::{
    iter::repeat_n,
    marker::PhantomData,
    ops::{Add, Div, Mul, Sub},
};

use aes::{
    Aes128Enc, Aes192Enc, Aes256Enc,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray as GenericArray_AES},
};
use generic_array::{
    ArrayLength, GenericArray,
    typenum::{
        Diff, Prod, Quot, Sum, U0, U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12, U14, U16,
        U17, U20, U22, U23, U24, U26, U32, U40, U48, U52, U60, U64, U102, U103, U110, U112, U120,
        U128, U160, U162, U163, U176, U192, U216, U218, U234, U245, U246, U256, U260, U312, U336,
        U340, U380, U384, U388, U448, U476, U506, U512, U548, U672, U696, U832, U906, U924, U948,
        U984, U1000, U1024, U2048, U4096, Unsigned,
    },
};
use rand_core::RngCore;

#[allow(unused_imports)]
use crate::{
    bavc::{
        BAVC128Fast, BAVC128FastEM, BAVC128Small, BAVC128SmallEM, BAVC192Fast, BAVC192FastEM,
        BAVC192Small, BAVC192SmallEM, BAVC256Fast, BAVC256FastEM, BAVC256Small, BAVC256SmallEM,
        BatchVectorCommitment,
    },
    fields::{BigGaloisField, Field, GF128, GF192, GF256},
    internal_keys::{PublicKey, SecretKey},
    prg::{PRG128, PRG192, PRG256, PseudoRandomGenerator},
    random_oracles::{RandomOracle, RandomOracleShake128, RandomOracleShake256},
    rijndael_32::{Rijndael192, Rijndael256},
    universal_hashing::{B, VoleHasher, VoleHasherInit, ZKHasher, ZKHasherInit},
    witness::aes_extendedwitness,
    zk_constraints::{CstrntsVal, aes_prove, aes_verify},
};

#[cfg(all(feature = "opt-simd", any(target_arch = "x86", target_arch = "x86_64")))]
use crate::fields::x86_simd_large_fields::{
    GF128 as SimdGF128, GF192 as SimdGF192, GF256 as SimdGF256,
};

// FAEST signature sizes
type U4506 = Sum<Prod<U4, U1000>, U506>;
type U5924 = Sum<Prod<U5, U1000>, U924>;
type U11260 = Sum<Prod<U11, U1000>, U260>;
type U14948 = Sum<Prod<U14, U1000>, U948>;
type U20696 = Sum<Prod<U20, U1000>, U696>;
type U26548 = Sum<Prod<U26, U1000>, U548>;

// FAEST-EM signature sizes
type U3906 = Sum<Prod<U1000, U3>, U906>;
type U5060 = Sum<Prod<U1000, U5>, U60>;
type U9340 = Sum<Prod<U1000, U9>, U340>;
type U12380 = Sum<Prod<U1000, U12>, U380>;
type U17984 = Sum<Prod<U1000, U17>, U984>;
type U23476 = Sum<Prod<U1000, U23>, U476>;

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
pub(crate) type Witness<O> = Box<GenericArray<u8, <O as OWFParameters>::LBytes>>;

pub(crate) trait SecurityParameter:
    ArrayLength
    + Add<Self, Output: ArrayLength>
    + Mul<U2, Output: ArrayLength>
    + Mul<U3, Output: ArrayLength>
    + Mul<U4, Output: ArrayLength>
    + Mul<U8, Output: ArrayLength>
    + PartialEq
{
}

impl SecurityParameter for U16 {}
impl SecurityParameter for U24 {}
impl SecurityParameter for U32 {}

/// Base parameters per security level
pub(crate) trait BaseParameters {
    /// The field that is of size `2^λ` which is defined as [`Self::Lambda`]
    type Field: BigGaloisField<Length = Self::LambdaBytes> + std::fmt::Debug + std::cmp::PartialEq;
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
    type Lambda: ArrayLength;
    /// Security parameter (in bytes)
    type LambdaBytes: SecurityParameter;
    /// Two times the security parameter (in bytes)
    type LambdaBytesTimes2: ArrayLength;
    type Chall: ArrayLength;
    type Chall1: ArrayLength;
    type VoleHasherOutputLength: ArrayLength;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BaseParams128<F>(PhantomData<F>)
where
    F: BigGaloisField;

impl<F> BaseParameters for BaseParams128<F>
where
    F: BigGaloisField<Length = U16> + std::fmt::Debug + std::cmp::PartialEq,
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
    F: BigGaloisField<Length = U24> + std::fmt::Debug + std::cmp::PartialEq,
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
    F: BigGaloisField<Length = U32> + std::fmt::Debug + std::cmp::PartialEq,
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
    type SK: ArrayLength;
    /// Length of public key (in bytes)
    type PK: ArrayLength;
    /// The input size of the OWF (in bytes)
    type InputSize: ArrayLength + Mul<U8, Output: ArrayLength>;
    /// The output size of the OWF (in bytes)
    type OutputSize: ArrayLength + Mul<U8, Output: ArrayLength>;
    /// Security parameter (in bits)
    type Lambda: ArrayLength + Mul<U2, Output: ArrayLength>;
    /// Security parameter (in bytes)
    type LambdaBytes: SecurityParameter
        + Mul<Self::NLeafCommit, Output: ArrayLength>
        + Mul<U2, Output = Self::LambdaBytesTimes2>
        + Mul<U8, Output = Self::Lambda>;
    /// Two times the security parameter (in bytes)
    type LambdaBytesTimes2: ArrayLength + Add<Self::LBytes, Output = Self::LProdLambdaBytes>;
    /// Extra length padding for the VOLE check
    type B: ArrayLength;
    /// Witness length for the zk proof (in bytes)
    type LBytes: ArrayLength + Mul<U8, Output = Self::L>;
    /// Witness length for the zk proof (in bits)
    type L: ArrayLength;
    /// Witness length plus extra randomness for VOLE + ZK checks
    type LHatBytes: ArrayLength + Mul<U8, Output: ArrayLength>;
    /// Number of message blocks
    type Beta: ArrayLength;
    /// Number of 32-bit words in key
    type NK: ArrayLength;
    /// Number of encryption rounds
    type R: ArrayLength;
    /// Number of S-boxes in key schedule
    type SKe: ArrayLength + Mul<U8, Output: ArrayLength>;
    /// Number of witness bits for key schedule (in bits)
    type LKe: ArrayLength;
    /// Number of witness bits for key schedule (in bytes)
    type LKeBytes: ArrayLength + Mul<U8, Output = Self::LKe>;
    /// Number of witness bits for encryption (in bits)
    type LEnc: ArrayLength;
    /// Number of witness bits for encryption (in bytes)
    type LEncBytes: ArrayLength + Mul<U8, Output: ArrayLength>;
    /// Block size (in 32-bit words)
    type NSt: ArrayLength + Mul<U4, Output = Self::NStBytes>;
    /// Block size (in bytes)
    type NStBytes: SecurityParameter
        + Mul<U8, Output = Self::NStBits>
        + Div<U2, Output: ArrayLength + Mul<U8, Output: ArrayLength>>;
    /// Block size (in bits)
    type NStBits: ArrayLength
        + Mul<U4, Output: ArrayLength>
        + Div<U2, Output: ArrayLength + Mul<U8, Output: ArrayLength>>;
    /// Number of Lambda-bit blocks in each leaf commitment
    type NLeafCommit: ArrayLength;
    /// Result of [`Self::L`] * [`Self::Lambda`] (in bytes)
    type LProdLambdaBytes: ArrayLength + Mul<U8, Output: ArrayLength>;
    /// Result of ([`Self::R`] + 1) * 128 (in bytes)
    type R1Times128Bytes: ArrayLength
        + Mul<U8, Output = Self::R1Times128>
        + Sub<Self::LKeBytes, Output: ArrayLength>;
    /// Result of ([`Self::R`] + 1) * 128 (in bits)
    type R1Times128: ArrayLength + Sub<Self::LKe, Output: ArrayLength>;
    /// Result of [`Self::LKe`] - [`Self::Lambda`] (in bytes)
    type LKeMinusLambdaBytes: ArrayLength + Mul<U8, Output: ArrayLength>;
    /// Result of [`Self::LKe`] - [`Self::Lambda`] (in bits)
    type LKeMinusLambda: ArrayLength;

    /// Returns whether the OWF is used in EM mode
    const IS_EM: bool;

    /// Applies the OWF using the secret key `key` to `input` and writes the result in the `output` slice
    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]);

    /// Compute the extended witness from `owf_key` and `owf_input`
    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LambdaBytes>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBytes>>;

    /// Compute the extended witness using the secret key `sk`
    fn witness(sk: &SecretKey<Self>) -> Box<GenericArray<u8, Self::LBytes>> {
        Self::extendwitness(&sk.owf_key, &sk.pk.owf_input)
    }

    /// Generates the prover's Quicksilver constraints
    fn prove(
        w: &GenericArray<u8, Self::LBytes>,
        u: &GenericArray<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self>;

    /// Derives the prover's challenge that can be used to verify the Quicksilver constraints
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LambdaBytes>,
        a1_tilde: &GenericArray<u8, Self::LambdaBytes>,
        a2_tilde: &GenericArray<u8, Self::LambdaBytes>,
    ) -> OWFField<Self>;

    /// Generates the prover's secret key using the input generator
    fn keygen_with_rng(mut rng: impl RngCore) -> SecretKey<Self> {
        let mut owf_key = GenericArray::default();

        loop {
            rng.fill_bytes(&mut owf_key);
            if owf_key[0] & 0b11 != 0b11 {
                break;
            }
        }

        let mut owf_input = GenericArray::default();
        rng.fill_bytes(&mut owf_input);

        let mut owf_output = GenericArray::default();
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
    F: BigGaloisField<Length = U16> + std::fmt::Debug + std::cmp::PartialEq,
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
        let aes = Aes128Enc::new(GenericArray_AES::from_slice(key));
        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(input),
            GenericArray_AES::from_mut_slice(output),
        );
    }

    #[inline]
    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LambdaBytes>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBytes>> {
        aes_extendedwitness::<Self>(owf_key, owf_input)
    }

    #[cfg(all(
        feature = "opt-simd", // using simd optimization feature
        any(target_arch = "x86", target_arch = "x86_64"), // we're on x86/x86_64
        not(all(target_feature = "avx2", target_feature = "pclmulqdq")) // simd support can't be statically detected
    ))]
    #[inline]
    fn prove(
        w: &GenericArray<u8, Self::LBytes>,
        u: &GenericArray<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("pclmulqdq") {
            let pk: &PublicKey<OWF128<SimdGF128>> = unsafe { std::mem::transmute(pk) };
            let qs_proof = aes_prove::<OWF128<SimdGF128>>(w, u, v, pk, chall_2);
            (
                OWFField::<Self>::from(qs_proof.0.as_bytes().as_slice()),
                OWFField::<Self>::from(qs_proof.1.as_bytes().as_slice()),
                OWFField::<Self>::from(qs_proof.2.as_bytes().as_slice()),
            )
        } else {
            aes_prove::<Self>(w, u, v, pk, chall_2)
        }
    }

    #[cfg(all(
        feature = "opt-simd", // using simd optimization feature
        any(target_arch = "x86", target_arch = "x86_64"), // we're on x86/x86_64
        not(all(target_feature = "avx2", target_feature = "pclmulqdq")) // simd support can't be statically detected
    ))]
    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LambdaBytes>,
        a1_tilde: &GenericArray<u8, Self::LambdaBytes>,
        a2_tilde: &GenericArray<u8, Self::LambdaBytes>,
    ) -> OWFField<Self> {
        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("pclmulqdq") {
            let pk: &PublicKey<OWF128<SimdGF128>> = unsafe { std::mem::transmute(pk) };
            let chall3 =
                aes_verify::<OWF128<SimdGF128>>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde);
            OWFField::<Self>::from(chall3.as_bytes().as_slice())
        } else {
            aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
        }
    }

    #[cfg(any(
        not(feature = "opt-simd"),
        not(any(target_arch = "x86", target_arch = "x86_64")),
        all(target_feature = "avx2", target_feature = "pclmulqdq")
    ))]
    fn prove(
        w: &GenericArray<u8, Self::LBytes>,
        u: &GenericArray<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, v, pk, chall_2)
    }

    #[cfg(any(
        not(feature = "opt-simd"),
        not(any(target_arch = "x86", target_arch = "x86_64")),
        all(target_feature = "avx2", target_feature = "pclmulqdq")
    ))]
    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LambdaBytes>,
        a1_tilde: &GenericArray<u8, Self::LambdaBytes>,
        a2_tilde: &GenericArray<u8, Self::LambdaBytes>,
    ) -> OWFField<Self> {
        aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF192<F = GF192>(PhantomData<F>);

impl<F> OWFParameters for OWF192<F>
where
    F: BigGaloisField<Length = U24> + std::fmt::Debug + std::cmp::PartialEq,
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
        let aes = Aes192Enc::new(GenericArray_AES::from_slice(key));
        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(input),
            GenericArray_AES::from_mut_slice(&mut output[..16]),
        );

        let mut input: [u8; 16] = (*input).try_into().expect("Invalid input length");
        input[0] ^= 1;

        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(&input),
            GenericArray_AES::from_mut_slice(&mut output[16..]),
        );
    }

    #[inline]
    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LambdaBytes>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBytes>> {
        aes_extendedwitness::<Self>(owf_key, owf_input)
    }

    #[cfg(all(
        feature = "opt-simd", // using simd optimization feature
        any(target_arch = "x86", target_arch = "x86_64"), // we're on x86/x86_64
        not(all(target_feature = "avx2", target_feature = "pclmulqdq")) // simd support can't be statically detected
    ))]
    #[inline]
    fn prove(
        w: &GenericArray<u8, Self::LBytes>,
        u: &GenericArray<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("pclmulqdq") {
            let pk: &PublicKey<OWF192<SimdGF192>> = unsafe { std::mem::transmute(pk) };
            let qs_proof = aes_prove::<OWF192<SimdGF192>>(w, u, v, pk, chall_2);
            (
                OWFField::<Self>::from(qs_proof.0.as_bytes().as_slice()),
                OWFField::<Self>::from(qs_proof.1.as_bytes().as_slice()),
                OWFField::<Self>::from(qs_proof.2.as_bytes().as_slice()),
            )
        } else {
            aes_prove::<Self>(w, u, v, pk, chall_2)
        }
    }

    #[cfg(all(
        feature = "opt-simd", // using simd optimization feature
        any(target_arch = "x86", target_arch = "x86_64"), // we're on x86/x86_64
        not(all(target_feature = "avx2", target_feature = "pclmulqdq")) // simd support can't be statically detected
    ))]
    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LambdaBytes>,
        a1_tilde: &GenericArray<u8, Self::LambdaBytes>,
        a2_tilde: &GenericArray<u8, Self::LambdaBytes>,
    ) -> OWFField<Self> {
        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("pclmulqdq") {
            let pk: &PublicKey<OWF192<SimdGF192>> = unsafe { std::mem::transmute(pk) };
            let chall3 =
                aes_verify::<OWF192<SimdGF192>>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde);
            OWFField::<Self>::from(chall3.as_bytes().as_slice())
        } else {
            aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
        }
    }

    #[cfg(any(
        not(feature = "opt-simd"),
        not(any(target_arch = "x86", target_arch = "x86_64")),
        all(target_feature = "avx2", target_feature = "pclmulqdq")
    ))]
    fn prove(
        w: &GenericArray<u8, Self::LBytes>,
        u: &GenericArray<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, v, pk, chall_2)
    }

    #[cfg(any(
        not(feature = "opt-simd"),
        not(any(target_arch = "x86", target_arch = "x86_64")),
        all(target_feature = "avx2", target_feature = "pclmulqdq")
    ))]
    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LambdaBytes>,
        a1_tilde: &GenericArray<u8, Self::LambdaBytes>,
        a2_tilde: &GenericArray<u8, Self::LambdaBytes>,
    ) -> OWFField<Self> {
        aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF256<F = GF256>(PhantomData<F>);

impl<F> OWFParameters for OWF256<F>
where
    F: BigGaloisField<Length = U32> + std::fmt::Debug + std::cmp::PartialEq,
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
        let aes = Aes256Enc::new(GenericArray_AES::from_slice(key));
        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(input),
            GenericArray_AES::from_mut_slice(&mut output[..16]),
        );

        let mut input: [u8; 16] = (*input).try_into().expect("Invalid input length");
        input[0] ^= 1;

        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(&input),
            GenericArray_AES::from_mut_slice(&mut output[16..]),
        );
    }

    #[inline]
    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LambdaBytes>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBytes>> {
        aes_extendedwitness::<Self>(owf_key, owf_input)
    }

    #[cfg(all(
        feature = "opt-simd", // using simd optimization feature
        any(target_arch = "x86", target_arch = "x86_64"), // we're on x86/x86_64
        not(all(target_feature = "avx2", target_feature = "pclmulqdq")) // simd support can't be statically detected
    ))]
    #[inline]
    fn prove(
        w: &GenericArray<u8, Self::LBytes>,
        u: &GenericArray<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("pclmulqdq") {
            let pk: &PublicKey<OWF256<SimdGF256>> = unsafe { std::mem::transmute(pk) };
            let qs_proof = aes_prove::<OWF256<SimdGF256>>(w, u, v, pk, chall_2);
            (
                OWFField::<Self>::from(qs_proof.0.as_bytes().as_slice()),
                OWFField::<Self>::from(qs_proof.1.as_bytes().as_slice()),
                OWFField::<Self>::from(qs_proof.2.as_bytes().as_slice()),
            )
        } else {
            aes_prove::<Self>(w, u, v, pk, chall_2)
        }
    }

    #[cfg(all(
        feature = "opt-simd", // using simd optimization feature
        any(target_arch = "x86", target_arch = "x86_64"), // we're on x86/x86_64
        not(all(target_feature = "avx2", target_feature = "pclmulqdq")) // simd support can't be statically detected
    ))]
    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LambdaBytes>,
        a1_tilde: &GenericArray<u8, Self::LambdaBytes>,
        a2_tilde: &GenericArray<u8, Self::LambdaBytes>,
    ) -> OWFField<Self> {
        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("pclmulqdq") {
            let pk: &PublicKey<OWF256<SimdGF256>> = unsafe { std::mem::transmute(pk) };
            let chall3 =
                aes_verify::<OWF256<SimdGF256>>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde);
            OWFField::<Self>::from(chall3.as_bytes().as_slice())
        } else {
            aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
        }
    }

    #[cfg(any(
        not(feature = "opt-simd"),
        not(any(target_arch = "x86", target_arch = "x86_64")),
        all(target_feature = "avx2", target_feature = "pclmulqdq")
    ))]
    fn prove(
        w: &GenericArray<u8, Self::LBytes>,
        u: &GenericArray<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, v, pk, chall_2)
    }

    #[cfg(any(
        not(feature = "opt-simd"),
        not(any(target_arch = "x86", target_arch = "x86_64")),
        all(target_feature = "avx2", target_feature = "pclmulqdq")
    ))]
    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LambdaBytes>,
        a1_tilde: &GenericArray<u8, Self::LambdaBytes>,
        a2_tilde: &GenericArray<u8, Self::LambdaBytes>,
    ) -> OWFField<Self> {
        aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF128EM<F = GF128>(PhantomData<F>);

impl<F> OWFParameters for OWF128EM<F>
where
    F: BigGaloisField<Length = U16> + std::fmt::Debug + std::cmp::PartialEq,
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
        let aes = Aes128Enc::new(GenericArray_AES::from_slice(input));
        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(key),
            GenericArray_AES::from_mut_slice(output),
        );
        for idx in 0..Self::InputSize::USIZE {
            output[idx] ^= key[idx];
        }
    }

    #[inline]
    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LambdaBytes>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBytes>> {
        aes_extendedwitness::<Self>(owf_input, owf_key)
    }

    #[cfg(all(
        feature = "opt-simd", // using simd optimization feature
        any(target_arch = "x86", target_arch = "x86_64"), // we're on x86/x86_64
        not(all(target_feature = "avx2", target_feature = "pclmulqdq")) // simd support can't be statically detected
    ))]
    #[inline]
    fn prove(
        w: &GenericArray<u8, Self::LBytes>,
        u: &GenericArray<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("pclmulqdq") {
            let pk: &PublicKey<OWF128EM<SimdGF128>> = unsafe { std::mem::transmute(pk) };
            let qs_proof = aes_prove::<OWF128EM<SimdGF128>>(w, u, v, pk, chall_2);
            (
                OWFField::<Self>::from(qs_proof.0.as_bytes().as_slice()),
                OWFField::<Self>::from(qs_proof.1.as_bytes().as_slice()),
                OWFField::<Self>::from(qs_proof.2.as_bytes().as_slice()),
            )
        } else {
            aes_prove::<Self>(w, u, v, pk, chall_2)
        }
    }

    #[cfg(all(
        feature = "opt-simd", // using simd optimization feature
        any(target_arch = "x86", target_arch = "x86_64"), // we're on x86/x86_64
        not(all(target_feature = "avx2", target_feature = "pclmulqdq")) // simd support can't be statically detected
    ))]
    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LambdaBytes>,
        a1_tilde: &GenericArray<u8, Self::LambdaBytes>,
        a2_tilde: &GenericArray<u8, Self::LambdaBytes>,
    ) -> OWFField<Self> {
        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("pclmulqdq") {
            let pk: &PublicKey<OWF128EM<SimdGF128>> = unsafe { std::mem::transmute(pk) };
            let chall3 =
                aes_verify::<OWF128EM<SimdGF128>>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde);
            OWFField::<Self>::from(chall3.as_bytes().as_slice())
        } else {
            aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
        }
    }

    #[cfg(any(
        not(feature = "opt-simd"),
        not(any(target_arch = "x86", target_arch = "x86_64")),
        all(target_feature = "avx2", target_feature = "pclmulqdq")
    ))]
    fn prove(
        w: &GenericArray<u8, Self::LBytes>,
        u: &GenericArray<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, v, pk, chall_2)
    }

    #[cfg(any(
        not(feature = "opt-simd"),
        not(any(target_arch = "x86", target_arch = "x86_64")),
        all(target_feature = "avx2", target_feature = "pclmulqdq")
    ))]
    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LambdaBytes>,
        a1_tilde: &GenericArray<u8, Self::LambdaBytes>,
        a2_tilde: &GenericArray<u8, Self::LambdaBytes>,
    ) -> OWFField<Self> {
        aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF192EM<F = GF192>(PhantomData<F>)
where
    F: BigGaloisField<Length = U24>;

type U1536 = Sum<U1024, U512>;

impl<F> OWFParameters for OWF192EM<F>
where
    F: BigGaloisField<Length = U24> + std::fmt::Debug + std::cmp::PartialEq,
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
        let aes = Rijndael192::new(GenericArray_AES::from_slice(input));
        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(key),
            GenericArray_AES::from_mut_slice(output),
        );
        for idx in 0..Self::InputSize::USIZE {
            output[idx] ^= key[idx];
        }
    }

    #[inline]
    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LambdaBytes>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBytes>> {
        aes_extendedwitness::<Self>(owf_input, owf_key)
    }

    #[cfg(all(
        feature = "opt-simd", // using simd optimization feature
        any(target_arch = "x86", target_arch = "x86_64"), // we're on x86/x86_64
        not(all(target_feature = "avx2", target_feature = "pclmulqdq")) // simd support can't be statically detected
    ))]
    #[inline]
    fn prove(
        w: &GenericArray<u8, Self::LBytes>,
        u: &GenericArray<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("pclmulqdq") {
            let pk: &PublicKey<OWF192EM<SimdGF192>> = unsafe { std::mem::transmute(pk) };
            let qs_proof = aes_prove::<OWF192EM<SimdGF192>>(w, u, v, pk, chall_2);
            (
                OWFField::<Self>::from(qs_proof.0.as_bytes().as_slice()),
                OWFField::<Self>::from(qs_proof.1.as_bytes().as_slice()),
                OWFField::<Self>::from(qs_proof.2.as_bytes().as_slice()),
            )
        } else {
            aes_prove::<Self>(w, u, v, pk, chall_2)
        }
    }

    #[cfg(any(
        not(feature = "opt-simd"),
        not(any(target_arch = "x86", target_arch = "x86_64")),
        all(target_feature = "avx2", target_feature = "pclmulqdq")
    ))]
    #[inline]
    fn prove(
        w: &GenericArray<u8, Self::LBytes>,
        u: &GenericArray<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, v, pk, chall_2)
    }

    #[cfg(all(
        feature = "opt-simd", // using simd optimization feature
        any(target_arch = "x86", target_arch = "x86_64"), // we're on x86/x86_64
        not(all(target_feature = "avx2", target_feature = "pclmulqdq")) // simd support can't be statically detected
    ))]
    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LambdaBytes>,
        a1_tilde: &GenericArray<u8, Self::LambdaBytes>,
        a2_tilde: &GenericArray<u8, Self::LambdaBytes>,
    ) -> OWFField<Self> {
        // Dynamic feature detection
        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("pclmulqdq") {
            let pk: &PublicKey<OWF192EM<SimdGF192>> = unsafe { std::mem::transmute(pk) };
            let chall3 =
                aes_verify::<OWF192EM<SimdGF192>>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde);
            OWFField::<Self>::from(chall3.as_bytes().as_slice())
        } else {
            aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
        }
    }

    #[cfg(any(
        not(feature = "opt-simd"),
        not(any(target_arch = "x86", target_arch = "x86_64")),
        all(target_feature = "avx2", target_feature = "pclmulqdq")
    ))]
    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LambdaBytes>,
        a1_tilde: &GenericArray<u8, Self::LambdaBytes>,
        a2_tilde: &GenericArray<u8, Self::LambdaBytes>,
    ) -> OWFField<Self> {
        aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF256EM<F = GF256>(PhantomData<F>)
where
    F: BigGaloisField<Length = U32>;

impl<F> OWFParameters for OWF256EM<F>
where
    F: BigGaloisField<Length = U32> + std::fmt::Debug + std::cmp::PartialEq,
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
        let aes = Rijndael256::new(GenericArray_AES::from_slice(input));
        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(key),
            GenericArray_AES::from_mut_slice(output),
        );
        for idx in 0..Self::InputSize::USIZE {
            output[idx] ^= key[idx];
        }
    }

    #[inline]
    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LambdaBytes>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBytes>> {
        aes_extendedwitness::<Self>(owf_input, owf_key)
    }

    #[cfg(all(
        feature = "opt-simd", // using simd optimization feature
        any(target_arch = "x86", target_arch = "x86_64"), // we're on x86/x86_64
        not(all(target_feature = "avx2", target_feature = "pclmulqdq")) // simd support can't be statically detected
    ))]
    #[inline]
    fn prove(
        w: &GenericArray<u8, Self::LBytes>,
        u: &GenericArray<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        use crate::fields::Field;

        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("pclmulqdq") {
            let pk: &PublicKey<OWF256EM<SimdGF256>> = unsafe { std::mem::transmute(pk) };
            let (a1_t, a2_t, a3_t) = aes_prove::<OWF256EM<SimdGF256>>(w, u, v, pk, chall_2);
            (
                OWFField::<Self>::from(a1_t.as_bytes().as_slice()),
                OWFField::<Self>::from(a2_t.as_bytes().as_slice()),
                OWFField::<Self>::from(a3_t.as_bytes().as_slice()),
            )
        } else {
            aes_prove::<Self>(w, u, v, pk, chall_2)
        }
    }

    #[cfg(all(
        feature = "opt-simd", // using simd optimization feature
        any(target_arch = "x86", target_arch = "x86_64"), // we're on x86/x86_64
        not(all(target_feature = "avx2", target_feature = "pclmulqdq")) // simd support can't be statically detected
    ))]
    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LambdaBytes>,
        a1_tilde: &GenericArray<u8, Self::LambdaBytes>,
        a2_tilde: &GenericArray<u8, Self::LambdaBytes>,
    ) -> OWFField<Self> {
        use crate::fields::Field;

        if is_x86_feature_detected!("avx2") && is_x86_feature_detected!("pclmulqdq") {
            let pk: &PublicKey<OWF256EM<SimdGF256>> = unsafe { std::mem::transmute(pk) };
            OWFField::<Self>::from(
                aes_verify::<OWF256EM<SimdGF256>>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
                    .as_bytes()
                    .as_slice(),
            )
        } else {
            let chall3 = aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde);
            OWFField::<Self>::from(chall3.as_bytes().as_slice())
        }
    }

    #[cfg(any(
        not(feature = "opt-simd"),
        not(any(target_arch = "x86", target_arch = "x86_64")),
        all(target_feature = "avx2", target_feature = "pclmulqdq")
    ))]
    fn prove(
        w: &GenericArray<u8, Self::LBytes>,
        u: &GenericArray<u8, Self::LambdaBytesTimes2>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, v, pk, chall_2)
    }

    #[cfg(any(
        not(feature = "opt-simd"),
        not(any(target_arch = "x86", target_arch = "x86_64")),
        all(target_feature = "avx2", target_feature = "pclmulqdq")
    ))]
    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBytes>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LambdaBytes>,
        a1_tilde: &GenericArray<u8, Self::LambdaBytes>,
        a2_tilde: &GenericArray<u8, Self::LambdaBytes>,
    ) -> OWFField<Self> {
        aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
    }
}

pub(crate) trait TauParameters {
    /// Number of small-VOLE instances
    type Tau: ArrayLength;
    /// Bit-length of the larger small-VOLE instances (the smaller small-VOLE instances have length K-1)
    type K: ArrayLength;
    /// Number of smaller small-VOLE instances
    type Tau0: ArrayLength;
    /// Number of larger small-VOLE instances
    type Tau1: ArrayLength;
    /// Number of leaves of the GGM tree
    type L: ArrayLength;
    /// Threshold for the maximum opening size of the GGM tree
    type Topen: ArrayLength;

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
            return Self::L::USIZE - 1 + Self::Tau::USIZE * j + i;
        }

        // Applying mod 2^(k-1) is same as taking the k-2 LSB
        let mask = tmp - 1;
        Self::L::USIZE - 1 + Self::Tau::USIZE * tmp + Self::Tau1::USIZE * (j & mask) + i
    }
}

// FAEST
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau128Small;

impl TauParameters for Tau128Small {
    type Tau = U11;
    type K = U12;
    type L = Prod<U11, U2048>;
    type Tau0 = U11;
    type Tau1 = U0;
    type Topen = U102;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau128Fast;

impl TauParameters for Tau128Fast {
    type Tau = U16;
    type K = U8;
    type L = Sum<Prod<U8, U256>, Prod<U8, U128>>;
    type Tau0 = U8;
    type Tau1 = U8;
    type Topen = U110;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau192Small;

impl TauParameters for Tau192Small {
    type Tau = U16;
    type K = U12;
    type L = Sum<Prod<U12, U2048>, Prod<U4, U4096>>;
    type Tau0 = U12;
    type Tau1 = U4;
    type Topen = U162;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau192Fast;

impl TauParameters for Tau192Fast {
    type Tau = U24;
    type K = U8;
    type L = Sum<Prod<U8, U128>, Prod<U16, U256>>;
    type Tau0 = U8;
    type Tau1 = U16;
    type Topen = U163;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau256Small;

impl TauParameters for Tau256Small {
    type Tau = U22;
    type K = U12;
    type L = Sum<Prod<U14, U2048>, Prod<U8, U4096>>;
    type Tau0 = U14;
    type Tau1 = U8;
    type Topen = U245;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau256Fast;

impl TauParameters for Tau256Fast {
    type Tau = U32;
    type K = U8;
    type L = Sum<Prod<U8, U128>, Prod<U24, U256>>;
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
    type L = Prod<U11, U2048>;
    type Tau0 = U11;
    type Tau1 = U0;
    type Topen = U103;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau128FastEM;

impl TauParameters for Tau128FastEM {
    type Tau = U16;
    type K = U8;
    type L = Sum<Prod<U8, U256>, Prod<U8, U128>>;
    type Tau0 = U8;
    type Tau1 = U8;
    type Topen = U112;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau192SmallEM;

impl TauParameters for Tau192SmallEM {
    type Tau = U16;
    type K = U12;
    type L = Sum<Prod<U8, U2048>, Prod<U8, U4096>>;
    type Tau0 = U8;
    type Tau1 = U8;
    type Topen = U162;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau192FastEM;

impl TauParameters for Tau192FastEM {
    type Tau = U24;
    type K = U8;
    type L = Sum<Prod<U8, U128>, Prod<U16, U256>>;
    type Tau0 = U8;
    type Tau1 = U16;
    type Topen = U176;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau256SmallEM;

impl TauParameters for Tau256SmallEM {
    type Tau = U22;
    type K = U12;
    type L = Sum<Prod<U14, U2048>, Prod<U8, U4096>>;
    type Tau0 = U14;
    type Tau1 = U8;
    type Topen = U218;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau256FastEM;

impl TauParameters for Tau256FastEM {
    type Tau = U32;
    type K = U8;
    type L = Sum<Prod<U8, U128>, Prod<U24, U256>>;
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
    type WGRIND: ArrayLength;
    /// Size of the signature (in bytes)
    type SignatureSize: ArrayLength;

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
pub(crate) struct FAEST128sParameters;

impl FAESTParameters for FAEST128sParameters {
    type OWF = OWF128<GF128>;
    type Tau = Tau128Small;
    type BAVC = BAVC128Small;
    type WGRIND = U7;
    type SignatureSize = U4506;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST128fParameters;

impl FAESTParameters for FAEST128fParameters {
    type OWF = OWF128<GF128>;
    type Tau = Tau128Fast;
    type BAVC = BAVC128Fast;
    type WGRIND = U8;
    type SignatureSize = U5924;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST192sParameters;

impl FAESTParameters for FAEST192sParameters {
    type OWF = OWF192;
    type Tau = Tau192Small;
    type BAVC = BAVC192Small;
    type WGRIND = U12;
    type SignatureSize = U11260;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST192fParameters;

impl FAESTParameters for FAEST192fParameters {
    type OWF = OWF192;
    type Tau = Tau192Fast;
    type BAVC = BAVC192Fast;
    type WGRIND = U8;
    type SignatureSize = U14948;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST256sParameters;

impl FAESTParameters for FAEST256sParameters {
    type OWF = OWF256;
    type Tau = Tau256Small;
    type BAVC = BAVC256Small;
    type WGRIND = U6;
    type SignatureSize = U20696;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST256fParameters;

impl FAESTParameters for FAEST256fParameters {
    type OWF = OWF256;
    type Tau = Tau256Fast;
    type BAVC = BAVC256Fast;
    type WGRIND = U8;
    type SignatureSize = U26548;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM128sParameters;

impl FAESTParameters for FAESTEM128sParameters {
    type OWF = OWF128EM;
    type Tau = Tau128SmallEM;
    type BAVC = BAVC128SmallEM;
    type WGRIND = U7;
    type SignatureSize = U3906;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM128fParameters;

impl FAESTParameters for FAESTEM128fParameters {
    type OWF = OWF128EM;
    type Tau = Tau128FastEM;
    type BAVC = BAVC128FastEM;
    type WGRIND = U8;
    type SignatureSize = U5060;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM192sParameters;

impl FAESTParameters for FAESTEM192sParameters {
    type OWF = OWF192EM;
    type Tau = Tau192SmallEM;
    type BAVC = BAVC192SmallEM;
    type WGRIND = U8;
    type SignatureSize = U9340;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM192fParameters;

impl FAESTParameters for FAESTEM192fParameters {
    type OWF = OWF192EM;
    type Tau = Tau192FastEM;
    type BAVC = BAVC192FastEM;
    type WGRIND = U8;
    type SignatureSize = U12380;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM256sParameters;

impl FAESTParameters for FAESTEM256sParameters {
    type OWF = OWF256EM;
    type Tau = Tau256SmallEM;
    type BAVC = BAVC256SmallEM;
    type WGRIND = U6;
    type SignatureSize = U17984;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM256fParameters;

impl FAESTParameters for FAESTEM256fParameters {
    type OWF = OWF256EM;
    type Tau = Tau256FastEM;
    type BAVC = BAVC256FastEM;
    type WGRIND = U8;
    type SignatureSize = U23476;
}

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
