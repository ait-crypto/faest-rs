use std::{
    marker::PhantomData,
    ops::{Add, Sub},
};

use aes::{
    cipher::{generic_array::GenericArray as GenericArray_AES, BlockEncrypt, KeyInit},
    Aes128Enc, Aes192Enc, Aes256Enc,
};
use generic_array::{
    typenum::{
        Diff, Double, Prod, Quot, Sum, Unsigned, U0, U1, U10, U1024, U11, U112, U12, U128, U14,
        U142, U152, U16, U160, U16384, U192, U194, U2, U200, U2048, U22, U224, U234, U24, U256,
        U288, U3, U32, U338, U384, U4, U40, U408, U4096, U416, U448, U458, U470, U476, U48, U5,
        U500, U511, U512, U514, U52, U56, U566, U576, U584, U596, U6, U600, U64, U640, U672, U7,
        U752, U8, U8192, U832, U96,
    },
    ArrayLength, GenericArray,
};
use rand_core::RngCore;

use crate::{
    aes::{aes_extendedwitness, aes_prove, aes_verify},
    em::{em_extendedwitness, em_prove, em_verify},
    faest::SecretKey,
    fields::{BigGaloisField, GF128, GF192, GF256},
    prg::{PseudoRandomGenerator, PRG128, PRG192, PRG256},
    random_oracles::{RandomOracle, RandomOracleShake128, RandomOracleShake256},
    rijndael_32::{Rijndael192, Rijndael256},
    universal_hashing::{VoleHasher, VoleHasherInit, ZKHasher, ZKHasherInit, B},
    vc::{VectorCommitment, VC},
};

/// Base parameters per security level
pub(crate) trait BaseParameters {
    /// The field that is of size `2^λ` which is defined as [Self::Lambda]
    type Field: BigGaloisField<Length = Self::LambdaBytes> + std::fmt::Debug;
    /// Hasher implementation of `ZKHash`
    type ZKHasher: ZKHasherInit<Self::Field, SDLength = Self::Chall>;
    /// Hasher implementation of `VOLEHash`
    type VoleHasher: VoleHasherInit<
        Self::Field,
        SDLength = Self::Chall1,
        OutputLength = Sum<Self::LambdaBytes, B>,
    >;
    /// Associated random oracle
    type RandomOracle: RandomOracle;
    /// Associated PRG
    type PRG: PseudoRandomGenerator<Lambda = Self::LambdaBytes>;
    type VC: VectorCommitment<Lambda = Self::LambdaBytes, LambdaTimes2 = Self::LambdaBytesTimes2>;

    /// Security parameter (in bits)
    type Lambda: ArrayLength;
    /// Security parameter (in bytes)
    type LambdaBytes: ArrayLength + Add<B>;
    type LambdaBytesTimes2: ArrayLength;
    type Chall: ArrayLength;
    type Chall1: ArrayLength;
}

#[derive(Debug, Clone)]
pub(crate) struct BaseParams128;

impl BaseParameters for BaseParams128 {
    type Field = GF128;
    type ZKHasher = ZKHasher<Self::Field>;
    type VoleHasher = VoleHasher<Self::Field>;
    type RandomOracle = RandomOracleShake128;
    type PRG = PRG128;
    type VC = VC<Self::PRG, Self::RandomOracle>;

    type Lambda = U128;
    type LambdaBytes = U16;
    type LambdaBytesTimes2 = U32;

    type Chall = Sum<U8, Prod<U3, Self::LambdaBytes>>;
    type Chall1 = Sum<U8, Prod<U5, Self::LambdaBytes>>;
}

#[derive(Debug, Clone)]
pub(crate) struct BaseParams192;

impl BaseParameters for BaseParams192 {
    type Field = GF192;
    type ZKHasher = ZKHasher<Self::Field>;
    type VoleHasher = VoleHasher<Self::Field>;
    type RandomOracle = RandomOracleShake256;
    type PRG = PRG192;
    type VC = VC<Self::PRG, Self::RandomOracle>;

    type Lambda = U192;
    type LambdaBytes = U24;
    type LambdaBytesTimes2 = U48;

    type Chall = Sum<U8, Prod<U3, Self::LambdaBytes>>;
    type Chall1 = Sum<U8, Prod<U5, Self::LambdaBytes>>;
}

#[derive(Debug, Clone)]
pub(crate) struct BaseParams256;

impl BaseParameters for BaseParams256 {
    type Field = GF256;
    type ZKHasher = ZKHasher<Self::Field>;
    type VoleHasher = VoleHasher<Self::Field>;
    type RandomOracle = RandomOracleShake256;
    type PRG = PRG256;
    type VC = VC<Self::PRG, Self::RandomOracle>;

    type Lambda = U256;
    type LambdaBytes = U32;
    type LambdaBytesTimes2 = U64;

    type Chall = Sum<U8, Prod<U3, Self::LambdaBytes>>;
    type Chall1 = Sum<U8, Prod<U5, Self::LambdaBytes>>;
}

pub(crate) type QSProof<O> = (
    GenericArray<u8, <O as PARAMOWF>::LAMBDABYTES>,
    GenericArray<u8, <O as PARAMOWF>::LAMBDABYTES>,
);

pub(crate) trait Variant<O: PARAMOWF> {
    fn witness(
        owf_key: &GenericArray<u8, O::LAMBDABYTES>,
        owf_input: &GenericArray<u8, O::InputSize>,
    ) -> Box<GenericArray<u8, O::LBYTES>>;

    ///input : witness of l bits, masking values (l+lambda in aes, lambda in em), Vole tag ((l + lambda) *lambda bits), public key, chall(3lambda + 64)
    ///Output : QuickSilver response (Lambda bytes)
    fn prove(
        w: &GenericArray<u8, O::LBYTES>,
        u: &GenericArray<u8, O::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        owf_input: &GenericArray<u8, O::InputSize>,
        owf_output: &GenericArray<u8, O::OutputSize>,
        chall: &GenericArray<u8, O::CHALL>,
    ) -> QSProof<O>;

    ///input : Masked witness (l bits), Vole Key ((l + lambda) * Lambda bits), hash of constrints values (lambda bits), chall2 (3*lambda + 64 bits), chall3 (lambda bits), public key
    ///output q_tilde - delta * a_tilde (lambda bytes)
    fn verify<Tau>(
        d: &GenericArray<u8, O::LBYTES>,
        gq: &GenericArray<GenericArray<u8, O::LAMBDALBYTES>, O::LAMBDA>,
        a_t: &GenericArray<u8, O::LAMBDABYTES>,
        chall2: &GenericArray<u8, O::CHALL>,
        chall3: &GenericArray<u8, O::LAMBDABYTES>,
        owf_input: &GenericArray<u8, O::InputSize>,
        owf_output: &GenericArray<u8, O::OutputSize>,
    ) -> GenericArray<u8, O::LAMBDABYTES>
    where
        Tau: TauParameters;

    ///input : a random number generator
    /// output = pk : input, output; sk : input, key
    fn keygen_with_rng(rng: impl RngCore) -> SecretKey<O>;
}

pub(crate) trait PARAMOWF {
    type BaseParams: BaseParameters<
        Lambda = Self::LAMBDA,
        LambdaBytes = Self::LAMBDABYTES,
        VoleHasher = Self::VoleHasher,
        Chall = Self::CHALL,
        Chall1 = Self::CHALL1,
    >;

    #[deprecated]
    type VoleHasher: VoleHasherInit<
        <Self::BaseParams as BaseParameters>::Field,
        SDLength = Self::CHALL1,
        OutputLength = Self::LAMBDAPLUS2,
    >;

    type InputSize: ArrayLength;
    type OutputSize: ArrayLength;

    type LAMBDA: ArrayLength;
    type LAMBDABYTES: ArrayLength;
    type L: ArrayLength;
    type LBYTES: ArrayLength;
    type NK: ArrayLength;
    type R: ArrayLength;
    type SKE: ArrayLength;
    type SENC: ArrayLength;
    type LKE: ArrayLength;
    type LENC: ArrayLength;
    type QUOTLENC8: ArrayLength;
    type BETA: ArrayLength;
    type C: ArrayLength;
    type NST: ArrayLength;
    type LAMBDALBYTES: ArrayLength;
    type LAMBDAL: ArrayLength;
    type PK: ArrayLength;
    type SK: ArrayLength;
    type CHALL: ArrayLength;
    type CHALL1: ArrayLength;
    type LHATBYTES: ArrayLength;
    type LAMBDAPLUS2: ArrayLength;
    type LAMBDADOUBLE: ArrayLength;
    type LAMBDATRIPLE: ArrayLength;
    type LAMBDAPLUS16: ArrayLength;
    type LAMBDAPLUS4: ArrayLength;
    type LBYTESPLUS4: ArrayLength;
    type LPRIMEBYTE: ArrayLength;
    type KBLENGTH: ArrayLength;
    type PRODRUN128: ArrayLength;
    type PRODSKE8: ArrayLength;
    type SENC2: ArrayLength;
    type LAMBDALBYTESLAMBDA: ArrayLength;
    type LAMBDAR1: ArrayLength;
    type LAMBDAR1BYTE: ArrayLength;

    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PARAMOWF128;

impl PARAMOWF for PARAMOWF128 {
    type BaseParams = BaseParams128;
    type VoleHasher = VoleHasher<<Self::BaseParams as BaseParameters>::Field>;

    type InputSize = U16;
    type OutputSize = U16;

    type LAMBDA = U128;

    type LAMBDABYTES = U16;

    type L = <U1024 as Add<U576>>::Output;

    type LBYTES = U200;

    type LAMBDALBYTES = <Self::LAMBDABYTES as Add<Self::LBYTES>>::Output;

    type NK = U4;

    type R = U10;

    type SKE = U40;

    type SENC = U160;

    type LKE = U448;

    type LENC = <U1024 as Add<U128>>::Output;

    type BETA = U1;

    type C = U200;

    type NST = U0;

    type PK = U32;

    type SK = U32;

    type CHALL = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type CHALL1 = Sum<U8, Prod<U5, Self::LAMBDABYTES>>;

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;

    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;

    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U256;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;

    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;

    type PRODSKE8 = Prod<Self::SKE, U8>;

    type SENC2 = Prod<Self::SENC, U2>;

    type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;

    type QUOTLENC8 = Quot<Self::LENC, U8>;

    type LAMBDAL = Sum<Self::LAMBDA, Self::L>;

    type LAMBDAR1 = Prod<Self::LAMBDA, Sum<Self::R, U1>>;

    type LAMBDAR1BYTE = Quot<Self::LAMBDAR1, U8>;

    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]) {
        let aes = Aes128Enc::new(GenericArray_AES::from_slice(key));
        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(input),
            GenericArray_AES::from_mut_slice(output),
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PARAMOWF192;

impl PARAMOWF for PARAMOWF192 {
    type BaseParams = BaseParams192;
    type VoleHasher = VoleHasher<<Self::BaseParams as BaseParameters>::Field>;

    type InputSize = U32;
    type OutputSize = U32;

    type LAMBDA = U192;

    type LAMBDABYTES = U24;

    type L = <U4096 as Sub<U832>>::Output;

    type LBYTES = U408;

    type LAMBDALBYTES = <Self::LAMBDABYTES as Add<Self::LBYTES>>::Output;

    type NK = U6;

    type R = U12;

    type SKE = U32;

    type SENC = U192;

    type LKE = U448;

    type LENC = <U1024 as Add<U384>>::Output;

    type BETA = U2;

    type C = U416;

    type NST = U0;

    type PK = U64;

    type SK = U56;

    type CHALL = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type CHALL1 = Sum<U8, Prod<U5, Self::LAMBDABYTES>>;

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;

    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;

    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U384;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;

    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;

    type PRODSKE8 = Prod<Self::SKE, U8>;

    type SENC2 = Prod<Self::SENC, U2>;

    type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;

    type QUOTLENC8 = Quot<Self::LENC, U8>;

    type LAMBDAL = Sum<Self::LAMBDA, Self::L>;

    type LAMBDAR1 = Prod<Self::LAMBDA, Sum<Self::R, U1>>;

    type LAMBDAR1BYTE = Quot<Self::LAMBDAR1, U8>;

    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]) {
        let aes = Aes192Enc::new(GenericArray_AES::from_slice(key));
        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(&input[..16]),
            GenericArray_AES::from_mut_slice(&mut output[..16]),
        );
        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(&input[16..]),
            GenericArray_AES::from_mut_slice(&mut output[16..]),
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PARAMOWF256;

impl PARAMOWF for PARAMOWF256 {
    type BaseParams = BaseParams256;
    type VoleHasher = VoleHasher<<Self::BaseParams as BaseParameters>::Field>;

    type InputSize = U32;
    type OutputSize = U32;

    type LAMBDA = U256;

    type LAMBDABYTES = U32;

    type L = <U4096 as Sub<U96>>::Output;

    type LBYTES = U500;

    type LAMBDALBYTES = <Self::LAMBDABYTES as Add<Self::LBYTES>>::Output;

    type NK = U8;

    type R = U14;

    type SKE = U52;

    type SENC = U224;

    type LKE = U672;

    type LENC = <U1024 as Add<U640>>::Output;

    type BETA = U2;

    type C = U500;

    type NST = U0;

    type PK = U64;

    type SK = U64;

    type CHALL = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type CHALL1 = Sum<U8, Prod<U5, Self::LAMBDABYTES>>;

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;

    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;

    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U512;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;

    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;

    type PRODSKE8 = Prod<Self::SKE, U8>;

    type SENC2 = Prod<Self::SENC, U2>;

    type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;

    type QUOTLENC8 = Quot<Self::LENC, U8>;

    type LAMBDAL = Sum<Self::LAMBDA, Self::L>;

    type LAMBDAR1 = Prod<Self::LAMBDA, Sum<Self::R, U1>>;

    type LAMBDAR1BYTE = Quot<Self::LAMBDAR1, U8>;

    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]) {
        let aes = Aes256Enc::new(GenericArray_AES::from_slice(key));
        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(&input[..16]),
            GenericArray_AES::from_mut_slice(&mut output[..16]),
        );
        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(&input[16..]),
            GenericArray_AES::from_mut_slice(&mut output[16..]),
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PARAMOWF128EM;

impl PARAMOWF for PARAMOWF128EM {
    type BaseParams = BaseParams128;
    type VoleHasher = VoleHasher<<Self::BaseParams as BaseParameters>::Field>;

    type InputSize = U16;
    type OutputSize = U16;

    type LAMBDA = U128;

    type LAMBDABYTES = U16;

    type L = <U1024 as Add<U256>>::Output;

    type LBYTES = U160;

    type LAMBDALBYTES = <Self::LAMBDABYTES as Add<Self::LBYTES>>::Output;

    type NK = U4;

    type R = U10;

    type SKE = U40;

    type SENC = U160;

    type LKE = U448;

    type LENC = <U1024 as Add<U128>>::Output;

    type BETA = U1;

    type C = U160;

    type NST = U4;

    type PK = U32;

    type SK = U32;

    type CHALL = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type CHALL1 = Sum<U8, Prod<U5, Self::LAMBDABYTES>>;

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;

    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;

    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U256;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;

    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;

    type PRODSKE8 = Prod<Self::SKE, U8>;

    type SENC2 = Prod<Self::SENC, U2>;

    type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;

    type QUOTLENC8 = Quot<Self::LENC, U8>;

    type LAMBDAL = Sum<Self::LAMBDA, Self::L>;

    type LAMBDAR1 = Prod<Self::LAMBDA, Sum<Self::R, U1>>;

    type LAMBDAR1BYTE = Quot<Self::LAMBDAR1, U8>;

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PARAMOWF192EM;

impl PARAMOWF for PARAMOWF192EM {
    type BaseParams = BaseParams192;
    type VoleHasher = VoleHasher<<Self::BaseParams as BaseParameters>::Field>;

    type InputSize = U24;
    type OutputSize = U24;

    type LAMBDA = U192;

    type LAMBDABYTES = U24;

    type L = <U2048 as Add<U256>>::Output;

    type LBYTES = U288;

    type LAMBDALBYTES = <Self::LAMBDABYTES as Add<Self::LBYTES>>::Output;

    type NK = U6;

    type R = U12;

    type SKE = U32;

    type SENC = U288;

    type LKE = U448;

    type LENC = <U1024 as Add<U384>>::Output;

    type BETA = U2;

    type C = U288;

    type NST = U6;

    type PK = U48;

    type SK = U48;

    type CHALL = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type CHALL1 = Sum<U8, Prod<U5, Self::LAMBDABYTES>>;

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;

    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;

    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U384;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;

    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;

    type PRODSKE8 = Prod<Self::SKE, U8>;

    type SENC2 = Prod<Self::SENC, U2>;

    type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;

    type QUOTLENC8 = Quot<Self::LENC, U8>;

    type LAMBDAL = Sum<Self::LAMBDA, Self::L>;

    type LAMBDAR1 = Prod<Self::LAMBDA, Sum<Self::R, U1>>;

    type LAMBDAR1BYTE = Quot<Self::LAMBDAR1, U8>;

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PARAMOWF256EM;

impl PARAMOWF for PARAMOWF256EM {
    type BaseParams = BaseParams256;
    type VoleHasher = VoleHasher<<Self::BaseParams as BaseParameters>::Field>;

    type InputSize = U32;
    type OutputSize = U32;

    type LAMBDA = U256;

    type LAMBDABYTES = U32;

    type L = <U4096 as Sub<U512>>::Output;

    type LBYTES = U448;

    type LAMBDALBYTES = <Self::LAMBDABYTES as Add<Self::LBYTES>>::Output;

    type NK = U8;

    type R = U14;

    type SKE = U52;

    type SENC = U448;

    type LKE = U672;

    type LENC = <U1024 as Add<U640>>::Output;

    type BETA = U2;

    type C = U448;

    type NST = U8;

    type PK = U64;

    type SK = U64;

    type CHALL = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type CHALL1 = Sum<U8, Prod<U5, Self::LAMBDABYTES>>;

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;

    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;

    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U512;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;

    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;

    type PRODSKE8 = Prod<Self::SKE, U8>;

    type SENC2 = Prod<Self::SENC, U2>;

    type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;

    type QUOTLENC8 = Quot<Self::LENC, U8>;

    type LAMBDAL = Sum<Self::LAMBDA, Self::L>;

    type LAMBDAR1 = Prod<Self::LAMBDA, Sum<Self::R, U1>>;

    type LAMBDAR1BYTE = Quot<Self::LAMBDAR1, U8>;

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
}

pub(crate) trait TauParameters {
    type Tau: ArrayLength;
    type TauMinus1: ArrayLength;
    type K0: ArrayLength;
    type K1: ArrayLength;
    type Tau0: ArrayLength;
    type Tau1: ArrayLength;

    fn decode_challenge(chal: &[u8], i: usize) -> Vec<u8> {
        let (lo, hi) = if i < Self::Tau0::USIZE {
            let lo = i * Self::K0::USIZE;
            let hi = (i + 1) * Self::K0::USIZE - 1;
            (lo, hi)
        } else {
            debug_assert!(i < Self::Tau0::USIZE + Self::Tau1::USIZE);
            let t = i - Self::Tau0::USIZE;
            let lo = Self::Tau0::USIZE * Self::K0::USIZE + t * Self::K1::USIZE;
            let hi = Self::Tau0::USIZE * Self::K0::USIZE + (t + 1) * Self::K1::USIZE - 1;
            (lo, hi)
        };

        (0..=(hi - lo))
            .map(|j| (chal[(lo + j) / 8] >> ((lo + j) % 8)) & 1)
            .collect()
    }
}

pub(crate) struct Tau128Small;

impl TauParameters for Tau128Small {
    type Tau = U11;
    type TauMinus1 = Diff<Self::Tau, U1>;
    type K0 = U12;
    type K1 = U11;
    type Tau0 = U7;
    type Tau1 = U4;
}

pub(crate) struct Tau128Fast;

impl TauParameters for Tau128Fast {
    type Tau = U16;
    type TauMinus1 = Diff<Self::Tau, U1>;
    type K0 = U8;
    type K1 = U8;
    type Tau0 = U8;
    type Tau1 = U8;
}

pub(crate) struct Tau192Small;

impl TauParameters for Tau192Small {
    type Tau = U16;
    type TauMinus1 = Diff<Self::Tau, U1>;
    type K0 = U12;
    type K1 = U12;
    type Tau0 = U8;
    type Tau1 = U8;
}

pub(crate) struct Tau192Fast;

impl TauParameters for Tau192Fast {
    type Tau = U24;
    type TauMinus1 = Diff<Self::Tau, U1>;
    type K0 = U8;
    type K1 = U8;
    type Tau0 = U12;
    type Tau1 = U12;
}

pub(crate) struct Tau256Small;

impl TauParameters for Tau256Small {
    type Tau = U22;
    type TauMinus1 = Diff<Self::Tau, U1>;
    type K0 = U12;
    type K1 = U11;
    type Tau0 = U14;
    type Tau1 = U8;
}

pub(crate) struct Tau256Fast;

impl TauParameters for Tau256Fast {
    type Tau = U32;
    type TauMinus1 = Diff<Self::Tau, U1>;
    type K0 = U8;
    type K1 = U8;
    type Tau0 = U16;
    type Tau1 = U16;
}

pub(crate) trait PARAM {
    type OWF: PARAMOWF<
        LAMBDA = Self::LAMBDA,
        LAMBDABYTES = Self::LAMBDABYTES,
        L = Self::L,
        LBYTES = Self::LBYTES,
    >;
    type Cypher: Variant<Self::OWF>;
    type Tau: TauParameters;

    type L: ArrayLength;
    type LBYTES: ArrayLength;
    type N0: ArrayLength;
    type N1: ArrayLength;
    type POWK0: ArrayLength;
    type POWK1: ArrayLength;
    type BETA: ArrayLength;
    type LAMBDA: ArrayLength;
    type LAMBDABYTES: ArrayLength;
    type LH: ArrayLength;
    type SIG: ArrayLength;
}

pub(crate) struct PARAM128S;

impl PARAM for PARAM128S {
    type OWF = PARAMOWF128;

    type Tau = Tau128Small;

    type L = <U1024 as Add<U576>>::Output;

    type LBYTES = U200;

    type BETA = U1;

    type LAMBDA = U128;

    type N0 = U4096;

    type POWK0 = Diff<U8192, U1>;

    type N1 = U2048;

    type POWK1 = Diff<U4096, U1>;

    type LH = U234;

    type SIG = Sum<U142, Sum<U256, Sum<U512, U4096>>>;

    type LAMBDABYTES = Quot<Self::LAMBDA, U8>;

    type Cypher = AesCypher<Self::OWF>;
}

pub(crate) struct PARAM128F;

impl PARAM for PARAM128F {
    type OWF = PARAMOWF128;
    type Tau = Tau128Fast;

    type L = <U1024 as Add<U576>>::Output;

    type LBYTES = U200;

    type BETA = U1;

    type LAMBDA = U128;

    type N0 = U256;

    type POWK0 = U511;

    type N1 = U256;

    type POWK1 = U511;

    type LH = U234;

    type SIG = Sum<U192, Sum<U2048, U4096>>;

    type LAMBDABYTES = Quot<Self::LAMBDA, U8>;

    type Cypher = AesCypher<Self::OWF>;
}

pub(crate) struct PARAM192S;

impl PARAM for PARAM192S {
    type OWF = PARAMOWF192;

    type Tau = Tau192Small;

    type L = <U4096 as Sub<U832>>::Output;

    type LBYTES = U408;

    type BETA = U2;

    type LAMBDA = U192;

    type N0 = U4096;

    type POWK0 = Diff<U8192, U1>;

    type N1 = U4096;

    type POWK1 = Diff<U8192, U1>;

    type LH = U458;

    type SIG = Sum<U200, Sum<U256, Sum<U8192, U4096>>>;

    type LAMBDABYTES = Quot<Self::LAMBDA, U8>;

    type Cypher = AesCypher<Self::OWF>;
}

pub(crate) struct PARAM192F;

impl PARAM for PARAM192F {
    type OWF = PARAMOWF192;

    type Tau = Tau192Fast;

    type L = <U4096 as Sub<U832>>::Output;

    type LBYTES = U408;

    type BETA = U2;

    type LAMBDA = U192;

    type N0 = U256;

    type POWK0 = U511;

    type N1 = U256;

    type POWK1 = U511;

    type LH = U458;

    type SIG = Sum<U152, Sum<U256, U16384>>;

    type LAMBDABYTES = Quot<Self::LAMBDA, U8>;

    type Cypher = AesCypher<Self::OWF>;
}

pub(crate) struct PARAM256S;

impl PARAM for PARAM256S {
    type OWF = PARAMOWF256;

    type Tau = Tau256Small;

    type L = <U4096 as Sub<U96>>::Output;

    type LBYTES = U500;

    type BETA = U2;

    type LAMBDA = U256;

    type N0 = U4096;

    type POWK0 = Diff<U8192, U1>;

    type N1 = U2048;

    type POWK1 = Diff<U4096, U1>;

    type LH = U566;

    type SIG = Sum<U596, Sum<U1024, Sum<U4096, U16384>>>;

    type LAMBDABYTES = Quot<Self::LAMBDA, U8>;

    type Cypher = AesCypher<Self::OWF>;
}

pub(crate) struct PARAM256F;

impl PARAM for PARAM256F {
    type OWF = PARAMOWF256;

    type Tau = Tau256Fast;

    type L = <U4096 as Sub<U96>>::Output;

    type LBYTES = U500;

    type BETA = U2;

    type LAMBDA = U256;

    type N0 = U256;

    type POWK0 = U511;

    type N1 = U256;

    type POWK1 = U511;

    type LH = U566;

    type SIG = Sum<U752, Sum<U1024, Sum<U2048, Sum<U8192, U16384>>>>;

    type LAMBDABYTES = Quot<Self::LAMBDA, U8>;

    type Cypher = AesCypher<Self::OWF>;
}

pub(crate) struct PARAM128SEM;

impl PARAM for PARAM128SEM {
    type OWF = PARAMOWF128EM;

    type Tau = Tau128Small;

    type L = <U1024 as Add<U256>>::Output;

    type LBYTES = U160;

    type BETA = U1;

    type LAMBDA = U128;

    type N0 = U4096;

    type POWK0 = Diff<U8192, U1>;

    type N1 = U2048;

    type POWK1 = Diff<U4096, U1>;

    type LH = U194;

    type SIG = Sum<U470, U4096>;

    type LAMBDABYTES = Quot<Self::LAMBDA, U8>;

    type Cypher = EmCypher<Self::OWF>;
}

pub(crate) struct PARAM128FEM;

impl PARAM for PARAM128FEM {
    type OWF = PARAMOWF128EM;

    type Tau = Tau128Fast;

    type L = <U1024 as Add<U256>>::Output;

    type LBYTES = U160;

    type BETA = U1;

    type LAMBDA = U128;

    type N0 = U256;

    type POWK0 = U511;

    type N1 = U256;

    type POWK1 = U511;

    type LH = U194;

    type SIG = Sum<U576, Sum<U1024, U4096>>;

    type LAMBDABYTES = Quot<Self::LAMBDA, U8>;

    type Cypher = EmCypher<Self::OWF>;
}

pub(crate) struct PARAM192SEM;

impl PARAM for PARAM192SEM {
    type OWF = PARAMOWF192EM;

    type Tau = Tau192Small;

    type L = <U2048 as Add<U256>>::Output;

    type LBYTES = U288;

    type BETA = U2;

    type LAMBDA = U192;

    type N0 = U4096;

    type POWK0 = Diff<U8192, U1>;

    type N1 = U4096;

    type POWK1 = Diff<U8192, U1>;

    type LH = U338;

    type SIG = Sum<U584, Sum<U2048, U8192>>;

    type LAMBDABYTES = Quot<Self::LAMBDA, U8>;

    type Cypher = EmCypher<Self::OWF>;
}

pub(crate) struct PARAM192FEM;

impl PARAM for PARAM192FEM {
    type OWF = PARAMOWF192EM;

    type Tau = Tau192Fast;

    type L = <U2048 as Add<U256>>::Output;

    type LBYTES = U288;

    type BETA = U2;

    type LAMBDA = U192;

    type N0 = U256;

    type POWK0 = U511;

    type N1 = U256;

    type POWK1 = U511;

    type LH = U338;

    type SIG = Sum<U600, Sum<U1024, Sum<U4096, U8192>>>;

    type LAMBDABYTES = Quot<Self::LAMBDA, U8>;

    type Cypher = EmCypher<Self::OWF>;
}

pub(crate) struct PARAM256SEM;

impl PARAM for PARAM256SEM {
    type OWF = PARAMOWF256EM;

    type Tau = Tau256Small;

    type L = Diff<U4096, U512>;

    type LBYTES = U448;

    type BETA = U2;

    type LAMBDA = U256;

    type N0 = U4096;

    type POWK0 = Diff<U8192, U1>;

    type N1 = U2048;

    type POWK1 = Diff<U4096, U1>;

    type LH = U514;

    type SIG = Sum<U476, Sum<U4096, U16384>>;

    type LAMBDABYTES = Quot<Self::LAMBDA, U8>;

    type Cypher = EmCypher<Self::OWF>;
}

pub(crate) struct PARAM256FEM;

impl PARAM for PARAM256FEM {
    type OWF = PARAMOWF256EM;

    type Tau = Tau256Fast;

    type L = Diff<U4096, U512>;

    type LBYTES = U448;

    type BETA = U2;

    type LAMBDA = U256;

    type N0 = U256;

    type POWK0 = U511;

    type N1 = U256;

    type POWK1 = U511;

    type LH = U514;

    type SIG = Sum<U112, Sum<U2048, Sum<U8192, U16384>>>;

    type LAMBDABYTES = Quot<Self::LAMBDA, U8>;

    type Cypher = EmCypher<Self::OWF>;
}

pub(crate) struct AesCypher<OWF>(PhantomData<OWF>)
where
    OWF: PARAMOWF;

impl<OWF: PARAMOWF> Variant<OWF> for AesCypher<OWF> {
    fn witness(
        owf_key: &GenericArray<u8, OWF::LAMBDABYTES>,
        owf_input: &GenericArray<u8, OWF::InputSize>,
    ) -> Box<GenericArray<u8, OWF::LBYTES>> {
        aes_extendedwitness::<OWF>(owf_key, owf_input).0
    }

    fn prove(
        w: &GenericArray<u8, OWF::LBYTES>,
        u: &GenericArray<u8, OWF::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, OWF::LAMBDALBYTES>, OWF::LAMBDA>,
        owf_input: &GenericArray<u8, OWF::InputSize>,
        owf_output: &GenericArray<u8, OWF::OutputSize>,
        chall: &GenericArray<u8, OWF::CHALL>,
    ) -> QSProof<OWF> {
        aes_prove::<OWF>(w, u, gv, owf_input, owf_output, chall)
    }

    fn verify<Tau>(
        d: &GenericArray<u8, OWF::LBYTES>,
        gq: &GenericArray<GenericArray<u8, OWF::LAMBDALBYTES>, OWF::LAMBDA>,
        a_t: &GenericArray<u8, OWF::LAMBDABYTES>,
        chall2: &GenericArray<u8, OWF::CHALL>,
        chall3: &GenericArray<u8, OWF::LAMBDABYTES>,
        owf_input: &GenericArray<u8, OWF::InputSize>,
        owf_output: &GenericArray<u8, OWF::OutputSize>,
    ) -> GenericArray<u8, OWF::LAMBDABYTES>
    where
        Tau: TauParameters,
    {
        aes_verify::<OWF, Tau>(d, gq, a_t, chall2, chall3, owf_input, owf_output)
    }

    ///Input : the parameter of the faest protocol
    /// Output : sk : inputOWF||keyOWF, pk : inputOWF||outputOWF
    fn keygen_with_rng(mut rng: impl RngCore) -> SecretKey<OWF> {
        loop {
            // This is a quirk of the NIST PRG to generate the test vectors. The array has to be sampled at once.
            let mut sk: GenericArray<u8, OWF::SK> = GenericArray::default();
            rng.fill_bytes(&mut sk);

            let owf_input = GenericArray::from_slice(&sk[..OWF::InputSize::USIZE]);
            let owf_key = GenericArray::from_slice(&sk[OWF::InputSize::USIZE..]);

            let test = aes_extendedwitness::<OWF>(owf_key, owf_input).1;
            if !test {
                continue;
            }

            let mut owf_output = GenericArray::default();
            OWF::evaluate_owf(owf_key, owf_input, &mut owf_output);

            return SecretKey {
                owf_key: owf_key.clone(),
                owf_input: owf_input.clone(),
                owf_output,
            };
        }
    }
}

pub(crate) struct EmCypher<OWF>(PhantomData<OWF>)
where
    OWF: PARAMOWF;

impl<OWF: PARAMOWF> Variant<OWF> for EmCypher<OWF> {
    fn witness(
        owf_key: &GenericArray<u8, OWF::LAMBDABYTES>,
        owf_input: &GenericArray<u8, OWF::InputSize>,
    ) -> Box<GenericArray<u8, OWF::LBYTES>> {
        em_extendedwitness::<OWF>(owf_key, owf_input).0
    }

    fn prove(
        w: &GenericArray<u8, OWF::LBYTES>,
        u: &GenericArray<u8, OWF::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, OWF::LAMBDALBYTES>, OWF::LAMBDA>,
        owf_input: &GenericArray<u8, OWF::InputSize>,
        owf_output: &GenericArray<u8, OWF::OutputSize>,
        chall: &GenericArray<u8, OWF::CHALL>,
    ) -> QSProof<OWF> {
        em_prove::<OWF>(w, u, gv, owf_input, owf_output, chall)
    }

    fn verify<Tau>(
        d: &GenericArray<u8, OWF::LBYTES>,
        gq: &GenericArray<GenericArray<u8, OWF::LAMBDALBYTES>, OWF::LAMBDA>,
        a_t: &GenericArray<u8, OWF::LAMBDABYTES>,
        chall2: &GenericArray<u8, OWF::CHALL>,
        chall3: &GenericArray<u8, OWF::LAMBDABYTES>,
        owf_input: &GenericArray<u8, OWF::InputSize>,
        owf_output: &GenericArray<u8, OWF::OutputSize>,
    ) -> GenericArray<u8, OWF::LAMBDABYTES>
    where
        Tau: TauParameters,
    {
        em_verify::<OWF, Tau>(d, gq, a_t, chall2, chall3, owf_input, owf_output)
    }

    fn keygen_with_rng(mut rng: impl RngCore) -> SecretKey<OWF> {
        loop {
            // This is a quirk of the NIST PRG to generate the test vectors. The array has to be sampled at once.
            let mut sk: GenericArray<u8, OWF::SK> = GenericArray::default();
            rng.fill_bytes(&mut sk);

            let owf_input = GenericArray::from_slice(&sk[..OWF::InputSize::USIZE]);
            let owf_key = GenericArray::from_slice(&sk[OWF::InputSize::USIZE..]);

            let test = em_extendedwitness::<OWF>(owf_key, owf_input).1;
            if !test {
                continue;
            }

            let mut owf_output = GenericArray::default();
            OWF::evaluate_owf(owf_key, owf_input, &mut owf_output);

            return SecretKey {
                owf_key: owf_key.clone(),
                owf_input: owf_input.clone(),
                owf_output,
            };
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataChalDec {
        chal: Vec<u8>,
        i: [usize; 1],
        k0: [usize; 1],
        res: Vec<u8>,
    }

    #[test]
    fn chaldec_test() {
        let database: Vec<DataChalDec> =
            serde_json::from_str(include_str!("../tests/data/decode_challenge.json"))
                .expect("error while reading or parsing");
        for data in database {
            if data.chal.len() == 16 {
                if data.k0[0] == 12 {
                    let res = Tau128Small::decode_challenge(&data.chal, data.i[0]);
                    assert_eq!(res, data.res);
                } else {
                    let res = Tau128Fast::decode_challenge(&data.chal, data.i[0]);
                    assert_eq!(res, data.res);
                }
            } else if data.chal.len() == 24 {
                if data.k0[0] == 12 {
                    let res = Tau192Small::decode_challenge(&data.chal, data.i[0]);
                    assert_eq!(res, data.res);
                } else {
                    let res = Tau192Fast::decode_challenge(&data.chal, data.i[0]);
                    assert_eq!(res, data.res);
                }
            } else if data.k0[0] == 12 {
                let res = Tau256Small::decode_challenge(&data.chal, data.i[0]);
                assert_eq!(res, data.res);
            } else {
                let res = Tau256Fast::decode_challenge(&data.chal, data.i[0]);
                assert_eq!(res, data.res);
            }
        }
    }

    fn test_parameters_owf<O: PARAMOWF>() {
        assert_eq!(O::SK::USIZE, O::InputSize::USIZE + O::LAMBDABYTES::USIZE);
        assert_eq!(O::PK::USIZE, O::InputSize::USIZE + O::OutputSize::USIZE);
    }

    #[test]
    fn test_parameters_owf_128() {
        test_parameters_owf::<PARAMOWF128>();
    }

    #[test]
    fn test_parameters_owf_192() {
        test_parameters_owf::<PARAMOWF192>();
    }

    #[test]
    fn test_parameters_owf_256() {
        test_parameters_owf::<PARAMOWF256>();
    }

    #[test]
    fn test_parameters_owf_128em() {
        test_parameters_owf::<PARAMOWF128EM>();
    }

    #[test]
    fn test_parameters_owf_192em() {
        test_parameters_owf::<PARAMOWF192EM>();
    }

    #[test]
    fn test_parameters_owf_256em() {
        test_parameters_owf::<PARAMOWF256EM>();
    }
}
