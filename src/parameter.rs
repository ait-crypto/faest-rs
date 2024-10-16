use aes::{
    cipher::{generic_array::GenericArray as GenericArray_AES, BlockEncrypt, KeyInit},
    Aes128Enc, Aes192Enc, Aes256Enc,
};
use generic_array::{
    typenum::{
        Diff, Prod, Quot, Sum, Unsigned, U0, U1, U10, U1024, U11, U112, U12, U128, U14, U142, U152,
        U16, U160, U16384, U192, U2, U200, U2048, U22, U224, U24, U256, U288, U3, U32, U384, U4,
        U40, U408, U4096, U448, U470, U476, U48, U5, U500, U511, U512, U52, U56, U576, U584, U596,
        U6, U600, U64, U640, U672, U7, U752, U8, U8192, U832, U96,
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
        OutputLength = Self::VoleHasherOutputLength,
    >;
    /// Associated random oracle
    type RandomOracle: RandomOracle;
    /// Associated PRG
    type PRG: PseudoRandomGenerator<Lambda = Self::LambdaBytes>;
    type VC: VectorCommitment<Lambda = Self::LambdaBytes, LambdaTimes2 = Self::LambdaBytesTimes2>;

    /// Security parameter (in bits)
    type Lambda: ArrayLength;
    /// Security parameter (in bytes)
    type LambdaBytes: ArrayLength;
    type LambdaBytesTimes2: ArrayLength;
    type Chall: ArrayLength;
    type Chall1: ArrayLength;
    type VoleHasherOutputLength: ArrayLength;
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    type VoleHasherOutputLength = Sum<Self::LambdaBytes, B>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    type VoleHasherOutputLength = Sum<Self::LambdaBytes, B>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    type VoleHasherOutputLength = Sum<Self::LambdaBytes, B>;
}

pub(crate) type QSProof<O> = (
    GenericArray<u8, <O as OWFParameters>::LAMBDABYTES>,
    GenericArray<u8, <O as OWFParameters>::LAMBDABYTES>,
);

pub(crate) trait OWFParameters: Sized {
    // Base parameters of the OWF
    type BaseParams: BaseParameters<Lambda = Self::LAMBDA, LambdaBytes = Self::LAMBDABYTES>;
    /// The input (= output) size of the OWF (in bytes)
    type InputSize: ArrayLength;

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
    type NST: ArrayLength;
    type LAMBDALBYTES: ArrayLength;
    type LAMBDAL: ArrayLength;
    type PK: ArrayLength;
    type SK: ArrayLength;
    type LHATBYTES: ArrayLength;
    type LAMBDAPLUS2: ArrayLength;
    type LPRIMEBYTE: ArrayLength;
    type KBLENGTH: ArrayLength;
    type PRODRUN128: ArrayLength;
    type PRODSKE8: ArrayLength;
    type LAMBDALBYTESLAMBDA: ArrayLength;
    type LAMBDAR1: ArrayLength;
    type LAMBDAR1BYTE: ArrayLength;

    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]);

    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Option<Box<GenericArray<u8, Self::LBYTES>>>;

    fn witness(
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBYTES>> {
        // SAFETY: only ever called on valid inputs
        Self::extendwitness(owf_key, owf_input).unwrap()
    }

    ///input : witness of l bits, masking values (l+lambda in aes, lambda in em), Vole tag ((l + lambda) *lambda bits), public key, chall(3lambda + 64)
    ///Output : QuickSilver response (Lambda bytes)
    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
        chall: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self>;

    ///input : Masked witness (l bits), Vole Key ((l + lambda) * Lambda bits), hash of constrints values (lambda bits), chall2 (3*lambda + 64 bits), chall3 (lambda bits), public key
    ///output q_tilde - delta * a_tilde (lambda bytes)
    fn verify<Tau>(
        d: &GenericArray<u8, Self::LBYTES>,
        gq: Box<GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>>,
        a_t: &GenericArray<u8, Self::LAMBDABYTES>,
        chall2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall3: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
    ) -> GenericArray<u8, Self::LAMBDABYTES>
    where
        Tau: TauParameters;

    ///input : a random number generator
    /// output = pk : input, output; sk : input, key
    fn keygen_with_rng(mut rng: impl RngCore) -> SecretKey<Self> {
        loop {
            // This is a quirk of the NIST PRG to generate the test vectors. The array has to be sampled at once.
            let mut sk: GenericArray<u8, Self::SK> = GenericArray::default();
            rng.fill_bytes(&mut sk);

            let owf_input = GenericArray::from_slice(&sk[..Self::InputSize::USIZE]);
            let owf_key = GenericArray::from_slice(&sk[Self::InputSize::USIZE..]);

            if Self::extendwitness(owf_key, owf_input).is_none() {
                continue;
            }

            let mut owf_output = GenericArray::default();
            Self::evaluate_owf(owf_key, owf_input, &mut owf_output);

            return SecretKey {
                owf_key: owf_key.clone(),
                owf_input: owf_input.clone(),
                owf_output,
            };
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF128;

impl OWFParameters for OWF128 {
    type BaseParams = BaseParams128;
    type InputSize = U16;

    type LAMBDA = U128;
    type LAMBDABYTES = U16;
    type L = Sum<U1024, U576>;
    type LBYTES = U200;
    type LAMBDALBYTES = Sum<Self::LAMBDABYTES, Self::LBYTES>;
    type NK = U4;
    type R = U10;
    type SKE = U40;
    type SENC = U160;
    type LKE = U448;
    type LENC = Sum<U1024, U128>;
    type BETA = U1;
    type NST = U0;
    type PK = U32;
    type SK = U32;
    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;
    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;
    type LPRIMEBYTE = U256;
    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;
    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;
    type PRODSKE8 = Prod<Self::SKE, U8>;
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

    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Option<Box<GenericArray<u8, Self::LBYTES>>> {
        aes_extendedwitness::<Self>(owf_key, owf_input)
    }

    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
        chall: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, gv, owf_input, owf_output, chall)
    }

    fn verify<Tau>(
        d: &GenericArray<u8, Self::LBYTES>,
        gq: Box<GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>>,
        a_t: &GenericArray<u8, Self::LAMBDABYTES>,
        chall2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall3: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
    ) -> GenericArray<u8, Self::LAMBDABYTES>
    where
        Tau: TauParameters,
    {
        aes_verify::<Self, Tau>(d, gq, a_t, chall2, chall3, owf_input, owf_output)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF192;

impl OWFParameters for OWF192 {
    type BaseParams = BaseParams192;
    type InputSize = U32;

    type LAMBDA = U192;
    type LAMBDABYTES = U24;
    type L = Diff<U4096, U832>;
    type LBYTES = U408;
    type LAMBDALBYTES = Sum<Self::LAMBDABYTES, Self::LBYTES>;
    type NK = U6;
    type R = U12;
    type SKE = U32;
    type SENC = U192;
    type LKE = U448;
    type LENC = Sum<U1024, U384>;
    type BETA = U2;
    type NST = U0;
    type PK = U64;
    type SK = U56;
    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;
    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;
    type LPRIMEBYTE = U384;
    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;
    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;
    type PRODSKE8 = Prod<Self::SKE, U8>;
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

    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Option<Box<GenericArray<u8, Self::LBYTES>>> {
        aes_extendedwitness::<Self>(owf_key, owf_input)
    }

    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
        chall: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, gv, owf_input, owf_output, chall)
    }

    fn verify<Tau>(
        d: &GenericArray<u8, Self::LBYTES>,
        gq: Box<GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>>,
        a_t: &GenericArray<u8, Self::LAMBDABYTES>,
        chall2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall3: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
    ) -> GenericArray<u8, Self::LAMBDABYTES>
    where
        Tau: TauParameters,
    {
        aes_verify::<Self, Tau>(d, gq, a_t, chall2, chall3, owf_input, owf_output)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF256;

impl OWFParameters for OWF256 {
    type BaseParams = BaseParams256;
    type InputSize = U32;

    type LAMBDA = U256;
    type LAMBDABYTES = U32;
    type L = Diff<U4096, U96>;
    type LBYTES = U500;
    type LAMBDALBYTES = Sum<Self::LAMBDABYTES, Self::LBYTES>;
    type NK = U8;
    type R = U14;
    type SKE = U52;
    type SENC = U224;
    type LKE = U672;
    type LENC = Sum<U1024, U640>;
    type BETA = U2;
    type NST = U0;
    type PK = U64;
    type SK = U64;
    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;
    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;
    type LPRIMEBYTE = U512;
    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;
    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;
    type PRODSKE8 = Prod<Self::SKE, U8>;
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

    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Option<Box<GenericArray<u8, Self::LBYTES>>> {
        aes_extendedwitness::<Self>(owf_key, owf_input)
    }

    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
        chall: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, gv, owf_input, owf_output, chall)
    }

    fn verify<Tau>(
        d: &GenericArray<u8, Self::LBYTES>,
        gq: Box<GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>>,
        a_t: &GenericArray<u8, Self::LAMBDABYTES>,
        chall2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall3: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
    ) -> GenericArray<u8, Self::LAMBDABYTES>
    where
        Tau: TauParameters,
    {
        aes_verify::<Self, Tau>(d, gq, a_t, chall2, chall3, owf_input, owf_output)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF128EM;

impl OWFParameters for OWF128EM {
    type BaseParams = BaseParams128;
    type InputSize = U16;

    type LAMBDA = U128;
    type LAMBDABYTES = U16;
    type L = Sum<U1024, U256>;
    type LBYTES = U160;
    type LAMBDALBYTES = Sum<Self::LAMBDABYTES, Self::LBYTES>;
    type NK = U4;
    type R = U10;
    type SKE = U40;
    type SENC = U160;
    type LKE = U448;
    type LENC = Sum<U1024, U128>;
    type BETA = U1;
    type NST = U4;
    type PK = U32;
    type SK = U32;
    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;
    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;
    type LPRIMEBYTE = U256;
    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;
    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;
    type PRODSKE8 = Prod<Self::SKE, U8>;
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

    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Option<Box<GenericArray<u8, Self::LBYTES>>> {
        em_extendedwitness::<Self>(owf_key, owf_input)
    }

    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
        chall: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        em_prove::<Self>(w, u, gv, owf_input, owf_output, chall)
    }

    fn verify<Tau>(
        d: &GenericArray<u8, Self::LBYTES>,
        gq: Box<GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>>,
        a_t: &GenericArray<u8, Self::LAMBDABYTES>,
        chall2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall3: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
    ) -> GenericArray<u8, Self::LAMBDABYTES>
    where
        Tau: TauParameters,
    {
        em_verify::<Self, Tau>(d, gq, a_t, chall2, chall3, owf_input, owf_output)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF192EM;

impl OWFParameters for OWF192EM {
    type BaseParams = BaseParams192;
    type InputSize = U24;

    type LAMBDA = U192;
    type LAMBDABYTES = U24;
    type L = Sum<U2048, U256>;
    type LBYTES = U288;
    type LAMBDALBYTES = Sum<Self::LAMBDABYTES, Self::LBYTES>;
    type NK = U6;
    type R = U12;
    type SKE = U32;
    type SENC = U288;
    type LKE = U448;
    type LENC = Sum<U1024, U384>;
    type BETA = U2;
    type NST = U6;
    type PK = U48;
    type SK = U48;
    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;
    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;
    type LPRIMEBYTE = U384;
    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;
    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;
    type PRODSKE8 = Prod<Self::SKE, U8>;
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

    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Option<Box<GenericArray<u8, Self::LBYTES>>> {
        em_extendedwitness::<Self>(owf_key, owf_input)
    }

    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
        chall: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        em_prove::<Self>(w, u, gv, owf_input, owf_output, chall)
    }

    fn verify<Tau>(
        d: &GenericArray<u8, Self::LBYTES>,
        gq: Box<GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>>,
        a_t: &GenericArray<u8, Self::LAMBDABYTES>,
        chall2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall3: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
    ) -> GenericArray<u8, Self::LAMBDABYTES>
    where
        Tau: TauParameters,
    {
        em_verify::<Self, Tau>(d, gq, a_t, chall2, chall3, owf_input, owf_output)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF256EM;

impl OWFParameters for OWF256EM {
    type BaseParams = BaseParams256;
    type InputSize = U32;

    type LAMBDA = U256;
    type LAMBDABYTES = U32;
    type L = Diff<U4096, U512>;
    type LBYTES = U448;
    type LAMBDALBYTES = Sum<Self::LAMBDABYTES, Self::LBYTES>;
    type NK = U8;
    type R = U14;
    type SKE = U52;
    type SENC = U448;
    type LKE = U672;
    type LENC = Sum<U1024, U640>;
    type BETA = U2;
    type NST = U8;
    type PK = U64;
    type SK = U64;
    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;
    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;
    type LPRIMEBYTE = U512;
    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;
    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;
    type PRODSKE8 = Prod<Self::SKE, U8>;
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

    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Option<Box<GenericArray<u8, Self::LBYTES>>> {
        em_extendedwitness::<Self>(owf_key, owf_input)
    }

    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDALBYTES>,
        gv: &GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
        chall: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        em_prove::<Self>(w, u, gv, owf_input, owf_output, chall)
    }

    fn verify<Tau>(
        d: &GenericArray<u8, Self::LBYTES>,
        gq: Box<GenericArray<GenericArray<u8, Self::LAMBDALBYTES>, Self::LAMBDA>>,
        a_t: &GenericArray<u8, Self::LAMBDABYTES>,
        chall2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall3: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
        owf_output: &GenericArray<u8, Self::InputSize>,
    ) -> GenericArray<u8, Self::LAMBDABYTES>
    where
        Tau: TauParameters,
    {
        em_verify::<Self, Tau>(d, gq, a_t, chall2, chall3, owf_input, owf_output)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau128Small;

impl TauParameters for Tau128Small {
    type Tau = U11;
    type TauMinus1 = Diff<Self::Tau, U1>;
    type K0 = U12;
    type K1 = U11;
    type Tau0 = U7;
    type Tau1 = U4;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau128Fast;

impl TauParameters for Tau128Fast {
    type Tau = U16;
    type TauMinus1 = Diff<Self::Tau, U1>;
    type K0 = U8;
    type K1 = U8;
    type Tau0 = U8;
    type Tau1 = U8;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau192Small;

impl TauParameters for Tau192Small {
    type Tau = U16;
    type TauMinus1 = Diff<Self::Tau, U1>;
    type K0 = U12;
    type K1 = U12;
    type Tau0 = U8;
    type Tau1 = U8;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau192Fast;

impl TauParameters for Tau192Fast {
    type Tau = U24;
    type TauMinus1 = Diff<Self::Tau, U1>;
    type K0 = U8;
    type K1 = U8;
    type Tau0 = U12;
    type Tau1 = U12;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau256Small;

impl TauParameters for Tau256Small {
    type Tau = U22;
    type TauMinus1 = Diff<Self::Tau, U1>;
    type K0 = U12;
    type K1 = U11;
    type Tau0 = U14;
    type Tau1 = U8;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tau256Fast;

impl TauParameters for Tau256Fast {
    type Tau = U32;
    type TauMinus1 = Diff<Self::Tau, U1>;
    type K0 = U8;
    type K1 = U8;
    type Tau0 = U16;
    type Tau1 = U16;
}

pub(crate) trait FAESTParameters {
    type OWF: OWFParameters;
    type Tau: TauParameters;

    type N0: ArrayLength;
    type N1: ArrayLength;
    type POWK0: ArrayLength;
    type POWK1: ArrayLength;
    type SIG: ArrayLength;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST128sParameters;

impl FAESTParameters for FAEST128sParameters {
    type OWF = OWF128;
    type Tau = Tau128Small;

    type N0 = U4096;
    type POWK0 = Diff<U8192, U1>;
    type N1 = U2048;
    type POWK1 = Diff<U4096, U1>;

    type SIG = Sum<U142, Sum<U256, Sum<U512, U4096>>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST128fParameters;

impl FAESTParameters for FAEST128fParameters {
    type OWF = OWF128;
    type Tau = Tau128Fast;

    type N0 = U256;
    type POWK0 = U511;
    type N1 = U256;
    type POWK1 = U511;
    type SIG = Sum<U192, Sum<U2048, U4096>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST192sParameters;

impl FAESTParameters for FAEST192sParameters {
    type OWF = OWF192;
    type Tau = Tau192Small;

    type N0 = U4096;
    type POWK0 = Diff<U8192, U1>;
    type N1 = U4096;
    type POWK1 = Diff<U8192, U1>;
    type SIG = Sum<U200, Sum<U256, Sum<U8192, U4096>>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST192fParameters;

impl FAESTParameters for FAEST192fParameters {
    type OWF = OWF192;
    type Tau = Tau192Fast;

    type N0 = U256;
    type POWK0 = U511;
    type N1 = U256;
    type POWK1 = U511;
    type SIG = Sum<U152, Sum<U256, U16384>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST256sParameters;

impl FAESTParameters for FAEST256sParameters {
    type OWF = OWF256;
    type Tau = Tau256Small;

    type N0 = U4096;
    type POWK0 = Diff<U8192, U1>;
    type N1 = U2048;
    type POWK1 = Diff<U4096, U1>;
    type SIG = Sum<U596, Sum<U1024, Sum<U4096, U16384>>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST256fParameters;

impl FAESTParameters for FAEST256fParameters {
    type OWF = OWF256;
    type Tau = Tau256Fast;

    type N0 = U256;
    type POWK0 = U511;
    type N1 = U256;
    type POWK1 = U511;
    type SIG = Sum<U752, Sum<U1024, Sum<U2048, Sum<U8192, U16384>>>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM128sParameters;

impl FAESTParameters for FAESTEM128sParameters {
    type OWF = OWF128EM;
    type Tau = Tau128Small;

    type N0 = U4096;
    type POWK0 = Diff<U8192, U1>;
    type N1 = U2048;
    type POWK1 = Diff<U4096, U1>;
    type SIG = Sum<U470, U4096>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM128fParameters;

impl FAESTParameters for FAESTEM128fParameters {
    type OWF = OWF128EM;
    type Tau = Tau128Fast;

    type N0 = U256;
    type POWK0 = U511;
    type N1 = U256;
    type POWK1 = U511;
    type SIG = Sum<U576, Sum<U1024, U4096>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM192sParameters;

impl FAESTParameters for FAESTEM192sParameters {
    type OWF = OWF192EM;
    type Tau = Tau192Small;

    type N0 = U4096;
    type POWK0 = Diff<U8192, U1>;
    type N1 = U4096;
    type POWK1 = Diff<U8192, U1>;
    type SIG = Sum<U584, Sum<U2048, U8192>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM192fParameters;

impl FAESTParameters for FAESTEM192fParameters {
    type OWF = OWF192EM;
    type Tau = Tau192Fast;

    type N0 = U256;
    type POWK0 = U511;
    type N1 = U256;
    type POWK1 = U511;
    type SIG = Sum<U600, Sum<U1024, Sum<U4096, U8192>>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM256sParameters;

impl FAESTParameters for FAESTEM256sParameters {
    type OWF = OWF256EM;
    type Tau = Tau256Small;

    type N0 = U4096;
    type POWK0 = Diff<U8192, U1>;
    type N1 = U2048;
    type POWK1 = Diff<U4096, U1>;
    type SIG = Sum<U476, Sum<U4096, U16384>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAESTEM256fParameters;

impl FAESTParameters for FAESTEM256fParameters {
    type OWF = OWF256EM;
    type Tau = Tau256Fast;

    type N0 = U256;
    type POWK0 = U511;
    type N1 = U256;
    type POWK1 = U511;
    type SIG = Sum<U112, Sum<U2048, Sum<U8192, U16384>>>;
}

#[cfg(test)]
mod test {
    use super::*;

    use serde::Deserialize;

    use crate::utils::test::read_test_data;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DataChalDec {
        chal: Vec<u8>,
        i: [usize; 1],
        k0: [usize; 1],
        res: Vec<u8>,
    }

    #[test]
    fn chaldec() {
        let database: Vec<DataChalDec> = read_test_data("decode_challenge.json");
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

    #[generic_tests::define]
    mod parameters {
        use super::*;

        #[test]
        fn pk_sk_size<O: OWFParameters>() {
            assert_eq!(O::SK::USIZE, O::InputSize::USIZE + O::LAMBDABYTES::USIZE);
            assert_eq!(O::PK::USIZE, O::InputSize::USIZE + O::InputSize::USIZE);
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
}
