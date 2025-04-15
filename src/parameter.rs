use std::{
    ops::{Add, Div, Mul, Sub},
    process::Output,
};

use aes::{
    cipher::{generic_array::GenericArray as GenericArray_AES, BlockEncrypt, KeyInit},
    Aes128Enc, Aes192Enc, Aes256Enc,
};
use generic_array::{
    typenum::{
        self, Diff, Prod, Quot, Sum, Unsigned, U0, U1, U10, U1000, U102, U1024, U103, U11, U110,
        U112, U12, U120, U128, U13, U14, U142, U152, U16, U160, U162, U163, U16384, U17, U176,
        U192, U2, U20, U200, U2048, U212, U216, U218, U22, U23, U234, U24, U245, U246, U256, U26,
        U260, U280, U288, U3, U312, U32, U320, U32768, U33, U336, U340, U380, U384, U388, U4, U40,
        U408, U4096, U410, U44, U448, U460, U470, U476, U48, U5, U500, U506, U511, U512, U52, U548,
        U56, U576, U584, U596, U6, U60, U600, U64, U640, U65536, U672, U68, U688, U696, U7, U752,
        U756, U8, U8192, U828, U832, U9, U906, U924, U948, U96, U960, U984, U992,
    },
    ArrayLength, GenericArray,
};
use rand_core::RngCore;

use crate::{
    bavc::{
        BAVC128Fast, BAVC128FastEM, BAVC128Small, BAVC128SmallEM, BAVC192Fast, BAVC192FastEM,
        BAVC192Small, BAVC192SmallEM, BAVC256Fast, BAVC256FastEM, BAVC256Small, BAVC256SmallEM,
        BatchVectorCommitment, BAVC,
    },
    fields::{BigGaloisField, GF128, GF192, GF256},
    internal_keys::{PublicKey, SecretKey},
    prg::{PseudoRandomGenerator, PRG128, PRG192, PRG256},
    random_oracles::{RandomOracle, RandomOracleShake128, RandomOracleShake256},
    rijndael_32::{Rijndael192, Rijndael256},
    universal_hashing::{VoleHasher, VoleHasherInit, ZKHasher, ZKHasherInit, B},
    utils::get_bit,
    witness::aes_extendedwitness,
    zk_constraints::aes_verify,
    zk_constraints::{aes_prove, CstrntsVal},
};

// l_hat = l + 3*lambda + B
type LHatBytes<LBytes, LambdaBytes, B> = Sum<LBytes, Sum<Prod<U3, LambdaBytes>, Quot<B, U8>>>;

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

    type Lambda = U256;
    type LambdaBytes = U32;
    type LambdaBytesTimes2 = U64;

    type Chall = Sum<U8, Prod<U3, Self::LambdaBytes>>;
    type Chall1 = Sum<U8, Prod<U5, Self::LambdaBytes>>;
    type VoleHasherOutputLength = Sum<Self::LambdaBytes, B>;
}

pub(crate) type QSProof<O> = (
    <<O as OWFParameters>::BaseParams as BaseParameters>::Field,
    <<O as OWFParameters>::BaseParams as BaseParameters>::Field,
    <<O as OWFParameters>::BaseParams as BaseParameters>::Field,
);

pub(crate) type OWFField<O> = <<O as OWFParameters>::BaseParams as BaseParameters>::Field;

pub(crate) trait OWFParameters: Sized {
    // Base parameters of the OWF
    type BaseParams: BaseParameters<Lambda = Self::LAMBDA, LambdaBytes = Self::LAMBDABYTES>;
    /// The input size of the OWF (in bytes)
    type InputSize: ArrayLength + Mul<U8, Output: ArrayLength>;
    /// The output size of the OWF (in bytes)
    type OutputSize: ArrayLength + Mul<U8, Output: ArrayLength>;

    type B: ArrayLength;
    type LAMBDA: ArrayLength + Mul<U2, Output: ArrayLength>;
    type LAMBDABYTES: SecurityParameter
        + Mul<Self::NLeafCommit, Output: ArrayLength>
        + Mul<U2, Output = Self::LAMBDABYTESTWO>
        + Mul<U8, Output = Self::LAMBDA>;
    type LAMBDABYTESTWO: ArrayLength + Add<Self::LBYTES, Output = Self::LAMBDALBYTES>;

    type L: ArrayLength;
    type LBYTES: ArrayLength + Mul<U8, Output = Self::L>;
    type LHATBYTES: ArrayLength + Mul<U8, Output: ArrayLength>;

    type BETA: ArrayLength;
    type NK: ArrayLength;
    type R: ArrayLength;
    type SKE: ArrayLength + Mul<U8, Output: ArrayLength>;
    type LKE: ArrayLength;
    type LKEBytes: ArrayLength + Mul<U8, Output = Self::LKE>;
    type LENC: ArrayLength;
    type LENCBytes: ArrayLength + Mul<U8, Output: ArrayLength>;
    type NST: ArrayLength + Mul<U4, Output = Self::NSTBytes>;
    type NSTBytes: ArrayLength
        + Mul<U8, Output = Self::NSTBits>
        + Div<U2, Output: ArrayLength + Mul<U8, Output: ArrayLength>>;
    type NSTBits: ArrayLength
        + Mul<U4, Output: ArrayLength>
        + Div<U2, Output: ArrayLength + Mul<U8, Output: ArrayLength>>;
    type NLeafCommit: ArrayLength;
    type LAMBDALBYTES: ArrayLength + Mul<U8, Output: ArrayLength>;

    type PRODRUN128Bytes: ArrayLength
        + Mul<U8, Output = Self::PRODRUN128>
        + Sub<Self::LKEBytes, Output: ArrayLength>;
    type PRODRUN128: ArrayLength + Sub<Self::LKE, Output: ArrayLength>;

    type DIFFLKELAMBDA: ArrayLength;
    type DIFFLKELAMBDABytes: ArrayLength + Mul<U8, Output: ArrayLength>;

    type SK: ArrayLength;
    type PK: ArrayLength;

    fn is_em() -> bool;

    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]);

    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBYTES>>;

    fn witness(sk: &SecretKey<Self>) -> Box<GenericArray<u8, Self::LBYTES>> {
        Self::extendwitness(&sk.owf_key, &sk.pk.owf_input)
    }

    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDABYTESTWO>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self>;

    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBYTES>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LAMBDABYTES>,
        a1_tilde: &OWFField<Self>,
        a2_tilde: &OWFField<Self>,
    ) -> OWFField<Self>;

    fn keygen_with_rng(mut rng: impl RngCore) -> SecretKey<Self> {

        let mut owf_input = GenericArray::default();
        let mut owf_key = GenericArray::default();
        
        let mut done = false;
        while !done {

            // TODO: Fix RNG and remove this line
            owf_key.fill(0);

            rng.fill_bytes(&mut owf_key);

            if (get_bit(&owf_key, 0) & get_bit(&owf_key, 1)) == 0 {
                done = true;
            }

        }


        rng.fill_bytes(&mut owf_input);


        let mut owf_output = GenericArray::default();
        Self::evaluate_owf(&owf_key, &owf_input, &mut owf_output);

        return SecretKey {
            owf_key,
            pk: PublicKey {
                owf_input,
                owf_output,
            },
        };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF128;

impl OWFParameters for OWF128 {
    type BaseParams = BaseParams128;
    type InputSize = U16;
    type OutputSize = U16;

    type B = U16;
    type LAMBDA = U128;
    type LAMBDABYTES = U16;
    type LAMBDABYTESTWO = Prod<Self::LAMBDABYTES, U2>;
    type LBYTES = U160;
    type L = Prod<Self::LBYTES, U8>;
    type LHATBYTES = LHatBytes<Self::LBYTES, Self::LAMBDABYTES, Self::B>;

    type NK = U4;
    type R = U10;
    type SKE = U40;
    type BETA = U1;
    type LKE = U448;
    type LKEBytes = Quot<Self::LKE, U8>;
    type LENC = U832;
    type LENCBytes = Quot<Self::LENC, U8>;
    type NST = U4;
    type NSTBytes = Prod<Self::NST, U4>;
    type NSTBits = Prod<Self::NSTBytes, U8>;
    type NLeafCommit = U3;
    type LAMBDALBYTES = Sum<Self::LAMBDABYTESTWO, Self::LBYTES>;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;
    type PRODRUN128Bytes = Quot<Self::PRODRUN128, U8>;

    type DIFFLKELAMBDA = Diff<Self::LKE, Self::LAMBDA>;
    type DIFFLKELAMBDABytes = Quot<Self::DIFFLKELAMBDA, U8>;

    type SK = U32;
    type PK = U32;

    fn is_em() -> bool {
        false
    }
    //type PK = U32;

    // type SK = U32;
    // type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;
    // type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;
    // type QUOTLENC8 = Quot<Self::LENC, U8>;
    // type LAMBDAL = Sum<Self::LAMBDA, Self::L>;
    // type LAMBDAR1BYTE = Quot<Prod<Self::LAMBDA, Sum<Self::R, U1>>, U8>;

    fn evaluate_owf(key: &[u8], input: &[u8], output: &mut [u8]) {
        let aes = Aes128Enc::new(GenericArray_AES::from_slice(key));
        aes.encrypt_block_b2b(
            GenericArray_AES::from_slice(input),
            GenericArray_AES::from_mut_slice(output),
        );
    }

    #[inline]
    fn extendwitness(
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBYTES>> {
        aes_extendedwitness::<Self>(owf_key, owf_input)
    }

    #[inline]
    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDABYTESTWO>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, v, pk, chall_2)
    }

    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBYTES>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LAMBDABYTES>,
        a1_tilde: &OWFField<Self>,
        a2_tilde: &OWFField<Self>,
    ) -> OWFField<Self> {
        aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF192;

impl OWFParameters for OWF192 {
    type BaseParams = BaseParams192;
    type InputSize = U16;
    type OutputSize = U32;

    type B = U16;
    type LAMBDA = U192;
    type LAMBDABYTES = U24;
    type LAMBDABYTESTWO = Prod<Self::LAMBDABYTES, U2>;
    type LBYTES = U312;
    type L = Prod<Self::LBYTES, U8>;
    type LHATBYTES = LHatBytes<Self::LBYTES, Self::LAMBDABYTES, Self::B>;
    type LAMBDALBYTES = Sum<Self::LAMBDABYTESTWO, Self::LBYTES>;

    type NK = U6;
    type R = U12;
    type SKE = U32;
    type BETA = U2;
    type LKE = U448;
    type LKEBytes = Quot<Self::LKE, U8>;
    type LENC = U1024;
    type LENCBytes = Quot<Self::LENC, U8>;
    type NST = U4;
    type NSTBytes = Prod<Self::NST, U4>;
    type NSTBits = Prod<Self::NSTBytes, U8>;
    type NLeafCommit = U3;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;
    type PRODRUN128Bytes = Quot<Self::PRODRUN128, U8>;

    type DIFFLKELAMBDA = Diff<Self::LKE, Self::LAMBDA>;
    type DIFFLKELAMBDABytes = Quot<Self::DIFFLKELAMBDA, U8>;

    type SK = U40;
    type PK = U48;

    fn is_em() -> bool {
        false
    }

    // type LAMBDALBYTES = Sum<Self::LAMBDABYTES, Self::LBYTES>;
    // type NK = U6;
    // type R = U12;
    // type SKE = U32;
    // type LKE = U448;
    // type LKEBytes = Quot<Self::LKE, U8>;
    // type LENC = Sum<U1024, U384>;
    // type NST = U0;
    // type PK = U64;
    // type SK = U56;
    // type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;
    // type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;
    // type PRODRUN128Bytes = Quot<Self::PRODRUN128, U8>;
    // type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;
    // type QUOTLENC8 = Quot<Self::LENC, U8>;
    // type LAMBDAL = Sum<Self::LAMBDA, Self::L>;
    // type LAMBDAR1BYTE = Quot<Prod<Self::LAMBDA, Sum<Self::R, U1>>, U8>;

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
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBYTES>> {
        aes_extendedwitness::<Self>(owf_key, owf_input)
    }

    #[inline]
    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDABYTESTWO>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, v, pk, chall_2)
    }

    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBYTES>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LAMBDABYTES>,
        a1_tilde: &OWFField<Self>,
        a2_tilde: &OWFField<Self>,
    ) -> OWFField<Self> {
        aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
    }
}

type U1216 = Sum<U1024, U192>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF256;

impl OWFParameters for OWF256 {
    type BaseParams = BaseParams256;
    type InputSize = U16;
    type OutputSize = U32;

    type B = U16;
    type LAMBDA = U256;
    type LAMBDABYTES = U32;
    type LAMBDABYTESTWO = Prod<Self::LAMBDABYTES, U2>;
    type LBYTES = U388;
    type L = Prod<Self::LBYTES, U8>;
    type LHATBYTES = LHatBytes<Self::LBYTES, Self::LAMBDABYTES, Self::B>;
    type LAMBDALBYTES = Sum<Self::LAMBDABYTESTWO, Self::LBYTES>;

    type NK = U8;
    type R = U14;
    type SKE = U52;
    type BETA = U2;
    type LKE = U672;
    type LKEBytes = Quot<Self::LKE, U8>;
    type LENC = U1216;
    type LENCBytes = Quot<Self::LENC, U8>;
    type NST = U4;
    type NSTBytes = Prod<Self::NST, U4>;
    type NSTBits = Prod<Self::NSTBytes, U8>;
    type NLeafCommit = U3;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;
    type PRODRUN128Bytes = Quot<Self::PRODRUN128, U8>;

    type DIFFLKELAMBDA = Diff<Self::LKE, Self::LAMBDA>;
    type DIFFLKELAMBDABytes = Quot<Self::DIFFLKELAMBDA, U8>;

    type SK = U48;
    type PK = U48;

    fn is_em() -> bool {
        false
    }

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
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBYTES>> {
        aes_extendedwitness::<Self>(owf_key, owf_input)
    }

    #[inline]
    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDABYTESTWO>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, v, pk, chall_2)
    }

    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBYTES>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LAMBDABYTES>,
        a1_tilde: &OWFField<Self>,
        a2_tilde: &OWFField<Self>,
    ) -> OWFField<Self> {
        aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF128EM;

impl OWFParameters for OWF128EM {
    type BaseParams = BaseParams128;
    type InputSize = U16;
    type OutputSize = U16;

    type B = U16;
    type LAMBDA = U128;
    type LAMBDABYTES = U16;
    type LAMBDABYTESTWO = Prod<Self::LAMBDABYTES, U2>;
    type LBYTES = U120;
    type L = Prod<Self::LBYTES, U8>;
    type LHATBYTES = LHatBytes<Self::LBYTES, Self::LAMBDABYTES, Self::B>;
    type LAMBDALBYTES = Sum<Self::LAMBDABYTESTWO, Self::LBYTES>;

    type NK = U4;
    type NST = U4;
    type NSTBytes = Prod<Self::NST, U4>;
    type NSTBits = Prod<Self::NSTBytes, U8>;
    type R = U10;
    type SKE = U40;
    type BETA = U1;
    type LKE = U128;
    type LKEBytes = Quot<Self::LKE, U8>;
    type LENC = U832;
    type LENCBytes = Quot<Self::LENC, U8>;
    type NLeafCommit = U2;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;
    type PRODRUN128Bytes = Quot<Self::PRODRUN128, U8>;

    type DIFFLKELAMBDA = Diff<Self::LKE, Self::LAMBDA>;
    type DIFFLKELAMBDABytes = Quot<Self::DIFFLKELAMBDA, U8>;

    type SK = U32;
    type PK = U32;

    fn is_em() -> bool {
        true
    }

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
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBYTES>> {
        aes_extendedwitness::<Self>(owf_input, owf_key)
    }

    #[inline]
    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDABYTESTWO>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, v, pk, chall_2)
    }

    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBYTES>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LAMBDABYTES>,
        a1_tilde: &OWFField<Self>,
        a2_tilde: &OWFField<Self>,
    ) -> OWFField<Self> {
        aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF192EM;

type U1536 = Sum<U1024, U512>;

impl OWFParameters for OWF192EM {
    type BaseParams = BaseParams192;
    type InputSize = U24;
    type OutputSize = U24;

    type B = U16;
    type LAMBDA = U192;
    type LAMBDABYTES = U24;
    type LAMBDABYTESTWO = Prod<Self::LAMBDABYTES, U2>;
    type LBYTES = U216;
    type L = Prod<Self::LBYTES, U8>;
    type LHATBYTES = LHatBytes<Self::LBYTES, Self::LAMBDABYTES, Self::B>;
    type LAMBDALBYTES = Sum<Self::LAMBDABYTESTWO, Self::LBYTES>;

    type NK = U6;
    type NST = U6;
    type NSTBytes = Prod<Self::NST, U4>;
    type NSTBits = Prod<Self::NSTBytes, U8>;
    type BETA = U1;
    type R = U12;
    type SKE = U52;
    type LKE = U192;
    type LKEBytes = Quot<Self::LKE, U8>;
    type LENC = U1536;
    type LENCBytes = Quot<Self::LENC, U8>;
    type NLeafCommit = U2;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, Self::LAMBDA>;
    type PRODRUN128Bytes = Quot<Self::PRODRUN128, U8>;

    type DIFFLKELAMBDA = Diff<Self::LKE, Self::LAMBDA>;
    type DIFFLKELAMBDABytes = Quot<Self::DIFFLKELAMBDA, U8>;

    type SK = U48;
    type PK = U48;

    fn is_em() -> bool {
        true
    }
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
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBYTES>> {
        aes_extendedwitness::<Self>(owf_input, owf_key)
    }

    #[inline]
    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDABYTESTWO>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, v, pk, chall_2)
    }

    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBYTES>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LAMBDABYTES>,
        a1_tilde: &OWFField<Self>,
        a2_tilde: &OWFField<Self>,
    ) -> OWFField<Self> {
        aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
    }
}

type U2432 = Sum<U2048, U384>;
type U2688 = Sum<Prod<U1000, U2>, U688>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OWF256EM;

impl OWFParameters for OWF256EM {
    type BaseParams = BaseParams256;
    type InputSize = U32;
    type OutputSize = U32;

    type B = U16;
    type LAMBDA = U256;
    type LAMBDABYTES = U32;
    type LAMBDABYTESTWO = Prod<Self::LAMBDABYTES, U2>;
    type LBYTES = U336;
    type L = Prod<Self::LBYTES, U8>;
    type LHATBYTES = LHatBytes<Self::LBYTES, Self::LAMBDABYTES, Self::B>;
    type LAMBDALBYTES = Sum<Self::LAMBDABYTESTWO, Self::LBYTES>;

    type NK = U8;
    type NST = U8;
    type NSTBytes = Prod<Self::NST, U4>;
    type NSTBits = Prod<Self::NSTBytes, U8>;
    type BETA = U1;
    type R = U14;
    type SKE = U60;
    type LKE = U256;
    type LKEBytes = Quot<Self::LKE, U8>;
    type LENC = U2432;
    type LENCBytes = Quot<Self::LENC, U8>;
    type NLeafCommit = U2;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, Self::LAMBDA>;
    type PRODRUN128Bytes = Quot<Self::PRODRUN128, U8>;

    type DIFFLKELAMBDA = Diff<Self::LKE, Self::LAMBDA>;
    type DIFFLKELAMBDABytes = Quot<Self::DIFFLKELAMBDA, U8>;

    type SK = U64;
    type PK = U64;

    fn is_em() -> bool {
        true
    }

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
        owf_key: &GenericArray<u8, Self::LAMBDABYTES>,
        owf_input: &GenericArray<u8, Self::InputSize>,
    ) -> Box<GenericArray<u8, Self::LBYTES>> {
        aes_extendedwitness::<Self>(owf_input, owf_key)
    }

    #[inline]
    fn prove(
        w: &GenericArray<u8, Self::LBYTES>,
        u: &GenericArray<u8, Self::LAMBDABYTESTWO>,
        v: CstrntsVal<Self>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
    ) -> QSProof<Self> {
        aes_prove::<Self>(w, u, v, pk, chall_2)
    }

    #[inline]
    fn verify(
        q: CstrntsVal<Self>,
        d: &GenericArray<u8, Self::LBYTES>,
        pk: &PublicKey<Self>,
        chall_2: &GenericArray<u8, <Self::BaseParams as BaseParameters>::Chall>,
        chall_3: &GenericArray<u8, Self::LAMBDABYTES>,
        a1_tilde: &OWFField<Self>,
        a2_tilde: &OWFField<Self>,
    ) -> OWFField<Self> {
        aes_verify::<Self>(q, d, pk, chall_2, chall_3, a1_tilde, a2_tilde)
    }
}

pub(crate) trait TauParameters {
    type Tau: ArrayLength;
    type K: ArrayLength;
    type Tau0: ArrayLength;
    type Tau1: ArrayLength;
    type L: ArrayLength;
    type Topen: ArrayLength;

    // fn decode_challenge(chal: &[u8], i: usize) -> Vec<u8> {
    //     Self::decode_challenge_as_iter(chal, i).collect()
    // }

    fn decode_challenge_as_iter(chal: &[u8], i: usize) -> impl Iterator<Item = u8> + '_ {
        let (lo, hi) = if i < Self::Tau1::USIZE {
            let lo = Self::tau1_offset_unchecked(i);
            let hi = lo + Self::K::USIZE - 1;
            (lo, hi)
        } else {
            debug_assert!(i < Self::Tau0::USIZE + Self::Tau1::USIZE);
            let lo = Self::tau0_offset_unchecked(i);
            let hi = lo + (Self::K::USIZE - 1) - 1;
            (lo, hi)
        };

        (lo..=hi).map(move |j| (chal[j / 8] >> (j % 8)) & 1)
    }

    #[inline]
    fn tau1_offset_unchecked(i: usize) -> usize {
        Self::K::USIZE * i
    }

    #[inline]
    fn tau0_offset_unchecked(i: usize) -> usize {
        Self::Tau1::USIZE * (Self::K::USIZE) + (Self::K::USIZE - 1) * (i - Self::Tau1::USIZE)
    }

    fn bavc_depth_offset(i: usize) -> usize {
        debug_assert!(i < Self::Tau::USIZE);

        if i < Self::Tau1::USIZE {
            return Self::K::USIZE * i;
        }

        Self::Tau1::USIZE * (Self::K::USIZE) + (Self::K::USIZE - 1) * (i - Self::Tau1::USIZE)
    }

    fn bavc_index_offset(i: usize) -> usize {
        debug_assert!(i < Self::Tau::USIZE);

        if i < Self::Tau1::USIZE {
            return (1 << Self::K::USIZE) * i;
        }
        Self::Tau1::USIZE * (1 << Self::K::USIZE)
            + (1 << (Self::K::USIZE - 1)) * (i - Self::Tau1::USIZE)
    }

    fn bavc_max_node_depth(i: usize) -> usize {
        if i < Self::Tau1::USIZE {
            return Self::K::USIZE;
        } else {
            Self::K::USIZE - 1
        }
    }

    fn bavc_max_node_index(i: usize) -> usize {
        1usize << Self::bavc_max_node_depth(i)
    }

    fn pos_in_tree(i: usize, j: usize) -> usize {
        let tmp = 1usize << (Self::K::USIZE - 1);

        if j < tmp {
            return Self::L::USIZE - 1 + Self::Tau::USIZE * j + i;
        }

        // mod 2^(k-1) is the same as & 2^(k-1)-1
        let mask = tmp - 1;
        return Self::L::USIZE - 1 + Self::Tau::USIZE * tmp + Self::Tau1::USIZE * (j & mask) + i;
    }

    // fn convert_index_and_size(i: usize) -> (usize, usize) {
    //     if i < Self::Tau0::USIZE {
    //         (Self::K0::USIZE * i, Self::K0::USIZE)
    //     } else {
    //         (
    //             Self::Tau0::USIZE * Self::K0::USIZE + Self::K1::USIZE * (i - Self::Tau0::USIZE),
    //             Self::K1::USIZE,
    //         )
    //     }
    // }
}

pub const MAX_TAU: usize = 32;

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
    type OWF: OWFParameters;
    type Tau: TauParameters<Tau = <<Self as FAESTParameters>::BAVC as BatchVectorCommitment>::Tau>;

    /// Associated BAVC
    type BAVC: BatchVectorCommitment<
        RO = <<Self::OWF as OWFParameters>::BaseParams as BaseParameters>::RandomOracle,
        PRG = <<Self::OWF as OWFParameters>::BaseParams as BaseParameters>::PRG,
        TAU = Self::Tau,
        LambdaBytes = <<Self::OWF as OWFParameters>::BaseParams as BaseParameters>::LambdaBytes,
        NLeafCommit = <Self::OWF as OWFParameters>::NLeafCommit,
    >;

    type WGRIND: ArrayLength;
    /// Size of the signature (in bytes)
    type SignatureSize: ArrayLength;

    #[inline]
    fn get_decom_size() -> usize {
        // coms
        <<Self as FAESTParameters>::OWF as OWFParameters>::NLeafCommit::USIZE
            * <<Self as FAESTParameters>::OWF as OWFParameters>::LAMBDABYTES::USIZE
            * <<Self as FAESTParameters>::Tau as TauParameters>::Tau::USIZE
            +
            // nodes
            <<Self as FAESTParameters>::Tau as TauParameters>::Topen::USIZE
                * <<Self as FAESTParameters>::OWF as OWFParameters>::LAMBDABYTES::USIZE
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST128sParameters;

impl FAESTParameters for FAEST128sParameters {
    type OWF = OWF128;
    type Tau = Tau128Small;
    type BAVC = BAVC128Small;

    type WGRIND = U7;
    type SignatureSize = U4506;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FAEST128fParameters;

impl FAESTParameters for FAEST128fParameters {
    type OWF = OWF128;
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

    // #[test]
    // fn chaldec() {
    //     let database: Vec<DataChalDec> = read_test_data("decode_challenge.json");
    //     for data in database {
    //         if data.chal.len() == 16 {
    //             if data.k0[0] == 12 {
    //                 let res = Tau128Small::decode_challenge(&data.chal, data.i[0]);
    //                 assert_eq!(res, data.res);
    //             } else {
    //                 let res = Tau128Fast::decode_challenge(&data.chal, data.i[0]);
    //                 assert_eq!(res, data.res);
    //             }
    //         } else if data.chal.len() == 24 {
    //             if data.k0[0] == 12 {
    //                 let res = Tau192Small::decode_challenge(&data.chal, data.i[0]);
    //                 assert_eq!(res, data.res);
    //             } else {
    //                 let res = Tau192Fast::decode_challenge(&data.chal, data.i[0]);
    //                 assert_eq!(res, data.res);
    //             }
    //         } else if data.k0[0] == 12 {
    //             let res = Tau256Small::decode_challenge(&data.chal, data.i[0]);
    //             assert_eq!(res, data.res);
    //         } else {
    //             let res = Tau256Fast::decode_challenge(&data.chal, data.i[0]);
    //             assert_eq!(res, data.res);
    //         }
    //     }
    // }

    #[generic_tests::define]
    mod owf_parameters {
        use super::*;

        #[test]
        fn lambda<O: OWFParameters>() {
            assert!(O::LAMBDA::USIZE == 128 || O::LAMBDA::USIZE == 192 || O::LAMBDA::USIZE == 256);
            assert_eq!(O::LAMBDABYTES::USIZE * 8, O::LAMBDA::USIZE);
        }

        #[test]
        fn pk_sk_size<O: OWFParameters>() {
            assert_eq!(O::SK::USIZE, O::InputSize::USIZE + O::LAMBDABYTES::USIZE);
            assert_eq!(O::PK::USIZE, O::InputSize::USIZE + O::OutputSize::USIZE);
        }

        #[test]
        fn owf_parameters<O: OWFParameters>() {
            assert_eq!(O::LKE::USIZE % 8, 0);
            assert_eq!(O::LKEBytes::USIZE * 8, O::LKE::USIZE);
            assert_eq!(O::LENC::USIZE % 8, 0);
            assert_eq!(O::L::USIZE % 8, 0);
            assert_eq!(O::LBYTES::USIZE * 8, O::L::USIZE);
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
                <P::OWF as OWFParameters>::LAMBDA::USIZE,
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
