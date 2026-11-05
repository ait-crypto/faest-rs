use std::{
    fmt::Debug,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use nist_pqc_seeded_rng::NistPqcAes256CtrRng;
use rand_core::SeedableRng;
use signature::{RandomizedSigner, SignatureEncoding, Verifier};

use faest::*;

#[derive(Default, Clone)]
struct TestVector {
    seed: Vec<u8>,
    message: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    sm: Vec<u8>,
}

fn parse_hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("hex value")
}

fn read_kats(kats: &str) -> Vec<TestVector> {
    let kats = BufReader::new(
        File::open(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/data")
                .join(kats),
        )
        .unwrap_or_else(|_| {
            File::open(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/data")
                    .join(format!("reduced_{kats}")),
            )
            .unwrap()
        }),
    );

    let mut ret = Vec::new();

    let mut kat = TestVector::default();
    let mut mlen = 0;
    let mut smlen = 0;
    for line in kats.lines() {
        let Ok(line) = line else {
            break;
        };

        // skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (kind, value) = line.split_once(" = ").expect("kind = value");
        match kind {
            // ignore count
            "count" => {}
            "mlen" => {
                mlen = value.parse().unwrap();
            }
            "smlen" => {
                smlen = value.parse().unwrap();
            }
            "seed" => {
                kat.seed = parse_hex(value);
            }
            "sk" => {
                kat.sk = parse_hex(value);
            }
            "pk" => {
                kat.pk = parse_hex(value);
            }
            "msg" => {
                kat.message = parse_hex(value);
                assert_eq!(kat.message.len(), mlen);
            }
            "sm" => {
                kat.sm = parse_hex(value);
                assert!(
                    !kat.sk.is_empty()
                        && !kat.pk.is_empty()
                        && !kat.message.is_empty()
                        && !kat.sm.is_empty()
                );
                assert_eq!(kat.sm.len(), smlen);
                ret.push(kat);
                kat = TestVector::default();
            }
            _ => {
                unreachable!("unknown kind");
            }
        }
    }
    ret
}

fn test_nist<KP, S>(test_data: &str)
where
    KP: KeypairGenerator
        + RandomizedSigner<Box<S>>
        + for<'a> TryFrom<&'a [u8], Error = Error>
        + Debug
        + Eq,
    KP::VerifyingKey: Verifier<S> + for<'a> TryFrom<&'a [u8], Error = Error> + Debug + Eq,
    S: SignatureEncoding,
{
    for TestVector {
        seed,
        message,
        pk,
        sk,
        sm,
    } in read_kats(test_data)
    {
        let mut rng = NistPqcAes256CtrRng::from_seed(seed.as_slice().try_into().unwrap());

        let kp = KP::generate(&mut rng);

        let vk = kp.verifying_key();
        assert_eq!(KP::VerifyingKey::try_from(&pk).unwrap(), vk);
        assert_eq!(KP::try_from(&sk).unwrap(), kp);

        let signature = kp.sign_with_rng(&mut rng, &message);
        assert!(vk.verify(&message, &signature).is_ok());

        assert_eq!(sm.len(), message.len() + signature.encoded_len());
        assert_eq!(sm[..sm.len() - signature.encoded_len()], message);
        assert_eq!(sm[sm.len() - signature.encoded_len()..], signature.to_vec());
    }
}

#[test]
fn faest_128s() {
    test_nist::<FAEST128sSigningKey, FAEST128sSignature>("PQCsignKAT_faest_128s.rsp");
}

#[test]
fn faest_128f() {
    test_nist::<FAEST128fSigningKey, FAEST128fSignature>("PQCsignKAT_faest_128f.rsp");
}

#[test]
fn faest_192s() {
    test_nist::<FAEST192sSigningKey, FAEST192sSignature>("PQCsignKAT_faest_192s.rsp");
}

#[test]
fn faest_192f() {
    test_nist::<FAEST192fSigningKey, FAEST192fSignature>("PQCsignKAT_faest_192f.rsp");
}

#[test]
fn faest_256s() {
    test_nist::<FAEST256sSigningKey, FAEST256sSignature>("PQCsignKAT_faest_256s.rsp");
}

#[test]
fn faest_256f() {
    test_nist::<FAEST256fSigningKey, FAEST256fSignature>("PQCsignKAT_faest_256f.rsp");
}

#[test]
fn faest_em_128s() {
    test_nist::<FAESTEM128sSigningKey, FAESTEM128sSignature>("PQCsignKAT_faest_em_128s.rsp");
}

#[test]
fn faest_em_128f() {
    test_nist::<FAESTEM128fSigningKey, FAESTEM128fSignature>("PQCsignKAT_faest_em_128f.rsp");
}

#[test]
fn faest_em_192s() {
    test_nist::<FAESTEM192sSigningKey, FAESTEM192sSignature>("PQCsignKAT_faest_em_192s.rsp");
}

#[test]
fn faest_em_192f() {
    test_nist::<FAESTEM192fSigningKey, FAESTEM192fSignature>("PQCsignKAT_faest_em_192f.rsp");
}

#[test]
fn faest_em_256s() {
    test_nist::<FAESTEM256sSigningKey, FAESTEM256sSignature>("PQCsignKAT_faest_em_256s.rsp");
}

#[test]
fn faest_em_256f() {
    test_nist::<FAESTEM256fSigningKey, FAESTEM256fSignature>("PQCsignKAT_faest_em_256f.rsp");
}
