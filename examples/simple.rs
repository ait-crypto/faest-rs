#![allow(unused_imports, dead_code)]
use faest::*;
use signature::RandomizedSigner;
use signature::{Signer, Verifier};

const MESSAGE: &str = "This is a message.";

fn run_example<KP, S>(name: &str)
where
    KP: KeypairGenerator + Signer<Box<S>> + RandomizedSigner<Box<S>>,
    KP::VerifyingKey: Verifier<S>,
{
    let mut rng = rand::thread_rng();

    println!("Generating {} key ...", name);
    let keypair = KP::generate(&mut rng);
    println!("Signing message '{}' with {} ...", MESSAGE, name);
    let signature = keypair.sign(MESSAGE.as_bytes());
    println!(
        "Verifying signature on message '{}' with {} ...",
        MESSAGE, name
    );
    let verification_key = keypair.verifying_key();
    assert!(verification_key
        .verify(MESSAGE.as_bytes(), &signature)
        .is_ok());

    println!(
        "Signing message '{}' with {} (randomized)...",
        MESSAGE, name
    );
    let signature = keypair.sign_with_rng(&mut rng, MESSAGE.as_bytes());
    println!(
        "Verifying signature on message '{}' with {} ...",
        MESSAGE, name
    );
    assert!(verification_key
        .verify(MESSAGE.as_bytes(), &signature)
        .is_ok());
}

fn main() {
    run_example::<FAEST128fSigningKey, FAEST128fSignature>("FAEST-128f");
    run_example::<FAEST128sSigningKey, FAEST128sSignature>("FAEST-128s");
    run_example::<FAEST192fSigningKey, FAEST192fSignature>("FAEST-192f");
    run_example::<FAEST192sSigningKey, FAEST192sSignature>("FAEST-192s");
    run_example::<FAEST256fSigningKey, FAEST256fSignature>("FAEST-256f");
    run_example::<FAEST256sSigningKey, FAEST256sSignature>("FAEST-256s");
    run_example::<FAESTEM128fSigningKey, FAESTEM128fSignature>("FAEST-EM-128f");
    run_example::<FAESTEM128sSigningKey, FAESTEM128sSignature>("FAEST-EM-128s");
    run_example::<FAESTEM192fSigningKey, FAESTEM192fSignature>("FAEST-EM-192f");
    run_example::<FAESTEM192sSigningKey, FAESTEM192sSignature>("FAEST-EM-192s");
    run_example::<FAESTEM256fSigningKey, FAESTEM256fSignature>("FAEST-EM-256f");
    run_example::<FAESTEM256sSigningKey, FAESTEM256sSignature>("FAEST-EM-256s");
}
