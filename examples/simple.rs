use faest::*;
use signature::RandomizedSigner;
use signature::{Signer, Verifier};

const MESSAGE: &str = "This is a message.";
fn run_example<KP, S>(name: &str)
where
    KP: KeypairGenerator + Signer<Box<S>> + RandomizedSigner<S>,
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
    run_example::<FAEST128fKeyPair, FAEST128fSignature>("FAEST-128f");
    run_example::<FAEST128sKeyPair, FAEST128sSignature>("FAEST-128s");
    run_example::<FAEST192fKeyPair, FAEST192fSignature>("FAEST-192f");
    run_example::<FAEST192sKeyPair, FAEST192sSignature>("FAEST-192s");
    run_example::<FAEST256fKeyPair, FAEST256fSignature>("FAEST-256f");
    run_example::<FAEST256sKeyPair, FAEST256sSignature>("FAEST-256s");
    run_example::<FAESTEM128fKeyPair, FAESTEM128fSignature>("FAEST-EM-128f");
    run_example::<FAESTEM128sKeyPair, FAESTEM128sSignature>("FAEST-EM-128s");
    run_example::<FAESTEM192fKeyPair, FAESTEM192fSignature>("FAEST-EM-192f");
    run_example::<FAESTEM192sKeyPair, FAESTEM192sSignature>("FAEST-EM-192s");
    run_example::<FAESTEM256fKeyPair, FAESTEM256fSignature>("FAEST-EM-256f");
    run_example::<FAESTEM256sKeyPair, FAESTEM256sSignature>("FAEST-EM-256s");
}
