use faest::*;
use faest_memcheck::FaestMemcheck;
use signature::{RandomizedSigner, Signer, Verifier};
use std::convert::AsRef;

const MESSAGE: &str = "This is a message.";

fn api_test<KP, S>(name: &str)
where
    KP: KeypairGenerator + Signer<Box<S>> + RandomizedSigner<Box<S>> + FaestMemcheck,
    KP::VerifyingKey: Verifier<S>,
    S: AsRef<[u8]>,
{
    // Generate key pair
    let mut rng = rand::thread_rng();
    let keypair = KP::generate(&mut rng);
    let verification_key = keypair.verifying_key();

    //---------------------------Sign.................................................

    println!("Signing message '{MESSAGE}' with {name} ...");

    // classify secret values (message and owf key)
    keypair.faest_classify();
    MESSAGE.faest_classify();

    let signature = keypair.sign(MESSAGE.as_bytes());
    //---------------------------Verify...............................................

    // declassify message (public for verifier) and signature (public)
    MESSAGE.faest_declassify();
    signature.faest_declassify();

    println!("Verifying signature on message '{MESSAGE}' with {name} ...");

    assert!(
        verification_key
            .verify(MESSAGE.as_bytes(), &signature)
            .is_ok()
    );
    //---------------------------Sign (randomized)....................................
    println!("Signing message '{MESSAGE}' with {name} (randomized) ...");

    // classify secret values (message and owf key)
    keypair.faest_classify();
    MESSAGE.faest_classify();

    let signature = keypair.sign_with_rng(&mut rng, MESSAGE.as_bytes());

    //---------------------------Verify...............................................
    // declassify message (public for verifier) and signature (public)
    MESSAGE.faest_declassify();
    signature.faest_declassify();

    println!("Verifying signature on message '{MESSAGE}' with {name} ...");

    assert!(
        verification_key
            .verify(MESSAGE.as_bytes(), &signature)
            .is_ok()
    );
}

fn main() {
    // TODO: preliminary testing only includes "f" version.
    // If necessary also include "s" versions (much slower with valgrind instrumentation).
    api_test::<FAEST128fSigningKey, FAEST128fSignature>("FAEST-128f");
    api_test::<FAESTEM128fSigningKey, FAESTEM128fSignature>("FAEST-EM-128f");
    api_test::<FAEST192fSigningKey, FAEST192fSignature>("FAEST-192f");
    api_test::<FAESTEM192fSigningKey, FAESTEM192fSignature>("FAEST-EM-192f");
    api_test::<FAEST256fSigningKey, FAEST256fSignature>("FAEST-256f");
    api_test::<FAESTEM256fSigningKey, FAESTEM256fSignature>("FAEST-EM-256f");
}
