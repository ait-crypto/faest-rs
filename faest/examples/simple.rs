use faest::{
    FAEST128EMfKeyPair, FAEST128EMfSignature, FAEST128EMsKeyPair, FAEST128EMsSignature,
    FAEST128fKeyPair, FAEST128fSignature, FAEST128sKeyPair, FAEST128sSignature, FAEST192EMfKeyPair,
    FAEST192EMfSignature, FAEST192EMsKeyPair, FAEST192EMsSignature, FAEST192fKeyPair,
    FAEST192fSignature, FAEST192sKeyPair, FAEST192sSignature, FAEST256EMfKeyPair,
    FAEST256EMfSignature, FAEST256EMsKeyPair, FAEST256EMsSignature, FAEST256fKeyPair,
    FAEST256fSignature, FAEST256sKeyPair, FAEST256sSignature, KeypairGenerator,
};
use rand::RngCore;
use signature::{Signer, Verifier};

type Message = [u8; 32];

fn random_message(mut rng: impl RngCore) -> Message {
    let mut ret = Message::default();
    rng.fill_bytes(&mut ret);
    ret
}

fn run_example<KP, S>(name: &str)
where
    KP: KeypairGenerator + Signer<S>,
    KP::VerifyingKey: Verifier<S>,
{
    let mut rng = rand::thread_rng();

    println!("Generating {} key ...", name);
    let keypair = KP::generate(&mut rng);
    println!("Signing message with {} ...", name);
    let message = random_message(&mut rng);
    let signature = keypair.sign(&message);
    println!("Verifying signature with {} ...", name);
    let verification_key = keypair.verifying_key();
    assert!(verification_key.verify(&message, &signature).is_ok());
}

fn main() {
    run_example::<FAEST128fKeyPair, FAEST128fSignature>("FAEST-128f");
    run_example::<FAEST128sKeyPair, FAEST128sSignature>("FAEST-128s");
    run_example::<FAEST192fKeyPair, FAEST192fSignature>("FAEST-192f");
    run_example::<FAEST192sKeyPair, FAEST192sSignature>("FAEST-192s");
    run_example::<FAEST256fKeyPair, FAEST256fSignature>("FAEST-256f");
    run_example::<FAEST256sKeyPair, FAEST256sSignature>("FAEST-256s");
    run_example::<FAEST128EMfKeyPair, FAEST128EMfSignature>("FAEST-EM-128f");
    run_example::<FAEST128EMsKeyPair, FAEST128EMsSignature>("FAEST-EM-128s");
    run_example::<FAEST192EMfKeyPair, FAEST192EMfSignature>("FAEST-EM-192f");
    run_example::<FAEST192EMsKeyPair, FAEST192EMsSignature>("FAEST-EM-192s");
    run_example::<FAEST256EMfKeyPair, FAEST256EMfSignature>("FAEST-EM-256f");
    run_example::<FAEST256EMsKeyPair, FAEST256EMsSignature>("FAEST-EM-256s");
}
