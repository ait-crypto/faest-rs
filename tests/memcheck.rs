cfg_if::cfg_if! {
    if #[cfg(all(
    valgrind = "enabled",
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm"
    )
))] {
use std::{env, os::unix::process::CommandExt, process::Command};

use faest::*;
use signature::{RandomizedSigner, Signer, Verifier};
use vgzzq::running_on_valgrind;

const MESSAGE: &str = "This is a message.";

fn api_test<KP, S>()
where
    KP: KeypairGenerator + Signer<Box<S>> + RandomizedSigner<Box<S>>,
    KP::VerifyingKey: Verifier<S>,
{
    // Generate key pair
    let mut rng = rand::thread_rng();
    let keypair = KP::generate(&mut rng);
    let verification_key = keypair.verifying_key();

    let message = MESSAGE.as_bytes();

    //---------------------------Sign.................................................
    classify!(message);
    let signature = keypair.sign(message);
    //---------------------------Verify...............................................
    declassify!(message);
    assert!(verification_key.verify(message, &signature).is_ok());

    //---------------------------Sign (randomized)....................................
    classify!(message);
    let signature = keypair.sign_with_rng(&mut rng, message);
    //---------------------------Verify...............................................
    declassify!(message);
    assert!(verification_key.verify(message, &signature).is_ok());
}

#[cfg(all(
    valgrind = "enabled",
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm"
    )
))]
fn main() -> Result<(), std::io::Error> {
    if running_on_valgrind() == 0 {
        Err(Command::new("valgrind")
            .args([
                "--tool=memcheck".into(),
                "--error-exitcode=1".into(),
                env::current_exe().unwrap().into_os_string(),
            ])
            .exec())
    } else {
        // FAEST-f
        api_test::<FAEST128fSigningKey, FAEST128fSignature>();
        api_test::<FAESTEM128fSigningKey, FAESTEM128fSignature>();
        api_test::<FAEST192fSigningKey, FAEST192fSignature>();
        api_test::<FAESTEM192fSigningKey, FAESTEM192fSignature>();
        api_test::<FAEST256fSigningKey, FAEST256fSignature>();
        api_test::<FAESTEM256fSigningKey, FAESTEM256fSignature>();

        // FAEST-s
        api_test::<FAEST128fSigningKey, FAEST128fSignature>();
        api_test::<FAESTEM128fSigningKey, FAESTEM128fSignature>();
        api_test::<FAEST192fSigningKey, FAEST192fSignature>();
        api_test::<FAESTEM192fSigningKey, FAESTEM192fSignature>();
        api_test::<FAEST256fSigningKey, FAEST256fSignature>();
        api_test::<FAESTEM256fSigningKey, FAESTEM256fSignature>();

        Ok(())
    }
}
} else {
    fn main() {}
}
}
