use criterion::{black_box, criterion_group, criterion_main, Criterion};
use faest::*;
use rand::{RngCore, SeedableRng};
use signature::{RandomizedSigner, Signer, Verifier};

type Message = [u8; 32];

fn random_message(mut rng: impl RngCore) -> Message {
    let mut ret = Message::default();
    rng.fill_bytes(&mut ret);
    ret
}

fn benchmark<KP, S>(c: &mut Criterion, name: &str)
where
    KP: KeypairGenerator + Signer<S> + RandomizedSigner<S>,
    KP::VerifyingKey: Verifier<S>,
{
    let mut rng = rand_chacha::ChaCha8Rng::from_seed([0; 32]);
    let mut c = c.benchmark_group(name);

    c.bench_function("keygen", |b| b.iter(|| black_box(KP::generate(&mut rng))));

    let kp = KP::generate(&mut rng);
    c.bench_function("sign", |b| {
        let message = random_message(&mut rng);
        b.iter(|| black_box(kp.sign(&message)));
    });
    c.bench_function("sign (randomized)", |b| {
        let message = random_message(&mut rng);
        b.iter(|| black_box(kp.sign_with_rng(&mut rng, &message)));
    });
    c.bench_function("verify", |b| {
        let message = random_message(&mut rng);
        let signature = kp.sign(&message);
        let vk = kp.verifying_key();
        b.iter(|| black_box(vk.verify(&message, &signature)))
    });
}

fn faest_benchmark(c: &mut Criterion) {
    benchmark::<FAEST128fSigningKey, FAEST128fSignature>(c, "FAEST-128f");
    benchmark::<FAEST128sSigningKey, FAEST128sSignature>(c, "FAEST-128s");
    benchmark::<FAEST192fSigningKey, FAEST192fSignature>(c, "FAEST-192f");
    benchmark::<FAEST192sSigningKey, FAEST192sSignature>(c, "FAEST-192s");
    benchmark::<FAEST256fSigningKey, FAEST256fSignature>(c, "FAEST-256f");
    benchmark::<FAEST256sSigningKey, FAEST256sSignature>(c, "FAEST-256s");
    benchmark::<FAESTEM128fSigningKey, FAESTEM128fSignature>(c, "FAEST-EM-128f");
    benchmark::<FAESTEM128sSigningKey, FAESTEM128sSignature>(c, "FAEST-EM-128s");
    benchmark::<FAESTEM192fSigningKey, FAESTEM192fSignature>(c, "FAEST-EM-192f");
    benchmark::<FAESTEM192sSigningKey, FAESTEM192sSignature>(c, "FAEST-EM-192s");
    benchmark::<FAESTEM256fSigningKey, FAESTEM256fSignature>(c, "FAEST-EM-256f");
    benchmark::<FAESTEM256sSigningKey, FAESTEM256sSignature>(c, "FAEST-EM-256s");
}

criterion_group!(benches, faest_benchmark);
criterion_main!(benches);
