use criterion::{black_box, criterion_group, criterion_main, Criterion};
use faest::{
    FAEST128EMfKeyPair, FAEST128EMfSignature, FAEST128EMsKeyPair, FAEST128EMsSignature,
    FAEST128fKeyPair, FAEST128fSignature, FAEST128sKeyPair, FAEST128sSignature, FAEST192EMfKeyPair,
    FAEST192EMfSignature, FAEST192EMsKeyPair, FAEST192EMsSignature, FAEST192fKeyPair,
    FAEST192fSignature, FAEST192sKeyPair, FAEST192sSignature, FAEST256EMfKeyPair,
    FAEST256EMfSignature, FAEST256EMsKeyPair, FAEST256EMsSignature, FAEST256fKeyPair,
    FAEST256fSignature, FAEST256sKeyPair, FAEST256sSignature, KeypairGenerator,
};
use rand::{RngCore, SeedableRng};
use signature::{Signer, Verifier};

type Message = [u8; 32];

fn random_message(mut rng: impl RngCore) -> Message {
    let mut ret = Message::default();
    rng.fill_bytes(&mut ret);
    ret
}

fn benchmark<KP, S>(c: &mut Criterion, name: &str)
where
    KP: KeypairGenerator + Signer<S>,
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
    c.bench_function("verify", |b| {
        let message = random_message(&mut rng);
        let signature = kp.sign(&message);
        let vk = kp.verifying_key();
        b.iter(|| black_box(vk.verify(&message, &signature)))
    });
}

fn faest_benchmark(c: &mut Criterion) {
    benchmark::<FAEST128fKeyPair, FAEST128fSignature>(c, "FAEST-128f");
    benchmark::<FAEST128sKeyPair, FAEST128sSignature>(c, "FAEST-128s");
    benchmark::<FAEST192fKeyPair, FAEST192fSignature>(c, "FAEST-192f");
    benchmark::<FAEST192sKeyPair, FAEST192sSignature>(c, "FAEST-192s");
    benchmark::<FAEST256fKeyPair, FAEST256fSignature>(c, "FAEST-256f");
    benchmark::<FAEST256sKeyPair, FAEST256sSignature>(c, "FAEST-256s");
    benchmark::<FAEST128EMfKeyPair, FAEST128EMfSignature>(c, "FAEST-EM-128f");
    benchmark::<FAEST128EMsKeyPair, FAEST128EMsSignature>(c, "FAEST-EM-128s");
    benchmark::<FAEST192EMfKeyPair, FAEST192EMfSignature>(c, "FAEST-EM-192f");
    benchmark::<FAEST192EMsKeyPair, FAEST192EMsSignature>(c, "FAEST-EM-192s");
    benchmark::<FAEST256EMfKeyPair, FAEST256EMfSignature>(c, "FAEST-EM-256f");
    benchmark::<FAEST256EMsKeyPair, FAEST256EMsSignature>(c, "FAEST-EM-256s");
}

criterion_group!(benches, faest_benchmark);
criterion_main!(benches);
