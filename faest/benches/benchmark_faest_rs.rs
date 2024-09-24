use ::faest::{
    faest::{faest_sign, faest_verify},
    parameter::{
        self, PARAM, PARAM128F, PARAM128FEM, PARAM128S, PARAM128SEM, PARAM192F, PARAM192FEM,
        PARAM192S, PARAM192SEM, PARAM256F, PARAM256FEM, PARAM256S, PARAM256SEM, PARAMOWF,
        PARAMOWF128, PARAMOWF128EM, PARAMOWF192, PARAMOWF192EM, PARAMOWF256, PARAMOWF256EM,
    },
};
use criterion::{criterion_group, criterion_main, Criterion};
use generic_array::{typenum::Unsigned, GenericArray};
use parameter::{AesCypher, EmCypher, Variant};
use rand::RngCore;
use signature::{Signer, Verifier};

fn random_message(mut rng: impl RngCore) -> Vec<u8> {
    let mut length = [0];
    while length[0] == 0 {
        rng.fill_bytes(&mut length);
    }
    let mut ret = vec![0; length[0] as usize];
    rng.fill_bytes(&mut ret);
    ret
}

fn benchmark<KP, S>(c: &mut Criterion, name: &str)
where
    KP: KeypairGenerator + Signer<S>,
    KP::VerifyingKey: Verifier<S>,
{
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
