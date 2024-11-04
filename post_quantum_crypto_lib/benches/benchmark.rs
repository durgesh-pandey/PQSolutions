use criterion::{black_box, criterion_group, criterion_main, Criterion};
use post_quantum_crypto_lib::kem::{KyberKeyPair, kyber_encapsulate, kyber_decapsulate};

fn benchmark_kyber(c: &mut Criterion) {
    c.bench_function("kyber key generation", |b| {
        b.iter(|| {
            KyberKeyPair::generate().expect("Kyber key generation failed");
        })
    });

    let kyber_keys = KyberKeyPair::generate().expect("Kyber key generation failed");
    c.bench_function("kyber encapsulation", |b| {
        b.iter(|| {
            kyber_encapsulate(black_box(&kyber_keys.public_key)).expect("Kyber encapsulation failed");
        })
    });

    let (ciphertext, _) =
        kyber_encapsulate(&kyber_keys.public_key).expect("Kyber encapsulation failed");
    c.bench_function("kyber decapsulation", |b| {
        b.iter(|| {
            kyber_decapsulate(black_box(&ciphertext), black_box(&kyber_keys.secret_key))
                .expect("Kyber decapsulation failed");
        })
    });
}

criterion_group!(benches, benchmark_kyber);
criterion_main!(benches);
