use criterion::{criterion_group, criterion_main, Criterion};
use libpaillier::{unknown_order::BigNumber, DecryptionKey, EncryptionKey};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub fn safe_primes(c: &mut Criterion) {
    let mut rng = chacha_rng();

    let mut g = c.benchmark_group("paillier-keypair-gen");
    g.sample_size(10);

    g.bench_function("unsafe primes", |b| {
        b.iter(|| {
            let p = BigNumber::prime_with_rng(&mut rng, 1024);
            let q = BigNumber::prime_with_rng(&mut rng, 1024);

            let dk = DecryptionKey::with_safe_primes_unchecked(&p, &q).unwrap();

            let ek: EncryptionKey = (&dk).into();

            (ek, dk)
        })
    });

    let mut rng = chacha_rng();

    g.bench_function("safe primes", |b| {
        b.iter(|| {
            let dk = DecryptionKey::with_rng(&mut rng).unwrap();

            let ek: EncryptionKey = (&dk).into();

            (ek, dk)
        })
    });
}

criterion_group!(benches, safe_primes);
criterion_main!(benches);

// initialize a deterministic rng to conserve random bits
fn chacha_rng() -> impl CryptoRng + RngCore {
    // get a random seed
    let mut seed = [0; 32];
    rand::thread_rng().fill_bytes(&mut seed);

    // or just use a fixed seed
    // let mut seed = [42; 32];

    ChaCha20Rng::from_seed(seed)
}
