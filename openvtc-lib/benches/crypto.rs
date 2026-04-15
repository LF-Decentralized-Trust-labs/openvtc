use criterion::{Criterion, criterion_group, criterion_main};
use openvtc::config::{
    derive_passphrase_key,
    secured_config::{unlock_code_decrypt, unlock_code_encrypt},
};

fn bench_derive_passphrase_key(c: &mut Criterion) {
    c.bench_function("derive_passphrase_key", |b| {
        b.iter(|| derive_passphrase_key(b"benchmark-passphrase", b"bench-context-v1").unwrap());
    });
}

fn bench_unlock_code_encrypt(c: &mut Criterion) {
    let key = derive_passphrase_key(b"benchmark-passphrase", b"bench-context-v1").unwrap();
    let plaintext = b"benchmark plaintext data for encryption testing";

    c.bench_function("unlock_code_encrypt", |b| {
        b.iter(|| unlock_code_encrypt(&key, plaintext).unwrap());
    });
}

fn bench_unlock_code_decrypt(c: &mut Criterion) {
    let key = derive_passphrase_key(b"benchmark-passphrase", b"bench-context-v1").unwrap();
    let plaintext = b"benchmark plaintext data for encryption testing";
    let encrypted = unlock_code_encrypt(&key, plaintext).unwrap();

    c.bench_function("unlock_code_decrypt", |b| {
        b.iter(|| unlock_code_decrypt(&key, &encrypted).unwrap());
    });
}

criterion_group!(
    benches,
    bench_derive_passphrase_key,
    bench_unlock_code_encrypt,
    bench_unlock_code_decrypt
);
criterion_main!(benches);
