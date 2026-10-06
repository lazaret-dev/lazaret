//! Rough throughput numbers for the primitives (single thread, release build).

use std::time::Instant;
use tiny_https::crypto::chacha20poly1305::ChaCha20Poly1305;
use tiny_https::crypto::gcm::AesGcm;
use tiny_https::crypto::sha2::{Hash, Sha256};
use tiny_https::crypto::x25519;
use tiny_https::pem;
use tiny_https::x509::{Certificate, TrustStore};

fn mbps(bytes: usize, secs: f64) -> f64 {
    bytes as f64 / 1e6 / secs
}

fn main() {
    let data = vec![0xa5u8; 1 << 20];
    let nonce = [7u8; 12];
    let rounds = 16;

    println!("AES backend         {}", if tiny_https::crypto::aes::hardware_accelerated() { "hardware (AES instructions + carry-less multiply)" } else { "portable (bitsliced, constant time)" });
    let g128 = AesGcm::new(&[1u8; 16]);
    let t = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(g128.seal(&nonce, b"", &data));
    }
    println!("AES-128-GCM        {:7.1} MB/s", mbps(rounds << 20, t.elapsed().as_secs_f64()));

    let g256 = AesGcm::new(&[1u8; 32]);
    let t = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(g256.seal(&nonce, b"", &data));
    }
    println!("AES-256-GCM        {:7.1} MB/s", mbps(rounds << 20, t.elapsed().as_secs_f64()));

    let cc = ChaCha20Poly1305::new(&[2u8; 32]);
    let t = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(cc.seal(&nonce, b"", &data));
    }
    println!("ChaCha20-Poly1305  {:7.1} MB/s", mbps(rounds << 20, t.elapsed().as_secs_f64()));

    let t = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(Sha256::digest(&data));
    }
    println!("SHA-256            {:7.1} MB/s", mbps(rounds << 20, t.elapsed().as_secs_f64()));

    let t = Instant::now();
    let n = 200;
    for i in 0..n {
        let mut k = [9u8; 32];
        k[0] = i as u8;
        std::hint::black_box(x25519::public_key(&k));
    }
    println!("X25519             {:7.2} ms per operation", t.elapsed().as_secs_f64() * 1000.0 / n as f64);

    // Certificate-chain validation cost (parse + signature checks + name checks), using the test fixtures.
    let der = |t: &str| pem::parse(t).remove(0).data;
    let root_rsa = der(include_str!("../tests/data/root_rsa.pem"));
    let inter = der(include_str!("../tests/data/inter_p256.pem"));
    let leaf = der(include_str!("../tests/data/leaf_p384.pem"));
    let mut store = TrustStore::empty();
    store.add_der(&root_rsa).unwrap();
    let chain = vec![leaf.clone(), inter];
    let now = 1_789_430_400;
    let n = 100;
    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(store.verify_server_chain(&chain, "example.test", now).unwrap());
    }
    println!(
        "chain check (1 RSA-2048 + 1 ECDSA P-256 verify + 3 cert parses)  {:6.2} ms",
        t.elapsed().as_secs_f64() * 1000.0 / n as f64
    );
    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(Certificate::from_der(&leaf).unwrap());
    }
    println!("parse one certificate (P-384 key)                                {:6.2} ms", t.elapsed().as_secs_f64() * 1000.0 / n as f64);
    let t = Instant::now();
    for _ in 0..20 {
        let mut s2 = TrustStore::empty();
        s2.add_der(&root_rsa).unwrap();
        std::hint::black_box(s2);
    }
    println!("parse one RSA-2048 root into a trust store                       {:6.2} ms", t.elapsed().as_secs_f64() * 1000.0 / 20.0);
    let t = Instant::now();
    let pem_text = std::fs::read_to_string("/etc/ssl/certs/ca-certificates.crt").ok();
    if let Some(text) = pem_text {
        let mut big = TrustStore::empty();
        let added = big.add_pem(&text);
        println!("load system CA bundle ({} roots)                                {:6.1} ms", added, t.elapsed().as_secs_f64() * 1000.0);
    }
}
