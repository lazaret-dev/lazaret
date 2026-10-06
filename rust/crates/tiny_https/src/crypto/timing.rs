//! Statistical timing-leak detection in the style of dudect ("Dude, is my code constant time?",
//! Reparaz, Balasch and Verbauwhede, 2016), with no dependencies.
//!
//! Method: for a function `op(input)`, build two classes of inputs (typically "fixed" and
//! "random", or two structurally different fixed inputs). Time many calls, with the class of each
//! call chosen at random inside small balanced blocks, so that drift in the machine's state hits
//! both classes alike. Then run a paired t-test over the blocks, both on all samples and after
//! discarding the slowest samples at several percentiles (which are dominated by interrupts and
//! scheduling noise). A large |t| means the running time depends on the secret-controlled
//! difference between the classes. dudect's rule of thumb: |t| > 4.5 is suspicious and
//! |t| > 10 is a leak; a run below those numbers is evidence of absence, not proof of it.
//!
//! The harness is validated by *positive controls*: functions that are known to leak (an
//! early-exit comparison, a ladder that does extra work for set scalar bits) must be flagged, so
//! that a clean result for the real code means the harness could have seen a leak.
//!
//! These tests are `#[ignore]`d because timing results depend on the machine and are too noisy for
//! an unattended build. Run them one at a time, in release mode, on a quiet machine:
//! `cargo test --release --lib crypto::timing::x25519 -- --ignored --nocapture` (and `ecdh`, `ghash`,
//! `poly1305`, `aead_and_mac`, `aes`, `harness`). Each takes 10 to 25 seconds;
//! `TINY_HTTPS_TIMING_SECS` (default 3) sets the time spent per comparison.
//! What this cannot see: cache-timing differences too small to move the clock on a quiet machine,
//! differences that only exist on other CPUs, and leaks smaller than the noise floor of the machine
//! it runs on. (The table-based AES this library used to have, backlog B-20, was such a case on
//! some machines and flagged reproducibly on others; its replacement has no tables at all.)

use super::chacha20poly1305::ChaCha20Poly1305;
use super::ecdh;
use super::ecdsa::Curve;
use super::aes::Backend;
use super::gcm::AesGcm;
use super::ghash::GhashKey;
use super::hmac::Hmac;
use super::poly1305::{limbs32, limbs64};
use super::sha2::{Hash, Sha256};
use super::x25519;
use crate::fuzz::Rng;
use crate::util::ct_eq;
use std::hint::black_box;
use std::time::{Duration, Instant};

/// |t| above this is reported as a leak.
const LEAK_T: f64 = 10.0;
/// |t| above this is reported as suspicious.
const SUSPICIOUS_T: f64 = 4.5;

pub(crate) struct Report {
    pub name: String,
    pub samples: usize,
    pub uncropped_t: f64,
    pub max_t: f64,
    pub median_ns: u32,
    /// (percentile kept, t) for each crop level.
    pub crops: Vec<(f64, f64)>,
}

impl Report {
    fn verdict(&self) -> &'static str {
        if self.max_t > LEAK_T {
            "LEAK"
        } else if self.max_t > SUSPICIOUS_T {
            "suspicious"
        } else {
            "no leak detected"
        }
    }
    fn print(&self) {
        println!(
            "{:<58} n={:>7}  median {:>7} ns  |t| uncropped {:>6.1}  max {:>6.1}  {}",
            self.name,
            self.samples,
            self.median_ns,
            self.uncropped_t.abs(),
            self.max_t,
            self.verdict()
        );
        if self.max_t > SUSPICIOUS_T {
            let crops: Vec<String> = self.crops.iter().map(|(p, t)| format!("p{:.1}:{:.1}", p * 100.0, t)).collect();
            println!("    t by crop level: {}", crops.join("  "));
        }
    }
}

/// Samples per block: eight of each class, in random order.
const BLOCK: usize = 16;

/// Paired t statistic over blocks. Each block holds the same number of samples of both classes, so
/// slow drift in the machine's speed (frequency changes, a noisy neighbour) hits both classes
/// alike and cancels in the per-block difference of means. A plain two-sample test over all
/// samples would treat correlated noise as independent and report leaks that are not there.
/// Samples slower than `cutoff` nanoseconds are ignored.
fn paired_t(samples: &[(u32, bool)], cutoff: u32) -> f64 {
    let mut diffs: Vec<f64> = Vec::with_capacity(samples.len() / BLOCK);
    for block in samples.chunks(BLOCK) {
        let (mut sum, mut n) = ([0f64; 2], [0f64; 2]);
        for &(d, class) in block {
            if d <= cutoff {
                sum[class as usize] += d as f64;
                n[class as usize] += 1.0;
            }
        }
        if n[0] > 0.0 && n[1] > 0.0 {
            diffs.push(sum[1] / n[1] - sum[0] / n[0]);
        }
    }
    let n = diffs.len() as f64;
    if n < 2.0 {
        return 0.0;
    }
    let mean = diffs.iter().sum::<f64>() / n;
    let var = diffs.iter().map(|d| (d - mean) * (d - mean)).sum::<f64>() / (n - 1.0);
    if var == 0.0 {
        0.0
    } else {
        mean / (var / n).sqrt()
    }
}

fn budget() -> Duration {
    let secs: f64 = std::env::var("TINY_HTTPS_TIMING_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(3.0);
    Duration::from_secs_f64(secs)
}

/// Times `op` on inputs from `gen(rng, class)` for `budget` and returns the statistics.
/// `gen` runs outside the timed region; `op`'s result is passed through `black_box`.
pub(crate) fn measure<I, R>(name: &str, budget: Duration, gen: impl FnMut(&mut Rng, bool) -> I, op: impl Fn(&I) -> R) -> Report {
    measure_seeded(name, budget, 0, gen, op)
}

/// [`measure`] with a chosen seed for the input generator, so that a repeat run sees fresh data.
fn measure_seeded<I, R>(
    name: &str,
    budget: Duration,
    seed: u64,
    mut gen: impl FnMut(&mut Rng, bool) -> I,
    op: impl Fn(&I) -> R,
) -> Report {
    const BATCH_BLOCKS: usize = 64;
    let mut rng = Rng::new(0xd0de_c7 ^ name.len() as u64 ^ seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let mut samples: Vec<(u32, bool)> = Vec::new();
    let start = Instant::now();
    let mut first = true;
    while first || start.elapsed() < budget {
        // balanced blocks: eight of each class per block, shuffled
        let mut classes: Vec<bool> = Vec::with_capacity(BATCH_BLOCKS * BLOCK);
        for _ in 0..BATCH_BLOCKS {
            let mut block: Vec<bool> = (0..BLOCK).map(|i| i < BLOCK / 2).collect();
            for i in (1..BLOCK).rev() {
                block.swap(i, rng.below(i + 1));
            }
            classes.extend(block);
        }
        let inputs: Vec<I> = classes.iter().map(|&c| gen(&mut rng, c)).collect();
        for (&class, input) in classes.iter().zip(&inputs) {
            let t0 = Instant::now();
            black_box(op(black_box(input)));
            let dt = t0.elapsed().as_nanos().min(u32::MAX as u128) as u32;
            // the first batch only warms caches, branch predictors and clocks up
            if !first {
                samples.push((dt, class));
            }
        }
        first = false;
    }
    let mut sorted: Vec<u32> = samples.iter().map(|s| s.0).collect();
    sorted.sort_unstable();
    let pct = |p: f64| sorted[(((sorted.len() - 1) as f64) * p) as usize];
    let uncropped_t = paired_t(&samples, u32::MAX);
    // dudect also crops the slow tail: interrupts and preemption add large, class-independent noise
    let mut max_t = uncropped_t.abs();
    let mut crops = Vec::new();
    for p in [0.999, 0.99, 0.95, 0.9, 0.75, 0.5] {
        let t = paired_t(&samples, pct(p));
        crops.push((p, t));
        max_t = max_t.max(t.abs());
    }
    Report { name: name.to_string(), samples: samples.len(), uncropped_t, max_t, median_ns: pct(0.5), crops }
}

thread_local! {
    /// Rows that stayed flagged on the repeat run; reported together by [`finish`].
    static FAILED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Reports a comparison and records a failure if it is flagged twice in a row.
///
/// A real leak depends on the input, so it shows up again on a repeat with fresh data; a burst of
/// noise (another core waking up, a clock change) almost never does. The first flagged run is
/// printed too, so nothing is hidden. A failure does not stop the remaining rows from running;
/// call [`finish`] at the end of the test to fail it.
fn expect_constant_time<I, R>(name: &str, mut gen: impl FnMut(&mut Rng, bool) -> I, op: impl Fn(&I) -> R) {
    let r = measure(name, budget(), &mut gen, &op);
    r.print();
    if r.max_t <= LEAK_T {
        return;
    }
    println!("    flagged; measuring {:?} again with fresh inputs", name);
    let again = measure_seeded(name, budget(), 1, &mut gen, &op);
    again.print();
    if again.max_t > LEAK_T {
        FAILED.with(|f| f.borrow_mut().push(format!("{}: |t| = {:.1} and {:.1} on two runs", name, r.max_t, again.max_t)));
    }
}

/// Fails the test if any comparison since the last call stayed flagged on its repeat run.
fn finish() {
    let failed = FAILED.with(|f| std::mem::take(&mut *f.borrow_mut()));
    assert!(failed.is_empty(), "timing depends on the input:\n  {}", failed.join("\n  "));
}

/// Reports and requires that the leak WAS found (a positive control for the harness itself).
fn expect_leak<I, R>(name: &str, budget: Duration, gen: impl FnMut(&mut Rng, bool) -> I, op: impl Fn(&I) -> R) {
    let r = measure(name, budget, gen, op);
    r.print();
    assert!(
        r.max_t > LEAK_T,
        "{}: the harness did not notice a known leak (|t| = {:.1}); its results cannot be trusted on this machine",
        name,
        r.max_t
    );
}

fn rand32(rng: &mut Rng) -> [u8; 32] {
    rng.bytes(32).try_into().unwrap()
}

// ------------------------------------------------------------------------ positive controls

/// The textbook mistake: stop at the first difference.
fn leaky_eq(a: &[u8], b: &[u8]) -> bool {
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

/// Two 4 KiB strings that differ at the first byte (class 0) or only at the last byte (class 1).
fn eq_pair(rng: &mut Rng, class: bool) -> (Vec<u8>, Vec<u8>) {
    let a = rng.bytes(4096);
    let mut b = a.clone();
    let at = if class { 4095 } else { 0 };
    b[at] ^= 0x80;
    (a, b)
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn harness_flags_an_early_exit_comparison_and_passes_ct_eq() {
    expect_leak("control: early-exit comparison (must be flagged)", Duration::from_secs(2), eq_pair, |(a, b)| {
        leaky_eq(black_box(a), black_box(b))
    });
    expect_constant_time("util::ct_eq, mismatch at first vs last byte", eq_pair, |(a, b)| ct_eq(a, b));
    finish();
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn harness_flags_a_ladder_that_works_harder_for_set_scalar_bits() {
    // zero scalar (after clamping, almost no set bits) against random scalars
    let gen = |rng: &mut Rng, class: bool| -> ([u8; 32], [u8; 32]) {
        (if class { rand32(rng) } else { [0u8; 32] }, x25519::BASE_POINT)
    };
    expect_leak("control: x25519 with extra work per set bit (must be flagged)", Duration::from_secs(4), gen, |(k, u)| {
        x25519::x25519_leaky_control(k, u)
    });
}

// ----------------------------------------------------------------------------- the real code

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn x25519_is_constant_time() {
    let op = |(k, u): &([u8; 32], [u8; 32])| x25519::x25519(k, u);
    // few set bits against random scalars
    expect_constant_time(
        "x25519 scalar: all zero vs random",
        |rng, c| (if c { rand32(rng) } else { [0u8; 32] }, x25519::BASE_POINT),
        op,
    );
    // many set bits against few
    expect_constant_time(
        "x25519 scalar: all ones vs all zeros",
        |_, c| (if c { [0xffu8; 32] } else { [0u8; 32] }, x25519::BASE_POINT),
        op,
    );
    // fixed scalar, special points against random points
    let fixed_scalar = [0x5au8; 32];
    expect_constant_time(
        "x25519 point: u = 0, 1 or p-1 vs random (fixed scalar)",
        move |rng, c| {
            let u = if c {
                rand32(rng)
            } else {
                let mut u = [0u8; 32];
                match rng.below(3) {
                    0 => {}
                    1 => u[0] = 1,
                    _ => {
                        u = [0xff; 32];
                        u[0] = 0xec;
                        u[31] = 0x7f;
                    }
                }
                u
            };
            (fixed_scalar, u)
        },
        op,
    );
    finish();
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn ecdh_on_p256_and_p384_is_constant_time() {
    for (curve, size) in [(Curve::P256, 32usize), (Curve::P384, 48)] {
        let label = if size == 32 { "p256" } else { "p384" };
        // 32 valid peer points, made outside the timed region
        let pool: Vec<Vec<u8>> = (0..32).map(|_| ecdh::generate(curve).unwrap().1).collect();
        let mut one = vec![0u8; size];
        one[size - 1] = 1;
        let generator = ecdh::public_key(curve, &one).unwrap();
        let random_scalar = move |rng: &mut Rng| -> Vec<u8> {
            loop {
                let k = rng.bytes(size);
                if ecdh::public_key(curve, &k).is_some() {
                    return k;
                }
            }
        };
        let op = move |(k, p): &(Vec<u8>, Vec<u8>)| ecdh::shared_secret(curve, k, p);
        let small = {
            let mut k = vec![0u8; size];
            k[size - 1] = 3;
            k
        };
        // few set bits and many leading zero bits against random scalars
        let (pool_a, small_a, rs) = (pool.clone(), small.clone(), random_scalar.clone());
        expect_constant_time(
            &format!("ecdh {label} scalar: 3 vs random"),
            move |rng, c| (if c { rs(rng) } else { small_a.clone() }, pool_a[rng.below(32)].clone()),
            op,
        );
        // a run of set bits against a run of zero bits (both in range)
        let pool_b = pool.clone();
        expect_constant_time(
            &format!("ecdh {label} scalar: 0x00ff..ff vs 0x7f00..00"),
            move |rng, c| {
                let mut k = vec![if c { 0x00 } else { 0x7f }; size];
                if c {
                    k[1..].fill(0xff);
                } else {
                    k[1..].fill(0);
                }
                (k, pool_b[rng.below(32)].clone())
            },
            op,
        );
        // fixed scalar: the generator against random points
        let fixed = random_scalar(&mut Rng::new(7));
        let pool_c = pool.clone();
        let generator_c = generator.clone();
        expect_constant_time(
            &format!("ecdh {label} peer: generator vs random point"),
            move |rng, c| (fixed.clone(), if c { pool_c[rng.below(32)].clone() } else { generator_c.clone() }),
            op,
        );
        // the public key of a secret scalar is also computed from it
        let (rs, small_b) = (random_scalar.clone(), small.clone());
        expect_constant_time(
            &format!("ecdh {label} public key: scalar 3 vs random"),
            move |rng, c| if c { rs(rng) } else { small_b.clone() },
            move |k: &Vec<u8>| ecdh::public_key(curve, k),
        );
    }
    finish();
}

/// The backends this machine can run: portable always, hardware where the CPU has it.
fn backends() -> Vec<Backend> {
    let mut v = vec![Backend::Portable];
    if super::aes_hw::available() {
        v.push(Backend::Hardware);
    }
    v
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn ghash_multiplication_is_constant_time() {
    // eight blocks per call, so one call is well above the timer's resolution
    let rand128 = |rng: &mut Rng| rng.bytes(16);
    for backend in backends() {
        let fixed_h = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210_u128.to_be_bytes();
        let blocks = |rng: &mut Rng, c: bool, fill: u8| -> Vec<u8> { if c { (0..8).flat_map(|_| rand128(rng)).collect() } else { vec![fill; 128] } };
        let by_data = |(h, data): &([u8; 16], Vec<u8>)| GhashKey::new(h, backend).hash(b"aad", data);
        expect_constant_time(&format!("ghash [{backend:?}] data blocks: 0 vs random (fixed H)"), |rng, c| (fixed_h, blocks(rng, c, 0)), by_data);
        expect_constant_time(&format!("ghash [{backend:?}] data blocks: all ones vs random (fixed H)"), |rng, c| (fixed_h, blocks(rng, c, 0xff)), by_data);
        let data = vec![0x5au8; 128];
        let key = |rng: &mut Rng, c: bool, fill: u8| -> [u8; 16] { if c { rand128(rng).try_into().unwrap() } else { [fill; 16] } };
        expect_constant_time(&format!("ghash [{backend:?}] hash key H: 0 vs random"), |rng, c| (key(rng, c, 0), data.clone()), by_data);
        expect_constant_time(&format!("ghash [{backend:?}] hash key H: all ones vs random"), |rng, c| (key(rng, c, 0xff), data.clone()), by_data);
    }
    finish();
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn poly1305_is_constant_time() {
    // 1 KiB messages; the key is the secret in the AEAD, the message is public but should not matter
    fn run64(k: &[u8; 32], m: &[u8]) -> [u8; 16] {
        let mut p = limbs64::Poly1305::new(k);
        for c in m.chunks_exact(16) {
            p.block(c.try_into().unwrap(), true);
        }
        p.finish()
    }
    fn run32(k: &[u8; 32], m: &[u8]) -> [u8; 16] {
        let mut p = limbs32::Poly1305::new(k);
        for c in m.chunks_exact(16) {
            p.block(c.try_into().unwrap(), true);
        }
        p.finish()
    }
    let fixed_key = [0x33u8; 32];
    let fixed_msg = vec![0xa7u8; 1024];
    for (label, run) in [("limbs64 (3 x 44-bit)", run64 as fn(&[u8; 32], &[u8]) -> [u8; 16]), ("limbs32 (5 x 26-bit)", run32)] {
        expect_constant_time(
            &format!("poly1305 {} key: zero vs random", label),
            |rng, c| (if c { rand32(rng) } else { [0u8; 32] }, fixed_msg.clone()),
            |(k, m)| run(k, m),
        );
        expect_constant_time(
            &format!("poly1305 {} key: all ones vs random", label),
            |rng, c| (if c { rand32(rng) } else { [0xffu8; 32] }, fixed_msg.clone()),
            |(k, m)| run(k, m),
        );
        expect_constant_time(
            &format!("poly1305 {} message: zeros vs random", label),
            |rng, c| (fixed_key, if c { rng.bytes(1024) } else { vec![0u8; 1024] }),
            |(k, m)| run(k, m),
        );
        expect_constant_time(
            &format!("poly1305 {} message: all ones vs random", label),
            |rng, c| (fixed_key, if c { rng.bytes(1024) } else { vec![0xffu8; 1024] }),
            |(k, m)| run(k, m),
        );
    }
    finish();
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn aead_and_mac_primitives_are_constant_time_in_their_data() {
    // end to end ChaCha20-Poly1305 and AES-GCM over 1 KiB: plaintext zeros / ones vs random
    let nonce = [9u8; 12];
    let cc = ChaCha20Poly1305::new(&[0x42u8; 32]);
    let sealed = |c: bool, rng: &mut Rng| {
        let mut buf = if c { rng.bytes(1024) } else { vec![0u8; 1024] };
        buf.extend_from_slice(&[0u8; 16]);
        buf
    };
    expect_constant_time("chacha20-poly1305 seal 1 KiB: zeros vs random", |rng, c| sealed(c, rng), |buf| {
        let mut b = buf.clone();
        cc.seal_in_place(&nonce, b"aad", &mut b);
        b
    });
    expect_constant_time("chacha20-poly1305 key setup + seal 64 B: zero key vs random", |rng, c| if c { rng.bytes(32) } else { vec![0u8; 32] }, |key| {
        let c = ChaCha20Poly1305::new(key);
        let mut b = vec![0u8; 64 + 16];
        c.seal_in_place(&nonce, b"", &mut b);
        b
    });
    let gcm = AesGcm::new(&[0x42u8; 16]);
    expect_constant_time("aes-128-gcm seal 1 KiB: zeros vs random", |rng, c| sealed(c, rng), |buf| {
        let mut b = buf.clone();
        gcm.seal_in_place(&nonce, b"aad", &mut b);
        b
    });
    // HMAC-SHA-256 and SHA-256: key / message bytes
    expect_constant_time("hmac-sha256 key: zero vs random (1 KiB message)", |rng, c| if c { rng.bytes(32) } else { vec![0u8; 32] }, |key| {
        let mut h = Hmac::<Sha256>::new(key);
        h.update(&[0x5au8; 1024]);
        h.finalize()
    });
    expect_constant_time("sha256 message: zeros vs random (1 KiB)", |rng, c| if c { rng.bytes(1024) } else { vec![0u8; 1024] }, |m| Sha256::digest(m));
    finish();
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn harness_detects_a_difference_of_about_one_percent() {
    // sensitivity: class 1 does ten extra dependent multiplications (about 9 ns) on an operation
    // that takes about 680 ns. A harness that cannot see that would give clean results for
    // leaks of that size too.
    fn delay(n: u32) -> u64 {
        let mut x = 0x9e37_79b9u64;
        for _ in 0..n {
            x = black_box(x.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(1));
        }
        x
    }
    let key = [0x33u8; 32];
    expect_leak("control: poly1305 1 KiB, one class ~1.3% slower", Duration::from_secs(3), |rng, c| (c, rng.bytes(1024)), |(c, m)| {
        let mut p = limbs64::Poly1305::new(&key);
        for ch in m.chunks_exact(16) {
            p.block(ch.try_into().unwrap(), true);
        }
        let tag = p.finish();
        if *c {
            black_box(delay(10));
        }
        tag
    });
}

#[test]
#[should_panic(expected = "timing depends on the input")]
fn finish_fails_when_a_row_stayed_flagged() {
    FAILED.with(|f| f.borrow_mut().push("example row".to_string()));
    finish();
}

/// AES with a secret key and secret data, on every backend this machine has. The cipher used to
/// index an S-box table with key-dependent bytes (backlog B-20), which one x86-64 host flagged
/// reproducibly (|t| 17 to 69) and the Apple M5 Max did not; the bitsliced and hardware
/// implementations have no such lookups, so unlike before, this is expected to stay clean.
#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn aes_is_constant_time() {
    let nonce = [9u8; 12];
    for backend in backends() {
        for key_len in [16usize, 32] {
            for (what, fill) in [("zero", 0u8), ("all-ones", 0xff)] {
                expect_constant_time(
                    &format!("aes-{}-gcm [{backend:?}] key setup + seal 64 B: {what} key vs random", key_len * 8),
                    |rng, c| if c { rng.bytes(key_len) } else { vec![fill; key_len] },
                    |key| {
                        let g = AesGcm::with_backend(key, backend);
                        let mut b = vec![0u8; 64 + 16];
                        g.seal_in_place(&nonce, b"", &mut b);
                        b
                    },
                );
            }
        }
        // a fixed key, secret plaintext of 1 KiB (CTR keystream and GHASH over the ciphertext).
        // Both classes are built the same way and only then overwritten: filling one class with
        // `vec![0; n]` (a calloc) and the other by pushing bytes puts the buffers at different
        // addresses, and at under a microsecond per call the harness sees that (|t| 5 to 7) even
        // though no byte of the data is ever branched on.
        let g = AesGcm::with_backend(&[0x6bu8; 16], backend);
        for (what, fill) in [("zeros", 0u8), ("all-ones", 0xff)] {
            expect_constant_time(
                &format!("aes-128-gcm [{backend:?}] seal 1 KiB: {what} vs random"),
                |rng, c| {
                    let mut v = rng.bytes(1024);
                    if !c {
                        v.fill(fill);
                    }
                    v
                },
                |pt| g.seal(&nonce, b"aad", pt),
            );
        }
    }
    finish();
}
