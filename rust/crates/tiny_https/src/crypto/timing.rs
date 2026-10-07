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
//! Which results fail a test: a comparison whose strongest |t| is above 4.5 is measured again with
//! fresh inputs, and it fails if the repeat is above 10 as well, or if the statistic that was strongest
//! on the first run (the uncropped one or one crop level) is above 4.5 again *with the same sign*, that is
//! with the same class slower again. Noise has no direction, so on top of having to reach 4.5 a second time
//! at one statistic fixed in advance it has to land on the same side, which is a coin toss; a difference
//! that depends on the input keeps its direction. The first run and the repeat are both printed.
//! `harness_does_not_fail_comparisons_of_identical_classes` measures the false-alarm rate against the
//! harness itself, the negative control that goes with the positive ones.
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

/// |t| above this is reported as a leak, and fails the test if the repeat is above it too.
const LEAK_T: f64 = 10.0;
/// |t| above this is reported as suspicious, is measured again, and fails the test if the same statistic is
/// above it again on the repeat with the same sign (see [`judge`]).
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

/// The fraction of the samples (the fastest) that each cropped view keeps; the slow tail is interrupts and scheduling.
const CROP_LEVELS: [f64; 6] = [0.999, 0.99, 0.95, 0.9, 0.75, 0.5];

impl Report {
    /// Every t value of the run with its sign: the uncropped one, then one per crop level of `crops`. The sign
    /// says which class was slower (positive: class 1), and is the same for a real difference run after run.
    fn statistics(&self) -> impl Iterator<Item = f64> + '_ {
        std::iter::once(self.uncropped_t).chain(self.crops.iter().map(|c| c.1))
    }

    /// The statistic with the largest |t|: its place in [`Report::statistics`] and its signed value.
    fn peak(&self) -> (usize, f64) {
        let mut best = (0, self.uncropped_t);
        for (i, t) in self.statistics().enumerate() {
            if t.abs() > best.1.abs() {
                best = (i, t);
            }
        }
        best
    }

    /// "uncropped", or "p99.9" and so on, for the statistic at `index`.
    fn label(&self, index: usize) -> String {
        match index {
            0 => "uncropped".to_string(),
            i => self.crops.get(i - 1).map_or("?".to_string(), |(p, _)| format!("p{:.1}", p * 100.0)),
        }
    }

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
        // No spread at all. With a mean of zero that is no evidence of a difference; with any other mean it is
        // the strongest evidence there can be (every block shows the same offset, which a coarse clock makes
        // the normal case for a cheap operation), and must not be reported as "no leak".
        if mean == 0.0 {
            0.0
        } else {
            f64::INFINITY.copysign(mean)
        }
    } else {
        mean / (var / n).sqrt()
    }
}

const DEFAULT_SECS: f64 = 3.0;

/// The time budget from the text of `TINY_HTTPS_TIMING_SECS` (`None` if it is not set): seconds, 0 or more
/// (0 is the shortest run, one measured batch). Anything else is an `Err` saying so.
fn parse_budget(value: Option<&str>) -> Result<Duration, String> {
    let Some(text) = value else { return Ok(Duration::from_secs_f64(DEFAULT_SECS)) };
    text.trim()
        .parse::<f64>()
        .ok()
        .filter(|secs| secs.is_finite() && *secs >= 0.0)
        .and_then(|secs| Duration::try_from_secs_f64(secs).ok())
        .ok_or_else(|| format!("TINY_HTTPS_TIMING_SECS={text:?} is not a number of seconds (0 or more); using {DEFAULT_SECS}"))
}

fn budget() -> Duration {
    match parse_budget(std::env::var("TINY_HTTPS_TIMING_SECS").ok().as_deref()) {
        Ok(d) => d,
        Err(why) => {
            eprintln!("{why}");
            Duration::from_secs_f64(DEFAULT_SECS)
        }
    }
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
    // the first batch only warms up, so a run is never over before one more has been measured
    while first || samples.is_empty() || start.elapsed() < budget {
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
    let pct = |p: f64| if sorted.is_empty() { 0 } else { sorted[(((sorted.len() - 1) as f64) * p) as usize] };
    let uncropped_t = paired_t(&samples, u32::MAX);
    // dudect also crops the slow tail: interrupts and preemption add large, class-independent noise
    let mut max_t = uncropped_t.abs();
    let mut crops = Vec::new();
    for p in CROP_LEVELS {
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

/// Whether a row that was flagged on its first run stays flagged on the repeat with fresh inputs, and
/// if so, why (the text that [`finish`] reports). There are two ways to stay flagged, and the second
/// only adds to the first:
///
/// * the strongest |t| of both runs is above [`LEAK_T`], whichever statistic and whichever sign;
/// * the first run's strongest statistic is above [`SUSPICIOUS_T`] and *that same statistic* is above
///   [`SUSPICIOUS_T`] again on the repeat, with the same sign (the same class slower again).
///
/// The second is a replication, not a second look at the maximum. The first run chose the statistic
/// out of seven, so a t value of 5 there is not much; the repeat then asks one question fixed in
/// advance (is it there again, in the same direction?), which noise answers yes to only rarely, because
/// its sign is a coin toss. A real difference in running time keeps its direction and its size.
fn judge(first: &Report, again: &Report) -> Option<String> {
    if first.max_t > LEAK_T && again.max_t > LEAK_T {
        return Some(format!("{}: |t| = {:.1} and {:.1} on two runs", first.name, first.max_t, again.max_t));
    }
    let (at, t) = first.peak();
    if t.abs() <= SUSPICIOUS_T {
        return None;
    }
    let repeat = again.statistics().nth(at)?;
    (repeat.abs() > SUSPICIOUS_T && repeat.signum() == t.signum()).then(|| {
        format!("{}: t = {:+.1} at {} and {:+.1} at the same statistic on a repeat with fresh inputs", first.name, t, first.label(at), repeat)
    })
}

/// Reports a comparison and records a failure if it is flagged twice in a row (see [`judge`]).
///
/// A real leak depends on the input, so it shows up again on a repeat with fresh data; a burst of
/// noise (another core waking up, a clock change) almost never does, and when a stretch of noise
/// does reach a t value above [`SUSPICIOUS_T`] its sign is as likely to be one as the other. The first
/// flagged run is printed too, so nothing is hidden. A failure does not stop the remaining rows from
/// running; call [`finish`] at the end of the test to fail it.
fn expect_constant_time<I, R>(name: &str, mut gen: impl FnMut(&mut Rng, bool) -> I, op: impl Fn(&I) -> R) {
    let r = measure(name, budget(), &mut gen, &op);
    r.print();
    if r.max_t <= SUSPICIOUS_T {
        return;
    }
    println!("    above {SUSPICIOUS_T}; measuring {:?} again with fresh inputs", name);
    let again = measure_seeded(name, budget(), 1, &mut gen, &op);
    again.print();
    match judge(&r, &again) {
        Some(why) => {
            println!("    came back: recorded as a failure");
            FAILED.with(|f| f.borrow_mut().push(why));
        }
        None => println!("    did not come back at the same statistic with the same sign: noise, not recorded"),
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
    // Both classes are built the same way, and the zero class is overwritten afterwards. Building it with
    // `vec![0; 1024]` (a zeroed allocation) and the other with `rng.bytes` puts the buffers in different
    // places, and on an operation of 550 ns the harness sees that: |t| 5 to 11 on every run, same sign, on
    // the AES-GCM row below. The same lesson is in `aes_is_constant_time`, where it was learned first.
    let sealed = |c: bool, rng: &mut Rng| {
        let mut buf = rng.bytes(1024);
        if !c {
            buf.fill(0);
        }
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

// ------------------------------------------------------------------------ the harness's own arithmetic

/// `blocks` blocks of eight samples of each class, class 0 taking `a` ns and class 1 taking `b(block)` ns.
fn blocks_of(blocks: usize, a: u32, b: impl Fn(usize) -> u32) -> Vec<(u32, bool)> {
    let mut v = Vec::new();
    for k in 0..blocks {
        for i in 0..BLOCK {
            let class = i % 2 == 1;
            v.push((if class { b(k) } else { a }, class));
        }
    }
    v
}

#[test]
fn a_difference_with_no_spread_is_the_strongest_evidence_not_none() {
    // class 1 is exactly 1 ns slower in every block: the old code answered 0 ("no leak detected")
    let t = paired_t(&blocks_of(200, 100, |_| 101), u32::MAX);
    assert_eq!(t, f64::INFINITY);
    assert_eq!(paired_t(&blocks_of(200, 101, |_| 100), u32::MAX), f64::NEG_INFINITY);
    // no difference and no spread is no evidence
    assert_eq!(paired_t(&blocks_of(200, 100, |_| 100), u32::MAX), 0.0);
    // the same offset with some spread was always found
    let t = paired_t(&blocks_of(200, 100, |k| 101 + (k % 3) as u32), u32::MAX);
    assert!(t.is_finite() && t > 10.0, "{t}");
    // and a report built on an infinite t says LEAK, in both signs
    let r = Report { name: "x".into(), samples: 0, uncropped_t: f64::INFINITY, max_t: f64::INFINITY, median_ns: 0, crops: vec![] };
    assert_eq!(r.verdict(), "LEAK");
    r.print();
}

#[test]
fn the_time_budget_is_read_with_care() {
    assert_eq!(parse_budget(None), Ok(Duration::from_secs(3)));
    assert_eq!(parse_budget(Some("0.5")), Ok(Duration::from_millis(500)));
    assert_eq!(parse_budget(Some(" 12 ")), Ok(Duration::from_secs(12)));
    assert_eq!(parse_budget(Some("0")), Ok(Duration::ZERO));
    // these panicked (a negative or enormous number in `Duration::from_secs_f64`) or were silently the default
    for bad in ["-1", "-0.001", "abc", "", "NaN", "inf", "1e300"] {
        let why = parse_budget(Some(bad)).unwrap_err();
        assert!(why.contains("TINY_HTTPS_TIMING_SECS"), "{bad}: {why}");
    }
}

#[test]
fn a_budget_of_zero_still_measures_something() {
    // it used to be one batch, the warm-up one, which is thrown away, and then an empty sample set to index into
    let r = measure("zero budget", Duration::ZERO, |rng, _| rng.next_u64(), |x| x.wrapping_mul(3));
    assert!(r.samples >= BLOCK, "{}", r.samples);
    assert!(r.max_t.is_finite() || r.max_t.is_infinite());
}

/// A report holding the given signed t values (the uncropped one, then one per crop level), as `measure_seeded` builds it.
fn report(ts: [f64; 7]) -> Report {
    let crops: Vec<(f64, f64)> = CROP_LEVELS.iter().copied().zip(ts[1..].iter().copied()).collect();
    let max_t = ts.iter().fold(0f64, |m, t| m.max(t.abs()));
    Report { name: "row".into(), samples: 1000, uncropped_t: ts[0], max_t, median_ns: 100, crops }
}

const QUIET: [f64; 7] = [0.5, -1.0, 0.3, 0.8, -0.2, 1.1, 0.4];

/// `QUIET` with `t` at statistic `at` (0 is the uncropped one).
fn with(at: usize, t: f64) -> [f64; 7] {
    let mut ts = QUIET;
    ts[at] = t;
    ts
}

#[test]
fn a_flagged_row_fails_when_its_statistic_comes_back_with_the_same_sign() {
    // the first run peaks at p95 (index 3) with +6: suspicious, not a leak
    let first = report(with(3, 6.0));
    assert_eq!(first.peak(), (3, 6.0));
    assert_eq!(first.label(3), "p95.0");
    assert_eq!(first.label(0), "uncropped");
    assert_eq!(first.label(6), "p50.0");
    assert_eq!(first.verdict(), "suspicious");

    // the same statistic, the same direction, above 4.5 again: a real difference
    let why = judge(&first, &report(with(3, 5.0))).expect("a difference that came back");
    assert!(why.contains("p95.0") && why.contains("+6.0") && why.contains("+5.0"), "{why}");
    // the other direction (class 1 faster this time) is what noise does half of the time
    assert_eq!(judge(&first, &report(with(3, -5.5))), None);
    assert_eq!(judge(&first, &report(with(3, -50.0))), None);
    // below 4.5 at that statistic, however loud another statistic is
    assert_eq!(judge(&first, &report(with(3, 4.4))), None);
    assert_eq!(judge(&first, &report(with(6, 7.0))), None);
    assert_eq!(judge(&first, &report(QUIET)), None);
    // a negative first run is judged the same way round
    let slower_first = report(with(2, -6.0));
    assert!(judge(&slower_first, &report(with(2, -4.6))).is_some());
    assert_eq!(judge(&slower_first, &report(with(2, 4.6))), None);
}

#[test]
fn the_old_rule_still_holds_and_the_new_one_only_adds_to_it() {
    // above 10 on both runs fails whichever statistic or sign it is: nothing that failed before passes now
    let first = report(with(2, 12.0));
    let why = judge(&first, &report(with(5, -11.0))).expect("two runs above 10");
    assert!(why.contains("on two runs"), "{why}");
    assert!(judge(&first, &report(with(2, 11.0))).is_some());
    // above 10 once and between 4.5 and 10 at the same statistic the second time: this is new, and fails
    let why = judge(&first, &report(with(2, 7.0))).expect("a replicated leak");
    assert!(why.contains("p99.0"), "{why}");
    // above 10 once and quiet the second time is a burst of noise, as before
    assert_eq!(judge(&first, &report(QUIET)), None);
    assert_eq!(judge(&first, &report(with(2, 4.0))), None);
    // a quiet first run is never held against the row
    assert_eq!(judge(&report(with(4, 4.0)), &report(with(4, 40.0))), None);
    // the coarse clock: every block offset by the same amount is an infinite t, in either direction
    let inf = report(with(0, f64::INFINITY));
    assert!(judge(&inf, &report(with(0, f64::INFINITY))).is_some());
    assert!(judge(&inf, &report(with(0, f64::NEG_INFINITY))).is_some());
    assert_eq!(judge(&inf, &report(QUIET)), None);
}

#[test]
fn a_report_with_fewer_statistics_than_expected_is_judged_not_crashed_on() {
    let bare = |t: f64| Report { name: "bare".into(), samples: 0, uncropped_t: t, max_t: t.abs(), median_ns: 0, crops: vec![] };
    assert_eq!(bare(6.0).peak(), (0, 6.0));
    assert_eq!(bare(6.0).label(0), "uncropped");
    assert_eq!(bare(6.0).label(3), "?");
    assert!(judge(&bare(6.0), &bare(5.0)).is_some());
    assert_eq!(judge(&bare(6.0), &bare(-5.0)), None);
    // the first run peaked at a crop level the repeat does not have
    assert_eq!(judge(&report(with(3, 6.0)), &bare(9.0)), None);
}

// ------------------------------------------------------------------------ the false-alarm rate

/// The time for each run of the negative control: `TINY_HTTPS_TIMING_SECS` if it is set, else half a second, so
/// that the default run (ten pairs of three operations) takes about half a minute and not a quarter of an hour.
fn null_budget() -> Duration {
    if std::env::var_os("TINY_HTTPS_TIMING_SECS").is_some() {
        budget()
    } else {
        Duration::from_millis(500)
    }
}

/// What [`false_alarms`] counted.
#[derive(Default)]
struct Tally {
    /// first runs whose strongest |t| was above [`SUSPICIOUS_T`], and above [`LEAK_T`]
    above_suspicious: usize,
    above_leak: usize,
    /// pairs that the old rule (above [`LEAK_T`] twice) and the new one ([`judge`]) would have failed
    old_rule: usize,
    new_rule: usize,
    /// the strongest |t| of any run
    largest_t: f64,
}

/// Measures `pairs` first runs and repeats of a comparison whose two classes are the same kind of input,
/// so that every difference the harness finds is noise, and counts what each rule would have done.
fn false_alarms<I, R>(name: &str, pairs: usize, mut gen: impl FnMut(&mut Rng, bool) -> I, op: impl Fn(&I) -> R) -> Tally {
    let mut tally = Tally::default();
    for k in 0..pairs {
        let first = measure_seeded(name, null_budget(), 2 * k as u64, &mut gen, &op);
        let again = measure_seeded(name, null_budget(), 2 * k as u64 + 1, &mut gen, &op);
        tally.above_suspicious += (first.max_t > SUSPICIOUS_T) as usize;
        tally.above_leak += (first.max_t > LEAK_T) as usize;
        tally.old_rule += (first.max_t > LEAK_T && again.max_t > LEAK_T) as usize;
        tally.largest_t = tally.largest_t.max(first.max_t).max(again.max_t);
        if let Some(why) = judge(&first, &again) {
            tally.new_rule += 1;
            println!("    new rule failed a pair of identical classes: {why}");
        }
    }
    tally
}

/// The negative control: the repeat rule must not fail comparisons that have nothing to find. Three operations
/// of very different length (the short one runs close to the clock's resolution, where noise is worst), each
/// compared with itself. `TINY_HTTPS_NULL_PAIRS` (default 10) sets the number of first-run and repeat pairs per
/// operation, `TINY_HTTPS_TIMING_SECS` the time of each run (default here 0.5).
#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn harness_does_not_fail_comparisons_of_identical_classes() {
    let pairs: usize = std::env::var("TINY_HTTPS_NULL_PAIRS").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(10);
    let mut new_rule_failures = 0;
    let mut report_row = |what: &str, c: Tally| {
        println!(
            "{what:<46} {pairs} pairs: first run above {SUSPICIOUS_T}: {:>2}, above {LEAK_T}: {:>2}; failed by the old rule: {:>2}, by the new rule: {:>2}; largest |t| of any run {:.1}",
            c.above_suspicious, c.above_leak, c.old_rule, c.new_rule, c.largest_t
        );
        new_rule_failures += c.new_rule;
    };
    report_row("x25519, random scalar (about 100 us)", false_alarms("null x25519", pairs, |rng, _| (rand32(rng), x25519::BASE_POINT), |(k, u)| x25519::x25519(k, u)));
    report_row("sha256, 1 KiB of random bytes (a few us)", false_alarms("null sha256", pairs, |rng, _| rng.bytes(1024), |m| Sha256::digest(m)));
    report_row("ct_eq, 32 equal random bytes (tens of ns)", false_alarms("null ct_eq", pairs, |rng, _| { let a = rng.bytes(32); (a.clone(), a) }, |(a, b)| ct_eq(a, b)));
    assert_eq!(new_rule_failures, 0, "the repeat rule failed comparisons of identical classes");
}
