//! Security-property and regression tests for azoth (KPDC).
//!
//! Cost note: tests whose property is independent of KDF strength (statistical
//! distribution, panic-safety, false-positive rate over many guesses) use
//! `KdfParams::FAST_TEST` so they can run thousands of evaluations. The KAT and the
//! functional multi-key/re-randomize tests run at `KdfParams::RECOMMENDED` (the real
//! default) with small K/maxprobe to keep the Argon2 call count low.

use azoth::{next_prime_coprime8, KdfParams, Kpdc};

// ---- a deterministic PRG so statistical tests never flake on getrandom ----
struct XorShift(u64);
impl XorShift {
    fn new(seed: u64) -> Self {
        XorShift(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let b = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
    }
}

fn det_block(n: usize, seed: u64) -> Vec<u8> {
    let mut v = vec![0u8; n];
    XorShift::new(seed).fill(&mut v);
    v
}

// ---- uniformity metrics ----
fn chi_square_bytes(block: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &b in block {
        counts[b as usize] += 1;
    }
    let expected = block.len() as f64 / 256.0;
    counts
        .iter()
        .map(|&o| {
            let d = o as f64 - expected;
            d * d / expected
        })
        .sum()
}

fn ones_fraction(block: &[u8]) -> f64 {
    let ones: u64 = block.iter().map(|b| b.count_ones() as u64).sum();
    ones as f64 / (block.len() as f64 * 8.0)
}

const REC: KdfParams = KdfParams::RECOMMENDED;
const FAST: KdfParams = KdfParams::FAST_TEST;

// =========================================================================== //
//  Indistinguishability (the headline property)
// =========================================================================== //

#[test]
fn full_container_is_statistically_uniform() {
    // Build a deterministic "random" block, then fill it with several payloads.
    // The result must still look uniform: no byte-value bias, ~50% bit density.
    let k = next_prime_coprime8(257);
    let mut c = Kpdc::from_bytes(det_block(262_144, 0xA5A5_1234), k, FAST).unwrap();
    for i in 0..10 {
        let pw = format!("pw-{i}");
        let known: Vec<String> = (0..i).map(|j| format!("pw-{j}")).collect();
        let kr: Vec<&str> = known.iter().map(|s| s.as_str()).collect();
        let _ = c.write(&pw, format!("secret number {i}").as_bytes(), &kr, 4, None);
    }
    let chi = chi_square_bytes(c.as_bytes());
    let ones = ones_fraction(c.as_bytes());
    // 255 d.o.f.: mean 255, sd ~22.6. Generous bound catches gross structure.
    assert!(
        chi > 150.0 && chi < 400.0,
        "chi-square {chi} out of uniform range"
    );
    assert!((ones - 0.5).abs() < 0.01, "bit density {ones} not ~0.5");
}

#[test]
fn empty_and_full_are_both_uniform() {
    // "Empty" (just random fill) and "full" (random fill + payloads) must both pass
    // the same uniformity test — there is nothing to distinguish them by.
    let k = next_prime_coprime8(131);
    let empty = Kpdc::from_bytes(det_block(131_072, 0x0F0F_9999), k, FAST).unwrap();
    let mut full = Kpdc::from_bytes(det_block(131_072, 0x3333_7777), k, FAST).unwrap();
    for i in 0..6 {
        let known: Vec<String> = (0..i).map(|j| format!("k{j}")).collect();
        let kr: Vec<&str> = known.iter().map(|s| s.as_str()).collect();
        full.write(&format!("k{i}"), b"payload data here", &kr, 4, None)
            .unwrap();
    }
    let ce = chi_square_bytes(empty.as_bytes());
    let cf = chi_square_bytes(full.as_bytes());
    assert!(ce > 150.0 && ce < 400.0, "empty chi {ce}");
    assert!(cf > 150.0 && cf < 400.0, "full chi {cf}");
}

// =========================================================================== //
//  Multi-key independence + wrong-credential behavior
// =========================================================================== //

#[test]
fn multi_key_independence_recommended() {
    let k = next_prime_coprime8(11);
    let mp = 3;
    let mut c = Kpdc::create(16384, k, REC).unwrap();
    c.write_all_fresh(
        &[
            ("alice", b"plan A"),
            ("bob", b"plan B"),
            ("carol", b"plan C"),
        ],
        mp,
    )
    .unwrap();
    assert_eq!(
        c.read("alice", mp).map(|z| z.to_vec()),
        Some(b"plan A".to_vec())
    );
    assert_eq!(
        c.read("bob", mp).map(|z| z.to_vec()),
        Some(b"plan B".to_vec())
    );
    assert_eq!(
        c.read("carol", mp).map(|z| z.to_vec()),
        Some(b"plan C".to_vec())
    );
    // wrong password and wrong K both yield nothing
    assert!(c.read("mallory", mp).is_none());
    let wrong_k = next_prime_coprime8(13);
    let c2 = Kpdc::from_bytes(c.into_bytes(), wrong_k, REC).unwrap();
    assert!(c2.read("alice", mp).is_none(), "wrong K must not decrypt");
}

#[test]
fn wrong_credentials_never_false_positive() {
    // Many wrong passwords against a populated container must all return None.
    let k = next_prime_coprime8(101);
    let mut c = Kpdc::from_bytes(det_block(65536, 0xDEAD_BEEF), k, FAST).unwrap();
    c.write("real-password", b"the actual secret", &[], 4, None)
        .unwrap();
    for i in 0..300 {
        let guess = format!("guess-{i}");
        assert!(c.read(&guess, 4).is_none(), "false positive on {guess}");
    }
    // the real one still works
    assert_eq!(
        c.read("real-password", 4).map(|z| z.to_vec()),
        Some(b"the actual secret".to_vec())
    );
}

// =========================================================================== //
//  Re-randomization defeats multi-snapshot diffing
// =========================================================================== //

#[test]
fn rerandomize_changes_almost_every_byte() {
    let k = next_prime_coprime8(11);
    let mp = 3;
    let mut c = Kpdc::create(16384, k, REC).unwrap();
    c.write_all_fresh(&[("a", b"first")], mp).unwrap();
    let before = c.as_bytes().to_vec();
    // re-randomize with an added payload
    c.write_all_fresh(&[("a", b"first"), ("b", b"second")], mp)
        .unwrap();
    let after = c.as_bytes();
    let differing = before.iter().zip(after).filter(|(x, y)| x != y).count();
    let frac = differing as f64 / before.len() as f64;
    // a whole-block rewrite changes ~half the BYTES (each byte differs w.p. ~1 - 1/256
    // for re-randomized fill); require a large fraction to prove it is not a sparse edit.
    assert!(
        frac > 0.9,
        "only {frac} of bytes changed; re-randomize not whole-block"
    );
    assert_eq!(c.read("a", mp).map(|z| z.to_vec()), Some(b"first".to_vec()));
    assert_eq!(
        c.read("b", mp).map(|z| z.to_vec()),
        Some(b"second".to_vec())
    );
}

// =========================================================================== //
//  Fuzz-lite: read must never panic on arbitrary bytes / credentials
// =========================================================================== //

#[test]
fn read_never_panics_on_arbitrary_input() {
    let mut rng = XorShift::new(0xF00D_F00D);
    for _ in 0..200 {
        let size = 1024 + (rng.next_u64() % 8192) as usize;
        let block = det_block(size, rng.next_u64());
        let k = next_prime_coprime8(2 + (rng.next_u64() % 200));
        if let Ok(c) = Kpdc::from_bytes(block, k, FAST) {
            let pw = format!("p{}", rng.next_u64());
            // must return None or Some, never panic / never crash
            let _ = c.read(&pw, 4);
        }
    }
}

// =========================================================================== //
//  Known Answer Test — pins the wire format (derivations + layout + walk).
//  Deterministic: fixed all-zero block, fixed salt, fixed (pw, K, maxprobe).
// =========================================================================== //

// FNV-1a 64-bit over the resulting block; any format change flips this.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

const KAT_K: u64 = 11;
const KAT_MP: usize = 1;
const KAT_SALT: [u8; 16] = [0x42; 16];
const KAT_PW: &str = "known-answer";
const KAT_PT: &[u8] = b"known answer payload";
const KAT_BLOCK_LEN: usize = 8192;
// Pinned under KdfParams::RECOMMENDED. Update ONLY if the wire format intentionally changes.
const KAT_FNV: u64 = 0xeabe2c5067fdcf54;

#[test]
fn known_answer_write_and_read() {
    // Start from an all-zero block so the output is fully determined by the inputs.
    let mut c = Kpdc::from_bytes(vec![0u8; KAT_BLOCK_LEN], KAT_K, REC).unwrap();
    let plane = c
        .write(KAT_PW, KAT_PT, &[], KAT_MP, Some(&KAT_SALT))
        .unwrap();
    let got = fnv1a(c.as_bytes());
    assert_eq!(
        got, KAT_FNV,
        "KAT MISMATCH: wire format changed (plane={plane}, fnv=0x{got:016x}). \
         If intentional, update KAT_FNV."
    );
    // And it reads back.
    assert_eq!(
        c.read(KAT_PW, KAT_MP).map(|z| z.to_vec()),
        Some(KAT_PT.to_vec())
    );
}
