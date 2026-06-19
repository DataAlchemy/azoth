//! Security-property and regression tests for azoth (KPDC).
//!
//! Cost note: tests whose property is independent of KDF strength (statistical
//! distribution, panic-safety, false-positive rate over many guesses) use
//! `KdfParams::INSECURE_FAST_TEST` so they can run thousands of evaluations. The KAT and the
//! functional multi-key/re-randomize tests run at `KdfParams::RECOMMENDED` (the real
//! default) with small K/maxprobe to keep the Argon2 call count low.

use azoth::{next_prime_coprime8, Cipher, KdfParams, Kpdc};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// Cryptographic deterministic fill: SHAKE256(seed). Used for the higher-order
/// statistical tests so they are reproducible AND genuinely pass digram / runs /
/// serial-correlation tests (a non-crypto PRG could show 2nd-order artifacts).
fn shake_fill(n: usize, seed: &[u8]) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(seed);
    let mut r = h.finalize_xof();
    let mut v = vec![0u8; n];
    r.read(&mut v);
    v
}

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

/// Adjacent-bit transitions across the whole bitstream (a runs test). For i.i.d.
/// uniform bits, E[T] = (nbits-1)/2, sd = sqrt(nbits-1)/2. Structure (e.g. a
/// patterned or over-balanced block) shifts this well outside the band.
fn bit_transitions(block: &[u8]) -> u64 {
    let mut t = 0u64;
    let mut prev = 0u8;
    let mut first = true;
    for &byte in block {
        for i in 0..8 {
            let bit = (byte >> i) & 1;
            if first {
                first = false;
            } else if bit != prev {
                t += 1;
            }
            prev = bit;
        }
    }
    t
}

/// Byte-pair (digram) chi-square over non-overlapping pairs, 65536 bins. Catches
/// 2nd-order structure that a 1st-order byte histogram misses.
fn digram_chi_square(block: &[u8]) -> f64 {
    let mut counts = vec![0u64; 65536];
    let pairs = block.len() / 2;
    for j in 0..pairs {
        let idx = ((block[2 * j] as usize) << 8) | (block[2 * j + 1] as usize);
        counts[idx] += 1;
    }
    let expected = pairs as f64 / 65536.0;
    counts
        .iter()
        .map(|&o| {
            let d = o as f64 - expected;
            d * d / expected
        })
        .sum()
}

/// Lag-1 serial correlation of byte values. ~0 for independent bytes; a non-zero
/// value reveals linear inter-byte structure.
fn serial_correlation(block: &[u8]) -> f64 {
    let n = block.len();
    let mean = block.iter().map(|&b| b as f64).sum::<f64>() / n as f64;
    let mut num = 0.0;
    let mut den = 0.0;
    for i in 0..n {
        let a = block[i] as f64 - mean;
        let b = block[(i + 1) % n] as f64 - mean;
        num += a * b;
        den += a * a;
    }
    num / den
}

const REC: KdfParams = KdfParams::RECOMMENDED;
const FAST: KdfParams = KdfParams::INSECURE_FAST_TEST;

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
// Pinned wire-format vectors (FNV-1a of the block) under KdfParams::RECOMMENDED, one per cipher.
// The SHAKE256 value is UNCHANGED from azoth's original single-cipher format (its cipher tag is
// empty, so the token/MAC/keystream derivation is byte-identical) — proving the cipher work did
// not perturb that path. Update a value ONLY on an intentional wire-format change for that cipher.
const KAT_FNV_AES256CTR: u64 = 0xd61dda5b3299391e;
const KAT_FNV_CHACHA20: u64 = 0xa3b6600350515b5e;
const KAT_FNV_SHAKE256: u64 = 0xeabe2c5067fdcf54;

fn kat_one(cipher: Cipher, expect_fnv: u64) {
    // Start from an all-zero block so the output is fully determined by the inputs.
    let mut c = Kpdc::from_bytes_with(vec![0u8; KAT_BLOCK_LEN], KAT_K, REC, cipher).unwrap();
    let plane = c
        .write(KAT_PW, KAT_PT, &[], KAT_MP, Some(&KAT_SALT))
        .unwrap();
    let got = fnv1a(c.as_bytes());
    eprintln!("KAT {cipher:?}: plane={plane} fnv=0x{got:016x}");
    if expect_fnv != 0 {
        assert_eq!(
            got, expect_fnv,
            "KAT MISMATCH for {cipher:?}: wire format changed (fnv=0x{got:016x}). \
             If intentional, update the pinned value."
        );
    }
    // And it reads back under that cipher.
    assert_eq!(
        c.read(KAT_PW, KAT_MP).map(|z| z.to_vec()),
        Some(KAT_PT.to_vec())
    );
}

#[test]
fn known_answer_write_and_read() {
    kat_one(Cipher::Aes256Ctr, KAT_FNV_AES256CTR);
    kat_one(Cipher::ChaCha20, KAT_FNV_CHACHA20);
    kat_one(Cipher::Shake256, KAT_FNV_SHAKE256);
    // The three ciphers must produce DIFFERENT containers from identical (pw, K, KDF, salt,
    // plaintext) — proof the cipher genuinely changes the keystream and the cipher-bound token/MAC.
    let fnvs = [KAT_FNV_AES256CTR, KAT_FNV_CHACHA20, KAT_FNV_SHAKE256];
    for i in 0..fnvs.len() {
        for j in (i + 1)..fnvs.len() {
            assert_ne!(
                fnvs[i], fnvs[j],
                "two ciphers produced identical KAT blocks"
            );
        }
    }
}

// =========================================================================== //
//  Expanded indistinguishability suite — confirm that WRITES never push the
//  container off the statistical norm (1st-order, 2nd-order, runs, serial corr),
//  across heavy fill and multiple sizes / K. A deviation here would signal a
//  cryptographic bug (the right response is to fix the primitive, never to
//  "flatten" the histogram — perfect flatness is itself a detectable signature).
// =========================================================================== //

#[test]
fn heavily_filled_container_stays_uniform() {
    // Pack ~one large payload per plane (close to capacity), then check the block is still uniform
    // in byte value, bit density, and runs. Here the keystream is the MAJORITY of the bits, so this
    // is the test with real statistical power over the cipher — run it for EVERY cipher so the
    // AES-CTR, ChaCha20, and SHAKE256 keystreams are each exercised against the battery (not just
    // the default). A cipher-specific structural artifact would surface here.
    for cipher in [Cipher::Aes256Ctr, Cipher::ChaCha20, Cipher::Shake256] {
        let k = next_prime_coprime8(17);
        let mp = k as usize;
        let seed = format!("heavy-fill-{cipher:?}");
        let mut c =
            Kpdc::from_bytes_with(shake_fill(65_536, seed.as_bytes()), k, FAST, cipher).unwrap();
        let mut known: Vec<String> = Vec::new();
        let mut placed = 0usize;
        while placed < k as usize {
            let pw = format!("p{placed}");
            let kr: Vec<&str> = known.iter().map(|s| s.as_str()).collect();
            match c.write(&pw, &vec![0xABu8; 3500], &kr, mp, None) {
                Ok(_) => {
                    known.push(pw);
                    placed += 1;
                }
                Err(_) => break,
            }
        }
        assert!(
            placed >= 12,
            "{cipher:?}: expected to pack many payloads, only placed {placed}"
        );

        let block = c.as_bytes();
        let nbits = (block.len() * 8) as f64;
        let chi = chi_square_bytes(block);
        let ones = ones_fraction(block);
        let t = bit_transitions(block) as f64;
        assert!(
            chi > 120.0 && chi < 420.0,
            "{cipher:?}: heavy-fill byte chi {chi}"
        );
        assert!(
            (ones - 0.5).abs() < 0.01,
            "{cipher:?}: heavy-fill bit density {ones}"
        );
        let exp_t = (nbits - 1.0) / 2.0;
        assert!(
            (t - exp_t).abs() < 3.0 * nbits.sqrt(),
            "{cipher:?}: heavy-fill runs {t} vs expected {exp_t}"
        );
    }
}

#[test]
fn second_order_structure_absent() {
    // 512 KiB block + several payloads: digram (byte-pair) chi-square and lag-1
    // serial correlation must look like independent uniform bytes.
    let k = next_prime_coprime8(131);
    let mut c = Kpdc::from_bytes(shake_fill(524_288, b"digram-seed"), k, FAST).unwrap();
    let mut known: Vec<String> = Vec::new();
    for i in 0..10 {
        let kr: Vec<&str> = known.iter().map(|s| s.as_str()).collect();
        c.write(&format!("d{i}"), &vec![0x5Au8; 3500], &kr, 12, None)
            .unwrap();
        known.push(format!("d{i}"));
    }
    let block = c.as_bytes();
    // 65535 d.o.f.: mean 65535, sd ~362. Generous +/-4000 (~11 sd) catches structure
    // without flaking. (A perfectly "flattened" block would instead drive the 1st-order
    // chi-square to ~0, which the uniformity tests above reject.)
    let dchi = digram_chi_square(block);
    assert!(
        (dchi - 65_535.0).abs() < 4000.0,
        "digram chi {dchi} out of band"
    );
    let r = serial_correlation(block);
    assert!(r.abs() < 0.02, "serial correlation {r} too high");
}

#[test]
fn uniform_across_sizes_and_k() {
    for (sz, kbase) in [(16_384usize, 11u64), (49_152, 53), (131_072, 257)] {
        let k = next_prime_coprime8(kbase);
        let seed = format!("size-{sz}-k-{k}");
        let mut c = Kpdc::from_bytes(shake_fill(sz, seed.as_bytes()), k, FAST).unwrap();
        let mut known: Vec<String> = Vec::new();
        for i in 0..5 {
            let kr: Vec<&str> = known.iter().map(|s| s.as_str()).collect();
            let _ = c.write(&format!("s{i}"), &[0x33u8; 64], &kr, 4, None);
            known.push(format!("s{i}"));
        }
        let block = c.as_bytes();
        let chi = chi_square_bytes(block);
        let ones = ones_fraction(block);
        assert!(
            chi > 120.0 && chi < 420.0,
            "size {sz} k {k}: byte chi {chi}"
        );
        assert!(
            (ones - 0.5).abs() < 0.015,
            "size {sz} k {k}: bit density {ones}"
        );
    }
}
