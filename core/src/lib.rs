//! # azoth — K-Plane Deniable Container (KPDC)
//!
//! A fixed-size block of random-looking bytes that holds up to `K` independent
//! encrypted payloads. Without the correct `(password, K)` the block is
//! computationally indistinguishable from random data: no header, no index, no
//! count. Different passwords decrypt to completely different plaintexts.
//!
//! This is the performant Rust implementation, faithful to spec v0.3 with
//! security/quality upgrades over the Python reference (`kpdc_reference.py`):
//!   * **Argon2id** memory-hard KDF with configurable, credential-bound cost;
//!   * **rejection sampling** for slot selection (no modulo bias);
//!   * **constant-time** token/tag comparison;
//!   * **zeroization** of derived key material.
//!
//! ## Container format is NOT interoperable with the Python reference.
//! The two use different slot walks (Rust: rejection-sampled XOF stream;
//! Python: counter-mode modulo) and different KDFs (Argon2id vs scrypt). A
//! container written by one cannot be read by the other. The Python file is a
//! readable spec mirror, not a wire-compatible implementation.
//!
//! Pinned primitives: Argon2id (KDF), SHAKE256 (XOF/PRF), SHA-256 (fast hash),
//! HMAC-SHA256 (integrity).
//!
//! **Experimental — not security audited. v1 = single-snapshot deniability only.**

#![forbid(unsafe_code)]

/// High-level create/write/read orchestration shared by all front-ends (CLI + GUI).
pub mod app;

use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::collections::HashSet;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// ---- field sizes (bits) ----
const S_BITS: usize = 128; // per-write salt (nonce)
const T_BITS: usize = 128; // recognition token (fast plane reject)
const LEN_BITS: usize = 32; // payload length field
const TAG_BITS: usize = 256; // HMAC-SHA256 integrity tag
const HEAD_BITS: usize = S_BITS + T_BITS + LEN_BITS;

/// Default open-addressing probe bound for reads.
pub const DEFAULT_MAXPROBE: usize = 64;

/// Memory-hard KDF cost. **Part of the credential** — read and write must use
/// the same params (like `K`), since nothing is stored in the block.
#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    pub mem_kib: u32,
    pub iters: u32,
    pub lanes: u32,
}

impl KdfParams {
    /// Recommended production cost (256 MiB, 3 passes). The default. Deliberately
    /// heavy to make offline brute force of the verification oracle impractical.
    pub const RECOMMENDED: KdfParams = KdfParams {
        mem_kib: 262_144,
        iters: 3,
        lanes: 1,
    };
    /// Low cost for high-volume statistical/fuzz tests ONLY (output distribution and
    /// panic-safety are independent of KDF cost). Never use for real data.
    pub const FAST_TEST: KdfParams = KdfParams {
        mem_kib: 8_192,
        iters: 1,
        lanes: 1,
    };
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams::RECOMMENDED
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidK { k: u64, nbits: u64 },
    ContainerFull,
    PayloadTooLarge { need_bits: u64, plane_bits: u64 },
    PayloadTooLong { len: usize },
    BadSaltLen { got: usize, expected: usize },
    Rng,
    Kdf,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidK { k, nbits } => write!(
                f,
                "invalid K={}: must satisfy 2 <= K <= block bit-count ({})",
                k, nbits
            ),
            Error::ContainerFull => write!(f, "container full: no free plane within probe bound"),
            Error::PayloadTooLarge {
                need_bits,
                plane_bits,
            } => write!(
                f,
                "payload too large: needs {} bits but plane holds {} (raise block size or lower K)",
                need_bits, plane_bits
            ),
            Error::PayloadTooLong { len } => {
                write!(
                    f,
                    "payload length {} exceeds u32 length field (max ~4 GiB)",
                    len
                )
            }
            Error::BadSaltLen { got, expected } => {
                write!(f, "salt must be exactly {} bytes, got {}", expected, got)
            }
            Error::Rng => write!(f, "failed to gather randomness"),
            Error::Kdf => write!(f, "KDF (Argon2id) failure — check parameters"),
        }
    }
}
impl std::error::Error for Error {}

// ---- primitive wrappers ----
fn shake(parts: &[&[u8]], n: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut reader = h.finalize_xof();
    let mut out = vec![0u8; n];
    reader.read(&mut out);
    out
}

fn sha256_cat(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

type HmacSha256 = Hmac<Sha256>;
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    Mac::update(&mut m, msg);
    m.finalize().into_bytes().into()
}

/// Validate KDF params up front so `argon2_kdf` can't fail mid-read (which would
/// otherwise be indistinguishable from a wrong password).
fn validate_kdf(p: KdfParams) -> Result<(), Error> {
    Params::new(p.mem_kib, p.iters, p.lanes, Some(32))
        .map(|_| ())
        .map_err(|_| Error::Kdf)
}

/// Argon2id over `pw || K_be64` with the given cost. Output is zeroized on drop.
/// Params are validated at container construction, so this is infallible here.
fn argon2_kdf(pw: &[u8], k: u64, salt: &[u8], p: KdfParams) -> Zeroizing<[u8; 32]> {
    let mut input = Zeroizing::new(Vec::with_capacity(pw.len() + 8));
    input.extend_from_slice(pw);
    input.extend_from_slice(&k.to_be_bytes());
    let params = Params::new(p.mem_kib, p.iters, p.lanes, Some(32))
        .expect("KDF params validated at construction");
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(&input, salt, &mut *out)
        .expect("argon2id hash");
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

// ---- bit / byte helpers (LSB-first within each byte) ----
fn bytes_to_bits(bs: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(bs.len() * 8);
    for &b in bs {
        for i in 0..8 {
            v.push((b >> i) & 1);
        }
    }
    v
}
fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, &b) in bits.iter().enumerate() {
        if b != 0 {
            out[i >> 3] |= 1 << (i & 7);
        }
    }
    out
}
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

/// Smallest prime >= n that is coprime to 8 (any odd prime qualifies).
pub fn next_prime_coprime8(n: u64) -> u64 {
    let mut c = std::cmp::max(3, n | 1); // force odd
    while !is_prime(c) {
        c = match c.checked_add(2) {
            Some(v) => v,
            None => return c, // saturate near u64::MAX rather than wrap/panic
        };
    }
    c
}

/// Whether `k` is a recommended plane count: an odd prime (so prime and coprime to 8).
pub fn is_recommended_k(k: u64) -> bool {
    k > 2 && k % 2 == 1 && is_prime(k)
}

fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n.is_multiple_of(2) {
        return n == 2;
    }
    let mut i = 3u64;
    while i <= n / i {
        // `i <= n / i` instead of `i * i <= n` to avoid overflow near u64::MAX
        if n.is_multiple_of(i) {
            return false;
        }
        i += 2;
    }
    true
}

/// A resumable, distinct-slot pseudo-random walk inside one plane.
/// SHAKE-driven XOF stream with rejection sampling (no modulo bias). Holding the
/// reader lets the read path extend the walk instead of recomputing it.
struct SlotWalk {
    reader: Box<dyn XofReader>,
    out: Vec<u64>,
    seen: HashSet<u64>,
    m: u64,
    zone: u64,
}

impl SlotWalk {
    fn new(prk: &[u8; 32], plane: u64, m: u64) -> Self {
        let mut h = Shake256::default();
        h.update(prk);
        h.update(b"slots");
        h.update(&plane.to_be_bytes());
        SlotWalk {
            reader: Box::new(h.finalize_xof()),
            out: Vec::new(),
            seen: HashSet::new(),
            m,
            zone: (u64::MAX / m) * m, // unbiased rejection threshold
        }
    }

    /// Ensure at least `count` distinct slot indices have been produced.
    fn ensure(&mut self, count: usize) {
        let mut buf = [0u8; 8];
        while self.out.len() < count {
            self.reader.read(&mut buf);
            let x = u64::from_be_bytes(buf);
            if x >= self.zone {
                continue;
            }
            let v = x % self.m;
            if self.seen.insert(v) {
                self.out.push(v);
            }
        }
    }
}

/// A K-plane deniable container backed by a mutable byte block.
pub struct Kpdc {
    block: Vec<u8>,
    k: u64,
    kdf: KdfParams,
}

impl Kpdc {
    /// Wrap an existing block (e.g. read from disk) with its credential params.
    pub fn from_bytes(block: Vec<u8>, k: u64, kdf: KdfParams) -> Result<Self, Error> {
        let nbits = (block.len() as u64) * 8;
        if k < 2 || k > nbits {
            return Err(Error::InvalidK { k, nbits });
        }
        validate_kdf(kdf)?;
        Ok(Kpdc { block, k, kdf })
    }

    /// Create a fresh container = `size` random bytes (indistinguishable from any full one).
    pub fn create(size: usize, k: u64, kdf: KdfParams) -> Result<Self, Error> {
        let nbits = (size as u64) * 8;
        if k < 2 || k > nbits {
            return Err(Error::InvalidK { k, nbits });
        }
        validate_kdf(kdf)?;
        let mut block = vec![0u8; size];
        getrandom::getrandom(&mut block).map_err(|_| Error::Rng)?;
        Ok(Kpdc { block, k, kdf })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.block
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.block
    }
    pub fn k(&self) -> u64 {
        self.k
    }

    fn nbits(&self) -> u64 {
        (self.block.len() as u64) * 8
    }

    // plane p owns global bit-indices g with g % K == p
    fn plane_slots(&self, p: u64) -> u64 {
        (self.nbits() - 1 - p) / self.k + 1
    }
    #[inline]
    fn global(&self, slot: u64, plane: u64) -> u64 {
        slot * self.k + plane
    }
    #[inline]
    fn get_bit(&self, g: u64) -> u8 {
        (self.block[(g >> 3) as usize] >> (g & 7)) & 1
    }
    #[inline]
    fn set_bit(&mut self, g: u64, b: u8) {
        let idx = (g >> 3) as usize;
        if b != 0 {
            self.block[idx] |= 1 << (g & 7);
        } else {
            self.block[idx] &= !(1 << (g & 7));
        }
    }

    // ---- derivations ----
    fn prk(&self, pw: &str) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(sha256_cat(&[pw.as_bytes(), &self.k.to_be_bytes()]))
    }

    /// Home plane via unbiased rejection sampling over a SHAKE stream.
    fn home(&self, prk: &[u8; 32]) -> u64 {
        let mut h = Shake256::default();
        h.update(prk);
        h.update(b"home");
        let mut reader = h.finalize_xof();
        let zone = (u64::MAX / self.k) * self.k;
        let mut buf = [0u8; 8];
        loop {
            reader.read(&mut buf);
            let x = u64::from_be_bytes(buf);
            if x < zone {
                return x % self.k;
            }
        }
    }
    fn smask(&self, prk: &[u8; 32]) -> Vec<u8> {
        shake(&[prk, b"saltmask"], S_BITS / 8)
    }

    // ---- read side ----
    fn locate(&self, pw: &str, maxprobe: usize) -> Option<(u64, Zeroizing<Vec<u8>>)> {
        let prk = self.prk(pw);
        let home = self.home(&prk);
        let smask = self.smask(&prk);

        for i in 0..maxprobe.min(self.k as usize) {
            let plane = (home + i as u64) % self.k;
            if (HEAD_BITS as u64) > self.plane_slots(plane) {
                continue;
            }
            let mut walk = SlotWalk::new(&prk, plane, self.plane_slots(plane));
            walk.ensure(HEAD_BITS);
            let head: Vec<u8> = (0..HEAD_BITS)
                .map(|j| self.get_bit(self.global(walk.out[j], plane)))
                .collect();

            let salt = xor(&bits_to_bytes(&head[0..S_BITS]), &smask);
            let mk = argon2_kdf(pw.as_bytes(), self.k, &salt, self.kdf);

            let token = shake(&[&*mk, b"token"], T_BITS / 8);
            let stored_token = bits_to_bytes(&head[S_BITS..S_BITS + T_BITS]);
            if !ct_eq(&token, &stored_token) {
                continue; // fast reject (constant-time)
            }

            let lenmask = shake(&[&*mk, b"len"], LEN_BITS / 8);
            let len_field = bits_to_bytes(&head[S_BITS + T_BITS..HEAD_BITS]);
            let l = u32::from_be_bytes(xor(&len_field, &lenmask).try_into().unwrap()) as u64;

            // u64 math avoids overflow on 32-bit targets; bound-check before use.
            let total = HEAD_BITS as u64 + 8 * l + TAG_BITS as u64;
            if total > self.plane_slots(plane) {
                continue;
            }
            let total = total as usize;
            let l = l as usize;
            walk.ensure(total);
            let ct_bits: Vec<u8> = (HEAD_BITS..HEAD_BITS + 8 * l)
                .map(|j| self.get_bit(self.global(walk.out[j], plane)))
                .collect();
            let tag_bits: Vec<u8> = (HEAD_BITS + 8 * l..total)
                .map(|j| self.get_bit(self.global(walk.out[j], plane)))
                .collect();
            let ct = bits_to_bytes(&ct_bits);
            let tag = bits_to_bytes(&tag_bits);

            let mackey = Zeroizing::new(shake(&[&*mk, b"mac"], 32));
            if !ct_eq(&hmac_sha256(&mackey, &ct), &tag) {
                continue; // tampered or rare false token match
            }
            let stream = Zeroizing::new(shake(&[&*mk, b"stream"], l));
            return Some((plane, Zeroizing::new(xor(&ct, &stream))));
        }
        None
    }

    /// Decrypt the payload for `pw`, or `None` (wrong credential / not present).
    /// The returned plaintext is zeroized on drop.
    pub fn read(&self, pw: &str, maxprobe: usize) -> Option<Zeroizing<Vec<u8>>> {
        self.locate(pw, maxprobe).map(|(_, pt)| pt)
    }

    /// The plane index holding `pw`'s payload, or `None`.
    pub fn plane_of(&self, pw: &str, maxprobe: usize) -> Option<u64> {
        self.locate(pw, maxprobe).map(|(p, _)| p)
    }

    // ---- write side ----
    /// Write `plaintext` under `pw`. Pass every *other* known password in
    /// `known_pws` so their planes are avoided (L4: all-keys-to-add). Reuses
    /// `pw`'s own plane if it already holds a payload. Returns the plane used.
    pub fn write(
        &mut self,
        pw: &str,
        plaintext: &[u8],
        known_pws: &[&str],
        maxprobe: usize,
        salt: Option<&[u8]>,
    ) -> Result<u64, Error> {
        if plaintext.len() as u64 > u32::MAX as u64 {
            return Err(Error::PayloadTooLong {
                len: plaintext.len(),
            });
        }
        if let Some(s) = salt {
            if s.len() != S_BITS / 8 {
                return Err(Error::BadSaltLen {
                    got: s.len(),
                    expected: S_BITS / 8,
                });
            }
        }
        let prk = self.prk(pw);

        let plane = match self.plane_of(pw, maxprobe) {
            Some(p) => p,
            None => {
                let home = self.home(&prk);
                let mut occupied = HashSet::new();
                for q in known_pws {
                    if let Some(p) = self.plane_of(q, maxprobe) {
                        occupied.insert(p);
                    }
                }
                // Search only the window the reader will probe — placing a payload
                // beyond min(maxprobe, K) would make it unreadable (silent loss).
                let mut chosen = None;
                for i in 0..(maxprobe as u64).min(self.k) {
                    let cand = (home + i) % self.k;
                    if !occupied.contains(&cand) {
                        chosen = Some(cand);
                        break;
                    }
                }
                chosen.ok_or(Error::ContainerFull)?
            }
        };

        let total = (HEAD_BITS + 8 * plaintext.len() + TAG_BITS) as u64;
        let cap = self.plane_slots(plane);
        if total > cap {
            return Err(Error::PayloadTooLarge {
                need_bits: total,
                plane_bits: cap,
            });
        }

        let mut salt_buf = [0u8; S_BITS / 8];
        let salt = match salt {
            Some(s) => s.to_vec(), // length already validated above
            None => {
                getrandom::getrandom(&mut salt_buf).map_err(|_| Error::Rng)?;
                salt_buf.to_vec()
            }
        };

        let smask = self.smask(&prk);
        let mk = argon2_kdf(pw.as_bytes(), self.k, &salt, self.kdf);
        let token = shake(&[&*mk, b"token"], T_BITS / 8);
        let lenmask = shake(&[&*mk, b"len"], LEN_BITS / 8);
        let stream = Zeroizing::new(shake(&[&*mk, b"stream"], plaintext.len()));
        let mackey = Zeroizing::new(shake(&[&*mk, b"mac"], 32));

        let ct = xor(plaintext, &stream);
        let tag = hmac_sha256(&mackey, &ct);
        let len_field = xor(&(plaintext.len() as u32).to_be_bytes(), &lenmask);
        let salt_field = xor(&salt, &smask);

        let mut bits = Vec::with_capacity(total as usize);
        bits.extend(bytes_to_bits(&salt_field));
        bits.extend(bytes_to_bits(&token));
        bits.extend(bytes_to_bits(&len_field));
        bits.extend(bytes_to_bits(&ct));
        bits.extend(bytes_to_bits(&tag));

        let mut walk = SlotWalk::new(&prk, plane, self.plane_slots(plane));
        walk.ensure(bits.len());
        for (j, &bit) in bits.iter().enumerate() {
            let g = self.global(walk.out[j], plane);
            self.set_bit(g, bit);
        }
        Ok(plane)
    }

    /// Re-randomize the **entire** container: discard the current block, fill a fresh
    /// random one, and re-write every supplied payload with new salts. Because every
    /// bit changes on every write, this defeats multi-snapshot diffing (an adversary
    /// who images the block before and after cannot localize changes or learn `K`).
    ///
    /// You MUST pass every payload the container should retain — anything omitted is
    /// permanently gone. The rebuild is atomic: on any error the original block is
    /// left untouched.
    pub fn write_all_fresh(
        &mut self,
        payloads: &[(&str, &[u8])],
        maxprobe: usize,
    ) -> Result<(), Error> {
        let mut fresh = vec![0u8; self.block.len()];
        getrandom::getrandom(&mut fresh).map_err(|_| Error::Rng)?;
        let mut tmp = Kpdc {
            block: fresh,
            k: self.k,
            kdf: self.kdf,
        };
        for i in 0..payloads.len() {
            let (pw, pt) = payloads[i];
            let known: Vec<&str> = payloads[..i].iter().map(|(p, _)| *p).collect();
            tmp.write(pw, pt, &known, maxprobe, None)?; // tmp dropped on error -> self unchanged
        }
        self.block = tmp.block;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Headline functional tests run at the REAL recommended cost (small K/maxprobe
    // keep the Argon2 call count low so they finish in a few seconds each).
    const REC: KdfParams = KdfParams::RECOMMENDED;
    // FAST_TEST is used only where a test needs many KDF evals and the property under
    // test (logic/invariants) is independent of KDF cost.
    const FAST: KdfParams = KdfParams::FAST_TEST;
    const MP: usize = 2;
    const K: u64 = 11;
    const SZ: usize = 8192;

    #[test]
    fn next_prime_coprime8_works() {
        assert_eq!(next_prime_coprime8(419), 419);
        assert_eq!(next_prime_coprime8(420), 421);
        assert_eq!(next_prime_coprime8(2), 3);
        assert!(is_recommended_k(419));
        assert!(!is_recommended_k(8));
        assert!(!is_recommended_k(2));
    }

    #[test]
    fn invalid_k_is_rejected_not_panic() {
        assert!(matches!(
            Kpdc::create(1024, 0, FAST),
            Err(Error::InvalidK { .. })
        ));
        assert!(matches!(
            Kpdc::create(1024, 1, FAST),
            Err(Error::InvalidK { .. })
        ));
        // K larger than the bit-count is also rejected (would underflow plane math)
        assert!(matches!(
            Kpdc::create(2, 100, FAST),
            Err(Error::InvalidK { .. })
        ));
    }

    #[test]
    fn roundtrip_two_payloads_recommended_cost() {
        let mut c = Kpdc::create(SZ, K, REC).unwrap();
        let pa = c
            .write("alpha-pass", b"treaty at dawn", &[], MP, None)
            .unwrap();
        let pb = c
            .write("beta-pass", b"pier 39", &["alpha-pass"], MP, None)
            .unwrap();
        assert_ne!(pa, pb);
        assert_eq!(
            c.read("alpha-pass", MP).map(|z| z.to_vec()),
            Some(b"treaty at dawn".to_vec())
        );
        assert_eq!(
            c.read("beta-pass", MP).map(|z| z.to_vec()),
            Some(b"pier 39".to_vec())
        );
        assert!(c.read("wrong-pass", MP).is_none());
    }

    #[test]
    fn empty_payload_roundtrips() {
        let mut c = Kpdc::create(SZ, K, REC).unwrap();
        c.write("pw", b"", &[], MP, None).unwrap();
        assert_eq!(c.read("pw", MP).map(|z| z.to_vec()), Some(Vec::new()));
    }

    #[test]
    fn tamper_is_detected() {
        let mut c = Kpdc::create(SZ, K, REC).unwrap();
        c.write("pw", b"secret message here", &[], MP, None)
            .unwrap();
        let mut bytes = c.into_bytes();
        bytes[100] ^= 0xFF;
        let c2 = Kpdc::from_bytes(bytes, K, REC).unwrap();
        // either still reads (if flip missed this plane) or None — never wrong plaintext
        if let Some(pt) = c2.read("pw", MP) {
            assert_eq!(pt.as_slice(), b"secret message here");
        }
    }

    #[test]
    fn wrong_salt_length_is_rejected() {
        let mut c = Kpdc::create(SZ, K, REC).unwrap();
        assert!(matches!(
            c.write("pw", b"hi", &[], MP, Some(&[0u8; 8])),
            Err(Error::BadSaltLen { .. })
        ));
        assert!(c.write("pw", b"hi", &[], MP, Some(&[0u8; 16])).is_ok());
    }

    #[test]
    fn rerandomize_roundtrips() {
        let mut c = Kpdc::create(SZ, K, REC).unwrap();
        c.write_all_fresh(&[("a", b"alpha"), ("b", b"bravo")], MP)
            .unwrap();
        assert_eq!(c.read("a", MP).map(|z| z.to_vec()), Some(b"alpha".to_vec()));
        assert_eq!(c.read("b", MP).map(|z| z.to_vec()), Some(b"bravo".to_vec()));
        assert!(c.read("c", MP).is_none());
    }

    #[test]
    fn write_success_implies_readable_at_same_maxprobe() {
        // Regression (logic invariant — uses FAST cost, runs many writes): a successful
        // write must never place a payload beyond the reader's probe window.
        let k = next_prime_coprime8(17);
        let mp = 3;
        let mut c = Kpdc::create(16384, k, FAST).unwrap();
        let pws = ["a", "b", "c", "d", "e", "f"];
        let mut written = Vec::new();
        for (i, pw) in pws.iter().enumerate() {
            let known: Vec<&str> = pws[..i].to_vec();
            let msg = format!("msg-{}", i);
            if c.write(pw, msg.as_bytes(), &known, mp, None).is_ok() {
                written.push((*pw, msg));
            }
        }
        for (pw, msg) in written {
            assert_eq!(
                c.read(pw, mp).map(|z| z.to_vec()),
                Some(msg.into_bytes()),
                "payload written under {:?} not readable at the same maxprobe",
                pw
            );
        }
    }
}
