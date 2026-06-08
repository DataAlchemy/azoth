//! # azoth — K-Plane Deniable Container (KPDC)
//!
//! A fixed-size block of random-looking bytes that holds up to `K` independent
//! encrypted payloads. Without the correct `(password, K)` the block is
//! computationally indistinguishable from random data: no header, no index, no
//! count. Different passwords decrypt to completely different plaintexts.
//!
//! This is the performant Rust port of the Python reference (`kpdc_reference.py`),
//! faithful to spec v0.3 with two upgrades:
//!   * **rejection sampling** for slot selection (removes the reference's modulo bias);
//!   * compiled bit-walking instead of per-bit Python object overhead.
//!
//! Pinned primitives: scrypt (memory-hard KDF), SHAKE256 (XOF/PRF), SHA-256
//! (fast hash), HMAC-SHA256 (integrity).
//!
//! **Experimental — not security audited. v1 = single-snapshot deniability only.**

use hmac::{Hmac, Mac};
use scrypt::{scrypt, Params};
use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::collections::HashSet;

// ---- field sizes (bits) ----
const S_BITS: usize = 128; // per-write salt (nonce)
const T_BITS: usize = 128; // recognition token (fast plane reject)
const LEN_BITS: usize = 32; // payload length field
const TAG_BITS: usize = 256; // HMAC-SHA256 integrity tag
const HEAD_BITS: usize = S_BITS + T_BITS + LEN_BITS;

/// Default open-addressing probe bound for reads.
pub const DEFAULT_MAXPROBE: usize = 64;

// ---- scrypt cost (raise N for real use) ----
const SCRYPT_LOG_N: u8 = 13; // N = 2^13
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

#[derive(Debug)]
pub enum Error {
    ContainerFull,
    PayloadTooLarge { need_bits: u64, plane_bits: u64 },
    Rng,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ContainerFull => write!(f, "container full: no free plane within probe bound"),
            Error::PayloadTooLarge { need_bits, plane_bits } => write!(
                f,
                "payload too large: needs {} bits but plane holds {} (raise block size or lower K)",
                need_bits, plane_bits
            ),
            Error::Rng => write!(f, "failed to gather randomness"),
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
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    Mac::update(&mut m, msg);
    m.finalize().into_bytes().into()
}

fn scrypt_kdf(pw: &[u8], k: u64, salt: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(pw.len() + 8);
    input.extend_from_slice(pw);
    input.extend_from_slice(&k.to_be_bytes());
    let params = Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32).expect("scrypt params");
    let mut out = [0u8; 32];
    scrypt(&input, salt, &params, &mut out).expect("scrypt");
    out
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
    let mut out = vec![0u8; (bits.len() + 7) / 8];
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
        c += 2;
    }
    c
}
fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n % 2 == 0 {
        return n == 2;
    }
    let mut i = 3u64;
    while i * i <= n {
        if n % i == 0 {
            return false;
        }
        i += 2;
    }
    true
}

/// A K-plane deniable container backed by a mutable byte block.
pub struct Kpdc {
    block: Vec<u8>,
    k: u64,
}

impl Kpdc {
    /// Wrap an existing block (e.g. read from disk) with its plane count.
    pub fn from_bytes(block: Vec<u8>, k: u64) -> Self {
        Kpdc { block, k }
    }

    /// Create a fresh container = `size` random bytes (indistinguishable from any full one).
    pub fn create(size: usize, k: u64) -> Result<Self, Error> {
        let mut block = vec![0u8; size];
        getrandom::getrandom(&mut block).map_err(|_| Error::Rng)?;
        Ok(Kpdc { block, k })
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
    fn prk(&self, pw: &str) -> [u8; 32] {
        sha256_cat(&[pw.as_bytes(), &self.k.to_be_bytes()])
    }
    fn home(&self, prk: &[u8; 32]) -> u64 {
        let h = shake(&[prk, b"home"], 8);
        u64::from_be_bytes(h.try_into().unwrap()) % self.k
    }
    fn smask(&self, prk: &[u8; 32]) -> Vec<u8> {
        shake(&[prk, b"saltmask"], S_BITS / 8)
    }

    /// `count` distinct slot indices in [0, M_p), SHAKE-driven with rejection sampling.
    fn slot_seq(&self, prk: &[u8; 32], plane: u64, count: usize) -> Vec<u64> {
        let m = self.plane_slots(plane);
        let mut h = Shake256::default();
        h.update(prk);
        h.update(b"slots");
        h.update(&plane.to_be_bytes());
        let mut reader = h.finalize_xof();

        let zone = (u64::MAX / m) * m; // unbiased rejection threshold
        let mut seen = HashSet::with_capacity(count * 2);
        let mut out = Vec::with_capacity(count);
        let mut buf = [0u8; 8];
        while out.len() < count {
            reader.read(&mut buf);
            let x = u64::from_be_bytes(buf);
            if x >= zone {
                continue;
            }
            let v = x % m;
            if seen.insert(v) {
                out.push(v);
            }
        }
        out
    }

    // ---- read side ----
    fn locate(&self, pw: &str, maxprobe: usize) -> Option<(u64, Vec<u8>)> {
        let prk = self.prk(pw);
        let home = self.home(&prk);
        let smask = self.smask(&prk);

        for i in 0..maxprobe.min(self.k as usize) {
            let plane = (home + i as u64) % self.k;
            if (HEAD_BITS as u64) > self.plane_slots(plane) {
                continue;
            }
            let seq = self.slot_seq(&prk, plane, HEAD_BITS);
            let head: Vec<u8> = (0..HEAD_BITS)
                .map(|j| self.get_bit(self.global(seq[j], plane)))
                .collect();

            let salt = xor(&bits_to_bytes(&head[0..S_BITS]), &smask);
            let mk = scrypt_kdf(pw.as_bytes(), self.k, &salt);

            let token = shake(&[&mk, b"token"], T_BITS / 8);
            let stored_token = bits_to_bytes(&head[S_BITS..S_BITS + T_BITS]);
            if token != stored_token {
                continue; // fast reject
            }

            let lenmask = shake(&[&mk, b"len"], LEN_BITS / 8);
            let len_field = bits_to_bytes(&head[S_BITS + T_BITS..HEAD_BITS]);
            let l = u32::from_be_bytes(xor(&len_field, &lenmask).try_into().unwrap()) as usize;

            let total = HEAD_BITS + 8 * l + TAG_BITS;
            if (total as u64) > self.plane_slots(plane) {
                continue;
            }
            let seq = self.slot_seq(&prk, plane, total);
            let ct_bits: Vec<u8> = (HEAD_BITS..HEAD_BITS + 8 * l)
                .map(|j| self.get_bit(self.global(seq[j], plane)))
                .collect();
            let tag_bits: Vec<u8> = (HEAD_BITS + 8 * l..total)
                .map(|j| self.get_bit(self.global(seq[j], plane)))
                .collect();
            let ct = bits_to_bytes(&ct_bits);
            let tag = bits_to_bytes(&tag_bits);

            let mackey = shake(&[&mk, b"mac"], 32);
            if hmac_sha256(&mackey, &ct).as_slice() != tag.as_slice() {
                continue; // tampered or rare false token match
            }
            let stream = shake(&[&mk, b"stream"], l);
            return Some((plane, xor(&ct, &stream)));
        }
        None
    }

    /// Decrypt the payload for `pw`, or `None` (wrong credential / not present).
    pub fn read(&self, pw: &str, maxprobe: usize) -> Option<Vec<u8>> {
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
        let prk = self.prk(pw);
        let home = self.home(&prk);

        let plane = match self.plane_of(pw, maxprobe) {
            Some(p) => p,
            None => {
                let mut occupied = HashSet::new();
                for q in known_pws {
                    if let Some(p) = self.plane_of(q, maxprobe) {
                        occupied.insert(p);
                    }
                }
                let mut chosen = None;
                for i in 0..self.k {
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
            return Err(Error::PayloadTooLarge { need_bits: total, plane_bits: cap });
        }

        let mut salt_buf = [0u8; S_BITS / 8];
        let salt = match salt {
            Some(s) => s.to_vec(),
            None => {
                getrandom::getrandom(&mut salt_buf).map_err(|_| Error::Rng)?;
                salt_buf.to_vec()
            }
        };

        let smask = self.smask(&prk);
        let mk = scrypt_kdf(pw.as_bytes(), self.k, &salt);
        let token = shake(&[&mk, b"token"], T_BITS / 8);
        let lenmask = shake(&[&mk, b"len"], LEN_BITS / 8);
        let stream = shake(&[&mk, b"stream"], plaintext.len());
        let mackey = shake(&[&mk, b"mac"], 32);

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

        let seq = self.slot_seq(&prk, plane, bits.len());
        for (j, &bit) in bits.iter().enumerate() {
            let g = self.global(seq[j], plane);
            self.set_bit(g, bit);
        }
        Ok(plane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_prime_coprime8_works() {
        assert_eq!(next_prime_coprime8(419), 419);
        assert_eq!(next_prime_coprime8(420), 421);
        assert_eq!(next_prime_coprime8(2), 3);
    }

    #[test]
    fn roundtrip_two_payloads() {
        let k = next_prime_coprime8(419);
        let mut c = Kpdc::create(65536, k).unwrap();
        let pa = c.write("alpha-pass", b"the treaty is signed at dawn", &[], DEFAULT_MAXPROBE, None).unwrap();
        let pb = c.write("beta-pass", b"pier 39, midnight", &["alpha-pass"], DEFAULT_MAXPROBE, None).unwrap();
        assert_ne!(pa, pb);
        assert_eq!(c.read("alpha-pass", DEFAULT_MAXPROBE).as_deref(), Some(&b"the treaty is signed at dawn"[..]));
        assert_eq!(c.read("beta-pass", DEFAULT_MAXPROBE).as_deref(), Some(&b"pier 39, midnight"[..]));
        assert_eq!(c.read("wrong-pass", DEFAULT_MAXPROBE), None);
    }

    #[test]
    fn tamper_is_detected() {
        let k = next_prime_coprime8(257);
        let mut c = Kpdc::create(32768, k).unwrap();
        c.write("pw", b"secret message here", &[], DEFAULT_MAXPROBE, None).unwrap();
        // flip a byte: HMAC should reject -> None (no panic, no garbage)
        let mut bytes = c.into_bytes();
        bytes[12345] ^= 0xFF;
        let c2 = Kpdc::from_bytes(bytes, k);
        // either still reads (if flip missed this plane) or returns None — never wrong plaintext
        match c2.read("pw", DEFAULT_MAXPROBE) {
            Some(pt) => assert_eq!(pt, b"secret message here"),
            None => {}
        }
    }
}
