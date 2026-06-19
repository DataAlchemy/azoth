//! Fuzz the read path against fully attacker-controlled containers.
//!
//! `read` parses bits, a length field, and plane arithmetic out of an untrusted
//! blob; it must never panic, overflow, or hang — only return None or Some.
//!
//! Run with nightly + cargo-fuzz:
//!   cargo install cargo-fuzz
//!   cargo +nightly fuzz run read_arbitrary
#![no_main]

use azoth::{Cipher, KdfParams, Kpdc};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least one control byte + a non-trivial block.
    if data.len() < 65 {
        return;
    }
    // Derive K (odd, >= 3, bounded well under the bit-count), a cipher, and a password from input.
    let k = 3 + (u64::from(data[0]) % 250) | 1;
    let cipher = match data[0] % 3 {
        0 => Cipher::Aes256Ctr,
        1 => Cipher::ChaCha20,
        _ => Cipher::Shake256,
    };
    let block = data[1..].to_vec();
    // INSECURE_FAST_TEST keeps each iteration cheap; the parsing logic is cost-independent.
    if let Ok(c) = Kpdc::from_bytes_with(block, k, KdfParams::INSECURE_FAST_TEST, cipher) {
        let pw = format!("fuzz-{}", data[0]);
        let _ = c.read(&pw, 4);
        let _ = c.plane_of(&pw, 4);
    }
});
