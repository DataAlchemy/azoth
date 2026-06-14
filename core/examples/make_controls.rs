//! Generate control containers for the deniability challenge battery.
//!
//! Produces, in the current directory:
//!   control_random.bin          - pure getrandom() bytes (a true uniform control)
//!   control_empty_NN.bin        - fresh azoth containers, no payloads (CSPRNG fill)
//!   control_full_NN.bin         - azoth containers filled to ~98.5% like the challenge
//!                                 (K=11, 11 payloads, 5800-byte random plaintexts)
//!   control_fullmax_NN.bin      - filled to plane capacity (~99.99%)
//!
//! KDF cost is irrelevant to the byte distribution (per the challenge), so we use a
//! cheap cost to generate many full controls quickly.
//!
//! Usage: cargo run --release --example make_controls -- <n_empty> <n_full>

use azoth::{KdfParams, Kpdc};
use std::env;

const SIZE: usize = 65_536;
const K: u64 = 11;
// Cheap KDF purely for speed of control generation; distribution is independent of cost.
const CHEAP: KdfParams = KdfParams {
    mem_kib: 1024,
    iters: 1,
    lanes: 1,
};

// tiny deterministic-ish payload filler so plaintext content varies per payload
fn fill_payload(buf: &mut [u8], mut seed: u64) {
    for b in buf.iter_mut() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *b = (seed & 0xff) as u8;
    }
}

fn build_full(per_payload_len: usize, tag: &str, idx: usize) -> Vec<u8> {
    let mut c = Kpdc::create(SIZE, K, CHEAP).expect("create");
    let pws: Vec<String> = (0..11)
        .map(|i| format!("ctrl-{tag}-{idx}-pw-{i}"))
        .collect();
    let mut pt = vec![0u8; per_payload_len];
    for i in 0..11 {
        fill_payload(
            &mut pt,
            0x9E37_79B9_7F4A_7C15u64 ^ ((idx as u64) << 32) ^ i as u64 | 1,
        );
        let known: Vec<&str> = pws[..i].iter().map(|s| s.as_str()).collect();
        // in-place write; final block distribution is identical to write_all_fresh
        c.write(&pws[i], &pt, &known, 64, None)
            .expect("write payload");
    }
    c.into_bytes()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let n_empty: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(32);
    let n_full: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(32);

    // one true-random control
    let r = Kpdc::create(SIZE, K, CHEAP).expect("create").into_bytes();
    std::fs::write("control_random.bin", &r).unwrap();

    for n in 0..n_empty {
        let b = Kpdc::create(SIZE, K, CHEAP).expect("create").into_bytes();
        std::fs::write(format!("control_empty_{n:02}.bin"), &b).unwrap();
    }

    for n in 0..n_full {
        // 5800 bytes/payload -> total = 544 + 8*5800 = 46944 bits ~= 98.5% of ~47662 slots
        let b = build_full(5800, "full", n);
        std::fs::write(format!("control_full_{n:02}.bin"), &b).unwrap();
    }

    // a few "filled to plane capacity" (~99.99%) to bracket the high end
    for n in 0..4usize.min(n_full) {
        let b = build_full(5889, "max", n);
        std::fs::write(format!("control_fullmax_{n:02}.bin"), &b).unwrap();
    }

    eprintln!(
        "wrote control_random.bin, {} empty, {} full (98.5%), {} fullmax (~max)",
        n_empty,
        n_full,
        4usize.min(n_full)
    );
}
