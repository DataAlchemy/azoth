//! Generate N successive snapshots of the SAME payload set, two ways:
//!   rerand : write_all_fresh (the CLI default) — whole block re-randomized each time
//!   inplace: write() in place (NOT multi-snapshot safe) — only payload bits change
//!
//! Lets us test whether a multi-snapshot adversary can localize payloads / recover K.
//!
//! Usage: cargo run --release --example make_snapshots -- <n_snapshots> <outdir>

use azoth::{KdfParams, Kpdc};
use std::env;

const SIZE: usize = 65_536;
const K: u64 = 11;
const CHEAP: KdfParams = KdfParams { mem_kib: 1024, iters: 1, lanes: 1 };

fn payloads() -> Vec<(String, Vec<u8>)> {
    // 11 fixed payloads (~98.5% fill), identical across every snapshot
    (0..11)
        .map(|i| (format!("snap-pw-{i}"), vec![(0x40 + i) as u8; 5800]))
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(32);
    let dir = args.get(2).cloned().unwrap_or_else(|| ".".into());

    let pl = payloads();
    let refs: Vec<(&str, &[u8])> = pl.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();

    // ---- rerand: write_all_fresh regenerates the WHOLE block each snapshot ----
    {
        let mut c = Kpdc::create(SIZE, K, CHEAP).unwrap();
        for s in 0..n {
            c.write_all_fresh(&refs, 64).unwrap();
            std::fs::write(format!("{dir}/snap_rerand_{s:02}.bin"), c.as_bytes()).unwrap();
        }
    }

    // ---- inplace: one random fill, then overwrite each payload (fresh salt) in place ----
    {
        let mut c = Kpdc::create(SIZE, K, CHEAP).unwrap();
        // initial placement into distinct planes (needs known_pws)
        for i in 0..pl.len() {
            let known: Vec<&str> = pl[..i].iter().map(|(p, _)| p.as_str()).collect();
            c.write(&pl[i].0, &pl[i].1, &known, 64, None).unwrap();
        }
        std::fs::write(format!("{dir}/snap_inplace_00.bin"), c.as_bytes()).unwrap();
        for s in 1..n {
            // re-write each payload in place: reuses its own plane, fresh salt -> new values
            for (pw, pt) in &pl {
                c.write(pw, pt, &[], 64, None).unwrap();
            }
            std::fs::write(format!("{dir}/snap_inplace_{s:02}.bin"), c.as_bytes()).unwrap();
        }
    }

    eprintln!("wrote {n} rerand + {n} inplace snapshots to {dir}");
}
