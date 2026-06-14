//! Core orchestration for the azoth GUI.
//!
//! **No cryptography lives here** — every primitive call goes through the `azoth`
//! library crate. These functions are plain, synchronous, and side-effecting only on
//! the filesystem, so the GUI can run them on a worker thread and the acceptance test
//! can drive the identical code path without egui in the loop.
//!
//! Secrets returned by the library (`Kpdc::read`) stay in `zeroize::Zeroizing` and are
//! never written to any log string.

use azoth::{KdfParams, Kpdc, DEFAULT_MAXPROBE};
use std::fs;
use zeroize::Zeroizing;

/// Recommended Argon2id cost, mirrored from the CLI (`KdfParams::RECOMMENDED`).
pub const REC_MEM_MIB: u32 = 256;
pub const REC_ITERS: u32 = 3;

/// The decoy-storage tip the CLI prints after `create` — reproduced verbatim so the GUI
/// mirrors the CLI's guidance.
pub const CREATE_TIP: &str = "\
Tip: a brand-new container is pure noise. Before storing your real secret,
consider writing one or two *genuine but innocuous* secrets (an old password,
a mundane note) under their own passwords. If ever compelled, you can reveal
those — they are real, so they're believable — while the existence of anything
else stays hidden (computationally deniable to anyone without its password).";

/// KDF cost as the user enters it in the GUI (memory in MiB, iterations).
/// This is part of the credential and is **not** stored in the container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub mem_mib: u32,
    pub iters: u32,
}

impl Kdf {
    /// The recommended (default) cost: 256 MiB / 3 passes / 1 lane.
    pub const RECOMMENDED: Kdf = Kdf {
        mem_mib: REC_MEM_MIB,
        iters: REC_ITERS,
    };

    /// Convert to the library's `KdfParams` (lanes fixed at 1, as the CLI does).
    pub fn params(self) -> KdfParams {
        KdfParams {
            mem_kib: self.mem_mib.saturating_mul(1024),
            iters: self.iters,
            lanes: 1,
        }
    }

    /// True when the cost differs from the recommended 256 MiB / 3 — used to surface the
    /// "you must reuse the exact same values to decrypt" warning.
    pub fn is_custom(self) -> bool {
        self.mem_mib != REC_MEM_MIB || self.iters != REC_ITERS
    }

    /// Reject zero cost, matching the CLI's `KdfArgs::validate`.
    pub fn validate(self) -> Result<(), String> {
        if self.mem_mib == 0 || self.iters == 0 {
            return Err("KDF memory (MiB) and iterations must each be >= 1".to_string());
        }
        Ok(())
    }
}

impl Default for Kdf {
    fn default() -> Self {
        Kdf::RECOMMENDED
    }
}

/// Result of a read attempt. `Found` keeps the plaintext in `Zeroizing` so it is wiped
/// from memory when dropped; the caller decides whether to display or save it.
pub enum ReadOutcome {
    Found(Zeroizing<Vec<u8>>),
    NotFound,
}

/// Parse a size like `65536`, `64k`, `512mb`, `2gb` (binary, 1024-based) into bytes.
/// Ported from `azoth/src/main.rs::parse_size` (returns `String` errors instead of anyhow).
pub fn parse_size(s: &str) -> Result<usize, String> {
    let lower = s.trim().to_ascii_lowercase();
    let mut t = lower.as_str();
    t = t.strip_suffix('b').unwrap_or(t); // accept the optional trailing 'b' in kb/mb/gb
    let (num, mult): (&str, u64) = if let Some(n) = t.strip_suffix('k') {
        (n, 1 << 10)
    } else if let Some(n) = t.strip_suffix('m') {
        (n, 1 << 20)
    } else if let Some(n) = t.strip_suffix('g') {
        (n, 1 << 30)
    } else if let Some(n) = t.strip_suffix('t') {
        (n, 1u64 << 40)
    } else {
        (t, 1)
    };
    let val: u64 = num.trim().parse().map_err(|_| {
        format!("invalid size {s:?}: use a number, optionally with k/kb/m/mb/g/gb (1024-based)")
    })?;
    let bytes = val
        .checked_mul(mult)
        .ok_or_else(|| format!("size {s:?} overflows"))?;
    usize::try_from(bytes).map_err(|_| format!("size {s:?} too large for this platform"))
}

/// Create a fresh container of `size` random bytes and write it to `path`.
/// Returns a log message including the decoy-storage tip.
pub fn create_container(path: &str, size: usize, k: u64, kdf: Kdf) -> Result<String, String> {
    kdf.validate()?;
    let c = Kpdc::create(size, k, kdf.params()).map_err(|e| e.to_string())?;
    fs::write(path, c.as_bytes()).map_err(|e| format!("writing {path}: {e}"))?;
    Ok(format!(
        "created {path} ({size} bytes, K={k})\n\n{CREATE_TIP}"
    ))
}

/// Write `plaintext` under `pw` into the container at `path`.
///
/// * `rerandomize` ON  → rebuild the WHOLE block from every supplied payload (multi-snapshot
///   safe). Requires `all_keys`; every `known` password must still decrypt, or we abort
///   before touching the file so re-randomize cannot destroy data.
/// * `rerandomize` OFF → in-place `write` (faster, but leaves a multi-snapshot diffing tell).
///
/// On any error the file on disk is left untouched (the rebuild happens in memory first).
pub fn write_payload(
    path: &str,
    pw: &str,
    plaintext: &[u8],
    known: &[String],
    k: u64,
    kdf: Kdf,
    rerandomize: bool,
    all_keys: bool,
) -> Result<String, String> {
    kdf.validate()?;
    let block = fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
    let mut c = Kpdc::from_bytes(block, k, kdf.params()).map_err(|e| e.to_string())?;

    let log = if rerandomize {
        if !all_keys {
            return Err(
                "re-randomize rebuilds the WHOLE container and destroys any payload whose \
                 password you don't supply. List every OTHER password under \"Known passwords\", \
                 then tick \"I have supplied ALL passwords\" to confirm. (Or turn off \
                 re-randomize for an in-place write that leaves a multi-snapshot diffing \
                 fingerprint.)"
                    .to_string(),
            );
        }
        // Recover every payload we're told about (all must decrypt), then rebuild from scratch.
        let mut payloads: Vec<(String, Zeroizing<Vec<u8>>)> = Vec::new();
        for q in known {
            match c.read(q, DEFAULT_MAXPROBE) {
                Some(pt) => payloads.push((q.clone(), pt)),
                None => {
                    return Err(
                        "a known password didn't decrypt any payload (wrong password, or wrong \
                         K / KDF cost). Aborting so re-randomize doesn't destroy data."
                            .to_string(),
                    )
                }
            }
        }
        // Drop any entry equal to the target password, then add the new payload.
        payloads.retain(|(p, _)| p.as_str() != pw);
        payloads.push((pw.to_string(), Zeroizing::new(plaintext.to_vec())));
        let refs: Vec<(&str, &[u8])> = payloads
            .iter()
            .map(|(p, d)| (p.as_str(), d.as_slice()))
            .collect();
        c.write_all_fresh(&refs, DEFAULT_MAXPROBE)
            .map_err(|e| e.to_string())?;
        format!(
            "re-randomized container with {} payload(s) — whole block rewritten (multi-snapshot safe)",
            refs.len()
        )
    } else {
        let known_refs: Vec<&str> = known.iter().map(|s| s.as_str()).collect();
        let plane = c
            .write(pw, plaintext, &known_refs, DEFAULT_MAXPROBE, None)
            .map_err(|e| e.to_string())?;
        format!(
            "wrote {} bytes into plane {} (in-place; multi-snapshot diffing NOT defended)",
            plaintext.len(),
            plane
        )
    };

    fs::write(path, c.as_bytes()).map_err(|e| format!("writing {path}: {e}"))?;
    Ok(log)
}

/// Attempt to decrypt the payload for `pw`. The plaintext, if any, comes back in `Zeroizing`.
pub fn read_payload(path: &str, pw: &str, k: u64, kdf: Kdf) -> Result<ReadOutcome, String> {
    kdf.validate()?;
    let block = fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
    let c = Kpdc::from_bytes(block, k, kdf.params()).map_err(|e| e.to_string())?;
    match c.read(pw, DEFAULT_MAXPROBE) {
        Some(pt) => Ok(ReadOutcome::Found(pt)),
        None => Ok(ReadOutcome::NotFound),
    }
}
