//! High-level orchestration shared by every front-end (Linux CLI, Windows CLI, GUI).
//!
//! **No cryptography lives here** — it composes the `azoth` primitives ([`Kpdc`],
//! [`KdfParams`]) into create / write / read operations, and owns the single source of truth
//! for the size parser, the KDF-cost type, and the advisory warnings. Front-ends layer their
//! own I/O and UX (atomic/raw writes, password prompts, dialogs) on top.
//!
//! Two granularities are offered:
//! * **block functions** ([`create_block`], [`write_block`], [`read_block`]) operate purely on
//!   in-memory byte blocks, so a CLI can keep its own atomic/raw file handling;
//! * **path wrappers** ([`create_container`], [`write_payload`], [`read_payload`]) add plain
//!   `std::fs` I/O for the GUI.
//!
//! Secrets returned by the library stay in [`zeroize::Zeroizing`] and are never logged.

use crate::{is_recommended_k, Cipher, KdfParams, Kpdc, DEFAULT_MAXPROBE};
use zeroize::Zeroizing;

/// Stable lowercase label for a cipher, shown in the GUI selector. (The CLIs parse `--cipher`
/// via their own clap `ValueEnum`, which yields the same `aes-ctr` / `chacha20` / `shake256`.)
pub fn cipher_label(c: Cipher) -> &'static str {
    match c {
        Cipher::Aes256Ctr => "aes-ctr",
        Cipher::ChaCha20 => "chacha20",
        Cipher::Shake256 => "shake256",
    }
}

/// Recommended Argon2id cost (the default): 256 MiB / 3 passes.
pub const REC_MEM_MIB: u32 = 256;
pub const REC_ITERS: u32 = 3;

/// Hard floor for KDF memory cost (the OWASP Argon2id minimum). The memory-hard gate is the
/// only defense against offline guessing of the verification oracle; below this it is too
/// cheap to brute-force, so every front-end refuses it. (The library's hidden
/// `INSECURE_FAST_TEST` cost is for tests only and bypasses this front-end policy.)
pub const MIN_KDF_MEM_MIB: u32 = 19;

/// Deniability-scope reminder printed/shown after `create`. Deliberately honest about the limits:
/// the block is deniable in isolation, but the tool and being compelled to run it are not covered.
pub const CREATE_TIP: &str = "\
Note on what this hides: this block is just random bytes — on its own, indistinguishable
from free space, a wiped disk, or any other encrypted blob. That is ALL it hides: the
contents and number of payloads in this block, to someone who finds the block alone.
It does NOT hide that you use azoth (the binary, your shell history, this command), and it
does NOT survive coercion: if you are compelled to decrypt, a tool built to hold hidden
payloads invites the demand 'now the others' — and they need not believe you've shown
everything. Reach for this only when the block can be found WITHOUT you and without the
tool, with a plausible reason to be random. It is not a way to beat an interrogation.";

/// KDF cost as a user enters it (memory in MiB, iterations). Part of the credential — not
/// stored in the container, so it must match between write and read.
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

    /// Convert to the library's [`KdfParams`] (lanes fixed at 1).
    pub fn params(self) -> KdfParams {
        KdfParams {
            mem_kib: self.mem_mib.saturating_mul(1024),
            iters: self.iters,
            lanes: 1,
        }
    }

    /// True when the cost differs from the recommended 256 MiB / 3.
    pub fn is_custom(self) -> bool {
        self.mem_mib != REC_MEM_MIB || self.iters != REC_ITERS
    }

    /// Reject zero iterations and memory below the security floor ([`MIN_KDF_MEM_MIB`]).
    pub fn validate(self) -> Result<(), String> {
        if self.iters == 0 {
            return Err("KDF iterations must be >= 1".to_string());
        }
        if self.mem_mib < MIN_KDF_MEM_MIB {
            return Err(format!(
                "KDF memory {} MiB is below the {} MiB minimum (OWASP Argon2id floor); a weaker \
                 gate makes offline guessing of the verification oracle cheap. Recommended is {} MiB.",
                self.mem_mib, MIN_KDF_MEM_MIB, REC_MEM_MIB
            ));
        }
        Ok(())
    }
}

impl Default for Kdf {
    fn default() -> Self {
        Kdf::RECOMMENDED
    }
}

/// Result of a read attempt. `Found` keeps the plaintext in [`Zeroizing`] so it is wiped on drop.
pub enum ReadOutcome {
    Found(Zeroizing<Vec<u8>>),
    NotFound,
}

// ---- advisory warnings (single source of truth; front-ends prefix/format as they like) ----

/// Warning text when `k` is not a recommended plane count, or `None` if it is fine.
pub fn bad_k_warning(k: u64) -> Option<String> {
    (!is_recommended_k(k)).then(|| {
        format!(
            "K={k} is not a prime coprime to 8; plane geometry may be skewed and deniability \
             weakened. Get a good K with `azoth prime <n>`."
        )
    })
}

/// Warning text when the KDF cost is non-default, or `None` if it is the recommended cost.
pub fn custom_kdf_warning(kdf: Kdf) -> Option<String> {
    kdf.is_custom().then(|| {
        format!(
            "custom KDF cost (mem={} MiB, iters={}) is part of the credential and is NOT stored \
             — you must supply these EXACT values to decrypt, or the payload is unrecoverable \
             and indistinguishable from a wrong password.",
            kdf.mem_mib, kdf.iters
        )
    })
}

/// Parse a size like `65536`, `64k`, `512mb`, `2gb` (binary, 1024-based) into bytes.
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

// ---- block-oriented orchestration (no file I/O) ----

/// A fresh container of `size` random bytes, returned as a byte block.
pub fn create_block(size: usize, k: u64, kdf: Kdf) -> Result<Vec<u8>, String> {
    kdf.validate()?;
    let c = Kpdc::create(size, k, kdf.params()).map_err(|e| e.to_string())?;
    Ok(c.into_bytes())
}

/// Write `plaintext` under `pw` into `block`, returning the new block and a log line.
///
/// * `rerandomize` ON  → rebuild the WHOLE block from every supplied payload (multi-snapshot
///   safe). Requires `all_keys`; every `known` password must still decrypt, or it aborts
///   before changing anything so re-randomize cannot destroy data.
/// * `rerandomize` OFF → in-place write (faster, but leaves a multi-snapshot diffing tell).
#[allow(clippy::too_many_arguments)]
pub fn write_block(
    block: Vec<u8>,
    pw: &str,
    plaintext: &[u8],
    known: &[String],
    k: u64,
    kdf: Kdf,
    cipher: Cipher,
    maxprobe: usize,
    rerandomize: bool,
    all_keys: bool,
) -> Result<(Vec<u8>, String), String> {
    kdf.validate()?;
    let mut c = Kpdc::from_bytes_with(block, k, kdf.params(), cipher).map_err(|e| e.to_string())?;

    let log = if rerandomize {
        if !all_keys {
            return Err(
                "re-randomize rebuilds the WHOLE container and destroys any payload whose \
                 password you don't supply. Provide every OTHER password as a known password and \
                 confirm all-keys. (Or disable re-randomize for an in-place write that leaves a \
                 multi-snapshot diffing fingerprint.)"
                    .to_string(),
            );
        }
        // Keep the recovered password + plaintext copies in Zeroizing so they wipe on drop.
        #[allow(clippy::type_complexity)]
        let mut payloads: Vec<(Zeroizing<String>, Zeroizing<Vec<u8>>)> = Vec::new();
        for q in known {
            match c.read(q, maxprobe) {
                Some(pt) => payloads.push((Zeroizing::new(q.clone()), pt)),
                None => {
                    return Err(
                        "a known password didn't decrypt any payload (wrong password, or wrong \
                         K / KDF cost). Aborting so re-randomize doesn't destroy data."
                            .to_string(),
                    )
                }
            }
        }
        payloads.retain(|(p, _)| p.as_str() != pw);
        payloads.push((
            Zeroizing::new(pw.to_string()),
            Zeroizing::new(plaintext.to_vec()),
        ));
        let refs: Vec<(&str, &[u8])> = payloads
            .iter()
            .map(|(p, d)| (p.as_str(), d.as_slice()))
            .collect();
        c.write_all_fresh(&refs, maxprobe)
            .map_err(|e| e.to_string())?;
        format!(
            "re-randomized container with {} payload(s) — whole block rewritten (multi-snapshot safe)",
            refs.len()
        )
    } else {
        let known_refs: Vec<&str> = known.iter().map(|s| s.as_str()).collect();
        let plane = c
            .write(pw, plaintext, &known_refs, maxprobe, None)
            .map_err(|e| e.to_string())?;
        format!(
            "wrote {} bytes into plane {} (in-place; multi-snapshot diffing NOT defended)",
            plaintext.len(),
            plane
        )
    };

    Ok((c.into_bytes(), log))
}

/// Attempt to decrypt the payload for `pw` from `block`.
pub fn read_block(
    block: &[u8],
    pw: &str,
    k: u64,
    kdf: Kdf,
    cipher: Cipher,
    maxprobe: usize,
) -> Result<ReadOutcome, String> {
    kdf.validate()?;
    let c = Kpdc::from_bytes_with(block.to_vec(), k, kdf.params(), cipher)
        .map_err(|e| e.to_string())?;
    Ok(match c.read(pw, maxprobe) {
        Some(pt) => ReadOutcome::Found(pt),
        None => ReadOutcome::NotFound,
    })
}

// ---- path convenience wrappers (plain fs) — used by the GUI ----

/// Create a fresh container and write it to `path`. Returns a log line including the
/// deniability-scope reminder (`CREATE_TIP`).
pub fn create_container(path: &str, size: usize, k: u64, kdf: Kdf) -> Result<String, String> {
    let bytes = create_block(size, k, kdf)?;
    std::fs::write(path, &bytes).map_err(|e| format!("writing {path}: {e}"))?;
    Ok(format!(
        "created {path} ({size} bytes, K={k})\n\n{CREATE_TIP}"
    ))
}

/// Read `path`, write the payload, and write the container back. On any error the file is
/// left untouched (the rebuild happens in memory first).
#[allow(clippy::too_many_arguments)]
pub fn write_payload(
    path: &str,
    pw: &str,
    plaintext: &[u8],
    known: &[String],
    k: u64,
    kdf: Kdf,
    cipher: Cipher,
    rerandomize: bool,
    all_keys: bool,
) -> Result<String, String> {
    let block = std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
    let (new_block, log) = write_block(
        block,
        pw,
        plaintext,
        known,
        k,
        kdf,
        cipher,
        DEFAULT_MAXPROBE,
        rerandomize,
        all_keys,
    )?;
    std::fs::write(path, &new_block).map_err(|e| format!("writing {path}: {e}"))?;
    Ok(log)
}

/// Read `path` and attempt to decrypt the payload for `pw`.
pub fn read_payload(
    path: &str,
    pw: &str,
    k: u64,
    kdf: Kdf,
    cipher: Cipher,
) -> Result<ReadOutcome, String> {
    let block = std::fs::read(path).map_err(|e| format!("reading {path}: {e}"))?;
    read_block(&block, pw, k, kdf, cipher, DEFAULT_MAXPROBE)
}
