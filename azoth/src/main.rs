//! azoth CLI — create / write / read deniable containers.
//!
//! A container is just a file of random-looking bytes. `K` and the KDF cost are
//! part of the credential and are never stored in the file — supply them every time.

use anyhow::{bail, Context, Result};
use azoth::{is_recommended_k, next_prime_coprime8, KdfParams, Kpdc, DEFAULT_MAXPROBE};
use clap::{Args, Parser, Subcommand};
use std::io::{Read, Write};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "azoth",
    version,
    about = "Deniable encryption container (KPDC)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// Recommended Argon2id cost (the default). Mirrors KdfParams::RECOMMENDED.
const REC_MEM_MIB: u32 = 256;
const REC_ITERS: u32 = 3;

/// KDF cost — must match between write and read (it's part of the credential, not stored).
#[derive(Args, Clone, Copy)]
struct KdfArgs {
    /// Argon2id memory cost in MiB (default = recommended).
    #[arg(long, default_value_t = REC_MEM_MIB)]
    kdf_mem_mib: u32,
    /// Argon2id iterations (passes).
    #[arg(long, default_value_t = REC_ITERS)]
    kdf_iters: u32,
}
impl KdfArgs {
    fn validate(&self) -> Result<()> {
        if self.kdf_mem_mib == 0 || self.kdf_iters == 0 {
            bail!("--kdf-mem-mib and --kdf-iters must each be >= 1");
        }
        Ok(())
    }
}
impl From<KdfArgs> for KdfParams {
    fn from(a: KdfArgs) -> Self {
        KdfParams {
            mem_kib: a.kdf_mem_mib.saturating_mul(1024),
            iters: a.kdf_iters,
            lanes: 1,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new container of `size` random bytes.
    Create {
        #[arg(long)]
        size: usize,
        #[arg(long)]
        k: u64,
        #[arg(long)]
        out: String,
    },
    /// Write a payload. By default the WHOLE container is re-randomized (multi-snapshot safe),
    /// which requires every existing password via --known plus --all-keys to confirm.
    Write {
        #[arg(long)]
        file: String,
        /// Password. If omitted, you are prompted (no echo) — preferred, since CLI args leak via `ps`.
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        k: u64,
        /// Path to plaintext, or "-" for stdin.
        #[arg(long)]
        data: String,
        /// Every OTHER password already in the container (required for re-randomize).
        #[arg(long = "known")]
        known: Vec<String>,
        /// Confirm you have supplied every existing password; re-randomize destroys any you omit.
        #[arg(long)]
        all_keys: bool,
        /// Skip whole-block re-randomization: faster in-place write, but leaves a
        /// multi-snapshot diffing fingerprint (an adversary who images before/after learns K).
        #[arg(long)]
        no_rerandomize: bool,
        #[arg(long, default_value_t = DEFAULT_MAXPROBE)]
        maxprobe: usize,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Read a payload to stdout (raw bytes).
    Read {
        #[arg(long)]
        file: String,
        /// Password. If omitted, you are prompted (no echo).
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        k: u64,
        #[arg(long, default_value_t = DEFAULT_MAXPROBE)]
        maxprobe: usize,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Print the smallest prime >= n that is coprime to 8 (a good K).
    Prime { n: u64 },
    /// Run the built-in self-test demo (low KDF cost for speed).
    Demo,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Create { size, k, out } => {
            warn_if_bad_k(k);
            let c = Kpdc::create(size, k, KdfParams::default()).map_err(anyhow_err)?;
            write_atomic(&out, c.as_bytes())?;
            eprintln!("created {} ({} bytes, K={})", out, size, k);
            eprintln!(
                "\nTip: a brand-new container is pure noise. Before storing your real secret,\n\
                 consider writing one or two *genuine but innocuous* secrets (an old password,\n\
                 a mundane note) under their own passwords. If ever compelled, you can reveal\n\
                 those — they are real, so they're believable — while the existence of anything\n\
                 else stays hidden (computationally deniable to anyone without its password)."
            );
        }
        Cmd::Write {
            file,
            password,
            k,
            data,
            known,
            all_keys,
            no_rerandomize,
            maxprobe,
            kdf,
        } => {
            kdf.validate()?;
            warn_if_bad_k(k);
            warn_if_custom_kdf(&kdf);
            let pw = resolve_password(password)?;
            let block = std::fs::read(&file).with_context(|| format!("reading {}", file))?;
            let plaintext = read_input(&data)?;
            let mut c = Kpdc::from_bytes(block, k, kdf.into()).map_err(anyhow_err)?;

            if no_rerandomize {
                let known_refs: Vec<&str> = known.iter().map(|s| s.as_str()).collect();
                let plane = c
                    .write(&pw, &plaintext, &known_refs, maxprobe, None)
                    .map_err(anyhow_err)?;
                write_atomic(&file, c.as_bytes())?;
                eprintln!(
                    "wrote {} bytes into plane {} (in-place; multi-snapshot diffing NOT defended)",
                    plaintext.len(),
                    plane
                );
            } else {
                if !all_keys {
                    bail!(
                        "default write re-randomizes the WHOLE container and destroys any payload \
                         whose password you don't supply. Pass --known <pw> for every other payload, \
                         then re-run with --all-keys to confirm. (Or --no-rerandomize for an in-place \
                         write that leaves a multi-snapshot diffing fingerprint.)"
                    );
                }
                // Recover every existing payload we're told about (all must decrypt), then rebuild.
                let mut payloads: Vec<(String, Vec<u8>)> = Vec::new();
                for q in &known {
                    match c.read(q, maxprobe) {
                        Some(pt) => payloads.push((q.clone(), pt.to_vec())),
                        None => bail!(
                            "a --known password did not decrypt any payload (wrong password, or wrong \
                             K / KDF cost). Aborting so re-randomize does not destroy data."
                        ),
                    }
                }
                payloads.retain(|(p, _)| p.as_str() != pw.as_str());
                payloads.push((pw.to_string(), plaintext.clone()));
                let refs: Vec<(&str, &[u8])> = payloads
                    .iter()
                    .map(|(p, d)| (p.as_str(), d.as_slice()))
                    .collect();
                c.write_all_fresh(&refs, maxprobe).map_err(anyhow_err)?;
                write_atomic(&file, c.as_bytes())?;
                eprintln!(
                    "re-randomized container with {} payload(s) — whole block rewritten (multi-snapshot safe)",
                    refs.len()
                );
            }
        }
        Cmd::Read {
            file,
            password,
            k,
            maxprobe,
            kdf,
        } => {
            kdf.validate()?;
            warn_if_bad_k(k);
            warn_if_custom_kdf(&kdf);
            let pw = resolve_password(password)?;
            let block = std::fs::read(&file).with_context(|| format!("reading {}", file))?;
            let c = Kpdc::from_bytes(block, k, kdf.into()).map_err(anyhow_err)?;
            match c.read(&pw, maxprobe) {
                Some(pt) => std::io::stdout().write_all(&pt).context("stdout")?,
                None => bail!("no payload for that (password, K, KDF cost) — just noise"),
            }
        }
        Cmd::Prime { n } => println!("{}", next_prime_coprime8(n)),
        Cmd::Demo => demo()?,
    }
    Ok(())
}

fn anyhow_err(e: azoth::Error) -> anyhow::Error {
    anyhow::anyhow!(e.to_string())
}

fn warn_if_custom_kdf(kdf: &KdfArgs) {
    if kdf.kdf_mem_mib != REC_MEM_MIB || kdf.kdf_iters != REC_ITERS {
        eprintln!(
            "warning: custom KDF cost (mem={} MiB, iters={}). This is part of the credential and \
             is NOT stored — you must supply these EXACT values to decrypt, or the payload is \
             unrecoverable and indistinguishable from a wrong password.",
            kdf.kdf_mem_mib, kdf.kdf_iters
        );
    }
}

fn warn_if_bad_k(k: u64) {
    if !is_recommended_k(k) {
        eprintln!(
            "warning: K={} is not a prime coprime to 8; plane geometry may be skewed and \
             deniability weakened. Get a good K with `azoth prime <n>`.",
            k
        );
    }
}

fn resolve_password(opt: Option<String>) -> Result<Zeroizing<String>> {
    match opt {
        Some(p) => {
            eprintln!("warning: passing --password on the command line leaks it via `ps`/history; prefer the prompt.");
            Ok(Zeroizing::new(p))
        }
        None => Ok(Zeroizing::new(
            rpassword::prompt_password("password: ").context("reading password")?,
        )),
    }
}

fn read_input(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).context("stdin")?;
        Ok(buf)
    } else {
        std::fs::read(path).with_context(|| format!("reading {}", path))
    }
}

/// Write via a temp file + atomic rename so a crash can't corrupt the container.
fn write_atomic(path: &str, data: &[u8]) -> Result<()> {
    let tmp = format!("{}.tmp.{}", path, std::process::id());
    std::fs::write(&tmp, data).with_context(|| format!("writing {}", tmp))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path))?;
    Ok(())
}

fn demo() -> Result<()> {
    // Uses the RECOMMENDED (default) cost; small K/maxprobe keep the smoke test quick.
    let k = next_prime_coprime8(11);
    let mp = 2;
    println!(
        "K = {} | KDF = recommended (Argon2id 256 MiB / 3 passes)",
        k
    );
    let mut c = Kpdc::create(16384, k, KdfParams::default()).map_err(anyhow_err)?;

    // Whole-block re-randomize write (the default behavior): rebuild from all payloads.
    c.write_all_fresh(
        &[
            (
                "correct horse battery staple",
                b"the treaty is signed at dawn",
            ),
            ("hunter2-xK!", b"meet at pier 39, midnight"),
        ],
        mp,
    )
    .map_err(anyhow_err)?;
    println!("re-randomized container with 2 payloads under 2 passwords");

    assert_eq!(
        c.read("correct horse battery staple", mp)
            .map(|z| z.to_vec()),
        Some(b"the treaty is signed at dawn".to_vec())
    );
    assert_eq!(
        c.read("hunter2-xK!", mp).map(|z| z.to_vec()),
        Some(b"meet at pier 39, midnight".to_vec())
    );
    assert!(c.read("wrong password", mp).is_none());
    println!("round-trip OK; wrong password -> None");

    let mean: f64 = c.as_bytes().iter().map(|&b| b as f64).sum::<f64>() / c.as_bytes().len() as f64;
    println!("block byte mean: {:.2} (uniform ~127.5)", mean);
    println!("block[:32] = {}", hex::encode(&c.as_bytes()[..32]));
    Ok(())
}
