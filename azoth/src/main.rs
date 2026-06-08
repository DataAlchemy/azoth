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
#[command(name = "azoth", version, about = "Deniable encryption container (KPDC)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// KDF cost — must match between write and read (it's part of the credential).
#[derive(Args, Clone, Copy)]
struct KdfArgs {
    /// Argon2id memory cost in MiB.
    #[arg(long, default_value_t = 64)]
    kdf_mem_mib: u32,
    /// Argon2id iterations (passes).
    #[arg(long, default_value_t = 3)]
    kdf_iters: u32,
}
impl From<KdfArgs> for KdfParams {
    fn from(a: KdfArgs) -> Self {
        KdfParams { mem_kib: a.kdf_mem_mib.saturating_mul(1024).max(8), iters: a.kdf_iters.max(1), lanes: 1 }
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
    /// Write a payload. Pass every OTHER known password via --known to avoid clobbering.
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
        #[arg(long = "known")]
        known: Vec<String>,
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
        }
        Cmd::Write { file, password, k, data, known, maxprobe, kdf } => {
            warn_if_bad_k(k);
            let pw = resolve_password(password)?;
            let block = std::fs::read(&file).with_context(|| format!("reading {}", file))?;
            let plaintext = read_input(&data)?;
            let mut c = Kpdc::from_bytes(block, k, kdf.into()).map_err(anyhow_err)?;
            let known_refs: Vec<&str> = known.iter().map(|s| s.as_str()).collect();
            let plane = c
                .write(&pw, &plaintext, &known_refs, maxprobe, None)
                .map_err(anyhow_err)?;
            write_atomic(&file, c.as_bytes())?;
            eprintln!("wrote {} bytes into plane {}", plaintext.len(), plane);
        }
        Cmd::Read { file, password, k, maxprobe, kdf } => {
            warn_if_bad_k(k);
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
    let k = next_prime_coprime8(419);
    let kdf = KdfParams::FAST_TEST; // low cost for a fast smoke test; real use defaults to ~64 MiB
    println!("K = {} (prime, coprime to 8)", k);
    let mut c = Kpdc::create(65536, k, kdf).map_err(anyhow_err)?;

    let pa = c.write("correct horse battery staple", b"the treaty is signed at dawn", &[], DEFAULT_MAXPROBE, None).map_err(anyhow_err)?;
    let pb = c.write("hunter2-xK!", b"meet at pier 39, midnight", &["correct horse battery staple"], DEFAULT_MAXPROBE, None).map_err(anyhow_err)?;
    println!("wrote payload A in plane {} | payload B in plane {}", pa, pb);

    assert_eq!(c.read("correct horse battery staple", DEFAULT_MAXPROBE).map(|z| z.to_vec()), Some(b"the treaty is signed at dawn".to_vec()));
    assert_eq!(c.read("hunter2-xK!", DEFAULT_MAXPROBE).map(|z| z.to_vec()), Some(b"meet at pier 39, midnight".to_vec()));
    assert!(c.read("wrong password", DEFAULT_MAXPROBE).is_none());
    println!("round-trip OK; wrong password -> None");

    let mean: f64 = c.as_bytes().iter().map(|&b| b as f64).sum::<f64>() / c.as_bytes().len() as f64;
    println!("block byte mean: {:.2} (uniform ~127.5)", mean);
    println!("block[:32] = {}", hex::encode(&c.as_bytes()[..32]));
    Ok(())
}
