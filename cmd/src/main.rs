//! azoth CLI (Windows) — create / write / read deniable containers.
//!
//! Windows-tailored command line: the same create/write/read model as the Unix CLI, but without
//! the raw block-device handling. The crypto orchestration is shared via `azoth::app` — **no new
//! crypto here**. `K` and the KDF cost are part of the credential and are never stored; supply
//! them every time.

use anyhow::{anyhow, bail, Context, Result};
use azoth::app::{self, Kdf, ReadOutcome};
use azoth::{next_prime_coprime8, Cipher, KdfParams, Kpdc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// Payload cipher selector (part of the credential, like K and the KDF cost — not stored).
/// Variant names kebab-case to `aes-ctr` / `chacha20` / `shake256` for `--cipher`.
#[derive(Clone, Copy, ValueEnum)]
enum CipherArg {
    AesCtr,
    Chacha20,
    Shake256,
}
impl From<CipherArg> for Cipher {
    fn from(c: CipherArg) -> Self {
        match c {
            CipherArg::AesCtr => Cipher::Aes256Ctr,
            CipherArg::Chacha20 => Cipher::ChaCha20,
            CipherArg::Shake256 => Cipher::Shake256,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "azoth",
    version,
    about = "Deniable encryption container (KPDC) — Windows"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// KDF cost — must match between write and read (it's part of the credential, not stored).
#[derive(Args, Clone, Copy)]
struct KdfArgs {
    /// Argon2id memory cost in MiB (default = recommended).
    #[arg(long, default_value_t = app::REC_MEM_MIB)]
    kdf_mem_mib: u32,
    /// Argon2id iterations (passes).
    #[arg(long, default_value_t = app::REC_ITERS)]
    kdf_iters: u32,
}
impl KdfArgs {
    fn to_kdf(self) -> Kdf {
        Kdf {
            mem_mib: self.kdf_mem_mib,
            iters: self.kdf_iters,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new container of `size` random bytes.
    Create {
        /// Container size: bytes, or with a unit — e.g. 64k, 512mb, 2gb (binary, 1024-based).
        #[arg(long, value_parser = size_parser)]
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
        /// Password. If omitted, you are prompted (no echo).
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
        /// multi-snapshot diffing fingerprint.
        #[arg(long)]
        no_rerandomize: bool,
        #[arg(long, default_value_t = azoth::DEFAULT_MAXPROBE)]
        maxprobe: usize,
        /// Payload cipher: aes-ctr (default) | chacha20 | shake256. Part of the credential —
        /// not stored, so you must read with the same value.
        #[arg(long, default_value = "aes-ctr")]
        cipher: CipherArg,
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
        #[arg(long, default_value_t = azoth::DEFAULT_MAXPROBE)]
        maxprobe: usize,
        /// Payload cipher: aes-ctr (default) | chacha20 | shake256 (must match the write).
        #[arg(long, default_value = "aes-ctr")]
        cipher: CipherArg,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Print the smallest prime >= n that is coprime to 8 (a good K).
    Prime { n: u64 },
    /// Run the built-in self-test demo.
    Demo,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Create { size, k, out } => {
            warn_if_bad_k(k);
            let bytes = app::create_block(size, k, Kdf::RECOMMENDED).map_err(anyhow::Error::msg)?;
            write_atomic(&out, &bytes)?;
            eprintln!("created {} ({} bytes, K={})", out, size, k);
            eprintln!("\n{}", app::CREATE_TIP);
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
            cipher,
            kdf,
        } => {
            let kdf = kdf.to_kdf();
            kdf.validate().map_err(anyhow::Error::msg)?;
            warn_if_bad_k(k);
            warn_if_custom_kdf(kdf);
            let pw = resolve_password(password)?;
            let block = std::fs::read(&file).with_context(|| format!("reading {}", file))?;
            let plaintext = read_input(&data)?;
            let (new_block, log) = app::write_block(
                block,
                &pw,
                &plaintext,
                &known,
                k,
                kdf,
                cipher.into(),
                maxprobe,
                !no_rerandomize,
                all_keys,
            )
            .map_err(anyhow::Error::msg)?;
            write_atomic(&file, &new_block)?;
            eprintln!("{}", log);
        }
        Cmd::Read {
            file,
            password,
            k,
            maxprobe,
            cipher,
            kdf,
        } => {
            let kdf = kdf.to_kdf();
            kdf.validate().map_err(anyhow::Error::msg)?;
            warn_if_bad_k(k);
            warn_if_custom_kdf(kdf);
            let pw = resolve_password(password)?;
            let block = std::fs::read(&file).with_context(|| format!("reading {}", file))?;
            match app::read_block(&block, &pw, k, kdf, cipher.into(), maxprobe)
                .map_err(anyhow::Error::msg)?
            {
                ReadOutcome::Found(pt) => std::io::stdout().write_all(&pt).context("stdout")?,
                ReadOutcome::NotFound => {
                    bail!("no payload for that (password, K, KDF cost) — just noise")
                }
            }
        }
        Cmd::Prime { n } => println!("{}", next_prime_coprime8(n)),
        Cmd::Demo => demo()?,
    }
    Ok(())
}

fn warn_if_custom_kdf(kdf: Kdf) {
    if let Some(w) = app::custom_kdf_warning(kdf) {
        eprintln!("warning: {w}");
    }
}

fn warn_if_bad_k(k: u64) {
    if let Some(w) = app::bad_k_warning(k) {
        eprintln!("warning: {w}");
    }
}

fn resolve_password(opt: Option<String>) -> Result<Zeroizing<String>> {
    match opt {
        Some(p) => {
            eprintln!("warning: passing --password on the command line leaks it via shell history; prefer the prompt.");
            Ok(Zeroizing::new(p))
        }
        None => Ok(Zeroizing::new(
            rpassword::prompt_password("password: ").context("reading password")?,
        )),
    }
}

/// clap value parser wrapper (its error must be a String) — delegates to the shared core.
fn size_parser(s: &str) -> std::result::Result<usize, String> {
    app::parse_size(s)
}

/// Read the plaintext to be written. Returned in `Zeroizing` so the secret is wiped from the
/// CLI's memory on drop (the library zeroizes its own copies).
fn read_input(path: &str) -> Result<Zeroizing<Vec<u8>>> {
    if path == "-" {
        let mut buf = Zeroizing::new(Vec::new());
        std::io::stdin().read_to_end(&mut buf).context("stdin")?;
        Ok(buf)
    } else {
        Ok(Zeroizing::new(
            std::fs::read(path).with_context(|| format!("reading {}", path))?,
        ))
    }
}

/// Write via a temp file + atomic rename so a crash can't corrupt the container.
///
/// The temp file uses a random, unpredictable name and is created with `create_new`
/// (refuses to follow or overwrite an existing path), so a pre-planted file/symlink cannot
/// redirect the write. It holds the full re-randomized container, so it is removed on any
/// failure. (`fs::rename` replaces the destination atomically on Windows.)
fn write_atomic(path: &str, data: &[u8]) -> Result<()> {
    let mut rnd = [0u8; 12];
    getrandom::getrandom(&mut rnd)
        .map_err(|e| anyhow!("gathering randomness for temp name: {e}"))?;
    let tmp = format!("{}.tmp.{}", path, hex::encode(rnd));

    let attempt = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("creating temp file {}", tmp))?;
        f.write_all(data)
            .with_context(|| format!("writing {}", tmp))?;
        f.sync_all()
            .with_context(|| format!("flushing {} to disk", tmp))?;
        Ok(())
    })();
    if let Err(e) = attempt {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp); // don't leave the container's plaintext-equivalent behind
        return Err(e).with_context(|| format!("renaming into {}", path));
    }
    Ok(())
}

fn anyhow_err(e: azoth::Error) -> anyhow::Error {
    anyhow::Error::msg(e.to_string())
}

fn demo() -> Result<()> {
    let k = next_prime_coprime8(11);
    let mp = 2;
    println!(
        "K = {} | KDF = recommended (Argon2id 256 MiB / 3 passes)",
        k
    );
    let mut c = Kpdc::create(16384, k, KdfParams::default()).map_err(anyhow_err)?;
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
    println!("block[:32] = {}", hex::encode(&c.as_bytes()[..32]));
    Ok(())
}
