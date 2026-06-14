//! azoth CLI (Linux/Unix) — create / write / read deniable containers.
//!
//! A container is just a file of random-looking bytes. `K` and the KDF cost are part of the
//! credential and are never stored in the file — supply them every time. The create/write/read
//! orchestration is shared with the GUI and Windows CLI via `azoth::app`; this binary adds arg
//! parsing, no-echo password prompts, raw block-device support (Unix), and atomic writes.

use anyhow::{anyhow, bail, Context, Result};
use azoth::app::{self, Kdf, ReadOutcome};
use azoth::{next_prime_coprime8, KdfParams, Kpdc};
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

/// KDF cost — must match between write and read (it's part of the credential, not stored).
#[derive(Args, Clone, Copy)]
struct KdfArgs {
    /// Argon2id memory cost in MiB (default = recommended; the floor is enforced by the core).
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
        /// May be omitted for a block device (auto-detected).
        #[arg(long, value_parser = size_parser)]
        size: Option<usize>,
        #[arg(long)]
        k: u64,
        #[arg(long)]
        out: String,
        /// Write straight to a raw target (e.g. a block device /dev/sdX): no temp-file + rename.
        /// Auto-enabled when the target is a block device.
        #[arg(long)]
        raw: bool,
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
        #[arg(long, default_value_t = azoth::DEFAULT_MAXPROBE)]
        maxprobe: usize,
        /// Write straight to a raw target (block device): no temp-file + rename. Auto-enabled for block devices.
        #[arg(long)]
        raw: bool,
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
        Cmd::Create { size, k, out, raw } => {
            warn_if_bad_k(k);
            let raw = raw || is_block_device(&out);
            let size = match size {
                Some(s) => s,
                None if raw => device_size(&out)
                    .with_context(|| format!("auto-detecting size of {}", out))?
                    as usize,
                None => bail!(
                    "--size is required (or use --raw on a block device to auto-detect its size)"
                ),
            };
            if raw {
                if let Ok(dev) = device_size(&out) {
                    if (size as u64) < dev {
                        eprintln!(
                            "warning: size {} is smaller than the target ({} bytes); the remaining {} \
                             bytes keep their old contents — a structure-after-noise tell. Fill the whole \
                             device for best deniability.",
                            size,
                            dev,
                            dev - size as u64
                        );
                    }
                }
            }
            // K must be odd (coprime to 8) — now a hard error in the core, not just a warning.
            let bytes = app::create_block(size, k, Kdf::RECOMMENDED).map_err(anyhow::Error::msg)?;
            write_target(&out, &bytes, raw)?;
            eprintln!(
                "created {} ({} bytes, K={}{})",
                out,
                size,
                k,
                if raw { ", raw" } else { "" }
            );
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
            raw,
            kdf,
        } => {
            let kdf = kdf.to_kdf();
            kdf.validate().map_err(anyhow::Error::msg)?; // enforces the KDF memory floor
            warn_if_bad_k(k);
            warn_if_custom_kdf(kdf);
            let raw = raw || is_block_device(&file);
            let pw = resolve_password(password)?;
            let block = std::fs::read(&file).with_context(|| format!("reading {}", file))?;
            let plaintext = read_input(&data)?; // Zeroizing
            let (new_block, log) = app::write_block(
                block,
                &pw,
                &plaintext,
                &known,
                k,
                kdf,
                maxprobe,
                !no_rerandomize,
                all_keys,
            )
            .map_err(anyhow::Error::msg)?;
            write_target(&file, &new_block, raw)?;
            eprintln!("{}", log);
        }
        Cmd::Read {
            file,
            password,
            k,
            maxprobe,
            kdf,
        } => {
            let kdf = kdf.to_kdf();
            kdf.validate().map_err(anyhow::Error::msg)?;
            warn_if_bad_k(k);
            warn_if_custom_kdf(kdf);
            let pw = resolve_password(password)?;
            let block = std::fs::read(&file).with_context(|| format!("reading {}", file))?;
            match app::read_block(&block, &pw, k, kdf, maxprobe).map_err(anyhow::Error::msg)? {
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
            eprintln!("warning: passing --password on the command line leaks it via `ps`/history; prefer the prompt.");
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
/// (Only valid for regular files — see `write_target` for raw block devices.)
///
/// The temp file uses a random, unpredictable name and is created with `create_new`
/// (`O_EXCL|O_CREAT`, which refuses to follow or overwrite an existing path — so a pre-planted
/// symlink cannot redirect the write) and owner-only `0o600` permissions. It holds the full
/// re-randomized container, so it is removed on any failure.
fn write_atomic(path: &str, data: &[u8]) -> Result<()> {
    let mut rnd = [0u8; 12];
    getrandom::getrandom(&mut rnd)
        .map_err(|e| anyhow!("gathering randomness for temp name: {e}"))?;
    let tmp = format!("{}.tmp.{}", path, hex::encode(rnd));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let attempt = (|| -> Result<()> {
        let mut f = opts
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

/// Write the full container to `path`. For raw targets (block devices) write the bytes directly
/// and fsync — the temp-file + rename trick is invalid on a device node.
fn write_target(path: &str, data: &[u8], raw: bool) -> Result<()> {
    if !raw {
        return write_atomic(path, data);
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        // Owner-only if we end up creating a regular file; a no-op on an existing device
        // node (whose permissions are managed in /dev). Don't rely on umask.
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("opening {} for raw write", path))?;
    f.write_all(data)
        .with_context(|| format!("writing {}", path))?;
    f.sync_all()
        .with_context(|| format!("flushing {} to disk", path))?;
    Ok(())
}

/// True if `path` is a block device (so writes must go directly to it).
#[cfg(unix)]
fn is_block_device(path: &str) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path)
        .map(|m| m.file_type().is_block_device())
        .unwrap_or(false)
}
#[cfg(not(unix))]
fn is_block_device(_path: &str) -> bool {
    false
}

/// Byte length of a file or block device (seek to end — works on devices where stat reports 0).
fn device_size(path: &str) -> Result<u64> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path))?;
    f.seek(SeekFrom::End(0))
        .with_context(|| format!("measuring {}", path))
}

fn anyhow_err(e: azoth::Error) -> anyhow::Error {
    anyhow::Error::msg(e.to_string())
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
