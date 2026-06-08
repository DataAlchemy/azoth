//! azoth CLI — create / write / read deniable containers.
//!
//! A container is just a file of random-looking bytes. `K` is part of the
//! credential and is never stored in the file — you must supply it every time.

use anyhow::{bail, Context, Result};
use azoth::{next_prime_coprime8, Kpdc, DEFAULT_MAXPROBE};
use clap::{Parser, Subcommand};
use std::io::{Read, Write};

#[derive(Parser)]
#[command(name = "azoth", version, about = "Deniable encryption container (KPDC)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
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
        #[arg(long)]
        password: String,
        #[arg(long)]
        k: u64,
        /// Path to plaintext, or "-" for stdin.
        #[arg(long)]
        data: String,
        #[arg(long = "known")]
        known: Vec<String>,
        #[arg(long, default_value_t = DEFAULT_MAXPROBE)]
        maxprobe: usize,
    },
    /// Read a payload to stdout (raw bytes).
    Read {
        #[arg(long)]
        file: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        k: u64,
        #[arg(long, default_value_t = DEFAULT_MAXPROBE)]
        maxprobe: usize,
    },
    /// Print the smallest prime >= n that is coprime to 8 (a good K).
    Prime { n: u64 },
    /// Run the built-in self-test demo.
    Demo,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Create { size, k, out } => {
            let c = Kpdc::create(size, k).context("create")?;
            std::fs::write(&out, c.as_bytes()).with_context(|| format!("writing {}", out))?;
            eprintln!("created {} ({} bytes, K={})", out, size, k);
        }
        Cmd::Write { file, password, k, data, known, maxprobe } => {
            let block = std::fs::read(&file).with_context(|| format!("reading {}", file))?;
            let plaintext = read_input(&data)?;
            let mut c = Kpdc::from_bytes(block, k);
            let known_refs: Vec<&str> = known.iter().map(|s| s.as_str()).collect();
            let plane = c
                .write(&password, &plaintext, &known_refs, maxprobe, None)
                .context("write")?;
            std::fs::write(&file, c.as_bytes()).with_context(|| format!("writing {}", file))?;
            eprintln!("wrote {} bytes into plane {}", plaintext.len(), plane);
        }
        Cmd::Read { file, password, k, maxprobe } => {
            let block = std::fs::read(&file).with_context(|| format!("reading {}", file))?;
            let c = Kpdc::from_bytes(block, k);
            match c.read(&password, maxprobe) {
                Some(pt) => std::io::stdout().write_all(&pt).context("stdout")?,
                None => bail!("no payload for that (password, K) — just noise"),
            }
        }
        Cmd::Prime { n } => println!("{}", next_prime_coprime8(n)),
        Cmd::Demo => demo()?,
    }
    Ok(())
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

fn demo() -> Result<()> {
    let k = next_prime_coprime8(419);
    println!("K = {} (prime, coprime to 8)", k);
    let mut c = Kpdc::create(65536, k)?;

    let pa = c.write("correct horse battery staple", b"the treaty is signed at dawn", &[], DEFAULT_MAXPROBE, None)?;
    let pb = c.write("hunter2-xK!", b"meet at pier 39, midnight", &["correct horse battery staple"], DEFAULT_MAXPROBE, None)?;
    println!("wrote payload A in plane {} | payload B in plane {}", pa, pb);

    assert_eq!(c.read("correct horse battery staple", DEFAULT_MAXPROBE).as_deref(), Some(&b"the treaty is signed at dawn"[..]));
    assert_eq!(c.read("hunter2-xK!", DEFAULT_MAXPROBE).as_deref(), Some(&b"meet at pier 39, midnight"[..]));
    assert_eq!(c.read("wrong password", DEFAULT_MAXPROBE), None);
    println!("round-trip OK; wrong password -> None");

    let mean: f64 = c.as_bytes().iter().map(|&b| b as f64).sum::<f64>() / c.as_bytes().len() as f64;
    println!("block byte mean: {:.2} (uniform ~127.5)", mean);
    println!("block[:32] = {}", hex::encode(&c.as_bytes()[..32]));
    Ok(())
}
