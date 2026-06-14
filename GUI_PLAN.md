# azoth GUI — build plan (for a Claude Code session on Windows)

You are a Claude Code session running **natively on Windows**, with the ability to build and run
locally. Your job: build a small **native Windows GUI** front-end for the existing `azoth`
deniable-container library in this repo. **Do not write any new cryptography** — call the library.
Iterate with `cargo run` until it builds and works, fixing errors as you go.

Read `README.md` and `TECHNICAL_DETAILS.md` first for the model and the warnings the GUI must mirror.

---

## 0. Toolchain setup (free; NO Visual Studio needed)

Use Rust's **GNU** toolchain — it bundles its own linker, so you avoid the multi-GB MSVC/VS Build
Tools download entirely.

```powershell
# If rustup isn't installed yet, get the native installer and run it with the GNU host:
#   download https://win.rustup.rs/x86_64  ->  rustup-init.exe
rustup-init.exe -y --default-host x86_64-pc-windows-gnu --default-toolchain stable --profile minimal

# If rustup IS already installed (e.g. with the MSVC host), add the GNU toolchain additively:
rustup toolchain install stable-x86_64-pc-windows-gnu
```

Then build/run everything with that toolchain. If your default is MSVC and you don't have the C++
build tools, prefix commands with `+stable-x86_64-pc-windows-gnu`, e.g.
`cargo +stable-x86_64-pc-windows-gnu run -p azoth-gui`.

> Gotcha: `azoth/rust-toolchain.toml` pins `1.96.0`, but it only applies to commands run from
> *inside* `azoth/`. Build the GUI from the **repo root**, where it doesn't apply.

---

## 1. Project layout — add a `gui/` crate, make the repo a workspace

Create a workspace root and a new GUI crate next to the existing `azoth/` crate.

`Cargo.toml` (repo root — new file):
```toml
[workspace]
resolver = "2"
members = ["azoth", "gui"]
exclude = ["azoth/fuzz"]   # azoth/fuzz has its own [workspace]
```

`gui/Cargo.toml`:
```toml
[package]
name = "azoth-gui"
version = "0.1.0"
edition = "2021"

[dependencies]
azoth = { path = "../azoth" }   # the library crate already in this repo
eframe = "0.28"                  # egui; if it won't compile, `cargo add eframe` for the current version and adjust
rfd = "0.14"                     # native file open/save dialogs
zeroize = "1"
```

`gui/src/main.rs`: the egui app (below).

---

## 2. Library API you will call (full source: `azoth/src/lib.rs` — read it)

```rust
pub fn next_prime_coprime8(n: u64) -> u64;          // suggest a good K (odd prime, coprime to 8)
pub fn is_recommended_k(k: u64) -> bool;            // for the "bad K" warning
pub const DEFAULT_MAXPROBE: usize;                  // 64

pub struct KdfParams { pub mem_kib: u32, pub iters: u32, pub lanes: u32 }
impl KdfParams { pub const RECOMMENDED: KdfParams; } // 256 MiB / 3 / 1 ; also Default
// build from a MiB value: KdfParams { mem_kib: mib * 1024, iters, lanes: 1 }

pub struct Kpdc { /* ... */ }
impl Kpdc {
    pub fn create(size: usize, k: u64, kdf: KdfParams) -> Result<Kpdc, Error>;     // size in BYTES
    pub fn from_bytes(block: Vec<u8>, k: u64, kdf: KdfParams) -> Result<Kpdc, Error>;
    pub fn write(&mut self, pw: &str, plaintext: &[u8], known_pws: &[&str],
                 maxprobe: usize, salt: Option<&[u8]>) -> Result<u64, Error>;        // in-place
    pub fn write_all_fresh(&mut self, payloads: &[(&str, &[u8])], maxprobe: usize)
                 -> Result<(), Error>;                                               // re-randomize (rebuild from ALL)
    pub fn read(&self, pw: &str, maxprobe: usize) -> Option<zeroize::Zeroizing<Vec<u8>>>;
    pub fn as_bytes(&self) -> &[u8];
    pub fn into_bytes(self) -> Vec<u8>;
}
// azoth::Error implements Display.
```

Reading/writing the container itself is plain file I/O: `std::fs::read(path)` → `from_bytes`,
and `std::fs::write(path, c.as_bytes())` to save. (No need for the CLI's `--raw` device logic in v1.)

---

## 3. UI spec (egui)

A window ~640×580 with a tab selector **Create | Write | Read**, a shared inputs block, and a
read-only **status log** pane at the bottom that you append results/errors to.

**Shared inputs (all tabs):**
- *Container file* — text field + **Browse…** (`rfd::FileDialog::pick_file` / `save_file`).
- *K* — text field + **Suggest prime** button → `next_prime_coprime8(parse)`. Show a yellow note if `!is_recommended_k(k)`.
- *KDF memory (MiB)* — default `256`. *KDF iterations* — default `3`. Show a note if changed from 256/3:
  *"custom KDF cost is part of the credential and isn't stored — you must use the exact same values to decrypt."*

**Create tab:**
- *Size* — text, accept a byte count or `64k`/`512mb`/`2gb` (binary, 1024-based) — port the small
  parser from `azoth/src/main.rs` (`parse_size`).
- **Create** button → `Kpdc::create(size, k, kdf)` → `fs::write(file, c.as_bytes())`. On success, log
  the decoy-storage tip from `azoth/src/main.rs`'s Create handler.

**Write tab:**
- *Password* (masked: `TextEdit::singleline(..).password(true)`).
- *Plaintext* — a Data file (Browse) **or** a multiline text box (pick whichever is non-empty).
- *Known passwords* — multiline, one per line (every OTHER password already in the container).
- Checkboxes: **Re-randomize (recommended)** default ON; **I have supplied ALL passwords** (gates re-randomize).
- **Write** button:
  - `block = fs::read(file)`; `c = Kpdc::from_bytes(block, k, kdf)?`.
  - If re-randomize ON: require the all-keys checkbox (else error). For each known pw, `c.read(pw)` —
    if any returns `None`, abort with "a known password didn't decrypt; aborting so re-randomize
    doesn't destroy data." Collect `(pw, plaintext)` for all knowns, drop any equal to the target
    password, push `(target_pw, plaintext)`, then `c.write_all_fresh(&refs, DEFAULT_MAXPROBE)`.
  - If re-randomize OFF: `c.write(pw, &plaintext, &known_refs, DEFAULT_MAXPROBE, None)` (in-place).
  - `fs::write(file, c.as_bytes())`. Log the plane / payload count. Mirror the CLI's data-loss warnings.

**Read tab:**
- *Password* (masked). **Read** button → `from_bytes` → `read(pw, DEFAULT_MAXPROBE)`:
  - `Some(pt)` → either **Save to file…** (`rfd::save_file`, write bytes) or show as text
    (`String::from_utf8_lossy`) in an output box.
  - `None` → log "no payload for that password / K / KDF cost — just noise."

---

## 4. Don't freeze the UI

Argon2id at 256 MiB makes write/read take ~1s+ (and re-randomize does several). egui's `update()`
must not block. Run the crypto on a worker thread and pass the result back via an
`std::sync::mpsc` channel (store a `Option<Receiver<Result<String,String>>>` in the app, poll it in
`update`, append to the log when it arrives, and `ctx.request_repaint()` while a job is in flight).
For a first compile you may block inline, but switch to a worker thread before calling it done.

---

## 5. Build, package, verify

- Iterate: `cargo run -p azoth-gui` (use the gnu toolchain — see §0).
- Release exe: `cargo build --release -p azoth-gui` → `target/release/azoth-gui.exe` (single,
  self-contained — windows-gnu links statically; confirm no stray DLLs are needed).
- When it works, hide the console window: add to the very top of `gui/src/main.rs`:
  `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]`
  (keep the console during development so panics/errors are visible).

**Acceptance test (do this before declaring done):**
1. Create a 64k container, K from `next_prime_coprime8(419)`.
2. Write two secrets under two different passwords (re-randomize ON; second write lists the first
   password as known + checks all-keys).
3. Read each back with its password — both round-trip.
4. A wrong password → "no payload."

---

## 6. Rules

- **No new crypto.** Only call the `azoth` crate. If you think the library needs a change, stop and
  describe it rather than reimplementing anything.
- Keep secrets in `Zeroizing` where the library returns them; don't log plaintext or passwords.
- Match the CLI's warnings (bad K, custom KDF "remember it", re-randomize destroys-unsupplied-payloads).
- When done, commit `gui/`, the root `Cargo.toml`, and update `README.md` with a "GUI" build note,
  then push. Do **not** commit built binaries.
