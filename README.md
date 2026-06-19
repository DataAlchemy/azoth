<div align="center">

# ⚗️ azoth

### one block of noise · many secrets · nothing to find without the key

![CI](https://github.com/DataAlchemy/azoth/actions/workflows/ci.yml/badge.svg)
![license](https://img.shields.io/badge/license-MIT-blue)
![status](https://img.shields.io/badge/status-experimental-orange)
![not audited](https://img.shields.io/badge/security-NOT%20audited-red)
![deniable](https://img.shields.io/badge/property-deniable-blueviolet)
![planes](https://img.shields.io/badge/payloads-up%20to%20K-success)

> *Azoth* — the alchemists' hidden universal essence, the secret agent of transmutation.
> Here it's a container that turns a block of pure randomness into as many secrets as you like.

</div>

---

```
        ┌─────────────────────────────────────────────────────────────┐
   disk │  9f a3 0c e7 5b 11 c4 8d 2a f0 71 b9 …  (looks like /dev/urandom)
        └─────────────────────────────────────────────────────────────┘
                 ▲                ▲                ▲
            password A       password B       password C?  …or nothing?
                 │                │                  (you can't prove it either way)
          "evac at dawn"   "harmless decoy"
                 └── same bytes ──┴── different truths ──┘
```

**azoth** is a deniable-encryption container. A fixed-size block of random-looking bytes
holds **up to `K` independent encrypted payloads**. Without the right `(password, K)` the
block is computationally **indistinguishable from random data** — no header, no index, no
count — and **no one, not even the owner, can prove how many secrets are inside.** Two
different passwords decrypt two completely different plaintexts from the very same block.

---

## ✦ What makes it different

| Property | What it means |
|---|---|
| 🜂 **Indistinguishable** | An empty block and a full one are byte-for-byte statistically identical. There is nothing to find. |
| 🜄 **Many-in-one** | Up to `K` payloads share one block, each on its own disjoint "plane." Set `K` as high as you want. |
| 🜁 **Deniable in isolation** | Found *without you and without this tool*, the block reveals nothing about whether — or how many — payloads it holds. This does **not** cover the tool's traces or being compelled to run it; see [What azoth does NOT hide](#what-azoth-does-not-hide-read-this-first). |
| 🜃 **No verifier an outsider can use** | No header, no fixed marker. The token that recognizes a correct password is random-looking and sits at a *credential-derived, scattered* position — without a candidate `(password, K, cost)` you can't find it, test it, or even tell data exists. Supply a candidate and it *does* confirm a correct guess: an offline oracle gated by the memory-hard KDF (use a strong password), not honey-encryption. |

## ✦ The trick, in one breath

The block's bits are sliced into `K` disjoint **planes** (bit-index ≡ k mod `K`, with `K`
prime and coprime to 8 so the planes cut diagonally across the byte grid). Each payload is
encrypted under a key derived from `(password, K)` via a memory-hard KDF, then its bits are
**scattered along a pseudo-random walk inside one plane**. A password hashes to a home plane
and is found by open-addressed probing; a per-write token + HMAC tag confirm the read — both
invisible without the key. Unused slots keep their original randomness. *Empty looks like full
looks like noise.*

## ✦ Try it (Rust — the real implementation)

```bash
cargo build --release -p azoth-cli        # the Linux/Unix CLI
BIN=./target/release/azoth

K=$($BIN prime 419)                                   # a good K: prime, coprime to 8
$BIN create --size 65536 --k $K --out vault.bin       # 64 KiB of pure randomness

# Each write re-randomizes the WHOLE block (multi-snapshot safe) and so requires
# every existing password via --known, plus --all-keys to confirm.
printf 'the treaty is signed at dawn' | $BIN write --file vault.bin --k $K --password alice --data - --all-keys
printf 'meet at pier 39, midnight'    | $BIN write --file vault.bin --k $K --password bob   --data - --known alice --all-keys

$BIN read --file vault.bin --k $K --password alice     # -> the treaty is signed at dawn
$BIN read --file vault.bin --k $K --password bob       # -> meet at pier 39, midnight
$BIN read --file vault.bin --k $K --password mallory   # -> error: just noise
```

As a library:

```rust
use azoth::{Kpdc, KdfParams, next_prime_coprime8};

let k = next_prime_coprime8(419);
let mut c = Kpdc::create(65536, k, KdfParams::default())?;    // 64 KiB of randomness
// Whole-block re-randomize: rebuild from ALL payloads (anything omitted is destroyed).
c.write_all_fresh(&[
    ("alice", b"the treaty is signed at dawn"),
    ("bob",   b"meet at pier 39, midnight"),
], 64)?;

c.read("alice", 64);   // Some(b"the treaty is signed at dawn")
c.read("bob",   64);   // Some(b"meet at pier 39, midnight")
c.read("mallory", 64); // None  (just noise)
// (Kpdc::write(...) still exists for an in-place, non-re-randomizing write.)
```

> **Operational notes.** Omit `--password` and azoth prompts without echo — preferred,
> since CLI args leak via `ps`/history. The **KDF cost** (`--kdf-mem-mib`/`--kdf-iters`,
> default Argon2id **256 MiB / 3 passes**) and the **payload cipher** (`--cipher`, default
> `aes-ctr`; also `chacha20` / `shake256`) are part of the credential and are **not stored**:
> change either and you must supply the exact same values to decrypt, or the data is lost
> (a wrong cipher fails cleanly, just like a wrong password — never garbage). **Migration:**
> containers written before the cipher option existed use the SHAKE256 keystream — read them with
> `--cipher shake256` (that mode's on-disk format is byte-identical to the original).
> Re-randomize is **on by default**; use `--no-rerandomize` for a faster in-place write
> that leaves a multi-snapshot diffing fingerprint.

### Writing straight to a raw device (no filesystem)

A whole unformatted block device full of random bytes is a strong cover ("blank/wiped stick"),
with no filesystem metadata. Point azoth directly at the device — `--raw` is auto-enabled for
block devices, and `create` auto-detects the size:

```bash
sudo azoth create --raw --out /dev/sdX --k "$(azoth prime 419)"   # fills the WHOLE device
sudo azoth write  --raw --file /dev/sdX --k <K> --password ... --data secret.txt --known ... --all-keys
sudo azoth read   --file /dev/sdX --k <K> --password ...
```

Caveats: needs root; the whole device is read into RAM per operation; the default re-randomize
rewrites the entire device on every write (slow over USB, and it burns flash cycles — occasional
use only); fill the **entire** device (don't leave a structured tail); and "2 GB" sticks are
usually a bit under — the auto-detected size is authoritative.

The **Python reference** (`kpdc_reference.py`) mirrors this for readability — run
`python3 kpdc_reference.py` for the same self-test. **Note:** the Python and Rust
containers are *not* wire-compatible (different KDF and slot walk); each reads only its own.

## ✦ Native GUI (Windows)

A small native-Windows front-end (egui / [eframe](https://crates.io/crates/eframe)) lives in
[`win/`](win/): **Create · Write · Read** tabs, a shared inputs block (container file, `K`, KDF
cost), and a status-log pane. It calls the shared `azoth` core — **no new crypto** — and mirrors
the CLI's warnings (non-prime `K`, custom KDF cost, re-randomize data-loss). Argon2id runs on a
worker thread, so the window never freezes.

**Download:** prebuilt, self-contained Windows binaries — `azoth-gui.exe` (GUI) and `azoth.exe`
(CLI) — are attached to every [release](https://github.com/DataAlchemy/azoth/releases/latest)
(built on CI; no runtime to install). Or build from source:

**Build with Rust's GNU toolchain (no Visual Studio needed):**

```powershell
rustup toolchain install stable-x86_64-pc-windows-gnu

# Modern windows-sys crates use raw-dylib, so building for windows-gnu needs a complete
# MinGW-w64 — specifically the GNU assembler `as.exe`, which the toolchain's bundled linker
# does NOT include. e.g. via MSYS2:  pacman -S mingw-w64-x86_64-toolchain
$msys = 'C:\msys64\mingw64\bin'
$env:Path = "$msys;$env:Path"
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER    = "$msys\gcc.exe"
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS = '-Clink-self-contained=no'

cargo run   -p azoth-gui                   # build & launch the GUI
cargo build -p azoth-gui --release         # -> target/release/azoth-gui.exe
cargo build -p azoth-cmd --release         # the Windows CLI (-> target/release/azoth.exe)
cargo test  -p azoth     --release         # shared-core round-trip: create -> 2 writes -> read-back
```

> Don't build on a **network / UNC drive** — the MinGW linker can't use UNC paths and Windows
> blocks executing build scripts from a share. Work from a local copy, or point
> `CARGO_TARGET_DIR` at a local disk.

## ✦ Map of the repo

| Path | What |
|---|---|
| [`core/`](core/) | **Shared core** — the `azoth` library crate: KPDC crypto + the create/write/read app orchestration every front-end calls. The real, fast one. |
| [`cli/`](cli/) | **Linux/Unix CLI** (`azoth`) — create/write/read, with raw block-device support. |
| [`cmd/`](cmd/) | **Windows CLI** (`azoth`) — the same model, Windows-tailored (no raw-device handling). |
| [`win/`](win/) | **Windows GUI** (egui) — a Create/Write/Read front-end over the core. |
| [`TECHNICAL_DETAILS.md`](TECHNICAL_DETAILS.md) | **In-depth write-up & self-review** — full construction, rationale, rejected designs, and exactly how we tested security (statistical suite + KAT + fuzz + a 4-round multi-agent adversarial review). |
| [`kpdc_reference.py`](kpdc_reference.py) | The **readable reference** (Python stdlib, no deps). Clarity over speed; mirrors the spec. |
| [`_bmad-output/.../8pdc-spec-draft.md`](_bmad-output/brainstorming/8pdc-spec-draft.md) | **The design spec (v0.3)** — threat model, algorithms, honest weaknesses from an adversarial review. |
| [`_bmad-output/.../brainstorming-session-2026-06-06.md`](_bmad-output/brainstorming/brainstorming-session-2026-06-06.md) | The brainstorming log that produced the design (14 building blocks → adversarial pass). |

## ✦ Pinned primitives

**Argon2id** (memory-hard KDF; the Python reference uses scrypt) · **SHAKE256** (XOF/PRF) · **SHA-256** (fast hash) · **HMAC-SHA256** (integrity) · **payload cipher** — AES-256-CTR (default), ChaCha20, or SHAKE256-keystream, selectable via `--cipher` and bound into the token so a wrong choice fails cleanly.

## ⚠ Status & honest scope

Brainstorm output — **experimental, not security-audited. Do not protect anything real with it yet.**
Exactly what it does, why, and **how we tested it was secure** — the statistical suite, the Known
Answer Test, fuzzing, and a four-round multi-agent **adversarial self-review** — is documented in
detail in **[`TECHNICAL_DETAILS.md`](TECHNICAL_DETAILS.md)** (see §10 rejected designs, §11 testing).
The Rust crate hardens the reference with **Argon2id** (configurable, credential-bound cost),
**rejection-sampled** slots (no modulo bias), **constant-time** tag/token compares, **zeroized**
key material, and **atomic** container writes. **Multi-snapshot diffing** (imaging the block before
and after a write) is **defended by default** via whole-block re-randomization — every write
regenerates the entire block, so nothing is localizable (`--no-rerandomize` opts out for a faster
in-place write that is *not* multi-snapshot-safe; see spec §4 and `TECHNICAL_DETAILS.md` §8). The
main caveat that remains **by design**: a *correct guess* of the credential compromises that payload
(the token is an offline oracle gated only by the KDF — use a strong password and high KDF cost).
The Python reference favors clarity over all of this.

### What azoth does NOT hide (read this first)

⚠ azoth makes a **block of bytes** indistinguishable from random. That is the whole claim, and it is
narrow. It hides *what* and *how much* is in the block — **to someone who finds the block alone.**
It does **not** hide:

- **that a high-entropy blob exists** — pair it with a plausible cover for randomness (disk
  free/slack space, a "wiped" partition);
- **that you use azoth** — the binary, package records, and shell history (`azoth read --file …`)
  all point at you, and the bytes' uniformity does nothing about that;
- **anything under coercion.** If you are compelled to decrypt, running a tool *built to hold hidden
  payloads* tells the adversary more may exist — and coercion runs on **suspicion, not proof**, so
  they need not accept that you've revealed everything. A "decoy you reveal under pressure" is **not**
  a defense (the construction is public; an adversary who knows it just keeps coercing), and we no
  longer recommend framing it that way.

So: deniable **in isolation**, for a blob found *without you and without the tool* — not a way to
beat an interrogation. Beating coercion is not a problem cryptography can solve. See
[`TECHNICAL_DETAILS.md`](TECHNICAL_DETAILS.md) §2 ("Operational / coercion deniability — NOT
provided").

<div align="center">

*solve et coagula*

</div>
