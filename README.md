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
| 🜁 **Plausibly deniable** | Reveal one password under pressure; against an inspector without the others, their existence stays computationally deniable. |
| 🜃 **No verifier** | The container never confirms a password. A wrong guess just yields more noise — no oracle, no tell. |

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
cd azoth && cargo build --release
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
> default Argon2id **256 MiB / 3 passes**) is part of the credential and is **not stored**:
> if you change it you must remember the exact values to decrypt, or the data is lost.
> Re-randomize is **on by default**; use `--no-rerandomize` for a faster in-place write
> that leaves a multi-snapshot diffing fingerprint.

The **Python reference** (`kpdc_reference.py`) mirrors this for readability — run
`python3 kpdc_reference.py` for the same self-test. **Note:** the Python and Rust
containers are *not* wire-compatible (different KDF and slot walk); each reads only its own.

## ✦ Map of the repo

| Path | What |
|---|---|
| [`azoth/`](azoth/) | **The Rust implementation** — `azoth` library crate + CLI (`create`/`write`/`read`). The real, fast one. |
| [`kpdc_reference.py`](kpdc_reference.py) | The **readable reference** (Python stdlib, no deps). Clarity over speed; mirrors the spec. |
| [`_bmad-output/.../8pdc-spec-draft.md`](_bmad-output/brainstorming/8pdc-spec-draft.md) | **The design spec (v0.3)** — threat model, algorithms, honest weaknesses from an adversarial review. |
| [`_bmad-output/.../brainstorming-session-2026-06-06.md`](_bmad-output/brainstorming/brainstorming-session-2026-06-06.md) | The brainstorming log that produced the design (14 building blocks → adversarial pass). |

## ✦ Pinned primitives

**Argon2id** (memory-hard KDF; the Python reference uses scrypt) · **SHAKE256** (XOF/PRF) · **SHA-256** (fast hash) · **HMAC-SHA256** (integrity).

## ⚠ Status & honest scope

Brainstorm output — **experimental, not security-audited. Do not protect anything real with it yet.**
v1 targets deniability against a *single-look* inspector; multi-snapshot diffing (imaging the block
before & after a write) is a known gap deferred to a V2 *whole-block re-randomize* mode — see spec
§4 and §11. The Rust crate hardens the reference with **Argon2id** (configurable, credential-bound
cost), **rejection-sampled** slots (no modulo bias), **constant-time** tag/token compares, **zeroized**
key material, and **atomic** container writes. Two caveats remain by design: a *correct guess* still
compromises that payload (the token is an offline oracle gated only by the KDF — use a strong password
and high KDF cost), and the multi-snapshot gap above. The Python reference favors clarity over all of this.

And remember: azoth hides *what* and *how much*, not *that a high-entropy blob exists* — pair it
with a plausible cover (disk free space, a "wiped" partition, or a benign decoy payload).

<div align="center">

*solve et coagula*

</div>
