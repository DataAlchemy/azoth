# azoth deniability challenge — independent security review

**Target:** `challenge_block.bin` (65,536 bytes) — an azoth "K-Plane Deniable Container",
K = 11, filled to capacity with 11 payloads (each under a distinct 24-char random password),
~98.5 % of bits carrying payload.

**Claim under attack:** the block is computationally indistinguishable from uniform random
bytes; without a password you cannot prove any payload exists, how many, or where, nor recover
the parameter `K`. An empty container and a full one are asserted statistically identical.

**Scope:** single snapshot, no passwords. Brute force is out of scope and infeasible (24-char
random passwords ≈ 150 bits, gated by Argon2id) and is *not* attempted.

---

## Verdict: NO BREAK FOUND

After a statistical battery against matched controls, an exhaustive residue/spectral sweep, a
K-recovery analysis, a multi-snapshot study, and a 10-lens adversarial source review, **no
single-snapshot, no-password distinguisher, leak, or implementation bug was found.** The
indistinguishability, unprovable-count, unprovable-location, and unrecoverable-`K` properties
hold under everything tested. The decisive "empty == full" separation test fails to separate on
*any* of 18 statistics.

One statistic (`res_ones_chisq_mod8`) initially flagged the challenge as an outlier; it was run
down and shown to be a single-block CSPRNG tail fluctuation that pure random data produces ~0.3 %
of the time and that the azoth construction does **not** induce — i.e. not a distinguisher.

The only real leak found is the **already-documented** one: multi-snapshot diffing of the
*in-place* (`--no-rerandomize`) write. It needs ≥2 images (we have one) and is defended by the
default re-randomizing write. Confirmed empirically and as a contrast below.

---

## Methodology

All controls were generated **from the real library** (`azoth/src/lib.rs`), so they are the same
statistical object as the challenge. KDF cost does not affect the byte distribution (per the
challenge and verified), so a cheap cost (Argon2id 1 MiB / 1 pass) was used to generate volume.

| Control set | n | What it is |
|---|---|---|
| `control_empty_*`  | 32 | fresh azoth containers, **no payload** (pure CSPRNG fill) |
| `control_full_*`   | 32 | azoth filled to **98.5 %** like the challenge (K=11, 11 × 5800-byte payloads) |
| `control_fullmax_*`| 4  | filled to plane capacity (~99.99 %) |
| `control_random` / `urandom.bin` | 2 | true uniform random |

Generators: `scripts/make_controls.rs`, `scripts/make_snapshots.rs` (copies of the
`azoth/examples/*.rs` used). Analyses: the Python scripts in `scripts/`. Captured outputs are in
`raw_output/`.

---

## Test inventory & results

### A. Statistical battery + the decisive test  (`scripts/battery.py` → `raw_output/battery.txt`)

18 statistics computed on the challenge and every control: byte chi-square, monobit, runs,
digram (byte-pair) chi-square, lag-1 serial correlation, residue-ones chi-square mod 7/8/11/88,
residue-byte chi-square mod 11, gzip/bz2/lzma ratios, Shannon & min-entropy, spectral max-power,
NIST block-frequency, cumulative-sums.

- **Challenge vs control distribution:** inside the control range on every statistic except the
  one mod-8 flag (below). E.g. byte chi-square 293.5 (controls 210–347), entropy 7.9968 bits/byte,
  all compressors ≥ 1.0 (incompressible).
- **Decisive "empty == full" test:** Welch-t and Mann-Whitney between the 32 empty and 32 full
  controls. **No statistic separates them** (all p ≫ Bonferroni α = 5.6e-4). The plane-targeted
  tests are clean: mod-11 ones p = 0.51, mod-8 p = 0.77, mod-11 byte p = 0.58.

  > A statistic that cannot tell a full container from an empty one cannot prove a payload exists.

**Directly answering the challenge's mod-11 hint:** no plane bias. `res_ones_chisq_mod11` = 10.70
(df 11, expected 11), z = −0.02 vs controls.

### B. The one flag, run down  (`scripts/investigate_mod8.py` → `raw_output/investigate_mod8.txt`)

`res_ones_chisq_mod8` (balance of the 8 within-byte bit positions) = 23.77 on the challenge,
above all 70 controls (z = 4.67). Investigated rather than dismissed:

- **Ordinary tail draw:** analytic χ²₈ tail p = 2.5e-3; empirically **~0.3 % of fresh
  `/dev/urandom` blocks equal or exceed it** (≈14/5000).
- **The construction does not produce it:** empty (mean 7.86) ≈ full (7.64) ≈ random (8.10),
  empty-vs-full p = 0.77. Since random data hits this value just as often, **no threshold
  separates azoth from random on it** — it cannot beat chance as a presence/count/location signal.
- Driven by within-byte bit positions 1 & 5, on which the plane/walk/layout do not depend
  (gcd(8,11)=1). A 1-of-18 multiple-comparison artifact; not significant after correction.

Looked like an "outlier vs 70 controls" only because 70 samples cannot bound a 0.3 % tail. Ten
independent code-review lenses re-derived the identical conclusion.

### C. Exhaustive residue + spectral capstone  (`scripts/capstone_fast.py` → `raw_output/capstone_fast.txt`)

- **Residue sweep K = 2..512** (analytic χ²_K): **no stride survives** familywise correction
  (α = 0.01/511). Smallest-p strides cluster at K = 4/8/20/38/76/190/218 — all even, artifacts of
  the harmless mod-8 fluctuation. True **K = 11 ranks 293/511** (p = 0.468).
- **Full bit-autocorrelation spectrum, all 262,143 lags** (one FFT): max |z| = 4.92 at lag 45191
  (a random lag) vs familywise threshold 5.50. Construction lags 8/11/88 are pure noise
  (z = −1.23, −0.12, +1.06). **No periodicity at the plane stride.**

### D. Can `K` be recovered?  (`scripts/k_analysis.py` → `raw_output/k_analysis.txt`)

- **From the single block: no.** True K = 11 is invisible (residue p = 0.47, rank 293/511). An
  attacker guessing K from residue bias would pick K = 4/8/20 — the **wrong** value. We only
  "know" K = 11 because the challenge stated it; `K` is a secret credential sent out-of-band.
- **The only K leak** (documented §8) — multi-snapshot diff of an *in-place* write — was
  demonstrated on our own snapshots: `GCD(changed-bit-position differences) = 11` recovers K with
  no password; and the **default re-randomize write defends it** (a re-randomized write changes
  50.0 % of bits across all 11 residue classes, GCD = 1).

### E. Multi-snapshot study  (`scripts/multisnapshot.py` → `raw_output/multisnapshot.txt`)

32 successive snapshots of the same 11-payload set, both write modes; per-position
change-frequency and "never-changing" maps:

| | DEFAULT re-randomize | in-place (`--no-rerandomize`) |
|---|---|---|
| never-changing positions | **0** | 7904 (= the unwritten slots, **1.51 %**) |
| change-freq map | flat ~0.5000 (max-dev z=4.49 < expected-max 5.13 → noise) | bimodal: ~0.5 on written, **exactly 0** on unwritten |
| per-plane (mod 11) static counts | — | `[719×6, 718×5]` — **matches the 6-vs-5 plane-size split** |
| leak | **nothing** | written/unwritten partition → presence/size/count/location |

> **Answer to "does multi-snapshot of the default full container show anything?": no.** Every
> bit (written and unwritten) is re-randomized each snapshot, so no position is static, there is
> no payload boundary, no count, and no `K`. The in-place mode leaks the partition — which is
> exactly why `write_all_fresh` is the CLI default.

### F. Adversarial source review — 10 lenses  (`raw_output/code_review_10lens.json`)

Ten independent reviewers (key/position derivation, `home()` rejection, `SlotWalk`, plane
geometry, plane-lookup/occupancy, field masking, bit/byte packing, Rust-vs-Python diff,
fill-to-capacity, creative side-channels), each finding-then-adversarially-verified.
**0 confirmed single-snapshot breaks.** Highlights:

- Plane partition verified a **perfect bijection** of all 524,288 bits (no double/unwritten/lost
  edge bits); the 6-vs-5 size split is a public function of (B,K), leaks nothing.
- `home()` and `SlotWalk` rejection sampling **unbiased** (the u64::MAX-vs-2⁶⁴ nuance only bites
  for power-of-two moduli, which coprime-to-8 K forbids).
- LEN field (only plaintext-derived field) XORed with a fresh per-write pad: **zero correlation
  with true length** (r = 0.03 over 120 writes).
- A **logistic-regression classifier** (21 features, 120 full vs 120 random) scored 0.487 CV
  accuracy — *below* the random-vs-random null 0.506 ⇒ zero learnable signal.
- FFT power at the period-11 plane stride: 3.08, p = 0.047 — matches analytic noise.
- Every lens independently re-found the mod-8 flag and ruled it a fluctuation, and noted the
  in-place multi-snapshot leak as the only real (documented, out-of-scope) tell.

### G. Decryption

Not possible without a password. Argon2id over 24-char random passwords (~150 bits), no leaked
key material in the repo or git history (`challenge_solution.txt` is gitignored and absent),
standard AE core with no shortcut. Every wrong-password read returns "just noise," as designed.

---

## Accepted limitations (out of scope / by design — not breaks)

1. **Offline guess oracle** — anyone holding the blob can test `(password, K, cost)` guesses,
   gated only by Argon2id. The most likely *real-world* compromise; unrelated to deniability.
2. **Computational, not information-theoretic** — rests on SHAKE256/HMAC/Argon2id being PRFs.
3. **Multi-snapshot of in-place writes leaks K/location** (shown in E/D) — defended by default.
4. **Existence of a high-entropy blob** is not hidden — azoth hides *what/how much*, not *that*.

---

## Reproduction

```bash
cd /prod/multicrypt

# 1) build controls from the real library (cheap KDF; distribution is cost-independent)
cargo build --release --manifest-path azoth/Cargo.toml --example make_controls
cargo build --release --manifest-path azoth/Cargo.toml --example make_snapshots
mkdir -p controls snapshots
head -c 65536 /dev/urandom > controls/urandom.bin
( cd controls && /prod/multicrypt/azoth/target/release/examples/make_controls 32 32 )
azoth/target/release/examples/make_snapshots 32 snapshots

# 2) run the battery (scripts expect to run from the repo root)
python3 secrev/scripts/battery.py
python3 secrev/scripts/investigate_mod8.py
python3 secrev/scripts/capstone_fast.py
python3 secrev/scripts/multisnapshot.py
# k_analysis.py additionally needs two in-place snapshots in /tmp/ksnap (see its header)
python3 secrev/scripts/k_analysis.py
```

Note: the Python scripts read `challenge_block.bin`, `controls/`, and `snapshots/` by relative
path, so run them from `/prod/multicrypt`. Empirical (simulation-based) numbers vary slightly per
run; analytic numbers are exact.

---

## File manifest

```
secrev/
  README.md                         this document
  scripts/
    battery.py                      18-stat battery + decisive empty-vs-full test
    investigate_mod8.py             run-down of the single flagged statistic
    capstone_fast.py                residue sweep K=2..512 + full autocorrelation spectrum
    k_analysis.py                   K-recovery analysis + multi-snapshot K-leak demo
    multisnapshot.py                rerand vs in-place multi-snapshot maps
    make_controls.rs                Rust: build empty/full/random controls from the library
    make_snapshots.rs               Rust: build successive snapshots (both write modes)
  raw_output/
    battery.txt
    investigate_mod8.txt
    capstone_fast.txt
    k_analysis.txt
    multisnapshot.txt
    code_review_10lens.json         10-lens adversarial source review result
```
