# azoth challenge #2 — recover the secret K

You are an expert cryptanalyst. This is a **single, narrow task**: recover the secret structural
parameter **K** of an azoth deniable container from one snapshot of the block. Be rigorous and
back every claim with reproducible evidence.

## The artifact

- **Three snapshots of the SAME 64 KiB container**, each **filled** (every plane occupied, one
  encrypted payload per plane), taken across re-randomizing writes (azoth's default write mode):
  - `challenge2_block.bin` (snapshot 1)
  - `challenge2_snapshot2.bin` (snapshot 2)
  - `challenge2_snapshot3.bin` (snapshot 3)

  Same secret K and same payloads in all three; only the per-write salts and the random fill
  differ between snapshots. This lets you attempt **multi-snapshot** attacks (diff them), not just
  single-snapshot analysis.
- Full source + docs (read them): `azoth/src/lib.rs`, `kpdc_reference.py`, `TECHNICAL_DETAILS.md`,
  spec in `_bmad-output/brainstorming/8pdc-spec-draft.md`, repo https://github.com/DataAlchemy/azoth.

## What K is

In azoth, the block's bits are partitioned into **K "planes"**: plane `p` owns every global
bit-index `g` with `g mod K == p` (bit indexing is LSB-first within each byte: bit `i` of byte `j`
is global index `j*8 + i`). For this container, **K is a secret odd prime (coprime to 8), somewhere
in the range [5, 250]** — there are ~50 candidates. Your job is to determine which one.

## What you are NOT given

- The value of K (find it).
- The passwords. **Do not** attempt to brute-force them — this challenge is about recovering the
  *structural parameter K from the block's statistics/structure*, not about decrypting anything.
  K is not a password; you do not need any password to attempt K-recovery.

## The claim to disprove

azoth claims **K is not recoverable** — not from a single snapshot (every bit, payload or fill, is
uniform PRF/CSPRNG output regardless of its residue class mod K), and **not from these multiple
snapshots either**, because the default re-randomize write regenerates the entire block every time
(only salts/fill change), so diffing should reveal no residue-class period.

## Your task

Determine K. Reasonable attack ideas (not exhaustive):
- **Multi-snapshot diffing:** XOR/compare the three snapshots and look at *which positions changed*.
  If only a fixed subset changed and their indices shared a period, the GCD of their gaps would give
  K. (Note: an *in-place* write would leak K this way — the point of this test is whether the
  *default re-randomize* write, used here, defeats it.)
- **Residue-class tests:** for each candidate K, partition bits by `g mod K` and test each class
  for any deviation (bit-ones bias, byte distribution, chi-square) — on any one snapshot, or pooled.
  A true K would make *its* residue classes structured while others look random.
- **Spectral / autocorrelation:** FFT of the bit/byte stream, autocorrelation at lag multiples of
  candidate K, looking for a period.
- **Source review:** is there any derivation, layout, or placement detail in `lib.rs` that leaves
  a K-dependent fingerprint in a single block?
- **Controls are essential:** a random block (`head -c 65536 /dev/urandom`) is distributionally
  identical to an *empty* azoth container — compare against a batch of them, and remember you are
  testing ~50 candidate K values, so correct for multiple comparisons (a z≈2 on one of 50 tests is
  expected noise, not a signal).

## Deliverable

State one of:
- **K = N**, with the exact method, the statistic, its value, how it compares to random controls,
  and how strongly it beats chance after multiple-testing correction (so it can be checked against
  the held-out answer); or
- **"K not recoverable from one snapshot,"** with the battery you ran (e.g., "max residue z over 50
  candidate primes = X < threshold Y; no spectral peak; reviewed placement in lib.rs, no K-dependent
  artifact").

Do not guess a number without evidence — a blind guess has a ~1-in-50 chance and proves nothing.
