# azoth challenge #2 — recover the secret K

You are an expert cryptanalyst. This is a **single, narrow task**: recover the secret structural
parameter **K** of an azoth deniable container from one snapshot of the block. Be rigorous and
back every claim with reproducible evidence.

## The artifact

- **`challenge2_block.bin`** — a **65,536-byte (64 KiB)** azoth container, **filled** (every plane
  is occupied: one encrypted payload per plane).
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

azoth claims **K is not recoverable from a single snapshot**: because every bit — payload or
fill — is uniform PRF/CSPRNG output regardless of which plane (residue class mod K) it sits in,
no statistical or structural test on one block should reveal K.

## Your task

Determine K. Reasonable attack ideas (not exhaustive):
- **Residue-class tests:** for each candidate K, partition bits by `g mod K` and test each class
  for any deviation (bit-ones bias, byte distribution, chi-square). A true K would make *its*
  residue classes structured while others look random.
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
