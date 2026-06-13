# azoth deniability challenge — break this

You are an expert cryptanalyst and security researcher. Your job is to **break a specific claim**
made by a deniable-encryption tool called **azoth** (a "K-Plane Deniable Container"). Be
adversarial, rigorous, and skeptical — assume the claim is false and try to prove it.

## The artifact

- **`challenge_block.bin`** — a **65,536-byte (64 KiB)** file. It is an azoth container that has
  been **filled to capacity**: **11 independent payloads** were written into it, each under a
  distinct, randomly-generated **24-character password** (~150 bits of entropy each). ~98.5% of
  the block's bits carry payload.
- The full **source code and documentation** are available — read them critically:
  - Implementation: `azoth/src/lib.rs`
  - Readable reference: `kpdc_reference.py`
  - Design + testing write-up: `TECHNICAL_DETAILS.md` (see §4 construction, §7 properties, §9
    limitations, §14 "for reviewers")
  - Spec: `_bmad-output/brainstorming/8pdc-spec-draft.md`
  - Repo (public): https://github.com/DataAlchemy/azoth

## What you are given

- The block file.
- The full source + docs.
- The container parameters: **K = 11**, KDF = **Argon2id (m = 64 MiB, t = 3, p = 1)**.
  Note: the KDF cost has **no effect on the block's byte distribution** — it only sets brute-force
  cost — so this is the same statistical object as one built at the shipped 256 MiB default. You
  may generate fresh containers (empty or full) from the source at any cost to use as controls.

## What you are NOT given

- **The 11 passwords.** They are 24 random characters each. Brute-forcing them is **out of scope
  and infeasible** — do not attempt it. "Given unbounded compute you could guess the password" is
  **not** a break; it's the documented, accepted limitation (the offline-guess oracle gated by the
  KDF). This challenge is about the *deniability*, not the password strength.

## The claim to disprove

azoth claims this block is **computationally indistinguishable from uniform random bytes** to
anyone without the credential — that you **cannot prove any payload is encrypted in it**, nor how
many, nor where. An empty container and a full one are asserted to be statistically identical.

## Your task

Demonstrate, **better than random chance**, any of:
1. that the block contains hidden encrypted data at all (a distinguisher from random);
2. how many payloads it holds;
3. the location of any payload's bits; or
4. any plaintext / key / position information.

Attack along any axis:

- **Statistical distinguishers** — byte/bit frequency, chi-square, runs, digram/n-gram, serial
  correlation, FFT/spectral, compressibility, entropy estimators, NIST-style suites — any test
  that separates `challenge_block.bin` from `/dev/urandom`. **Generate your own controls:** a
  random block (`head -c 65536 /dev/urandom > control.bin`) and one or more *empty* azoth
  containers built from the source. If you can't reliably tell the challenge block apart from
  those, the claim holds.
- **Structural / residue analysis** — any header, marker, fixed-position artifact, alignment, or
  bias. You know K = 11, so specifically: is there any detectable bias in the residue classes
  `g ≡ p (mod 11)` (the "planes")? Any leak of which planes are occupied?
- **Source-code review** — find a real bug or design flaw in the key/keystream/position
  derivations, salt handling, the SHAKE-driven slot walk, the open-addressed plane lookup, or the
  on-walk layout that leaks the presence/count/location of payloads or makes the output
  distinguishable from random. Read `lib.rs` adversarially.
- **Anything else** — be creative (timing, side channels in the code, etc.).

## Ground rules

- This is a **deniability / indistinguishability** challenge, not a brute-force challenge.
- **Back every claim with reproducible evidence**: exact commands, code, numbers, significance,
  and a comparison against a random control and/or a freshly-built empty container. A distinguisher
  must beat chance with a stated, defensible significance level.
- Do not hand-wave. "There might be a bias" is not a result; "residue-class-mod-11 chi-square = X
  on the challenge vs Y on random/empty controls, p < Z, reproducible via <command>" is.

## Deliverable

A clear verdict, one of:
- **(a) BREAK:** a concrete, reproducible distinguisher or leak — the exact mechanism, the code to
  reproduce it, the numbers, and how strongly it beats chance; or
- **(b) NO BREAK FOUND:** an explicit statement, plus the full battery of tests you ran and their
  results (including the strongest negative results, e.g. "byte chi-square 293 vs control 248/271;
  no mod-11 residue bias at p<0.01; no compressibility; reviewed derivations X/Y/Z, found no
  presence/count leak").

Be specific and honest. Don't claim a break you can't demonstrate, and don't declare victory for
the design without actually running the tests.
