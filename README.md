# azoth — K-Plane Deniable Container (KPDC)

> *Azoth* — the alchemists' hidden universal essence, the secret agent of transmutation.

A deniable encryption container: a fixed-size block of random-looking bytes that holds
up to **K** independent encrypted payloads. Without the correct `(password, K)` the block
is computationally indistinguishable from random data — there is no stored header, index,
or count, and no party (including the owner) can prove how many payloads it contains.

Different passwords decrypt to completely different plaintexts from the same block.

## Contents

- **[`_bmad-output/brainstorming/8pdc-spec-draft.md`](_bmad-output/brainstorming/8pdc-spec-draft.md)**
  — the design spec (v0.3), including the threat model, algorithms, and an honest
  weaknesses section from an adversarial review.
- **[`_bmad-output/brainstorming/brainstorming-session-2026-06-06.md`](_bmad-output/brainstorming/brainstorming-session-2026-06-06.md)**
  — the brainstorming session log that produced the design (14 building blocks + adversarial pass).
- **[`kpdc_reference.py`](kpdc_reference.py)** — a dependency-free (Python stdlib) reference
  implementation. Run `python3 kpdc_reference.py` for a self-test.

## The four properties

1. **Oversized** — block ≥ ~10× total payload; plane size (`8B/K`) is the per-item cap.
2. **Multi-payload** — up to `K` independent payloads, one per disjoint "plane".
3. **Indistinguishable** — empty and full blocks are byte-statistically identical.
4. **Multi-key** — each password yields its own plaintext; wrong credential → noise.

## How it works (one paragraph)

The block's bits are partitioned into `K` disjoint **planes** (bit-index ≡ k mod K, with K
prime and coprime to 8 so planes cut diagonally across the byte grid). Each payload is
AEAD-style encrypted under a key derived from `(password, K)` via a memory-hard KDF, then
its bits are scattered along a SHAKE-driven walk **within one plane**. A password hashes to
a home plane and is found by open-addressed probing; recognition is a per-write token +
HMAC tag, both invisible without the key. Empty slots stay as the original random fill.

## Status & scope

Brainstorm output, **not security-audited**. v1 targets deniability against a single-look
inspector; multi-snapshot diffing is a known gap deferred to a V2 whole-block re-randomize
mode (see spec §4 and §11). The reference implementation is for clarity, not production
(see header notes: modulo bias in slot selection, low scrypt cost, etc.).

## Pinned primitives

scrypt (memory-hard KDF) · SHAKE256 (XOF/PRF) · SHA-256 (fast hash) · HMAC-SHA256 (integrity).
