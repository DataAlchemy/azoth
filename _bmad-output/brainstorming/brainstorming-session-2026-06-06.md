---
stepsCompleted: [1, 2]
inputDocuments: []
session_topic: 'Designing a buildable deniable encryption scheme: a data block >=10x payload size, holding many independent payloads, indistinguishable from random without a key, where different passwords decrypt to completely different plaintexts'
session_goals: 'Converge toward a buildable spec; prioritize deniability/indistinguishability above all, with a strong lean toward theoretical (provable/information-theoretic) strength'
selected_approach: 'ai-recommended'
techniques_used: ['First Principles Thinking', 'Cross-Pollination + Analogical Thinking', 'Morphological Analysis']
ideas_generated: 14
ideas_generated: []
context_file: ''
---

# Brainstorming Session Results

**Facilitator:** Xhi
**Date:** 2026-06-06

## Session Overview

**Topic:** Designing a buildable deniable encryption scheme with these properties:
1. Ciphertext block is at least 10x the payload size (expandable larger by choice).
2. Many independent payloads can be stored in the same block simultaneously.
3. Without the correct password it is impossible to tell whether anything is encrypted at all (indistinguishable from random/empty data).
4. Different passwords decrypt to completely different plaintexts from the same block.

**Goals:** Converge toward a buildable spec. Priority order: deniability/indistinguishability first, theoretical strength a close second, practicality third.

### Context Guidance

This is the territory of *deniable encryption*, *steganographic file systems*, and *plausible-deniability* constructions (e.g., VeraCrypt hidden volumes, Rubberhose/StegFS, honey encryption, all-or-nothing transforms). The user's specific combination of constraints defines its own design space.

### Session Setup

- Outcome target: a concrete, implementable design with defined components and threat model.
- Priority weighting: deniability above all, then theoretical/provable strength, then practicality.

## Technique Execution Results

We ran First Principles -> Cross-Pollination -> Morphological convergence and landed on a
buildable skeleton: the **Eight-Plane Deniable Container (8PDC)**. Full spec in
[`8pdc-spec-draft.md`](./8pdc-spec-draft.md).

### Ideas / building blocks generated

- **#1-#5 (First Principles / Laws):** L1 no cleartext structure; L2 empty==full (random fill);
  L3 unprovable count even to the owner; L4 all-keys-to-add; L5 no system verifier (every
  password "works").
- **#6 Bit-Plane Slots:** 8 disjoint bit-planes (bit 0..7), one payload each -> structural
  collision-freedom.
- **#7 Circular Stride Walk:** positions `(start + i*stride) mod p`, prime block -> full-period
  scatter; the password defines the geometry, location IS the secret.
- **#8 Scope decision:** outsider-deniable, not brute-force-immune (drop honey super-power).
- **#9 Recognition token as index-free plane selector:** reader sweeps planes, token self-identifies.
- **#10 Sizing rule:** B >= 10x sum, 100x largest item -> implicit ~8-item cap.
- **#11 Encrypt-then-Scatter:** payloads are encrypted; recognition = decrypt/token success, not by eye.
- **#12 Per-write salt:** fresh token + keystream each write -> semantic security + snapshot resistance.
- **#13 Configurable interleaved planes + open addressing:** K planes by bit-index residue mod K;
  hash-to-home + linear probe lifts the 8-cap to K; legit reads cheap, wrong-credential reads costly.
- **#14 Secret byte-coprime plane count:** K (prime, e.g. 419) is a secret second factor folded into
  all derivations; coprime to 8 -> planes cut diagonally across bit-positions, whitening layout.

Design generalized from fixed 8-plane (8PDC) to K-plane (KPDC). Current spec: v0.3.

### Adversarial pass (Phase 4)

Attacked KPDC across single-snapshot stats, multi-snapshot diffing, chosen/known plaintext,
open-addressing fingerprints, partial-credential coercion, malleability, and timing.

- **Core crypto sound under a single look** (all stored fields are uniform PRF/random).
- **Real break found:** multi-snapshot diffing leaks `K` (GCD of changed positions = K) and
  payload footprints. -> scoped out for v1; V2 fix = whole-block re-randomize per write,
  which L4 enables for free. (User: nice for V2, out of scope now.)
- **Deployment trap:** a random blob is itself suspicious -> user supplies cover medium /
  benign decoy. (User: agreed, user's responsibility.)
- **Fixed in v0.3:** added encrypt-then-MAC integrity (A3).
- **Clarified:** `K` is config + whitener, ~0 security bits; all strength rests on `pw` (A5).
- Out of scope: read-timing side channel (A4).

### Breakthrough moment

The user's "put them in bits" reframed collision-avoidance from an allocation problem into a
structural partition (disjoint bit-planes), which dissolved the corruption problem entirely and
made the rest of the design fall out. The recognition token + salt then provided index-free,
verifier-light plane selection.

### Open weaknesses (carried forward)

8-item cap; 8x memory-hard KDF per read; computational (not info-theoretic) indistinguishability;
deniable destruction via tampering; deterministic-per-password walk geometry. See spec section 9.
