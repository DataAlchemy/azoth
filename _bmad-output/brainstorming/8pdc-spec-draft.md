# K-Plane Deniable Container (KPDC) — Draft Spec v0.3

**Status:** Brainstorm output, 2026-06-06 (adversarial pass 2026-06-07). Buildable skeleton, not yet security-audited.
**Supersedes:** v0.2 (added integrity MAC; reframed K; scoped multi-snapshot to a V2 mode).
**Lineage:** v0.1 fixed 8-plane (8PDC) -> v0.2 K-plane -> v0.3 hardened-per-adversarial-pass.

A fixed-size block of random-looking bytes holding up to `K` independent encrypted
payloads. Without the correct credential it is computationally indistinguishable from
random data, and no party — including the owner — can prove how many payloads it holds.

---

## 1. Credential

The unlock credential is **(password `pw`, plane count `K`)**. Both must be known; `K` is
chosen at instantiation and folded into every key derivation, so a wrong `K` makes the
entire layout and all keys wrong.

- **`K` is configuration, NOT a password.** It is a required-to-know structural parameter and
  a layout whitener — treat its entropy as ~0. **All cryptographic strength rests on `pw`.**
  Do not pick `pw` weak on the theory that `K` protects you.
- `K` SHOULD be **prime and coprime to 8** (e.g., 419, 10007). Coprimality with the byte
  width de-aligns planes from bit-positions (see Section 5).
- `K` is per-container: all payloads in one block share it. Revealing `K` exposes the
  *ceiling* (<= K slots) but not the actual count and not other passwords.

---

## 2. Design properties (the four requirements)

1. **Oversized / configurable.** Block size `B` bytes. Plane size = `8B/K` bits is the
   per-payload capacity; keep load factor (payloads / K) modest (<= ~2/3) for headroom.
2. **Multi-payload.** Up to `K` payloads, one per plane.
3. **Indistinguishable.** Empty block = `B` random bytes; full block = `B` random-looking
   bytes. No header, magic, index, count, or cleartext token. `K` and `B` are not stored.
4. **Multi-key.** Each (pw) decrypts its own plane to its own plaintext; wrong credential
   yields noise everywhere.

---

## 3. Core invariants ("laws")

- **L1 — No structure in the clear.** No headers, version bytes, markers, or tokens at
  fixed / structurally-guessable locations. `K` and `B` live in the credential/format, not
  the block.
- **L2 — Empty == Full.** Fresh block = CSPRNG bytes. Writing overwrites some with
  PRF/keystream output that is itself indistinguishable from random.
- **L3 — Unprovable count.** No index or count exists. A holder of `j` passwords learns
  `j` planes and nothing about whether the other planes are empty or full. (With `K`
  revealed, they learn only the ceiling.)
- **L4 — All-keys-to-add.** Safely adding a payload requires every existing password (to
  find which planes are occupied, via open-addressing probe). Blind writes risk overwrite.
- **L5 (relaxed) — No system verifier.** Recognition is a per-write token gated behind a
  memory-hard KDF; it is an oracle only to someone supplying a candidate credential.

---

## 4. Scope / threat model

- **Targeted:** deniability vs *single-look inspection* — given one image of the block and no
  correct password, the adversary cannot tell anything is stored or how much.
- **Not targeted (v1):**
  - *Multi-snapshot* adversaries (before/after images). Diffing reveals write activity and
    leaks `K`. **Out of scope for v1.** Planned V2 mitigation: re-randomize the whole block on
    every write (re-encrypt all payloads + refresh all fill). L4 already requires all
    passwords to write, so this costs only O(B) work and defeats diffing entirely.
  - *Successful guessing.* A guessed `pw` compromises that payload. No honey-decoys;
    guess-resistance = **password** entropy + memory-hard KDF (not `K`).
  - *Read-side timing* channels (probe-count side channel). Optional hardening: constant
    `maxprobe` reads.
- **Existence of the container.** KPDC hides *what/how-much*, not *that a high-entropy blob
  exists*. A 2 GB random file can itself invite suspicion. Deployment guidance: give the blob
  a plausible cover (disk free/slack space, a "wiped" partition) and/or **store a benign
  decoy payload** the owner can reveal under pressure. The cover story is the user's to supply.
- **Indistinguishability is COMPUTATIONAL,** resting on PRF/PRG output being
  indistinguishable from random. Not information-theoretic.

---

## 5. Plane structure (interleaved, byte-coprime)

Number the block's bits `0 .. 8B-1`. **Plane `k` = every bit-index `i` with `i mod K = k`.**
There are `K` disjoint planes; plane `k` has `floor or ceil(8B/K)` slots.

Because `gcd(K, 8) = 1`, consecutive slots of a plane fall on *different bit-positions*
within their bytes — each plane is a diagonal through the byte grid, not a fixed bit-layer.
This removes byte-grid alignment and whitens layout. (If `K` shared a factor with 8, planes
would collapse toward fixed bit-positions — avoid.)

Slot `t` of plane `k` is global bit-index `g = t*K + k`; that is byte `g div 8`, bit `g mod 8`.

---

## 6. Parameters

| Symbol | Meaning | Suggested |
|--------|---------|-----------|
| `B`    | block size, bytes | sized to capacity; need not be prime in v0.2 |
| `K`    | plane count (SECRET, in credential) | prime, coprime to 8 (e.g., 419) |
| `S`    | salt length (bits) | 128 |
| `T`    | token length (bits) | 128 |
| `Lf`   | length field (bits) | 32 |
| `maxprobe` | open-addressing probe bound | e.g., 64 (>= expected cluster) |
| KDF    | memory-hard password KDF | Argon2id (t=3, m=64MiB, p=1) |
| PRF/XOF| derivation + keystream | HKDF-SHA256 / SHAKE256 |

A payload occupies `S + T + Lf + 8*len` bits along its plane-walk; must be <= plane size.

---

## 7. Derivations (all on the fly; nothing below is stored)

```
# Fast, salt-independent (locate plane + walk before salt is known):
home   = HKDF(SHA256(pw, K), "home")   mod K
start  = HKDF(SHA256(pw, K), "start")  mod M       # M = size of the chosen plane
stride = 1 + ( HKDF(SHA256(pw, K), "stride") mod (M-1) )   # coprime to M (M prime, or use PRP)
smask  = HKDF(SHA256(pw, K), "saltmask", S)

# Slow, salt-dependent (memory-hard gate):
mk      = Argon2id(pw || K, salt)
token   = HKDF(mk, "token",  T)        # fast plane-reject during probing
lenmask = HKDF(mk, "len",    Lf)
stream  = HKDF(mk, "stream", 8*len)
mackey  = HKDF(mk, "mac")              # integrity over the ciphertext (A3)
```

Intra-plane scatter visits plane-slot indices `slot(j) = (start + j*stride) mod M`
(M prime => full period). Constraint-free alternative: a keyed PRP over `[0, M)`
(small-domain Feistel / cycle-walking) — recommended if you don't want to size planes prime.

---

## 8. On-walk layout of one payload

```
[ salt XOR smask | token | len XOR lenmask | ciphertext = M XOR stream | tag ]
                                                                          ^ tag = MAC(mackey, ct)
```

- **`token`** (read after only `S+T` bits) lets the reader reject a wrong plane *cheaply*
  during open-addressing probing — no need to read the whole payload to dismiss a miss.
- **`tag`** is encrypt-then-MAC integrity over the ciphertext: it detects tampering and is a
  second, stronger confirmation that the payload decrypted intact. Being a MAC value, it is
  indistinguishable from random -> zero deniability cost.

---

## 9. Algorithms

### 9.1 Initialize
```
block = CSPRNG(B bytes)
```

### 9.2 Write M under (pw, K)   — writer must know ALL existing passwords
```
occupied = { plane_of(block, q, K) for each known password q }     # via 9.3 lookup
home = HKDF(SHA256(pw,K),"home") mod K
plane = first of (home, home+1, ..., home+maxprobe-1) mod K not in occupied   # open addressing
assert plane found and (S+T+Lf+8*len(M)) <= size(plane)

salt = CSPRNG(S bits); derive start,stride,smask (pw,K); mk,token,lenmask,stream (pw,K,salt)
bits = (salt^smask) || token || (len^lenmask) || (M^stream)
for j,b in enumerate(bits):
    g = slot(j)*K + plane            # slot(j) walks the plane
    set bit (g mod 8) of block[g div 8] = b
# untouched slots keep original random fill -> plane looks random
```

### 9.3 Read under (pw, K)
```
home = HKDF(SHA256(pw,K),"home") mod K
for p in (home, home+1, ..., home+maxprobe-1) mod K:
    walk plane p: salt = read S bits ^ smask
    mk = Argon2id(pw||K, salt)
    if read T bits == HKDF(mk,"token",T):          # fast plane match
        len = read Lf ^ HKDF(mk,"len",Lf)
        ct  = read 8*len
        tag = read tagbits
        if tag != MAC(HKDF(mk,"mac"), ct): continue # tampered / false token match -> keep probing
        return ct ^ HKDF(mk,"stream",8*len)
return NONE
```
Legit reads terminate in ~`1/(1-loadfactor)` probes (cheap). A wrong credential probes the
full `maxprobe` and fails — deliberately expensive, raising brute-force cost.

---

## 10. Why each requirement holds

- **Indistinguishable:** all stored fields are PRF/keystream/random fill; no fixed structure;
  `K`,`B` not in the block. Byte-coprime planes remove layout alignment.
- **Multi-payload, no collisions:** planes are disjoint residue classes; writer assigns
  distinct planes via open addressing (needs all keys, L4).
- **Multi-key:** each (pw,K) => own home, walk, keys; wrong credential => noise.
- **Unprovable count:** no index/count; secret `K` hides even the geometry and ceiling.

---

## 11. Known weaknesses / open questions

**Adversarial pass (2026-06-07) outcomes:**
- **[RESOLVED v0.3] Integrity / malleability (A3):** encrypt-then-MAC (`tag`) added; recovered
  data is now tamper-evident.
- **[SCOPED OUT v1 -> V2] Multi-snapshot K-leak (A1):** diffing two block images reveals write
  activity and leaks `K` (changed positions are all `= p mod K`; their GCD = K). Deferred;
  V2 fix = whole-block re-randomize per write (enabled for free by L4).
- **[DEPLOYMENT] Container existence (A2):** a random blob can invite suspicion. User supplies a
  cover medium and/or a benign decoy payload. Not a cryptographic fix.
- **[SCOPED OUT] Read timing (A4):** probe-count side channel; optional constant-`maxprobe`.
- **[CLARIFIED] `K` entropy (A5):** `K` is config + whitener, ~0 bits of security. Strength = `pw`.

**Structural limits / assumptions:**
1. **Payload cap = K**; `maxprobe` bounds usable load factor; wrong-credential reads cost
   `maxprobe` KDF evals (a feature for guess-resistance, a UX cost).
2. **Computational, not information-theoretic** indistinguishability.
3. **Walk geometry deterministic per (pw,K)** (salt-independent): a correct guess reveals all
   that payload's positions; repeated updates to the same payload erode multi-snapshot
   deniability (see A1). Accepted under v1 Scope.
4. **Unequal plane sizes** when `K` does not divide `8B` (differ by <=1 slot); handle in the
   slot->(byte,bit) mapping.
5. **Whole deniability claim assumes** KDF/PRG output is indistinguishable from random.

---

## 12. Next steps

- [DONE] Adversarial Phase-4 pass — see Section 11.
- [DONE] Pinned primitives + runnable reference: `kpdc_reference.py` (stdlib only).
  - memory-hard KDF = scrypt; XOF/PRF = SHAKE256; MAC = HMAC-SHA256; fast hash = SHA-256.
  - intra-plane scatter = SHAKE-driven distinct-slot walk (counter mode). Self-test passes:
    2 payloads / 2 passwords round-trip, wrong password -> None, block reads uniform-random.
- Still open: rejection-sample slots (remove modulo bias); harden scrypt params; constant-probe
  reads (A4); stride-walk-with-prime-plane variant; production-grade test vectors + KATs.
- V2: whole-block re-randomize write mode (multi-snapshot deniability).
