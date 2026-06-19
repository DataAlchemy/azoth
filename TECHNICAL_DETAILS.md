# azoth — Technical Details

> **Status: experimental, not security-audited.** This document explains exactly what the
> KPDC construction does, why each decision was made, what it does and does not defend
> against, and how we tested those claims. It is an engineering + design record, not a
> peer-reviewed security proof. Do not protect anything whose disclosure would endanger
> you with this until it has had an independent professional cryptographic review.

---

## Table of contents

1. [Goal and the four properties](#1-goal-and-the-four-properties)
2. [Threat model and scope](#2-threat-model-and-scope)
3. [Design rationale — why this shape](#3-design-rationale--why-this-shape)
4. [The construction in full](#4-the-construction-in-full)
5. [Pinned primitives and why](#5-pinned-primitives-and-why)
6. [Invariants ("laws") the design must never break](#6-invariants-laws-the-design-must-never-break)
7. [How each security property is achieved](#7-how-each-security-property-is-achieved)
8. [Multi-snapshot deniability and re-randomization](#8-multi-snapshot-deniability-and-re-randomization)
9. [Known weaknesses and honest limitations](#9-known-weaknesses-and-honest-limitations)
10. [Rejected designs and why](#10-rejected-designs-and-why)
11. [How we tested that it is secure](#11-how-we-tested-that-it-is-secure)
12. [Prior art and how azoth differs](#12-prior-art-and-how-azoth-differs)
13. [Reproducing the results](#13-reproducing-the-results)
14. [For reviewers — where to focus](#14-for-reviewers--where-to-focus)

---

## 1. Goal and the four properties

azoth (the **K-Plane Deniable Container**, KPDC) is a fixed-size block of random-looking bytes
that holds up to **K** independent encrypted payloads. The design targets four properties:

1. **Oversized / configurable.** The block is much larger than any single payload (per-payload
   capacity is the plane size, `8·B/K` bits for a `B`-byte block); the user picks `B` and `K`.
2. **Multi-payload.** Up to `K` independent payloads coexist in one block, each under its own
   password.
3. **Indistinguishability.** Without the correct credential, the block is computationally
   indistinguishable from uniform random bytes — no header, no index, no count. An *empty*
   container and a *full* one are byte-for-byte statistically identical.
4. **Multi-key.** Different passwords decrypt to completely different plaintexts; a wrong
   credential decrypts nothing — the read simply fails (returns `None` / the CLI errors),
   indistinguishable from probing an empty plane. It does *not* return noise or a decoy.

The defining differentiator versus deployed tools (e.g. VeraCrypt's outer+hidden volume, which
tops out at two) is property 3 + 4 combined at scale: **K independent payloads whose very count
is unprovable** — an adversary cannot show "there is a 3rd / 4th payload," even to the owner.

---

## 2. Threat model and scope

**Credential.** Unlocking requires `(password, K, KDF-cost, cipher)`. None of these is stored in
the block. `K`, the Argon2id cost, and the payload cipher (AES-256-CTR default · ChaCha20 ·
SHAKE256-keystream) are per-container parameters you must remember/transmit out-of-band, exactly
like the password. The cipher is bound into the recognition token + MAC key, so a wrong cipher
fails cleanly (no payload found) like a wrong password — it never yields garbage plaintext.

### Defended

- **Single-look inspection.** An adversary who images the block once and has no correct
  password cannot tell whether anything is stored, or how much. (Computational; see §7.)
- **Partial compromise.** An adversary who extracts `j` of the passwords learns `j` planes and
  learns nothing about whether the other planes are empty or full. Revealing `K` reveals only
  the *ceiling* (≤ K), never the actual count.
- **Multi-snapshot diffing** (before/after images) — **defended by default** via whole-block
  re-randomization (`write_all_fresh`); see §8. The plain in-place `write()` does **not** defend
  against this and is documented as such.
- **Tampering** — detected by a per-payload HMAC (encrypt-then-MAC). A flipped bit yields a
  clean read failure, never a wrong plaintext.

### Explicitly out of scope (by design)

- **Successful guessing.** A correctly guessed `(password, K, cost)` compromises that payload.
  There are no honey-encryption decoys (see §10). Resistance to guessing rests on **password
  entropy + a deliberately heavy memory-hard KDF**, not on `K` (which carries ~0 entropy).
- **Information-theoretic deniability.** Indistinguishability is **computational** — it rests on
  SHAKE256/HMAC/Argon2id outputs being indistinguishable from random. A break of those breaks
  the claim.
- **Existence of the container as a high-entropy blob.** azoth hides *what* and *how much*, not
  *that a random-looking file exists*. A file of pure entropy can itself invite suspicion; the
  only answer is a plausible cover for randomness (disk free/slack space, a "wiped" partition).
- **Operational / coercion deniability — NOT provided.** This is the important one. Indistinguish-
  ability is a property of the *block in isolation*; it says nothing about the rest of your system.
  The `azoth` binary, package records, shell history (`azoth read --file …`), and your demonstrable
  use of deniable-encryption software are all trails that the bytes' uniformity does nothing to
  hide. Above all, it does **not** survive **coercion**: if you are compelled to decrypt, running a
  tool built to hold hidden payloads tells the adversary more may exist, and coercion runs on
  *suspicion, not proof* — they need not accept that you revealed everything. A "genuine but
  innocuous decoy you reveal under pressure" is **not** a defense and we no longer recommend it: the
  construction is public, so an adversary who knows it simply keeps coercing. The property is
  meaningful only when the blob is found *without you and without the tool* (abandoned/wiped media,
  slack space, bytes mixed into other randomness) by an inspector who cannot tie it to azoth.
  Beating an interrogation is not a problem cryptography can solve, and azoth does not pretend to.
- **Read-side timing channels** (e.g. probe-count timing). Not hardened in v1.

---

## 3. Design rationale — why this shape

The construction is the product of a long chain of first-principles decisions. The key ones:

- **Why a random-filled block, not a structured container?** Property 3 requires that "empty"
  and "full" be indistinguishable. The only way two states are statistically identical is if a
  fresh block is **uniform random** and writing a payload *overwrites random bytes with output
  that is itself indistinguishable from random*. Encryption/PRF output already looks random, so
  "writing a secret" and "leaving it random" produce statistically identical bytes. Hence: no
  headers, no magic, no slot table — nothing structural anywhere (invariant **L1**).

- **Why "planes"?** We need many payloads in one block with **no collisions** and **no stored
  index**. We partition the block's bits into **K disjoint planes** by residue class: plane `p`
  owns every global bit-index `g` with `g mod K == p`. Two payloads in different planes touch
  *different bits even of the same byte*, so they can never corrupt one another — collision-
  freedom is **structural**, not luck-based, and needs no allocator metadata.

- **Why K secret, prime, and coprime to 8?** `K` is part of the credential (an adversary who
  doesn't know it cannot even lay out the planes). It must be **coprime to 8** (the byte width):
  if `K` shared a factor with 8, a plane's bits would collapse toward a fixed bit-position
  (at `K=8`, "plane = bit 0, plane = bit 1…"), which is structured. Coprime-to-8 makes each
  plane a *diagonal* spread across all bit-positions. Prime guarantees coprime-to-8 and gives
  clean full-period behavior for any stride. `K` carries negligible entropy and is **not**
  counted as a key — it is a structural whitener and a speed bump.

- **Why is the intra-plane walk salt-independent?** The reader must locate and read the per-write
  salt *before* it knows the salt. So the positions that hold the salt (and the rest of the
  walk) are derived from `(password, K, plane)` only — never from the salt. This is a hard
  constraint, and it is why position-randomization per write is not possible without a full
  re-randomize (see §8 and the rejected "anchor" design in §10).

- **Why open-addressed plane lookup, not `hash(pw) mod K`?** `hash(pw) mod K` collides
  birthday-style — two passwords can map to the same plane. Instead a password hashes to a
  *home* plane and the reader probes forward (`home, home+1, …`) until its payload's recognition
  token validates. The writer (which must know all passwords — invariant **L4**) places each
  payload in a distinct free plane. Critically, **read and write use the same probe window**
  `min(maxprobe, K)`; placing a payload outside the reader's window would lose it silently — a
  bug we found and fixed (see §11).

- **Why a recognition token + MAC, not "the human recognizes the plaintext"?** Payloads are
  encrypted, so they look like noise; the human can't eyeball the right plane. A per-write token
  lets the reader cheaply reject a wrong plane after only `S+T` bits, and the HMAC tag confirms
  integrity. Both are PRF outputs (indistinguishable from random) and invisible without the key.

- **Why drop honey-encryption?** Making *every wrong guess* yield a plausible decoy is a large,
  fragile design burden. We made an explicit scope decision: target deniability vs. *inspection*,
  not vs. a *successful guess*. Security against guessing then rests on a strong password + heavy
  Argon2id, like LUKS/VeraCrypt. (See §10.)

---

## 4. The construction in full

Notation: `B` = block size in bytes; `nbits = 8·B`; `K` = plane count. All multi-byte integers
are big-endian. Bit ordering within a byte is **LSB-first**. `‖` is concatenation.

### 4.1 Plane geometry

- Plane `p` (for `p` in `0..K`) owns global bit-indices `g` with `g mod K == p`.
- Slot `t` of plane `p` is global bit-index `g = t·K + p` → byte `g/8`, bit `g mod 8`.
- Number of slots in plane `p`: `plane_slots(p) = (nbits − 1 − p) / K + 1` (planes differ in size
  by at most one slot when `K ∤ nbits`).
- `K` is validated at construction: `2 ≤ K ≤ nbits` (else the plane math underflows).

### 4.2 Field sizes (bits)

| Field | Size | Purpose |
|---|---|---|
| `S_BITS` | 128 | per-write salt (nonce) |
| `T_BITS` | 128 | recognition token (fast plane reject) |
| `LEN_BITS` | 32 | payload length |
| `TAG_BITS` | 256 | HMAC-SHA256 integrity tag |
| `HEAD_BITS` | 288 | = S+T+LEN, the part read before the body |

A payload occupies `HEAD_BITS + 8·len + TAG_BITS` slots along its plane's walk; this must be
`≤ plane_slots(plane)`.

### 4.3 Key / position derivations

All derived on demand; **nothing below is ever written to the block**.

```
# Fast, salt-INDEPENDENT (locate the plane + walk before the salt is known):
prk     = SHA256( pw_utf8 ‖ K_be64 )                       # 32 bytes
home    = rejection_sample( SHAKE256(prk ‖ "home") )  mod K # unbiased
smask   = SHAKE256( prk ‖ "saltmask" )                      # 16 bytes
walk(p) = distinct slot indices in [0, plane_slots(p)),     # SlotWalk:
          drawn from SHAKE256(prk ‖ "slots" ‖ p_be64) as a stream,
          rejection-sampled (no modulo bias)

# Slow, salt-DEPENDENT (the memory-hard gate):
mk      = Argon2id( pw_utf8 ‖ K_be64, salt )               # 32 bytes, zeroized
ctag    = "aes256ctr" | "chacha20" | "" (shake256)         # cipher domain-separation tag
token   = SHAKE256( mk ‖ "token" ‖ ctag )                   # 16 bytes
lenmask = SHAKE256( mk ‖ "len" )                            # 4 bytes
mackey  = SHAKE256( mk ‖ "mac" ‖ ctag )                     # 32 bytes
tag     = HMAC-SHA256( mackey, ciphertext )
# Keystream — selected by the cipher credential (all IND$; key/nonce SHAKE-derived from mk):
stream  = AES-256-CTR( k=H(mk‖"stream-aes256ctr")[:32], iv=…[32:48] )   # default
        | ChaCha20(    k=H(mk‖"stream-chacha20")[:32],   nonce=…[32:44] )
        | SHAKE256( mk ‖ "stream" )                                       # original
        truncated to len bytes
```

The `home`/`smask`/`walk` derivations use only `prk` (i.e. `pw` and `K`), so the reader can
bootstrap. The memory-hard `mk` and everything below it depend on the salt, so they cannot be
computed until the salt has been read — and computing them is the expensive, brute-force-gating
step. The cipher is bound into `token` and `mackey` via `ctag`; SHAKE256 uses the **empty** tag,
so its wire format is byte-identical to the original single-cipher design (its KAT is unchanged),
while a mismatched cipher fails at the constant-time token compare — a clean miss, not garbage.

### 4.4 On-walk layout of one payload

```
[ salt ⊕ smask | token | len ⊕ lenmask | ciphertext = pt ⊕ stream | tag = HMAC(mackey, ct) ]
       128b        128b       32b              8·len bits                     256b
```

Every field is either a fresh nonce, a PRF output, or a MAC — all indistinguishable from random.

### 4.5 Initialize

```
block = CSPRNG(B bytes)        # getrandom(); that is the whole "create".
```

An empty container is just `B` random bytes — identical in distribution to a full one.

### 4.6 Write (in-place)

```
write(pw, plaintext, known_pws, maxprobe, salt?):
    reject if plaintext.len > u32::MAX            # length field is 32 bits
    reject if salt provided and salt.len != 16    # fail fast, before any KDF
    prk = SHA256(pw ‖ K)
    if pw already present (plane_of(pw)): reuse that plane          # overwrite
    else:
        occupied = { plane_of(q) for q in known_pws }              # needs all keys (L4)
        plane = first free plane in (home, home+1, …) within min(maxprobe, K)
        error ContainerFull if none                                # never place beyond the read window
    reject if (HEAD + 8·len + TAG) > plane_slots(plane)            # PayloadTooLarge
    salt = provided or CSPRNG(16)
    derive mk, token, lenmask, stream, mackey; ct = pt ⊕ stream; tag = HMAC(mackey, ct)
    bits = (salt⊕smask) ‖ token ‖ (len⊕lenmask) ‖ ct ‖ tag
    walk = SlotWalk(prk, plane, plane_slots(plane)); walk.ensure(len(bits))
    for j, bit in bits: set block bit at global(walk[j], plane)
```

Untouched slots keep their original random fill, so the plane looks uniformly random whether
1% or 95% full.

### 4.7 Read (sweep + recognize)

```
read(pw, maxprobe):
    prk = SHA256(pw ‖ K); home; smask
    for i in 0 .. min(maxprobe, K):
        plane = (home + i) mod K
        walk = SlotWalk(prk, plane); read first HEAD_BITS slots
        salt = head[0:128] ⊕ smask
        mk = Argon2id(pw ‖ K, salt)                  # the expensive per-probe step
        if SHAKE256(mk‖"token") != head[128:256]:  continue      # constant-time fast reject
        len = head[256:288] ⊕ lenmask
        total = HEAD + 8·len + TAG; bound-check vs plane_slots; continue if too big
        read ct and tag from the rest of the walk
        if HMAC(mackey, ct) != tag:  continue        # tamper / rare false token match
        return ct ⊕ stream                           # zeroized plaintext
    return None
```

Token and tag comparisons are **constant-time** (`subtle::ConstantTimeEq`). A correct read
terminates near the home plane (few probes); a wrong credential probes the full
`min(maxprobe, K)` and fails — that per-attempt cost is part of guess-resistance.

### 4.8 Whole-block re-randomize (`write_all_fresh`)

```
write_all_fresh(payloads /* all (pw, plaintext) the container should retain */, maxprobe):
    fresh = CSPRNG(B bytes)                          # brand-new random block
    tmp = Kpdc(fresh, K, kdf)
    for i, (pw, pt) in payloads:
        tmp.write(pw, pt, /*known=*/payloads[0..i].pws, maxprobe, None)
    commit: self.block = tmp.block                   # atomic — original untouched on any error
```

Because the entire block is regenerated and every payload re-salted, **every bit changes on
every write**. This is the multi-snapshot defense (§8). It requires every password (anything
omitted is destroyed), so the CLI gates it behind `--all-keys`.

### 4.9 CLI surface

- `create --size --k --out` — fill a random block; prints a deniability-scope reminder.
- `write --file --k [--password] --data [--known …] [--all-keys] [--no-rerandomize] [--kdf-mem-mib --kdf-iters]`
  — default re-randomizes the whole block (requires `--all-keys`); `--no-rerandomize` does a
  faster in-place write that is **not** multi-snapshot-safe. Custom KDF cost warns "remember it."
- `read --file --k [--password] [--kdf-mem-mib --kdf-iters]` — prints plaintext or errors "just
  noise."
- `prime n` — smallest prime ≥ n coprime to 8 (a good `K`).
- `demo` — self-test at the recommended cost.

Passwords are read from a no-echo prompt when `--password` is omitted (CLI args leak via `ps`).
Container writes are **atomic** (temp file + rename), so a crash cannot corrupt the file.

---

## 5. Pinned primitives and why

| Role | Primitive | Why |
|---|---|---|
| Memory-hard KDF | **Argon2id**, default 256 MiB / 3 passes / 1 lane | Side-channel-resistant memory-hardness; the cost is the brute-force gate. Cost is part of the credential, not stored. |
| XOF / PRF / subkeys | **SHAKE256** | A XOF needs no HKDF extract/expand; `SHAKE256(key ‖ label)` is a clean keyed PRF with domain separation by label, with no SHA-2 length-extension concern. Used for token/len/mac subkeys, masks, the walk, and (in SHAKE256 mode) the keystream. |
| Payload cipher | **AES-256-CTR** (default) · **ChaCha20** · **SHAKE256-keystream** | Selectable, part of the credential (not stored). All three are IND$ — the ciphertext is indistinguishable from random and from each other — so the choice leaks nothing. Key/nonce are SHAKE-derived from `mk` under a cipher-specific label; the cipher is bound into `token`+`mackey` so a wrong choice fails cleanly. AES-CTR & ChaCha20 via RustCrypto `aes`/`ctr`/`chacha20`. **Migration:** containers from the pre-cipher build use SHAKE256 (byte-identical original format) — read with `--cipher shake256`. |
| Fast hash (positions) | **SHA-256** | `prk` only derives positions (cheap, salt-independent); the slow gate is Argon2id, so a fast hash here doesn't weaken brute-force resistance. |
| Integrity | **HMAC-SHA256** | Encrypt-then-MAC; tamper-evident; tag is indistinguishable from random. |
| CSPRNG | OS (`getrandom`) / Python `secrets` | Block fill and per-write salts. |
| Slot scatter | SHAKE-driven **rejection sampling** | Distinct slot indices in `[0, M)` with no modulo bias. |
| Constant-time compare | `subtle::ConstantTimeEq` | Token and MAC comparisons don't leak via timing. |
| Zeroization | `zeroize::Zeroizing` | `prk`, `mk`, `mackey`, `stream`, and recovered plaintext are wiped on drop. |

The Rust crate (`azoth/`) is the real implementation. The Python file (`kpdc_reference.py`) is a
readable spec mirror: stdlib-only, so it uses **scrypt** (no Argon2id in the stdlib) and a
counter-mode (rather than XOF-stream) rejection-sampled walk. **The two are deliberately NOT
wire-compatible** — a container written by one cannot be read by the other.

---

## 6. Invariants ("laws") the design must never break

- **L1 — No structure in the clear.** No headers, version bytes, markers, counts, or tokens at
  fixed/structurally-guessable locations. `K` and `B` live in the credential/format, not the block.
- **L2 — Empty == Full.** A fresh block is CSPRNG bytes; writing overwrites some with PRF/keystream
  output that is itself indistinguishable from random. The two states are statistically identical.
- **L3 — Unprovable count.** No index or count exists. A holder of `j` passwords learns `j` planes
  and nothing about the rest. Revealing `K` exposes only the ceiling.
- **L4 — All-keys-to-add.** Safely adding a payload requires every existing password (to find
  which planes are occupied). This is also what makes whole-block re-randomization possible.
- **L5 (relaxed) — No system verifier.** The container never confirms a password by itself.
  Recognition is a per-write token gated behind the memory-hard KDF; it is an oracle only to
  someone who already supplies a candidate credential (accepted under the scope decision).

---

## 7. How each security property is achieved

- **Indistinguishable (req 3 / L1 / L2).** Every byte in the block is either fresh CSPRNG fill or
  a PRF/keystream/MAC output. Writing replaces uniform-random bits with PRF-uniform bits, so the
  whole block stays i.i.d.-uniform. There is no stored structure, and `K`/`B` are not in the
  block. **Empirically verified** at 1st order (byte chi-square ≈ 255), bit density (≈ 0.5), runs,
  2nd order (digram chi-square), and serial correlation — see §11.
- **Multi-payload, collision-free (req 2).** Planes are disjoint residue classes, so payloads in
  different planes never share a bit. The writer assigns distinct planes (L4).
- **Multi-key (req 4).** Each `(pw, K)` defines its own home, walk, and keys. A wrong credential
  computes a different walk and reads noise; the token fast-rejects, and the HMAC backstops
  against the ~2⁻¹²⁸ chance of a spurious token match.
- **Unprovable count (L3).** Nothing records how many planes are used; an unused plane and a used
  one are both random. A `j`-password holder cannot distinguish empty from full in the rest.
- **Integrity.** Encrypt-then-MAC; the tag is verified before the plaintext is returned, so
  tampering yields `None`, never a wrong plaintext (verified by `tamper_is_detected`).
- **Guess-resistance gate.** The recognition token and stream both derive from `mk = Argon2id(...)`,
  so testing a password guess costs (at least) one Argon2id evaluation per probed plane — the
  fast `prk`/position derivation cannot bypass it.

---

## 8. Multi-snapshot deniability and re-randomization

A multi-snapshot adversary images the block **before and after** a write. With the plain in-place
`write()`, only the payload's positions change between snapshots — and those positions are all
`≡ p (mod K)`, so the **GCD of changed-position differences leaks K**, and the changed footprint
reveals that a payload exists.

The defense is **whole-block re-randomization** (`write_all_fresh`, the CLI default): refill the
entire block with fresh CSPRNG bytes and re-write every payload with new salts. Now **every** bit
changes on every write — the changed-position set is the whole block, so a per-position
change-frequency map is uniform and nothing is localizable. This works precisely because the fill
is regenerated; any in-place scheme that leaves the fill static, or that touches a fixed
`(pw,K)`-derived position, leaves a detectable tell (this is why the "salt-derived walk + fixed
anchor" idea was rejected — see §10). The cost is O(B) work and the requirement that you supply
every password (L4); the CLI enforces the latter with `--all-keys`.

Note on positions: the per-payload bit *positions* are deterministic from `(pw, K, plane)` and do
**not** move between re-encryptions; what defeats diffing is that the surrounding fill and all
field *values* are regenerated, so the payload's changes are statistically indistinguishable from
the fill's changes.

---

## 9. Known weaknesses and honest limitations

1. **Offline verification oracle.** Anyone holding the blob can test `(password, K, cost)` guesses
   offline, gated only by Argon2id. Deniability is therefore against *inspection*, not against a
   *successful guess*. Mitigation: strong password + high KDF cost. (Scope decision, §10.)
2. **Computational, not information-theoretic.** The whole indistinguishability claim rests on
   SHAKE256/HMAC/Argon2id being indistinguishable from random.
3. **`K` is low-entropy config, not a key.** Don't rely on it for strength.
4. **Payload cap = K**, and `maxprobe` bounds the usable load factor; wrong-credential reads cost
   up to `min(maxprobe, K)` Argon2id evaluations (a feature for guessing-cost, a UX cost).
5. **Deniable destruction.** A coercer can randomize the block to destroy data without reading it;
   the HMAC detects but cannot prevent this.
6. **Cover-story & tool-trace problem.** A high-entropy blob can itself be incriminating, and the
   *tool* leaves traces (binary, package records, shell history) that no decoy payload hides. azoth
   provides content-deniability of the block **in isolation** — not existence-of-the-blob
   deniability, and **not** deniability under coercion. Revealing a decoy does nothing against an
   adversary who knows you use a hidden-payload tool; see §2 ("Operational / coercion deniability —
   NOT provided"). Do not rely on azoth to survive a "decrypt-or-else" demand.
7. **Read-side timing** is not constant-probe in v1.
8. **Unaudited.** No independent professional cryptographic review has been done.

---

## 10. Rejected designs and why

The design is as much about what we *didn't* do. Each of these was considered and rejected after
analysis (some after independent adversarial review):

- **Corruption-tolerant overlap** (let payloads collide, repair with error-correcting codes).
  Rejected: re-admits silent corruption; at the target fill (~10% of bits) collisions damage
  ~10% of every payload's bits, demanding heavy ECC. Disjoint planes avoid the problem entirely.
- **XOR-superposition** (overlapping bytes hold the sum of two payloads). Rejected: recovering one
  payload would require exposing another's key as "proof," inverting deniability.
- **Honey encryption** (every wrong guess yields a plausible decoy). Rejected as scope: large,
  fragile design burden; we instead rely on password entropy + memory-hard KDF and accept that a
  correct guess compromises that payload.
- **`hash(pw) mod K` plane selection.** Rejected: birthday collisions. Replaced by open-addressed
  probing with a recognition token.
- **Salt-derived walk + fixed anchor** (move the bulk data positions per write, keep a small fixed
  `(pw,K)` anchor that points to the salt). Rejected after a dedicated adversarial review: the
  fixed anchor is itself a per-payload position `≡ p (mod K)` that, under multi-snapshot
  change-frequency analysis, leaks `K` (GCD of anchor indices) and the payload count — exactly the
  leak it tried to prevent. It also makes a pre-Argon2 read address depend on attacker-controlled
  bits (a tampering oracle) and adds silent-corruption fragility, while buying nothing over
  whole-block re-randomization.
- **`--flatten` (force exactly-equal byte counts).** Rejected: real random data is *not* perfectly
  flat — it has binomial histogram fluctuation. A perfectly even histogram has chi-square ≈ 0,
  which no natural high-entropy source produces, so flattening is a *detectable signature*, not
  camouflage. The correct target is "matches a CSPRNG's natural fluctuation," which the design
  already achieves.

---

## 11. How we tested that it is secure

Security here was pursued on four fronts: a precise spec, an automated test suite that checks the
*security properties* (not just round-trips), repeated adversarial review, and CI to keep it all
honest. No amount of this substitutes for an independent professional audit — but it is far more
than "the round-trip passes."

### 11.1 Functional + regression tests (`azoth/src/lib.rs`, run at the real recommended cost)

- `roundtrip_two_payloads_recommended_cost` — two passwords, two plaintexts, wrong password → None.
- `empty_payload_roundtrips`, `rerandomize_roundtrips` — edge and re-randomize paths.
- `invalid_k_is_rejected_not_panic` — `K = 0/1/>nbits` error cleanly (a panic bug karen found, fixed).
- `wrong_salt_length_is_rejected` — public-API footgun closed with a clear error.
- `tamper_is_detected` — a flipped byte yields a correct read or `None`, never a wrong plaintext.
- `write_success_implies_readable_at_same_maxprobe` — **regression test** for the most serious bug
  found: write originally scanned the full `K` ring while read capped at `min(maxprobe, K)`, so a
  payload could be written where read never looks (silent data loss). Now write is bounded to the
  same window; the test asserts every successful write is readable at the same `maxprobe`.

### 11.2 Security-property tests (`azoth/tests/security.rs`)

These check the *claims*, not just functionality. Statistical tests use a deterministic SHAKE256
fill so they are reproducible and never flake; the property under test (distribution, panic-safety,
false-positive rate) is independent of KDF cost, so they use the fast KDF to afford volume.

- **Indistinguishability — 1st order:** `full_container_is_statistically_uniform` and
  `empty_and_full_are_both_uniform` — byte chi-square in-band and bit density ≈ 0.5; an empty and a
  full block both pass the *same* test (nothing distinguishes them).
- **Indistinguishability — heavy fill:** `heavily_filled_container_stays_uniform` packs ~one large
  payload per plane so PRF output is the *majority* of bits, then checks byte chi-square, bit
  density, and a **runs test** (adjacent-bit transitions). This directly answers "do our writes
  keep the blob on the statistical norm even when they dominate it?"
- **Indistinguishability — 2nd order:** `second_order_structure_absent` — **digram (byte-pair)
  chi-square** over 65,536 bins plus **lag-1 serial correlation** on a 512 KiB block. Catches
  structure a 1st-order histogram would miss. (A "flattened" block would instead drive the 1st-
  order chi-square to ≈ 0 — which these very tests would flag.)
- **Across parameters:** `uniform_across_sizes_and_k` — uniformity across several `B` and `K`.
- **Multi-key independence:** `multi_key_independence_recommended` — three payloads, each reads its
  own plaintext; a wrong password and a wrong `K` both yield nothing.
- **No false positives:** `wrong_credentials_never_false_positive` — 300 wrong passwords against a
  populated container all return `None`; the real one still works.
- **Multi-snapshot defense:** `rerandomize_changes_almost_every_byte` — a re-randomizing write
  changes > 90% of bytes (proving it is a whole-block rewrite, not a sparse edit).
- **Robustness / fuzz-lite:** `read_never_panics_on_arbitrary_input` — 200 random blocks +
  credentials fed to `read`; it must return `None`/`Some`, never panic.
- **Known Answer Test:** `known_answer_write_and_read` — a fixed all-zero block + fixed salt + fixed
  `(pw, K)` produces a byte-exact result, pinned by an FNV checksum. **Any** change to a
  derivation, the layout, or the walk flips the checksum — a tripwire against silent wire-format
  drift (which random-salt round-trip tests cannot catch).

### 11.3 Continuous fuzzing

`azoth/fuzz/` is a `cargo-fuzz` (libFuzzer) target that drives `read`/`plane_of` on
fully-attacker-controlled bytes (`cargo +nightly fuzz run read_arbitrary`). The in-suite
`read_never_panics_on_arbitrary_input` gives a portion of the same coverage on stable CI.

### 11.4 Adversarial review (the bulk of the "security testing")

The implementation was put through **four rounds of multi-agent adversarial review** plus a
standalone whole-project security review. Each round ran five independent reviewers in parallel
(spec-conformance, reality-check/"does it actually work", task-completion, code-quality, and
project-rule compliance), findings were applied, then all five were re-run — looping until a full
round returned no valid issues. Notable findings and fixes:

- **Round 1 (incl. security review):** moved to **Argon2id** with a heavy, credential-bound cost;
  added **constant-time** tag/token comparison; **zeroized** key material and plaintext; added a
  **no-echo password prompt** (CLI args leak via `ps`); **atomic** container writes; `u32`
  length guard; `K` validation; unbiased `home`; single resumable slot walk.
- **Round 2:** found and fixed the **write/read `maxprobe` asymmetry** (silent data-loss bug, now
  regression-tested); rejected a silent `--kdf-mem-mib 0` downgrade; validated KDF params at
  construction so a bad cost surfaces as an error instead of "no payload"; fixed a prime-helper
  overflow.
- **Round 3:** closed the wrong-length-`salt` public-API footgun.
- **Round 4:** all five reviewers reported no valid issues.

Separately, two *design* proposals were independently red-teamed and **rejected before
implementation** — the "salt-derived walk + fixed anchor" scheme and `--flatten` (see §10) — each
because it would have *reintroduced* a distinguisher. That "red-team the idea before building it"
discipline is itself part of how we kept the design honest.

### 11.5 CI and hygiene

GitHub Actions runs on every push: `cargo fmt --check`, `cargo clippy --all-targets -D warnings`,
`cargo test --release` (all unit + security tests), and the Python reference self-test. The
toolchain is pinned (`rust-toolchain.toml`, channel 1.96.0), the MSRV is declared
(`rust-version = 1.87`), and `#![forbid(unsafe_code)]` is enforced crate-wide.

### 11.6 What this does NOT establish

- No formal proof of indistinguishability or deniability.
- No independent professional cryptographic audit.
- Statistical tests can only *fail* on detectable structure; passing is necessary, not sufficient.
- The guess-oracle and computational-only caveats (§9) are inherent, not bugs to be tested away.

---

## 12. Prior art and how azoth differs

azoth's *concept* is well-trodden; the design space includes:

- **Rubberhose / Marutukku** (Assange et al., ~2000) — multiple deniable "aspects," count
  unprovable, scattered in a random medium. azoth's nearest spiritual ancestor.
- **The Steganographic File System** (Anderson–Needham–Shamir, 1998) / **StegFS** — data at
  key-derived positions hidden in random fill. azoth's scatter-in-random-fill descends from this.
- **VeraCrypt / TrueCrypt hidden volumes** — the deployed two-level (outer + one hidden) version.
- **Artifice** (UCSC, FOCI 2019) and the PD-storage line (**HIVE, DataLair, INVISILINE, HiPDS,
  Mobiflage, DEFY**) — deniable block devices, including multi-snapshot defenses.
- **Deniable Encryption** (Canetti–Dwork–Naor–Ostrovsky, CRYPTO 1997) — the formal definition.
- **Honey Encryption** (Juels–Ristenpart, 2014) — wrong-key-yields-decoy (azoth opted out).
- **Chaffing and winnowing** (Rivest, 1998), **all-or-nothing transforms**, **PURBs** (2019).

**What is azoth's actual niche:** deployed tools (VeraCrypt) cap at two-level deniability. azoth
targets **unbounded K with an unprovable count** in a single bare blob (no filesystem) — the gap
those tools don't fill. The *idea* is not novel; the specific construction (residue-class planes,
secret prime-coprime-to-8 `K`, open-addressed token lookup, whole-block re-randomize) is one
particular engineering take that has **not** been independently vetted.

---

## 13. Reproducing the results

```bash
# Rust implementation (the real one)
cd azoth
cargo test --release          # 8 unit + 10 security tests (incl. the statistical + KAT suite)
cargo clippy --all-targets -- -D warnings
cargo run --release -- demo   # self-test at the recommended Argon2id cost

# Continuous fuzzing (nightly)
cargo +nightly fuzz run read_arbitrary

# Python reference (readable spec mirror; NOT wire-compatible with the Rust crate)
python3 ../kpdc_reference.py
```

Authoritative documents: the design spec is
`_bmad-output/brainstorming/8pdc-spec-draft.md`; this file summarizes and extends it with the
testing and rationale record.

---

## 14. For reviewers — where to focus

The cryptographic risk here is **not** uniformly distributed. If you're reviewing this (thank
you — please try to break it), separate the two layers; they need very different amounts of
scrutiny.

### Lower-risk: the per-payload confidentiality core

The encryption of a single payload is a textbook composition of conservative, well-vetted
primitives — **Argon2id** (KDF) → **SHAKE256** keystream → XOR → **HMAC-SHA256** (encrypt-then-MAC),
with a fresh 128-bit salt per write and domain-separated subkeys. There is nothing novel in this
layer. It is **not** where to spend time on primitive selection (AES-vs-ChaCha-style debates).

Two caveats that nonetheless live in *this* layer and bound its real-world strength:

- **Confidentiality is only as strong as `password entropy × KDF cost`.** The recognition token
  and HMAC form an **offline verification oracle**: anyone holding the blob can test guesses
  offline, gated solely by Argon2id. A weak password is brute-forceable — not because the cipher
  is weak, but because that is the nature of password-based encryption. "The cipher is sound"
  holds *only* for a strong password + heavy cost. This is the most likely real-world break, and
  it has nothing to do with the deniability machinery.
- **Standard primitives ≠ audited assembly.** The composition is hand-rolled and unaudited; a
  subtle bug in key derivation, keystream generation, the MAC, salt/nonce handling, or the
  bit-placement would dent confidentiality regardless of how good the primitives are.

### Where the actual experimental surface is: the deniability machinery

The novel, design-risk-concentrated part is everything that makes this *deniable*: the
residue-class **plane** construction, the **indistinguishable-from-random** claim, the
**unprovable-count** property, and the **multi-snapshot re-randomization**. This is what most
needs expert eyes.

### The three questions worth a reviewer's time

1. **Does the deniability / indistinguishability actually hold** — under chosen-plaintext,
   partial-credential (an adversary who knows `j` of the `K` passwords), and multi-snapshot
   conditions? In particular, does anything leak the **payload count** or **`K`**?
2. **Does the hand-rolled key / keystream / position derivation have an implementation bug** —
   salt/nonce handling, domain separation, the bit-plane walk, the open-addressed plane lookup?
3. **Is the offline-guess oracle the only practical attack**, or is there a cheaper distinguisher
   or extraction we missed?

### Suggested framing when requesting a review

> "The confidentiality core is standard primitives in a textbook AE composition — I'm not asking
> you to vet primitive choices. I'm asking: (1) does the deniability/indistinguishability
> construction hold, (2) does the hand-rolled key/keystream/position derivation have a bug, and
> (3) is the offline-guess oracle the only practical attack, or did I miss one?"

Good venues: **[Cryptography Stack Exchange](https://crypto.stackexchange.com)** (scoped
questions), **r/cryptography**, the **IACR ePrint archive** / **PETS** community for the deniable-
storage angle, and a professional audit (Trail of Bits / NCC Group / Cure53 / Kudelski) for any
"safe to actually rely on" verdict. Lead with the prior-art acknowledgment (§12) and the
"experimental, please break this" framing — do not claim novelty or security.
