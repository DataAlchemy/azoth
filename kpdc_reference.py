#!/usr/bin/env python3
"""
KPDC -- K-Plane Deniable Container -- reference implementation (spec v0.3).

A fixed-size block of random-looking bytes that holds up to K independent encrypted
payloads. Without the correct (password, K) the block is computationally
indistinguishable from random data, and there is no stored index, header, or count.

Spec: _bmad-output/brainstorming/8pdc-spec-draft.md

Pinned primitives (this reference):
  memory-hard KDF : hashlib.scrypt            (stdlib)
  XOF / PRF       : SHAKE256
  fast hash       : SHA-256
  MAC             : HMAC-SHA256
  payload cipher  : aes256ctr (default) | chacha20 | shake256  (selectable, part of credential)
  intra-plane walk: SHAKE-driven distinct-slot sequence (counter mode + rejection sampling)

THIS IS A READABLE REFERENCE, NOT PRODUCTION CODE.
  * Slot/home selection uses rejection sampling (no modulo bias), matching the Rust crate.
  * scrypt N defaults to 2^16 (~64 MiB); raise for higher assurance.
  * Whole-block re-randomize is available via write_all_fresh() (defeats multi-snapshot
    diffing). v1 single-snapshot scope still applies to the plain in-place write().
  * The payload cipher is selectable and is part of the credential (not stored, like K). It is
    bound into the token + MAC so a wrong cipher fails cleanly. aes256ctr / chacha20 require
    `pip install cryptography` (imported lazily); shake256 is pure stdlib.

NOT WIRE-COMPATIBLE with the Rust crate (azoth/). The Rust implementation uses
Argon2id (not scrypt) and a rejection-sampled XOF *stream* slot walk (vs this file's
counter-mode rejection), so containers written by one cannot be read by the other.
This file is a readable spec mirror, not an interoperable implementation.
"""

import hashlib
import hmac
import secrets

# ---- field sizes (bits) ----
S_BITS   = 128   # per-write salt (nonce)
T_BITS   = 128   # recognition token (fast plane reject)
LEN_BITS = 32    # payload length field
TAG_BITS = 256   # HMAC-SHA256 integrity tag

# ---- scrypt cost (recommended-ish: N=2^16 -> ~64 MiB; raise for higher assurance) ----
SCRYPT_N = 1 << 16
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 128 * SCRYPT_N * SCRYPT_R * 2


def shake(*parts, nbytes):
    h = hashlib.shake_256()
    for p in parts:
        h.update(p)
    return h.digest(nbytes)


def _u64(x):
    return x.to_bytes(8, "big")


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# ---- K helper: smallest prime >= n coprime to 8 (any odd prime qualifies) ----
def _is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def next_prime_coprime8(n):
    c = max(3, n | 1)            # force odd -> coprime to 8
    while not _is_prime(c):
        c += 2
    return c


# ---- bit access over a bytearray block (LSB-first within each byte) ----
def _get_bit(block, g):
    return (block[g >> 3] >> (g & 7)) & 1


def _set_bit(block, g, bit):
    if bit:
        block[g >> 3] |= (1 << (g & 7))
    else:
        block[g >> 3] &= ~(1 << (g & 7))


def _bytes_to_bits(bs):
    out = []
    for byte in bs:
        for i in range(8):
            out.append((byte >> i) & 1)
    return out


def _bits_to_bytes(bits):
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i >> 3] |= (1 << (i & 7))
    return bytes(out)


class KPDC:
    """A K-plane deniable container backed by a mutable byte block."""

    # Selectable payload ciphers — like K and the KDF cost, the cipher is part of the credential
    # and is NOT stored; read and write must use the same value. (The default mirrors the Rust
    # crate's default.) AES-CTR and ChaCha20 need `cryptography` (imported lazily); SHAKE256 is stdlib.
    CIPHERS = ("aes256ctr", "chacha20", "shake256")

    def __init__(self, block, K, cipher="aes256ctr"):
        self.block = bytearray(block)
        self.B = len(self.block)
        self.nbits = 8 * self.B
        if cipher not in self.CIPHERS:
            raise ValueError("unknown cipher %r: use one of %s" % (cipher, ", ".join(self.CIPHERS)))
        self.cipher = cipher
        if K < 2 or K > self.nbits:
            raise ValueError(
                "invalid K=%d: must satisfy 2 <= K <= block bit-count (%d)" % (K, self.nbits)
            )
        # K MUST be coprime to 8 (i.e. odd): otherwise gcd(K,8) > 1 and each plane
        # touches only fixed within-byte bit positions, which a password-less adversary
        # can detect on a single snapshot — voiding indistinguishability. (Mirrors the
        # Rust core's hard check; an odd prime via next_prime_coprime8 is recommended.)
        if K % 2 == 0:
            raise ValueError(
                "invalid K=%d: must be coprime to 8 (odd) or the planes collapse onto fixed "
                "bit positions and the container is no longer indistinguishable from random "
                "(use next_prime_coprime8)" % K
            )
        self.K = K

    @classmethod
    def create(cls, B, K, rng=secrets.token_bytes, cipher="aes256ctr"):
        """Fresh container = B random bytes. Indistinguishable from any full one."""
        return cls(bytearray(rng(B)), K, cipher)

    # ---- plane geometry: plane p owns global bit-indices g with g % K == p ----
    def _plane_slots(self, p):
        # number of valid t such that t*K + p < nbits
        return (self.nbits - 1 - p) // self.K + 1

    def _global(self, slot_t, plane):
        return slot_t * self.K + plane

    # ---- derivations ----
    def _prk(self, pw):
        # fast, salt-independent: locates plane + walk before the salt is known
        return hashlib.sha256(pw.encode("utf-8") + _u64(self.K)).digest()

    def _home(self, prk):
        # unbiased reduction mod K via rejection sampling over a counter stream
        zone = (2 ** 64 // self.K) * self.K
        ctr = 0
        while True:
            x = int.from_bytes(shake(prk, b"home", _u64(ctr), nbytes=8), "big")
            ctr += 1
            if x < zone:
                return x % self.K

    def _smask(self, prk):
        return shake(prk, b"saltmask", nbytes=S_BITS // 8)

    def _slot_seq(self, prk, plane, count):
        """`count` distinct slot indices in [0, M_p), SHAKE counter-mode with
        rejection sampling (no modulo bias)."""
        Mp = self._plane_slots(plane)
        if count > Mp:
            raise ValueError("walk longer than plane capacity")
        zone = (2 ** 64 // Mp) * Mp
        seen = set()
        out = []
        ctr = 0
        while len(out) < count:
            x = int.from_bytes(
                shake(prk, b"slots", _u64(plane), _u64(ctr), nbytes=8), "big"
            )
            ctr += 1
            if x >= zone:
                continue
            v = x % Mp
            if v not in seen:
                seen.add(v)
                out.append(v)
        return out

    def _slow(self, pw, salt):
        return hashlib.scrypt(
            pw.encode("utf-8") + _u64(self.K),
            salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
            maxmem=SCRYPT_MAXMEM, dklen=32,
        )

    def _cipher_tag(self):
        # Domain-separation tag bound into the token + MAC key so reading with the wrong cipher
        # fails at the token gate (clean None), not with garbage. shake256 uses an EMPTY tag, so
        # its wire format is byte-identical to the original single-cipher reference.
        return {"aes256ctr": b"aes256ctr", "chacha20": b"chacha20", "shake256": b""}[self.cipher]

    def _keystream(self, mk, n):
        # ct = pt XOR keystream. All three are IND$ stream ciphers; the choice is invisible in the
        # ciphertext. AES-CTR / ChaCha20 use the `cryptography` package (imported lazily so the
        # shake256 mode — and the rest of this reference — stay stdlib-only). pip install cryptography.
        if self.cipher == "shake256":
            return shake(mk, b"stream", nbytes=n)
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        if self.cipher == "aes256ctr":
            kn = shake(mk, b"stream-aes256ctr", nbytes=48)  # 32-byte key + 16-byte IV (BE counter)
            algo, mode = algorithms.AES(kn[:32]), modes.CTR(kn[32:48])
        elif self.cipher == "chacha20":
            # NOTE: `cryptography`'s ChaCha20 is the 16-byte-nonce / 64-bit-counter (Bernstein)
            # variant — NOT the Rust crate's IETF ChaCha20 (12-byte nonce). Self-consistent for this
            # reference's own round-trip; it does not reproduce the Rust keystream (this file is not
            # wire-compatible with the Rust crate regardless — different KDF + walk).
            kn = shake(mk, b"stream-chacha20", nbytes=48)  # 32-byte key + 16-byte nonce
            algo, mode = algorithms.ChaCha20(kn[:32], kn[32:48]), None
        else:
            raise ValueError("unknown cipher %r" % self.cipher)
        enc = Cipher(algo, mode, backend=default_backend()).encryptor()
        return enc.update(b"\x00" * n) + enc.finalize()

    # ---- read side ----
    def _locate(self, pw, maxprobe):
        """Return (plane, plaintext) for pw, or None. Sweeps from home, open-addressed."""
        prk = self._prk(pw)
        home = self._home(prk)
        smask = self._smask(prk)
        head_n = S_BITS + T_BITS + LEN_BITS
        for i in range(min(maxprobe, self.K)):   # only K distinct planes exist
            plane = (home + i) % self.K
            if head_n > self._plane_slots(plane):
                continue
            seq = self._slot_seq(prk, plane, head_n)
            head = [_get_bit(self.block, self._global(seq[j], plane)) for j in range(head_n)]

            salt = _xor(_bits_to_bytes(head[0:S_BITS]), smask)
            mk = self._slow(pw, salt)
            token = shake(mk, b"token", self._cipher_tag(), nbytes=T_BITS // 8)
            stored_token = _bits_to_bytes(head[S_BITS:S_BITS + T_BITS])
            if not hmac.compare_digest(token, stored_token):
                continue  # fast reject: wrong plane / wrong credential

            lenmask = shake(mk, b"len", nbytes=LEN_BITS // 8)
            len_field = _bits_to_bytes(head[S_BITS + T_BITS:head_n])
            L = int.from_bytes(_xor(len_field, lenmask), "big")
            total = head_n + 8 * L + TAG_BITS
            if total > self._plane_slots(plane):
                continue

            seq = self._slot_seq(prk, plane, total)
            ct_bits = [_get_bit(self.block, self._global(seq[j], plane))
                       for j in range(head_n, head_n + 8 * L)]
            tag_bits = [_get_bit(self.block, self._global(seq[j], plane))
                        for j in range(head_n + 8 * L, total)]
            ct = _bits_to_bytes(ct_bits)
            tag = _bits_to_bytes(tag_bits)

            mackey = shake(mk, b"mac", self._cipher_tag(), nbytes=32)
            if not hmac.compare_digest(tag, hmac.new(mackey, ct, hashlib.sha256).digest()):
                continue  # tampered or rare false token-match
            stream = self._keystream(mk, L)
            return plane, _xor(ct, stream)
        return None

    def read(self, pw, maxprobe=64):
        r = self._locate(pw, maxprobe)
        return None if r is None else r[1]

    def plane_of(self, pw, maxprobe=64):
        r = self._locate(pw, maxprobe)
        return None if r is None else r[0]

    # ---- write side ----
    def write(self, pw, plaintext, known_pws=(), maxprobe=64, salt=None):
        """
        Write `plaintext` under `pw`. To avoid corrupting existing payloads (L4),
        pass every other known password in `known_pws` so their planes are avoided.
        Reuses pw's own plane if it already has a payload (overwrite).
        Returns the plane index used.
        """
        if len(plaintext) >= (1 << 32):
            raise ValueError("payload length exceeds 32-bit length field (max ~4 GiB)")
        if salt is not None and len(salt) != S_BITS // 8:
            raise ValueError("salt must be exactly %d bytes" % (S_BITS // 8))
        prk = self._prk(pw)
        home = self._home(prk)

        existing = self.plane_of(pw, maxprobe)
        if existing is not None:
            plane = existing
        else:
            occupied = set()
            for q in known_pws:
                pq = self.plane_of(q, maxprobe)
                if pq is not None:
                    occupied.add(pq)
            # Search only the window the reader probes; placing beyond
            # min(maxprobe, K) would make the payload unreadable (silent loss).
            plane = None
            for i in range(min(maxprobe, self.K)):
                cand = (home + i) % self.K
                if cand not in occupied:
                    plane = cand
                    break
            if plane is None:
                raise ValueError("container full")

        total = S_BITS + T_BITS + LEN_BITS + 8 * len(plaintext) + TAG_BITS
        if total > self._plane_slots(plane):
            raise ValueError(
                "payload too large for plane size (%d bits > %d). Raise B or lower K."
                % (total, self._plane_slots(plane))
            )

        if salt is None:
            salt = secrets.token_bytes(S_BITS // 8)
        smask = self._smask(prk)
        mk = self._slow(pw, salt)
        token = shake(mk, b"token", self._cipher_tag(), nbytes=T_BITS // 8)
        lenmask = shake(mk, b"len", nbytes=LEN_BITS // 8)
        stream = self._keystream(mk, len(plaintext))
        mackey = shake(mk, b"mac", self._cipher_tag(), nbytes=32)

        ct = _xor(plaintext, stream)
        tag = hmac.new(mackey, ct, hashlib.sha256).digest()
        len_field = _xor(len(plaintext).to_bytes(LEN_BITS // 8, "big"), lenmask)
        salt_field = _xor(salt, smask)

        bits = (_bytes_to_bits(salt_field) + _bytes_to_bits(token) +
                _bytes_to_bits(len_field) + _bytes_to_bits(ct) + _bytes_to_bits(tag))
        seq = self._slot_seq(prk, plane, len(bits))
        for j, bit in enumerate(bits):
            _set_bit(self.block, self._global(seq[j], plane), bit)
        return plane

    def write_all_fresh(self, payloads, maxprobe=64, rng=secrets.token_bytes):
        """Re-randomize the WHOLE container: discard the current block, fill a fresh
        random one, and re-write every supplied payload with new salts. Defeats
        multi-snapshot diffing. You MUST pass every payload to retain — anything
        omitted is gone. Atomic: on error the original block is left untouched.

        `payloads` is an iterable of (password, plaintext) pairs."""
        payloads = list(payloads)
        tmp = KPDC(bytearray(rng(self.B)), self.K, self.cipher)
        for i, (pw, pt) in enumerate(payloads):
            known = [p for (p, _) in payloads[:i]]
            tmp.write(pw, pt, known, maxprobe, None)
        self.block = tmp.block  # commit only after all writes succeed


# --------------------------------------------------------------------------- #
#  Self-test / demo / reproducible vector
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    def det_rng(n, seed=b"KPDC-demo-seed-v0.3"):
        return hashlib.shake_256(seed).digest(n)

    K = next_prime_coprime8(419)
    print("K =", K, "(prime, coprime to 8)")
    pw_a, msg_a = "correct horse battery staple", b"the treaty is signed at dawn"
    pw_b, msg_b = "hunter2-xK!", b"meet at pier 39, midnight"

    # Exercise every selectable cipher. The cipher — like K and the KDF cost — is part of the
    # credential and is never stored. aes256ctr / chacha20 need `cryptography`; shake256 is stdlib.
    for cipher in KPDC.CIPHERS:
        try:
            c = KPDC.create(65536, K, rng=det_rng, cipher=cipher)
            # Whole-block re-randomize write (defeats multi-snapshot diffing): rebuild from ALL
            # payloads. Anything omitted would be destroyed.
            c.write_all_fresh([(pw_a, msg_a), (pw_b, msg_b)], maxprobe=4, rng=det_rng)
            assert c.read(pw_a, maxprobe=4) == msg_a, "A round-trip failed"
            assert c.read(pw_b, maxprobe=4) == msg_b, "B round-trip failed"
            assert c.read("wrong password", maxprobe=4) is None, "wrong pw should yield None"
            mean = sum(c.block) / len(c.block)
            print(
                "[%-10s] 2 payloads round-trip OK; wrong pw -> None; "
                "byte mean %.2f (uniform ~127.5); block[:16]=%s"
                % (cipher, mean, c.block[:16].hex())
            )
        except ImportError:
            print("[%-10s] skipped (needs cryptography: pip install cryptography)" % cipher)

    print(
        "(note: the cipher, like K and the KDF cost, is part of the credential and is not stored. "
        "azoth hides the contents/count of the block IN ISOLATION — not that you use it, and not "
        "under coercion: a tool built to hide payloads invites 'now the others'. Not an "
        "interrogation defense; see README / TECHNICAL_DETAILS.)"
    )
