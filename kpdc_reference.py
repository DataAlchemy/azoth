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
  intra-plane walk: SHAKE-driven distinct-slot sequence (counter mode)

THIS IS A READABLE REFERENCE, NOT PRODUCTION CODE.
  * Slot selection uses `mod M_p`, which has small modulo bias -- use rejection
    sampling in production.
  * scrypt parameters are low for demo speed; raise N for real use.
  * v1 scope: single-snapshot deniability only (see spec section 4). Multi-snapshot
    diffing leaks K; the V2 whole-block re-randomize mode is not implemented here.

NOT WIRE-COMPATIBLE with the Rust crate (azoth/). The Rust implementation uses
Argon2id (not scrypt) and a rejection-sampled XOF slot walk (not counter-mode
modulo), so containers written by one cannot be read by the other. This file is a
readable spec mirror, not an interoperable implementation.
"""

import hashlib
import hmac
import secrets

# ---- field sizes (bits) ----
S_BITS   = 128   # per-write salt (nonce)
T_BITS   = 128   # recognition token (fast plane reject)
LEN_BITS = 32    # payload length field
TAG_BITS = 256   # HMAC-SHA256 integrity tag

# ---- scrypt cost (LOW for demo; raise N for real use) ----
SCRYPT_N = 1 << 13
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

    def __init__(self, block, K):
        self.block = bytearray(block)
        self.B = len(self.block)
        self.nbits = 8 * self.B
        self.K = K

    @classmethod
    def create(cls, B, K, rng=secrets.token_bytes):
        """Fresh container = B random bytes. Indistinguishable from any full one."""
        return cls(bytearray(rng(B)), K)

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
        return int.from_bytes(shake(prk, b"home", nbytes=8), "big") % self.K

    def _smask(self, prk):
        return shake(prk, b"saltmask", nbytes=S_BITS // 8)

    def _slot_seq(self, prk, plane, count):
        """`count` distinct slot indices in [0, M_p), SHAKE-driven (counter mode)."""
        Mp = self._plane_slots(plane)
        if count > Mp:
            raise ValueError("walk longer than plane capacity")
        seen = set()
        out = []
        ctr = 0
        while len(out) < count:
            x = int.from_bytes(
                shake(prk, b"slots", _u64(plane), _u64(ctr), nbytes=8), "big"
            ) % Mp
            ctr += 1
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    def _slow(self, pw, salt):
        return hashlib.scrypt(
            pw.encode("utf-8") + _u64(self.K),
            salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
            maxmem=SCRYPT_MAXMEM, dklen=32,
        )

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
            token = shake(mk, b"token", nbytes=T_BITS // 8)
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

            mackey = shake(mk, b"mac", nbytes=32)
            if not hmac.compare_digest(tag, hmac.new(mackey, ct, hashlib.sha256).digest()):
                continue  # tampered or rare false token-match
            stream = shake(mk, b"stream", nbytes=L)
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
            plane = None
            for i in range(self.K):
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
        token = shake(mk, b"token", nbytes=T_BITS // 8)
        lenmask = shake(mk, b"len", nbytes=LEN_BITS // 8)
        stream = shake(mk, b"stream", nbytes=len(plaintext))
        mackey = shake(mk, b"mac", nbytes=32)

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


# --------------------------------------------------------------------------- #
#  Self-test / demo / reproducible vector
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    def det_rng(n, seed=b"KPDC-demo-seed-v0.3"):
        return hashlib.shake_256(seed).digest(n)

    K = next_prime_coprime8(419)
    print("K =", K, "(prime, coprime to 8)")

    c = KPDC.create(65536, K, rng=det_rng)

    pw_a, msg_a = "correct horse battery staple", b"the treaty is signed at dawn"
    pw_b, msg_b = "hunter2-xK!", b"meet at pier 39, midnight"

    pa = c.write(pw_a, msg_a, known_pws=[], salt=b"\x01" * 16)
    pb = c.write(pw_b, msg_b, known_pws=[pw_a], salt=b"\x02" * 16)
    print("wrote payload A in plane", pa, "| payload B in plane", pb)

    assert c.read(pw_a) == msg_a, "A round-trip failed"
    assert c.read(pw_b) == msg_b, "B round-trip failed"
    assert c.read("wrong password") is None, "wrong password should yield None"
    print("round-trip OK; wrong password -> None")

    # holder of pw_a learns plane A only; cannot see B or the count
    print("pw_a sees plane:", c.plane_of(pw_a), "| pw_b sees plane:", c.plane_of(pw_b))

    # indistinguishability sniff: byte mean should sit near 127.5 (uniform)
    mean = sum(c.block) / len(c.block)
    print("block byte mean: %.2f (uniform ~127.5)" % mean)
    print("reproducible vector block[:32] =", c.block[:32].hex())
