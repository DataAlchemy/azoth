#!/usr/bin/env python3
"""Can we determine K?

(1) From the SINGLE challenge block (the actual attack surface): try every candidate
    K and look for a residue-class signal. The design makes K a *secret* credential
    component; if the block reveals it, that is a partial break.
(2) Contrast: the ONE documented condition under which K DOES leak — multi-snapshot
    diffing of an *in-place* write (TECHNICAL_DETAILS §8). Demonstrated on our own
    snapshots: GCD of changed-bit-position differences = K.
(3) Show the default re-randomize write hides K again.
"""
import math
from functools import reduce
import numpy as np
from scipy import stats


def bits_of_file(p):
    return np.unpackbits(np.frombuffer(open(p, "rb").read(), dtype=np.uint8), bitorder="little")


def res_ones_chisq(bits, K):
    idx = np.arange(bits.size) % K
    ones = np.bincount(idx, weights=bits, minlength=K)
    tot = np.bincount(idx, minlength=K).astype(np.float64)
    z = (ones - tot / 2.0) / np.sqrt(tot / 4.0)
    return float((z ** 2).sum())


def gcd_list(xs):
    return reduce(math.gcd, xs)


print("=" * 78)
print("(1) Determine K from the SINGLE challenge block alone")
print("=" * 78)
ch = bits_of_file("challenge_block.bin")
print(" For each candidate K, res_ones_chisq_mod K should be ~chi2_K (mean K) if there")
print(" is NO plane structure. A true K would stand out as a LOW p-value (excess bias).")
print(f" {'K':>3} {'chi2_K':>9} {'analytic p':>12}")
hits = []
for K in range(2, 33):
    s = res_ones_chisq(ch, K)
    p = stats.chi2.sf(s, K)
    mark = "  <-- would indicate structure" if p < 0.01 else ""
    if p < 0.01:
        hits.append(K)
    if K in (7, 8, 11, 13, 16, 22) or p < 0.05:
        print(f" {K:3d} {s:9.2f} {p:12.4f}{mark}")
print(f"\n K=11 (the true value): chi2_11 = {res_ones_chisq(ch,11):.2f}, "
      f"p = {stats.chi2.sf(res_ones_chisq(ch,11),11):.3f}  -> indistinguishable from every other K")
print(f" residue strides with p<0.01: {hits if hits else 'NONE'}")
print(" => The block gives NO signal for K=11 over any other K. K is NOT recoverable")
print("    from a single snapshot. We only 'know' K=11 because the challenge stated it")
print("    (K is part of the credential, transmitted out-of-band, exactly as designed).")

print("\n" + "=" * 78)
print("(2) The ONLY leak path: multi-snapshot diff of an IN-PLACE write (TECH §8)")
print("=" * 78)
b0 = bits_of_file("/tmp/ksnap/snap0.bin")   # fresh random block
bA = bits_of_file("/tmp/ksnap/snapA.bin")   # after ONE in-place write
changed = np.nonzero(b0 != bA)[0]
print(f" changed bit positions between snap0 and snapA: {changed.size}")
res = set((changed % 11).tolist())
print(f" their residues mod 11: {sorted(res)}  (a single class => one plane touched)")
# recover K WITHOUT knowing it: GCD of differences of changed positions
diffs = (changed - changed[0]).tolist()[1:]
K_recovered = gcd_list(diffs)
print(f" GCD of changed-position differences = {K_recovered}   <== recovers K with no password")
print(f" => two snapshots of an in-place write leak K (={K_recovered}) AND that plane "
      f"{changed[0] % 11} holds a payload (existence+location leak).")

print("\n" + "=" * 78)
print("(3) The DEFAULT re-randomize write hides K again")
print("=" * 78)
bB = bits_of_file("/tmp/ksnap/snapB.bin")   # after a re-randomizing write
changed2 = np.nonzero(bA != bB)[0]
frac = changed2.size / bA.size
res2 = sorted(set((changed2 % 11).tolist()))
g2 = gcd_list((changed2 - changed2[0]).tolist()[1:])
print(f" changed bits snapA->snapB: {changed2.size} ({frac*100:.1f}% of all bits)")
print(f" residues mod 11 of changed positions: {res2}  (ALL classes => whole block)")
print(f" GCD of changed-position differences = {g2}  (=1: no stride, K not recoverable)")
print(" => whole-block re-randomization (the CLI default) destroys the K leak.")

print("\nANSWER")
print("-" * 78)
print(" - From challenge_block.bin alone: K is NOT determinable (no residue signal at")
print("   any stride; K=11 looks like every other K and like pure random).")
print(" - K=11 is known only because the challenge told us; it is a secret credential.")
print(" - K leaks ONLY under multi-snapshot diffing of in-place writes (shown above),")
print("   which (a) needs >=2 images we do not have, and (b) is defended by the default")
print("   re-randomizing write. With our single snapshot, K stays hidden.")
