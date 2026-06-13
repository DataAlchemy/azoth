#!/usr/bin/env python3
"""Run down the single flagged statistic: res_ones_chisq_mod8 on the challenge.

Questions:
  A) Which bit-positions (0..7) carry the imbalance, and how big is it?
  B) Is 23.77 an unusual draw under the i.i.d-uniform null? (large empirical null:
     fresh /dev/urandom blocks + the azoth controls)
  C) Does the AZOTH CONSTRUCTION push this statistic up (full vs empty vs random)?
     If full==empty==random on this stat, the challenge's value is a fluctuation,
     NOT a distinguisher: no threshold separates azoth-full from random.
"""
import glob
import math
import os

import numpy as np
from scipy import stats

N = 65536


def bits_of(b):
    return np.unpackbits(b, bitorder="little")


def res_ones_chisq(bits, K):
    n = bits.size
    idx = np.arange(n) % K
    ones = np.bincount(idx, weights=bits, minlength=K)
    tot = np.bincount(idx, minlength=K).astype(np.float64)
    z = (ones - tot / 2.0) / np.sqrt(tot / 4.0)
    return float((z ** 2).sum()), z


def load_bits(path):
    return bits_of(np.frombuffer(open(path, "rb").read(), dtype=np.uint8))


ch_bits = load_bits("challenge_block.bin")
ch_stat, ch_z = res_ones_chisq(ch_bits, 8)

print("A) Challenge per-bit-position ones imbalance (z = (ones-50%)/sd, 65536 bits/position)")
print(f"   {'bitpos':>6} {'ones':>8} {'frac':>10} {'z':>8}")
idx = np.arange(ch_bits.size) % 8
for p in range(8):
    ones = int(ch_bits[idx == p].sum())
    frac = ones / 65536
    print(f"   {p:6d} {ones:8d} {frac:10.5f} {ch_z[p]:8.2f}")
print(f"   -> res_ones_chisq_mod8 = {ch_stat:.3f}  (chi2_8: mean 8, sd 4)")
print(f"   -> analytic tail p = P(chi2_8 > {ch_stat:.2f}) = {stats.chi2.sf(ch_stat, 8):.4e}")

# B) large empirical null from fresh OS randomness (in-memory, no files)
print("\nB) Empirical null from fresh /dev/urandom blocks (same size)")
NSIM = 5000
sims = np.empty(NSIM)
for i in range(NSIM):
    b = np.frombuffer(os.urandom(N), dtype=np.uint8)
    sims[i], _ = res_ones_chisq(bits_of(b), 8)
exceed = int((sims >= ch_stat).sum())
print(f"   {NSIM} random blocks: mean {sims.mean():.3f}, sd {sims.std():.3f}, "
      f"max {sims.max():.3f}")
print(f"   fraction of RANDOM blocks with stat >= challenge ({ch_stat:.2f}): "
      f"{exceed}/{NSIM} = {exceed/NSIM:.4f}")
print(f"   (i.e. a pure-random block is at least this 'biased' ~{100*exceed/NSIM:.1f}% of the time)")

# C) does the construction move this statistic? full vs empty vs random
print("\nC) Does the AZOTH construction push res_ones_chisq_mod8 up?")
def group_stat(paths):
    return np.array([res_ones_chisq(load_bits(p), 8)[0] for p in paths])

empty = group_stat(sorted(glob.glob("controls/control_empty_*.bin")))
full = group_stat(sorted(glob.glob("controls/control_full_*.bin")))
fmax = group_stat(sorted(glob.glob("controls/control_fullmax_*.bin")))
print(f"   empty   azoth (n={len(empty)}): mean {empty.mean():.3f} sd {empty.std():.3f} max {empty.max():.3f}")
print(f"   full    azoth (n={len(full)}):  mean {full.mean():.3f} sd {full.std():.3f} max {full.max():.3f}")
print(f"   fullmax azoth (n={len(fmax)}):  mean {fmax.mean():.3f} sd {fmax.std():.3f} max {fmax.max():.3f}")
print(f"   random  (sim n={NSIM}):         mean {sims.mean():.3f} sd {sims.std():.3f}")
tp = stats.ttest_ind(empty, full, equal_var=False).pvalue
print(f"   empty-vs-full t-test p = {tp:.3f}  (construction does NOT change this stat if p large)")

print("\nCONCLUSION")
print("-" * 70)
if exceed / NSIM > 0.001 and tp > 0.01:
    print(f"The challenge's mod-8 value is a TAIL FLUCTUATION shared by pure random")
    print(f"(~{100*exceed/NSIM:.1f}% of random blocks match or exceed it) and the azoth")
    print(f"construction does NOT elevate it (empty~full~random). It therefore CANNOT")
    print(f"separate an azoth container from random — it is NOT a distinguisher.")
else:
    print("Investigate further: the statistic may carry real structure.")
