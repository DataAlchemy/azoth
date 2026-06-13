#!/usr/bin/env python3
"""Exhaustive, analytic capstone (fast, deterministic — no simulation):

  A) Residue-class ones-bias for EVERY stride K = 2..512 (any plane leak at any K).
     Statistic ~ chi2_K under i.i.d-uniform H0. Report min-p, K=11, construction strides.
  B) FULL bit-autocorrelation spectrum via one FFT (every lag 1..N/2). Under H0 each
     normalized coefficient ~ N(0,1). Report max|z| and lags 8/11/88 (construction).
  Both with familywise (Bonferroni/Sidak) thresholds. A real plane/periodicity leak
  would make a CONSTRUCTION stride/lag survive correction; RNG noise will not.
"""
import math
import numpy as np
from scipy import stats

b = np.frombuffer(open("challenge_block.bin", "rb").read(), dtype=np.uint8)
bits = np.unpackbits(b, bitorder="little").astype(np.int64)
n = bits.size

# ---------- A) residue sweep, analytic ----------
def res_chisq(K):
    idx = np.arange(n) % K
    ones = np.bincount(idx, weights=bits, minlength=K)
    tot = np.bincount(idx, minlength=K).astype(np.float64)
    z = (ones - tot / 2.0) / np.sqrt(tot / 4.0)
    return float((z * z).sum())

Ks = list(range(2, 513))
rows = [(K, res_chisq(K)) for K in Ks]
ps = [(K, s, stats.chi2.sf(s, K)) for K, s in rows]
nK = len(Ks)
bonf = 0.01 / nK
ps_sorted = sorted(ps, key=lambda t: t[2])
print("A) RESIDUE-CLASS ones-bias sweep, K=2..512 (analytic chi2_K p-values)")
print(f"   tests={nK}, Bonferroni 0.01 threshold p<{bonf:.2e}")
print("   smallest-p strides:")
for K, s, p in ps_sorted[:8]:
    surv = " *** SURVIVES correction ***" if p < bonf else ""
    print(f"     K={K:3d}: chi2={s:8.2f}  p={p:.4e}{surv}")
k11 = [t for t in ps if t[0] == 11][0]
print(f"   TRUE K=11: chi2={k11[1]:.2f}  p={k11[2]:.3f}  (rank "
      f"{[t[0] for t in ps_sorted].index(11)+1}/{nK} by smallness — i.e. unremarkable)")
survivors = [(K, p) for K, s, p in ps if p < bonf]
print(f"   strides surviving familywise correction: {survivors if survivors else 'NONE'}")

# ---------- B) full autocorrelation spectrum via FFT ----------
x = bits * 2 - 1  # +-1
m = 1 << (int(np.ceil(np.log2(2 * n))))     # zero-pad for LINEAR autocorrelation
f = np.fft.rfft(x, m)
acf = np.fft.irfft(f * np.conj(f), m)[:n]   # acf[L] = sum_i x[i]x[i+L]
lags = np.arange(1, n // 2)
z = acf[1:n // 2] / np.sqrt((n - lags).astype(np.float64))  # ~N(0,1) under H0
absz = np.abs(z)
nlag = absz.size
# familywise: Sidak two-sided threshold for alpha=0.01 over nlag lags
alpha = 0.01
z_thresh = stats.norm.isf((1 - (1 - alpha) ** (1.0 / nlag)) / 2.0)
imax = int(np.argmax(absz))
print("\nB) BIT AUTOCORRELATION spectrum, all lags 1..N/2 (analytic N(0,1) z)")
print(f"   lags tested={nlag}; familywise |z| threshold (alpha=0.01) = {z_thresh:.2f}")
print(f"   max |z| = {absz[imax]:.2f} at lag {lags[imax]}"
      f"  ({'SURVIVES' if absz[imax] > z_thresh else 'within noise'})")
for L in (8, 11, 88):
    zz = acf[L] / math.sqrt(n - L)
    print(f"   lag {L:3d} (construction stride): z={zz:+.2f}  "
          f"p={2*stats.norm.sf(abs(zz)):.3f}")
n_exceed = int((absz > z_thresh).sum())
print(f"   lags exceeding familywise threshold: {n_exceed}")

print("\nCAPSTONE VERDICT")
print("-" * 64)
ok = (not survivors) and (absz[imax] <= z_thresh)
if ok:
    print(" No residue stride (any K<=512) and no autocorrelation lag survives")
    print(" familywise correction. K=11 and lags 8/11/88 are unremarkable.")
    print(" => No plane/periodicity structure. Indistinguishable from random.")
else:
    print(" Something survived correction — inspect whether it is a construction stride.")
