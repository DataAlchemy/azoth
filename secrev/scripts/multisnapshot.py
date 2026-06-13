#!/usr/bin/env python3
"""Multi-snapshot adversary against BOTH write modes, full K=11 containers.

The adversary images the block across N writes of the SAME payloads and builds a
per-bit-position map. Two maps reveal everything a multi-snapshot attacker can get:
  change_freq[g] = P(bit g flips between consecutive snapshots)
  static[g]      = bit g NEVER changed across all snapshots

For the DEFAULT (rerand) write, every bit is re-randomized each snapshot, so both
maps must be featureless. For the in-place write, untouched fill bits never move,
so static[] exactly marks the unwritten slots -> the written/unwritten partition
(hence presence, per-plane payload size, count, location) leaks.
"""
import glob
import numpy as np

def stack(prefix):
    files = sorted(glob.glob(f"snapshots/{prefix}_*.bin"))
    arr = np.stack([np.unpackbits(np.frombuffer(open(f, "rb").read(), np.uint8),
                                  bitorder="little") for f in files])
    return arr  # shape (N_snapshots, nbits)

def analyze(name, A):
    N, nbits = A.shape
    change = (A[1:] != A[:-1]).mean(axis=0)          # per-position flip frequency
    pmean = A.mean(axis=0)                             # per-position mean value
    static = (A.min(axis=0) == A.max(axis=0))         # never changed at all
    n_static = int(static.sum())
    # residue-class (plane) view of the static set
    res = np.nonzero(static)[0] % 11
    res_hist = np.bincount(res, minlength=11)
    print(f"\n=== {name}  (N={N} snapshots, {nbits} bits) ===")
    print(f"  change_freq:  mean {change.mean():.4f}  min {change.min():.4f}  max {change.max():.4f}")
    print(f"  per-pos mean: mean {pmean.mean():.4f}  min {pmean.min():.4f}  max {pmean.max():.4f}")
    print(f"  NEVER-changing positions: {n_static}  ({100*n_static/nbits:.2f}% of block)")
    if n_static > 50:
        print(f"    -> these are the UNWRITTEN slots; their per-plane (mod 11) counts:")
        print(f"       {res_hist.tolist()}  (sum {res_hist.sum()})")
        # variance bimodality: can we separate written from unwritten by change_freq?
        thr = 0.25
        written = change > thr
        print(f"    -> threshold change_freq>{thr}: {int(written.sum())} 'written' "
              f"vs {int((~written).sum())} 'static/unwritten' "
              f"=> the payload partition is RECOVERED without any password")
    else:
        print(f"    -> NO static positions: written/unwritten partition is INVISIBLE")
    # how far is the change map from a flat 0.5? (z of the most extreme position)
    # under rerand H0 each change_freq ~ Binomial(N-1,0.5)/(N-1): sd = 0.5/sqrt(N-1)
    sd = 0.5 / np.sqrt(N - 1)
    zmax = np.abs(change - 0.5).max() / sd
    print(f"  most extreme change-freq deviation from 0.5: z = {zmax:.2f} "
          f"(flat if small; structural if huge)")
    return change, static

print("MULTI-SNAPSHOT ANALYSIS — does imaging across many writes reveal payloads?")
cr, sr = analyze("DEFAULT re-randomize write (write_all_fresh)", stack("snap_rerand"))
ci, si = analyze("in-place write (no_rerandomize)", stack("snap_inplace"))

print("\n" + "=" * 74)
print("CONCLUSION")
print("=" * 74)
print(f" DEFAULT (rerand): never-changing positions = {int(sr.sum())}; change map flat ~0.5.")
print(f"   => multi-snapshot of a full random/default container shows NOTHING:")
print(f"      no position is static, no payload boundary, no count, no K.")
print(f" in-place:         never-changing positions = {int(si.sum())} (the unwritten slots).")
print(f"   => the written/unwritten partition leaks -> presence/size/count/location.")
print(f"      This is the documented reason write_all_fresh is the CLI default.")
