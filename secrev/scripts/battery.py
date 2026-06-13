#!/usr/bin/env python3
"""
azoth deniability challenge — statistical distinguisher battery.

Compares challenge_block.bin against matched controls:
  - urandom.bin / control_random.bin : uniform random
  - control_empty_*.bin              : fresh azoth containers (no payload)
  - control_full_*.bin               : azoth filled to ~98.5% (like the challenge)
  - control_fullmax_*.bin            : azoth filled to plane capacity

Strategy:
  1. Compute a battery of statistics on every file.
  2. Empirical null: where does the challenge sit inside the CONTROL distribution?
  3. Decisive test: can ANY statistic separate {empty} from {full}? If "empty==full"
     fails, that separating statistic is the structural distinguisher.
"""
import glob
import gzip
import bz2
import lzma
import math
import os
import sys

import numpy as np
from scipy import stats

CTRL = "controls"


def load(path):
    return np.frombuffer(open(path, "rb").read(), dtype=np.uint8)


def bits_of(b):
    # LSB-first within each byte, matching azoth's bit ordering
    return np.unpackbits(b, bitorder="little")


# ---------------- individual statistics ----------------
def byte_chisq(b):
    counts = np.bincount(b, minlength=256).astype(np.float64)
    exp = len(b) / 256.0
    return float(((counts - exp) ** 2 / exp).sum())


def monobit_z(bits):
    n = bits.size
    ones = int(bits.sum())
    # z of ones count vs Binomial(n,1/2)
    return (ones - n / 2) / math.sqrt(n / 4)


def runs_z(bits):
    # adjacent-bit transitions ~ Normal((n-1)/2, (n-1)/4)
    t = int(np.count_nonzero(bits[1:] != bits[:-1]))
    n = bits.size
    mu = (n - 1) / 2.0
    sd = math.sqrt((n - 1) / 4.0)
    return (t - mu) / sd


def digram_chisq(b):
    n = (b.size // 2) * 2
    pairs = b[:n].reshape(-1, 2)
    idx = pairs[:, 0].astype(np.int32) * 256 + pairs[:, 1]
    counts = np.bincount(idx, minlength=65536).astype(np.float64)
    exp = pairs.shape[0] / 65536.0
    return float(((counts - exp) ** 2 / exp).sum())


def serial_corr(b):
    x = b.astype(np.float64)
    x = x - x.mean()
    num = float((x[:-1] * x[1:]).sum())
    den = float((x * x).sum())
    return num / den


def residue_ones_chisq(bits, K):
    """chi-square of ones-count per residue class g mod K (the 'planes').
    H0: every class is ~50% ones. df = K (each class an independent Binomial)."""
    n = bits.size
    idx = np.arange(n) % K
    ones = np.bincount(idx, weights=bits, minlength=K)
    tot = np.bincount(idx, minlength=K).astype(np.float64)
    # per-class z^2 of ones vs Binomial(tot,1/2); sum ~ chi2_K
    z = (ones - tot / 2.0) / np.sqrt(tot / 4.0)
    return float((z ** 2).sum())


def residue_byte_chisq(b, K):
    """Treat bytes at positions p mod K as a sub-stream; sum per-class byte chi2.
    Catches any byte-level bias keyed to a stride-K layout. df = K*255."""
    total = 0.0
    for r in range(K):
        sub = b[r::K]
        if sub.size < 256:
            continue
        total += byte_chisq(sub)
    return total


def compress_ratio(b, fn):
    raw = b.tobytes()
    return len(fn(raw)) / len(raw)


def shannon_entropy(b):
    counts = np.bincount(b, minlength=256).astype(np.float64)
    p = counts / counts.sum()
    nz = p[p > 0]
    return float(-(nz * np.log2(nz)).sum())  # bits per byte; 8.0 = perfectly uniform


def min_entropy(b):
    counts = np.bincount(b, minlength=256).astype(np.float64)
    pmax = counts.max() / counts.sum()
    return float(-math.log2(pmax))


def spectral_maxpower(bits):
    # DFT of +-1 sequence; report max normalized power excluding DC.
    x = bits.astype(np.float64) * 2 - 1
    f = np.fft.rfft(x)
    p = (f.real ** 2 + f.imag ** 2)
    p[0] = 0.0
    # normalize: for white noise, power ~ Exp(mean=n/2 *2?) — use ratio to mean
    return float(p.max() / p[1:].mean())


def block_freq_chisq(bits, m=128):
    # NIST block frequency: proportion of ones in M-bit blocks
    nblk = bits.size // m
    blk = bits[: nblk * m].reshape(nblk, m).sum(axis=1)
    # each ~ Binomial(m,1/2); chi2 = sum((ones - m/2)^2/(m/4))
    return float((((blk - m / 2.0) ** 2) / (m / 4.0)).sum()), nblk


def cusum_max(bits):
    # NIST cumulative sums: max excursion of the +-1 walk, normalized by sqrt(n)
    x = bits.astype(np.float64) * 2 - 1
    s = np.cumsum(x)
    return float(np.max(np.abs(s)) / math.sqrt(bits.size))


# ---------------- run battery on a file ----------------
def stats_for(path):
    b = load(path)
    bits = bits_of(b)
    bf, nblk = block_freq_chisq(bits, 128)
    return {
        "byte_chisq": byte_chisq(b),
        "monobit_z": monobit_z(bits),
        "runs_z": runs_z(bits),
        "digram_chisq": digram_chisq(b),
        "serial_corr": serial_corr(b),
        "res_ones_chisq_mod7": residue_ones_chisq(bits, 7),
        "res_ones_chisq_mod8": residue_ones_chisq(bits, 8),
        "res_ones_chisq_mod11": residue_ones_chisq(bits, 11),
        "res_ones_chisq_mod16": residue_ones_chisq(bits, 11 * 8),  # plane x bitpos
        "res_byte_chisq_mod11": residue_byte_chisq(b, 11),
        "gzip_ratio": compress_ratio(b, lambda r: gzip.compress(r, 9)),
        "bz2_ratio": compress_ratio(b, lambda r: bz2.compress(r, 9)),
        "lzma_ratio": compress_ratio(b, lzma.compress),
        "entropy_bpb": shannon_entropy(b),
        "min_entropy": min_entropy(b),
        "spectral_maxpow": spectral_maxpower(bits),
        "blockfreq_chisq": bf,
        "cusum_max": cusum_max(bits),
    }


def group(paths):
    return [stats_for(p) for p in paths]


def col(rows, key):
    return np.array([r[key] for r in rows], dtype=np.float64)


def main():
    challenge = stats_for("challenge_block.bin")

    empty = group(sorted(glob.glob(f"{CTRL}/control_empty_*.bin")))
    full = group(sorted(glob.glob(f"{CTRL}/control_full_*.bin")))
    fullmax = group(sorted(glob.glob(f"{CTRL}/control_fullmax_*.bin")))
    rand = group(
        [f"{CTRL}/urandom.bin", f"{CTRL}/control_random.bin"]
    )
    allctrl = empty + full + fullmax + rand

    print(f"# controls: {len(empty)} empty, {len(full)} full, "
          f"{len(fullmax)} fullmax, {len(rand)} random\n")

    keys = list(challenge.keys())

    # ---- 1. Challenge inside the control distribution ----
    print("=" * 100)
    print("1) CHALLENGE vs CONTROL DISTRIBUTION  (z = how many control-sd's the challenge sits from the control mean)")
    print("=" * 100)
    hdr = f"{'statistic':24} {'challenge':>14} {'ctrl_mean':>14} {'ctrl_sd':>12} {'z':>8} {'ctrl_min':>14} {'ctrl_max':>14} inside?"
    print(hdr)
    print("-" * len(hdr))
    flags = []
    for k in keys:
        c = col(allctrl, k)
        ch = challenge[k]
        mu, sd = c.mean(), c.std(ddof=1)
        z = (ch - mu) / sd if sd > 0 else 0.0
        inside = c.min() <= ch <= c.max()
        if abs(z) > 4:
            flags.append((k, z))
        print(f"{k:24} {ch:14.5f} {mu:14.5f} {sd:12.5f} {z:8.2f} "
              f"{c.min():14.5f} {c.max():14.5f} {'YES' if inside else '*** NO ***'}")

    # ---- 2. Decisive: can any statistic separate EMPTY from FULL? ----
    print("\n" + "=" * 100)
    print("2) DECISIVE TEST — does 'empty == full' hold? (Welch t-test + Mann-Whitney per statistic)")
    print("   A statistic that separates empty from full IS the structural distinguisher.")
    print("=" * 100)
    print(f"{'statistic':24} {'empty_mean':>14} {'full_mean':>14} {'t_p':>12} {'mw_p':>12}  separates?")
    print("-" * 92)
    m = len(keys)
    alpha = 0.01 / m  # Bonferroni across the battery
    sep = []
    for k in keys:
        e, f = col(empty, k), col(full, k)
        # guard against degenerate (zero-variance) columns
        try:
            t_p = stats.ttest_ind(e, f, equal_var=False).pvalue
        except Exception:
            t_p = float("nan")
        try:
            mw_p = stats.mannwhitneyu(e, f, alternative="two-sided").pvalue
        except Exception:
            mw_p = float("nan")
        is_sep = (t_p < alpha) or (mw_p < alpha)
        if is_sep:
            sep.append((k, t_p, mw_p))
        print(f"{k:24} {e.mean():14.5f} {f.mean():14.5f} {t_p:12.2e} {mw_p:12.2e}  "
              f"{'*** YES ***' if is_sep else 'no'}")
    print(f"\n(Bonferroni alpha = 0.01/{m} = {alpha:.2e})")

    # ---- 3. Verdict ----
    print("\n" + "=" * 100)
    print("VERDICT")
    print("=" * 100)
    if flags:
        print("Challenge is an OUTLIER vs controls on:", flags)
    else:
        print("Challenge sits INSIDE the control distribution on every statistic (|z|<=4).")
    if sep:
        print("empty/full SEPARATED by:", [(k, f'tp={tp:.1e}', f'mwp={mp:.1e}') for k, tp, mp in sep])
        print(">>> POTENTIAL BREAK: a statistic distinguishes empty from full.")
    else:
        print("NO statistic separates empty from full at Bonferroni alpha. 'empty == full' holds.")
        print(">>> NO BREAK on the statistical/structural axis.")


if __name__ == "__main__":
    main()
