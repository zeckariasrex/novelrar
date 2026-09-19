#!/usr/bin/env python3
"""3-D lift of the windmill dual: one hole per axis-parallel line.

A Latin square L[y, x] = z places a hole so that every x-line, y-line
and z-line of the D^3 cube holds exactly one hole. Dual codec: store L
(D^2 bytes) + per-slice windmill recipes, paint, XOR residual.

This is geometry, not RAR/LZMA/LZ4.
"""
from __future__ import annotations

import math
import numpy as np


def latin_square(D: int, a: int = 1, b: int = 2) -> np.ndarray:
    """L[y, x] = (a*x + b*y) mod D. Need gcd(a,D)=gcd(b,D)=1."""
    if math.gcd(a, D) != 1:
        a = next(i for i in range(1, D) if math.gcd(i, D) == 1)
    if math.gcd(b, D) != 1:
        b = next(i for i in range(1, D) if math.gcd(i, D) == 1 and i != a)
    y, x = np.indices((D, D))
    return ((a * x + b * y) % D).astype(np.int32)


def verify_latin(L: np.ndarray) -> dict:
    D = L.shape[0]
    rows = all(len(set(L[r].tolist())) == D for r in range(D))
    cols = all(len(set(L[:, c].tolist())) == D for c in range(D))
    return {"ok": rows and cols, "D": D, "rows": rows, "cols": cols}


def hole_mask(L: np.ndarray) -> np.ndarray:
    D = L.shape[0]
    m = np.zeros((D, D, D), dtype=bool)
    yy, xx = np.indices((D, D))
    m[L, yy, xx] = True
    return m


def pack_volume_slices(vol: np.ndarray, pack_slice):
    D = vol.shape[0]
    reps = []
    for z in range(D):
        reps.append(pack_slice(vol[z]))
    return {
        "D": D,
        "mean_residual_zero": float(np.mean([r["residual_zero"] for r in reps])),
        "all_lossless": all(r.get("lossless", False) for r in reps),
        "slices": reps,
    }
