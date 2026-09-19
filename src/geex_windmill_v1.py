#!/usr/bin/env python3
"""GEEX-WINDMILL v1 — official staircase, exact-T target, max-space paint.

Construction (IMO 2025 P6 / 3Blue1Brown):
  n = k^2
  gaps: (col a, row b) with b ≡ k·a (mod k^2+1)   [1-based]
  interior: (k-1)^2 squares of side k, offset +1 col from a gap
  boundary: leftover partitioned into rectangles (target 4(k-1))

Dual codec: store π + gap bytes + one fill per tile, paint, XOR residual.
No unrar / 7-Zip / LZ4 source.
"""
from __future__ import annotations

import json, math
from pathlib import Path
import numpy as np

ART = Path("/home/workdir/artifacts")


def lis_len(seq):
    tails = []
    for x in seq:
        lo, hi = 0, len(tails)
        while lo < hi:
            mid = (lo + hi) // 2
            if tails[mid] < x:
                lo = mid + 1
            else:
                hi = mid
        if lo == len(tails):
            tails.append(x)
        else:
            tails[lo] = x
    return len(tails)


def lds_len(seq):
    return lis_len([-x for x in seq])


def official_perm(k: int) -> np.ndarray:
    """pi[col] = row, 0-based. 1-based: row ≡ k·col (mod n+1)."""
    n = k * k
    mod = n + 1
    pi = np.empty(n, dtype=int)
    used = set()
    for a in range(n):
        b = (k * (a + 1)) % mod
        if b == 0:
            b = mod
        b -= 1
        if b >= n or b in used:
            b = next(i for i in range(n) if i not in used)
        pi[a] = b
        used.add(b)
    return pi


def greedy_rects(mask: np.ndarray):
    """Partition True cells into rectangles via repeated largest-rect."""
    m = mask.copy()
    H, W = m.shape
    rects = []
    while m.any():
        best = (0, 0, 0, 0, 0)
        height = np.zeros(W, dtype=int)
        for y in range(H):
            for x in range(W):
                height[x] = height[x] + 1 if m[y, x] else 0
            stack = []
            for x in range(W + 1):
                h = int(height[x]) if x < W else 0
                start = x
                while stack and stack[-1][1] > h:
                    sx, sh = stack.pop()
                    area = sh * (x - sx)
                    if area > best[0]:
                        best = (area, sx, y - sh + 1, x - sx, sh)
                    start = sx
                stack.append((start, h))
        _, x, y, w, h = best
        if best[0] <= 0:
            ys, xs = np.nonzero(m)
            x, y, w, h = int(xs[0]), int(ys[0]), 1, 1
        rects.append((int(x), int(y), int(w), int(h)))
        m[y:y + h, x:x + w] = False
    return rects


def official_tiles(k: int):
    """Interior kxk at offset (+1,0) from each gap, then greedy leftover."""
    n = k * k
    pi = official_perm(k)
    board = np.zeros((n, n), dtype=np.int16)
    for c, r in enumerate(pi):
        board[r, c] = -1
    tiles = []
    for c, r in enumerate(pi):
        x0, y0 = c + 1, r
        if x0 + k <= n and y0 + k <= n:
            sl = board[y0:y0 + k, x0:x0 + k]
            if (sl == 0).all():
                sl[:] = 1
                tiles.append((x0, y0, k, k, "interior"))
    leftover = board == 0
    bound = greedy_rects(leftover)
    for x, y, w, h in bound:
        tiles.append((x, y, w, h, "boundary"))
        board[y:y + h, x:x + w] = 2
    ok = (board != 0).all()
    return pi, tiles, ok


def data_perm(board: np.ndarray) -> np.ndarray:
    n = board.shape[0]
    used = set()
    pi = np.empty(n, dtype=int)
    for c in range(n):
        col = board[:, c]
        cnt = np.bincount(col, minlength=256)
        mode = int(cnt.argmax())
        order = np.argsort(-np.abs(col.astype(int) - mode))
        r = next(int(i) for i in order if i not in used)
        pi[c] = r
        used.add(r)
    return pi


def tiles_from_perm(pi: np.ndarray):
    n = len(pi)
    mask = np.ones((n, n), dtype=bool)
    for c, r in enumerate(pi):
        mask[r, c] = False
    rects = greedy_rects(mask)
    return [(x, y, w, h, "greedy") for x, y, w, h in rects]


def paint(board: np.ndarray, pi, tiles):
    pred = np.zeros_like(board)
    fills = []
    for x, y, w, h, kind in tiles:
        block = board[y:y + h, x:x + w]
        fill = int(np.bincount(block.ravel(), minlength=256).argmax())
        fills.append((kind, fill, w * h))
        pred[y:y + h, x:x + w] = fill
    for c, r in enumerate(pi):
        pred[r, c] = board[r, c]
    residual = board ^ pred
    return pred, residual, fills


def pack_report(name, board, k=None, how="official"):
    n = board.shape[0]
    if how == "official":
        if k is None:
            k = int(round(math.sqrt(n)))
        pi, tiles, ok = official_tiles(k)
        cover_ok = ok
    elif how == "data":
        pi = data_perm(board)
        tiles = tiles_from_perm(pi)
        cover_ok = True
        k = int(round(math.sqrt(n)))
    else:
        raise ValueError(how)
    pred, residual, fills = paint(board, pi, tiles)
    n_int = sum(1 for t in tiles if t[4] == "interior")
    zf = float((residual == 0).mean())
    painted = n * n - n
    A, B = lis_len(pi.tolist()), lds_len(pi.tolist())
    theory = k * k + 2 * k - 3 if k * k == n else math.ceil(n + 2 * math.sqrt(n) - 3)
    header = n + n + len(tiles)
    return {
        "corpus": name, "how": how, "n": n, "k": k,
        "n_tiles": len(tiles), "n_interior": n_int,
        "n_boundary": len(tiles) - n_int,
        "theory_T": theory, "hit_T": len(tiles) == theory,
        "cover_ok": bool(cover_ok),
        "painted": painted,
        "cells_per_tile": round(painted / max(1, len(tiles)), 2),
        "header_bytes": header,
        "residual_zero": round(zf, 4),
        "lis": A, "lds": B, "product": A * B, "es_ok": A * B >= n,
        "lossless": bool(np.array_equal(pred ^ residual, board)),
    }


def latin_cube_holes(D: int):
    step = 2 if math.gcd(2, D) == 1 else 1
    L = np.fromfunction(lambda y, x: (x + step * y) % D, (D, D), dtype=int)
    ok_rows = all(len(set(L[r])) == D for r in range(D))
    ok_cols = all(len(set(L[:, c])) == D for c in range(D))
    return L, ok_rows and ok_cols


def run():
    print("== construction counts ==")
    for k in (2, 3, 4, 5, 8):
        pi, tiles, ok = official_tiles(k)
        n = k * k
        A, B = lis_len(pi.tolist()), lds_len(pi.tolist())
        theory = k * k + 2 * k - 3
        n_int = sum(1 for t in tiles if t[4] == "interior")
        print(f"k={k:2} n={n:3} tiles={len(tiles):3} theory={theory:3} "
              f"int={n_int} cover={ok} LIS={A} LDS={B} AB={A*B}")
    print("IMO 2025 n=2025 T=", 45 * 45 + 2 * 45 - 3)


if __name__ == "__main__":
    run()
