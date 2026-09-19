#!/usr/bin/env python3
"""Motif fill for windmill tiles. Public-domain recipes, not LZ77/LZMA/LZ4.

Kind 7 BCHK: p,oy,ox,a,b — 2-color p×p blocks with phase so official
interior squares (offset +1 col) still paint period-2 tilings.
"""
from __future__ import annotations

from dataclasses import dataclass
import numpy as np

KIND_CONST, KIND_CHECKER, KIND_SX, KIND_SY, KIND_CELL2, KIND_ROW, KIND_COL, KIND_BCHK = range(8)
KIND_NAME = {
    0: "const", 1: "checker", 2: "stripe_x", 3: "stripe_y",
    4: "cell2", 5: "axis_row", 6: "axis_col", 7: "bchk",
}


@dataclass
class Motif:
    kind: int
    params: bytes
    pred: np.ndarray
    zeros: float
    payload: int

    @property
    def name(self) -> str:
        return KIND_NAME[self.kind]


def _mode(arr):
    return int(np.bincount(arr.ravel(), minlength=256).argmax())


def _zf(pred, block):
    return float((pred == block).mean()) if block.size else 1.0


def motif_candidates(block):
    block = np.asarray(block, dtype=np.uint8)
    h, w = block.shape
    out = []
    c = _mode(block)
    pred = np.full((h, w), c, dtype=np.uint8)
    out.append(Motif(KIND_CONST, bytes([c]), pred, _zf(pred, block), 1))
    yy, xx = np.indices((h, w))
    a = _mode(block[(yy + xx) % 2 == 0]) if block.size else c
    b = _mode(block[(yy + xx) % 2 == 1]) if block.size else c
    pred = np.where((yy + xx) % 2 == 0, a, b).astype(np.uint8)
    out.append(Motif(KIND_CHECKER, bytes([a, b]), pred, _zf(pred, block), 2))
    ax = _mode(block[:, 0::2]) if block[:, 0::2].size else c
    bx = _mode(block[:, 1::2]) if w > 1 else ax
    pred = np.where(xx % 2 == 0, ax, bx).astype(np.uint8)
    out.append(Motif(KIND_SX, bytes([ax, bx]), pred, _zf(pred, block), 2))
    ay = _mode(block[0::2, :]) if block[0::2, :].size else c
    by = _mode(block[1::2, :]) if h > 1 else ay
    pred = np.where(yy % 2 == 0, ay, by).astype(np.uint8)
    out.append(Motif(KIND_SY, bytes([ay, by]), pred, _zf(pred, block), 2))
    cell = np.zeros((2, 2), dtype=np.uint8)
    for i in range(2):
        for j in range(2):
            sl = block[i::2, j::2]
            cell[i, j] = _mode(sl) if sl.size else c
    pred = np.tile(cell, ((h + 1) // 2, (w + 1) // 2))[:h, :w]
    out.append(Motif(KIND_CELL2, bytes(cell.ravel().tolist()), pred, _zf(pred, block), 4))
    if h <= 16:
        rows = np.array([_mode(block[i]) for i in range(h)], dtype=np.uint8)
        pred = np.repeat(rows[:, None], w, axis=1)
        out.append(Motif(KIND_ROW, bytes(rows.tolist()), pred, _zf(pred, block), h))
    if w <= 16:
        cols = np.array([_mode(block[:, j]) for j in range(w)], dtype=np.uint8)
        pred = np.repeat(cols[None, :], h, axis=0)
        out.append(Motif(KIND_COL, bytes(cols.tolist()), pred, _zf(pred, block), w))
    if min(h, w) >= 2:
        best_pred = None; best_z = -1; best_params = None
        for oy in range(2):
            for ox in range(2):
                grid = (((np.arange(h)[:, None] + oy) // 2)
                        + ((np.arange(w)[None, :] + ox) // 2)) % 2
                even = block[grid == 0]; odd = block[grid == 1]
                aa = _mode(even) if even.size else c
                bb = _mode(odd) if odd.size else c
                pred = np.where(grid == 0, aa, bb).astype(np.uint8)
                z = _zf(pred, block)
                if z > best_z:
                    best_z = z; best_pred = pred; best_params = bytes([2, oy, ox, aa, bb])
        out.append(Motif(KIND_BCHK, best_params, best_pred, best_z, 5))
    return out


def choose_motif(block, slack=0.01):
    cands = motif_candidates(block)
    best_z = max(m.zeros for m in cands)
    kept = [m for m in cands if m.zeros >= best_z - slack]
    kept.sort(key=lambda m: (m.payload, -m.zeros, m.kind))
    return kept[0]


def apply_motif(kind, params, h, w):
    yy, xx = np.indices((h, w))
    if kind == KIND_CONST:
        return np.full((h, w), params[0], dtype=np.uint8)
    if kind == KIND_CHECKER:
        return np.where((yy + xx) % 2 == 0, params[0], params[1]).astype(np.uint8)
    if kind == KIND_SX:
        return np.where(xx % 2 == 0, params[0], params[1]).astype(np.uint8)
    if kind == KIND_SY:
        return np.where(yy % 2 == 0, params[0], params[1]).astype(np.uint8)
    if kind == KIND_CELL2:
        cell = np.frombuffer(params[:4], dtype=np.uint8).reshape(2, 2)
        return np.tile(cell, ((h + 1) // 2, (w + 1) // 2))[:h, :w]
    if kind == KIND_ROW:
        rows = np.frombuffer(params[:h], dtype=np.uint8)
        return np.repeat(rows[:, None], w, axis=1)
    if kind == KIND_COL:
        cols = np.frombuffer(params[:w], dtype=np.uint8)
        return np.repeat(cols[None, :], h, axis=0)
    if kind == KIND_BCHK:
        p, oy, ox, a, b = params[:5]
        grid = (((np.arange(h)[:, None] + oy) // p)
                + ((np.arange(w)[None, :] + ox) // p)) % 2
        return np.where(grid == 0, a, b).astype(np.uint8)
    raise ValueError(kind)


def paint_motifs(board, pi, tiles):
    board = np.asarray(board, dtype=np.uint8)
    pred = np.zeros_like(board)
    recipes = []
    for x, y, w, h, kind in tiles:
        mot = choose_motif(board[y:y + h, x:x + w])
        pred[y:y + h, x:x + w] = mot.pred
        recipes.append((kind, mot.kind, mot.params, mot.zeros, w * h))
    for c, r in enumerate(pi):
        pred[int(r), int(c)] = board[int(r), int(c)]
    return pred, board ^ pred, recipes
