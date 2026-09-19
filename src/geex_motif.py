#!/usr/bin/env python3
"""Motif recipes for NR01 / windmill tiles.

choose_motif(block) -> Recipe(kind, params, pred, agreed)
apply_motif(kind, params, h, w) -> ndarray
"""
from __future__ import annotations

from dataclasses import dataclass
import numpy as np

KIND_CONST, KIND_CHECKER, KIND_STRIPE_X, KIND_STRIPE_Y = 0, 1, 2, 3
KIND_CELL2, KIND_AXIS_ROW, KIND_AXIS_COL, KIND_BCHK = 4, 5, 6, 7
CONST, CHECKER, BCHK = KIND_CONST, KIND_CHECKER, KIND_BCHK


@dataclass
class Recipe:
    kind: int
    params: bytes
    pred: np.ndarray
    agreed: int


def _mode(arr: np.ndarray) -> int:
    if arr.size == 0:
        return 0
    return int(np.bincount(arr.ravel().astype(np.uint8), minlength=256).argmax())


def apply_motif(kind: int, params: bytes, h: int, w: int) -> np.ndarray:
    yy, xx = np.ogrid[:h, :w]
    p = list(params or b"\x00")
    a = p[0] if p else 0
    b = p[1] if len(p) > 1 else a
    if kind == KIND_CONST:
        return np.full((h, w), a, dtype=np.uint8)
    if kind == KIND_CHECKER:
        return np.where(((xx + yy) & 1) == 0, a, b).astype(np.uint8)
    if kind == KIND_BCHK:
        phase = p[2] if len(p) > 2 else 0
        return np.where((((xx + yy) + phase) & 1) == 0, a, b).astype(np.uint8)
    if kind == KIND_STRIPE_X:
        return np.where((xx & 1) == 0, a, b).astype(np.uint8)
    if kind == KIND_STRIPE_Y:
        return np.where((yy & 1) == 0, a, b).astype(np.uint8)
    if kind == KIND_CELL2:
        cells = (p + [a] * 4)[:4]
        pred = np.empty((h, w), dtype=np.uint8)
        pred[0::2, 0::2] = cells[0]
        pred[0::2, 1::2] = cells[1]
        pred[1::2, 0::2] = cells[2]
        pred[1::2, 1::2] = cells[3]
        return pred
    if kind == KIND_AXIS_ROW:
        fills = np.frombuffer((params or b"") + bytes(h), dtype=np.uint8)[:h]
        return np.repeat(fills[:, None], w, axis=1)
    if kind == KIND_AXIS_COL:
        fills = np.frombuffer((params or b"") + bytes(w), dtype=np.uint8)[:w]
        return np.repeat(fills[None, :], h, axis=0)
    return np.full((h, w), a, dtype=np.uint8)


def choose_motif(block: np.ndarray) -> Recipe:
    h, w = block.shape
    if block.size == 0:
        return Recipe(KIND_CONST, b"\x00", np.zeros((h, w), dtype=np.uint8), 0)
    a = _mode(block)
    even = block[(np.arange(h)[:, None] + np.arange(w)[None, :]) % 2 == 0]
    odd = block[(np.arange(h)[:, None] + np.arange(w)[None, :]) % 2 == 1]
    ae = _mode(even) if even.size else a
    ao = _mode(odd) if odd.size else a
    cands = [
        (KIND_CONST, bytes([a])),
        (KIND_CHECKER, bytes([ae, ao])),
        (KIND_BCHK, bytes([ae, ao, 0])),
        (KIND_BCHK, bytes([ao, ae, 1])),
        (KIND_STRIPE_X, bytes([
            _mode(block[:, 0::2]) if w else a,
            _mode(block[:, 1::2]) if w > 1 else a,
        ])),
        (KIND_STRIPE_Y, bytes([
            _mode(block[0::2]) if h else a,
            _mode(block[1::2]) if h > 1 else a,
        ])),
        (KIND_CELL2, bytes([
            _mode(block[0::2, 0::2]),
            _mode(block[0::2, 1::2]) if w > 1 else a,
            _mode(block[1::2, 0::2]) if h > 1 else a,
            _mode(block[1::2, 1::2]) if (h > 1 and w > 1) else a,
        ])),
        (KIND_AXIS_ROW, bytes(_mode(block[r]) for r in range(h))),
        (KIND_AXIS_COL, bytes(_mode(block[:, c]) for c in range(w))),
    ]
    best = None
    best_key = None
    for kind, params in cands:
        pred = apply_motif(kind, params, h, w)
        agreed = int((pred == block).sum())
        key = (agreed - len(params), -len(params), -kind)
        if best_key is None or key > best_key:
            best = Recipe(kind, params, pred, agreed)
            best_key = key
    return best
