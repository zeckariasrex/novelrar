#!/usr/bin/env python3
"""NR01 public-domain windmill container.
Paint tiles + gap literals, then XOR residual.
Skip path paints gaps before XOR so the diagonal is not cancelled.
Not UnRAR / 7-Zip / LZ4.
"""
from __future__ import annotations

import hashlib, math, struct, sys, zlib
from pathlib import Path
import numpy as np

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import geex_windmill_v1 as v1
import geex_motif as motif

MAGIC = b"NR01"
ROUTE_OFFICIAL, ROUTE_AXIS, ROUTE_SKIP = 0, 1, 2
FLAG_RES, FLAG_ZLIB, FLAG_SKIP, FLAG_OFFICIAL_PI = 1, 2, 4, 8


def es_route(pi, n, klass=None, paint_agree=None):
    A = v1.lis_len(list(map(int, pi)))
    B = v1.lds_len(list(map(int, pi)))
    if klass in ("language", "noise"):
        return ROUTE_SKIP
    if paint_agree is not None and paint_agree < 0.40:
        return ROUTE_SKIP
    if klass == "planar" or A >= n - 1 or B >= n - 1:
        return ROUTE_AXIS
    if A * B >= n:
        return ROUTE_OFFICIAL
    return ROUTE_AXIS


def paint_gaps_first(board, pi, tiles, route):
    board = np.asarray(board, dtype=np.uint8)
    n = board.shape[0]
    pred = np.zeros_like(board)
    recipes = []
    if route == ROUTE_SKIP:
        tiles = []
    elif route == ROUTE_AXIS:
        for r in range(n):
            fill = int(np.bincount(board[r], minlength=256).argmax())
            pred[r, :] = fill
            recipes.append((0, r, n, 1, motif.KIND_CONST, bytes([fill])))
    else:
        for x, y, w, h, _k in tiles:
            mot = motif.choose_motif(board[y:y + h, x:x + w])
            pred[y:y + h, x:x + w] = mot.pred
            recipes.append((x, y, w, h, mot.kind, mot.params))
    for c, r in enumerate(pi):
        pred[int(r), int(c)] = board[int(r), int(c)]
    return pred, board ^ pred, recipes


def encode(board, klass=None, how="official"):
    board = np.asarray(board, dtype=np.uint8)
    n = board.shape[0]
    k = int(round(math.sqrt(n)))
    if how == "official" and k * k == n:
        pi, tiles, _ok = v1.official_tiles(k)
        official_pi = True
    else:
        pi = v1.data_perm(board)
        tiles = v1.tiles_from_perm(pi)
        official_pi = False
    _p, res_try, _ = paint_gaps_first(board, pi, tiles, ROUTE_OFFICIAL)
    route = es_route(pi, n, klass=klass, paint_agree=float((res_try == 0).mean()))
    pred, residual, recipes = paint_gaps_first(board, pi, tiles, route)
    raw_res = residual.tobytes()
    flags = 0
    if route == ROUTE_SKIP:
        flags |= FLAG_SKIP
    if official_pi:
        flags |= FLAG_OFFICIAL_PI
    payload = b""
    if residual.any():
        flags |= FLAG_RES
        z = zlib.compress(raw_res, 9)
        if len(z) < len(raw_res):
            flags |= FLAG_ZLIB
            payload = z
        else:
            payload = raw_res
    sha = hashlib.sha256(board.tobytes()).digest()
    body = bytearray()
    body += MAGIC + bytes([1, flags])
    body += struct.pack("<HH", n, k)
    body += bytes([route, 0])
    body += struct.pack("<H", len(recipes))
    if not official_pi:
        body += bytes(int(x) & 0xFF for x in pi)
    body += bytes(int(board[int(r), int(c)]) & 0xFF for c, r in enumerate(pi))
    for x, y, w, h, kind, params in recipes:
        body += bytes([x & 255, y & 255, w & 255, h & 255, kind & 255, len(params) & 255])
        body += params
    body += struct.pack("<I", len(payload)) + payload + sha
    return bytes(body)


def decode(blob):
    if blob[:4] != MAGIC:
        raise ValueError("not NR01")
    version, flags = blob[4], blob[5]
    if version != 1:
        raise ValueError(version)
    n, k = struct.unpack_from("<HH", blob, 6)
    route = blob[10]
    n_tiles = struct.unpack_from("<H", blob, 12)[0]
    off = 14
    if flags & FLAG_OFFICIAL_PI:
        pi = v1.official_perm(k)
    else:
        pi = np.frombuffer(blob[off:off + n], dtype=np.uint8).astype(int)
        off += n
    gaps = blob[off:off + n]
    off += n
    recipes = []
    for _ in range(n_tiles):
        x, y, w, h, kind, plen = blob[off:off + 6]
        off += 6
        params = blob[off:off + plen]
        off += plen
        recipes.append((x, y, w, h, kind, params))
    plen = struct.unpack_from("<I", blob, off)[0]
    off += 4
    payload = blob[off:off + plen]
    off += plen
    sha = blob[off:off + 32]
    pred = np.zeros((n, n), dtype=np.uint8)
    if route != ROUTE_SKIP:
        for x, y, w, h, kind, params in recipes:
            pred[y:y + h, x:x + w] = motif.apply_motif(kind, params, h, w)
    for c, r in enumerate(pi):
        pred[int(r), int(c)] = gaps[c]
    if flags & FLAG_RES:
        raw = zlib.decompress(payload) if flags & FLAG_ZLIB else payload
        residual = np.frombuffer(raw, dtype=np.uint8).reshape(n, n)
    else:
        residual = np.zeros((n, n), dtype=np.uint8)
    board = pred ^ residual
    if hashlib.sha256(board.tobytes()).digest() != sha:
        raise ValueError("SHA mismatch")
    return board


def pack_report(board, klass=None, how="official"):
    blob = encode(board, klass=klass, how=how)
    recon = decode(blob)
    n = board.shape[0]
    return {
        "n": n, "k": int(round(math.sqrt(n))), "klass": klass,
        "blob": len(blob), "raw": int(board.size),
        "ratio": round(len(blob) / board.size, 3),
        "lossless": bool(np.array_equal(recon, board)),
    }


if __name__ == "__main__":
    b = np.zeros((16, 16), dtype=np.uint8)
    b[:] = 40
    b[8:] = 200
    blob = encode(b, klass="planar")
    assert np.array_equal(decode(blob), b)
    print("NR01 self-test ok", len(blob), "bytes")
