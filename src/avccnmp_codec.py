#!/usr/bin/env python3
"""
AVCCNMP-v0 / ICCNMP-v0
Anvolxelized (Involxelized) Cryptic-Curve N-gram Multi-Projection codec.

Novel combination (not a claim of new components in isolation):
  1. Pack a 1-D byte block into a 3-D cube  (anvoxelize).
  2. Predict each voxel from three orthogonal MODE projections.
  3. Residual = vol XOR pred  (lossless).
  4. Serialize residual along a cryptic curve:
       Morton-3D  composed with a cubic twist  t |-> t^3 + a t + b  (mod 2^{3m}).
  5. Phrase-code the curve-ordered residual with block-local n-grams + RLE.

Also ships:
  - a container sniffer / dispatch decompressor for zlib, xz/lzma, bz2,
    gzip, the native AV01 bitstream, and a toy LZ4 frame.
  - 7z / RAR magic detection (no payload crypto, no password attacks).

Does not attempt to beat zlib/LZMA/LZ4. Novelty is the architecture.
"""

from __future__ import annotations

import io
import math
import struct
import zlib
import lzma
import bz2
import gzip
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable

MAGIC = b"AV01"
VERSION = 1

# ---------------------------------------------------------------------------
# Bit / byte helpers
# ---------------------------------------------------------------------------

def uvarint(n: int) -> bytes:
    if n < 0:
        raise ValueError("uvarint needs non-negative")
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def read_uvarint(buf: bytes, i: int) -> tuple[int, int]:
    n = 0
    shift = 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated uvarint")
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << shift
        if b < 0x80:
            return n, i
        shift += 7
        if shift > 63:
            raise ValueError("uvarint too long")


def pack_bytes(seq: Iterable[int]) -> bytes:
    return bytes(int(x) & 0xFF for x in seq)


# ---------------------------------------------------------------------------
# Cryptic curve: 3-D Morton + cubic twist
# ---------------------------------------------------------------------------

def part1by2(n: int) -> int:
    n &= 0x1FFFFF
    n = (n | (n << 32)) & 0x1F00000000FFFF
    n = (n | (n << 16)) & 0x1F0000FF0000FF
    n = (n | (n << 8)) & 0x100F00F00F00F00F
    n = (n | (n << 4)) & 0x10C30C30C30C30C3
    n = (n | (n << 2)) & 0x1249249249249249
    return n


def morton3(x: int, y: int, z: int) -> int:
    return part1by2(x) | (part1by2(y) << 1) | (part1by2(z) << 2)


def compact1by2(n: int) -> int:
    n &= 0x1249249249249249
    n = (n | (n >> 2)) & 0x10C30C30C30C30C3
    n = (n | (n >> 4)) & 0x100F00F00F00F00F
    n = (n | (n >> 8)) & 0x1F0000FF0000FF
    n = (n | (n >> 16)) & 0x1F00000000FFFF
    n = (n | (n >> 32)) & 0x1FFFFF
    return n


def inv_morton3(c: int) -> tuple[int, int, int]:
    return compact1by2(c), compact1by2(c >> 1), compact1by2(c >> 2)


def cubic_twist(t: int, mod: int, a: int = 5, b: int = 17) -> int:
    """Weierstrass-inspired permutation of Z/modZ when mod is a power of two
    and we use an odd cubic (x^3 + a x + b with a odd => invertible-ish on
    small power-of-two grids in practice; we store a,b so decode is exact
    via a precomputed inverse table, not via algebraic inverse).
    """
    return (pow(t, 3, mod) + (a * t) + b) % mod


def build_curve_order(side: int, a: int = 5, b: int = 17) -> list[tuple[int, int, int]]:
    """Return a permutation of the cube cells along the cryptic curve."""
    bits = max(1, side.bit_length() - 1)
    # Morton lives naturally on 2^bits; if side is not p2, still walk the
    # embedding cube and skip out-of-range cells.
    p2 = 1 << bits
    if p2 < side:
        p2 *= 2
        bits += 1
    mod = p2 * p2 * p2
    # map twisted Morton index -> first visit of each in-range cell
    order: list[tuple[int, int, int]] = []
    seen = set()
    for t in range(mod):
        m = cubic_twist(t, mod, a, b)
        x, y, z = inv_morton3(m)
        if x < side and y < side and z < side and (x, y, z) not in seen:
            seen.add((x, y, z))
            order.append((x, y, z))
    # belt-and-suspenders: any missed cell (shouldn't happen) goes last
    if len(order) < side * side * side:
        for z in range(side):
            for y in range(side):
                for x in range(side):
                    if (x, y, z) not in seen:
                        order.append((x, y, z))
    return order


# 2-D Hilbert (used as an ablation serializer)
def hilbert_xy(n: int, d: int) -> tuple[int, int]:
    x = y = 0
    s = 1
    t = d
    while s < n:
        rx = 1 & (t // 2)
        ry = 1 & (t ^ rx)
        if ry == 0:
            if rx == 1:
                x = n_s = s - 1 - x  # noqa
                y = s - 1 - y
            x, y = y, x
        x += s * rx
        y += s * ry
        t //= 4
        s *= 2
    return x, y


def build_hilbert_2d_order(side: int) -> list[tuple[int, int, int]]:
    p2 = 1
    while p2 < side:
        p2 *= 2
    order = []
    seen = set()
    for d in range(p2 * p2):
        x, y = hilbert_xy(p2, d)
        if x < side and y < side:
            # fold the missing z by slicing in row-chunks of `side`
            z = 0
            key = (x, y, z)
            if key not in seen:
                seen.add(key)
                order.append(key)
    # remaining z-layers: same xy Hilbert, increment z
    full = []
    xy = [(x, y) for x, y, _ in order]
    for z in range(side):
        for x, y in xy:
            full.append((x, y, z))
    return full


# ---------------------------------------------------------------------------
# Anvoxelize + multi-projection predictor
# ---------------------------------------------------------------------------

def cube_side_for(n: int) -> int:
    s = int(round(n ** (1 / 3)))
    while s * s * s < n:
        s += 1
    return max(1, s)


def anvoxelize(block: bytes, side: int) -> list[list[list[int]]]:
    vol = [[[0] * side for _ in range(side)] for _ in range(side)]
    for i, b in enumerate(block):
        x = i % side
        y = (i // side) % side
        z = i // (side * side)
        if z < side:
            vol[z][y][x] = b
    return vol


def linearize(vol, side: int, nbytes: int) -> bytes:
    out = bytearray(nbytes)
    cap = side * side * side
    for i in range(min(nbytes, cap)):
        x = i % side
        y = (i // side) % side
        z = i // (side * side)
        out[i] = vol[z][y][x]
    return bytes(out)


def _mode(vals: list[int]) -> int:
    if not vals:
        return 0
    return Counter(vals).most_common(1)[0][0]


def projection_modes(vol, side: int):
    """Three orthogonal mode maps.
    Px[y,z] = mode_x vol[:,y,z]
    Py[x,z] = mode_y
    Pz[x,y] = mode_z
    """
    px = [[0] * side for _ in range(side)]  # [y][z]
    py = [[0] * side for _ in range(side)]  # [x][z]
    pz = [[0] * side for _ in range(side)]  # [x][y]
    for z in range(side):
        for y in range(side):
            px[y][z] = _mode([vol[z][y][x] for x in range(side)])
        for x in range(side):
            py[x][z] = _mode([vol[z][y][x] for y in range(side)])
    for y in range(side):
        for x in range(side):
            pz[x][y] = _mode([vol[z][y][x] for z in range(side)])
    return px, py, pz


def pack_mode_map(m, side: int) -> bytes:
    return bytes(m[i][j] for i in range(side) for j in range(side))


def unpack_mode_map(buf: bytes, side: int, offset: int):
    need = side * side
    chunk = buf[offset : offset + need]
    if len(chunk) != need:
        raise ValueError("truncated mode map")
    m = [[0] * side for _ in range(side)]
    k = 0
    for i in range(side):
        for j in range(side):
            m[i][j] = chunk[k]
            k += 1
    return m, offset + need


def predict_vol(px, py, pz, side: int):
    pred = [[[0] * side for _ in range(side)] for _ in range(side)]
    for z in range(side):
        for y in range(side):
            for x in range(side):
                a, b, c = px[y][z], py[x][z], pz[x][y]
                if a == b or a == c:
                    pred[z][y][x] = a
                elif b == c:
                    pred[z][y][x] = b
                else:
                    pred[z][y][x] = a  # deterministic tie-break
    return pred


def xor_vol(a, b, side: int):
    out = [[[0] * side for _ in range(side)] for _ in range(side)]
    for z in range(side):
        for y in range(side):
            for x in range(side):
                out[z][y][x] = a[z][y][x] ^ b[z][y][x]
    return out


# ---------------------------------------------------------------------------
# N-gram phrase coder on the curve-ordered residual
# ---------------------------------------------------------------------------

def discover_phrases(seq: bytes, min_n: int = 2, max_n: int = 6, min_count: int = 3, cap: int = 48) -> list[bytes]:
    """Block-local phrases: n-grams that pay rent (count * (n-1) large)."""
    scored: list[tuple[int, bytes]] = []
    for n in range(max_n, min_n - 1, -1):
        c = Counter(seq[i : i + n] for i in range(len(seq) - n + 1))
        for gram, cnt in c.items():
            if cnt >= min_count:
                # save vs literals: each use after the first stores 1 byte id
                # instead of n bytes, minus the dict entry cost n+1
                save = cnt * (n - 1) - (n + 1)
                if save > 0:
                    scored.append((save, gram))
    scored.sort(reverse=True)
    phrases = []
    used = set()
    for _, g in scored:
        # skip phrases that are exact prefixes of one already taken at same start pattern
        if g in used:
            continue
        phrases.append(g)
        used.add(g)
        if len(phrases) >= cap:
            break
    return phrases


def phrase_encode(seq: bytes, phrases: list[bytes]) -> bytes:
    """
    Stream format (byte-aligned, simple):
      0xxxxxxx           literal byte (7-bit). If high bytes needed:
      11111110 <byte>    escaped literal (any byte)
      11111111 <len>     RLE: next byte repeated (len+3) times
      1iiiiiii           phrase id 0..126  (we cap phrases at 48)
    We only use phrase ids 0x80..0xFD (126 slots). 0xFE escape, 0xFF RLE.
    """
    if len(phrases) > 126:
        phrases = phrases[:126]
    # longest-first greedy
    phrases_sorted = sorted(phrases, key=len, reverse=True)
    id_of = {p: i for i, p in enumerate(phrases)}
    out = bytearray()
    i = 0
    n = len(seq)
    while i < n:
        # RLE?
        run = 1
        while i + run < n and seq[i + run] == seq[i] and run < 258:
            run += 1
        if run >= 3:
            # emit as RLE chunks of max 258
            remain = run
            while remain >= 3:
                chunk = min(remain, 258)
                out.append(0xFF)
                out.append(chunk - 3)
                out.append(seq[i])
                remain -= chunk
                i += chunk
            continue
        matched = None
        for p in phrases_sorted:
            if seq.startswith(p, i):
                matched = p
                break
        if matched is not None:
            out.append(0x80 | id_of[matched])
            i += len(matched)
            continue
        b = seq[i]
        if b < 0x80:
            out.append(b)
        else:
            out.append(0xFE)
            out.append(b)
        i += 1
    return bytes(out)


def phrase_decode(blob: bytes, phrases: list[bytes]) -> bytes:
    out = bytearray()
    i = 0
    n = len(blob)
    while i < n:
        op = blob[i]
        i += 1
        if op == 0xFF:
            if i + 1 >= n:
                raise ValueError("truncated RLE")
            ln = blob[i] + 3
            val = blob[i + 1]
            i += 2
            out.extend([val] * ln)
        elif op == 0xFE:
            if i >= n:
                raise ValueError("truncated escape")
            out.append(blob[i])
            i += 1
        elif op >= 0x80:
            pid = op & 0x7F
            if pid >= len(phrases):
                raise ValueError(f"bad phrase id {pid}")
            out.extend(phrases[pid])
        else:
            out.append(op)
    return bytes(out)


def pack_phrases(phrases: list[bytes]) -> bytes:
    out = bytearray()
    out.extend(uvarint(len(phrases)))
    for p in phrases:
        out.extend(uvarint(len(p)))
        out.extend(p)
    return bytes(out)


def unpack_phrases(buf: bytes, i: int) -> tuple[list[bytes], int]:
    n, i = read_uvarint(buf, i)
    phrases = []
    for _ in range(n):
        ln, i = read_uvarint(buf, i)
        phrases.append(buf[i : i + ln])
        i += ln
    return phrases, i


# ---------------------------------------------------------------------------
# Block encode / decode
# ---------------------------------------------------------------------------

FLAG_PROJ = 1 << 0
FLAG_CURVE = 1 << 1
FLAG_NGRAM = 1 << 2
FLAG_HILBERT2D = 1 << 3  # ablation: 2D Hilbert layers instead of Morton+twist


@dataclass
class EncodeOptions:
    use_proj: bool = True
    use_curve: bool = True
    use_ngram: bool = True
    hilbert2d: bool = False
    curve_a: int = 5
    curve_b: int = 17
    min_n: int = 2
    max_n: int = 6
    min_count: int = 3


def encode_block(block: bytes, opt: EncodeOptions) -> bytes:
    side = cube_side_for(len(block))
    vol = anvoxelize(block, side)
    flags = 0
    body = bytearray()

    if opt.use_proj:
        flags |= FLAG_PROJ
        px, py, pz = projection_modes(vol, side)
        pred = predict_vol(px, py, pz, side)
        resid = xor_vol(vol, pred, side)
        body.extend(pack_mode_map(px, side))
        body.extend(pack_mode_map(py, side))
        body.extend(pack_mode_map(pz, side))
    else:
        resid = vol

    if opt.use_curve:
        flags |= FLAG_CURVE
        if opt.hilbert2d:
            flags |= FLAG_HILBERT2D
            order = build_hilbert_2d_order(side)
        else:
            order = build_curve_order(side, opt.curve_a, opt.curve_b)
    else:
        order = [(x, y, z) for z in range(side) for y in range(side) for x in range(side)]

    seq = bytes(resid[z][y][x] for (x, y, z) in order)

    if opt.use_ngram:
        flags |= FLAG_NGRAM
        phrases = discover_phrases(seq, opt.min_n, opt.max_n, opt.min_count)
        coded = phrase_encode(seq, phrases)
        body.extend(pack_phrases(phrases))
        body.extend(uvarint(len(coded)))
        body.extend(coded)
    else:
        body.extend(uvarint(len(seq)))
        body.extend(seq)

    head = bytearray()
    head.append(flags)
    head.extend(uvarint(len(block)))
    head.extend(uvarint(side))
    head.append(opt.curve_a & 0xFF)
    head.append(opt.curve_b & 0xFF)
    return bytes(head) + bytes(body)


def decode_block(buf: bytes, i: int = 0) -> tuple[bytes, int]:
    flags = buf[i]
    i += 1
    nbytes, i = read_uvarint(buf, i)
    side, i = read_uvarint(buf, i)
    curve_a = buf[i]
    curve_b = buf[i + 1]
    i += 2

    if flags & FLAG_PROJ:
        px, i = unpack_mode_map(buf, side, i)
        py, i = unpack_mode_map(buf, side, i)
        pz, i = unpack_mode_map(buf, side, i)
        pred = predict_vol(px, py, pz, side)
    else:
        pred = [[[0] * side for _ in range(side)] for _ in range(side)]

    if flags & FLAG_CURVE:
        if flags & FLAG_HILBERT2D:
            order = build_hilbert_2d_order(side)
        else:
            order = build_curve_order(side, curve_a, curve_b)
    else:
        order = [(x, y, z) for z in range(side) for y in range(side) for x in range(side)]

    if flags & FLAG_NGRAM:
        phrases, i = unpack_phrases(buf, i)
        clen, i = read_uvarint(buf, i)
        coded = buf[i : i + clen]
        i += clen
        seq = phrase_decode(coded, phrases)
    else:
        slen, i = read_uvarint(buf, i)
        seq = buf[i : i + slen]
        i += slen

    if len(seq) != side * side * side:
        # tolerate over/under by padding
        if len(seq) < side * side * side:
            seq = seq + bytes(side * side * side - len(seq))
        else:
            seq = seq[: side * side * side]

    resid = [[[0] * side for _ in range(side)] for _ in range(side)]
    for k, (x, y, z) in enumerate(order):
        resid[z][y][x] = seq[k]

    vol = xor_vol(resid, pred, side)
    return linearize(vol, side, nbytes), i


# ---------------------------------------------------------------------------
# File container
# ---------------------------------------------------------------------------

def compress(data: bytes, opt: EncodeOptions | None = None, block_size: int = 4096) -> bytes:
    opt = opt or EncodeOptions()
    out = bytearray()
    out.extend(MAGIC)
    out.append(VERSION)
    out.extend(uvarint(len(data)))
    out.extend(uvarint(block_size))
    nblocks = (len(data) + block_size - 1) // block_size if data else 0
    out.extend(uvarint(nblocks))
    if not data:
        return bytes(out)
    for off in range(0, len(data), block_size):
        blob = encode_block(data[off : off + block_size], opt)
        out.extend(uvarint(len(blob)))
        out.extend(blob)
    return bytes(out)


def decompress(blob: bytes) -> bytes:
    if blob[:4] != MAGIC:
        raise ValueError("not an AV01 bitstream")
    if blob[4] != VERSION:
        raise ValueError(f"unsupported version {blob[4]}")
    i = 5
    total, i = read_uvarint(blob, i)
    _bs, i = read_uvarint(blob, i)
    nblocks, i = read_uvarint(blob, i)
    parts = []
    for _ in range(nblocks):
        ln, i = read_uvarint(blob, i)
        block = blob[i : i + ln]
        i += ln
        raw, _ = decode_block(block, 0)
        parts.append(raw)
    out = b"".join(parts)
    return out[:total]


# ---------------------------------------------------------------------------
# Dispatch decompressor (native formats + AV01)
# ---------------------------------------------------------------------------

def sniff(blob: bytes) -> str:
    if blob[:4] == MAGIC:
        return "avccnmp"
    if blob[:2] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
        return "zlib"
    if blob[:2] == b"\x1f\x8b":
        return "gzip"
    if blob[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if blob[:3] == b"BZh":
        return "bz2"
    if blob[:2] == b"PK":
        return "zip"
    if blob[:6] == b"7z\xbc\xaf'\x1c":
        return "7z"
    if blob[:7] == b"Rar!\x1a\x07\x00":
        return "rar4"
    if blob[:8] == b"Rar!\x1a\x07\x01\x00":
        return "rar5"
    if blob[:4] == b"\x04\x22\x4d\x18":
        return "lz4_frame"
    return "unknown"


def dispatch_decompress(blob: bytes) -> tuple[str, bytes | None, str]:
    """Return (kind, payload or None, note). Never attacks encryption.

    Container formats are routed through :mod:`unarchive`, so the note carries
    the licence lane the bytes came out of. Bare compressed streams go to the
    stdlib. LZ4 now decodes in-tree; 7z now decodes in-tree over stdlib
    codecs; RAR still only yields stored members plus metadata.
    """
    kind = sniff(blob)
    try:
        if kind == "avccnmp":
            return kind, decompress(blob), "AV01 self-decoder"
        if kind == "zlib":
            return kind, zlib.decompress(blob), "STDLIB: zlib (RFC 1950/1951)"
        if kind == "gzip":
            return kind, gzip.decompress(blob), "STDLIB: gzip"
        if kind == "xz":
            return kind, lzma.decompress(blob), "STDLIB: lzma (the XZ/LZMA2 family 7z payloads use)"
        if kind == "bz2":
            return kind, bz2.decompress(blob), "STDLIB: bz2"
        if kind in ("lz4_frame", "zip", "7z", "rar4", "rar5"):
            import unarchive
            arch = unarchive.open_archive(blob, "stream")
            got = [m for m in arch.members if m.payload is not None]
            lanes = sorted({r.lane for r in arch.receipts})
            note = (f"{arch.container}: {len(got)}/{len(arch.members)} members "
                    f"decoded via lane(s) {', '.join(lanes) or 'none'}")
            if not got:
                blocked = [m.error for m in arch.members if m.error]
                return kind, None, note + (f" — {blocked[0]}" if blocked else "")
            if len(got) == 1:
                return kind, got[0].payload, note
            return kind, b"".join(m.payload for m in got), note + " (concatenated)"
        return kind, None, "unrecognized stream"
    except Exception as e:
        return kind, None, f"decode error: {type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# Analytics helpers used by the experiment runner
# ---------------------------------------------------------------------------

def residual_entropy_drop(block: bytes, opt: EncodeOptions) -> dict:
    import math
    from collections import Counter as C

    def H(b: bytes) -> float:
        if not b:
            return 0.0
        c = C(b)
        n = len(b)
        return -sum((v / n) * math.log2(v / n) for v in c.values())

    side = cube_side_for(len(block))
    vol = anvoxelize(block, side)
    raw = bytes(vol[z][y][x] for z in range(side) for y in range(side) for x in range(side))
    if opt.use_proj:
        px, py, pz = projection_modes(vol, side)
        pred = predict_vol(px, py, pz, side)
        resid_vol = xor_vol(vol, pred, side)
    else:
        resid_vol = vol
    if opt.use_curve:
        order = (
            build_hilbert_2d_order(side)
            if opt.hilbert2d
            else build_curve_order(side, opt.curve_a, opt.curve_b)
        )
    else:
        order = [(x, y, z) for z in range(side) for y in range(side) for x in range(side)]
    resid = bytes(resid_vol[z][y][x] for (x, y, z) in order)
    zero_frac = resid.count(0) / max(1, len(resid))
    return {
        "H_raw_cube": H(raw),
        "H_residual": H(resid),
        "drop": H(raw) - H(resid),
        "zero_frac": zero_frac,
        "side": side,
    }
