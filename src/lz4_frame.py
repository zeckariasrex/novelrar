#!/usr/bin/env python3
"""LZ4 decoder — clean-room, from the public LZ4 format specifications.

Provenance
----------
Implemented from two documents published by Yann Collet in the lz4/lz4
repository, both under a **BSD 2-Clause / CC0-equivalent** grant that
explicitly permits independent implementation:

  * ``doc/lz4_Block_format.md``  — the token / literal / match grammar
  * ``doc/lz4_Frame_format.md``  — magic, FLG/BD descriptor, block framing
  * ``doc/xxHash_spec.md``       — XXH32, used for the frame checksums

No LZ4 reference source is vendored, copied, or translated here; this is
written against the prose specs. LZ4 therefore carries **no** proprietary
licensing obstacle — it is in the tree as lane ``CLEANROOM``.

Supports: modern frames (0x184D2204), legacy frames (0x184C2102),
skippable frames (0x184D2A50-5F), linked and independent blocks, stored
blocks, block checksums, content checksum, content size, dictionary id.

Not supported (and refused, not guessed): frames that declare a dictionary
id we were not handed a dictionary for.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

MAGIC = 0x184D2204
MAGIC_LEGACY = 0x184C2102
MAGIC_SKIP_LO = 0x184D2A50
MAGIC_SKIP_HI = 0x184D2A5F

BLOCK_MAX = {4: 64 << 10, 5: 256 << 10, 6: 1 << 20, 7: 4 << 20}
LEGACY_BLOCK_MAX = 8 << 20


class LZ4Error(ValueError):
    """Malformed or unsupported LZ4 stream."""


# ---------------------------------------------------------------------------
# XXH32 (xxHash_spec.md) — needed for the frame header byte and checksums
# ---------------------------------------------------------------------------

P1, P2, P3, P4, P5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
M32 = 0xFFFFFFFF


def _rotl(x: int, r: int) -> int:
    x &= M32
    return ((x << r) | (x >> (32 - r))) & M32


def xxh32(data: bytes, seed: int = 0) -> int:
    n = len(data)
    i = 0
    if n >= 16:
        v1 = (seed + P1 + P2) & M32
        v2 = (seed + P2) & M32
        v3 = seed & M32
        v4 = (seed - P1) & M32
        limit = n - 16
        while i <= limit:
            l1, l2, l3, l4 = struct.unpack_from("<IIII", data, i)
            v1 = (_rotl((v1 + l1 * P2) & M32, 13) * P1) & M32
            v2 = (_rotl((v2 + l2 * P2) & M32, 13) * P1) & M32
            v3 = (_rotl((v3 + l3 * P2) & M32, 13) * P1) & M32
            v4 = (_rotl((v4 + l4 * P2) & M32, 13) * P1) & M32
            i += 16
        h = (_rotl(v1, 1) + _rotl(v2, 7) + _rotl(v3, 12) + _rotl(v4, 18)) & M32
    else:
        h = (seed + P5) & M32
    h = (h + n) & M32
    while i + 4 <= n:
        (lane,) = struct.unpack_from("<I", data, i)
        h = (_rotl((h + lane * P3) & M32, 17) * P4) & M32
        i += 4
    while i < n:
        h = (_rotl((h + data[i] * P5) & M32, 11) * P1) & M32
        i += 1
    h ^= h >> 15
    h = (h * P2) & M32
    h ^= h >> 13
    h = (h * P3) & M32
    h ^= h >> 16
    return h


# ---------------------------------------------------------------------------
# Block format (lz4_Block_format.md)
# ---------------------------------------------------------------------------

def decompress_block(src: bytes, max_out: int = 0, prefix: bytes = b"") -> bytes:
    """Decode one LZ4 block.

    ``prefix`` is the already-decoded history a linked block may match into.
    Returns only the bytes produced by *this* block.
    """
    out = bytearray(prefix)
    base = len(out)
    n = len(src)
    i = 0
    while i < n:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                if i >= n:
                    raise LZ4Error("truncated literal length")
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        if i + lit > n:
            raise LZ4Error(f"literal run overruns block ({lit} at {i}/{n})")
        out += src[i:i + lit]
        i += lit
        if i == n:
            break  # last sequence carries literals only
        if i + 2 > n:
            raise LZ4Error("truncated match offset")
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0:
            raise LZ4Error("match offset 0")
        if offset > len(out):
            raise LZ4Error(f"match offset {offset} before start of history")
        mlen = token & 0x0F
        if mlen == 15:
            while True:
                if i >= n:
                    raise LZ4Error("truncated match length")
                b = src[i]
                i += 1
                mlen += b
                if b != 255:
                    break
        mlen += 4  # minmatch
        start = len(out) - offset
        if offset >= mlen:
            out += out[start:start + mlen]
        else:  # overlapping run — must copy byte by byte
            for k in range(mlen):
                out.append(out[start + k])
        if max_out and len(out) - base > max_out:
            raise LZ4Error("block expands past declared maximum")
    return bytes(out[base:])


# ---------------------------------------------------------------------------
# Frame format (lz4_Frame_format.md)
# ---------------------------------------------------------------------------

@dataclass
class FrameInfo:
    kind: str = "frame"
    block_independent: bool = False
    block_checksum: bool = False
    content_size: Optional[int] = None
    content_checksum: bool = False
    dict_id: Optional[int] = None
    block_max: int = 4 << 20
    n_blocks: int = 0
    n_stored: int = 0
    header_bytes: int = 0
    checks: list = field(default_factory=list)


def _parse_descriptor(buf: bytes, i: int) -> tuple[FrameInfo, int]:
    start = i
    if i + 2 > len(buf):
        raise LZ4Error("truncated frame descriptor")
    flg, bd = buf[i], buf[i + 1]
    i += 2
    if (flg >> 6) != 1:
        raise LZ4Error(f"unsupported LZ4 frame version {flg >> 6}")
    if flg & 0x02:
        raise LZ4Error("reserved FLG bit set")
    if bd & 0x8F:
        raise LZ4Error("reserved BD bits set")
    info = FrameInfo(
        block_independent=bool(flg & 0x20),
        block_checksum=bool(flg & 0x10),
        content_checksum=bool(flg & 0x04),
        block_max=BLOCK_MAX.get((bd >> 4) & 7, 0),
    )
    if not info.block_max:
        raise LZ4Error(f"reserved block max size code {(bd >> 4) & 7}")
    if flg & 0x08:
        info.content_size = struct.unpack_from("<Q", buf, i)[0]
        i += 8
    if flg & 0x01:
        info.dict_id = struct.unpack_from("<I", buf, i)[0]
        i += 4
    if i >= len(buf):
        raise LZ4Error("truncated header checksum")
    want = buf[i]
    got = (xxh32(buf[start:i]) >> 8) & 0xFF
    if want != got:
        raise LZ4Error(f"frame header checksum {got:02x} != {want:02x}")
    i += 1
    info.checks.append("header-xxh32 ok")
    info.header_bytes = i - start + 4
    return info, i


def decompress_frame(buf: bytes, i: int = 0, dictionary: bytes = b"") -> tuple[bytes, FrameInfo, int]:
    """Decode one frame starting at ``i``. Returns (data, info, next_offset)."""
    if i + 4 > len(buf):
        raise LZ4Error("truncated magic")
    (magic,) = struct.unpack_from("<I", buf, i)
    if MAGIC_SKIP_LO <= magic <= MAGIC_SKIP_HI:
        (size,) = struct.unpack_from("<I", buf, i + 4)
        end = i + 8 + size
        if end > len(buf):
            raise LZ4Error("truncated skippable frame")
        return b"", FrameInfo(kind="skippable", header_bytes=8), end
    if magic == MAGIC_LEGACY:
        return _decompress_legacy(buf, i + 4)
    if magic != MAGIC:
        raise LZ4Error(f"not an LZ4 frame magic: {magic:#010x}")
    info, i = _parse_descriptor(buf, i + 4)
    if info.dict_id is not None and not dictionary:
        raise LZ4Error(f"frame needs dictionary {info.dict_id:#x}; none supplied")

    out = bytearray()
    history = bytearray(dictionary)
    while True:
        if i + 4 > len(buf):
            raise LZ4Error("truncated block size")
        (bsize,) = struct.unpack_from("<I", buf, i)
        i += 4
        if bsize == 0:
            break  # EndMark
        stored = bool(bsize & 0x80000000)
        bsize &= 0x7FFFFFFF
        if i + bsize > len(buf):
            raise LZ4Error("truncated block body")
        body = buf[i:i + bsize]
        i += bsize
        if info.block_checksum:
            if i + 4 > len(buf):
                raise LZ4Error("truncated block checksum")
            (want,) = struct.unpack_from("<I", buf, i)
            i += 4
            got = xxh32(body)
            if got != want:
                raise LZ4Error(f"block xxh32 {got:#010x} != {want:#010x}")
        if stored:
            chunk = body
            info.n_stored += 1
        else:
            prefix = b"" if info.block_independent else bytes(history)
            chunk = decompress_block(body, info.block_max, prefix)
        out += chunk
        info.n_blocks += 1
        if not info.block_independent:
            history += chunk
            if len(history) > 65536:  # 64 KiB window is all LZ4 can reference
                del history[:-65536]
    if info.block_checksum:
        info.checks.append(f"block-xxh32 ok x{info.n_blocks}")
    if info.content_checksum:
        if i + 4 > len(buf):
            raise LZ4Error("truncated content checksum")
        (want,) = struct.unpack_from("<I", buf, i)
        i += 4
        got = xxh32(bytes(out))
        if got != want:
            raise LZ4Error(f"content xxh32 {got:#010x} != {want:#010x}")
        info.checks.append("content-xxh32 ok")
    if info.content_size is not None:
        if len(out) != info.content_size:
            raise LZ4Error(f"content size {len(out)} != declared {info.content_size}")
        info.checks.append("content-size ok")
    return bytes(out), info, i


def _decompress_legacy(buf: bytes, i: int) -> tuple[bytes, FrameInfo, int]:
    """Legacy frame: magic then bare 4-byte-size-prefixed blocks, no EndMark."""
    info = FrameInfo(kind="legacy", block_independent=True,
                     block_max=LEGACY_BLOCK_MAX, header_bytes=4)
    out = bytearray()
    n = len(buf)
    while i + 4 <= n:
        (bsize,) = struct.unpack_from("<I", buf, i)
        # A following frame magic ends the legacy stream.
        if bsize in (MAGIC, MAGIC_LEGACY) or MAGIC_SKIP_LO <= bsize <= MAGIC_SKIP_HI:
            break
        if bsize == 0 or bsize > LEGACY_BLOCK_MAX or i + 4 + bsize > n:
            break
        out += decompress_block(buf[i + 4:i + 4 + bsize], LEGACY_BLOCK_MAX)
        i += 4 + bsize
        info.n_blocks += 1
    return bytes(out), info, i


def decompress(buf: bytes, dictionary: bytes = b"") -> bytes:
    """Decode every concatenated frame in ``buf``. Skippable frames drop out."""
    out = bytearray()
    i = 0
    while i < len(buf):
        data, _info, i2 = decompress_frame(buf, i, dictionary)
        if i2 <= i:
            raise LZ4Error("no forward progress")
        out += data
        i = i2
    return bytes(out)


def inspect(buf: bytes, dictionary: bytes = b"") -> dict:
    """Decode and report every frame, for the capability probe."""
    frames, i = [], 0
    total = bytearray()
    while i < len(buf):
        try:
            data, info, i2 = decompress_frame(buf, i, dictionary)
        except LZ4Error as e:
            frames.append({"error": str(e), "at": i})
            break
        frames.append({
            "kind": info.kind, "blocks": info.n_blocks, "stored": info.n_stored,
            "n_out": len(data), "linked": not info.block_independent,
            "checks": info.checks, "dict_id": info.dict_id,
        })
        total += data
        if i2 <= i:
            break
        i = i2
    return {"frames": frames, "n_out": len(total), "payload": bytes(total)}


def is_lz4(buf: bytes) -> bool:
    if len(buf) < 4:
        return False
    (m,) = struct.unpack_from("<I", buf, 0)
    return m == MAGIC or m == MAGIC_LEGACY or MAGIC_SKIP_LO <= m <= MAGIC_SKIP_HI
