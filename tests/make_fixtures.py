#!/usr/bin/env python3
"""Build archive fixtures for the capability probe.

Dev-only. py7zr / lz4 are *oracles* used to author test inputs and to
cross-check our decoders; they are never imported by src/. RAR fixtures are
written here directly from the public RAR4 technote / RAR5 format notes,
because no rar/unrar binary exists in this sandbox.
"""
from __future__ import annotations

import io
import os
import struct
import sys
import zipfile
import zlib
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures")

def big_text() -> bytes:
    """The multi-block LZ4 payload, recomputed rather than committed."""
    return (b"The quick brown fox jumps over the lazy dog. "
            b"NOVELRAR windmill paint. ") * 3000


def pseudo_random(n: int = 70000) -> bytes:
    """Incompressible bytes, deterministic so fixtures stay stable.

    A counter through SHA-256: reproducible without shipping the blob, and
    genuinely unmatchable, so LZ4 is forced to emit *stored* blocks.
    """
    import hashlib
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b"novelrar" + i.to_bytes(8, "little")).digest()
        i += 1
    return bytes(out[:n])


TEXT = (b"The quick brown fox jumps over the lazy dog. "
        b"Pack my box with five dozen liquor jugs. "
        b"Geometry evaluates shadow, shape, and surface. ") * 40
BIN = bytes((i * 37 + (i >> 3)) & 0xFF for i in range(4096))
SMALL = b"hello novelrar\n"

PAYLOADS = {"text.txt": TEXT, "bin.dat": BIN, "small.txt": SMALL}


# --------------------------------------------------------------------------
# ZIP
# --------------------------------------------------------------------------
def zip_fixtures():
    made = {}
    for tag, comp in (("store", zipfile.ZIP_STORED), ("deflate", zipfile.ZIP_DEFLATED)):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", comp) as zf:
            for n, d in PAYLOADS.items():
                zf.writestr(n, d)
        made[f"zip_{tag}.zip"] = buf.getvalue()
    # bzip2 + lzma ZIP members (methods 12 / 14)
    for tag, comp in (("bzip2", zipfile.ZIP_BZIP2), ("lzma", zipfile.ZIP_LZMA)):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", comp) as zf:
            zf.writestr("text.txt", TEXT)
        made[f"zip_{tag}.zip"] = buf.getvalue()
    # streamed ZIP: general-purpose bit 3 (sizes in a trailing data descriptor)
    made["zip_datadesc.zip"] = _zip_streamed()
    # ZipCrypto-encrypted member (bit 0) — built by hand so we can prove refusal
    made["zip_zipcrypto.zip"] = _zip_zipcrypto()
    return made


def _zip_streamed():
    """Local headers with GPBF bit 3: zero sizes + trailing PK\\x07\\x08."""
    out = bytearray()
    central = bytearray()
    for name, data in PAYLOADS.items():
        nb = name.encode()
        comp = zlib.compressobj(9, zlib.DEFLATED, -15)
        blob = comp.compress(data) + comp.flush()
        crc = zlib.crc32(data) & 0xFFFFFFFF
        off = len(out)
        out += b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0x08, 8, 0, 0, 0, 0, 0,
                                           len(nb), 0) + nb
        out += blob
        out += b"PK\x07\x08" + struct.pack("<III", crc, len(blob), len(data))
        central += b"PK\x01\x02" + struct.pack(
            "<HHHHHHIIIHHHHHII", 20, 20, 0x08, 8, 0, 0, crc, len(blob), len(data),
            len(nb), 0, 0, 0, 0, 0, off) + nb
    coff = len(out)
    out += central
    out += b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, len(PAYLOADS), len(PAYLOADS),
                                       len(central), coff, 0)
    return bytes(out)


def _zipcrypto_stream(pw: bytes, plain: bytes, crc: int):
    k = [0x12345678, 0x23456789, 0x34567890]
    tab = zlib.crc32

    def upd(c):
        k[0] = tab(bytes([c]), k[0] ^ 0xFFFFFFFF) ^ 0xFFFFFFFF
        k[1] = (k[1] + (k[0] & 0xFF)) & 0xFFFFFFFF
        k[1] = (k[1] * 134775813 + 1) & 0xFFFFFFFF
        k[2] = tab(bytes([(k[1] >> 24) & 0xFF]), k[2] ^ 0xFFFFFFFF) ^ 0xFFFFFFFF

    def stream_byte():
        t = (k[2] | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    for c in pw:
        upd(c)
    hdr = bytes(range(11)) + bytes([(crc >> 24) & 0xFF])
    out = bytearray()
    for c in hdr + plain:
        out.append(c ^ stream_byte())
        upd(c)
    return bytes(out)


def _zip_zipcrypto(pw=b"novelrar"):
    name, data = "secret.txt", b"classified payload\n"
    nb = name.encode()
    crc = zlib.crc32(data) & 0xFFFFFFFF
    enc = _zipcrypto_stream(pw, data, crc)
    out = bytearray()
    out += b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0x01, 0, 0, 0, crc,
                                       len(enc), len(data), len(nb), 0) + nb
    out += enc
    coff = len(out)
    central = b"PK\x01\x02" + struct.pack(
        "<HHHHHHIIIHHHHHII", 20, 20, 0x01, 0, 0, 0, crc, len(enc), len(data),
        len(nb), 0, 0, 0, 0, 0, 0) + nb
    out += central
    out += b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(central), coff, 0)
    return bytes(out)


# --------------------------------------------------------------------------
# LZ4 (oracle: python-lz4 -> liblz4)
# --------------------------------------------------------------------------
def lz4_fixtures():
    import lz4.frame
    import lz4.block
    made = {}
    made["lz4_text.lz4"] = lz4.frame.compress(TEXT, compression_level=9)
    made["lz4_bin.lz4"] = lz4.frame.compress(BIN, compression_level=0)
    made["lz4_csize.lz4"] = lz4.frame.compress(
        TEXT, content_checksum=True, block_checksum=True,
        store_size=True, block_size=lz4.frame.BLOCKSIZE_MAX64KB)
    made["lz4_linked.lz4"] = lz4.frame.compress(
        TEXT * 3, block_linked=True, content_checksum=True,
        block_size=lz4.frame.BLOCKSIZE_MAX64KB)
    made["lz4_indep.lz4"] = lz4.frame.compress(
        TEXT * 3, block_linked=False, block_size=lz4.frame.BLOCKSIZE_MAX64KB)
    made["lz4_nochk.lz4"] = lz4.frame.compress(
        SMALL, content_checksum=False, store_size=False)
    # multi-block frames: linked blocks carry matches across a block boundary,
    # independent ones may not, and incompressible input forces stored blocks.
    big = big_text()
    made["lz4_linkedbig.lz4"] = lz4.frame.compress(
        big, block_size=lz4.frame.BLOCKSIZE_MAX64KB, block_linked=True,
        content_checksum=True, block_checksum=True)
    made["lz4_indepbig.lz4"] = lz4.frame.compress(
        big, block_size=lz4.frame.BLOCKSIZE_MAX64KB, block_linked=False,
        content_checksum=True, block_checksum=True)
    rnd = pseudo_random()
    made["lz4_stored.lz4"] = lz4.frame.compress(
        rnd, block_size=lz4.frame.BLOCKSIZE_MAX64KB, content_checksum=True)
    # skippable frame prefix + a real frame
    skip = struct.pack("<II", 0x184D2A50, 8) + b"SKIPDATA"
    made["lz4_skippable.lz4"] = skip + lz4.frame.compress(SMALL)
    # legacy frame (magic 0x184C2102): 4-byte magic then size-prefixed blocks
    legacy = struct.pack("<I", 0x184C2102)
    for chunk in (TEXT[:2048], TEXT[2048:4096]):
        b = lz4.block.compress(chunk, store_size=False)
        legacy += struct.pack("<I", len(b)) + b
    made["lz4_legacy.lz4"] = legacy
    return made


# --------------------------------------------------------------------------
# 7z (oracle: py7zr)
# --------------------------------------------------------------------------
def sevenz_fixtures():
    import py7zr
    from py7zr import FILTER_LZMA, FILTER_LZMA2, FILTER_COPY, FILTER_BZIP2
    from py7zr import FILTER_DEFLATE, FILTER_DELTA, FILTER_X86
    made = {}
    specs = {
        "7z_lzma2.7z": [{"id": FILTER_LZMA2, "preset": 6}],
        "7z_lzma1.7z": [{"id": FILTER_LZMA, "preset": 6}],
        "7z_copy.7z": [{"id": FILTER_COPY}],
        "7z_bzip2.7z": [{"id": FILTER_BZIP2}],
        "7z_deflate.7z": [{"id": FILTER_DEFLATE}],
        "7z_delta_lzma2.7z": [{"id": FILTER_DELTA, "dist": 4},
                              {"id": FILTER_LZMA2, "preset": 6}],
        "7z_bcj_lzma2.7z": [{"id": FILTER_X86},
                            {"id": FILTER_LZMA2, "preset": 6}],
    }
    for fn, filters in specs.items():
        buf = io.BytesIO()
        with py7zr.SevenZipFile(buf, "w", filters=filters) as z:
            for n, d in PAYLOADS.items():
                z.writef(io.BytesIO(d), n)
        made[fn] = buf.getvalue()
    # Coders with no in-tree path: these must refuse cleanly, not crash.
    from py7zr import FILTER_PPMD, FILTER_ZSTD
    for fn, flt in (("7z_ppmd.7z", FILTER_PPMD), ("7z_zstd.7z", FILTER_ZSTD)):
        buf = io.BytesIO()
        try:
            with py7zr.SevenZipFile(buf, "w", filters=[{"id": flt}]) as z:
                z.writef(io.BytesIO(TEXT), "text.txt")
            made[fn] = buf.getvalue()
        except Exception as e:                       # optional in some builds
            print(f"  (skipped {fn}: {type(e).__name__})")

    # AES-256 encrypted -> must be refused, never cracked
    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w", password="novelrar") as z:
        z.writef(io.BytesIO(SMALL), "secret.txt")
    made["7z_aes.7z"] = buf.getvalue()
    return made


# --------------------------------------------------------------------------
# RAR — written here from the public RAR4 technote / RAR5 format notes.
# Store method only; enough to exercise the header walkers.
# --------------------------------------------------------------------------
RAR4_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"


def _rar4_block(htype, flags, body, data=b"", add_size=False):
    """crc16 | type | flags | hsize [| add_size] | body  (+ trailing data)."""
    extra = struct.pack("<I", len(data)) if add_size else b""
    hsize = 7 + len(extra) + len(body)
    head = struct.pack("<BHH", htype, flags, hsize) + extra + body
    crc = zlib.crc32(head) & 0xFFFF
    return struct.pack("<H", crc) + head + data


def _rar4_file(name: str, data: bytes, method=0x30, encrypted=False):
    nb = name.encode()
    flags = 0x8000 | (0x04 if encrypted else 0)  # LONG_BLOCK -> PACK_SIZE present
    # PACK_SIZE rides in the add_size slot; the body starts at UNP_SIZE.
    body = (struct.pack("<I", len(data)) + struct.pack("<B", 0x03) +
            struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF) +
            struct.pack("<I", 0) + struct.pack("<BB", 20, method) +
            struct.pack("<H", len(nb)) + struct.pack("<I", 0x20) + nb)
    return _rar4_block(0x74, flags, body, data, add_size=True)


def rar4_fixtures():
    made = {}
    body = RAR4_MAGIC
    body += _rar4_block(0x73, 0x0000, struct.pack("<HI", 0, 0))  # main
    for n, d in PAYLOADS.items():
        body += _rar4_file(n, d)
    body += _rar4_block(0x7b, 0x4000, b"")  # end
    made["rar4_store.rar"] = body

    # "compressed" (method 0x33) — headers real, payload opaque
    body = RAR4_MAGIC + _rar4_block(0x73, 0x0000, struct.pack("<HI", 0, 0))
    body += _rar4_file("text.txt", zlib.compress(TEXT)[2:-4], method=0x33)
    body += _rar4_block(0x7b, 0x4000, b"")
    made["rar4_normal.rar"] = body

    # encrypted file flag (0x04)
    body = RAR4_MAGIC + _rar4_block(0x73, 0x0000, struct.pack("<HI", 0, 0))
    body += _rar4_file("secret.txt", b"\x00" * 32, method=0x30, encrypted=True)
    body += _rar4_block(0x7b, 0x4000, b"")
    made["rar4_enc.rar"] = body
    return made


def _vint(n: int) -> bytes:
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _rar5_block(htype, hflags, body, data=b"", extra=b""):
    tail = _vint(htype) + _vint(hflags)
    if extra:
        tail += _vint(len(extra))
    if data:
        tail += _vint(len(data))
    tail += body + extra
    blk = _vint(len(tail)) + tail
    crc = zlib.crc32(blk) & 0xFFFFFFFF
    return struct.pack("<I", crc) + blk + data


def _rar5_file(name: str, data: bytes, method=0, encrypted=False):
    nb = name.encode()
    fflags = 0x0004  # CRC32 present
    comp = (0 << 0) | (method << 7) | (0 << 10)  # ver 0 | method | dict 0
    body = (_vint(fflags) + _vint(len(data)) + _vint(0x20) +
            struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF) +
            _vint(comp) + _vint(0) + _vint(len(nb)) + nb)
    extra = b""
    hflags = 0x0002  # data area present
    if encrypted:
        rec = _vint(1) + _vint(0) + b"\x00" * 16  # type 1 = file encryption
        extra = _vint(len(rec)) + rec
        hflags |= 0x0001
    return _rar5_block(2, hflags, body, data, extra)


def rar5_fixtures():
    made = {}
    body = RAR5_MAGIC + _rar5_block(1, 0, _vint(0) + _vint(0))  # main
    for n, d in PAYLOADS.items():
        body += _rar5_file(n, d)
    body += _rar5_block(5, 0, _vint(0))  # end
    made["rar5_store.rar"] = body

    body = RAR5_MAGIC + _rar5_block(1, 0, _vint(0) + _vint(0))
    body += _rar5_file("text.txt", zlib.compress(TEXT)[2:-4], method=3)
    body += _rar5_block(5, 0, _vint(0))
    made["rar5_normal.rar"] = body

    body = RAR5_MAGIC + _rar5_block(1, 0, _vint(0) + _vint(0))
    body += _rar5_file("secret.txt", b"\x00" * 32, encrypted=True)
    body += _rar5_block(5, 0, _vint(0))
    made["rar5_enc.rar"] = body

    # whole-archive encryption header (type 4) right after the marker
    made["rar5_hdrenc.rar"] = (RAR5_MAGIC +
                               _rar5_block(4, 0, _vint(0) + _vint(0) + b"\x00" * 16))
    return made


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    made = {}
    made.update(zip_fixtures())
    made.update(lz4_fixtures())
    made.update(sevenz_fixtures())
    made.update(rar4_fixtures())
    made.update(rar5_fixtures())
    for name, blob in sorted(made.items()):
        (OUT / name).write_bytes(blob)
        print(f"{name:24} {len(blob):8} bytes")
    (OUT / "_payloads.py").write_text(
        '"""Generated by tests/make_fixtures.py -- do not edit."""\n'
        "PAYLOADS = {\n"
        + "".join(f"    {k!r}: {v!r},\n" for k, v in PAYLOADS.items())
        + "}\n\n"
        "def big_text():\n"
        "    return (b'The quick brown fox jumps over the lazy dog. '\n"
        "            b'NOVELRAR windmill paint. ') * 3000\n\n"
        "def pseudo_random(n=70000):\n"
        "    import hashlib\n"
        "    out, i = bytearray(), 0\n"
        "    while len(out) < n:\n"
        "        out += hashlib.sha256(b'novelrar' + i.to_bytes(8, 'little')).digest()\n"
        "        i += 1\n"
        "    return bytes(out[:n])\n")
    print(f"\n{len(made)} fixtures -> {OUT}")


if __name__ == "__main__":
    main()
