#!/usr/bin/env python3
"""RAR container reader — metadata and stored members only, by design.

Provenance
----------
RAR is the one format in this tree with a genuine licensing obstacle, and it
is worth stating precisely, because it is narrower than "RAR is proprietary".

  * The **container layout** (RAR4 ``technote.txt``, and the RAR5 format
    notes published with the unrar distribution) is public documentation.
    Parsing block headers from it is lane ``CLEANROOM``.
  * Method 0x30 (RAR4) / method 0 (RAR5) is **store** — the payload is a
    byte-for-byte copy. Copying bytes is not an algorithm anybody licenses.
  * The **compressed** payload is the problem. The unrar source is published
    under a licence that permits using the sources to *read* RAR archives but
    forbids using them to recreate the RAR compression algorithm, and forbids
    reverse engineering. So we do not vendor it, do not translate it, and do
    not guess at it. Compressed members are lane ``HOST`` (hand off to a
    binary the operator installed themselves) or lane ``REFUSED``.

Encrypted members and encrypted headers are refused outright. No password is
derived, tried, or accepted anywhere in this module.

Fixes over the earlier walker: RAR4 0x8000 is LONG_BLOCK (present on every
file header), not header encryption — the old code aborted on the first file
of every archive; the RAR4 file-header struct had FTIME as 1 byte instead of
4; RAR5 extra-area records were walked with an expression that could not
advance; and the RAR5 method field is bits 7-9, not 8-10.
"""
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from typing import Optional

RAR4_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"

# --- RAR4 ------------------------------------------------------------------
R4_MARK, R4_MAIN, R4_FILE, R4_COMMENT = 0x72, 0x73, 0x74, 0x75
R4_AV, R4_SUB, R4_PROTECT, R4_AV2, R4_SUBBLOCK, R4_END = 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B
R4_TYPE = {R4_MARK: "mark", R4_MAIN: "main", R4_FILE: "file", R4_COMMENT: "comment",
           R4_AV: "av", R4_SUB: "sub", R4_PROTECT: "recovery", R4_AV2: "av2",
           R4_SUBBLOCK: "subblock", R4_END: "end"}

LONG_BLOCK = 0x8000      # ADD_SIZE field present — set on EVERY file header
MHD_PASSWORD = 0x0080    # main-header flag: the whole archive's headers are AES
LHD_SPLIT_BEFORE = 0x0001
LHD_SPLIT_AFTER = 0x0002
LHD_PASSWORD = 0x0004
LHD_SOLID = 0x0010
LHD_LARGE = 0x0100
LHD_UNICODE = 0x0200
LHD_SALT = 0x0400

R4_METHOD = {0x30: "store", 0x31: "fastest", 0x32: "fast",
             0x33: "normal", 0x34: "good", 0x35: "best"}

# --- RAR5 ------------------------------------------------------------------
R5_MAIN, R5_FILE, R5_SERVICE, R5_CRYPT, R5_END = 1, 2, 3, 4, 5
R5_TYPE = {R5_MAIN: "main", R5_FILE: "file", R5_SERVICE: "service",
           R5_CRYPT: "crypt", R5_END: "end"}
R5_EXTRA = {1: "file-encryption", 2: "file-hash", 3: "file-time",
            4: "file-version", 5: "redirection", 6: "unix-owner", 7: "service-data"}
R5_METHOD = {0: "store", 1: "fastest", 2: "fast", 3: "normal", 4: "good", 5: "best"}

HF_EXTRA, HF_DATA = 0x0001, 0x0002
FF_DIRECTORY, FF_MTIME, FF_CRC32, FF_UNKNOWN_SIZE = 0x0001, 0x0002, 0x0004, 0x0008


class RarError(ValueError):
    pass


@dataclass
class RarMember:
    version: str
    name: str
    method: int
    method_name: str
    encrypted: bool
    solid: bool
    is_dir: bool
    pack_size: int
    unp_size: int
    crc32: Optional[int]
    data_off: int
    payload: Optional[bytes] = None
    error: Optional[str] = None
    extra: dict = field(default_factory=dict)

    @property
    def stored(self) -> bool:
        return (self.version == "rar4" and self.method == 0x30) or \
               (self.version == "rar5" and self.method == 0)


@dataclass
class RarArchive:
    version: str = ""
    members: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    header_encrypted: bool = False
    solid: bool = False
    volume: bool = False


def _rar4_name(raw: bytes, unicode_flag: bool) -> str:
    """Unicode names store 'ascii\\0<rar-packed utf16>'; keep the ascii form.

    Unpacking the second half needs RAR's own name encoder, which is part of
    the licensed source. The ASCII fallback is always present and is what the
    format guarantees for compatibility.
    """
    if unicode_flag and b"\x00" in raw:
        raw = raw.split(b"\x00", 1)[0]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp437", "replace")


def read_rar4(blob: bytes) -> RarArchive:
    arch = RarArchive(version="rar4")
    i = blob.find(RAR4_MAGIC)
    if i < 0:
        raise RarError("no RAR4 marker")
    i += len(RAR4_MAGIC)
    n = len(blob)
    while i + 7 <= n:
        _crc, htype, flags, hsize = struct.unpack_from("<HBHH", blob, i)
        if hsize < 7 or i + hsize > n:
            arch.notes.append(f"bad header size {hsize} at {i}; stop")
            break
        kind = R4_TYPE.get(htype, f"0x{htype:02x}")
        add_size = 0
        if flags & LONG_BLOCK and i + 11 <= n:
            add_size = struct.unpack_from("<I", blob, i + 7)[0]
        arch.notes.append(
            f"@{i} {kind} flags=0x{flags:04x} hsize={hsize} add={add_size}")
        if htype == R4_MAIN:
            if flags & MHD_PASSWORD:
                arch.header_encrypted = True
                arch.notes.append(
                    "MHD_PASSWORD set: headers are AES-encrypted; refuse the walk")
                break
            arch.solid = bool(flags & 0x0008)
            arch.volume = bool(flags & 0x0001)
            i += hsize + add_size
            continue
        if htype == R4_END:
            arch.notes.append("end-of-archive block")
            break
        if htype == R4_FILE:
            # PACK_SIZE is the ADD_SIZE slot; the rest follows at +11.
            pack = add_size
            (unp, host, fcrc, ftime, unpver, method, nsz, attr) = struct.unpack_from(
                "<IBIIBBHI", blob, i + 11)
            off = i + 11 + 4 + 1 + 4 + 4 + 1 + 1 + 2 + 4
            if flags & LHD_LARGE:
                hi_pack, hi_unp = struct.unpack_from("<II", blob, off)
                pack |= hi_pack << 32
                unp |= hi_unp << 32
                off += 8
            name_raw = blob[off:off + nsz]
            m = RarMember(
                version="rar4",
                name=_rar4_name(name_raw, bool(flags & LHD_UNICODE)),
                method=method, method_name=R4_METHOD.get(method, f"0x{method:02x}"),
                encrypted=bool(flags & LHD_PASSWORD),
                solid=bool(flags & LHD_SOLID),
                is_dir=(attr & 0x10) != 0 or (flags & 0xE0) == 0xE0,
                pack_size=pack, unp_size=unp, crc32=fcrc,
                data_off=i + hsize,
                extra={"host_os": host, "unp_ver": unpver, "flags": flags,
                       "split_before": bool(flags & LHD_SPLIT_BEFORE),
                       "split_after": bool(flags & LHD_SPLIT_AFTER),
                       "salted": bool(flags & LHD_SALT)},
            )
            _finish(m, blob)
            arch.members.append(m)
            i = m.data_off + pack
            continue
        i += hsize + add_size
    return arch


def _read_vint(buf: bytes, off: int) -> tuple[int, int]:
    val = shift = 0
    while off < len(buf):
        b = buf[off]
        off += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, off
        shift += 7
        if shift > 63:
            raise RarError("vint overflow")
    raise RarError("truncated vint")


def _walk_extra(area: bytes) -> dict:
    """Extra-area records: <size vint><type vint><data>, size covers type+data."""
    seen, off = {}, 0
    while off < len(area):
        try:
            size, p = _read_vint(area, off)
        except RarError:
            break
        if size == 0 or p + size > len(area) + 1:
            break
        rec_end = p + size
        try:
            rtype, q = _read_vint(area, p)
        except RarError:
            break
        seen[R5_EXTRA.get(rtype, f"type{rtype}")] = area[q:rec_end]
        if rec_end <= off:
            break
        off = rec_end
    return seen


def read_rar5(blob: bytes) -> RarArchive:
    arch = RarArchive(version="rar5")
    i = blob.find(RAR5_MAGIC)
    if i < 0:
        raise RarError("no RAR5 marker")
    i += len(RAR5_MAGIC)
    n = len(blob)
    while i + 5 <= n:
        start = i
        i += 4  # header CRC32
        try:
            hsize, hstart = _read_vint(blob, i)
        except RarError as e:
            arch.notes.append(str(e))
            break
        if hsize <= 0 or hstart + hsize > n:
            arch.notes.append(f"bad header size {hsize} at {start}; stop")
            break
        hend = hstart + hsize
        try:
            htype, j = _read_vint(blob, hstart)
            hflags, j = _read_vint(blob, j)
            extra_sz = data_sz = 0
            if hflags & HF_EXTRA:
                extra_sz, j = _read_vint(blob, j)
            if hflags & HF_DATA:
                data_sz, j = _read_vint(blob, j)
        except RarError as e:
            arch.notes.append(f"header parse: {e}")
            break
        kind = R5_TYPE.get(htype, f"type{htype}")
        arch.notes.append(
            f"@{start} {kind} flags=0x{hflags:x} extra={extra_sz} data={data_sz}")
        if htype == R5_CRYPT:
            arch.header_encrypted = True
            arch.notes.append(
                "archive encryption header (type 4, AES-256); refuse the walk")
            break
        if htype == R5_END:
            arch.notes.append("end-of-archive block")
            break
        if htype in (R5_FILE, R5_SERVICE):
            extra = blob[hend - extra_sz:hend] if extra_sz else b""
            records = _walk_extra(extra)
            try:
                fflags, k = _read_vint(blob, j)
                unp, k = _read_vint(blob, k)
                attr, k = _read_vint(blob, k)
                if fflags & FF_MTIME:
                    k += 4
                crc = None
                if fflags & FF_CRC32:
                    crc = struct.unpack_from("<I", blob, k)[0]
                    k += 4
                comp, k = _read_vint(blob, k)
                _host, k = _read_vint(blob, k)
                nlen, k = _read_vint(blob, k)
                name = blob[k:k + nlen].decode("utf-8", "replace")
            except (RarError, struct.error) as e:
                arch.notes.append(f"{kind} header body: {e}")
                i = hend + data_sz
                continue
            method = (comp >> 7) & 0x07          # bits 7-9, not 8-10
            if htype == R5_SERVICE:
                arch.notes.append(f"service record '{name}' ({data_sz} bytes)")
                i = hend + data_sz
                continue
            m = RarMember(
                version="rar5", name=name, method=method,
                method_name=R5_METHOD.get(method, f"m{method}"),
                encrypted="file-encryption" in records,
                solid=bool(comp & 0x40),
                is_dir=bool(fflags & FF_DIRECTORY),
                pack_size=data_sz,
                unp_size=0 if fflags & FF_UNKNOWN_SIZE else unp,
                crc32=crc, data_off=hend,
                extra={"comp_info": comp, "attr": attr,
                       "dict_shift": (comp >> 10) & 0x0F,
                       "rar_version": comp & 0x3F,
                       "extra_records": sorted(records)},
            )
            _finish(m, blob)
            arch.members.append(m)
            i = hend + data_sz
            continue
        i = hend + data_sz
    return arch


def _finish(m: RarMember, blob: bytes) -> None:
    """Attach a payload only when a lawful path exists."""
    if m.encrypted:
        m.error = ("encrypted member (AES); refuse — no password is derived, "
                   "tried, or accepted")
        return
    if m.is_dir:
        m.payload = b""
        return
    if not m.stored:
        m.error = (f"method '{m.method_name}' is RAR's proprietary LZ/PPM stage; "
                   "no in-tree path. Hand off to an operator-installed unrar.")
        return
    data = blob[m.data_off:m.data_off + m.pack_size]
    if len(data) != m.pack_size:
        m.error = f"truncated: {len(data)} of {m.pack_size} packed bytes"
        return
    if m.unp_size and len(data) != m.unp_size:
        m.error = f"store size mismatch {len(data)} != {m.unp_size}"
        return
    if m.crc32 is not None and m.crc32 != 0:
        got = zlib.crc32(data) & 0xFFFFFFFF
        if got != m.crc32:
            m.error = f"CRC32 {got:08x} != {m.crc32:08x}"
            return
    m.payload = data


def read(blob: bytes) -> RarArchive:
    if RAR5_MAGIC in blob[:1 << 20]:
        return read_rar5(blob)
    if RAR4_MAGIC in blob[:1 << 20]:
        return read_rar4(blob)
    raise RarError("no RAR marker in the first megabyte")


def is_rar(blob: bytes) -> bool:
    head = blob[:1 << 20]
    return RAR5_MAGIC in head or RAR4_MAGIC in head
