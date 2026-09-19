#!/usr/bin/env python3
"""One entry point over every container, brokered by licence lane.

``open_archive(blob)`` sniffs the container, routes to the right reader, and
returns members alongside a :class:`license_broker.Receipt` for each one, so a
caller can ask not only "what came out" but "under what licence did it come
out, and how was it verified". ``audit()`` then gates the run.

Nothing here decides to be clever when a lawful path is missing: a member with
no permitted lane comes back with ``payload is None`` and a receipt that says
which lane it would have needed.
"""
from __future__ import annotations

import io
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Optional

import license_broker as LB
import lz4_frame
import rar_reader
import sevenzip
from license_broker import Policy, Receipt, make_receipt

PK_LOCAL = b"PK\x03\x04"
PK_CENTRAL = b"PK\x01\x02"
PK_EOCD = b"PK\x05\x06"
PK_EOCD64 = b"PK\x06\x06"

ZIP_METHODS = {0: "store", 8: "deflate", 9: "deflate64", 12: "bzip2",
               14: "lzma", 93: "zstd", 95: "xz", 98: "ppmd", 99: "aes"}


@dataclass
class Member:
    name: str
    container: str
    codec: str
    size: int = 0
    payload: Optional[bytes] = None
    error: Optional[str] = None
    is_dir: bool = False
    receipt: Optional[Receipt] = None


@dataclass
class Archive:
    container: str
    members: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    receipts: list = field(default_factory=list)

    def audit(self, policy: Optional[Policy] = None) -> LB.AuditResult:
        return LB.audit(self.receipts, policy)

    @property
    def extracted(self) -> int:
        return sum(1 for m in self.members if m.payload is not None)


# ---------------------------------------------------------------------------
# Sniffing
# ---------------------------------------------------------------------------

def sniff(blob: bytes) -> str:
    if blob.startswith(sevenzip.SIGNATURE):
        return "7z"
    if lz4_frame.is_lz4(blob):
        return "lz4"
    if blob[:4] in (PK_LOCAL, PK_CENTRAL, PK_EOCD):
        return "zip"
    head = blob[:1 << 20]
    if rar_reader.RAR5_MAGIC in head:
        return "rar5"
    if rar_reader.RAR4_MAGIC in head:
        return "rar4"
    if blob[:2] == b"\x1f\x8b":
        return "gzip"
    if blob[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if blob[:3] == b"BZh":
        return "bzip2"
    if blob[:4] == b"AV01":
        return "av01"
    return "raw"


# ---------------------------------------------------------------------------
# ZIP
# ---------------------------------------------------------------------------

def _zip_central(blob: bytes) -> list:
    """Walk the central directory: the authoritative index, per APPNOTE."""
    out = []
    i = blob.rfind(PK_CENTRAL)
    if i < 0:
        return out
    i = blob.find(PK_CENTRAL)
    while i >= 0 and i + 46 <= len(blob):
        (_v, _vn, flags, method, _t, _d, crc, csz, usz,
         nlen, elen, clen, _ds, _ia, _ea, off) = struct.unpack_from("<HHHHHHIIIHHHHHII", blob, i + 4)
        name = blob[i + 46:i + 46 + nlen].decode("utf-8", "replace")
        out.append(dict(name=name, flags=flags, method=method, crc=crc,
                        csize=csz, usize=usz, offset=off))
        i += 46 + nlen + elen + clen
        if blob[i:i + 4] != PK_CENTRAL:
            break
    return out


def read_zip(blob: bytes, password: Optional[bytes] = None, max_output: int = 64 << 20) -> Archive:
    arch = Archive(container="zip")
    index = _zip_central(blob)
    arch.notes.append(f"central directory: {len(index)} entries")
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
        infos = zf.infolist()
    except Exception as e:
        arch.notes.append(f"zipfile refused the container: {e}")
        return arch
    if sum(info.file_size for info in infos) > max_output:
        arch.notes.append("ZIP exceeds aggregate output limit")
        return arch
    by_name = {e["name"]: e for e in index}
    for info in infos:
        ent = by_name.get(info.filename, {})
        flags = info.flag_bits
        method = info.compress_type
        codec = ZIP_METHODS.get(method, f"method{method}")
        enc_weak = bool(flags & 0x01)
        enc_strong = bool(flags & 0x40) or method == 99
        m = Member(name=info.filename, container="zip", codec=codec,
                   size=info.file_size, is_dir=info.is_dir())
        if enc_strong or (enc_weak and password is None):
            codec = "aes" if enc_strong else "zipcrypto"
            m.codec = codec
            m.error = ("encrypted (WinZip AES)" if enc_strong else
                       "encrypted (ZipCrypto)") + "; refuse — no password handling"
            m.receipt = make_receipt(info.filename, "zip", codec,
                                     detail=m.error, ok=False)
        elif m.is_dir:
            m.payload = b""
            m.receipt = make_receipt(info.filename, "zip", "store",
                                     verified="directory", ok=True)
        else:
            try:
                with zf.open(info, pwd=password) as stream:
                    raw = stream.read(min(info.file_size,max_output)+1)
                if len(raw) != info.file_size:
                    raise ValueError("ZIP output size mismatch")
            except Exception as e:
                m.error = f"{type(e).__name__}: {e}"
                m.receipt = make_receipt(info.filename, "zip", codec,
                                         detail=m.error, ok=False)
            else:
                m.payload = raw
                verified = "—"
                if info.CRC is not None:
                    good = (zlib.crc32(raw) & 0xFFFFFFFF) == info.CRC
                    verified = "CRC-32 ok" if good else "CRC-32 BAD"
                    if not good:
                        m.error = "CRC-32 mismatch"
                m.size = len(raw)
                if enc_weak:
                    codec = "zipcrypto-password"
                m.receipt = make_receipt(info.filename, "zip", codec,
                                         n_bytes=len(raw), verified=verified,
                                         ok=m.error is None,
                                         detail=("streamed (data descriptor)"
                                                 if flags & 0x08 else ""))
        arch.members.append(m)
        arch.receipts.append(m.receipt)
    return arch


# ---------------------------------------------------------------------------
# 7z
# ---------------------------------------------------------------------------

def _sevenz_codec(chain: str) -> str:
    """Pick the registry key that decides the lane for a whole coder chain."""
    parts = [p.strip() for p in chain.split("->")]
    for want in ("aes256-sha256", "bcj2", "ppmd", "zstd", "brotli",
                 "lzma2", "lzma1", "bzip2", "deflate", "delta", "copy"):
        if want in parts:
            return want
    for p in parts:
        if p.startswith("bcj"):
            return "bcj"
    return parts[0] if parts else "container"


def read_7z(blob: bytes) -> Archive:
    arch = Archive(container="7z")
    try:
        a = sevenzip.read(blob)
    except sevenzip.SevenZRefused as e:
        arch.notes.append(str(e))
        arch.receipts.append(make_receipt("<archive>", "7z", "aes256-sha256",
                                          detail=str(e), ok=False))
        return arch
    except sevenzip.SevenZError as e:
        arch.notes.append(f"7z parse error: {e}")
        return arch
    arch.notes.extend(a.notes)
    if a.encrypted_header:
        arch.receipts.append(make_receipt("<header>", "7z", "aes256-sha256",
                                          detail="encrypted header", ok=False))
        return arch
    for e in a.entries:
        codec = _sevenz_codec(e.coders) if e.coders else "copy"
        m = Member(name=e.name, container="7z", codec=e.coders or "copy",
                   size=e.size, is_dir=e.is_dir, payload=e.payload, error=e.error)
        verified = ""
        if e.payload is not None:
            verified = "CRC-32 ok" if e.crc is not None and not e.error else "—"
            if e.error == "CRC32 mismatch":
                verified = "CRC-32 BAD"
        m.receipt = make_receipt(e.name, "7z", codec, chain=e.coders or "copy",
                                 n_bytes=len(e.payload or b""), verified=verified,
                                 ok=e.payload is not None and not e.error,
                                 detail=e.error or "")
        arch.members.append(m)
        arch.receipts.append(m.receipt)
    return arch


# ---------------------------------------------------------------------------
# LZ4
# ---------------------------------------------------------------------------

def read_lz4(blob: bytes, name: str = "stream") -> Archive:
    arch = Archive(container="lz4")
    try:
        info = lz4_frame.inspect(blob)
    except lz4_frame.LZ4Error as e:
        arch.notes.append(str(e))
        arch.receipts.append(make_receipt(name, "lz4", "frame",
                                          detail=str(e), ok=False))
        return arch
    kinds = [f["kind"] for f in info["frames"] if "kind" in f]
    errs = [f["error"] for f in info["frames"] if "error" in f]
    checks = sorted({c for f in info["frames"] for c in f.get("checks", [])})
    arch.notes.append(f"frames: {', '.join(kinds) or 'none'}")
    verified = "xxHash-32 ok" if any("xxh32" in c for c in checks) else "—"
    m = Member(name=name, container="lz4", codec="frame",
               size=info["n_out"], payload=None if errs else info["payload"],
               error="; ".join(errs) or None)
    m.receipt = make_receipt(name, "lz4", "frame",
                             chain="frame -> block", n_bytes=info["n_out"],
                             verified=verified, ok=not errs,
                             detail="; ".join(errs))
    arch.members.append(m)
    arch.receipts.append(m.receipt)
    return arch


# ---------------------------------------------------------------------------
# RAR
# ---------------------------------------------------------------------------

def read_rar(blob: bytes, policy: Optional[Policy] = None) -> Archive:
    policy = policy or Policy()
    arch = Archive(container="rar")
    try:
        a = rar_reader.read(blob)
    except rar_reader.RarError as e:
        arch.notes.append(str(e))
        return arch
    arch.container = a.version
    arch.notes.extend(a.notes)
    if a.header_encrypted:
        arch.receipts.append(make_receipt("<headers>", "rar", "header-encrypted",
                                          detail="headers are AES-encrypted",
                                          ok=False))
        return arch
    for r in a.members:
        m = Member(name=r.name, container=a.version, codec=r.method_name,
                   size=r.unp_size, is_dir=r.is_dir,
                   payload=r.payload, error=r.error)
        if r.encrypted:
            m.receipt = make_receipt(r.name, "rar", "encrypted",
                                     detail=r.error or "", ok=False)
        elif r.stored or r.is_dir:
            m.receipt = make_receipt(
                r.name, "rar", "store", chain="store",
                n_bytes=len(r.payload or b""),
                verified="CRC-32 ok" if (r.crc32 is not None and r.payload is not None and not r.error)
                         else ("directory" if r.is_dir else "—"),
                ok=r.payload is not None and not r.error, detail=r.error or "")
        else:
            # The one real licence obstacle: RAR's compressed stage.
            payload, tool, detail = LB.host_extract("rar", blob, r.name, policy)
            if payload is not None:
                ok = True
                if r.crc32 is not None and (zlib.crc32(payload) & 0xFFFFFFFF) != r.crc32:
                    ok, detail = False, "CRC-32 mismatch from host tool"
                m.payload = payload if ok else None
                m.error = None if ok else detail
                m.receipt = make_receipt(
                    r.name, "rar", "compressed", chain=f"rar-{r.method_name}",
                    n_bytes=len(payload), verified=("CRC-32 ok" if r.crc32 is not None else "not checked") if ok else "CRC-32 BAD",
                    ok=ok, detail=detail, tool=tool)
            else:
                m.error = r.error or detail
                m.receipt = make_receipt(
                    r.name, "rar", "compressed", chain=f"rar-{r.method_name}",
                    ok=False, detail=detail, tool=tool)
        arch.members.append(m)
        arch.receipts.append(m.receipt)
    return arch


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def open_archive(blob: bytes, name: str = "input",
                 policy: Optional[Policy] = None, password: Optional[bytes] = None, backend: str = "builtin") -> Archive:
    kind = sniff(blob)
    if kind == "zip":
        return read_zip(blob, password)
    if kind == "7z":
        if backend == "py7zr":
            pol = policy or Policy()
            if not pol.permits(LB.OPTIONAL):
                raise ValueError("policy forbids optional backend")
            from optional_sevenzip import read
            entries=read(blob,password.decode('utf-8') if password is not None else None)
            arch=Archive(container='7z')
            for name,data in entries.items():
                receipt=make_receipt(name,'7z','py7zr',n_bytes=len(data),
                                     verified='backend checks + size',ok=True)
                arch.members.append(Member(name,'7z','py7zr',len(data),data,receipt=receipt))
                arch.receipts.append(receipt)
            return arch
        return read_7z(blob)
    if kind == "lz4":
        return read_lz4(blob, name)
    if kind in ("rar4", "rar5"):
        return read_rar(blob, policy)
    arch = Archive(container=kind)
    arch.notes.append(f"'{kind}' is not a container this module unpacks")
    return arch
