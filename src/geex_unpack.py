#!/usr/bin/env python3
"""
GEEX-UNPACK: geometric eval/extract *after* a real unzip/unrar-style pipeline.

ZIP  — PK local/central/EOCD walk, method 0 store / 8 raw DEFLATE inflate
       (zlib wbits=-15, same as zipfile), CRC-32 check.
RAR4 — marker + block walk; extract METHOD 0x30 store only.
RAR5 — marker + vint headers; extract compression method 0 (store) only.
Encrypted members: list metadata, refuse payload.

GEEX then scores the *decoded* member, not the container bytes.
Optional: DEFLATE token trace → (pos, distance, length) match cloud.

Does not invert AES, ZipCrypto, RAR header crypt, or proprietary RAR LZ.
"""
from __future__ import annotations

import io
import struct
import zlib
import zipfile
import hashlib
import math
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple
from pathlib import Path
import numpy as np

# ---------------------------------------------------------------------------
# ZIP — modeled on unzip / APPNOTE
# ---------------------------------------------------------------------------

PK_LOCAL = b"PK\x03\x04"
PK_CENTRAL = b"PK\x01\x02"
PK_EOCD = b"PK\x05\x06"
PK_DDESC = b"PK\x07\x08"

ZIP_METHODS = {
    0: "store",
    8: "deflate",
    9: "deflate64",
    12: "bzip2",
    14: "lzma",
}

@dataclass
class ZipMember:
    name: str
    method: int
    method_name: str
    encrypted: bool
    comp_size: int
    uncomp_size: int
    crc32: int
    flags: int
    data_off: int
    payload: Optional[bytes] = None
    error: Optional[str] = None


def parse_zip_locals(blob: bytes) -> List[ZipMember]:
    """Walk local file headers the way unzip scans the stream."""
    members: List[ZipMember] = []
    i, n = 0, len(blob)
    while i + 30 <= n:
        if blob[i:i+4] != PK_LOCAL:
            # skip to next possible header / central dir
            j = blob.find(PK_LOCAL, i + 1)
            if j < 0:
                break
            i = j
            continue
        ver, flags, method, _mtime, _mdate, crc, csz, usz, nlen, elen = struct.unpack_from(
            "<HHHHHIIIHH", blob, i + 4
        )
        name = blob[i+30:i+30+nlen].decode("utf-8", "replace")
        data_off = i + 30 + nlen + elen
        encrypted = bool(flags & 1) or bool(flags & 0x40)
        m = ZipMember(
            name=name, method=method, method_name=ZIP_METHODS.get(method, f"meth{method}"),
            encrypted=encrypted, comp_size=csz, uncomp_size=usz, crc32=crc,
            flags=flags, data_off=data_off,
        )
        # data descriptor: sizes may be zero if bit 3 set
        if flags & 8:
            # compressed data runs until we see a descriptor; we still need csz.
            # Prefer central-directory sizes when available; here scan descriptor.
            # After data: optional PK\x07\x08 + crc + csz + usz
            m.error = "data-descriptor sizes unknown in local walk; use zipfile fallback"
        members.append(m)
        if flags & 8:
            break  # cannot safely skip without csz
        i = data_off + csz
    return members


def unzip_member(blob: bytes, m: ZipMember) -> ZipMember:
    """Real unzip step: store copy or raw DEFLATE inflate + CRC."""
    if m.encrypted:
        m.error = "encrypted; refuse (ZipCrypto/AES). no password attempt"
        return m
    sl = blob[m.data_off:m.data_off + m.comp_size]
    try:
        if m.method == 0:
            raw = sl
        elif m.method == 8:
            # ZIP stores raw DEFLATE, not zlib-wrapped — same as unzip
            raw = zlib.decompress(sl, -15)
        else:
            m.error = f"unsupported ZIP method {m.method} ({m.method_name})"
            return m
    except zlib.error as e:
        m.error = f"inflate failed: {e}"
        return m
    if m.uncomp_size and len(raw) != m.uncomp_size:
        m.error = f"size mismatch got {len(raw)} want {m.uncomp_size}"
    got = zlib.crc32(raw) & 0xFFFFFFFF
    if m.crc32 and got != m.crc32:
        m.error = f"CRC mismatch got {got:08x} want {m.crc32:08x}"
    m.payload = raw
    return m


def unzip_via_stdlib(blob: bytes) -> List[ZipMember]:
    """Fallback / cross-check using zipfile, still refuses encrypt."""
    out: List[ZipMember] = []
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for info in zf.infolist():
            enc = bool(info.flag_bits & 1)
            m = ZipMember(
                name=info.filename, method=info.compress_type,
                method_name=ZIP_METHODS.get(info.compress_type, str(info.compress_type)),
                encrypted=enc, comp_size=info.compress_size, uncomp_size=info.file_size,
                crc32=info.CRC, flags=info.flag_bits, data_off=info.header_offset,
            )
            if enc:
                m.error = "encrypted; refuse"
            else:
                try:
                    m.payload = zf.read(info)
                except Exception as e:
                    m.error = str(e)
            out.append(m)
    return out


# ---------------------------------------------------------------------------
# DEFLATE token trace (RFC 1951) — match cloud from the real inflate grammar
# Stored + fixed Huffman + dynamic Huffman. Used to *observe* unzip, not replace it.
# ---------------------------------------------------------------------------

class BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.i = 0
        self.buf = 0
        self.nbits = 0

    def bits(self, k: int) -> int:
        while self.nbits < k:
            if self.i >= len(self.data):
                raise EOFError("deflate truncated")
            self.buf |= self.data[self.i] << self.nbits
            self.i += 1
            self.nbits += 8
        v = self.buf & ((1 << k) - 1)
        self.buf >>= k
        self.nbits -= k
        return v

    def align(self):
        self.buf = 0
        self.nbits = 0


# RFC 1951 length/distance extra-bit tables
LEN_BASE = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258]
LEN_EXTRA = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0]
DIST_BASE = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577]
DIST_EXTRA = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13]


def _build_codes(lengths):
    """canonical Huffman: lengths[sym] -> (code,len) map via first-code method."""
    maxl = max(lengths) if lengths else 0
    bl_count = [0] * (maxl + 1)
    for l in lengths:
        if l:
            bl_count[l] += 1
    code = 0
    next_code = [0] * (maxl + 1)
    for bits in range(1, maxl + 1):
        code = (code + bl_count[bits - 1]) << 1
        next_code[bits] = code
    codes = {}
    decode = {}
    for sym, l in enumerate(lengths):
        if l:
            c = next_code[l]
            next_code[l] += 1
            decode[(c, l)] = sym
    # bit-reversed lookup by consuming MSB first? DEFLATE packs LSB first in the stream
    # so we read bits LSB-first and build codes in that convention (zlib/RFC).
    return decode, maxl


def _decode_symbol(br: BitReader, decode, maxl):
    code = 0
    for l in range(1, maxl + 1):
        code = (code << 1) | br.bits(1)
        # wait: DEFLATE bits are packed LSB first, Huffman codes are also
        # considered in the bit-reversed-on-wire convention used by zlib:
        # the canonical code is assigned then sent LSB of code first?
        # Standard approach: read bits LSB-first into an accumulating integer
        # from the LOW end. Rebuild.
        pass
    raise RuntimeError("unreachable")


def _codes_lsb(lengths):
    """Return table: for each length, dict of lsb-packed code -> symbol.
    Canonical codes assigned MSB-first then bit-reversed onto the wire."""
    maxl = max(lengths) if lengths else 0
    bl_count = [0] * (maxl + 1)
    for l in lengths:
        if l:
            bl_count[l] += 1
    code = 0
    next_code = [0] * (maxl + 1)
    for bits in range(1, maxl + 1):
        code = (code + bl_count[bits - 1]) << 1
        next_code[bits] = code
    tables = [None] + [{} for _ in range(maxl)]
    for sym, l in enumerate(lengths):
        if not l:
            continue
        c = next_code[l]
        next_code[l] += 1
        # reverse l bits so we can accumulate LSB-first
        rev = 0
        x = c
        for _ in range(l):
            rev = (rev << 1) | (x & 1)
            x >>= 1
        tables[l][rev] = sym
    return tables, maxl


def _read_sym(br, tables, maxl):
    code = 0
    for l in range(1, maxl + 1):
        code |= br.bits(1) << (l - 1)
        if code in tables[l]:
            return tables[l][code]
    raise ValueError("bad huffman symbol")


def _fixed_lit_lengths():
    L = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
    return L


def _fixed_dist_lengths():
    return [5] * 32


def _inflate_dynamic(br: BitReader):
    nlit = br.bits(5) + 257
    ndist = br.bits(5) + 1
    nclen = br.bits(4) + 4
    order = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]
    clen = [0] * 19
    for i in range(nclen):
        clen[order[i]] = br.bits(3)
    ct, cmax = _codes_lsb(clen)
    lengths = []
    total = nlit + ndist
    while len(lengths) < total:
        s = _read_sym(br, ct, cmax)
        if s < 16:
            lengths.append(s)
        elif s == 16:
            if not lengths:
                raise ValueError("bad 16")
            lengths.extend([lengths[-1]] * (3 + br.bits(2)))
        elif s == 17:
            lengths.extend([0] * (3 + br.bits(3)))
        else:
            lengths.extend([0] * (11 + br.bits(7)))
    return lengths[:nlit], lengths[nlit:]


@dataclass
class MatchEvent:
    pos: int
    distance: int
    length: int


def inflate_trace(data: bytes) -> Tuple[bytes, List[MatchEvent], dict]:
    """RFC 1951 inflate with match diary. Returns (out, matches, stats)."""
    br = BitReader(data)
    out = bytearray()
    matches: List[MatchEvent] = []
    n_lit = n_match = n_stored = 0
    last = 0
    while not last:
        last = br.bits(1)
        btype = br.bits(2)
        if btype == 3:
            raise ValueError("reserved BTYPE")
        if btype == 0:
            br.align()
            ln = br.bits(16)
            nln = br.bits(16)
            if (ln ^ 0xFFFF) != nln:
                raise ValueError("bad stored LEN")
            # stored bytes are byte-aligned in BitReader after align
            chunk = br.data[br.i:br.i+ln]
            if len(chunk) < ln:
                raise EOFError("stored short")
            br.i += ln
            out.extend(chunk)
            n_stored += ln
            continue
        if btype == 1:
            lit_t, lit_m = _codes_lsb(_fixed_lit_lengths())
            dist_t, dist_m = _codes_lsb(_fixed_dist_lengths())
        else:
            ll, dd = _inflate_dynamic(br)
            lit_t, lit_m = _codes_lsb(ll)
            dist_t, dist_m = _codes_lsb(dd)
        while True:
            s = _read_sym(br, lit_t, lit_m)
            if s < 256:
                out.append(s)
                n_lit += 1
            elif s == 256:
                break
            else:
                idx = s - 257
                length = LEN_BASE[idx] + (br.bits(LEN_EXTRA[idx]) if LEN_EXTRA[idx] else 0)
                dsym = _read_sym(br, dist_t, dist_m)
                dist = DIST_BASE[dsym] + (br.bits(DIST_EXTRA[dsym]) if DIST_EXTRA[dsym] else 0)
                if dist <= 0 or dist > len(out):
                    raise ValueError(f"bad distance {dist} at {len(out)}")
                matches.append(MatchEvent(len(out), dist, length))
                for _ in range(length):
                    out.append(out[-dist])
                n_match += 1
    stats = dict(n_lit=n_lit, n_match=n_match, n_stored=n_stored,
                 n_out=len(out), n_in=br.i)
    return bytes(out), matches, stats


# ---------------------------------------------------------------------------
# RAR4 header walk (technote) — store only
# ---------------------------------------------------------------------------

RAR4_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"

RAR4_HEAD = {
    0x72: "mark",
    0x73: "main",
    0x74: "file",
    0x75: "comment",
    0x76: "av",
    0x77: "sub",
    0x78: "recovery",
    0x79: "av2",
    0x7a: "subblock",
    0x7b: "end",
}

RAR4_METHOD = {
    0x30: "store",
    0x31: "fastest",
    0x32: "fast",
    0x33: "normal",
    0x34: "good",
    0x35: "best",
}


@dataclass
class RarMember:
    version: str
    name: str
    method: int
    method_name: str
    encrypted: bool
    pack_size: int
    unp_size: int
    data_off: int
    payload: Optional[bytes] = None
    error: Optional[str] = None
    extra: dict = field(default_factory=dict)


def walk_rar4(blob: bytes) -> Tuple[list, List[RarMember]]:
    notes = []
    members: List[RarMember] = []
    i = blob.find(RAR4_MAGIC)
    if i < 0:
        return notes, members
    i += 7
    n = len(blob)
    while i + 7 <= n:
        crc, htype, flags, hsize = struct.unpack_from("<HBHH", blob, i)
        if hsize < 7 or i + hsize > n:
            notes.append(f"bad header size {hsize} at {i}")
            break
        kind = RAR4_HEAD.get(htype, f"0x{htype:02x}")
        notes.append(f"RAR4 @{i} type={kind} flags=0x{flags:04x} hsize={hsize}")
        if htype == 0x7b:
            break
        if flags & 0x8000:
            notes.append("header-encrypted (0x8000); refuse further parse")
            break
        add_size = 0
        if flags & 0x8000:
            add_size = 0
        # blocks with data: long block flag 0x8000 is "add_size present" in RAR4
        # actually 0x8000 = ADD_SIZE_PRESENT for many headers
        data_size = 0
        if flags & 0x8000 and htype != 0x74:
            if i + 11 <= n:
                data_size = struct.unpack_from("<I", blob, i + 7)[0]
        if htype == 0x74:
            # file header
            pack, unp, host, fcrc, ftime, unpver, method, nsz, attr = struct.unpack_from(
                "<IIBIBBHHI", blob, i + 7
            )
            name_off = i + 7 + 4+4+1+4+4+1+1+2+4
            # HIGH sizes if 0x100
            extra_off = 0
            if flags & 0x100:
                name_off += 8
            name = blob[name_off:name_off + nsz]
            try:
                name_s = name.decode("utf-8")
            except Exception:
                name_s = name.decode("latin-1", "replace")
            encrypted = bool(flags & 0x04)
            data_off = i + hsize
            m = RarMember(
                version="rar4", name=name_s, method=method,
                method_name=RAR4_METHOD.get(method, f"0x{method:02x}"),
                encrypted=encrypted, pack_size=pack, unp_size=unp, data_off=data_off,
                extra={"host": host, "unp_ver": unpver, "flags": flags},
            )
            if encrypted:
                m.error = "RAR4 encrypted file (HEAD_FLAGS 0x04); refuse"
            elif method == 0x30:
                m.payload = blob[data_off:data_off + pack]
                if unp and len(m.payload) != unp:
                    m.error = f"store size mismatch {len(m.payload)}!={unp}"
            else:
                m.error = f"RAR4 method {m.method_name} needs native unrar LZ+Huffman; not implemented"
            members.append(m)
            i = data_off + pack
            continue
        i += hsize + data_size
    return notes, members


def _read_vint(buf: bytes, off: int) -> Tuple[int, int]:
    val = 0
    shift = 0
    start = off
    while off < len(buf):
        b = buf[off]
        off += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, off
        shift += 7
        if shift > 63:
            raise ValueError("vint overflow")
    raise ValueError("truncated vint")


def walk_rar5(blob: bytes) -> Tuple[list, List[RarMember]]:
    notes = []
    members: List[RarMember] = []
    i = blob.find(RAR5_MAGIC)
    if i < 0:
        return notes, members
    i += 8
    n = len(blob)
    while i + 5 <= n:
        start = i
        hdr_crc = struct.unpack_from("<I", blob, i)[0]
        i += 4
        try:
            hsize, i = _read_vint(blob, i)
        except ValueError as e:
            notes.append(str(e))
            break
        hstart = i
        if hsize <= 0 or hstart + hsize > n:
            notes.append(f"bad RAR5 hsize {hsize} at {start}")
            break
        hend = hstart + hsize
        try:
            htype, j = _read_vint(blob, hstart)
            flags, j = _read_vint(blob, j)
            extra_sz = data_sz = 0
            if flags & 0x0001:
                extra_sz, j = _read_vint(blob, j)
            if flags & 0x0002:
                data_sz, j = _read_vint(blob, j)
        except ValueError as e:
            notes.append(str(e))
            break
        notes.append(f"RAR5 @{start} type={htype} flags=0x{flags:x} extra={extra_sz} data={data_sz}")
        if htype == 4:
            notes.append("RAR5 archive encryption header (type 4, AES-256); refuse further")
            break
        if htype == 5:
            break
        if htype == 2:
            # file header body at j
            try:
                fflags, k = _read_vint(blob, j)
                unp, k = _read_vint(blob, k)
                attr, k = _read_vint(blob, k)
                if fflags & 0x0002:
                    k += 4  # mtime
                crc = 0
                if fflags & 0x0004:
                    crc = struct.unpack_from("<I", blob, k)[0]
                    k += 4
                comp, k = _read_vint(blob, k)
                host, k = _read_vint(blob, k)
                nlen, k = _read_vint(blob, k)
                name = blob[k:k+nlen].decode("utf-8", "replace")
                method = (comp >> 8) & 0x7
                solid = bool(comp & 0x40)
                enc = False  # extra record 0x01 would say so; we scan extra if present
            except ValueError as e:
                notes.append(f"file hdr parse {e}")
                i = hend + data_sz
                continue
            # extra area sits at hend - extra_sz
            extra = blob[hend - extra_sz:hend] if extra_sz else b""
            # walk extra records for encryption type 1
            eoff = 0
            while extra and eoff < len(extra):
                try:
                    esz, eoff = _read_vint(extra, eoff)
                    et, eoff2 = _read_vint(extra, eoff)
                except ValueError:
                    break
                if et == 1:
                    enc = True
                eoff = eoff + max(0, esz - (eoff2 - eoff)) if False else eoff2 + max(0, esz)
                # conservative: if type 1 seen, encrypted
                if et == 1:
                    break
            data_off = hend
            m = RarMember(
                version="rar5", name=name, method=method,
                method_name=("store" if method == 0 else f"rar5-m{method}"),
                encrypted=enc, pack_size=data_sz, unp_size=unp, data_off=data_off,
                extra={"solid": solid, "comp": comp, "host": host},
            )
            if enc:
                m.error = "RAR5 file encryption extra (AES-256); refuse"
            elif method == 0:
                m.payload = blob[data_off:data_off + data_sz]
            else:
                m.error = "RAR5 compressed method needs native unrar; not implemented"
            members.append(m)
            i = hend + data_sz
            continue
        i = hend + data_sz
    return notes, members


# ---------------------------------------------------------------------------
# Dispatch + GEEX on decoded members
# ---------------------------------------------------------------------------

def sniff(blob: bytes) -> str:
    if blob.startswith(b"AV01"):
        return "av01"
    if blob.startswith(b"PK\x03\x04") or blob.startswith(b"PK\x05\x06"):
        return "zip"
    if blob.startswith(RAR5_MAGIC) or RAR5_MAGIC in blob[:1024*1024]:
        return "rar5"
    if blob.startswith(RAR4_MAGIC) or RAR4_MAGIC in blob[:1024*1024]:
        return "rar4"
    if blob.startswith(b"7z\xbc\xaf'\x1c"):
        return "7z"
    if blob.startswith(b"\x04\"M\x18"):
        return "lz4-frame"
    return "raw"


def geex_lite(data: bytes, cap=4096) -> dict:
    """Small eval on decoded bytes (cube shadows / foam / language gate)."""
    block = data[:cap]
    n = len(block)
    if n == 0:
        return dict(type="empty", n=0)
    D = int(math.ceil(n ** (1/3)))
    vol = np.zeros((D, D, D), dtype=np.uint8)
    a = np.frombuffer(block, dtype=np.uint8)
    vol.reshape(-1)[:n] = a
    mean = float(a.mean())
    hb = vol >= 128
    nz = vol != 0
    V_hb = int(hb.sum())
    # shadows of highbit
    sx, sy, sz = hb.any(2).sum(), hb.any(1).sum(), hb.any(0).sum()
    areas = (int(sx), int(sy), int(sz))
    # foam on highbit
    def faces(occ):
        p = np.pad(occ, 1, constant_values=False)
        return int(
            np.count_nonzero(p[1:] != p[:-1])
            + np.count_nonzero(p[:,1:] != p[:,:-1])
            + np.count_nonzero(p[:,:,1:] != p[:,:,:-1])
        )
    A = faces(hb if V_hb else nz)
    V = V_hb if V_hb else int(nz.sum())
    F = A / max(1.0, 6.0 * (max(V,1) ** (2/3)))
    aniso = float(np.std(areas) / (np.mean(areas) + 1e-9)) if V_hb else 0.0
    # axis constancy
    cx = float(np.mean(vol.max(2) == vol.min(2)))
    cy = float(np.mean(vol.max(1) == vol.min(1)))
    cz = float(np.mean(vol.max(0) == vol.min(0)))
    aconst = max(cx, cy, cz)
    if V_hb == 0 and mean < 128:
        typ = "language"
    elif F >= 3.5 and aniso < 0.12 and 0.35 <= (V_hb/(D**3)) <= 0.65:
        typ = "noise"
    elif aconst >= 0.8:
        typ = "planar"
    else:
        typ = "raster"
    return dict(
        type=typ, n=n, D=D, mean=mean, V_highbit=V_hb, foam=F,
        shadow_areas=areas, aniso=aniso, axis_const=aconst,
        sha256=hashlib.sha256(data).hexdigest()[:16],
    )


def match_cloud_eval(matches: List[MatchEvent], n_out: int) -> dict:
    if not matches:
        return dict(n_matches=0, mean_dist=0, mean_len=0, cover=0.0)
    dists = np.array([m.distance for m in matches], dtype=float)
    lens = np.array([m.length for m in matches], dtype=float)
    cover = float(lens.sum() / max(n_out, 1))
    # voxelize log-distance vs length vs pos-frac as a tiny 8^3 occupancy
    D = 8
    occ = np.zeros((D, D, D), dtype=bool)
    for m in matches:
        x = min(D-1, int(math.log2(max(m.distance,1)) / 15 * D))
        y = min(D-1, int((m.length - 3) / 255 * D))
        z = min(D-1, int(m.pos / max(n_out,1) * D))
        occ[z, y, x] = True
    sx, sy, sz = int(occ.any(2).sum()), int(occ.any(1).sum()), int(occ.any(0).sum())
    return dict(
        n_matches=len(matches),
        mean_dist=float(dists.mean()),
        median_dist=float(np.median(dists)),
        mean_len=float(lens.mean()),
        max_len=int(lens.max()),
        cover=cover,
        cloud_shadows=(sx, sy, sz),
        cloud_fill=float(occ.mean()),
    )


def process_blob(blob: bytes, name="input") -> dict:
    kind = sniff(blob)
    report = dict(name=name, sniff=kind, members=[], notes=[], geex=[])
    if kind == "zip":
        # stdlib is the real unzip; local walk is the documented process
        try:
            members = unzip_via_stdlib(blob)
        except Exception as e:
            report["notes"].append(f"zipfile failed: {e}")
            members = []
        walked = parse_zip_locals(blob)
        report["notes"].append(f"local-header walk saw {len(walked)} entries")
        for m in members:
            rec = dict(
                name=m.name, method=m.method_name, encrypted=m.encrypted,
                comp=m.comp_size, uncomp=m.uncomp_size, error=m.error,
                extracted=m.payload is not None,
            )
            if m.payload is not None:
                g = geex_lite(m.payload)
                rec["geex"] = g
                # token trace on the raw deflate slice if method 8
                if m.method == 8 and not m.encrypted:
                    sl = blob[m.data_off + 30 + len(m.name.encode("utf-8", "replace")):]
                    # better: use zipfile header_offset
                    try:
                        # locate compressed payload via local header
                        off = m.data_off
                        if blob[off:off+4] == PK_LOCAL:
                            nlen, elen = struct.unpack_from("<HH", blob, off+26)
                            payload = blob[off+30+nlen+elen:off+30+nlen+elen+m.comp_size]
                            raw, matches, st = inflate_trace(payload)
                            rec["inflate_trace"] = dict(stats=st, match=match_cloud_eval(matches, st["n_out"]),
                                                       matches_zlib=raw==m.payload)
                    except Exception as e:
                        rec["inflate_trace_error"] = str(e)
            report["members"].append(rec)
        return report
    if kind == "rar4":
        notes, members = walk_rar4(blob)
        report["notes"] = notes
        for m in members:
            rec = dict(name=m.name, method=m.method_name, encrypted=m.encrypted,
                       pack=m.pack_size, unp=m.unp_size, error=m.error,
                       extracted=m.payload is not None)
            if m.payload is not None:
                rec["geex"] = geex_lite(m.payload)
            report["members"].append(rec)
        return report
    if kind == "rar5":
        notes, members = walk_rar5(blob)
        report["notes"] = notes
        for m in members:
            rec = dict(name=m.name, method=m.method_name, encrypted=m.encrypted,
                       pack=m.pack_size, unp=m.unp_size, error=m.error,
                       extracted=m.payload is not None)
            if m.payload is not None:
                rec["geex"] = geex_lite(m.payload)
            report["members"].append(rec)
        return report
    if kind in ("7z", "lz4-frame"):
        report["notes"].append(f"{kind} sniffed; hand off to native tool; no geometric invert")
        return report
    # raw
    report["members"].append(dict(name=name, method="raw", extracted=True, geex=geex_lite(blob)))
    return report


if __name__ == "__main__":
    print("geex_unpack module loaded")
