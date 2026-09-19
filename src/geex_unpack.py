#!/usr/bin/env python3
"""GEEX-UNPACK: geometric eval/extract *after* a real unarchive pipeline.

Container handling now lives in :mod:`unarchive`, brokered by licence lane
(see :mod:`license_broker`). This module keeps the two things that are its
own job:

  * ``inflate_trace`` — an independent RFC 1951 inflater that reports the
    (position, distance, length) match cloud. It exists to *observe* what a
    DEFLATE stream is doing, not to replace zlib, and it is checked
    byte-for-byte against zlib on every run.
  * ``geex_lite`` — the cube/shadow/foam scoring, run on *decoded* member
    bytes rather than on container bytes.

Does not invert AES, ZipCrypto, RAR header crypt, or RAR's proprietary LZ.
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

import license_broker as LB
import unarchive
from unarchive import Member, sniff

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
# GEEX on decoded members
# ---------------------------------------------------------------------------

def geex_lite(data: bytes, cap=4096) -> dict:
    """Small eval on decoded bytes (cube shadows / foam / language gate)."""
    block = data[:cap]
    n = len(block)
    if n == 0:
        return dict(type="empty", n=0)
    D = int(round(n ** (1 / 3)))
    while D ** 3 < n:
        D += 1
    D = max(D, 1)
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


def process_blob(blob: bytes, name="input", policy=None, trace=True) -> dict:
    """Unarchive through the licence broker, then score each decoded member.

    The report carries a receipt per stream, so a caller can audit *how* the
    bytes were obtained as well as what they look like geometrically.
    """
    arch = unarchive.open_archive(blob, name, policy)
    report = dict(name=name, sniff=arch.container, notes=list(arch.notes),
                  members=[], receipts=[], audit=None)
    for m in arch.members:
        rec = dict(name=m.name, codec=m.codec, is_dir=m.is_dir,
                   size=m.size, error=m.error,
                   extracted=m.payload is not None)
        if m.receipt is not None:
            rec["lane"] = m.receipt.lane
            rec["licence"] = m.receipt.licence
            rec["verified"] = m.receipt.verified
            if m.receipt.tool:
                rec["tool"] = m.receipt.tool
        if m.payload:
            rec["geex"] = geex_lite(m.payload)
        report["members"].append(rec)

    if trace and arch.container == "zip":
        report["inflate_trace"] = _trace_zip_members(blob)

    report["receipts"] = [asdict(r) for r in arch.receipts]
    res = arch.audit(policy)
    report["audit"] = dict(policy=res.policy, clean=res.clean,
                           extracted=res.extracted, total=res.total,
                           by_lane=res.by_lane, violations=res.violations)
    return report


def _trace_zip_members(blob: bytes) -> dict:
    """Run the in-tree inflater beside zlib on every DEFLATE member.

    Any disagreement is a bug in *our* inflater, so it is reported rather
    than swallowed.
    """
    out = {}
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    for info in zf.infolist():
        if info.compress_type != 8 or info.flag_bits & 0x41:
            continue
        off = info.header_offset
        if blob[off:off + 4] != b"PK\x03\x04":
            continue
        try:
            nlen, elen = struct.unpack_from("<HH", blob, off + 26)
            start = off + 30 + nlen + elen
            payload = blob[start:start + info.compress_size]
            raw, matches, st = inflate_trace(payload)
            out[info.filename] = dict(
                stats=st, agrees_with_zlib=raw == zf.read(info),
                match=match_cloud_eval(matches, st["n_out"]))
        except Exception as e:
            out[info.filename] = {"error": f"{type(e).__name__}: {e}"}
    return out


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(__doc__)
        print(LB.capability_table())
    else:
        import json
        for path in sys.argv[1:]:
            data = Path(path).read_bytes()
            print(json.dumps(process_blob(data, Path(path).name),
                             indent=2, default=str))
