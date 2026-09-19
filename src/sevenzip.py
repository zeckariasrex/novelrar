#!/usr/bin/env python3
"""7z container reader — clean-room header parser over public-domain codecs.

Provenance
----------
There was never a proprietary decompressor to reimplement here. The two
pieces are licensed apart, and both are permissive:

  * The **container layout** is described in ``DOC/7zFormat.txt``, shipped
    with the 7-Zip distribution and placed in the **public domain** by Igor
    Pavlov along with the rest of the LZMA SDK. This module is a fresh
    parser written against that document — lane ``CLEANROOM``.
  * The **codecs** (LZMA1, LZMA2, BCJ/Delta branch filters, Deflate, BZip2)
    are all reachable from the Python standard library: ``lzma`` wraps
    liblzma, whose LZMA/branch-filter core descends from the public-domain
    LZMA SDK; ``zlib`` and ``bz2`` are likewise permissive — lane ``STDLIB``.

So a non-encrypted 7z archive needs no licensed source at all. What 7-Zip's
own LGPL carries an extra restriction for is its bundled *RAR* decoder, and
that is a different format, handled separately (see ``rar_reader.py``).

AES-256 archives are identified and refused. No password is derived, tried,
or accepted.
"""
from __future__ import annotations

import bz2
import lzma
import struct
import zlib
from dataclasses import dataclass, field
from typing import Optional

SIGNATURE = b"7z\xbc\xaf\x27\x1c"

# Property ids, 7zFormat.txt
kEnd, kHeader, kArchiveProperties, kAdditionalStreams = 0x00, 0x01, 0x02, 0x03
kMainStreamsInfo, kFilesInfo, kPackInfo, kUnpackInfo = 0x04, 0x05, 0x06, 0x07
kSubStreamsInfo, kSize, kCRC, kFolder = 0x08, 0x09, 0x0A, 0x0B
kCodersUnpackSize, kNumUnpackStream = 0x0C, 0x0D
kEmptyStream, kEmptyFile, kAnti, kName = 0x0E, 0x0F, 0x10, 0x11
kCTime, kATime, kMTime, kAttributes = 0x12, 0x13, 0x14, 0x15
kEncodedHeader, kStartPos, kDummy = 0x17, 0x18, 0x19

COPY = b"\x00"
DELTA = b"\x03"
LZMA1 = b"\x03\x01\x01"
LZMA2 = b"\x21"
BCJ2 = b"\x03\x03\x01\x1b"
DEFLATE = b"\x04\x01\x08"
BZIP2 = b"\x04\x02\x02"
AES256 = b"\x06\xf1\x07\x01"

# Branch filters: 7z short id and legacy id -> liblzma filter constant
BRANCH = {
    b"\x04": lzma.FILTER_X86,
    b"\x03\x03\x01\x03": lzma.FILTER_X86,
    b"\x05": lzma.FILTER_POWERPC,
    b"\x03\x03\x02\x05": lzma.FILTER_POWERPC,
    b"\x06": lzma.FILTER_IA64,
    b"\x03\x03\x04\x01": lzma.FILTER_IA64,
    b"\x07": lzma.FILTER_ARM,
    b"\x03\x03\x05\x01": lzma.FILTER_ARM,
    b"\x08": lzma.FILTER_ARMTHUMB,
    b"\x03\x03\x07\x01": lzma.FILTER_ARMTHUMB,
    b"\x09": lzma.FILTER_SPARC,
    b"\x03\x03\x08\x05": lzma.FILTER_SPARC,
}

CODEC_NAMES = {
    COPY: "copy", DELTA: "delta", LZMA1: "lzma1", LZMA2: "lzma2",
    BCJ2: "bcj2", DEFLATE: "deflate", BZIP2: "bzip2", AES256: "aes256-sha256",
    b"\x04": "bcj-x86", b"\x03\x03\x01\x03": "bcj-x86",
    b"\x05": "bcj-ppc", b"\x06": "bcj-ia64", b"\x07": "bcj-arm",
    b"\x08": "bcj-armt", b"\x09": "bcj-sparc", b"\x0a": "bcj-arm64",
    b"\x04\xf7\x11\x01": "zstd", b"\x04\x01\x09": "deflate64",
    b"\x03\x04\x01": "ppmd", b"\x0a": "bcj-arm64", b"\x0b": "bcj-riscv",
    b"\x04\xf7\x11\x02": "brotli", b"\x04\x01\x0a": "deflate64",
}


class SevenZError(ValueError):
    """Malformed 7z container."""


class SevenZRefused(SevenZError):
    """A lawful decode path does not exist (encryption, or an alien codec)."""


# ---------------------------------------------------------------------------
# Primitive readers
# ---------------------------------------------------------------------------

class Reader:
    def __init__(self, buf: bytes, i: int = 0):
        self.b = buf
        self.i = i

    def byte(self) -> int:
        if self.i >= len(self.b):
            raise SevenZError("header truncated")
        v = self.b[self.i]
        self.i += 1
        return v

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise SevenZError("header truncated")
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def number(self) -> int:
        """7zFormat.txt REAL_UINT64 / NUMBER: leading-ones length prefix."""
        first = self.byte()
        mask = 0x80
        value = 0
        for k in range(8):
            if not (first & mask):
                return value | ((first & (mask - 1)) << (8 * k))
            value |= self.byte() << (8 * k)
            mask >>= 1
        return value

    def bits(self, n: int) -> list[bool]:
        out, cur, mask = [], 0, 0
        for _ in range(n):
            if mask == 0:
                cur, mask = self.byte(), 0x80
            out.append(bool(cur & mask))
            mask >>= 1
        return out

    def bool_vector(self, n: int) -> list[bool]:
        return [True] * n if self.byte() else self.bits(n)


# ---------------------------------------------------------------------------
# Folder / coder graph
# ---------------------------------------------------------------------------

@dataclass
class Coder:
    method: bytes
    n_in: int
    n_out: int
    props: bytes = b""

    @property
    def name(self) -> str:
        return CODEC_NAMES.get(self.method, "id:" + self.method.hex())


@dataclass
class Folder:
    coders: list = field(default_factory=list)
    bind_pairs: list = field(default_factory=list)   # (in_index, out_index)
    packed_indices: list = field(default_factory=list)
    unpack_sizes: list = field(default_factory=list)
    crc: Optional[int] = None
    num_unpack_substreams: int = 1

    @property
    def total_in(self) -> int:
        return sum(c.n_in for c in self.coders)

    @property
    def total_out(self) -> int:
        return sum(c.n_out for c in self.coders)

    def main_out(self) -> int:
        bound = {o for _, o in self.bind_pairs}
        for j in range(self.total_out):
            if j not in bound:
                return j
        raise SevenZError("folder has no unbound output stream")

    @property
    def size(self) -> int:
        return self.unpack_sizes[self.main_out()]

    def chain(self) -> str:
        return " -> ".join(c.name for c in self.coders)

    def encrypted(self) -> bool:
        return any(c.method == AES256 for c in self.coders)


def _read_folder(r: Reader) -> Folder:
    f = Folder()
    for _ in range(r.number()):
        flags = r.byte()
        idsize = flags & 0x0F
        method = r.take(idsize)
        n_in = n_out = 1
        if flags & 0x10:                      # complex coder
            n_in, n_out = r.number(), r.number()
        props = b""
        if flags & 0x20:                      # attributes present
            props = r.take(r.number())
        if flags & 0x80:
            raise SevenZError("alternative coder methods are not defined")
        f.coders.append(Coder(method, n_in, n_out, props))
    for _ in range(f.total_out - 1):
        f.bind_pairs.append((r.number(), r.number()))
    n_packed = f.total_in - len(f.bind_pairs)
    if n_packed == 1:
        bound_in = {i for i, _ in f.bind_pairs}
        f.packed_indices = [next(j for j in range(f.total_in) if j not in bound_in)]
    else:
        f.packed_indices = [r.number() for _ in range(n_packed)]
    return f


# ---------------------------------------------------------------------------
# StreamsInfo
# ---------------------------------------------------------------------------

@dataclass
class StreamsInfo:
    pack_pos: int = 0
    pack_sizes: list = field(default_factory=list)
    folders: list = field(default_factory=list)
    substream_sizes: list = field(default_factory=list)   # per folder
    substream_crcs: list = field(default_factory=list)    # per folder


def _read_digests(r: Reader, n: int) -> list:
    defined = r.bool_vector(n)
    return [r.u32() if d else None for d in defined]


def _read_streams_info(r: Reader) -> StreamsInfo:
    si = StreamsInfo()
    while True:
        pid = r.number()
        if pid == kEnd:
            return si
        if pid == kPackInfo:
            si.pack_pos = r.number()
            n = r.number()
            while True:
                p = r.number()
                if p == kEnd:
                    break
                if p == kSize:
                    si.pack_sizes = [r.number() for _ in range(n)]
                elif p == kCRC:
                    _read_digests(r, n)
                else:
                    raise SevenZError(f"unexpected id {p:#x} in PackInfo")
        elif pid == kUnpackInfo:
            while True:
                p = r.number()
                if p == kEnd:
                    break
                if p == kFolder:
                    nf = r.number()
                    if r.byte():
                        raise SevenZRefused("folders held in an external stream")
                    si.folders = [_read_folder(r) for _ in range(nf)]
                elif p == kCodersUnpackSize:
                    for f in si.folders:
                        f.unpack_sizes = [r.number() for _ in range(f.total_out)]
                elif p == kCRC:
                    for f, c in zip(si.folders, _read_digests(r, len(si.folders))):
                        f.crc = c
                else:
                    raise SevenZError(f"unexpected id {p:#x} in UnpackInfo")
        elif pid == kSubStreamsInfo:
            _read_substreams(r, si)
        else:
            raise SevenZError(f"unexpected id {pid:#x} in StreamsInfo")


def _read_substreams(r: Reader, si: StreamsInfo) -> None:
    counts = [1] * len(si.folders)
    pid = r.number()
    if pid == kNumUnpackStream:
        counts = [r.number() for _ in si.folders]
        pid = r.number()
    for f, c in zip(si.folders, counts):
        f.num_unpack_substreams = c
    # sizes: every substream but the last of each folder is listed
    sizes = []
    for f, c in zip(si.folders, counts):
        if c == 0:
            sizes.append([])
            continue
        got, acc = [], 0
        for _ in range(c - 1):
            v = r.number() if pid == kSize else 0
            got.append(v)
            acc += v
        got.append(f.size - acc)
        sizes.append(got)
    si.substream_sizes = sizes
    if pid == kSize:
        pid = r.number()
    # digests are supplied only for substreams whose CRC is not already known
    n_unknown = sum(c for f, c in zip(si.folders, counts)
                    if not (c == 1 and f.crc is not None))
    crcs = [[None] * c for c in counts]
    while pid != kEnd:
        if pid == kCRC:
            got = _read_digests(r, n_unknown)
            it = iter(got)
            for fi, (f, c) in enumerate(zip(si.folders, counts)):
                if c == 1 and f.crc is not None:
                    crcs[fi][0] = f.crc
                else:
                    for k in range(c):
                        crcs[fi][k] = next(it)
        else:
            r.take(r.number())  # skip an unknown property
        pid = r.number()
    si.substream_crcs = crcs


# ---------------------------------------------------------------------------
# Coder execution
# ---------------------------------------------------------------------------

def _lzma1(data: bytes, props: bytes, out_size: int) -> bytes:
    if len(props) < 5:
        raise SevenZError("LZMA1 needs 5 property bytes")
    d = props[0]
    lc, rem = d % 9, d // 9
    lp, pb = rem % 5, rem // 5
    dict_size = struct.unpack("<I", props[1:5])[0]
    if dict_size > 64 << 20: raise SevenZError("LZMA dictionary exceeds 64 MiB")
    flt = [{"id": lzma.FILTER_LZMA1, "dict_size": max(dict_size, 4096),
            "lc": lc, "lp": lp, "pb": pb}]
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=flt)
    return dec.decompress(data, max_length=out_size+1)


def _lzma2(data: bytes, props: bytes, out_size: int) -> bytes:
    if not props:
        raise SevenZError("LZMA2 needs 1 property byte")
    p = props[0]
    if p > 40:
        raise SevenZError(f"bad LZMA2 dict size code {p}")
    dict_size = 0xFFFFFFFF if p == 40 else (2 | (p & 1)) << (p // 2 + 11)
    if dict_size > 64 << 20: raise SevenZError("LZMA dictionary exceeds 64 MiB")
    flt = [{"id": lzma.FILTER_LZMA2, "dict_size": max(dict_size, 4096)}]
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=flt)
    return dec.decompress(data, max_length=out_size+1)


def _branch_unfilter(data: bytes, filt: int, props: bytes) -> bytes:
    """Run a liblzma branch filter in the decode direction, standalone.

    liblzma exposes branch filters only as part of a raw chain that ends in a
    compressor, so we wrap the payload in a throwaway LZMA2 layer and let
    liblzma unfilter it on the way back out. The filter itself is still
    liblzma's public-domain implementation — we never reimplement it.
    """
    spec = {"id": filt}
    if props:
        spec["start_offset"] = struct.unpack("<I", props[:4].ljust(4, b"\0"))[0]
    comp = lzma.LZMACompressor(format=lzma.FORMAT_RAW,
                               filters=[{"id": lzma.FILTER_LZMA2, "preset": 0}])
    wrapped = comp.compress(data) + comp.flush()
    dec = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=[spec, {"id": lzma.FILTER_LZMA2, "preset": 0}])
    return dec.decompress(wrapped)


def _delta_unfilter(data: bytes, props: bytes) -> bytes:
    dist = (props[0] if props else 0) + 1
    out = bytearray(data)
    for i in range(dist, len(out)):
        out[i] = (out[i] + out[i - dist]) & 0xFF
    return bytes(out)


def _bcj2(ins: list, out_size: int) -> bytes:
    """BCJ2 is not implemented, and saying so beats guessing.

    BCJ2 splits x86 branch targets across four streams (main / call / jump /
    a range-coded control stream). It is public-domain and perfectly legal to
    implement; it is simply not implemented here, because nothing available
    in this tree can *write* a BCJ2 archive, so an implementation could not
    be tested against a known-good oracle. Untested decode code that claims
    clean-room provenance is worse than a clear refusal.

    7-Zip only emits BCJ2 for executables at -mx9-class settings, so this is
    rare in practice. Route such an archive through the HOST lane.
    """
    raise SevenZRefused(
        "BCJ2 (coder 0303011B) is not implemented in-tree; hand the archive "
        "to an operator-installed 7z via the HOST lane")


def run_coder(coder: Coder, inputs: list, out_size: int) -> bytes:
    m = coder.method
    if m == COPY:
        return inputs[0][:out_size]
    if m == LZMA1:
        return _lzma1(inputs[0], coder.props, out_size)
    if m == LZMA2:
        return _lzma2(inputs[0], coder.props, out_size)
    if m == DELTA:
        return _delta_unfilter(inputs[0], coder.props)[:out_size]
    if m in BRANCH:
        return _branch_unfilter(inputs[0], BRANCH[m], coder.props)[:out_size]
    if m == DEFLATE:
        return zlib.decompressobj(-15).decompress(inputs[0], out_size+1)
    if m == BZIP2:
        return bz2.BZ2Decompressor().decompress(inputs[0], out_size+1)
    if m == BCJ2:
        return _bcj2(inputs, out_size)
    if m == AES256:
        raise SevenZRefused("AES-256 coder; refuse (no password handling)")
    raise SevenZRefused(f"no lawful in-tree path for coder {coder.name}")


def decode_folder(folder: Folder, packed: list) -> bytes:
    """Resolve the coder graph and return the folder's main output stream."""
    if any(size > 64 << 20 for size in folder.unpack_sizes):
        raise SevenZError("folder exceeds 64 MiB output limit")
    if folder.encrypted():
        raise SevenZRefused("folder is AES-256 encrypted; refuse")
    # map global in/out stream indices to (coder, local index)
    in_of, out_of = [], []
    for ci, c in enumerate(folder.coders):
        in_of += [(ci, k) for k in range(c.n_in)]
        out_of += [(ci, k) for k in range(c.n_out)]
    bind = {i: o for i, o in folder.bind_pairs}
    packed_for = {gi: packed[k] for k, gi in enumerate(folder.packed_indices)}
    produced: dict[int, bytes] = {}
    depth = 0

    def out_stream(gout: int) -> bytes:
        nonlocal depth
        if gout in produced:
            return produced[gout]
        depth += 1
        if depth > 64:
            raise SevenZError("coder graph too deep / cyclic")
        ci, _ = out_of[gout]
        coder = folder.coders[ci]
        first_in = sum(c.n_in for c in folder.coders[:ci])
        args = []
        for k in range(coder.n_in):
            gi = first_in + k
            if gi in packed_for:
                args.append(packed_for[gi])
            elif gi in bind:
                args.append(out_stream(bind[gi]))
            else:
                raise SevenZError(f"input stream {gi} is unbound")
        data = run_coder(coder, args, folder.unpack_sizes[gout])
        if len(data) != folder.unpack_sizes[gout]:
            raise SevenZError("coder output size mismatch")
        produced[gout] = data
        depth -= 1
        return data

    raw = out_stream(folder.main_out())
    if folder.crc is not None and zlib.crc32(raw) & 0xffffffff != folder.crc:
        raise SevenZError("folder CRC mismatch")
    return raw


# ---------------------------------------------------------------------------
# Archive
# ---------------------------------------------------------------------------

@dataclass
class SevenZEntry:
    name: str
    size: int = 0
    crc: Optional[int] = None
    is_dir: bool = False
    empty: bool = False
    folder_index: Optional[int] = None
    coders: str = ""
    payload: Optional[bytes] = None
    error: Optional[str] = None


def _read_files_info(r: Reader, si: StreamsInfo) -> list:
    n = r.number()
    empty_stream = [False] * n
    empty_file: list = []
    names: list = []
    attrs: list = []
    while True:
        pid = r.number()
        if pid == kEnd:
            break
        size = r.number()
        stop = r.i + size
        if pid == kEmptyStream:
            empty_stream = r.bits(n)
        elif pid == kEmptyFile:
            empty_file = r.bits(sum(empty_stream))
        elif pid == kName:
            if r.byte():
                raise SevenZRefused("file names held in an external stream")
            raw = r.take(stop - r.i)
            names = raw.decode("utf-16-le", "replace").split("\x00")[:-1]
        elif pid == kAttributes:
            defined = r.bool_vector(n)
            if not r.byte():
                attrs = [r.u32() if d else 0 for d in defined]
        r.i = stop
    out = []
    ei = 0
    for k in range(n):
        name = names[k] if k < len(names) else f"<unnamed {k}>"
        if empty_stream[k]:
            is_file = empty_file[ei] if ei < len(empty_file) else False
            ei += 1
            out.append(SevenZEntry(name=name, size=0, is_dir=not is_file, empty=True))
        else:
            out.append(SevenZEntry(name=name))
    return out


@dataclass
class SevenZArchive:
    entries: list = field(default_factory=list)
    folders: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    encrypted_header: bool = False
    version: tuple = (0, 0)


def _parse_header(r: Reader, blob: bytes, arch: SevenZArchive) -> None:
    pid = r.number()
    if pid == kArchiveProperties:
        while True:
            p = r.number()
            if p == kEnd:
                break
            r.take(r.number())
        pid = r.number()
    if pid == kAdditionalStreams:
        _read_streams_info(r)
        pid = r.number()
    si = StreamsInfo()
    if pid == kMainStreamsInfo:
        si = _read_streams_info(r)
        pid = r.number()
    if sum(f.size for f in si.folders) > 64 << 20:
        raise SevenZError("archive exceeds 64 MiB output limit")
    arch.folders = si.folders
    for f in si.folders:
        arch.notes.append(f"folder: {f.chain()} -> {f.size} bytes")
    entries = _read_files_info(r, si) if pid == kFilesInfo else []

    # Attach payloads folder by folder.
    base = 32 + si.pack_pos
    pack_at, offs = [], base
    for s in si.pack_sizes:
        pack_at.append((offs, s))
        offs += s
    streamed = [e for e in entries if not e.empty]
    ei = 0
    pi = 0
    for fi, folder in enumerate(si.folders):
        chunks = []
        for gi in range(len(folder.packed_indices)):
            o, s = pack_at[pi]
            chunks.append(blob[o:o + s])
            pi += 1
        sizes = si.substream_sizes[fi] if si.substream_sizes else [folder.size]
        crcs = si.substream_crcs[fi] if si.substream_crcs else [folder.crc]
        try:
            data = decode_folder(folder, chunks)
        except (SevenZError, lzma.LZMAError, OSError, EOFError) as e:
            for _ in sizes:
                if ei < len(streamed):
                    streamed[ei].error = f"{type(e).__name__}: {e}"
                    streamed[ei].folder_index = fi
                    streamed[ei].coders = folder.chain()
                    ei += 1
            continue
        off = 0
        for k, sz in enumerate(sizes):
            if ei >= len(streamed):
                break
            e = streamed[ei]
            e.folder_index = fi
            e.coders = folder.chain()
            e.size = sz
            e.payload = data[off:off + sz]
            want = crcs[k] if k < len(crcs) else None
            e.crc = want
            if want is not None and (zlib.crc32(e.payload) & 0xFFFFFFFF) != want:
                e.error = "CRC32 mismatch"
                e.payload = None
            off += sz
            ei += 1
    arch.entries = entries


def read(blob: bytes) -> SevenZArchive:
    """Parse a 7z container and decode every member we have a lawful path for."""
    arch = SevenZArchive()
    if not blob.startswith(SIGNATURE):
        raise SevenZError("not a 7z signature header")
    if len(blob) < 32:
        raise SevenZError("truncated signature header")
    arch.version = (blob[6], blob[7])
    start_crc = struct.unpack_from("<I", blob, 8)[0]
    if (zlib.crc32(blob[12:32]) & 0xFFFFFFFF) != start_crc:
        raise SevenZError("start-header CRC mismatch")
    nh_off, nh_size, nh_crc = struct.unpack_from("<QQI", blob, 12)
    if nh_size == 0:
        arch.notes.append("empty archive")
        return arch
    lo = 32 + nh_off
    hdr = blob[lo:lo + nh_size]
    if len(hdr) != nh_size:
        raise SevenZError("next header runs past end of file")
    if (zlib.crc32(hdr) & 0xFFFFFFFF) != nh_crc:
        raise SevenZError("next-header CRC mismatch")

    r = Reader(hdr)
    pid = r.number()
    if pid == kEncodedHeader:
        si = _read_streams_info(r)
        if not si.folders:
            raise SevenZError("encoded header declares no folder")
        folder = si.folders[0]
        if folder.encrypted():
            arch.encrypted_header = True
            arch.notes.append(
                "header is AES-256 encrypted (coder 06f10701); refuse. "
                "Names and sizes are unreadable without the password.")
            return arch
        base = 32 + si.pack_pos
        chunks, off = [], base
        for s in si.pack_sizes:
            chunks.append(blob[off:off + s])
            off += s
        arch.notes.append(f"encoded header via {folder.chain()}")
        hdr = decode_folder(folder, chunks)
        r = Reader(hdr)
        pid = r.number()
    if pid != kHeader:
        raise SevenZError(f"expected kHeader, saw {pid:#x}")
    _parse_header(r, blob, arch)
    return arch


def is_7z(blob: bytes) -> bool:
    return blob.startswith(SIGNATURE)
