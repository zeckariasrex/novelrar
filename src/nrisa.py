"""NRISA reference codec: affine reconstruction over Z/256Z.

Owned format (magic NRIS). Not a RAR/ZIP/LZ4/DEFLATE decoder.
"""
from __future__ import annotations

import hashlib
import struct

MAGIC = b'NRIS'
VERSION = 1
OP_EMIT, OP_COPY, OP_FILL, OP_AXPY = 0, 1, 2, 3
WINDOW = 65535
MIN_MATCH = 4
MAX_SPAN = 65535
DEFAULT_LIMIT = 64 << 20


def _le16(buf, i):
    return buf[i] | (buf[i + 1] << 8)


def _le32(buf, i):
    return buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16) | (buf[i + 3] << 24)


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def decode(blob: bytes, max_output: int = DEFAULT_LIMIT) -> bytes:
    if not 0 <= max_output <= 256 << 20:
        raise ValueError('output limit must be in [0, 256 MiB]')
    if len(blob) < 14 or blob[:4] != MAGIC:
        raise ValueError('bad NRISA magic')
    ver, flags = blob[4], blob[5]
    usize, ncmd = _le32(blob, 6), _le32(blob, 10)
    if ver != VERSION or usize > max_output:
        raise ValueError('unsupported version or output limit')
    i = 14
    out = bytearray()
    for _ in range(ncmd):
        if i >= len(blob):
            raise ValueError('truncated command')
        op = blob[i]
        i += 1
        if op == OP_EMIT:
            if i + 2 > len(blob):
                raise ValueError('truncated emit')
            n = _le16(blob, i)
            i += 2
            if n > max_output - len(out) or i + n > len(blob):
                raise ValueError('emit overflow')
            out.extend(blob[i:i + n])
            i += n
            continue
        if op == OP_COPY:
            if i + 4 > len(blob):
                raise ValueError('truncated copy')
            n, dist = _le16(blob, i), _le16(blob, i + 2)
            i += 4
            if n == 0 or dist == 0 or dist > len(out) or n > max_output - len(out):
                raise ValueError('invalid copy')
            for _k in range(n):
                out.append(out[-dist])
            continue
        if op == OP_FILL:
            if i + 3 > len(blob):
                raise ValueError('truncated fill')
            n = _le16(blob, i)
            v = blob[i + 2]
            i += 3
            if n == 0 or n > max_output - len(out):
                raise ValueError('invalid fill')
            out.extend(bytes([v]) * n)
            continue
        if op == OP_AXPY:
            if i + 6 > len(blob):
                raise ValueError('truncated axpy')
            n, dist = _le16(blob, i), _le16(blob, i + 2)
            a, b = blob[i + 4], blob[i + 5]
            i += 6
            if (n == 0 or dist == 0 or dist > len(out) or n > dist
                    or n > max_output - len(out)):
                raise ValueError('invalid axpy')
            if a == 0:
                out.extend(bytes([b]) * n)
            elif a == 1:
                for _k in range(n):
                    out.append((out[-dist] + b) & 255)
            elif a == 255:
                for _k in range(n):
                    out.append((b - out[-dist]) & 255)
            else:
                for _k in range(n):
                    out.append((a * out[-dist] + b) & 255)
            continue
        raise ValueError('unknown NRISA opcode')
    if flags & 1:
        if i + 32 > len(blob):
            raise ValueError('truncated digest')
        if hashlib.sha256(out).digest() != blob[i:i + 32]:
            raise ValueError('NRISA checksum mismatch')
        i += 32
    if i != len(blob):
        raise ValueError('trailing NRISA bytes')
    if len(out) != usize:
        raise ValueError('NRISA size mismatch')
    return bytes(out)


def _fit_axpy(src: bytes, dst: bytes):
    n = len(src)
    if n == 0:
        return None
    for a in (0, 1, 255, 2, 3, 5, 254):
        b = (dst[0] - a * src[0]) & 255
        if all(((a * src[k] + b) & 255) == dst[k] for k in range(n)):
            if a == 0 or (a == 1 and b == 0):
                continue
            return a, b
    for i in range(min(n, 8)):
        for j in range(i + 1, min(n, i + 16)):
            ds = (src[i] - src[j]) & 255
            dd = (dst[i] - dst[j]) & 255
            if ds == 0:
                if dd != 0:
                    return None
                continue
            g = _gcd(ds, 256)
            if dd % g:
                continue
            for a in range(256):
                if (a * ds) & 255 != dd:
                    continue
                b = (dst[i] - a * src[i]) & 255
                if all(((a * src[k] + b) & 255) == dst[k] for k in range(n)):
                    if a == 0 or (a == 1 and b == 0):
                        return None
                    return a, b
            return None
    return None


def _distances(i: int):
    start = max(0, i - WINDOW)
    span = i - start
    dists = list(range(1, min(65, span + 1)))
    step = 64
    while step <= span:
        dists.append(step)
        step *= 2
    for extra in (3, 5, 7, 9, 11, 13, 15, 17, 24, 48, 96, 128, 256, 512):
        if 1 <= extra <= span:
            dists.append(extra)
    seen = set()
    out = []
    for d in dists:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def encode(data: bytes) -> bytes:
    data = bytes(data)
    n = len(data)
    cmds = bytearray()
    ncmd = 0
    i = 0
    lit = 0

    def flush(end):
        nonlocal ncmd
        chunk = data[lit:end]
        while chunk:
            part = chunk[:MAX_SPAN]
            cmds.append(OP_EMIT)
            cmds.extend(struct.pack('<H', len(part)))
            cmds.extend(part)
            ncmd += 1
            chunk = chunk[len(part):]

    while i < n:
        best = None
        run = 1
        while i + run < n and data[i + run] == data[i] and run < MAX_SPAN:
            run += 1
        if run >= 3:
            best = (run - 4, 'fill', (run, data[i]), run)
        for d in _distances(i):
            cl = 0
            while i + cl < n and data[i - d + cl] == data[i + cl] and cl < MAX_SPAN:
                cl += 1
            if cl >= MIN_MATCH:
                saved = cl - 5
                if best is None or saved > best[0]:
                    best = (saved, 'copy', (cl, d), cl)
            ax_max = min(MAX_SPAN, n - i, d)
            if ax_max >= MIN_MATCH:
                fit = _fit_axpy(data[i - d:i - d + MIN_MATCH], data[i:i + MIN_MATCH])
                if fit:
                    a, b = fit
                    al = MIN_MATCH
                    while al < ax_max and ((a * data[i - d + al] + b) & 255) == data[i + al]:
                        al += 1
                    saved = al - 7
                    if best is None or saved > best[0]:
                        best = (saved, 'axpy', (al, d, a, b), al)
        if best and best[0] > 0:
            flush(i)
            kind = best[1]
            if kind == 'fill':
                length, value = best[2]
                cmds.append(OP_FILL)
                cmds.extend(struct.pack('<HB', length, value))
            elif kind == 'copy':
                length, dist = best[2]
                cmds.append(OP_COPY)
                cmds.extend(struct.pack('<HH', length, dist))
            else:
                length, dist, a, b = best[2]
                cmds.append(OP_AXPY)
                cmds.extend(struct.pack('<HHBB', length, dist, a, b))
            ncmd += 1
            i += best[3]
            lit = i
        else:
            i += 1
    flush(n)
    header = MAGIC + struct.pack('<BBII', VERSION, 1, n, ncmd)
    return bytes(header + cmds + hashlib.sha256(data).digest())


def decompress_native(blob: bytes, max_output: int = DEFAULT_LIMIT, mode: str = 'grow') -> bytes:
    """Opt-in C executor. There is no silent fallback: a missing or stale
    ``build/libnovelrar.so`` raises instead of quietly decoding in Python.

    The C core validates structure only. The plaintext digest is checked here
    so that the native and pure-Python paths accept exactly the same streams.
    """
    import ctypes as C
    import platform
    from native_lz4 import MODES, _library
    if mode not in MODES:
        raise ValueError('unknown native mode')
    if mode in ('sse2', 'asm') and platform.machine() not in ('x86_64', 'AMD64'):
        raise ValueError('requested instruction set requires x86-64')
    if not 0 <= max_output <= 256 << 20:
        raise ValueError('output limit must be in [0, 256 MiB]')
    if len(blob) < 14 or blob[:4] != MAGIC:
        raise ValueError('bad NRISA magic')
    # Trust the header only as an allocation hint; the executor still refuses
    # to write past the capacity it is handed.
    usize = _le32(blob, 6)
    if usize > max_output:
        raise ValueError('unsupported version or output limit')
    lib = _library()
    try:
        fn = lib.nr_isa
    except AttributeError as exc:
        raise OSError('build/libnovelrar.so has no nr_isa; rebuild it with '
                      'scripts/build_native.py') from exc
    fn.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t,
                   C.c_int, C.POINTER(C.c_size_t)]
    fn.restype = C.c_int
    out = C.create_string_buffer(max(1, usize))
    written = C.c_size_t()
    rc = fn(blob, len(blob), out, usize, MODES[mode], C.byref(written))
    if rc:
        raise ValueError('malformed NRISA stream or output limit exceeded')
    result = out.raw[:written.value]
    if blob[5] & 1:
        if hashlib.sha256(result).digest() != blob[-32:]:
            raise ValueError('NRISA checksum mismatch')
    return result
