"""Opt-in native LZ4 block experiments; bounded output, explicit local build."""
import ctypes as C
import platform
from functools import lru_cache
from pathlib import Path
MODES = {'scalar': 0, 'grow': 1, 'sse2': 2, 'asm': 3}

@lru_cache(maxsize=1)
def _library():
    lib = C.CDLL(str(Path(__file__).resolve().parents[1] / 'build/libnovelrar.so'))
    lib.nr_lz4.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t,
                          C.c_size_t, C.c_int, C.POINTER(C.c_size_t)]
    lib.nr_lz4.restype = C.c_int
    return lib

def decompress_block(data, max_output, prefix=b'', mode='grow'):
    if not 0 <= max_output <= 256 * 1024 * 1024:
        raise ValueError('max_output must be between 0 and 256 MiB')
    if mode not in MODES:
        raise ValueError('unknown native mode')
    if mode in ('sse2', 'asm') and platform.machine() not in ('x86_64', 'AMD64'):
        raise ValueError('requested instruction set requires x86-64')
    prefix = bytes(prefix[-65536:])
    out = C.create_string_buffer(max(1, len(prefix) + max_output))
    C.memmove(out, prefix, len(prefix))
    size = C.c_size_t()
    rc = _library().nr_lz4(bytes(data), len(data), out, len(prefix)+max_output,
                          len(prefix), MODES[mode], C.byref(size))
    if rc:
        raise ValueError('malformed LZ4 block or output limit exceeded')
    return out.raw[len(prefix):len(prefix)+size.value]
