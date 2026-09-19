#!/usr/bin/env python3
"""64 KiB and 1 MiB corpora; native DEFLATE parse vs Python IR vs zlib.
Attempts perf-stat hardware counters when available. Not a universal claim.
"""
import json
import platform
import random
import resource
import statistics
import subprocess
import sys
import time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import deflate_ir
import zlib

try:
    import lz4.block as lz4_block
    import lz4_frame
    import native_lz4
    HAS_LZ4 = True
except Exception:
    HAS_LZ4 = False


def measure(fn, expected, iterations):
    assert fn() == expected
    samples = []
    for _ in range(5):
        start = time.perf_counter_ns()
        for _ in range(iterations):
            assert fn() == expected
        samples.append((time.perf_counter_ns() - start) / iterations / 1e9)
    seconds = statistics.median(samples)
    return {'seconds': seconds, 'MiB_per_second': len(expected) / (1 << 20) / seconds}


def corpus(size, kind, rng):
    if kind == 'repeat1':
        return b'A' * size
    if kind == 'period3':
        return (b'abc' * (size // 3 + 3))[:size]
    if kind == 'text':
        phrase = b'Independent machine-level archive research. '
        return (phrase * (size // len(phrase) + 1))[:size]
    if kind == 'ramp':
        return (bytes(range(256)) * (size // 256 + 1))[:size]
    return rng.randbytes(size)


def main():
    rng = random.Random(912)
    result = {
        'environment': {
            'platform': platform.platform(),
            'python': sys.version,
            'compiler': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
        },
        'methodology': (
            '5 samples, median; 64KiB: 20 decodes (DEFLATE parse 8); '
            '1MiB: 4 decodes. Tight max_output=len(data). Includes FFI. '
            'perf-stat attempted once per process.'
        ),
        'deflate': {},
        'lz4': {},
        'perf_stat': {'available': False},
    }
    try:
        proc = subprocess.run(
            ['perf', 'stat', '-x,', '-e', 'cycles,instructions', sys.executable, '-c', 'pass'],
            capture_output=True, text=True, timeout=30)
        result['perf_stat'] = {'available': proc.returncode == 0, 'stderr': (proc.stderr or '')[:500]}
    except (OSError, subprocess.SubprocessError) as exc:
        result['perf_stat'] = {'available': False, 'reason': type(exc).__name__}
    for size, label, iterations, deflate_iters in (
        (65536, '64KiB', 20, 8),
        (1 << 20, '1MiB', 4, 3),
    ):
        result['deflate'][label] = {}
        result['lz4'][label] = {}
        for kind in ('repeat1', 'period3', 'text', 'ramp', 'random'):
            data = corpus(size, kind, rng)
            enc = zlib.compressobj(6, zlib.DEFLATED, -15)
            raw = enc.compress(data) + enc.flush()
            cap = len(data)
            variants = {
                'python-ir-grow': lambda p=raw, c=cap: deflate_ir.decompress(p, max_output=c, parse='ir'),
                'native-parse-grow': lambda p=raw, c=cap: deflate_ir.decompress(p, max_output=c, parse='native'),
                'zlib': lambda p=raw: zlib.decompress(p, -15),
            }
            result['deflate'][label][kind] = {
                name: measure(fn, data, deflate_iters if name != 'zlib' else iterations)
                for name, fn in variants.items()
            }
            if HAS_LZ4:
                packed = lz4_block.compress(data, store_size=False)
                lz = {
                    'python-periodic': lambda p=packed, n=len(data): lz4_frame.decompress_block(p, n),
                    'liblz4-oracle': lambda p=packed, n=len(data): lz4_block.decompress(p, uncompressed_size=n),
                }
                if (ROOT / 'build/libnovelrar.so').exists():
                    for mode in native_lz4.MODES:
                        lz[f'native-{mode}'] = (
                            lambda p=packed, n=len(data), m=mode: native_lz4.decompress_block(p, n, mode=m)
                        )
                result['lz4'][label][kind] = {name: measure(fn, data, iterations) for name, fn in lz.items()}
    target = ROOT / 'results/lz4_scale_benchmark.json'
    target.write_text(json.dumps(result, indent=2) + '\n')
    print(target)
    for size in ('64KiB', '1MiB'):
        text = result['deflate'][size].get('text', {})
        print(size, {k: round(v['MiB_per_second'], 1) for k, v in text.items()})


if __name__ == '__main__':
    main()
