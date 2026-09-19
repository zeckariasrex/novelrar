"""Follow-up tests for native DEFLATE parse and HOST isolation."""
import random
import unittest
import zlib
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import native_lz4

@unittest.skipUnless((ROOT / 'build/libnovelrar.so').exists(), 'native library not built')
class NativeParseTests(unittest.TestCase):
    def test_native_parse_against_zlib(self):
        import deflate_ir
        rng = random.Random(11)
        payloads = (b'a' * 4096, b'abc' * 2000, b'Independent archive research. ' * 200,
                    rng.randbytes(8000), bytes(range(256)) * 40)
        for data in payloads:
            for level in (1, 6, 9):
                for strategy in (zlib.Z_DEFAULT_STRATEGY, zlib.Z_FIXED, zlib.Z_HUFFMAN_ONLY):
                    enc = zlib.compressobj(level, zlib.DEFLATED, -15, strategy=strategy)
                    packed = enc.compress(data) + enc.flush()
                    self.assertEqual(deflate_ir.decompress(packed, parse='native'), data)
                    with self.assertRaises(ValueError):
                        deflate_ir.decompress(packed, max_output=max(0, len(data) - 1), parse='native')

class HostIsolateTests(unittest.TestCase):
    def test_wrap_and_run_echo(self):
        import host_isolate
        raw = ['/bin/echo', '-n', 'ok']
        wrapped = host_isolate.wrap(raw)
        if wrapped and wrapped[0].endswith('unshare'):
            self.assertEqual(wrapped[-3:], raw)
        else:
            self.assertEqual(wrapped, raw)
        proc = host_isolate.run(['/bin/echo', '-n', 'isolated-ok'], timeout=10)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b'isolated-ok')
    def test_run_nonzero_child(self):
        import host_isolate
        proc = host_isolate.run(['/bin/false'], timeout=5)
        self.assertNotEqual(proc.returncode, 0)

if __name__ == '__main__':
    unittest.main()
