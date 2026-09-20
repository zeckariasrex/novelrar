#!/usr/bin/env python3
"""NRISA reference codec: round-trip, stream validation, and native parity."""
from __future__ import annotations

import os
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'src'))

import nrisa  # noqa: E402

SAMPLES = {
    'empty': b'',
    'single': b'Z',
    'repeat200': b'A' * 200,
    'period3': b'abc' * 80,
    'ramp512': bytes(i & 255 for i in range(512)),
    'text450': (b'the quick brown fox jumps over the lazy dog. ' * 11)[:450],
    'affine_add': bytes(range(64)) + bytes((i + 7) & 255 for i in range(64)),
    'affine_neg': bytes(range(64)) + bytes((200 - i) & 255 for i in range(64)),
    'incompressible': os.urandom(300),
    'long_run': b'\x00' * 70000,
}


def _native_available():
    try:
        nrisa.decompress_native(nrisa.encode(b'probe' * 20))
        return True
    except (OSError, ImportError):
        return False


class RoundTripTests(unittest.TestCase):

    def test_round_trip(self):
        for name, payload in SAMPLES.items():
            with self.subTest(name):
                self.assertEqual(nrisa.decode(nrisa.encode(payload)), payload)

    def test_header_is_well_formed(self):
        blob = nrisa.encode(b'abc' * 40)
        self.assertEqual(blob[:4], nrisa.MAGIC)
        self.assertEqual(blob[4], nrisa.VERSION)
        self.assertEqual(nrisa._le32(blob, 6), 120)

    def test_repetitive_input_shrinks(self):
        for name in ('repeat200', 'period3', 'ramp512', 'text450'):
            with self.subTest(name):
                self.assertLess(len(nrisa.encode(SAMPLES[name])),
                                len(SAMPLES[name]))


class StreamValidationTests(unittest.TestCase):

    def setUp(self):
        self.blob = nrisa.encode(b'the quick brown fox ' * 20)

    def _rejects(self, blob, msg=''):
        with self.assertRaises(ValueError, msg=msg):
            nrisa.decode(blob)

    def test_rejects_bad_magic_and_version(self):
        self._rejects(b'XXXX' + self.blob[4:])
        self._rejects(self.blob[:4] + bytes([2]) + self.blob[5:])
        self._rejects(b'')
        self._rejects(b'NRIS')

    def test_rejects_corrupted_digest(self):
        bad = bytearray(self.blob)
        bad[-1] ^= 0xFF
        self._rejects(bytes(bad))

    def test_rejects_corrupted_payload(self):
        bad = bytearray(self.blob)
        bad[20] ^= 0x01
        self._rejects(bytes(bad))

    def test_rejects_truncation_and_trailing_bytes(self):
        self._rejects(self.blob[:-1])
        self._rejects(self.blob[:20])
        self._rejects(self.blob + b'\x00')

    def test_rejects_declared_size_mismatch(self):
        bad = bytearray(self.blob)
        bad[6:10] = struct.pack('<I', 999)
        self._rejects(bytes(bad))

    def test_rejects_output_limit_overrun(self):
        with self.assertRaises(ValueError):
            nrisa.decode(nrisa.encode(b'A' * 5000), max_output=10)
        with self.assertRaises(ValueError):
            nrisa.decode(self.blob, max_output=-1)
        with self.assertRaises(ValueError):
            nrisa.decode(self.blob, max_output=(512 << 20))

    def _stream(self, cmds, ncmd, usize):
        return nrisa.MAGIC + struct.pack('<BBII', 1, 0, usize, ncmd) + cmds

    def test_rejects_unknown_opcode(self):
        self._rejects(self._stream(b'\x09', 1, 0))

    def test_rejects_copy_distance_past_start(self):
        # COPY dist=1 with nothing written yet.
        self._rejects(self._stream(struct.pack('<BHH', 1, 4, 1), 1, 4))

    def test_rejects_zero_length_commands(self):
        emit = struct.pack('<BH', 0, 4) + b'abcd'
        for cmd in (struct.pack('<BHH', 1, 0, 1),
                    struct.pack('<BHB', 2, 0, 7),
                    struct.pack('<BHHBB', 3, 0, 1, 1, 1)):
            self._rejects(self._stream(emit + cmd, 2, 4))

    def test_rejects_axpy_longer_than_distance(self):
        # docs/NRISA.md caps AXPY length at the distance; the source span must
        # already be final for the vector path to agree with the scalar one.
        emit = struct.pack('<BH', 0, 4) + b'abcd'
        bad = emit + struct.pack('<BHHBB', 3, 8, 4, 1, 1)
        self._rejects(self._stream(bad, 2, 12))
        ok = emit + struct.pack('<BHHBB', 3, 4, 4, 1, 1)
        self.assertEqual(nrisa.decode(self._stream(ok, 2, 8)), b'abcdbcde')


@unittest.skipUnless(_native_available(), 'build/libnovelrar.so lacks nr_isa')
class NativeParityTests(unittest.TestCase):

    MODES = ('scalar', 'grow', 'sse2', 'asm')

    def test_matches_python_decoder(self):
        for name, payload in SAMPLES.items():
            blob = nrisa.encode(payload)
            for mode in self.MODES:
                with self.subTest(sample=name, mode=mode):
                    self.assertEqual(nrisa.decompress_native(blob, mode=mode),
                                     payload)

    def test_native_rejects_what_python_rejects(self):
        blob = nrisa.encode(b'the quick brown fox ' * 20)
        corrupt_digest = bytearray(blob)
        corrupt_digest[-1] ^= 0xFF
        corrupt_payload = bytearray(blob)
        corrupt_payload[20] ^= 0x01
        for name, bad in (('digest', bytes(corrupt_digest)),
                          ('payload', bytes(corrupt_payload)),
                          ('truncated', blob[:-1]),
                          ('trailing', blob + b'\x00')):
            with self.subTest(name):
                with self.assertRaises(ValueError):
                    nrisa.decode(bad)
                with self.assertRaises(ValueError):
                    nrisa.decompress_native(bad)

    def test_rejects_unknown_mode(self):
        with self.assertRaises(ValueError):
            nrisa.decompress_native(nrisa.encode(b'abc' * 40), mode='nope')


if __name__ == '__main__':
    unittest.main(verbosity=2)
