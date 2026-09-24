"""Real archives + independent CPU/OpenCL differential checks. No speed claims."""
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import zlib

from rar_crypto import cpu_decrypt, rar4_key, rar5_keys, blake2sp
from rar_extract import (extract, safe_name, Reader, Normalizer, Decryptor,
                         RAR5, block5, vint, LIMIT)

ROOT = Path(__file__).parent / 'rar_fixtures'
FIXTURES = json.loads((ROOT / 'archives.json').read_text())
TEXT = b''.join(('%03d\n' % i).encode() for i in range(512))


def fixture(name):
    record = FIXTURES[name]
    data = base64.b64decode(record['base64'])
    assert hashlib.sha256(data).hexdigest() == record['sha256']
    return data, record['password']


class RarTests(unittest.TestCase):
    def test_real_encrypted_archives(self):
        for name in FIXTURES:
            if name == 'rar3-solid.rar' or 'fractional' in name:
                continue
            with self.subTest(name=name):
                blob, password = fixture(name)
                report = extract(blob, password, 'cpu')
                self.assertTrue(report['verified'])
                expected = b'Modern RAR forensic extraction.\n' * 1000 if name.startswith('rar7') else TEXT
                for member in report['members']:
                    self.assertEqual(base64.b64decode(member['data_b64']), expected)
                self.assertEqual(report['acceleration']['gpu_bytes'], 0)
                self.assertEqual(report['source_sha256'], hashlib.sha256(blob).hexdigest())

    def test_wrong_password_and_missing_password(self):
        for name in ('rar4-aes-compressed.rar', 'rar4-aes-compressed-headers.rar',
                     'rar5-psw.rar', 'rar5-hpsw.rar', 'rar5-psw-blake.rar'):
            blob, _ = fixture(name)
            for password in (None, 'wrong'):
                with self.subTest(name=name, password=password), self.assertRaises(ValueError):
                    extract(blob, password, 'cpu')

    def test_ciphertext_corruption_never_returns_members(self):
        blob, password = fixture('rar5-psw.rar')
        # Change a stored payload byte; its header and password check stay valid.
        position = len(blob) - 64
        damaged = blob[:position] + bytes([blob[position] ^ 1]) + blob[position+1:]
        with self.assertRaises(ValueError):
            extract(damaged, password, 'cpu')

    def test_truncation_trailing_data_and_bad_header(self):
        blob, password = fixture('rar5-hpsw.rar')
        for damaged in (blob[:-1], blob + b'junk', blob[:10] + b'\xff' + blob[11:]):
            with self.assertRaises(ValueError):
                extract(damaged, password, 'cpu')

    def test_resource_bounds(self):
        with self.assertRaises(ValueError):
            rar5_keys('password', bytes(16), 21)
        with self.assertRaises(ValueError):
            rar4_key('x' * 29, bytes(8))
        with self.assertRaises(ValueError):
            Reader(b'\xff' * 10).vint()
        n = Normalizer(None, Decryptor('cpu'))
        with self.assertRaises(ValueError):
            n.add('oversize', LIMIT + 1, False, bytes(4))

    def test_unsafe_names(self):
        for name in ('../escape', '/root', 'a/../b', 'a//b', 'C:/file', 'a:b',
                     'NUL', 'con.txt', 'a.', 'a ', 'a\x00b', '\\root'):
            with self.subTest(name=name), self.assertRaises((ValueError, UnicodeError)):
                safe_name(name.encode())
        self.assertEqual(safe_name(b'a/b/', True), 'a/b')

    def test_alias_and_prefix_collisions(self):
        for second in ('file', 'FILE', 'file/child'):
            n = Normalizer(None, Decryptor('cpu'))
            n.add('file', 0, False, bytes(4))
            with self.assertRaises(ValueError):
                n.add(second, 0, False, bytes(4))
        n = Normalizer(None, Decryptor('cpu'))
        n.add('Parent/a', 0, False, bytes(4))
        with self.assertRaises(ValueError):
            n.add('parent/b', 0, False, bytes(4))

    def test_synthetic_unchecksummed_and_large_dictionary_refused(self):
        for flags, size, comp in ((0, 1, 0), (4, LIMIT+1, 0), (4, 1, (10 << 10) | (3 << 7))):
            body = vint(flags) + vint(size) + vint(0) + (bytes(4) if flags & 4 else b'')
            body += vint(comp) + vint(0) + vint(1) + b'x'
            blob = RAR5 + block5(1, 0, vint(0)) + block5(2, 2, body, b'x') + block5(5, 0, vint(0))
            with self.assertRaises(ValueError):
                extract(blob, backend='cpu')

    def test_original_checksums_required_even_if_decoder_claims_success(self):
        blob, password = fixture('rar5-psw.rar')
        n = Normalizer(password, Decryptor('cpu'))
        n.parse5(blob)
        from rar_extract import verify_member
        with self.assertRaises(ValueError):
            verify_member(n.members[0], b'x' * n.members[0]['size'])

    def test_auto_does_not_label_cpu_as_gpu(self):
        blob, password = fixture('rar5-psw.rar')
        report = extract(blob, password, 'auto')
        self.assertEqual(report['acceleration']['gpu_bytes'], 0)
        self.assertGreater(report['acceleration']['cpu_bytes'], 0)

    def test_explicit_gpu_failure_is_fatal(self):
        blob, password = fixture('rar5-psw.rar')
        with patch('rar_opencl.OpenCLAes', side_effect=ValueError('no device')):
            with self.assertRaisesRegex(ValueError, 'requested RAR GPU unavailable'):
                extract(blob, password, 'gpu')

    def test_gpu_disagreement_is_fatal(self):
        class BadDevice:
            description = 'fault injection'
            def decrypt(self, key, iv, data): return b'\x00' * len(data)
            def close(self): pass
        with patch('rar_opencl.OpenCLAes', return_value=BadDevice()):
            with self.assertRaisesRegex(ValueError, 'GPU/CPU AES disagreement'):
                extract(*fixture('rar5-psw.rar'), 'gpu', verify_gpu=True)

    @unittest.skipUnless(os.environ.get('NOVELRAR_RAR_TOOL'), 'operator RAR tool not configured')
    def test_modern_external_decoder(self):
        for name in ('rar3-solid.rar', 'rar7-header.rar'):
            report = extract(*fixture(name), 'cpu', rar_tool=os.environ['NOVELRAR_RAR_TOOL'])
            self.assertTrue(report['external_tools_used'])
            expected = TEXT if name == 'rar3-solid.rar' else b'Modern RAR forensic extraction.\n' * 1000
            for m in report['members']:
                self.assertEqual(base64.b64decode(m['data_b64']), expected)

    def test_external_decoder_must_be_explicit_absolute_file(self):
        with self.assertRaises(ValueError):
            extract(*fixture('rar5-psw.rar'), 'cpu', rar_tool='unconfigured-tool')


@unittest.skipUnless(os.environ.get('NOVELRAR_TEST_OPENCL') == '1', 'OpenCL test device not requested')
class OpenCLTests(unittest.TestCase):
    def device(self):
        from rar_opencl import OpenCLAes
        # CPU ICD is allowed ONLY by this internal test parameter. Production
        # selection requires GPU type AND AMD/NVIDIA PCI vendor ID.
        return OpenCLAes(_test_cpu=os.environ.get('NOVELRAR_TEST_GPU') != '1')

    def test_aes128_aes256_chunks_and_reuse(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        device = self.device()
        try:
            for size in (16, 32):
                key, iv = bytes(range(size)), bytes(range(16))
                for length in (0, 16, 48, 1024, (8 << 20) + 48, 32):
                    plain = (bytes(range(256)) * ((length+255)//256))[:length]
                    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
                    ciphertext = enc.update(plain) + enc.finalize()
                    self.assertEqual(device.decrypt(key, iv, ciphertext), plain)
            with self.assertRaises(ValueError):
                device.decrypt(bytes(16), bytes(16), b'bad')
        finally:
            device.close()

    def test_real_archives_gpu_cpu_equivalence(self):
        for name in ('rar4-aes-compressed.rar', 'rar4-aes-compressed-headers.rar',
                     'rar5-psw.rar', 'rar5-hpsw.rar', 'rar5-psw-blake.rar', 'rar7-header.rar'):
            blob, password = fixture(name)
            cpu = extract(blob, password, 'cpu')
            device = self.device()
            with patch('rar_opencl.OpenCLAes', return_value=device):
                gpu = extract(blob, password, 'gpu', verify_gpu=True)
            self.assertEqual(cpu['members'], gpu['members'])
            self.assertGreater(gpu['acceleration']['gpu_bytes'], 0)


if __name__ == '__main__':
    unittest.main()
