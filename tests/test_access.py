"""Supplied-password and HOST-handoff tests. No password search."""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FIX = Path(os.environ.get('NOVELRAR_FIXTURES', ROOT / 'tests' / 'fixtures'))
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(FIX))

import host_handoff
import license_broker as LB
import unarchive

PASSWORD = b'novelrar'


def blob(name):
    return (FIX / name).read_bytes()


class PasswordRefusalTests(unittest.TestCase):
    def test_zipcrypto_without_password_stays_refused(self):
        a = unarchive.open_archive(blob('zip_zipcrypto.zip'))
        self.assertEqual(a.extracted, 0)
        self.assertEqual(a.members[0].receipt.lane, LB.REFUSED)

    def test_zipcrypto_with_password_extracts(self):
        a = unarchive.open_archive(blob('zip_zipcrypto.zip'), password=PASSWORD)
        self.assertGreater(a.extracted, 0)
        self.assertIsNotNone(a.members[0].payload)
        self.assertEqual(a.members[0].receipt.lane, LB.STDLIB)

    def test_7z_aes_without_password_stays_refused(self):
        a = unarchive.open_archive(blob('7z_aes.7z'))
        self.assertEqual(a.extracted, 0)
        self.assertTrue(all(r.lane == LB.REFUSED for r in a.receipts))

    def test_rar_encrypted_without_password_stays_refused(self):
        for name in ('rar4_enc.rar', 'rar5_enc.rar'):
            a = unarchive.open_archive(blob(name))
            self.assertEqual(a.extracted, 0)
            self.assertEqual(a.receipts[0].lane, LB.REFUSED)

    def test_strict_policy_never_calls_host(self):
        payload, _, detail = LB.host_extract('rar', blob('rar5_normal.rar'), 'x',
                                             LB.Policy.strict(), password=PASSWORD)
        self.assertIsNone(payload)
        self.assertIn('forbids', detail)


class HostCommandTests(unittest.TestCase):
    def test_password_is_a_single_argument(self):
        cmd = host_handoff.host_command('unrar', '/usr/bin/unrar', 'a.rar', 'out',
                                        'member.txt', b'secret')
        self.assertIn('-psecret', cmd)
        self.assertTrue(all(not isinstance(x, bytes) for x in cmd))

    def test_empty_unrar_password_disables_prompt(self):
        cmd = host_handoff.host_command('unrar', '/usr/bin/unrar', 'a.rar', 'out',
                                        'member.txt', None)
        self.assertIn('-p-', cmd)

    def test_7z_password_flag_does_not_split(self):
        cmd = host_handoff.host_command('7z', '/usr/bin/7z', 'a.7z', 'out',
                                        'm', b'a b')
        self.assertIn('-pa b', cmd)


class HostHandoffTests(unittest.TestCase):
    def test_extract_uses_isolated_run(self):
        policy = LB.Policy()
        with mock.patch.object(LB, 'find_host_tool', return_value=LB.HostTool('unrar', '/bin/unrar', '1')):
            with mock.patch('host_handoff.isolated_available', create=True):
                with mock.patch('host_isolate.run') as run:
                    run.return_value = mock.Mock(returncode=1, stdout=b'', stderr=b'')
                    payload, desc, detail = host_handoff.extract(
                        'rar', b'Rar!', 'file.txt', policy, password=PASSWORD)
                    self.assertIsNone(payload)
                    self.assertTrue(run.called)
                    self.assertIn('isolated', desc)

    def test_wrong_password_does_not_search(self):
        a = unarchive.open_archive(blob('zip_zipcrypto.zip'), password=b'wrong')
        self.assertEqual(a.extracted, 0)


@unittest.skipUnless(__import__('importlib').util.find_spec('py7zr'), 'optional py7zr missing')
class SevenZipPasswordTests(unittest.TestCase):
    def test_aes_with_password_and_backend(self):
        a = unarchive.open_archive(blob('7z_aes.7z'), password=PASSWORD, backend='py7zr')
        self.assertGreater(a.extracted, 0)
        self.assertEqual(a.receipts[0].lane, LB.OPTIONAL)

    def test_strict_policy_rejects_optional_backend(self):
        with self.assertRaises(ValueError):
            unarchive.open_archive(blob('7z_aes.7z'), password=PASSWORD,
                                   backend='py7zr', policy=LB.Policy.strict())


if __name__ == '__main__':
    unittest.main()
