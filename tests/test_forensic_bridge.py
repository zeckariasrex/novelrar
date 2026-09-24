import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch
import zlib

import forensic_bridge as bridge
import rar_reader
import rar_store
import research_codec

FIXTURES = Path(__file__).parent / "fixtures"


class ForensicBridgeTests(unittest.TestCase):
    def test_metadata_never_decodes_member_payload(self):
        blob = rar_store.create({"one.txt": b"evidence", "empty": b""})
        with patch.object(rar_reader, "_finish", side_effect=AssertionError("decoded")):
            result = bridge.analyze(blob, "inspect-rar")
        self.assertEqual(result["source_sha256"], hashlib.sha256(blob).hexdigest())
        self.assertEqual([m["name"] for m in result["members"]], ["one.txt", "empty"])
        self.assertTrue(result["inspection_complete"])
        self.assertFalse(result["payloads_verified"])
        self.assertFalse(result["writes_performed"])
        self.assertNotIn("payload", result["members"][0])

    def test_rar4_and_rar5_compressed_metadata(self):
        for name in ("rar4_store", "rar5_store", "rar4_normal", "rar5_normal"):
            with self.subTest(name=name):
                result = bridge.analyze((FIXTURES / (name + ".rar")).read_bytes(), "inspect-rar")
                self.assertTrue(result["inspection_complete"])
                self.assertGreater(len(result["members"]), 0)

    def test_encrypted_headers_are_explicitly_incomplete(self):
        result = bridge.analyze((FIXTURES / "rar5_hdrenc.rar").read_bytes(), "inspect-rar")
        self.assertTrue(result["header_encrypted"])
        self.assertFalse(result["inspection_complete"])

    def test_truncated_archives_never_report_success(self):
        blob = rar_store.create({"a": b"a" * 40})
        for length in range(len(blob)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                bridge.analyze(blob[:length], "inspect-rar")

    def test_corrupt_header_and_member_limit(self):
        blob = bytearray(rar_store.create({"a": b"a", "b": b"b"}))
        blob[8] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC"):
            bridge.analyze(bytes(blob), "inspect-rar")
        with self.assertRaisesRegex(ValueError, "member limit"):
            rar_reader.read(rar_store.create({"a": b"a", "b": b"b"}),
                            strict=True, metadata_only=True, max_members=1)

    def test_malformed_file_body_does_not_disappear(self):
        blob = rar_reader.RAR5_MAGIC + rar_store._block(1, b"\x00")
        blob += rar_store._block(2, b"\x80", b"payload")
        blob += rar_store._block(5, b"\x00")
        with self.assertRaises(ValueError):
            bridge.analyze(blob, "inspect-rar")

    def test_member_crc_is_not_claimed_verified(self):
        blob = bytearray(rar_store.create({"a": b"unique payload"}))
        blob[blob.index(b"unique payload")] ^= 1
        result = bridge.analyze(bytes(blob), "inspect-rar")
        self.assertFalse(result["payloads_verified"])

    def test_digest_and_output_cap_for_every_codec(self):
        raw = b"cross-check payload" * 200
        for codec in bridge.CODECS:
            with self.subTest(codec=codec):
                blob = research_codec.compress(raw, codec)
                result = bridge.analyze(blob, "digest", codec, len(raw))
                self.assertEqual(result["decoded_sha256"], hashlib.sha256(raw).hexdigest())
                self.assertEqual(result["decoded_bytes"], len(raw))
                with self.assertRaises(ValueError):
                    bridge.analyze(blob, "digest", codec, len(raw) - 1)

    def test_digest_rejects_truncation_trailing_and_unsupported(self):
        for codec in bridge.CODECS:
            blob = research_codec.compress(b"x" * 100, codec)
            for bad in (blob[:-1], blob + b"garbage"):
                with self.subTest(codec=codec), self.assertRaises(ValueError):
                    bridge.analyze(bad, "digest", codec)
        with self.assertRaises(ValueError):
            bridge.analyze(b"", "digest", "rar")
        with self.assertRaises(ValueError):
            bridge.analyze(b"", "digest", "lz4")

    def test_concatenated_lz4_hashes_every_frame(self):
        blob = research_codec.compress(b"first", "lz4") + research_codec.compress(b"second", "lz4")
        result = bridge.analyze(blob, "digest", "lz4")
        self.assertEqual(result["decoded_sha256"], hashlib.sha256(b"firstsecond").hexdigest())

    def test_invalid_limits(self):
        for limit in (-1, bridge.MAX_OUTPUT + 1):
            with self.assertRaises(ValueError):
                bridge.analyze(b"", "inspect-rar", max_output=limit)
        with patch.object(bridge, "MAX_INPUT", 1), self.assertRaises(ValueError):
            bridge.analyze(b"xx", "inspect-rar")

    def test_cli_error_is_json_and_nonzero(self):
        proc = subprocess.run([sys.executable, str(Path(bridge.__file__)), "inspect-rar"],
                              input=b"bad", capture_output=True)
        self.assertEqual(proc.returncode, 1)
        self.assertFalse(json.loads(proc.stdout)["ok"])
        self.assertEqual(proc.stderr, b"")

    def test_rar4_payload_marker_does_not_change_archive_version(self):
        blob = bytearray((FIXTURES / "rar4_store.rar").read_bytes())
        member = rar_reader.read(bytes(blob)).members[0]
        blob[member.data_off:member.data_off + 8] = rar_reader.RAR5_MAGIC
        self.assertEqual(bridge.analyze(bytes(blob), "inspect-rar")["container"], "rar4")

    def test_codec_error_is_json(self):
        for codec in bridge.CODECS:
            proc = subprocess.run([sys.executable, str(Path(bridge.__file__)),
                                   "digest", "--codec", codec],
                                  input=b"bad stream", capture_output=True)
            self.assertEqual(proc.returncode, 1)
            self.assertFalse(json.loads(proc.stdout)["ok"])
            self.assertEqual(proc.stderr, b"")


if __name__ == "__main__":
    unittest.main()
