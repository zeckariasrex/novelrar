#!/usr/bin/env python3
"""Does novelrar actually unzip / decompress rar, 7z, zip and lz4?

Every assertion here is byte-for-byte against a payload we authored, so
"it ran without raising" never counts as a pass. Encrypted fixtures assert
the *refusal*, which is as much a requirement as the extraction.

Run:  PYTHONPATH=src python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import sys
import unittest
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(os.environ.get("NOVELRAR_FIXTURES", ROOT / "tests" / "fixtures"))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(FIX))

import license_broker as LB          # noqa: E402
import lz4_frame                      # noqa: E402
import rar_reader                     # noqa: E402
import sevenzip                       # noqa: E402
import unarchive                      # noqa: E402
from geex_unpack import inflate_trace  # noqa: E402

try:
    from _payloads import PAYLOADS, big_text, pseudo_random
except ImportError:  # pragma: no cover
    raise SystemExit("fixtures missing; run: python3 tests/make_fixtures.py tests/fixtures")


def blob(name: str) -> bytes:
    return (FIX / name).read_bytes()


class ZipTests(unittest.TestCase):
    """ZIP already worked; these pin it down and add the streamed case."""

    def _check(self, fixture, names=None):
        a = unarchive.open_archive(blob(fixture), fixture)
        self.assertEqual(a.container, "zip")
        got = {m.name: m.payload for m in a.members}
        for n in (names or PAYLOADS):
            self.assertIn(n, got, f"{fixture}: member {n} missing")
            self.assertEqual(got[n], PAYLOADS[n], f"{fixture}: {n} not bit-exact")
        return a

    def test_store(self):
        self._check("zip_store.zip")

    def test_deflate(self):
        self._check("zip_deflate.zip")

    def test_bzip2_member(self):
        self._check("zip_bzip2.zip", ["text.txt"])

    def test_lzma_member(self):
        self._check("zip_lzma.zip", ["text.txt"])

    def test_data_descriptor(self):
        """GPBF bit 3: sizes live in a trailing descriptor, not the header."""
        self._check("zip_datadesc.zip")

    def test_zipcrypto_is_refused(self):
        a = unarchive.open_archive(blob("zip_zipcrypto.zip"), "z")
        self.assertEqual(a.extracted, 0)
        m = a.members[0]
        self.assertIsNone(m.payload)
        self.assertIn("encrypted", (m.error or "").lower())
        self.assertEqual(m.receipt.lane, LB.REFUSED)


class InflateTraceTests(unittest.TestCase):
    """The in-tree RFC 1951 inflater must agree with zlib, always."""

    CASES = {
        "text": b"The quick brown fox. " * 300,
        "zeros": b"\x00" * 50000,
        "tiny": b"a",
        "empty": b"",
        "pseudo_random": pseudo_random(20000),
    }

    def test_matches_zlib_at_every_level(self):
        for name, data in self.CASES.items():
            for level in (0, 1, 6, 9):
                with self.subTest(case=name, level=level):
                    c = zlib.compressobj(level, zlib.DEFLATED, -15)
                    stream = c.compress(data) + c.flush()
                    out, matches, stats = inflate_trace(stream)
                    self.assertEqual(out, data)
                    self.assertEqual(stats["n_out"], len(data))
                    for ev in matches:
                        self.assertGreater(ev.distance, 0)
                        self.assertLessEqual(ev.distance, ev.pos)

    def test_rejects_reserved_block_type(self):
        with self.assertRaises(ValueError):
            inflate_trace(b"\x07\x00")


class Lz4Tests(unittest.TestCase):
    """LZ4 went from magic-sniffing to a complete clean-room decoder."""

    def test_xxh32_published_vectors(self):
        self.assertEqual(lz4_frame.xxh32(b""), 0x02CC5D05)
        self.assertEqual(lz4_frame.xxh32(b"abc"), 0x32D153FF)
        self.assertEqual(lz4_frame.xxh32(b"", 1), 0x0B2CB792)

    def test_frames(self):
        cases = {
            "lz4_text.lz4": PAYLOADS["text.txt"],
            "lz4_bin.lz4": PAYLOADS["bin.dat"],
            "lz4_nochk.lz4": PAYLOADS["small.txt"],
            "lz4_csize.lz4": PAYLOADS["text.txt"],
            "lz4_linked.lz4": PAYLOADS["text.txt"] * 3,
            "lz4_indep.lz4": PAYLOADS["text.txt"] * 3,
            "lz4_skippable.lz4": PAYLOADS["small.txt"],
            "lz4_legacy.lz4": PAYLOADS["text.txt"][:4096],
            "lz4_linkedbig.lz4": big_text(),
            "lz4_indepbig.lz4": big_text(),
            "lz4_stored.lz4": pseudo_random(),
        }
        for fixture, want in cases.items():
            with self.subTest(fixture=fixture):
                self.assertEqual(lz4_frame.decompress(blob(fixture)), want)

    def test_linked_blocks_really_span_a_boundary(self):
        """Guards the cross-block history path, not just 'it decoded'."""
        info = lz4_frame.inspect(blob("lz4_linkedbig.lz4"))
        frame = info["frames"][0]
        self.assertGreater(frame["blocks"], 1, "fixture no longer multi-block")
        self.assertTrue(frame["linked"])
        self.assertIn("content-xxh32 ok", frame["checks"])

    def test_stored_blocks(self):
        info = lz4_frame.inspect(blob("lz4_stored.lz4"))
        self.assertGreater(info["frames"][0]["stored"], 0)

    def test_corrupt_checksum_is_caught(self):
        raw = bytearray(blob("lz4_csize.lz4"))
        raw[-1] ^= 0xFF
        with self.assertRaises(lz4_frame.LZ4Error):
            lz4_frame.decompress(bytes(raw))

    def test_bad_offset_is_caught(self):
        with self.assertRaises(lz4_frame.LZ4Error):
            lz4_frame.decompress_block(b"\x10\x41\xff\xff")


class SevenZipTests(unittest.TestCase):
    """7z went from magic-sniffing to a full container reader."""

    CODEC_FIXTURES = ["7z_copy.7z", "7z_lzma1.7z", "7z_lzma2.7z", "7z_bzip2.7z",
                      "7z_deflate.7z", "7z_delta_lzma2.7z", "7z_bcj_lzma2.7z"]

    def test_every_coder_chain_round_trips(self):
        for fixture in self.CODEC_FIXTURES:
            with self.subTest(fixture=fixture):
                a = sevenzip.read(blob(fixture))
                got = {e.name: e.payload for e in a.entries}
                self.assertEqual(set(got), set(PAYLOADS))
                for n, want in PAYLOADS.items():
                    self.assertEqual(got[n], want, f"{fixture}: {n} not bit-exact")

    def test_crc_is_checked(self):
        a = sevenzip.read(blob("7z_lzma2.7z"))
        for e in a.entries:
            self.assertIsNone(e.error)
            self.assertIsNotNone(e.crc)
            self.assertEqual(zlib.crc32(e.payload) & 0xFFFFFFFF, e.crc)

    def test_encoded_header_is_decoded(self):
        a = sevenzip.read(blob("7z_lzma2.7z"))
        self.assertTrue(any("encoded header" in n for n in a.notes))

    def test_aes_is_refused(self):
        a = unarchive.open_archive(blob("7z_aes.7z"), "7z")
        self.assertEqual(a.extracted, 0)
        self.assertTrue(all(r.lane == LB.REFUSED for r in a.receipts))

    def test_unsupported_coders_refuse_cleanly(self):
        """PPMd / Zstd have no stdlib path: refuse with a reason, never crash."""
        for fixture in ("7z_ppmd.7z", "7z_zstd.7z"):
            if not (FIX / fixture).exists():
                continue
            with self.subTest(fixture=fixture):
                a = unarchive.open_archive(blob(fixture), fixture)
                self.assertEqual(a.extracted, 0)
                self.assertTrue(all(r.lane in (LB.HOST, LB.REFUSED)
                                    for r in a.receipts))
                self.assertTrue(all(m.error for m in a.members))

    def test_bcj2_is_refused_rather_than_guessed(self):
        coder = sevenzip.Coder(sevenzip.BCJ2, 4, 1)
        with self.assertRaises(sevenzip.SevenZRefused):
            sevenzip.run_coder(coder, [b"", b"", b"", b""], 10)

    def test_truncated_archive_raises_not_crashes(self):
        with self.assertRaises(sevenzip.SevenZError):
            sevenzip.read(blob("7z_lzma2.7z")[:20])


class RarTests(unittest.TestCase):
    """RAR4 was broken outright; RAR5 store worked. Both are pinned here."""

    def test_rar4_store(self):
        a = rar_reader.read(blob("rar4_store.rar"))
        self.assertEqual(a.version, "rar4")
        self.assertEqual(len(a.members), 3, "RAR4 walk aborted early again")
        for m in a.members:
            self.assertEqual(m.payload, PAYLOADS[m.name])

    def test_rar5_store(self):
        a = rar_reader.read(blob("rar5_store.rar"))
        self.assertEqual(len(a.members), 3)
        for m in a.members:
            self.assertEqual(m.payload, PAYLOADS[m.name])

    def test_long_block_flag_is_not_mistaken_for_encryption(self):
        """0x8000 is LONG_BLOCK and is set on every RAR4 file header."""
        a = rar_reader.read(blob("rar4_store.rar"))
        self.assertFalse(a.header_encrypted)
        self.assertTrue(all(not m.encrypted for m in a.members))

    def test_compressed_members_are_not_guessed_at(self):
        for fixture, method in (("rar4_normal.rar", "normal"),
                                ("rar5_normal.rar", "normal")):
            with self.subTest(fixture=fixture):
                a = rar_reader.read(blob(fixture))
                m = a.members[0]
                self.assertEqual(m.method_name, method)
                self.assertIsNone(m.payload)
                self.assertIn("proprietary", m.error)

    def test_encrypted_members_are_refused(self):
        for fixture in ("rar4_enc.rar", "rar5_enc.rar"):
            with self.subTest(fixture=fixture):
                a = unarchive.open_archive(blob(fixture), fixture)
                self.assertEqual(a.extracted, 0)
                self.assertEqual(a.receipts[0].lane, LB.REFUSED)

    def test_encrypted_headers_stop_the_walk(self):
        a = rar_reader.read(blob("rar5_hdrenc.rar"))
        self.assertTrue(a.header_encrypted)
        self.assertEqual(a.members, [])


class BrokerTests(unittest.TestCase):
    """The licence boundary has to be enforceable, not just documented."""

    def test_unregistered_codec_defaults_to_refused(self):
        self.assertEqual(LB.capability("zip", "nonesuch").lane, LB.REFUSED)

    def test_strict_policy_rejects_host_lane_bytes(self):
        r = LB.make_receipt("x.bin", "rar", "compressed", chain="rar-normal",
                            n_bytes=10, ok=True, tool="unrar 6.2")
        self.assertEqual(r.lane, LB.HOST)
        self.assertTrue(LB.audit([r], LB.Policy.permissive()).clean)
        strict = LB.audit([r], LB.Policy.strict())
        self.assertFalse(strict.clean)
        self.assertIn("not permitted", strict.violations[0])

    def test_refused_streams_never_count_as_extracted(self):
        r = LB.make_receipt("s.txt", "zip", "zipcrypto", ok=False)
        self.assertEqual(LB.audit([r]).extracted, 0)

    def test_strict_policy_disables_host_handoff(self):
        payload, tool, detail = LB.host_extract(
            "rar", b"", "x", LB.Policy.strict())
        self.assertIsNone(payload)
        self.assertIn("forbids", detail)

    def test_every_receipt_we_emit_resolves_to_a_known_lane(self):
        for fixture in sorted(p.name for p in FIX.iterdir()
                              if not p.name.startswith("_")):
            a = unarchive.open_archive(blob(fixture), fixture)
            for r in a.receipts:
                with self.subTest(fixture=fixture, member=r.name):
                    self.assertIn(r.lane, LB.LANE_ORDER)
                    self.assertTrue(r.basis, "receipt has no citable basis")

    def test_no_fixture_yields_bytes_from_an_unauthorised_lane(self):
        receipts = []
        for fixture in sorted(p.name for p in FIX.iterdir()
                              if not p.name.startswith("_")):
            receipts += unarchive.open_archive(blob(fixture), fixture).receipts
        self.assertTrue(LB.audit(receipts, LB.Policy.strict()).clean)


class DispatchTests(unittest.TestCase):

    def test_sniff(self):
        expect = {"zip_store.zip": "zip", "7z_lzma2.7z": "7z",
                  "lz4_text.lz4": "lz4", "lz4_legacy.lz4": "lz4",
                  "rar4_store.rar": "rar4", "rar5_store.rar": "rar5"}
        for fixture, kind in expect.items():
            with self.subTest(fixture=fixture):
                self.assertEqual(unarchive.sniff(blob(fixture)), kind)

    def test_unknown_input_is_reported_not_raised(self):
        a = unarchive.open_archive(b"not an archive at all", "x")
        self.assertEqual(a.members, [])
        self.assertTrue(a.notes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
