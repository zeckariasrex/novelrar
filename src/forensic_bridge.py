"""Read-only, bounded JSON protocol for forensic hosts. No external extractors.

Input bytes arrive on stdin. Reports never contain decoded payloads or passwords.
This is an inspection/differential-testing API, not an evidence certification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import zlib
import sys

SCHEMA = "novelrar.forensic-bridge"
VERSION = 1
MAX_INPUT = 64 << 20
MAX_OUTPUT = 64 << 20
MAX_MEMBERS = 1000
CODECS = ("gzip", "zlib", "bzip2", "xz", "lz4")


def analyze(blob, operation, codec=None, max_output=MAX_OUTPUT):
    if len(blob) > MAX_INPUT:
        raise ValueError("input limit exceeded")
    if not isinstance(max_output, int) or not 0 <= max_output <= MAX_OUTPUT:
        raise ValueError("output limit must be in [0, 64 MiB]")
    report = {
        "schema": SCHEMA, "schema_version": VERSION, "operation": operation,
        "source_sha256": hashlib.sha256(blob).hexdigest(), "source_bytes": len(blob),
        "writes_performed": False, "external_tools_used": False,
    }
    if operation == "inspect-rar":
        import rar_reader
        archive = rar_reader.read(blob, metadata_only=True, strict=True,
                                  max_members=MAX_MEMBERS)
        report.update(container=archive.version, header_encrypted=archive.header_encrypted,
                      volume=archive.volume, solid=archive.solid,
                      payloads_verified=False, members=[])
        for member in archive.members:
            report["members"].append({
                "name": member.name, "method": member.method_name,
                "packed_bytes": member.pack_size, "unpacked_bytes": member.unp_size,
                "data_offset": member.data_off, "crc32_declared": member.crc32,
                "encrypted": member.encrypted, "solid": member.solid,
                "is_dir": member.is_dir, "extra": member.extra,
            })
        # Structural/header CRC validation does not verify member contents.
        report["inspection_complete"] = not archive.header_encrypted
    elif operation == "digest":
        if codec not in CODECS:
            raise ValueError("unsupported cross-check codec")
        import research_codec
        if codec == "lz4" and not blob:
            raise ValueError("empty input is not an LZ4 frame")
        raw = research_codec.decompress(blob, codec, max_output)
        report.update(codec=codec, decoded_bytes=len(raw),
                      decoded_sha256=hashlib.sha256(raw).hexdigest())
    else:
        raise ValueError("unsupported operation")
    report["ok"] = True
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("inspect-rar", "digest"))
    parser.add_argument("--codec", choices=CODECS)
    parser.add_argument("--max-output", type=int, default=MAX_OUTPUT)
    args = parser.parse_args(argv)
    try:
        blob = sys.stdin.buffer.read(MAX_INPUT + 1)
        result = analyze(blob, args.operation, args.codec, args.max_output)
    except (ValueError, OSError, EOFError, lzma.LZMAError, zlib.error) as exc:
        result = {"schema": SCHEMA, "schema_version": VERSION,
                  "operation": args.operation, "ok": False, "error": str(exc)}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
