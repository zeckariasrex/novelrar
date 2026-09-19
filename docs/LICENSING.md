# Provenance and dependency accounting

Original novelrar code is MIT; see LICENSE. No upstream decompressor source was
copied or translated for the native LZ4 / DEFLATE-IR experiments. They use the
published format grammar plus existing original parser helpers in this repo.
The assembly is a small original System V AMD64 routine using `rep movsb`.

| Lane | Meaning |
|---|---|
| STDLIB | Python standard-library implementation; underlying libraries have their own terms |
| CLEANROOM | Project implementation with a documented public-format basis; not a legal certification |
| HOST | Operator-installed executable, with runtime identity recorded |
| OPTIONAL | Explicit third-party Python adapter with its own dependency terms |
| REFUSED | Unsupported, disabled, or unavailable in the selected path |

A receipt records a chosen implementation path. It cannot establish a legal
right for every deployment, and refusing a codec does not mean that codec is
inherently unlawful. Invoking an external binary does not remove its terms.

## Dependencies

- CPython zipfile/zlib/bz2/lzma retain their respective Python and underlying
  library licenses. No categorical claim is made that all liblzma code is
  public domain or that CPython automatically discharges redistribution duties.
- Optional py7zr metadata reports LGPL-2.1-or-later. Its transitive dependencies
  have separate terms. It is not vendored here.
- Optional cryptography metadata reports Apache-2.0 OR BSD-3-Clause. Its native
  dependencies also have their own terms. It is not vendored here.
- python-lz4 / liblz4 are test and benchmark oracles, not runtime dependencies
  of the original encoder/native decoder. libarchive is an optional RAR writer
  test oracle discovered on the host.
- UnRAR / other host extractors remain separately installed. No RAR compressed
  decoder source was examined, copied, or adapted in this research increment.

## Technical sources

- LZ4 block grammar: https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
- LZ4 frame grammar: https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md
- DEFLATE grammar: https://www.rfc-editor.org/rfc/rfc1951
- RAR5 container fields: https://www.rarlab.com/technote.htm
- py7zr adapter API: https://py7zr.readthedocs.io/en/latest/api.html
- cryptography AEAD API: https://cryptography.io/en/latest/hazmat/primitives/aead/

Format compatibility, copyright provenance, patent clearance, and performance
novelty are separate questions. This repository documents the first two as
engineering evidence; it does not promise patent clearance or a legal opinion.
