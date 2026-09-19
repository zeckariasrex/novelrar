# Boundary

novelrar is a licence-brokered unarchiver plus a geometric eval / extract /
pack prototype. It is not a drop-in archiver and it is not a password tool.

Each bullet below names the lane it runs in; `docs/LICENSING.md` explains the
lanes and `src/license_broker.py` is the machine-readable registry.

## Allowed

- Parse public container headers — ZIP APPNOTE, 7z `7zFormat.txt`, RAR4/RAR5
  block types. (`CLEANROOM`)
- Decode ZIP methods 0, 8, 12, 14 with CPython `zipfile` / `zlib` / `bz2` /
  `lzma`, and verify CRC-32. (`STDLIB`)
- Decode 7z folders whose coders are Copy, LZMA1, LZMA2, Deflate, BZip2,
  Delta, or a BCJ branch filter. (`STDLIB` / `CLEANROOM`)
- Decode LZ4 frames end to end and verify the XXH32 checksums. (`CLEANROOM`)
- Extract RAR stored members (method 0x30 / 0) and list RAR metadata.
  (`CLEANROOM`)
- Hand a compressed RAR member to an `unrar` the **operator** installed, and
  record which binary and version served the bytes. (`HOST`)
- Run GEEX and windmill paint on **decoded** bytes.

## Refused

- ZIP general-purpose bit 0 (ZipCrypto) or bit 6 / method 99 (WinZip AES).
- 7z coder `06F10701` (AES-256), including AES-encrypted headers.
- RAR4 `LHD_PASSWORD` / `MHD_PASSWORD`, RAR5 extra record type 1 and header
  type 4 (`HEAD_CRYPT`).
- Reimplementing RAR's LZ/PPM compression stage from licensed sources, or
  reverse engineering it.
- Password search, KDF grinding, or treating ciphertext foam as a key.
- 7z BCJ2, PPMd and Zstd. All three are legal to implement; none has a
  stdlib path here and nothing in this tree can *write* a BCJ2 archive, so
  an implementation could not be tested. Refused in-tree, routed to `HOST`.
- Any codec absent from the capability registry — unregistered resolves to
  `REFUSED`, so the default is "no", not "try it".

## Handoff

If a real `unrar`, `7z`, `unar` or `lz4` binary is present on the host, the
HOST lane calls it for unencrypted proprietary payloads and stamps the
receipt with its version. Do not paste those programs into this tree.
`--strict` removes the HOST lane entirely and the audit gate fails any run
that used it.
