# Boundary

novelrar is a geometric eval / extract / pack prototype. It is not a drop-in
archiver and it is not a password tool.

## Allowed

- Parse public container headers (ZIP APPNOTE, RAR4/RAR5 block types).
- Decode unencrypted ZIP method 0 (store) and method 8 (DEFLATE) with
  Python `zipfile` / `zlib` (RFC 1951).
- Verify CRC-32 of ZIP members.
- Run GEEX and windmill paint on **decoded** bytes.
- List RAR file names when headers are not encrypted.

## Refused

- ZIP general-purpose bit 0 (traditional encryption) or bit 6 (strong / AES).
- RAR4 `LHD_PASSWORD` / `MHD_PASSWORD`, RAR5 header type 4 (`HEAD_CRYPT`).
- Reimplementing RAR LZ+Huffman, 7-Zip LZMA2, or LZ4 frame decode from
  licensed sources.
- Password search, KDF grinding, or treating ciphertext foam as a key.

## Handoff

If a real `unrar`, `7z`, or `lz4` binary is present on the host, call it for
unencrypted proprietary payloads. Do not paste those programs into this tree.
