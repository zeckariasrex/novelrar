# GEEX-UNPACK

GEEX does not inflate. The unarchiver inflates. GEEX names the recovered
member.

Container handling lives in `src/unarchive.py`, brokered by licence lane
(`src/license_broker.py`, and `docs/LICENSING.md` for the argument).
`src/geex_unpack.py` keeps two jobs of its own:

- **`inflate_trace`** — an independent RFC 1951 inflater (stored, fixed and
  dynamic Huffman) that reports the `(pos, distance, length)` match cloud.
  It exists to *observe* what a DEFLATE stream is doing, not to replace zlib,
  and `process_blob` checks it byte-for-byte against zlib on every ZIP it
  touches. Any disagreement is reported as our bug.
- **`geex_lite`** — cube / shadow / foam scoring, run on **decoded** member
  bytes rather than on container bytes.

Per format:

- **ZIP** — central-directory walk for the index, `zipfile` for decode,
  CRC-32 verified. Methods 0, 8, 12, 14. Data descriptors (GPBF bit 3)
  handled. GPBF bit 0 / bit 6 / method 99 stop.
- **7z** — full container parse including encoded (LZMA-compressed) headers,
  folders, coder graphs, bind pairs and substreams; coders dispatched to
  stdlib `lzma` / `zlib` / `bz2` plus in-tree Delta. AES-256 stops; BCJ2,
  PPMd and Zstd refuse with a reason rather than guessing.
- **LZ4** — full clean-room frame and block decode, all checksums verified.
- **RAR** — headers and stored members. Compressed members go to the HOST
  lane or are refused; RAR LZ+Huffman/PPM is not reimplemented.

See `src/geex_unpack.py`, `src/unarchive.py`.
