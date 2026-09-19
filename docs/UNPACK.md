# GEEX-UNPACK

GEEX does not inflate. Unzip inflates. GEEX names the recovered member.

ZIP: sniff PK signatures, refuse GPBF bit 0/6, method 0 store or method 8
DEFLATE via zlib, CRC-32, then GEEX.

RAR: list public headers. HEAD_CRYPT or password flags stop the walk.
Do not reimplement RAR LZ+Huffman.

See `src/geex_unpack.py`.
