# novelrar

A licence-brokered unarchiver, plus a geometric eval/extract codec and a
**windmill dual** of IMO 2025 Problem 6.

This is **not** UnRAR, 7-Zip, or LZ4. It vendors no decompressor source.
What it does instead is make the licence status of every extracted byte a
checkable property of a run — see **[docs/LICENSING.md](docs/LICENSING.md)**,
which is the centre of the project.

Repo: [github.com/zeckariasrex/novelrar](https://github.com/zeckariasrex/novelrar)

## Can it actually unzip / decompress rar, 7z, zip, lz4?

Measured, byte-for-byte, by `tests/capability_probe.py`:

| format | status | how |
|---|---|---|
| **ZIP** | **yes** — store, DEFLATE, bzip2, LZMA, streamed (data descriptor) | CPython `zipfile`/`zlib`/`bz2`/`lzma`, plus an independent RFC 1951 inflater that is cross-checked against zlib on every run |
| **LZ4** | **yes** — modern, legacy and skippable frames; linked and independent blocks; stored blocks; all three checksums | clean-room decoder from the public LZ4 specs, incl. XXH32 |
| **7z** | **yes** — copy, LZMA1, LZMA2, BZip2, Deflate, Delta, BCJ branch filters, encoded headers, solid archives. BCJ2/PPMd/Zstd refuse cleanly. | clean-room container parser over public-domain codecs already in CPython |
| **RAR** | **partly, by design** — full metadata, and stored members extract exactly. Compressed members are handed to an operator-installed `unrar`, or refused. | RAR's compressed stage is the one genuine licence obstacle; it is not implemented, translated, or reverse engineered |
| encrypted, any format | **refused** | ZipCrypto, WinZip AES, 7z AES-256, RAR4/RAR5 AES. No password is derived, tried, or accepted. |

```
ZIP    6 fixtures  11/11 streams bit-exact  1 correctly refused
7z    10 fixtures  21/21 streams bit-exact  3 correctly refused
RAR    7 fixtures   6/6  streams bit-exact  5 correctly refused
LZ4   11 fixtures  11/11 streams bit-exact  0 correctly refused
```

Full table: [results/capability_matrix.md](results/capability_matrix.md).

Before this pass, ZIP worked, RAR5 store worked, **RAR4 was broken outright**
(`0x8000` is `LONG_BLOCK`, present on every file header — it was read as
header encryption, so the walk aborted on the first file of every archive),
and 7z and LZ4 were magic-number sniffing with no decode path at all.

## The licence argument, in one paragraph

Three of the four formats never had a licence problem. ZIP is a public
specification over RFC 1951. The LZ4 block/frame/xxHash specs are published
under a BSD-2-Clause/CC0-equivalent grant that invites independent
implementation. The LZMA SDK — and `7zFormat.txt` with it — is **public
domain**, and liblzma already ships inside CPython, so a non-encrypted 7z
archive needs no licensed code; only a container parser was missing. The real
obstacle is one stage of one format: RAR's compressed LZ/PPM payload. So the
answer is not to reimplement anything, it is to **name the lane every byte
came out of and let a policy fail the build**.

| lane | meaning |
|---|---|
| `STDLIB` | permissive library already inside CPython |
| `CLEANROOM` | written here from a cited public specification |
| `HOST` | delegated to a binary the operator installed; never shipped |
| `REFUSED` | no lawful path — encryption, and RAR's compressed stage |

## Run

```bash
python3 -m pip install -r requirements.txt

PYTHONPATH=src python3 src/novelrar_cli.py capabilities
PYTHONPATH=src python3 src/novelrar_cli.py list    tests/fixtures/7z_bcj_lzma2.7z
PYTHONPATH=src python3 src/novelrar_cli.py extract ARCHIVE -d out
PYTHONPATH=src python3 src/novelrar_cli.py audit   ARCHIVE... --strict   # exits 2 on violation

PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 tests/capability_probe.py
```

Regenerating fixtures needs the dev oracles (`pip install -r
requirements-dev.txt`); running the tests does not — fixtures are committed.

## Layout

| path | job |
|---|---|
| `src/license_broker.py` | lanes, capability registry, receipts, audit gate, HOST handoff |
| `src/unarchive.py` | one entry point over every container, receipt per member |
| `src/lz4_frame.py` | clean-room LZ4 frame + block + XXH32 |
| `src/sevenzip.py` | clean-room 7z container parser, coder graph over stdlib codecs |
| `src/rar_reader.py` | RAR4/RAR5 headers; stored members only, by design |
| `src/geex_unpack.py` | RFC 1951 match-cloud tracer, GEEX scoring on decoded bytes |
| `src/geex_eval_extract.py` | GEEX: voxelize, classify, object + XOR residual |
| `src/geex_windmill_v1.py` | windmill dual of IMO 2025 P6 |
| `src/avccnmp_codec.py` | AV01 experimental codec + dispatch |
| `tests/` | fixtures, test suite, capability probe |

## GEEX and the windmill (unchanged by this pass)

A block of bytes is packed into a cube; cortex columns measure shadow, shape
and surface; a router emits a typed geometric object. Reconstruction is
bit-exact:

```
original = object XOR residual
```

IMO 2025 P6 minimises rectangles on an `n×n` board with one gap per row and
column. For `n = k²` the minimum is `T = k² + 2k − 3` (`n = 2025 = 45²` →
**2112**). This repo uses the opposite objective: store the permutation and
one fill per tile, paint, keep an XOR residual.

| k | n | tiles | theory | cells / tile |
|--:|--:|------:|-------:|-------------:|
| 4 | 16 | 21 | 21 | 11.43 |
| 8 | 64 | 77 | 77 | 52.36 |

## Boundary

- Encrypted anything: read the flag, stop. No password handling exists.
- Do not vendor `unrar`, 7-Zip, or LZ4 source.
- Geometry is not a key.

## License

Original code in this repository is MIT (see `LICENSE`). That does not grant
rights to RAR, 7-Zip, or LZ4 implementations. See `NOTICE`.
