# novelrar

Archive extraction and independent codec research: LZ4 encoding/decoding,
DEFLATE command execution, geometric predictors, password handling, and
machine-level copy experiments. Original code is MIT. Independent development
and documented provenance are goals; no patent clearance or algorithmic
novelty is claimed.

`main` is the accepted line. See [status](docs/STATUS.md),
[the implementation and measured-results report](docs/RESEARCH_REPORT.md),
[format boundaries](docs/BOUNDARY.md), and [dependency provenance](docs/LICENSING.md).

## Implemented capabilities

| Format / operation | Implementation |
|---|---|
| ZIP read/write | Store, DEFLATE, bzip2, LZMA through Python; supplied-password ZipCrypto reading |
| Raw DEFLATE | zlib production path; independent Python tracer; experimental command parser + native LZ executor |
| zlib / gzip | In-memory and incremental file-like stream APIs |
| bzip2 / XZ | Bounded in-memory decoding and standard-library encoding |
| LZ4 | Independent block encoder and frame writer; Python decoder; optional original C/SSE2/assembly block kernels |
| 7z | Built-in selected codec chains; explicit optional py7zr read/write, including AES and encrypted headers |
| RAR4 / RAR5 | Metadata and stored extraction; independent RAR5 method-0 writer; existing external compressed extraction |
| NA01 | Experimental adaptive raw / zlib / bzip2 / XZ / row-XOR prediction selection, measured by full encoded size |
| NRX1 | Experimental authenticated password envelope: fixed-cost scrypt + AES-256-GCM through cryptography |
| AV01 / NR01 / GEEX | Existing geometric research, with stricter AV01 length checks |

**RAR compressed decoding, RAR password decryption, and RAR compression are not
implemented in-tree.** NRX1 is a distinct format, not RAR/ZIP/7z encryption.
WinZip AES is still unsupported. The built-in 7z reader still rejects AES,
BCJ2, PPMd and Zstd; explicit `py7zr` selection supports that backend's subset.

The default capability probe still refuses passworded and compressed-RAR
fixtures. That is the unattended policy, not a claim that supplied-password
ZIP/7z paths do not exist. See `results/capability_matrix.md`.

## Install and build

```bash
python -m pip install -r requirements.txt
# Optional encryption and 7z adapters:
python -m pip install -r requirements-crypto.txt -r requirements-backends.txt
# Explicit native build, currently Linux (x86-64 enables SSE2 and assembly):
python scripts/build_native.py
```

Native code is never compiled automatically on import. Python decoding remains
available without a compiler. Assembly uses System V AMD64 `rep movsb`; SSE2
uses bounded unaligned vector loads/stores. ARM uses C scalar/growing-copy modes.
Growing-copy is the default experimental backend because it won the repetitive
LZ4 samples; `asm` is available and is not uniformly faster.

## CLI examples

Commands refuse to overwrite existing output files. Passwords are prompted,
not placed in command arguments or receipts.

```bash
PYTHONPATH=src python src/novelrar_cli.py capabilities
PYTHONPATH=src python src/novelrar_cli.py extract archive.zip -d out --password
PYTHONPATH=src python src/novelrar_cli.py extract archive.7z -d out --backend py7zr --password
PYTHONPATH=src python src/novelrar_cli.py create-zip file.txt -o archive.zip
PYTHONPATH=src python src/novelrar_cli.py create-7z file.txt -o archive.7z --password
PYTHONPATH=src python src/novelrar_cli.py create-rar-store file.txt -o stored.rar
PYTHONPATH=src python src/novelrar_cli.py compress file.txt -o file.lz4 --codec lz4
PYTHONPATH=src python src/novelrar_cli.py decompress file.lz4 -o decoded.txt --codec lz4 --backend grow
PYTHONPATH=src python src/novelrar_cli.py decompress stream.deflate -o decoded.bin --codec deflate --backend asm
PYTHONPATH=src python src/novelrar_cli.py encrypt file.txt -o private.nrx
PYTHONPATH=src python src/novelrar_cli.py decrypt private.nrx -o restored.txt
PYTHONPATH=src python src/novelrar_cli.py --strict audit archive.zip
```

`list` currently decodes members as well as listing them; it is not a cheap
metadata-only operation. CLI operations are in-memory. The separate
`research_codec.transform_stream(source, sink, codec, decode=...)` API handles
incremental raw-DEFLATE/zlib/gzip streams. Its sink is provisional until success.

## Verification

```bash
python -m pip install -r requirements-dev.txt -r requirements-crypto.txt -r requirements-backends.txt
python scripts/build_native.py
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python tests/capability_probe.py
PYTHONPATH=src python scripts/benchmark_research.py
mkdir -p build
cc -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer native/lz4_decode.c native/repeat_x86_64.S native/sanitize_test.c -o build/sanitize_test
./build/sanitize_test
```

The tests include oracle interoperability and negative cases. Optional tests
skip when their backend/native build is absent. Benchmark numbers include FFI,
allocation and equality-check overhead; see the report before interpreting them.

## Existing geometric research

- [GEEX](docs/GEEX.md): geometric evaluation and residual prediction.
- [Windmill](docs/WINDMILL.md), [motifs](docs/MOTIF.md), and `src/geex_nr01.py`:
  reconstruct an original board from a model and XOR residual.
- Historical tables under `results/` are experiments, not general compression
  claims. NA01 provides a separate conservative size-selection experiment.

## Forensic host integration

`src/forensic_bridge.py` provides version-1 JSON over stdout, taking bounded
archive bytes on stdin. It never extracts files, runs external tools, accepts
passwords, or includes decoded payloads in reports.

```bash
python src/forensic_bridge.py inspect-rar < archive.rar
python src/forensic_bridge.py digest --codec lz4 < stream.lz4
```

RAR4/5 inspection is metadata-only: header CRCs and block bounds are checked,
while `payloads_verified` is always false. Encrypted headers return
`inspection_complete: false`; malformed/truncated input returns JSON with
`ok: false` and a nonzero exit. Strict inspection requires an end block;
legacy archives without one are rejected by this interface. The existing
reader remains available with its default non-strict walk.

Digest mode supports gzip, zlib, bzip2, XZ and LZ4. Hosts can compare the
source SHA-256, decoded length and decoded SHA-256 with their own decoder.
Limits: 64 MiB input/output, 1,000 RAR members and 4,100 header blocks.
Only LZ4 accepts concatenated frames; the other digest profiles reject
concatenation/trailing bytes. These are local differential checks, not
interoperability certification. A host must also enforce a subprocess timeout
and report-size cap. No compressed RAR decoder is added by this interface.

## RAR supplied-password extraction and GPU AES

`src/rar_extract.py` now provides bounded RAR4/RAR5 extraction/decryption, with an
original AMD/NVIDIA OpenCL AES path, CPU reference checks and original member
integrity verification. Compressed decoding remains CPU-based. See
[the exact support matrix, dependencies and tests](docs/RAR-ACCELERATION.md).
