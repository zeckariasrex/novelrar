# Native codec research implementation report

Date: 2026-09-19. Base commit: `41d00941e003c73a55a3fbb43e4ab552dae0f275`.
This report accompanies the `research/native-codecs` branch.

## Outcome

Implemented original machine-level LZ4 decoding experiments, an independent
LZ4 encoder, a DEFLATE command intermediate representation with native
execution, adaptive compression, ordinary supplied-password operations,
RAR5 stored writing, and regression fixes. The code builds locally and the
verification below passes. This is a research release, not a complete universal
archiver or a claim to have implemented every possible enhancement.

The main performance finding is workload-dependent: growing-copy LZ expansion
wins several repetitive LZ4 microbenchmarks; `rep movsb` is not uniformly faster.
The native DEFLATE IR path is correct on the tested corpus but loses to both
zlib and the improved Python periodic tracer here. Keep it opt-in; move parsing
into native code or batch more efficiently before proposing a production switch.

## Original implementations

1. `native/lz4_decode.c`: bounded block grammar, four match reconstruction modes.
   Growing-copy expands an initialized seed using successively larger disjoint
   `memcpy` calls. SSE2 issues 16-byte loads/stores only when the back-distance
   permits them; short matches use growing-copy. No deliberate overreads.
2. `native/repeat_x86_64.S`: original System V AMD64 forward `rep movsb` routine.
   Forward overlap is intentional because LZ matches can reproduce their own
   newly written bytes. Source/destination bounds are checked by C callers.
3. `src/lz4_encode.py`: greedy 4-byte dictionary matching; compliant final-literal
   restrictions; independent-block frames with content size and checksum. Stores
   blocks when encoding them would grow the block.
4. `src/deflate_ir.py`: parses stored/fixed/dynamic Huffman blocks using existing
   original parser helpers; emits literal/match commands; reconstructs the output
   through the shared C executor without zlib producing the decoded bytes.
5. `src/research_codec.py`: NA01 selection between raw storage, zlib, bzip2, XZ,
   and row-XOR predictors with strides 1/16/64/256. Selection includes transform
   metadata. The invariant is encoded size <= input size + 45-byte container
   header; it does not promise every input gets smaller.
6. `src/rar_store.py`: public RAR5 container construction with method 0. Validated
   with both this repo's reader and independently installed libarchive. It does
   not compress payloads and is not a RAR compressed-format implementation.

The proposed generated Huffman machine-code/JIT and dependency-parallel RAR
research have not been implemented. The code does not claim that known ideas
such as periodic expansion or SIMD copying are themselves novel inventions.

## Other implemented functionality

- Standard stream compression/decompression: raw DEFLATE, zlib, gzip, bzip2, XZ,
  LZ4, and adaptive NA01. Raw/zlib/gzip also have incremental file-like APIs.
- ZIP writing with store/DEFLATE/bzip2/LZMA and supplied-password ZipCrypto reading.
- Explicit optional py7zr adapter: in-memory 7z read/write, supplied passwords,
  encrypted headers, aggregate output sinks and member checksum/size checks.
- NRX1 password envelope: random 16-byte salt, random 12-byte nonce, fixed scrypt
  N=16384/r=8/p=1 deriving a 32-byte key, AES-256-GCM with 16-byte tag. Header is
  authenticated associated data. Authentication completes before decompression.
  This is an experimental envelope and has not received an independent crypto
  protocol audit. It is not a substitute name for RAR/ZIP/7z encryption.
- CLI commands for creation, compression, decompression, encryption and decryption;
  native strategy selection for LZ4 frames and raw DEFLATE; interactive passwords.

## Correctness and extraction changes

- Restored the missing committed fixture payload helper: the baseline test suite
  otherwise failed to import before running a single test.
- Python LZ4 checks literal and match limits before growth, enforces aggregate
  frame limits, checks skippable-header truncation, and uses periodic expansion.
- DEFLATE tracer bounds output and rejects reserved symbols, oversubscribed
  Huffman trees and malformed dynamic length lists.
- RAR checks zero-valued CRCs, validates header CRCs and filename/header bounds,
  and refuses to expose a split stored member as a complete file.
- 7z rejects header CRC failures, excessive dictionary/output sizes and decoded
  size mismatches; failed member CRCs no longer expose a payload.
- AV01 rejects incorrect cube/output/block lengths instead of padding/truncating
  reconstructed data. AV01 remains experimental and lacks whole-stream checksums.
- POSIX extraction uses directory descriptors/no-follow operations and exclusive
  creation. Tests cover destination symlinks and overwrite refusal.
- HOST extraction requires a successful exit, exact output identity and no output
  symlinks, and rejects unsafe/ambiguous selectors. It is still not sandboxed.
- Provenance documentation no longer treats a project refusal as proof that
  independent implementation or supplied-password decryption is unlawful.

## Validation

- 58 unittest tests passed locally with native, cryptography, py7zr and python-lz4
  available. Includes existing tests and new differential/negative/integration
  tests. Native overlap testing covers distances 1..256 and dictionary prefixes.
- Independent liblz4 decodes the new encoder's blocks and frames; all four native
  strategies decode independently authored oracle blocks, including 100 seeded
  cases. RAR5 stored output was independently read by libarchive.
- AddressSanitizer + UndefinedBehaviorSanitizer harness: 50,000 malformed LZ4
  inputs and 10,000 shared-IR trials, each across four strategies; no reported
  errors or output disagreements. Assembly instructions themselves are not
  compiler-instrumented. This is finite testing, not proof of memory safety.
- This managed runtime prevents LeakSanitizer's ptrace-based inspection; local
  sanitizer invocation used `ASAN_OPTIONS=detect_leaks=0`. Address/UB checks
  remained enabled. The GitHub workflow uses default sanitizer settings.
- Existing capability probe: ZIP 11/11, 7z 21/21, RAR stored 6/6, LZ4 11/11
  decoded streams bit-exact. Refusal fixtures remain refused without an explicit
  password/backend. These RAR “compressed” fixtures use opaque synthetic payloads
  and do NOT establish compatibility with real compressed RAR files.
- Compileall and git whitespace checks passed. A CI workflow was added; local
  results do not imply that remote CI has already completed.

## Measured LZ4 decoding

MiB/s; larger is faster. Each input is 65,536 bytes. Oracle-compressed block
input is identical for all variants. Five timing samples, 20 repetitions per
sample, median per-call time; includes allocation, FFI and equality checking.
No branch/cache hardware counters were collected. These small hot-cache samples
are not representative of all archives or end-to-end filesystem extraction.

| Corpus | Python periodic | C scalar | Growing copy | SSE2 | Assembly | liblz4 oracle |
|---|---:|---:|---:|---:|---:|---:|
| repeat1 | 2347.8 | 474.4 | 7637.5 | 7435.4 | 331.9 | 8636.3 |
| period3 | 3303.4 | 1424.7 | 9713.0 | 9484.1 | 1014.1 | 1323.6 |
| text | 3085.2 | 3297.3 | 9693.4 | 3439.5 | 3250.0 | 4167.2 |
| ramp | 2832.9 | 9296.9 | 9741.8 | 9159.8 | 9676.0 | 14409.1 |
| random | 3328.7 | 8974.1 | 8973.4 | 8766.7 | 8836.9 | 14749.6 |

## Measured raw DEFLATE decoding

MiB/s. Tracer/IR timing uses two iterations per sample; zlib uses twenty.
All timings include complete parsing and reconstruction, not just copy kernels.
Random input can take the stored-block path and is not an entropy-decoding test.

| Corpus | Python scalar | Python periodic | Native IR growing copy | zlib |
|---|---:|---:|---:|---:|
| repeat1 | 29.2 | 198.8 | 133.0 | 519.5 |
| period3 | 30.6 | 194.4 | 144.0 | 1372.3 |
| text | 23.8 | 140.3 | 117.5 | 3199.8 |
| ramp | 18.9 | 64.9 | 46.4 | 3003.6 |
| random | 4541.8 | 4727.7 | 2897.2 | 9695.6 |

## Encoded size, including format metadata

Bytes for each 65,536-byte input. NA01 is called “adaptive” below. Encoding
latency was recorded as a single observation per candidate and is exploratory;
see JSON rather than drawing reliable timing conclusions from it.

| Corpus | Raw | zlib | XZ | Independent LZ4 frame | Adaptive NA01 |
|---|---:|---:|---:|---:|---:|
| repeat1 | 65536 | 85 | 140 | 294 | 88 |
| period3 | 65536 | 87 | 144 | 296 | 93 |
| text | 65536 | 255 | 180 | 337 | 206 |
| ramp | 65536 | 585 | 372 | 549 | 320 |
| random | 65536 | 65562 | 65600 | 65563 | 65581 |

## Remaining limitations and next research

- Native RAR compressed decoding/encoding and RAR password decryption are not
  implemented. Public container fields alone are not a complete compressed
  bitstream specification. This increment did not inspect proprietary decoder
  source or establish a complete independent RAR codec provenance plan.
- WinZip AES is not implemented. py7zr is an optional dependency, not original
  compression research. Built-in unsupported 7z codecs are not automatically
  routed to HOST despite older documentation claiming that; select py7zr
  explicitly for the subset it supports.
- Full archive streaming, solid-group scheduling, multivolume reconstruction,
  independently implemented RAR4 Unicode name decoding and JIT Huffman kernels
  remain future work. “List” and normal CLI inputs still materialize data.
- HOST tools may write before this library can verify output. The optional 7z
  parser/KDF/dictionary allocations are not globally constrained by the memory
  sink. Use process isolation for hostile inputs; this is not a hardened service.
- Default 64 MiB limits may reject valid large archives. POSIX safe extraction
  currently fails closed on unsupported systems. Native build script is Linux;
  SSE2/assembly tests and benchmarks were run only on x86-64.
- NA01 predictors are row-XOR experiments, not the existing NR01 windmill codec.
  The latter's full adaptive integration needs further malformed-input hardening.
- Python does not guarantee zeroization of immutable password/key objects.
- No broad-corpus performance win, formal novelty, or patent noninfringement has
  been established. Current results support experiments, not those conclusions.

Next priorities: full native DEFLATE parsing versus the current Python IR setup
cost; real-world LZ4 corpora and perf counters; a documented independent RAR
bitstream research plan; isolated backend execution; streaming archive outputs.

## Reproduction and provenance

Commands are in README.md. Machine-readable measurements are in
`results/native_research_benchmark.json`; the benchmark script records platform,
compiler and Python version. The exact package versions used locally were
py7zr 1.1.3, cryptography 46.0.0, and python-lz4 4.4.5.

Technical bases: [LZ4 block specification](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md),
[LZ4 frame specification](https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md),
[RFC1951](https://www.rfc-editor.org/rfc/rfc1951),
[RAR5 format](https://www.rarlab.com/technote.htm),
[py7zr API](https://py7zr.readthedocs.io/en/latest/api.html),
[cryptography AEAD API](https://cryptography.io/en/latest/hazmat/primitives/aead/).
See LICENSING.md for dependency boundaries.
