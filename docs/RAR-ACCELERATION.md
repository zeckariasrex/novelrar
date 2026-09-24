# Bounded RAR extraction and supplied-password acceleration

`src/rar_extract.py` adds a separate extraction worker/library. The older
`forensic_bridge inspect-rar` contract remains read-only metadata inspection.

The worker decrypts RAR4 AES-128-CBC and RAR5 AES-256-CBC, including encrypted
headers. It validates original member CRC32 and BLAKE2sp checksums, including
RAR5 password-dependent HMAC transformations. All members must validate before
any result is returned. Source bytes remain unchanged. This is supplied-password
decryption, not password discovery.

## Execution stages

| Stage | Implementation |
| --- | --- |
| RAR4 key derivation | SHA-1 via Python hashlib, CPU |
| RAR5 key derivation | PBKDF2-HMAC-SHA256 via hashlib, CPU; bounded cost/cache |
| Header AES | cryptography CPU provider with runtime instruction dispatch |
| Payload AES | CPU provider or original OpenCL 1.2 kernel |
| Compressed member decode | System libarchive, or explicitly supplied installed RAR-compatible tool |
| Original integrity + SHA-256 report | CPU |

The OpenCL path accepts actual GPU devices from AMD/NVIDIA, not just an installed
loader. Each device must first pass AES-128 and AES-256 tests against the
independent cryptography provider. `backend='gpu'` fails if initialization fails;
`auto` considers GPU payloads starting at 256 KiB, otherwise uses CPU. This is a
conservative transfer threshold, not a measured crossover point. Runtime GPU
failures are fatal. `verify_gpu=True` compares every decrypted byte with CPU AES.

One AES block runs per work-item. The kernel uses 16-byte vector loads/stores,
private round state, constant round keys, and reusable input/output arenas capped
at 8 MiB each. CBC chaining carries the previous ciphertext across chunks. The
runtime selects workgroup size, avoiding assumptions about AMD/NVIDIA wave widths.
No password-dependent tables are placed in shared local memory, but this kernel
is **not claimed constant-time**. There are no speculative ISA flags, forced
AVX-512 requirements, pinned-memory claims, or zero-copy claims. The CPU provider
controls its own ISA dispatch; Quarry's native `--isa baseline` does not control it.

## Decoder choices and bounds

Python 3.10+ and `requirements-crypto.txt` are needed for encrypted archives.
The default CPU decoder is the system's BSD-licensed libarchive. Its capabilities
vary by installed version. Tested with libarchive 3.7.2: stored/compressed RAR4
non-solid; stored/compressed/solid RAR5; archives created by RAR 7.23 using compatible
compression. RAR4 solid requires the explicit external decoder on that version.

`rar_tool='/absolute/path/to/installed/decoder'` opts into a RAR-compatible `p`
command for modern/solid decoding. The tool receives **no password or AES key**,
only an already-decrypted normalized archive in a private temporary directory.
It streams bytes to bounded stdout and never extracts archive paths. No decoder
binary or restricted decoder source is bundled. Install/license that tool
separately. Plain decrypted compressed data exists temporarily on disk in this
mode; the directory is removed on ordinary completion/failure. OS crash, forced
termination and Python/driver memory copies prevent a secure-erasure guarantee.
The report explicitly identifies external use and temporary plaintext.

Limits: 64 MiB input, 64 MiB total output/dictionary, 1,000 members, 4,100 headers,
RAR5 KDF exponent at most 20 and aggregate KDF budget. Reject SFX prefixes,
multivolume/split entries, links/copies/special files, duplicate/case-alias paths,
traversal, absent supported checksums, unknown mandatory features and trailing data.
RAR4 passwords over 28 UTF-16 units and legacy delta-encoded Unicode names are
currently refused rather than misinterpreted. RAR7 dictionaries above 64 MiB are
refused even with the external decoder. Native RAR7 version-1 compression is not
implemented here; external decoding remains necessary for incompatible methods.

Checksums prove agreement with archive contents, not authenticity or provenance
of an untrusted archive. KDF and decompression remain CPU stages. This is **GPU AES
acceleration**, not GPU RAR decompression or a performance certification.

## Verification

`PYTHONPATH=src NOVELRAR_TEST_OPENCL=1 python -m unittest discover -s tests -p test_rar_acceleration.py -v`

CI installs POCL and libarchive. The test-only CPU OpenCL selector is not reachable
from the production CLI. For physical AMD/NVIDIA testing set
`NOVELRAR_TEST_GPU=1` as well. Optional installed decoder tests require
`NOVELRAR_RAR_TOOL=/absolute/path/to/decoder`.

Tests cover real RAR4/RAR5 encrypted payloads and headers, keyed CRC/BLAKE2sp,
solid RAR5, archives made with RAR 7.23, wrong/missing passwords, corrupt/truncated
input, path and resource refusals, injected GPU disagreement, AES-128/256 chunk
boundaries and arena reuse. POCL execution and CPU comparisons passed locally;
physical AMD/NVIDIA measurements remain outstanding. No throughput claim is made.

## Sources and fixture provenance

Format definitions: https://www.rarlab.com/technote.htm . KDF conventions checked
against Marko Kreen's ISC-licensed rarfile project, https://github.com/markokr/rarfile
(commit d2f7df6fc843dae356fd6b0a85971dc36fd6e757).
BLAKE2 tree parameters: https://www.blake2.net/ . No restricted decoder source was
copied into these modules.

`tests/rar_fixtures/archives.json` stores byte-exact base64 archives and
SHA-256 identities. Rarfile fixtures retain its ISC notice in `LICENSE-rarfile`.
RAR4 AES fixtures wrap one real compressed rarfile member with independent rarfile
KDF + cryptography encryption and were tested by an installed reference decoder.
The RAR 7.23 fixture contains our generated repeated text. Reference tool binaries
are not included. Expected recovered text is fixed independently in the tests.
