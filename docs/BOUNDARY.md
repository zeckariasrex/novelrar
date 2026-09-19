# Implementation boundaries

The project now explicitly permits original assembly/C/Python codec experiments
and ordinary supplied-password operations. The previous blanket no-password
rule was a project choice, not a conclusion that decryption is inherently
unlawful. No password search functionality is included.

## Original research

- LZ4 block encoding and framing from public format documentation.
- Scalar, growing-copy, SSE2 and `rep movsb` match reconstruction.
- RFC1951 parsing into an intermediate representation and native execution.
- Adaptive compression with full-size candidate comparison and raw fallback.
- RAR5 stored-container writing, without a RAR compression implementation.

These are testable implementation experiments. They do not establish patent
noninfringement or scientific novelty. Reusing a format does not automatically
mean copying an implementation; writing assembly does not automatically prove
independence or novelty either.

## Passwords and encryption

- ZIP ZipCrypto: a supplied password is handled by Python's zipfile. Legacy
  confidentiality only; no new ZipCrypto writer is added.
- 7z: explicit optional py7zr backend supports its encryption capabilities.
- NRX1: a separate authenticated envelope using cryptography, not a compatible
  implementation of RAR/ZIP/7z encryption. Fixed scrypt parameters; AES-GCM
  authenticates the header and compressed payload before decompression.
- RAR passwords and ZIP AES remain unsupported.

## Operational limits

Default new stream/envelope output limit is 64 MiB (configurable up to 256 MiB).
Built-in ZIP/7z/LZ4 archive paths have 64 MiB aggregate limits; built-in 7z also
limits individual dictionary sizes. Native LZ4 output is explicitly bounded.
These are not universal process CPU/memory guarantees for every legacy parser.

Filesystem extraction creates files exclusively under no-follow directory
handles on POSIX. Existing destinations, symlinks and hardlinks are not
silently overwritten. Unsupported platforms fail closed. Caller-chosen root
ancestors are outside this mechanism's scope.

The existing HOST subprocess path still trusts installed extractors. It checks
exit status, selectors, exact member paths and returned symlinks, but it is not
a process sandbox and limits are not enforced during backend disk writes.
Use isolation before processing hostile archives with that path. The optional
py7zr backend writes through bounded memory sinks; its parser, dictionary and
KDF allocation behavior remain the backend's responsibility.

`--strict` excludes HOST and OPTIONAL extraction. The audit checks provenance
of successful receipts; PASS does not imply every archive member was extracted
or verified. Archive creation and new standalone stream APIs do not emit
legacy archive receipts. Full streaming archive extraction is future work.
