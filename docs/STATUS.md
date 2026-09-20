# Main-line status

Date: 2026-09-19.

## What main is

The landed research increment (PR #9) plus the four follow-up items and the
product extraction path the owner asked for:

1. Native DEFLATE *parsing* (`native/deflate.c`, `parse='native'`).
2. 64 KiB and 1 MiB scale benches with rusage; perf-stat when present.
3. Independent RAR bitstream *plan* only (`docs/RAR_BITSTREAM.md`).
4. Isolated HOST execution (`src/host_isolate.py`, `src/host_handoff.py`).
5. Supplied-password routing: encrypted/compressed members go to HOST or
   OPTIONAL. No password still refuses. No in-tree RAR codec.

Geometric work (GEEX, windmill, NR01, AV01) remains in tree.

## Review decisions

| Change | Decision |
|---|---|
| PR #9 `research/native-codecs` | Squash-merged to `main`. |
| PR #8 `codex/harden-extraction-paths` | Closed. Lexical `Path.resolve` is weaker than `safe_output.write_member`. |
| Post-#9 items 1–4 | Landed on `main`. |
| Encrypted/compressed refusal | Product path is HOST/OPTIONAL when a password is supplied. Default probe stays REFUSED. |
| Topic branches from PRs #3–#7 / #9 | Already in `main`. Delete when a ref-delete token is available. |

GitHub's review API rejects self-APPROVE on this account. The merge to
`main` is the acceptance record.

## Still out of scope

- In-tree compressed RAR encode/decode or RAR password decryption.
- In-tree WinZip AES (supplied password is HOST-only).
- Password search or brute force.
- Treating NRX1 as compatible RAR/ZIP/7z encryption.
- Claiming the microbenchmarks are universal speedups.
- Treating `unshare` + rlimits as a hardened sandbox.

## Next research, in order

1. Streaming archive outputs and solid-group scheduling.
2. Independently implemented RAR4 Unicode name decoding.
3. Broader LZ4 corpora than the synthetic 1 MiB set, on bare metal with
   working perf counters.
4. Execute the RAR bitstream plan only if the policy is explicitly revised.
