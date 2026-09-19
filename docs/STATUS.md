# Main-line status

Date: 2026-09-19. `main` is `8b146137` (squash of PR #9) plus this
housekeeping commit.

## What main is

The landed research increment: independent LZ4 encode/decode, optional
native match kernels, DEFLATE IR (opt-in), NA01, stored RAR5 write,
supplied-password ZIP/optional-7z, NRX1 envelope, POSIX no-follow
extraction, and the measured report in `docs/RESEARCH_REPORT.md`.

Geometric work (GEEX, windmill, NR01, AV01) remains in tree. It is not
replaced by NA01.

## Review decisions

| Change | Decision |
|---|---|
| PR #9 `research/native-codecs` | Squash-merged to `main`. |
| PR #8 `codex/harden-extraction-paths` | Closed. Lexical `Path.resolve` is weaker than `safe_output.write_member`. |
| Topic branches from PRs #3–#7 | Already in `main`. Delete when the GitHub UI or a ref-delete token is available. |

GitHub's review API rejects self-APPROVE on this account. The squash
merge is the acceptance record.

## Still out of scope

- In-tree compressed RAR encode/decode or RAR password decryption.
- WinZip AES.
- Treating NRX1 as compatible RAR/ZIP/7z encryption.
- Claiming the microbenchmarks are universal speedups.

## Next research, in order

1. Native DEFLATE *parsing* (not just match replay) if the Python IR
   setup cost remains the measured bottleneck.
2. Real LZ4 corpora and hardware counters, not only 64 KiB hot-cache
   samples.
3. A written independent RAR *bitstream* research plan before any codec
   attempt. Public container fields are not that plan.
4. Isolated HOST execution; the current subprocess path is not a sandbox.
