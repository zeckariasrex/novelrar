# Independent RAR bitstream research plan

Date: 2026-09-19. Status: plan only. **No compressed RAR codec is implemented
in this increment and none is scheduled by this document.**

This is item 3 of the post-PR-#9 research list. Public container fields
already parsed by `src/rar_reader.py` are not a bitstream specification.

## Why a plan comes before code

RAR's stored path is a documented byte copy (RAR4 method 0x30, RAR5 method 0).
That path is in-tree. The compressed path is a proprietary LZ/PPM family whose
public notes describe *headers, flags, dictionary sizes and method numbers*,
not a complete, versioned grammar of the compressed payload.

Writing a decoder from "the method field is 3" plus remembered folklore is
how independent implementations accidentally become copies of a particular
binary. The licence lane model only works if CLEANROOM means "written from a
cited public grammar that another person can re-derive." That grammar does
not exist here yet. HOST remains the only lawful compressed-RAR path.

## What public material actually specifies

Citable without opening UnRAR, unarr, or libarchive's RAR module:

| Topic | Public source | Enough for a decoder? |
|---|---|---|
| RAR5 block/header CRC, extra records, flags | rarlab technote | Yes, already used |
| Method numbers, dictionary size fields | rarlab technote | Identifies the stage; does not define it |
| RAR4 block types, LONG_BLOCK, file-header layout | historical technote.txt | Yes for headers; no for payload |
| Store payload | same | Yes |
| Solid archives, split volumes | same, at container level | Reconstruction policy only |
| Encrypted headers / file data | same | Out of scope; REFUSED / supplied-password later |
| Compressed match/literal grammar | not in the public notes | **No** |

Expired or published patents can describe *an* LZ variant. They do not
automatically match the bitstream WinRAR emits today, and they are not a
substitute for a current public grammar.

## What this repository will not use as a source

- UnRAR, unrar.dll, unrar source drops, RAR for Linux.
- libarchive RAR code, The Unarchiver, 7-Zip's RAR module, unarr, rardecode.
- Decompilation, tracing, or instruction-level dumps of any of the above.
- "I remember how it worked" reconstructions written while those trees are
  open in another window.

HOST extraction may *invoke* an operator-installed binary. That is a
delegation, not a specification.

## Work items, in order, if compressed-RAR research is ever authorised

1. Freeze the legal question explicitly. If the answer is still "no
   in-tree codec", stop.
2. Collect only public, dated documents. Quote the sentences that define
   tokens. Mark every gap as a gap. Do not fill gaps from a binary.
3. Build a *known-plaintext corpus* without reading decoder source:
   archives created by a public WinRAR/RAR CLI the operator already owns,
   stored vs each advertised method, small alphabets, documented dictionary
   sizes. Keep generation scripts; keep hashes.
4. Write the grammar as a document first: token alphabet, endianness, start
   state, end state, solid-window lifetime, PPM vs LZ switch if any. Review
   that document as if it were the codec.
5. Only then write a bounded parser that emits the same IR `nr_execute`
   already runs. Refuse any stream the grammar does not name.
6. Differential test against the HOST binary on the generated corpus. Any
   mismatch is a grammar bug, not a reason to peek at HOST internals.
7. Sanitizer + output-limit + trailing-byte discipline, same bar as LZ4/DEFLATE.

None of steps 3–7 start in this commit.

## Isolation and HOST

Compressed RAR stays HOST. `src/host_isolate.py` wraps that subprocess in
unprivileged namespaces and rlimits when the kernel allows it. Isolation is
an operational control, not evidence that the payload grammar is understood.

## Success criteria for a future codec increment

- A public grammar document with no "see UnRAR" citations.
- Byte-exact decode of the operator-generated corpus for at least one named
  method, plus documented refusals for the rest.
- No vendored RAR source anywhere in the tree.
- RESEARCH_REPORT separates those measurements from speculation.

Until those exist, a compressed-RAR function in `src/` would be a boundary
violation, not research progress.
