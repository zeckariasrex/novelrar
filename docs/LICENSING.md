# The licence problem, and what this repo does about it

The brief was a **novel** way to deal with the licensing of proprietary
decompressors — explicitly *not* a faster or better decompressor. This is the
answer, and it starts by narrowing the problem, because most of "the
proprietary decompression licensing problem" turns out not to exist.

## 1. Three of the four formats have no licence problem at all

| format | the actual licence situation |
|---|---|
| **ZIP** | PKWARE's APPNOTE is a public specification. DEFLATE is RFC 1951. CPython already ships `zlib`, `bz2` and `lzma`, so methods 0, 8, 12 and 14 are free. |
| **LZ4** | The block, frame and xxHash specs are published by Yann Collet under a BSD-2-Clause / CC0-equivalent grant that *invites* independent implementation. There has never been an obstacle. |
| **7-Zip** | Igor Pavlov placed the **LZMA SDK in the public domain**, and `DOC/7zFormat.txt` with it. liblzma — inside CPython as `lzma` — descends from that SDK. A non-encrypted 7z archive needs no licensed code; only a container parser was ever missing. |
| **RAR** | This one is real. The unrar sources may be used to *read* RAR archives, but not to recreate the RAR compression algorithm, and not to reverse engineer it. |

So the licence surface is not four formats. It is **one stage of one format**:
RAR's compressed LZ/PPM payload. Everything else was an absence of code, not
an absence of rights — and the repo previously refused all four alike, which
conceded far more than the law requires.

## 2. Lanes: make the boundary a property of the code

Every decode path is tagged with a lane, in `src/license_broker.py`:

| lane | meaning |
|---|---|
| `STDLIB` | A permissive library already inside CPython. Nothing vendored; CPython has discharged the obligation. |
| `CLEANROOM` | Written in this tree from a published specification that permits independent implementation. Each entry cites its document. |
| `HOST` | Delegated to a binary **the operator installed**. Never shipped, never linked, never copied from. The receipt records which binary and version served the bytes. |
| `REFUSED` | No lawful path. Encrypted payloads and RAR's compressed stage live here and stay here. |

An unregistered codec resolves to `REFUSED`. The default is "no", not "try it".

## 3. Receipts: say where every byte came from

Extraction returns a `Receipt` per stream — container, coder chain, lane,
licence, the citable basis, and how the bytes were verified (CRC-32,
xxHash-32). A pipeline can then answer a question it previously could not:
*under what licence did this byte arrive?*

```
   lane      fmt   codecs                     bytes  verified     member
ok STDLIB    7z    lzma2 -> bcj-x86            5320  CRC-32 ok    text.txt
-- HOST      rar   rar-normal                                     big.bin  [no operator-installed extractor on PATH]
-- REFUSED   zip   zipcrypto                                      secret.txt
```

## 4. The audit gate: fail the build, not the legal review

```bash
PYTHONPATH=src python3 src/novelrar_cli.py audit corpus/*.rar --strict
```

`--strict` drops the `HOST` lane. Any byte that came from an external binary
becomes a violation and the command exits non-zero. A shop that cannot accept
a `HOST` dependency finds out at extraction time, in CI, instead of at legal
review months later.

```
audit[strict-no-host] 1/1 streams extracted; lanes HOST=1
FAIL: 1 stream(s) outside policy:
  - big.bin: 999 bytes via lane HOST (rar-normal, operator's own unrar install)
    — not permitted by policy 'strict-no-host'
```

## 5. What this does not claim

It is not faster than the native tools and does not try to be — the point of
`HOST` is that when a native tool is the right answer, you call it and say so.
It does not decode RAR's compressed stage, and nothing here is a step toward
doing so. It does not touch encryption: no password is derived, tried, or
accepted anywhere in the tree, so an encrypted archive is a refusal and never
a puzzle.

The novelty claim is deliberately modest, and architectural rather than
algorithmic: **the licence status of a decompression pipeline becomes a
checkable property of a run** instead of a paragraph in a README that nobody
can test.

## 6. One note on the BCJ shim

liblzma exposes its branch filters (BCJ x86, ARM, PPC, …) only as part of a
raw filter chain ending in a compressor, so a 7z folder that applies BCJ as a
separate coder has nowhere to call. Rather than reimplement the filter,
`sevenzip._branch_unfilter` wraps the payload in a throwaway LZMA2 layer and
lets liblzma unfilter it on the way back out. The filter stays liblzma's
public-domain code; we only arrange the call. Validated bit-exactly against a
200 KB x86-64 ELF.
