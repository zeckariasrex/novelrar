# novelrar

Novel geometric eval / extract for byte cubes, plus a windmill dual of
[IMO 2025 Problem 6](https://www.imo-official.org/) as explained in
3Blue1Brown’s *The last IMO problem AI could not solve*.

This is **not** an unrar, 7-Zip, or LZ4 clone. It does not copy licensed
unpacker source. Encrypted archives are refused. ZIP inflate uses public
`zlib` (RFC 1951). RAR and 7z are sniffed and listed only.

Repository: [zeckariasrex/novelrar](https://github.com/zeckariasrex/novelrar)

---

## What this is

Three layers, in the order a real extract tool would run them:

1. **UNPACK** — walk ZIP / RAR / 7z headers like unzip/unrar.
   Encryption flag → stop. Method 0 → copy. Method 8 → `zlib`.
2. **GEEX** — voxelize a member into a cube. Measure shadow, shape,
   surface, visual hull. Classify `planar | shell | tiled | language |
   noise | foam | raster`. Extract a typed object + XOR residual.
3. **WINDMILL** — dual of IMO 2025/6. Gaps are a permutation. Official
   staircase places \((k-1)^2\) interior \(k\\times k\) squares plus
   \(4(k-1)\) boundary rectangles so
   \(T = k^2 + 2k - 3\) exactly. Paint each rectangle. Residual XOR
   keeps the rebuild lossless.

Novelty is the architecture, not beating zlib/LZMA on English text.

---

## Layout

```
src/          Python modules
docs/         specs (AVCCNMP, GEEX, UNPACK, WINDMILL)
results/      measured tables and JSON
```

| module | role |
|---|---|
| `src/avccnmp_codec.py` | AV01 cube + mode projections + cryptic curve |
| `src/avccnmp_cortex.py` | cubic stains, shadows, hull, gated encode |
| `src/geex_eval_extract.py` | typed eval + extract |
| `src/geex_unpack.py` | real ZIP inflate / RAR header walk |
| `src/geex_windmill.py` | dual codec experiments |
| `src/geex_windmill_v1.py` | official π, exact \(T\) |
| `src/geex_windmill_exact.py` | exact \(T\) + Latin-cube 3-D lift |

---

## Windmill (IMO 2025/6 dual)

Video: minimize rectangles on an \(n\\times n\) board with one gap per
row and column. For \(n=k^2\),

\[
T = k^2 + 2k - 3 = n + 2\\sqrt{n} - 3
\]

(\(n=2025=45^2 \\Rightarrow T=2112\)).

This repo inverts the objective: **maximize reconstructed cells per
stored recipe**. Gaps are stored literals. Tiles are paint recipes.

Official permutation (1-based \(a\)):

\[
\\pi(a) \\equiv k\\cdot a \\pmod{k^2+1}
\]

Verified \(k=2\\ldots8\): tile count equals theory. LIS \(=\) LDS \(=k\),
so Erdős–Szekeres is tight.

### FAQ from the video

**How do tiles touch multiple gaps?**
An interior \(k\\times k\) square is pinned by four X’s, one near each
corner, each in a distinct row and column. The tile does not cover the
X’s. The proof maps highlighted *edges* injectively to tiles, so one
square is counted once even though it faces four gaps.

**Why is the windmill efficient?**
Each interior square spends four unique (row, column) anchors and
covers \(k^2\) cells. The staircase packs \((k-1)^2\) of them.
Boundary cost is only \(4(k-1)\). ES + AM-GM says you cannot beat
\(n+2\\sqrt{n}-3\).

**What is Erdős–Szekeres?**
Any sequence of more than \(ab\) distinct numbers has an increasing
subsequence of length \(a+1\) or a decreasing one of length \(b+1\).
For a permutation of \(n\) symbols, \(\\mathrm{LIS}\\cdot\\mathrm{LDS}\\ge n\),
hence \(\\mathrm{LIS}+\\mathrm{LDS}\\ge 2\\sqrt{n}\).

---

## Boundary

| container | this repo |
|---|---|
| ZIP store / deflate | parse headers, `zlib` inflate, CRC-32 |
| ZIP encrypted (GP bit 0 / AES) | refuse |
| RAR4 / RAR5 | magic + public header walk |
| RAR encrypted / packed LZ | refuse / hand off |
| 7z / LZ4 | magic sniff only |

Do not vendor unrar, 7-Zip, or LZ4 source into this tree.

---

## Quick start

```bash
python src/geex_windmill_exact.py
python src/geex_unpack.py
python src/geex_eval_extract.py
```

Requires Python 3.10+ and `numpy` (GEEX eval). `zlib` / `zipfile` are
stdlib.

---

## Findings for the next revision

1. Keep unzip order: sniff → list → refuse crypto → native decode → GEEX.
2. Occupancy-condition period and axis scores (empty cells fake geometry).
3. Official windmill squares, not greedy row-merge, to hit \(T\).
4. Router: \(A\\approx n\) → axis-mode; \(AB\\approx n\) and high paint-agree
   → windmill; paint-agree \(<0.4\) → raw residual.
5. 3-D lift is a Latin cube of holes (one per axis-parallel line).

## License

MIT for original code and docs in this repository.
IMO 2025/6 is cited as the combinatorial source, not copied as an
official statement. 3Blue1Brown’s video is referenced by title only.
