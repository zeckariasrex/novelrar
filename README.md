# novelrar

Geometric eval / extract codec and a **windmill dual** of IMO 2025 Problem 6.

This is **not** UnRAR, 7-Zip, or LZ4. It does not contain and does not
reimplement those licensed decompressors. ZIP members are inflated with
the public `zlib` / `zipfile` stack (RFC 1951). RAR and 7z are sniffed
and listed from public headers only. Encrypted archives stop.

Repo: [github.com/zeckariasrex/novelrar](https://github.com/zeckariasrex/novelrar)

## What it is

| Layer | Job |
|---|---|
| **AVCCNMP** | Voxelize a byte block, measure projections / n-grams / curves |
| **GEEX** | Evaluate shadow, shape, surface, visual hull; extract a typed object + XOR residual |
| **UNPACK** | Real unzip-style walk (magic → flags → store/deflate → CRC), then GEEX on members |
| **WINDMILL** | Dual of IMO 2025 P6: maximize reconstructed space from a gap permutation + rectangle recipes |

Lossless contract:

```
original = object XOR residual
```

## Windmill (current headline)

IMO 2025 P6 minimizes rectangles on an `n×n` board with one gap per row
and column. For `n = k²` the minimum is

```
T = k² + 2k − 3
```

(`n = 2025 = 45²` → **2112** tiles). Construction: `(k−1)²` interior
`k×k` squares plus `4(k−1)` boundary rectangles. Gaps:

```
row ≡ k · col  (mod k² + 1)
```

This repo uses the **opposite** objective: store the permutation and one
fill byte per tile, paint the squares, keep an XOR residual. Official
construction now hits `T` exactly:

| k | n | tiles | theory | cells / tile |
|--:|--:|------:|-------:|-------------:|
| 4 | 16 | 21 | 21 | 11.43 |
| 8 | 64 | 77 | 77 | 52.36 |

Erdős–Szekeres is tight on the official `π` (`LIS = LDS = k`).
Constant / planar boards paint with residual zeros = 1.0.
Language and noise are left in the residual.

## Layout

```
src/        Python modules (no third-party codec source)
docs/       specs
results/    measured tables
```

## Run

```bash
python3 -m pip install -r requirements.txt
PYTHONPATH=src python3 src/geex_windmill_v1.py
PYTHONPATH=src python3 src/geex_eval_extract.py
PYTHONPATH=src python3 src/geex_unpack.py
```

## Boundary

- ZIPCrypto / WinZip AES / RAR4 AES-128 / RAR5 AES-256: read the flag, stop.
- Do not vendor `unrar`, 7-Zip, or LZ4 source.
- Geometry is not a key.

## License

Original code in this repository is MIT (see `LICENSE`).
That does not grant rights to RAR, 7-Zip, or LZ4 implementations.
