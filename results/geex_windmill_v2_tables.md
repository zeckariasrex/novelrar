# windmill v2 results

Measured 2026-09-19. Official construction still hits `T = k² + 2k − 3`.
Motif fill is constant / row / col / period-2 / checker / 2×2, scored as `residual_nonzero + motif_bytes`.

## construction

| k | n | T | theory | hit | LIS | LDS |
|--:|--:|--:|-------:|:---:|----:|----:|
| 2 | 4 | 5 | 5 | true | 2 | 2 |
| 3 | 9 | 12 | 12 | true | 3 | 3 |
| 4 | 16 | 21 | 21 | true | 4 | 4 |
| 5 | 25 | 32 | 32 | true | 5 | 5 |
| 8 | 64 | 77 | 77 | true | 8 | 8 |

IMO 2025 P6: n=2025 k=45 T=2112.

## n=16 motif vs single-mode paint

| corpus | how | T | mode_zf | motif_zf | gain | blob/raw | sha |
|---|---|---:|---:|---:|---:|---:|:---:|
| planes | official | 21 | 0.359 | 1.000 | +0.641 | 1.344 | true |
| tiles8 | official | 21 | 0.891 | 0.969 | +0.078 | 1.344 | true |
| shell | official | 21 | 0.750 | 0.875 | +0.125 | 1.801 | true |
| checker | data | 30 | 0.562 | 1.000 | +0.438 | 1.535 | true |
| gradient | official | 21 | 0.144 | 0.453 | +0.309 | 4.172 | true |
| english | data | 33 | 0.328 | 0.457 | +0.129 | 4.441 | true |
| random | data | 34 | 0.211 | 0.508 | +0.297 | 4.391 | true |

Header tax dominates at n=16. First size wins at n=64:

| corpus | T | hit_T | motif_zf | blob/raw | sha |
|---|---:|:---:|---:|---:|:---:|
| planes | 77 | true | 1.000 | 0.360 | true |
| checker | 77 | true | 1.000 | 0.250 | true |
| english | 77 | true | 0.246 | 4.023 | true |

## pipeline

stdlib `zipfile` (DEFLATE / zlib) → 16×16 slice → NR01.

- zip/planes: official, SHA ok
- zip/shell: official, SHA ok
- zip/english: GEEX class=language → skip path; skip XOR bug on the diagonal, SHA miss. Fix: paint gap literals before XOR residual.

Language and noise should skip paint (residual holds the text). Geometry is not a key.
