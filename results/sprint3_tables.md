# sprint 3 — NR01 + motif + skip-XOR

After Claude/Fable PR #6 (licence broker, draft; not merged here).

## Verify

| k | T | theory | hit |
|--:|--:|-------:|:---:|
| 2 | 5 | 5 | true |
| 3 | 12 | 12 | true |
| 4 | 21 | 21 | true |
| 5 | 32 | 32 | true |
| 8 | 77 | 77 | true |

Latin D=16 holes ok.

## NR01 n=16 (gaps painted before XOR)

| corpus | route | blob/raw | lossless | residual zeros | recipes |
|---|---:|---:|:---:|---:|---|
| planes | axis | 0.695 | true | 1.000 | const x16 |
| checker | official | 0.914 | true | 1.000 | checker x21 |
| shell | official | 1.180 | true | 0.891 | bchk + axis + const |
| english | skip | 0.594 | true | 0.062 | none (text in residual) |
| random | skip | 1.258 | true | 0.070 | none |
| checker2 | official | 1.129 | true | 1.000 | bchk x13 + axis |

Language skip is lossless. The diagonal-XOR bug is gone.

## n=64 size wins

| corpus | blob | raw | ratio | lossless |
|---|---:|---:|---:|:---:|
| planes | 562 | 4096 | 0.137 | true |
| checker | 730 | 4096 | 0.178 | true |

Route: language/noise skip; planar axis; else official windmill.
