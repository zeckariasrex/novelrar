# mode vs motif (first 16x16 slice)

| corpus | fill | T | zf | hist | lossless |
|---|---|---|---|---|---|
| planes | mode | 21 | 1.000 | const x21 | True |
| planes | motif | 21 | 1.000 | const x21 | True |
| tiles8 | mode | 21 | 0.145 | const x21 | True |
| tiles8 | motif | 21 | 0.453 | cell2 9, axis_row 6, axis_col 6 | True |
| shell | mode | 21 | 1.000 | const x21 | True |
| shell | motif | 21 | 1.000 | const x21 | True |
| english | mode | 21 | 0.262 | const x21 | True |
| english | motif | 21 | 0.516 | cell2 5, axis_row 7, axis_col 9 | True |
| random | mode | 21 | 0.160 | const x21 | True |
| random | motif | 21 | 0.465 | cell2 8, axis_row 6, axis_col 7 | True |
| checker | mode | 21 | 0.531 | const x21 | True |
| checker | motif | 21 | 1.000 | checker x21 | True |

Official T exact for k=2,3,4,5,8. IMO 2025 n=2025 -> T=2112.
