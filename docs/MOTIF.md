# Motif fill (v2)

v1 painted one mode byte per windmill rectangle. Motif fill tries a small public-domain recipe family and keeps the cheapest recipe near the best residual-zero fraction.

## Family

| tag | name | payload |
|---|---|---|
| 0 | const | 1 byte |
| 1 | checker | 2 bytes |
| 2 | stripe_x | 2 bytes |
| 3 | stripe_y | 2 bytes |
| 4 | cell2 | 4 bytes |
| 5 | axis_row | h bytes |
| 6 | axis_col | w bytes |

`apply_motif` is the decoder. Residual is XOR. Always lossless.

## First-slice n=16 (this pass)

| corpus | mode zf | motif zf | recipes |
|---|---|---|---|
| planes | 1.000 | 1.000 | const x21 |
| tiles8 | 0.145 | 0.453 | cell2 / axis_row / axis_col |
| shell | 1.000 | 1.000 | const x21 |
| english | 0.262 | 0.516 | cell2 / axis |
| random | 0.160 | 0.465 | cell2 / axis |
| checker | 0.531 | 1.000 | checker x21 |

Construction still hits T = k^2+2k-3 through k=8. Latin square holes verified at D=16.

ZIP pipeline: sniff PK -> zlib raw DEFLATE -> motif pack. Encrypted members stop. No unrar/7-Zip/LZ4 source.
