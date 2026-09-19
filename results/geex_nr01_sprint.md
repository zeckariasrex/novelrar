# NR01 sprint

Issue #5: container + skip-path fix. Official T still exact k=2..8.

Skip path paints gap literals before XOR. Residual on the permutation diagonal is all zeros. Language SHA matches.

| corpus | n | klass | blob/raw | lossless |
|---|---:|---|---:|:---:|
| planes | 16 | planar | 0.695 | yes |
| checker | 16 | tiled | 0.914 | yes |
| english | 16 | language skip | 0.652 | yes |
| planes | 64 | planar | **0.137** | yes |
| checker | 64 | tiled | **0.178** | yes |

ZIP method 8 (stdlib zlib) then NR01: planes and readme both SHA-ok. Encrypted members stop. No UnRAR / 7-Zip / LZ4 source.
