# Post-PR-#9 follow-up

The four STATUS items after the squash are on `main`.

1. Native RFC1951 parse: `native/deflate.c`, `deflate_ir.decompress(..., parse='native')`.
2. Scale benches: `scripts/benchmark_scale.py`, `results/lz4_scale_benchmark.json`.
3. RAR bitstream plan only: `docs/RAR_BITSTREAM.md`. No codec.
4. HOST isolation helper: `src/host_isolate.py`. `host_extract` should call
   `host_isolate.run`; if a tree still uses bare `subprocess.run` there, use
   the helper. Isolation is not a sandbox.

Measured raw-DEFLATE text, tight `max_output=len(data)`, MiB/s including FFI:

| Size | Python IR grow | Native parse grow | zlib |
|---|---:|---:|---:|
| 64 KiB | 97.4 | 139.3 | 2147.4 |
| 1 MiB | 105.7 | 755.6 | 979.8 |

Native parse beats Python IR setup cost and is still behind zlib. Opt-in only.
Compressed RAR remains out of scope.
