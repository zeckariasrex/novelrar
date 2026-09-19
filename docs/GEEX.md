# GEEX-v0 — Geometric Eval + EXtraction

A block of bytes is packed into a cube. Cortex columns measure shadow, shape,
and surface. The router emits a typed geometric object. Reconstruction is

    block = object XOR residual

and is bit-exact. This is not an LZMA / RAR / LZ4 / AES inverse.

Occupancy stains: `nonzero`, `highbit` (>=128), `nibble`, `mid` ([64,192)), `fold`.

Classes: planar, shell, tiled, language, noise, foam, raster.
Held-out synthetics (n=4096): 9/9 class accuracy, 9/9 bit-exact reconstruct.

See `src/geex_eval_extract.py`.
