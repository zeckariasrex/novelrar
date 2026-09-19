# WINDMILL-GEEX — dual of IMO 2025 P6

Video: minimize rectangles on an n x n board with one gap per row and column.
For n = k^2:

    T = k^2 + 2k - 3

Official permutation: pi(a) = (k * a) mod (k^2 + 1).
Interior: (k-1)^2 squares of side k at gap + (1, 0).
This repo's dual maximizes reconstructed cells per stored recipe.

v1 hits T exactly through k=8 (77 tiles, 52.36 cells/tile).

See `src/geex_windmill_v1.py`.
