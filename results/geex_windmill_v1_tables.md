# WINDMILL-GEEX v1

Exact IMO 2025 P6 construction. Dual codec paints those rectangles.

## Construction hits T = k^2 + 2k - 3

| k | n | interior | boundary | tiles | T | LIS | LDS | LIS*LDS | cover |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 2 | 4 | 1 | 4 | 5 | 5 | 2 | 2 | 4 | exact |
| 3 | 9 | 4 | 8 | 12 | 12 | 3 | 3 | 9 | exact |
| 4 | 16 | 9 | 12 | 21 | 21 | 4 | 4 | 16 | exact |
| 5 | 25 | 16 | 16 | 32 | 32 | 5 | 5 | 25 | exact |
| 8 | 64 | 49 | 28 | 77 | 77 | 8 | 8 | 64 | exact |

Official pi: (k*a) mod (k^2+1). Interior squares at gap + (1, 0).
