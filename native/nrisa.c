/* NRISA executor. Owned format. Independent of RAR/ZIP/LZ4 parsers. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "expand.h"
#if defined(__SSE2__)
#include <emmintrin.h>
#endif

static uint16_t le16(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void axpy_bytes(unsigned char *p, size_t dist, size_t len,
                       unsigned a, unsigned b, int mode) {
    if (a == 0) {
        memset(p, (int)b, len);
        return;
    }
#if defined(__SSE2__)
    if (mode == 2 && dist >= 16 && (a == 1 || a == 255)) {
        if (a == 1) {
            __m128i vb = _mm_set1_epi8((char)b);
            while (len >= 16) {
                __m128i v = _mm_loadu_si128((const __m128i *)(p - dist));
                _mm_storeu_si128((__m128i *)p, _mm_add_epi8(v, vb));
                p += 16;
                len -= 16;
            }
        } else {
            __m128i vb = _mm_set1_epi8((char)b);
            while (len >= 16) {
                __m128i v = _mm_loadu_si128((const __m128i *)(p - dist));
                _mm_storeu_si128((__m128i *)p, _mm_sub_epi8(vb, v));
                p += 16;
                len -= 16;
            }
        }
    }
#else
    (void)mode;
#endif
    while (len--) {
        unsigned src = p[-((ptrdiff_t)dist)];
        if (a == 1) *p = (unsigned char)((src + b) & 255u);
        else if (a == 255) *p = (unsigned char)((b - src) & 255u);
        else *p = (unsigned char)((a * src + b) & 255u);
        p++;
    }
}

int nr_isa(const unsigned char *s, size_t n, unsigned char *out,
           size_t capacity, int mode, size_t *written) {
    if (!written || mode < 0 || mode > 3) return -1;
    *written = 0;
    if (!s || n < 14) return -1;
    if (s[0] != 'N' || s[1] != 'R' || s[2] != 'I' || s[3] != 'S') return -1;
    if (s[4] != 1) return -1;
    unsigned flags = s[5];
    uint32_t usize = le32(s + 6);
    uint32_t ncmd = le32(s + 10);
    if (usize > capacity) return -1;
    size_t i = 14, o = 0;
    for (uint32_t c = 0; c < ncmd; c++) {
        if (i >= n) return -1;
        unsigned op = s[i++];
        if (op == 0) {
            if (i + 2 > n) return -1;
            unsigned len = le16(s + i); i += 2;
            if (len > n - i || len > capacity - o) return -1;
            if (len && out) memcpy(out + o, s + i, len);
            i += len; o += len;
            continue;
        }
        if (op == 1) {
            if (i + 4 > n) return -1;
            unsigned len = le16(s + i), dist = le16(s + i + 2); i += 4;
            if (!len || !dist || dist > o || len > capacity - o) return -1;
            nr_expand(out + o, dist, len, mode);
            o += len;
            continue;
        }
        if (op == 2) {
            if (i + 3 > n) return -1;
            unsigned len = le16(s + i); unsigned v = s[i + 2]; i += 3;
            if (!len || len > capacity - o) return -1;
            memset(out + o, (int)v, len);
            o += len;
            continue;
        }
        if (op == 3) {
            if (i + 6 > n) return -1;
            unsigned len = le16(s + i), dist = le16(s + i + 2);
            unsigned a = s[i + 4], b = s[i + 5]; i += 6;
            if (!len || !dist || dist > o || len > capacity - o) return -1;
            axpy_bytes(out + o, dist, len, a, b, mode);
            o += len;
            continue;
        }
        return -1;
    }
    if (flags & 1u) {
        if (i + 32 > n) return -1;
        i += 32;
    }
    if (i != n || o != usize) return -1;
    *written = o;
    return 0;
}
