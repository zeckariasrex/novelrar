/* Shared LZ match expansion. Modes: 0 scalar, 1 growing-copy, 2 SSE2, 3 rep movsb. */
#ifndef NOVELRAR_EXPAND_H
#define NOVELRAR_EXPAND_H
#include <stddef.h>
#include <string.h>
#if defined(__SSE2__)
#include <emmintrin.h>
#endif
#if defined(__x86_64__) && !defined(_WIN32)
extern void nr_repeat_asm(unsigned char *, size_t, size_t);
#endif
static void nr_expand(unsigned char *p, size_t dist, size_t len, int mode) {
    if (mode == 0) { for (size_t i = 0; i < len; i++) p[i] = *(p + i - dist); return; }
#if defined(__x86_64__) && !defined(_WIN32)
    if (mode == 3) { nr_repeat_asm(p, dist, len); return; }
#endif
#if defined(__SSE2__)
    if (mode == 2 && dist >= 16) {
        while (len >= 16) {
            __m128i v = _mm_loadu_si128((const __m128i *)(p - dist));
            _mm_storeu_si128((__m128i *)p, v); p += 16; len -= 16;
        }
    }
#endif
    size_t done = 0;
    while (done < len) {
        size_t available = dist + done, n = len - done;
        if (n > available) n = available;
        memcpy(p + done, p - dist, n); done += n;
    }
}
#endif
