/* One-pass RFC 1951 inflater. Independent of zlib. Shared LZ expand only.
 * Fast path: 15-bit LSB Huffman LUT. Stored / fixed / dynamic blocks.
 * Does not parse RAR compressed payloads.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "expand.h"

static const uint16_t LEN_BASE[29] = {
    3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,
    131,163,195,227,258
};
static const uint8_t LEN_EXTRA[29] = {
    0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0
};
static const uint16_t DIST_BASE[30] = {
    1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,
    2049,3073,4097,6145,8193,12289,16385,24577
};
static const uint8_t DIST_EXTRA[30] = {
    0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13
};
static const uint8_t CL_ORDER[19] = {
    16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
};

enum { LUT_BITS = 15, LUT_SIZE = 1 << LUT_BITS };

struct br {
    const unsigned char *s;
    size_t n, i;
    uint64_t buf;
    unsigned bits;
};

struct huff {
    uint16_t sym[LUT_SIZE];
    uint8_t len[LUT_SIZE];
};

static int refill(struct br *b) {
    while (b->bits <= 56 && b->i < b->n) {
        b->buf |= (uint64_t)b->s[b->i++] << b->bits;
        b->bits += 8;
    }
    return 0;
}

static int bits(struct br *b, unsigned k, unsigned *out) {
    if (k > 16) return -1;
    if (b->bits < k) refill(b);
    if (b->bits < k) return -1;
    *out = (unsigned)(b->buf & ((1u << k) - 1u));
    b->buf >>= k;
    b->bits -= k;
    return 0;
}

static void align_byte(struct br *b) {
    unsigned drop = b->bits & 7u;
    if (drop) {
        b->buf >>= drop;
        b->bits -= drop;
    }
}

static unsigned bitrev(unsigned v, unsigned n) {
    unsigned r = 0;
    for (unsigned i = 0; i < n; i++) {
        r = (r << 1) | (v & 1u);
        v >>= 1;
    }
    return r;
}

static int huff_build(struct huff *h, const uint8_t *lengths, unsigned count) {
    unsigned bl[16] = {0};
    unsigned next[16] = {0};
    unsigned maxl = 0;
    memset(h->len, 0, LUT_SIZE);
    memset(h->sym, 0, LUT_SIZE * sizeof(uint16_t));
    for (unsigned i = 0; i < count; i++) {
        unsigned L = lengths[i];
        if (L > 15) return -1;
        if (L) {
            bl[L]++;
            if (L > maxl) maxl = L;
        }
    }
    if (!maxl) return 0;
    unsigned code = 0;
    for (unsigned bitsn = 1; bitsn <= 15; bitsn++) {
        code = (code + bl[bitsn - 1]) << 1;
        next[bitsn] = code;
    }
    if (bl[15] && (next[15] + bl[15]) > (1u << 15)) return -1;
    unsigned used = 0;
    for (unsigned L = 1; L <= 15; L++) used += bl[L] << (15 - L);
    if (used > LUT_SIZE) return -1;
    for (unsigned i = 0; i < count; i++) {
        unsigned L = lengths[i];
        if (!L) continue;
        unsigned c = next[L]++;
        unsigned wire = bitrev(c, L);
        unsigned step = 1u << L;
        for (unsigned fill = wire; fill < LUT_SIZE; fill += step) {
            if (h->len[fill] && h->len[fill] != (uint8_t)L) return -1;
            h->len[fill] = (uint8_t)L;
            h->sym[fill] = (uint16_t)i;
        }
    }
    return 0;
}

static int huff_sym(struct br *b, const struct huff *h, unsigned *sym) {
    if (b->bits < LUT_BITS) refill(b);
    if (!b->bits) return -1;
    unsigned peek = (unsigned)(b->buf & (LUT_SIZE - 1));
    unsigned L = h->len[peek];
    if (!L || L > b->bits) {
        if (b->bits < LUT_BITS) refill(b);
        peek = (unsigned)(b->buf & (LUT_SIZE - 1));
        L = h->len[peek];
        if (!L || L > b->bits) return -1;
    }
    *sym = h->sym[peek];
    b->buf >>= L;
    b->bits -= L;
    return 0;
}

static void fixed_lengths(uint8_t *ll, uint8_t *dd) {
    unsigned i;
    for (i = 0; i < 144; i++) ll[i] = 8;
    for (; i < 256; i++) ll[i] = 9;
    for (; i < 280; i++) ll[i] = 7;
    for (; i < 288; i++) ll[i] = 8;
    for (i = 0; i < 32; i++) dd[i] = 5;
}

static int read_dyn_lengths(struct br *b, uint8_t *ll, unsigned nlit,
                            uint8_t *dd, unsigned ndist) {
    unsigned hclen;
    if (bits(b, 4, &hclen)) return -1;
    hclen += 4;
    uint8_t cl[19] = {0};
    for (unsigned i = 0; i < hclen; i++) {
        unsigned v;
        if (bits(b, 3, &v)) return -1;
        cl[CL_ORDER[i]] = (uint8_t)v;
    }
    struct huff ch;
    if (huff_build(&ch, cl, 19)) return -1;
    uint8_t all[288 + 32];
    unsigned need = nlit + ndist, got = 0;
    while (got < need) {
        unsigned sym;
        if (huff_sym(b, &ch, &sym)) return -1;
        if (sym < 16) {
            all[got++] = (uint8_t)sym;
            continue;
        }
        unsigned extra, rep, val;
        if (sym == 16) {
            if (!got) return -1;
            if (bits(b, 2, &extra)) return -1;
            rep = 3 + extra;
            val = all[got - 1];
        } else if (sym == 17) {
            if (bits(b, 3, &extra)) return -1;
            rep = 3 + extra;
            val = 0;
        } else if (sym == 18) {
            if (bits(b, 7, &extra)) return -1;
            rep = 11 + extra;
            val = 0;
        } else return -1;
        if (got + rep > need) return -1;
        while (rep--) all[got++] = (uint8_t)val;
    }
    memcpy(ll, all, nlit);
    memcpy(dd, all + nlit, ndist);
    return 0;
}

int nr_deflate(const unsigned char *s, size_t n, unsigned char *out,
               size_t capacity, int mode, size_t *written) {
    if (!written || mode < 0 || mode > 3) return -1;
    *written = 0;
    if (!s || (n && !out && capacity)) return -1;
    struct br b = {s, n, 0, 0, 0};
    size_t o = 0;
    unsigned last = 0;
    struct huff fixed_lit, fixed_dist;
    uint8_t fll[288], fdd[32];
    fixed_lengths(fll, fdd);
    if (huff_build(&fixed_lit, fll, 288) || huff_build(&fixed_dist, fdd, 32))
        return -1;
    while (!last) {
        unsigned kind;
        if (bits(&b, 1, &last) || bits(&b, 2, &kind)) return -1;
        if (kind == 3) return -1;
        if (kind == 0) {
            align_byte(&b);
            {
                size_t unread = b.bits / 8;
                if (unread > b.i) return -1;
                b.i -= unread;
                b.buf = 0;
                b.bits = 0;
            }
            if (4 > n - b.i) return -1;
            unsigned len = (unsigned)s[b.i] | ((unsigned)s[b.i + 1] << 8);
            unsigned nlen = (unsigned)s[b.i + 2] | ((unsigned)s[b.i + 3] << 8);
            b.i += 4;
            if ((len ^ nlen) != 0xFFFFu) return -1;
            if (len > n - b.i || len > capacity - o) return -1;
            if (len) memcpy(out + o, s + b.i, len);
            b.i += len;
            o += len;
            continue;
        }
        struct huff lit, dist;
        const struct huff *lt, *dt;
        if (kind == 1) {
            lt = &fixed_lit;
            dt = &fixed_dist;
        } else {
            unsigned hlit, hdist;
            if (bits(&b, 5, &hlit) || bits(&b, 5, &hdist)) return -1;
            hlit += 257;
            hdist += 1;
            if (hlit > 286 || hdist > 32) return -1;
            uint8_t ll[288] = {0}, dd[32] = {0};
            if (read_dyn_lengths(&b, ll, hlit, dd, hdist)) return -1;
            if (huff_build(&lit, ll, hlit) || huff_build(&dist, dd, hdist))
                return -1;
            lt = &lit;
            dt = &dist;
        }
        for (;;) {
            unsigned sym;
            if (huff_sym(&b, lt, &sym)) return -1;
            if (sym == 256) break;
            if (sym < 256) {
                if (o >= capacity) return -1;
                out[o++] = (unsigned char)sym;
                continue;
            }
            if (sym > 285) return -1;
            unsigned idx = sym - 257, extra, length;
            if (bits(&b, LEN_EXTRA[idx], &extra)) return -1;
            length = (unsigned)LEN_BASE[idx] + extra;
            unsigned dsym;
            if (huff_sym(&b, dt, &dsym)) return -1;
            if (dsym > 29) return -1;
            if (bits(&b, DIST_EXTRA[dsym], &extra)) return -1;
            unsigned distance = (unsigned)DIST_BASE[dsym] + extra;
            if (!distance || distance > o || length > capacity - o) return -1;
            nr_expand(out + o, distance, length, mode);
            o += length;
        }
    }
    *written = o;
    return 0;
}
