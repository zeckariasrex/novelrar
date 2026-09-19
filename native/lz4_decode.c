/* Original implementation from the LZ4 block grammar, not reference source.
 * Input/output bounds checked before every access. No speculative overreads.
 * Modes: 0 scalar; 1 growing copy; 2 SSE2 + growing copy; 3 x86 rep movsb.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#if defined(__SSE2__)
#include <emmintrin.h>
#endif
#if defined(__x86_64__) && !defined(_WIN32)
extern void nr_repeat_asm(unsigned char *, size_t, size_t);
#endif
static void expand(unsigned char *p, size_t dist, size_t len, int mode) {
    if (mode == 0) { for (size_t i=0;i<len;i++) p[i]=*(p+i-dist); return; }
#if defined(__x86_64__) && !defined(_WIN32)
    if (mode == 3) { nr_repeat_asm(p,dist,len); return; }
#endif
#if defined(__SSE2__)
    if (mode == 2 && dist >= 16) {
        while (len >= 16) {
            __m128i v = _mm_loadu_si128((const __m128i *)(p-dist));
            _mm_storeu_si128((__m128i *)p,v); p+=16; len-=16;
        }
    }
#endif
    /* Each memcpy is disjoint. Newly produced bytes grow the available seed. */
    size_t done=0;
    while (done<len) {
        size_t available=dist+done, n=len-done;
        if (n>available) n=available;
        memcpy(p+done,p-dist,n); done+=n;
    }
}
static int length(const unsigned char *s,size_t n,size_t *i,size_t *v) {
    unsigned int b;
    do { if (*i>=n) return -1; b=s[(*i)++];
         if (*v>SIZE_MAX-b) return -1;
         *v+=b; } while(b==255);
    return 0;
}
/* out begins with prefix bytes. capacity includes prefix. written excludes it. */
int nr_lz4(const unsigned char *s,size_t n,unsigned char *out,size_t capacity,
           size_t prefix,int mode,size_t *written) {
    size_t i=0,o=prefix;
    if(prefix>capacity || mode<0 || mode>3 || n==0) return -1;
    while(i<n) {
        unsigned int token=s[i++]; size_t lit=token>>4;
        if(lit==15 && length(s,n,&i,&lit)) return -1;
        if(lit>n-i || lit>capacity-o) return -1;
        memcpy(out+o,s+i,lit); i+=lit; o+=lit;
        if(i==n) { *written=o-prefix; return 0; }
        if(n-i<2) return -1;
        size_t dist=(size_t)s[i] | ((size_t)s[i+1]<<8); i+=2;
        if(!dist || dist>o) return -1;
        size_t len=token&15;
        if(len==15 && length(s,n,&i,&len)) return -1;
        if(len>SIZE_MAX-4) return -1;
        len+=4;
        if(len>capacity-o) return -1;
        expand(out+o,dist,len,mode); o+=len;
    }
    return -1; /* missing final literal sequence */
}

/* Shared LZ execution IR: literal slice followed by optional distance/length.
 * Parsers remain format-specific. This does not parse RAR compressed payloads.
 */
struct nr_command {size_t literal_offset, literal_length, distance, match_length;};
int nr_execute(const unsigned char *literals,size_t literal_size,
               const struct nr_command *commands,size_t count,
               unsigned char *out,size_t capacity,int mode,size_t *written) {
    size_t o=0;
    if(mode<0 || mode>3) return -1;
    for(size_t i=0;i<count;i++) {
        struct nr_command c=commands[i];
        if(c.literal_offset>literal_size || c.literal_length>literal_size-c.literal_offset
           || c.literal_length>capacity-o) return -1;
        memcpy(out+o,literals+c.literal_offset,c.literal_length); o+=c.literal_length;
        if(c.match_length) {
            if(!c.distance || c.distance>o || c.match_length>capacity-o) return -1;
            expand(out+o,c.distance,c.match_length,mode); o+=c.match_length;
        }
    }
    *written=o; return 0;
}
