/* Deterministic malformed-input differential harness for ASan/UBSan. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int nr_lz4(const unsigned char*,size_t,unsigned char*,size_t,size_t,int,size_t*);
struct nr_command {size_t literal_offset,literal_length,distance,match_length;};
int nr_execute(const unsigned char*,size_t,const struct nr_command*,size_t,unsigned char*,size_t,int,size_t*);
int nr_isa(const unsigned char*,size_t,unsigned char*,size_t,int,size_t*);
static uint32_t state=1234567;
static uint32_t rnd(void) {state^=state<<13;state^=state>>17;state^=state<<5;return state;}
/* Emit a well-formed NRISA stream (flags=0, no digest) into b. */
static size_t nrisa_valid(unsigned char *b, size_t room) {
    size_t p=14, o=0; uint32_t ncmd=0;
    size_t lit=1+rnd()%64;
    b[p++]=0; b[p++]=(unsigned char)lit; b[p++]=(unsigned char)(lit>>8);
    for(size_t i=0;i<lit;i++) b[p++]=(unsigned char)rnd();
    o+=lit; ncmd++;
    int cmds=1+rnd()%8;
    for(int c=0;c<cmds;c++) {
        size_t dist, n;
        switch(rnd()%4) {
        case 0:
            n=1+rnd()%32; if(o+n>room) goto done;
            b[p++]=0; b[p++]=(unsigned char)n; b[p++]=(unsigned char)(n>>8);
            for(size_t i=0;i<n;i++) b[p++]=(unsigned char)rnd();
            break;
        case 1:
            dist=1+rnd()%o; n=1+rnd()%256;       /* may overlap: n > dist */
            if(o+n>room) goto done;
            b[p++]=1; b[p++]=(unsigned char)n; b[p++]=(unsigned char)(n>>8);
            b[p++]=(unsigned char)dist; b[p++]=(unsigned char)(dist>>8);
            break;
        case 2:
            n=1+rnd()%256; if(o+n>room) goto done;
            b[p++]=2; b[p++]=(unsigned char)n; b[p++]=(unsigned char)(n>>8);
            b[p++]=(unsigned char)rnd();
            break;
        default:
            /* bias toward dist>=16 and a in {0,1,255} so the PADDB/PSUBB and
               memset branches of axpy_bytes are reached, not just the scalar. */
            dist=(o>16)?16+rnd()%(o-15):1+rnd()%o;
            n=1+rnd()%dist;                      /* the format caps len at dist */
            if(o+n>room) goto done;
            b[p++]=3; b[p++]=(unsigned char)n; b[p++]=(unsigned char)(n>>8);
            b[p++]=(unsigned char)dist; b[p++]=(unsigned char)(dist>>8);
            { static const unsigned char as[]={0,1,255,1,255};
              b[p++]=(rnd()%4)?as[rnd()%5]:(unsigned char)rnd(); }
            b[p++]=(unsigned char)rnd();
            break;
        }
        o+=n; ncmd++;
    }
done:
    b[0]='N';b[1]='R';b[2]='I';b[3]='S';b[4]=1;b[5]=0;
    b[6]=(unsigned char)o;b[7]=(unsigned char)(o>>8);
    b[8]=(unsigned char)(o>>16);b[9]=(unsigned char)(o>>24);
    b[10]=(unsigned char)ncmd;b[11]=(unsigned char)(ncmd>>8);
    b[12]=(unsigned char)(ncmd>>16);b[13]=(unsigned char)(ncmd>>24);
    return p;
}
int main(void) {
    unsigned char in[256], reference[4096], output[4096], stream[4096];
    int decoded=0;
    for(int trial=0;trial<50000;trial++) {
        size_t n=rnd()%sizeof(in), cap=rnd()%4097, prefix=cap>32?32:0;
        for(size_t i=0;i<n;i++) in[i]=(unsigned char)rnd();
        memset(reference,0,sizeof(reference));
        size_t expected=0;
        int rc=nr_lz4(in,n,reference,cap,prefix,0,&expected);
        for(int mode=1;mode<4;mode++) {
            memset(output,0,sizeof(output)); size_t got=0;
            int r=nr_lz4(in,n,output,cap,prefix,mode,&got);
            if(r!=rc || (!r && (got!=expected || memcmp(reference,output,prefix+got)))) abort();
        }
    }
    puts("50000 malformed-LZ4 trials x 4 strategies: no sanitizer errors or disagreements");
    for(int trial=0;trial<10000;trial++) {
        struct nr_command c[2]={{0,1,1,rnd()%5000},{rnd()%300,rnd()%100,1,rnd()%100}};
        size_t n=0; memset(reference,0,sizeof(reference));
        int rc=nr_execute((unsigned char*)"A",1,c,2,reference,sizeof(reference),0,&n);
        for(int mode=1;mode<4;mode++) {
            size_t got=0; memset(output,0,sizeof(output));
            int r=nr_execute((unsigned char*)"A",1,c,2,output,sizeof(output),mode,&got);
            if(r!=rc || (!r && (got!=n || memcmp(reference,output,n)))) abort();
        }
    }
    puts("10000 shared-IR trials x 4 strategies: no sanitizer errors or disagreements");
    /* NRISA. Random bytes are rejected at the final i==n && o==usize check,
       which would make a differential over them vacuous, so build structurally
       valid streams and corrupt half of them afterwards. */
    for(int trial=0;trial<50000;trial++) {
        size_t len=nrisa_valid(stream,2048);
        if(trial%2) stream[rnd()%len]^=(unsigned char)(1u<<(rnd()%8));
        size_t cap=(trial%8)?4096:rnd()%4097;
        memset(reference,0,sizeof(reference));
        size_t expected=0;
        int rc=nr_isa(stream,len,reference,cap,0,&expected);
        if(!rc) decoded++;
        for(int mode=1;mode<4;mode++) {
            memset(output,0,sizeof(output)); size_t got=0;
            int r=nr_isa(stream,len,output,cap,mode,&got);
            if(r!=rc || (!r && (got!=expected || memcmp(reference,output,got)))) abort();
        }
    }
    if(!decoded) abort();  /* the differential must actually compare outputs */
    printf("50000 NRISA trials x 4 strategies (%d decoded): "
           "no sanitizer errors or disagreements\n", decoded);
    return 0;
}
