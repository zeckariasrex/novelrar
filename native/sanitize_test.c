/* Deterministic malformed-input differential harness for ASan/UBSan. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int nr_lz4(const unsigned char*,size_t,unsigned char*,size_t,size_t,int,size_t*);
struct nr_command {size_t literal_offset,literal_length,distance,match_length;};
int nr_execute(const unsigned char*,size_t,const struct nr_command*,size_t,unsigned char*,size_t,int,size_t*);
static uint32_t state=1234567;
static uint32_t rnd(void) {state^=state<<13;state^=state>>17;state^=state<<5;return state;}
int main(void) {
    unsigned char in[256], reference[4096], output[4096];
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
    return 0;
}
