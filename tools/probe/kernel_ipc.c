#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include "bench_perf.h"
void ChaCha20_16x(uint8_t*,const uint8_t*,size_t,const void*,const void*);
void ChaCha20_16x_mac(uint8_t*,const uint8_t*,size_t,const void*,const void*,void*);
void ChaCha20_tail_avx512(uint8_t*,const uint8_t*,size_t,const void*,const void*);
void poly1305_aead_update_fma_avx512(const void*,uint64_t,void*,const void*);
static uint8_t buf[1<<17], out[1<<17], key[32]={1,2,3}, ctr[16]={1,0,0,0,9};
static uint8_t pk[64]; static uint64_t hash[3];
struct macctx { uint64_t A[3],B[3],k[3]; const uint8_t *ptr; };
static struct macctx mc;
static void probe(const char *name, void (*fn)(void), unsigned it, double bytes) {
    double bc=1e30, bi=0;
    for (int r=0;r<9;r++){ struct bench_sample s; bench_perf_start();
        for (unsigned i=0;i<it;i++) fn();
        if (bench_perf_stop(it,&s)) continue;
        if (s.cycles_per_byte<bc){bc=s.cycles_per_byte; bi=s.instructions_per_byte;} }
    printf("%-24s %8.1f c  %8.1f instr  IPC %5.2f", name, bc, bi, bi/bc);
    if (bytes) printf("   %.4f c/B  %.3f instr/B", bc/bytes, bi/bytes);
    printf("\n");
}
static void f_16x(void){ ChaCha20_16x(out,buf,1024,key,ctr); }
static void f_mac(void){ mc.ptr=buf; ChaCha20_16x_mac(out,buf,1024,key,ctr,&mc); }
static void f_tail(void){ ChaCha20_tail_avx512(out,buf,1024,key,ctr); }
static void f_ifma(void){ poly1305_aead_update_fma_avx512(buf,1024,hash,pk); }
int main(int argc,char**argv){
    int cpu=argc>1?atoi(argv[1]):0; cpu_set_t s; CPU_ZERO(&s); CPU_SET(cpu,&s);
    if(sched_setaffinity(0,sizeof s,&s)){perror("aff");return 2;}
    if(bench_perf_init()>0){fprintf(stderr,"no PMU\n");return 2;}
    memset(buf,0x5a,sizeof buf); memset(pk,0x11,sizeof pk);
    probe("ChaCha20_16x 1024B",      f_16x, 20000, 1024);
    probe("ChaCha20_16x_mac 1024B",  f_mac, 20000, 1024);
    probe("ChaCha20_tail 1024B",     f_tail,20000, 1024);
    probe("poly1305 IFMA 1024B",     f_ifma,20000, 1024);
    return 0;
}
