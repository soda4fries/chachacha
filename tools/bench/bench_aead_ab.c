#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>
#include "bench_perf.h"
#include "../../chacha20poly1305.h"
static uint8_t in[20000], out[20100];
static uint8_t key[32], nonce[12], ad[13];
int main(void){
    cpu_set_t s; CPU_ZERO(&s); CPU_SET(0,&s); sched_setaffinity(0,sizeof s,&s);
    if (bench_perf_init()>0){puts("no PMU");return 2;}
    size_t L[]={1088,1280,1420,1500,1600,1984,2048,2049,4096,16384};
    printf("%7s %10s %10s\n","len","seal c/B","open c/B");
    for(unsigned i=0;i<sizeof L/sizeof*L;i++){
        size_t n=L[i], ol, pl; double bs=1e30, bo=1e30;
        int reps=(int)(2u*1024*1024/n)+1;
        chacha20_poly1305_seal(out,&ol,sizeof out,in,n,ad,sizeof ad,key,nonce);
        for(int r=0;r<9;r++){
            struct bench_sample sm;
            bench_perf_start();
            for(int k=0;k<reps;k++) chacha20_poly1305_seal(out,&ol,sizeof out,in,n,ad,sizeof ad,key,nonce);
            if(!bench_perf_stop((uint64_t)n*reps,&sm)&&sm.cycles_per_byte<bs) bs=sm.cycles_per_byte;
            bench_perf_start();
            for(int k=0;k<reps;k++) chacha20_poly1305_open(in,&pl,sizeof in,out,ol,ad,sizeof ad,key,nonce);
            if(!bench_perf_stop((uint64_t)n*reps,&sm)&&sm.cycles_per_byte<bo) bo=sm.cycles_per_byte;
        }
        printf("%7zu %10.4f %10.4f\n",n,bs,bo);
    }
    return 0;}
