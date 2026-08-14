#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <sched.h>
#include <cpuid.h>
#include "bench_perf.h"

unsigned int OPENSSL_ia32cap_P[4] = {0};
static void caps(void){
    unsigned a,b,c,d,vb,vc,vd;
    __cpuid_count(0,0,a,vb,vc,vd);
    __cpuid_count(1,0,a,b,c,d);
    OPENSSL_ia32cap_P[0]=d; OPENSSL_ia32cap_P[1]=c & ~(1u<<11);
    if(vb==0x68747541u){unsigned ea,eb,ec,ed;__cpuid_count(0x80000001,0,ea,eb,ec,ed);
        if(ec&(1u<<11)) OPENSSL_ia32cap_P[1]|=(1u<<11);}
    __cpuid_count(7,0,a,b,c,d);
    OPENSSL_ia32cap_P[2]=b; OPENSSL_ia32cap_P[3]=c;
}
void ChaCha20_ctr32(uint8_t*,const uint8_t*,size_t,const uint32_t*,const uint32_t*);
static uint8_t in[300000],out[300000]; static uint32_t k[8]={1,2,3,4,5,6,7,8},c[4]={0,9,8,7};
int main(void){cpu_set_t s;CPU_ZERO(&s);CPU_SET(0,&s);sched_setaffinity(0,sizeof s,&s);
 caps();
 if(bench_perf_init()>0){puts("no PMU");return 2;}
 size_t L[]={1024,1420,2047,2048,2049,2560,3072,4096,4097,5120,8192,9000,12288,16384,16385,32768,65536,262144};
 for(unsigned i=0;i<sizeof L/sizeof*L;i++){size_t n=L[i];int reps=(int)(4u*1024*1024/n)+1;double b=1e30;
  ChaCha20_ctr32(out,in,n,k,c);
  for(int r=0;r<9;r++){struct bench_sample m;bench_perf_start();
   for(int j=0;j<reps;j++)ChaCha20_ctr32(out,in,n,k,c);
   if(!bench_perf_stop((uint64_t)n*reps,&m)&&m.cycles_per_byte<b)b=m.cycles_per_byte;}
  printf("%8zu %9.4f\n",n,b);} return 0;}
