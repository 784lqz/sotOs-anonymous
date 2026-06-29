#define _GNU_SOURCE
#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
static inline uint64_t rd(void){unsigned lo,hi;__asm__ volatile("lfence;rdtsc":"=a"(lo),"=d"(hi));return ((uint64_t)hi<<32)|lo;}
int main(void){
  struct timespec ts; struct timeval tv; const int N=100000; uint64_t mn=~0ull,sum=0;
  for(int i=0;i<5000;i++) clock_gettime(CLOCK_MONOTONIC,&ts);            /* warmup */
  for(int i=0;i<N;i++){uint64_t a=rd(); clock_gettime(CLOCK_MONOTONIC,&ts); uint64_t d=rd()-a; if(d<mn)mn=d; sum+=d;}
  printf("[native-vdso] clock_gettime min=%lu mean=%lu\n", mn, sum/N);
  mn=~0ull;sum=0;
  for(int i=0;i<N;i++){uint64_t a=rd(); gettimeofday(&tv,0); uint64_t d=rd()-a; if(d<mn)mn=d; sum+=d;}
  printf("[native-vdso] gettimeofday  min=%lu mean=%lu\n", mn, sum/N);
  return 0;
}
