/* sotOs T5 · syscall-latency microbench · -nostdlib (raw _start, no libc).
 * getpid (sysno 39)         → trivial fast-path
 * clock_gettime (sysno 228) → non-trivial · single-thread normal path
 * Raw syscalls under lfence;rdtsc.  Reports min/mean/max: on a properly isolated core
 * (isolcpus+nohz_full, SMT off, perf governor, no turbo) max↔min is tight — that spread
 * IS the proof the measurement is clean.  min = the least-perturbed per-syscall floor. */
typedef unsigned long u64;
static long sys1(long n,long a){long r;
  __asm__ __volatile__("syscall":"=a"(r):"a"(n),"D"(a):"rcx","r11","memory"); return r;}
static long sys2(long n,long a,long b){long r;
  __asm__ __volatile__("syscall":"=a"(r):"a"(n),"D"(a),"S"(b):"rcx","r11","memory"); return r;}
static long sys3(long n,long a,long b,long c){long r;
  __asm__ __volatile__("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory"); return r;}
static u64 rdtsc(void){unsigned lo,hi;
  __asm__ __volatile__("lfence;rdtsc":"=a"(lo),"=d"(hi)::"memory"); return ((u64)hi<<32)|lo;}
static int utoa(u64 v,char*p){char t[24];int n=0; if(!v){*p='0';return 1;}
  while(v){t[n++]=(char)('0'+v%10);v/=10;} for(int i=0;i<n;i++)p[i]=t[n-1-i]; return n;}
static char buf[320]; static u64 ts[2];
static char* emit(char*p,const char*lbl,u64 mn,u64 mx,u64 sum){const char*s;
  for(s=lbl;*s;)*p++=*s++;
  s=" min="; while(*s)*p++=*s++; p+=utoa(mn,p);
  s=" mean=";while(*s)*p++=*s++; p+=utoa(sum/100000,p);
  s=" max="; while(*s)*p++=*s++; p+=utoa(mx,p); *p++='\n'; return p;}
void _start(void){
  const int N=100000; u64 mn,mx,sum,a,b,d;
  for(int i=0;i<2000;i++) sys1(39,0);                          /* warmup getpid */
  mn=~0UL; mx=0; sum=0;
  for(int i=0;i<N;i++){a=rdtsc(); sys1(39,0); b=rdtsc(); d=b-a; sum+=d; if(d<mn)mn=d; if(d>mx)mx=d;}
  char*p=buf; p=emit(p,"[ubench] getpid",mn,mx,sum);
  for(int i=0;i<2000;i++) sys2(228,1,(long)ts);               /* warmup clock_gettime */
  mn=~0UL; mx=0; sum=0;
  for(int i=0;i<N;i++){a=rdtsc(); sys2(228,1,(long)ts); b=rdtsc(); d=b-a; sum+=d; if(d<mn)mn=d; if(d>mx)mx=d;}
  p=emit(p,"[ubench] clock_gettime",mn,mx,sum);
  sys3(1,1,(long)buf,(long)(p-buf));                          /* write(1,...) */
  sys1(60,0); for(;;);                                        /* exit */
}
