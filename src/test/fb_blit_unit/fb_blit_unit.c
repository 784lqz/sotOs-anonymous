/*  cc -I include src/test/fb_blit_unit/fb_blit_unit.c src/orch/fb_blit.c -o /tmp/fbb && /tmp/fbb  */
#include <orch/fb_blit.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static int fails=0;
#define CHECK(c) do{ if(!(c)){printf("FAIL: %s (line %d)\n",#c,__LINE__);fails++;} }while(0)
int main(void){
    uint8_t src[2*2*4];
    memset(src,0,sizeof src);
    src[0*4+0]=255;                 /* (0,0) B */
    src[1*4+1]=255;                 /* (1,0) G */
    src[(2+0)*4+2]=255;             /* (0,1) R */
    src[(2+1)*4+0]=src[(2+1)*4+1]=src[(2+1)*4+2]=255; /* (1,1) white */
    uint8_t dst[4*4*4]; memset(dst,0xEE,sizeof dst);
    fb_blit_scale_fill(dst,4,4,4*4,src,2,2);
    CHECK(dst[0*16+0*4+0]==255 && dst[0*16+1*4+0]==255);   /* (0,0)+(1,0)=blue from src(0,0) */
    CHECK(dst[0*16+2*4+1]==255);                            /* (2,0)=green from src(1,0) */
    CHECK(dst[2*16+0*4+2]==255);                            /* (0,2)=red from src(0,1) */
    uint8_t dst2[4*6*4]; memset(dst2,0x77,sizeof dst2);
    fb_blit_scale_fill(dst2,4,6,4*4,src,2,2);               /* 4x4 image centered in 4x6 */
    CHECK(dst2[0*16+0*4+0]==0 && dst2[0*16+0*4+1]==0 && dst2[0*16+0*4+2]==0);  /* row0 letterbox black */
    if(!fails) printf("fb_blit_unit: ALL PASS\n");
    return fails?1:0;
}
