/* Host unit · pure union resolution + whiteout + getdents-merge.  No seL4. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "lucas/backends_union.h"

int main(void){
    /* resolve: upper present → UPPER; whiteout → ENOENT; else base present → BASE; else ENOENT */
    assert(union_resolve_layer(/*upper_has=*/1,/*upper_wh=*/0,/*base_has=*/1) == UNION_UPPER);
    assert(union_resolve_layer(0,0,1) == UNION_BASE);
    assert(union_resolve_layer(0,1,1) == UNION_NONE);   /* whiteout hides base */
    assert(union_resolve_layer(1,0,0) == UNION_UPPER);
    assert(union_resolve_layer(0,0,0) == UNION_NONE);

    /* getdents merge: base has {a,b,c}; upper has {b(new),d}; upper whiteouts {c}.
     * result = {a, b(upper), d}  (c hidden, b shadowed by upper). */
    const char *base[] = {"a","b","c"};
    const char *up[]   = {"b","d"};
    const char *wh[]   = {"c"};
    char out[8][16]; int n = union_merge_dents(base,3, up,2, wh,1, out, 8);
    /* expect exactly a, b, d in some order — assert membership + no c */
    int has_a=0,has_b=0,has_c=0,has_d=0;
    for(int i=0;i<n;i++){ if(!strcmp(out[i],"a"))has_a=1; if(!strcmp(out[i],"b"))has_b=1;
                          if(!strcmp(out[i],"c"))has_c=1; if(!strcmp(out[i],"d"))has_d=1; }
    assert(n==3 && has_a && has_b && has_d && !has_c);
    printf("[union-unit] ALL PASS\n");
    return 0;
}
