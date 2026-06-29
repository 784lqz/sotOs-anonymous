/*  cc -DVIRTIO_MOUSE_HOST_TEST -I include src/test/virtio_mouse_unit/virtio_mouse_unit.c \
       src/orch/virtio_mouse.c -o /tmp/vmo && /tmp/vmo  */
#include <orch/virtio_mouse.h>
#include <stdio.h>
static int fails=0;
#define CHECK(c) do{ if(!(c)){printf("FAIL: %s (line %d)\n",#c,__LINE__);fails++;} }while(0)
int main(void){
    CHECK(mouse_abs_to_screen(0, 1280) == 0);
    CHECK(mouse_abs_to_screen(32767, 1280) == 1279);
    CHECK(mouse_abs_to_screen(16384, 1280) == 640);
    CHECK(mouse_abs_to_screen(32767, 800) == 799);
    if(!fails) printf("virtio_mouse_unit: ALL PASS\n");
    return fails?1:0;
}
