/*  cc -DVIRTIO_INPUT_HOST_TEST -I include src/test/virtio_input_unit/virtio_input_unit.c \
       src/orch/virtio_input.c -o /tmp/viu && /tmp/viu  */
#include <orch/virtio_input.h>
#include <stdio.h>
static int fails=0;
#define CHECK(c) do{ if(!(c)){printf("FAIL: %s (line %d)\n",#c,__LINE__);fails++;} }while(0)
int main(void){
    CHECK(kbd_translate(30,0)=='a');   /* KEY_A */
    CHECK(kbd_translate(30,1)=='A');
    CHECK(kbd_translate(2,0)=='1');    /* KEY_1 */
    CHECK(kbd_translate(2,1)=='!');
    CHECK(kbd_translate(57,0)==' ');   /* KEY_SPACE */
    CHECK(kbd_translate(28,0)=='\r');  /* KEY_ENTER */
    CHECK(kbd_translate(14,0)==8);     /* KEY_BACKSPACE */
    CHECK(kbd_translate(0,0)==0);
    if(!fails) printf("virtio_input_unit: ALL PASS\n");
    return fails?1:0;
}
