#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "tls13_wire.h"
int main(void){
    uint8_t b[4];
    tls13_wr16(b, 0x0304); assert(b[0]==0x03 && b[1]==0x04);
    tls13_wr24(b, 0x010203); assert(b[0]==1 && b[1]==2 && b[2]==3);
    uint8_t x[2]={0x13,0x01}; assert(tls13_rd16(x)==0x1301);
    uint8_t c[4];
    tls13_wr24(c, 0xabcdef); assert(tls13_rd24(c)==0xabcdefu);
    tls13_wr32(c, 0x01020304); assert(c[0]==1 && c[1]==2 && c[2]==3 && c[3]==4);
    tls13_wr8(c, 0x17); assert(c[0]==0x17);
    return 0;
}
