#include <unistd.h>
void _start_unused(void){}
int main(void){ write(1, "[hello-dyn] dynamic musl OK\n", 28); return 0; }
