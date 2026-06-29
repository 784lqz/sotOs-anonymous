/* Host test: cc -I include src/net-synth/inbound_http.c src/test/inbound_http_unit/inbound_http_unit.c -o /tmp/ihu && /tmp/ihu */
#include <net-synth/inbound_http.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
int main(void) {
    uint8_t out[1024];
    const char *get_root = "GET / HTTP/1.0\r\n\r\n";
    uint32_t n = http_route((const uint8_t*)get_root, (uint32_t)strlen(get_root), out, sizeof out);
    out[n < sizeof out ? n : sizeof out - 1] = 0;
    assert(n > 0);
    assert(strstr((char*)out, "HTTP/1.1 200 OK"));
    assert(strstr((char*)out, "Server: nginx/1.18.0"));
    assert(strstr((char*)out, "Welcome to nginx"));
    assert(strstr((char*)out, "Content-Length:"));

    const char *get_admin = "GET /admin HTTP/1.0\r\n\r\n";
    n = http_route((const uint8_t*)get_admin, (uint32_t)strlen(get_admin), out, sizeof out); out[n]=0;
    assert(strstr((char*)out, "Admin Login") && strstr((char*)out, "<form"));

    const char *post_login = "POST /login HTTP/1.0\r\n\r\nuser=root&pass=x";
    n = http_route((const uint8_t*)post_login, (uint32_t)strlen(post_login), out, sizeof out); out[n]=0;
    assert(strstr((char*)out, "Login successful"));

    const char *junk = "FOO /x";   /* malformed/unknown → still a 200 */
    n = http_route((const uint8_t*)junk, (uint32_t)strlen(junk), out, sizeof out); out[n]=0;
    assert(strstr((char*)out, "HTTP/1.1 200 OK"));

    fprintf(stderr, "inbound_http_unit OK\n");
    return 0;
}
