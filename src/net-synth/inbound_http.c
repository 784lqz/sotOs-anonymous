#include <net-synth/inbound_http.h>
#include <string.h>
#include <stdio.h>

/* Build one complete HTTP/1.1 response (status line + Server/Date/Content-Type
 * + computed Content-Length + body). Fixed Date (no RTC). Returns length. */
static uint32_t build_resp(uint8_t *out, uint32_t outmax,
                           const char *status, const char *ctype, const char *body) {
    size_t blen = strlen(body);
    int n = snprintf((char *)out, outmax,
        "HTTP/1.1 %s\r\n"
        "Server: nginx/1.26.3\r\n"
        "Date: Mon, 01 Jun 2026 00:00:00 GMT\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "%s",
        status, ctype, blen, body);
    if (n < 0) return 0;
    return (uint32_t)((size_t)n < outmax ? (size_t)n : outmax - 1);  /* snprintf truncation: don't count the NUL */
}

uint32_t http_route(const uint8_t *req, uint32_t reqlen, uint8_t *out, uint32_t outmax) {
    /* Bounded request-line parse: method = first token, path = second token. */
    char method[8] = {0}, path[128] = {0};
    uint32_t i = 0, j = 0;
    while (i < reqlen && req[i] != ' ' && req[i] != '\r' && j < sizeof(method) - 1)
        method[j++] = (char)req[i++];
    while (i < reqlen && req[i] == ' ') i++;
    j = 0;
    while (i < reqlen && req[i] != ' ' && req[i] != '\r' && j < sizeof(path) - 1)
        path[j++] = (char)req[i++];

    int is_post = (strcmp(method, "POST") == 0);
    int is_admin = (strncmp(path, "/admin", 6) == 0 || strncmp(path, "/login", 6) == 0);

    if (is_admin && is_post)
        return build_resp(out, outmax, "200 OK", "text/html",
            "<html><body>Login successful. Redirecting to /dashboard...</body></html>");
    if (is_admin)
        return build_resp(out, outmax, "200 OK", "text/html",
            "<html><body><h1>Admin Login</h1>"
            "<form method=\"post\" action=\"/login\">"
            "<input name=\"user\"><input name=\"pass\" type=\"password\">"
            "<button>Sign in</button></form></body></html>");
    if (strcmp(path, "/") == 0)
        return build_resp(out, outmax, "200 OK", "text/html",
            "<html><head><title>Welcome to nginx!</title></head>"
            "<body><h1>Welcome to nginx!</h1>"
            "<p>If you see this page, the nginx web server is successfully installed.</p>"
            "</body></html>");
    /* generic 200 (lenient · keep the adversary engaged) */
    return build_resp(out, outmax, "200 OK", "text/html",
        "<html><body>OK</body></html>");
}
