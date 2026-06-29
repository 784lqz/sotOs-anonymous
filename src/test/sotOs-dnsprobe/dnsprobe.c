/* dnsprobe — resolve a name via UDP:53 and print the first A record.
 * argv[1] = domain (default "example.com"). Static musl. */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int build_query(const char *name, uint8_t *buf) {
    int o = 0;
    buf[o++] = 0x12; buf[o++] = 0x34;   /* ID */
    buf[o++] = 0x01; buf[o++] = 0x00;   /* flags: RD */
    buf[o++] = 0x00; buf[o++] = 0x01;   /* QDCOUNT=1 */
    buf[o++]=0;buf[o++]=0;buf[o++]=0;buf[o++]=0;buf[o++]=0;buf[o++]=0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int seglen = dot ? (int)(dot - p) : (int)strlen(p);
        if (o + seglen + 5 > 128) return -1;  /* room for root + QTYPE + QCLASS */
        buf[o++] = (uint8_t)seglen;
        memcpy(buf + o, p, seglen); o += seglen;
        if (!dot) break;
        p = dot + 1;
    }
    buf[o++] = 0;                       /* root */
    buf[o++] = 0x00; buf[o++] = 0x01;   /* QTYPE A */
    buf[o++] = 0x00; buf[o++] = 0x01;   /* QCLASS IN */
    return o;
}

int main(int argc, char **argv) {
    const char *name = (argc > 1) ? argv[1] : "example.com";
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { printf("[dnsprobe] socket FAIL\n"); return 1; }
    struct sockaddr_in ns; memset(&ns, 0, sizeof ns);
    ns.sin_family = AF_INET; ns.sin_port = htons(53);
    ns.sin_addr.s_addr = htonl(0x01010101);   /* 1.1.1.1 */
    if (connect(fd, (struct sockaddr *)&ns, sizeof ns) != 0)
        { printf("[dnsprobe] connect FAIL\n"); return 1; }
    uint8_t q[128]; int qlen = build_query(name, q);
    if (qlen < 0) { printf("[dnsprobe] name too long\n"); return 1; }
    printf("[dnsprobe] query %s (%d bytes)\n", name, qlen);
    /* Pass the dest sockaddr explicitly (do NOT rely on the connect() peer):
     * the UDP:53 DNS-sotbox-intercept hook keys on the sendto() dest address,
     * so a connected-socket sendto(NULL) would be dropped before the synth/
     * forward path. */
    if (sendto(fd, q, qlen, 0, (struct sockaddr *)&ns, sizeof ns) != qlen)
        { printf("[dnsprobe] sendto FAIL\n"); return 1; }
    uint8_t r[512];
    int n = recvfrom(fd, r, sizeof r, 0, NULL, NULL);
    if (n < 12) { printf("[dnsprobe] recvfrom FAIL n=%d\n", n); return 1; }
    int ancount = (r[6] << 8) | r[7];
    printf("[dnsprobe] response %d bytes ancount=%d\n", n, ancount);
    int o = 12;
    while (o < n && r[o]) o += r[o] + 1;
    o += 1 + 4;                         /* root + QTYPE + QCLASS */
    for (int i = o; i + 16 <= n; i++) {
        if (r[i] == 0xc0 &&
            r[i+2] == 0x00 && r[i+3] == 0x01 &&
            r[i+4] == 0x00 && r[i+5] == 0x01) {
            const uint8_t *rd = r + i + 12;
            printf("[dnsprobe] RESOLVED %s -> %u.%u.%u.%u\n",
                   name, rd[0], rd[1], rd[2], rd[3]);
            return 0;
        }
    }
    printf("[dnsprobe] no A record parsed (ancount=%d)\n", ancount);
    return ancount > 0 ? 0 : 2;
}
