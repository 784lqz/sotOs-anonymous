/*
 * sotOs · sotNet-β-4 · UDP send fixture.
 *
 * Tiny x86_64 Linux ELF that calls:
 *   fd = socket(AF_INET=2, SOCK_DGRAM=2, 0)   ; syscall 41
 *   sendto(fd, msg, 2, 0, &sa, 16)             ; syscall 44
 *   exit_group(0)                               ; syscall 231
 *
 * Destination: 10.0.2.2:9999 (QEMU user-mode host-side NAT address).
 *
 * No libc, no PT_INTERP, no relocations.  Compiled to a tiny static ELF
 * (~400 bytes text) so it fits in the allocman pool budget at spawn 4.
 *
 * Build:
 *   gcc -nostdlib -static -no-pie -Wl,--build-id=none -o udp_send.bin udp_send.S
 *   strip udp_send.bin
 *
 * Verify on Linux host:
 *   nc -u -l 9999 &
 *   ./udp_send.bin
 *   # nc should receive "hi"
 */

.intel_syntax noprefix

.section .text
.global _start
_start:
    /* socket(AF_INET=2, SOCK_DGRAM=2, 0) */
    mov rax, 41         /* SYS_socket */
    mov rdi, 2          /* AF_INET */
    mov rsi, 2          /* SOCK_DGRAM */
    xor rdx, rdx        /* protocol = 0 */
    syscall
    /* rax = fd on success, negative on error */
    test rax, rax
    js   .Lfail
    mov r12, rax        /* save fd */

    /*
     * sendto(fd, msg, 2, 0, &sockaddr_in, 16)
     *
     * sockaddr_in layout (16 bytes):
     *   uint16_t sin_family = 2  (AF_INET)
     *   uint16_t sin_port   = 9999 in network byte order = 0x0F27 (big-endian → bytes: 0x0F, 0x27)
     *   uint32_t sin_addr   = 10.0.2.2 in NBO = bytes: 0x0A, 0x00, 0x02, 0x02
     *   uint8_t  sin_zero[8] = 0
     *
     * Stored in memory (x86 LE):
     *   .word  0x0002           sin_family (LE: 02 00)
     *   .word  0x270F           sin_port BE (bytes: 0F 27)
     *   .long  0x0202000A       sin_addr BE (bytes: 0A 00 02 02)
     *   .quad  0                sin_zero[8]
     */
    mov rax, 44         /* SYS_sendto */
    mov rdi, r12        /* fd */
    lea rsi, [rip + msg]  /* buf */
    mov rdx, 2          /* len */
    xor r10, r10        /* flags = 0 */
    lea r8,  [rip + sa] /* dest_addr */
    mov r9,  16         /* addrlen */
    syscall

.Lfail:
    /* exit_group(0) */
    mov rax, 231        /* SYS_exit_group */
    xor rdi, rdi
    syscall
    ud2

.section .rodata
msg:
    .ascii "hi"

sa:
    .word  0x0002           /* sin_family = AF_INET (LE) */
    .byte  0x0F, 0x27       /* sin_port = 9999 in network byte order */
    .byte  0x0A, 0x00, 0x02, 0x02  /* sin_addr = 10.0.2.2 NBO */
    .quad  0                /* sin_zero[8] */
