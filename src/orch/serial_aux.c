/* sotOs · auxiliary userspace UARTs (COM2 / COM3) for the multi-pane I/O split.
 *
 * orch holds the FULL-RANGE x86 IOPort cap (root delegates 0x0000-0xFFFF), so
 * extra 16550s are drivable here with no kernel change and no new cap.  Each port
 * is PRESENCE-DETECTED via the 16550 scratch-register probe, so a single-serial
 * `just run` / a gate is untouched: if QEMU does not back the port the probe
 * fails, the channel stays inactive, and trace + the orch firehose remain on COM1
 * (the default) — exactly what the gates grep.
 *
 *   COM2 (0x2F8) · the sottrace LIVE audit stream  (com2_trace_sink)
 *   COM3 (0x3E8) · the orch debug firehose         (com3_stdio_write · orch stdout)
 *
 * Each putc is port I/O (a VM-exit), so the KVM host-CPU yield that COM1 writes
 * gave the inbound-DMA path is preserved on these channels too. */
#include <sel4/sel4.h>
#include <stddef.h>
#include <stdint.h>

extern seL4_CPtr orch_get_io_port_cap(void);   /* src/orch/sotbox_table.c */

#define UART_DLL 0u   /* data / divisor-latch low */
#define UART_IER 1u   /* interrupt enable / divisor-latch high */
#define UART_FCR 2u   /* FIFO control */
#define UART_LCR 3u   /* line control (DLAB) */
#define UART_MCR 4u   /* modem control */
#define UART_LSR 5u   /* line status (bit5 = THR empty) */
#define UART_SCR 7u   /* scratch register (16450+ · 16550A in QEMU has it) */
#define LSR_THRE 0x20u

/* 16550 scratch-register probe: write/read-back two patterns.  A real,
 * QEMU-backed UART round-trips them; an absent ISA port reads back 0xFF. */
static int uart_present(uint16_t base) {
    seL4_CPtr io = orch_get_io_port_cap();
    if (io == 0) return 0;
    seL4_X86_IOPort_Out8(io, base + UART_SCR, 0xAE);
    seL4_X86_IOPort_In8_t a = seL4_X86_IOPort_In8(io, base + UART_SCR);
    if (a.error || a.result != 0xAE) return 0;
    seL4_X86_IOPort_Out8(io, base + UART_SCR, 0x55);
    seL4_X86_IOPort_In8_t b = seL4_X86_IOPort_In8(io, base + UART_SCR);
    return (!b.error && b.result == 0x55);
}

static void uart_init(uint16_t base) {
    seL4_CPtr io = orch_get_io_port_cap();
    if (io == 0) return;
    seL4_X86_IOPort_Out8(io, base + UART_IER, 0x00);   /* poll-only · no interrupts */
    seL4_X86_IOPort_Out8(io, base + UART_LCR, 0x80);   /* DLAB on */
    seL4_X86_IOPort_Out8(io, base + UART_DLL, 0x01);   /* divisor = 1 (QEMU ignores rate) */
    seL4_X86_IOPort_Out8(io, base + UART_IER, 0x00);   /* divisor latch high */
    seL4_X86_IOPort_Out8(io, base + UART_LCR, 0x03);   /* 8N1, DLAB off */
    seL4_X86_IOPort_Out8(io, base + UART_FCR, 0xC7);   /* FIFO enable + clear, 14-byte trigger */
    seL4_X86_IOPort_Out8(io, base + UART_MCR, 0x0B);   /* DTR | RTS | OUT2 */
}

static void uart_putc(uint16_t base, char c) {
    seL4_CPtr io = orch_get_io_port_cap();
    if (io == 0) return;
    /* Poll THR-empty, bounded so an absent/wedged backend can never hang orch. */
    for (int i = 0; i < 100000; ++i) {
        seL4_X86_IOPort_In8_t lsr = seL4_X86_IOPort_In8(io, base + UART_LSR);
        if (lsr.error) return;
        if (lsr.result & LSR_THRE) break;
    }
    seL4_X86_IOPort_Out8(io, base, (uint8_t)c);
}

/* ---- COM2 · the sottrace audit channel ---- */
#define COM2_BASE 0x2F8u
static int g_com2 = 0;
void com2_init(void)    { if ((g_com2 = uart_present(COM2_BASE))) uart_init(COM2_BASE); }
int  com2_present(void) { return g_com2; }

/* sottrace text-line sink: one formatted audit line → COM2, CRLF-terminated so a
 * raw terminal (socat/screen) renders it cleanly. */
void com2_trace_sink(const char *line) {
    if (!g_com2 || !line) return;
    for (const char *p = line; *p; ++p) uart_putc(COM2_BASE, *p);
    uart_putc(COM2_BASE, '\r');
    uart_putc(COM2_BASE, '\n');
}

/* ---- COM3 · the orch debug firehose channel ---- */
#define COM3_BASE 0x3E8u
static int g_com3 = 0;
void com3_init(void)    { if ((g_com3 = uart_present(COM3_BASE))) uart_init(COM3_BASE); }
int  com3_present(void) { return g_com3; }

/* muslc stdio write_buf_fn: orch's printf/writev → COM3, byte for byte, when COM3
 * is present.  Registered via sel4muslcsys_register_stdio_write_fn so the whole
 * orch debug firehose leaves COM1, freeing the operator console.  Returns count
 * so writev reports every byte consumed (the bytes still go out a UART → the
 * VM-exit yield the firehose provided for inbound DMA is preserved). */
size_t com3_stdio_write(void *data, size_t count) {
    if (g_com3 && data) {
        const char *p = (const char *)data;
        for (size_t i = 0; i < count; ++i) {
            if (p[i] == '\n') uart_putc(COM3_BASE, '\r');   /* ONLCR · terminals need CRLF */
            uart_putc(COM3_BASE, p[i]);
        }
    }
    return count;
}
