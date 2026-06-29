#ifndef ORCH_CONSOLE_FB_H
#define ORCH_CONSOLE_FB_H
/* On-screen text console over the virtio-gpu framebuffer. */
void console_fb_init(void);       /* clear screen, home cursor; no-op if no gpu */
void console_fb_putc(char c);     /* render one char; no-op if console inactive */
void console_fb_puts(const char *s); /* v2.9 · render a string with ONE flush (batched) */
int  console_fb_active(void);     /* 1 if a framebuffer console is live */
#endif
