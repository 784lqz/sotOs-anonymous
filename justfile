# sotOs · top-level commands
# Run `just` to list all recipes.
#
# Linux  : runs natively under bash.
# Windows: recipes run inside WSL2 via `windows-shell` below. One-time setup:
#   1. Install a real distro (podman/docker machines won't do):
#        wsl --install -d Ubuntu
#   2. Make it the default so wsl.exe picks it up:
#        wsl --set-default Ubuntu
#   3. Inside the distro, install the toolchain + just, then bootstrap:
#        sudo apt install build-essential cmake ninja-build qemu-system-x86 python3 git
#        # just: https://just.systems (needed because recipes call `just` recursively)
#        just bootstrap
#   Notes:
#   - Without /dev/kvm (WSL2 nested virtualization), QEMU falls back to TCG
#     software emulation via KVM_FLAGS — boots still work, just slower.
#   - Builds under /mnt/c are slow (9p filesystem). For serious work clone the
#     repo inside the WSL filesystem (~/) and run just from there.
#   `just doctor` checks all of the above.

set shell := ["bash", "-uc"]
set windows-shell := ["wsl.exe", "-e", "bash", "-uc"]

# Relative on purpose: when invoked from Windows, WSL maps the justfile cwd to
# /mnt/c/... — an absolute C:\ path would break inside bash.
BUILD_DIR  := "build"

# Hardware accel when /dev/kvm is usable (Linux host, or WSL2 with nested
# virtualization); otherwise TCG software emulation so boots still work.
KVM_FLAGS  := `test -w /dev/kvm 2>/dev/null && echo "-enable-kvm -cpu host" || echo "-accel tcg -cpu max"`

# PCID needs the vCPU to expose CPUID.1:ECX.PCID; seL4's head.S pcid_check HANGS
# the boot ("PCIDs not supported by the processor") when it's absent. Two hosts
# lack it: (a) TCG software emulation (no /dev/kvm), and (b) WSL2 — Hyper-V
# nested virtualization does NOT pass PCID/INVPCID through to the L2 guest even
# with -enable-kvm -cpu host (the WSL2 /proc/cpuinfo shows pcid, the nested seL4
# vCPU does not). In both cases compile PCID out (slightly more TLB flushing,
# boots anywhere). Only native Linux + real KVM keeps PCID on.
KERNEL_ACCEL_OPTS := `if test -w /dev/kvm 2>/dev/null && ! grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then echo ""; else echo "-DKernelSupportPCID=OFF"; fi`

default:
    @just --list

# Full bootstrap: install deps, clone seL4 stack, prepare external/
bootstrap:
    ./bootstrap.sh

# Configure CMake (idempotent). Uses the seL4 init-build.sh helper which
# sets the toolchain, generator, and -C settings.cmake correctly.
configure:
    @test -d external/kernel || (echo "Run 'just bootstrap' first"; exit 1)
    @test -L init-build.sh || (echo "Layout symlinks missing — re-run 'just bootstrap'"; exit 1)
    mkdir -p {{BUILD_DIR}}
    cd {{BUILD_DIR}} && ../init-build.sh {{KERNEL_ACCEL_OPTS}}

# Build everything. Usage: just build [target]
build target="all":
    @test -d {{BUILD_DIR}} || just configure
    ninja -C {{BUILD_DIR}} {{target}}

# Build with the FULL completed-arc demo battery at headless boot.
# Default builds are LEAN (the scripted demo_commands[] runs only the cheap
# deception/observability core + bbsh-auto, so apt/ssh/smoke gates boot fast).
# The arc-specific gates that grep a completed-arc demo's marker (doom, gtk,
# wayland, gnu/glibc/git, validate/soak/churn, tcc, …) build with this so the
# markers come back.  `just build-lean` restores the fast default.
build-full:
    @test -d {{BUILD_DIR}} || just configure
    cd {{BUILD_DIR}} && cmake -DSOTOS_DEMO_FULL=ON .. >/dev/null
    ninja -C {{BUILD_DIR}}

# Restore the fast default (LEAN demo battery).
build-lean:
    @test -d {{BUILD_DIR}} || just configure
    cd {{BUILD_DIR}} && cmake -DSOTOS_DEMO_FULL=OFF .. >/dev/null
    ninja -C {{BUILD_DIR}}

# Boot interactively in QEMU · drops to sotshell after demo phase.
# Ctrl-A then C → QEMU monitor; type 'quit' there to exit.
# Or type 'quit' at the sotos> prompt for clean shutdown.
# Usage: just run [memory_mb]
run mem="4096":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    pkill -9 -f '^qemu-system-x86_64 ' 2>/dev/null || true
    sleep 1
    qemu-system-x86_64 \
        -m {{mem}} -display none -serial mon:stdio -serial null \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        -netdev user,id=net1 -device virtio-net-pci,netdev=net1,mac=52:54:00:12:34:57

# Boot with a real QEMU window + virtio-gpu (and virtio-keyboard for later input).
# NO pkill — never kill the operator's QEMU.  Ctrl-A C → monitor, Ctrl-A X → exit.
run-interactive mem="4096":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    qemu-system-x86_64 \
        -m {{mem}} -display gtk -vga none -serial mon:stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::18022-:22,hostfwd=tcp::18443-:443 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        -netdev user,id=net1 -device virtio-net-pci,netdev=net1,mac=52:54:00:12:34:57 \
        -device virtio-gpu-pci \
        -device virtio-keyboard-pci \
        -device virtio-tablet-pci

# 3-PANE parallel I/O · run the operator console, the attacker shell and the
# sottrace audit stream on THREE independent terminals at once (tmux):
#   pane 0 (left)        = OPERATOR trusted sotShell — COM1 (-serial mon:stdio)
#   pane 1 (top-right)   = ATTACKER shell — ssh into the honey SSH (Alpine/Debian)
#   pane 2 (bottom-right)= sottrace LIVE audit stream — COM2 (own UART → unix socket)
# COM2 is driven by orch in userspace (it holds the full-range IOPort cap); the
# 2nd -serial maps to it.  Needs tmux + socat.  Ctrl-b o = switch pane · Ctrl-b x
# = kill pane · in the operator pane Ctrl-a x = quit QEMU.
run-3pane mem="4096":
    @command -v tmux  >/dev/null || { echo "need tmux (apt install tmux)";   exit 1; }
    @command -v socat >/dev/null || { echo "need socat (apt install socat)"; exit 1; }
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || (echo "sotfs.img missing · run 'just build'"; exit 1)
    rm -f /tmp/sotos-trace.sock
    tmux kill-session -t sotos3 2>/dev/null || true
    tmux new-session -d -s sotos3 -x 230 -y 52 bash -c '\
        qemu-system-x86_64 -m {{mem}} -display none \
            -serial mon:stdio \
            -serial unix:/tmp/sotos-trace.sock,server,nowait \
            {{KVM_FLAGS}} \
            -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
            -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
            -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
            -device virtio-blk-pci,drive=sd0 \
            -netdev user,id=net0,hostfwd=tcp::18022-:22,hostfwd=tcp::18080-:80,hostfwd=tcp::18443-:443 \
            -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
            -netdev user,id=net1 -device virtio-net-pci,netdev=net1,mac=52:54:00:12:34:57; \
        echo "[run-3pane] QEMU exited · press enter"; read _'
    tmux set-option -t sotos3 mouse on
    tmux split-window -h -t sotos3 bash -c '\
        echo "[trace] waiting for COM2 socket /tmp/sotos-trace.sock ..."; \
        while [ ! -S /tmp/sotos-trace.sock ]; do sleep 0.3; done; \
        echo "[trace] sottrace LIVE on COM2 ↓↓↓"; \
        socat -,raw,echo=0 unix-connect:/tmp/sotos-trace.sock; \
        echo "[trace] socket closed · press enter"; read _'
    tmux split-window -v -t sotos3.0 bash -c '\
        echo "[attacker] waiting for honey-SSH on :18022 ..."; \
        until (exec 3<>/dev/tcp/127.0.0.1/18022) 2>/dev/null; do sleep 0.5; done; exec 3>&- 2>/dev/null; \
        echo "[attacker] connecting · ssh -p 18022 root@localhost"; \
        ssh -p 18022 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost; \
        echo "[attacker] ssh ended · press enter"; read _'
    tmux select-pane -t sotos3.0
    tmux attach -t sotos3

# 4-PANE parallel I/O · like run-3pane but the OPERATOR console is CLEAN: the orch
# debug firehose ([orch]/[procd]/[wal]/[sotnet]/mmap churn) is redirected off COM1
# onto its OWN UART (COM3), so the sotShell pane shows only the operator prompt.
#   pane 0 = OPERATOR sotShell — COM1 (clean · no firehose, no trace)
#   pane 1 = ATTACKER shell    — ssh into the honey SSH
#   pane 2 = sottrace stream   — COM2 (own UART → unix socket)
#   pane 3 = orch firehose     — COM3 (own UART → unix socket · diagnostics)
# Both aux UARTs are presence-detected by orch, so this needs no special build.
# Needs tmux + socat.  Ctrl-b o = switch pane · Ctrl-b z = zoom · operator Ctrl-a x = quit.
run-4pane mem="4096":
    @command -v tmux  >/dev/null || { echo "need tmux (apt install tmux)";   exit 1; }
    @command -v socat >/dev/null || { echo "need socat (apt install socat)"; exit 1; }
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || (echo "sotfs.img missing · run 'just build'"; exit 1)
    rm -f /tmp/sotos-trace.sock /tmp/sotos-orch.sock
    tmux kill-session -t sotos4 2>/dev/null || true
    tmux new-session -d -s sotos4 -x 230 -y 56 bash -c '\
        qemu-system-x86_64 -m {{mem}} -display none \
            -chardev stdio,id=c1,mux=on,signal=off,logfile=/tmp/sotos-com1.log -mon chardev=c1 -serial chardev:c1 \
            -chardev socket,id=c2,path=/tmp/sotos-trace.sock,server=on,wait=off,logfile=/tmp/sotos-trace.log -serial chardev:c2 \
            -chardev socket,id=c3,path=/tmp/sotos-orch.sock,server=on,wait=off,logfile=/tmp/sotos-orch.log -serial chardev:c3 \
            {{KVM_FLAGS}} \
            -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
            -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
            -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
            -device virtio-blk-pci,drive=sd0 \
            -netdev user,id=net0,hostfwd=tcp::18022-:22,hostfwd=tcp::18080-:80,hostfwd=tcp::18443-:443 \
            -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
            -netdev user,id=net1 -device virtio-net-pci,netdev=net1,mac=52:54:00:12:34:57; \
        echo "[run-4pane] QEMU exited · press enter"; read _'
    tmux set-option -t sotos4 mouse on
    tmux split-window -t sotos4 bash -c '\
        echo "[attacker] waiting for honey-SSH on :18022 ..."; \
        until (exec 3<>/dev/tcp/127.0.0.1/18022) 2>/dev/null; do sleep 0.5; done; exec 3>&- 2>/dev/null; \
        echo "[attacker] connecting · ssh -p 18022 root@localhost"; \
        ssh -p 18022 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost; \
        echo "[attacker] ssh ended · press enter"; read _'
    tmux split-window -t sotos4 bash -c '\
        echo "[trace] waiting for COM2 socket ..."; \
        while [ ! -S /tmp/sotos-trace.sock ]; do sleep 0.3; done; \
        echo "[trace] sottrace LIVE on COM2 ↓↓↓"; \
        socat -,raw,echo=0 unix-connect:/tmp/sotos-trace.sock; \
        echo "[trace] socket closed · press enter"; read _'
    tmux split-window -t sotos4 bash -c '\
        echo "[firehose] waiting for COM3 socket ..."; \
        while [ ! -S /tmp/sotos-orch.sock ]; do sleep 0.3; done; \
        echo "[firehose] orch debug on COM3 ↓↓↓"; \
        socat -,raw,echo=0 unix-connect:/tmp/sotos-orch.sock; \
        echo "[firehose] socket closed · press enter"; read _'
    tmux select-layout -t sotos4 tiled
    tmux select-pane -t sotos4.0
    tmux attach -t sotos4

# Boot with QEMU + software TPM 2.0 (swtpm).
# Install: apt install swtpm  |  pacman -S swtpm  |  dnf install swtpm
# Documentation: https://github.com/stefanberger/swtpm
#
# Boots interactively in QEMU with a tpm-tis device backed by a swtpm
# unix-socket emulator.  swtpm is started in the background and cleaned
# up on exit.  Foundation for TPM driver work (Unit T2).
# Usage: just run-tpm [memory_mb]
run-tpm mem="4096":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    @command -v swtpm >/dev/null || \
        (echo "swtpm not installed."; \
         echo "Install: apt install swtpm  |  pacman -S swtpm  |  dnf install swtpm"; \
         echo "Docs:    https://github.com/stefanberger/swtpm"; exit 1)
    pkill -9 -f '^qemu-system-x86_64 ' 2>/dev/null || true
    sleep 1
    SWTPM_DIR=$(mktemp -d /tmp/sotos-swtpm-XXXXXX); \
    trap 'kill $SWTPM_PID 2>/dev/null; rm -rf $SWTPM_DIR' EXIT; \
    swtpm socket --tpmstate dir=$SWTPM_DIR \
        --ctrl type=unixio,path=$SWTPM_DIR/swtpm-sock \
        --tpm2 --daemon --pid file=$SWTPM_DIR/swtpm.pid; \
    SWTPM_PID=$(cat $SWTPM_DIR/swtpm.pid); \
    echo "swtpm started · pid=$SWTPM_PID · state=$SWTPM_DIR"; \
    qemu-system-x86_64 \
        -m {{mem}} -display none -serial mon:stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        -chardev socket,id=chrtpm,path=$SWTPM_DIR/swtpm-sock \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-tis,tpmdev=tpm0

# Boot headless with QEMU + software TPM 2.0 (swtpm).
# Same swtpm setup as `run-tpm`, but captures log and prints a quick summary.
# Usage: just run-tpm-headless [timeout_s] [log_path]
run-tpm-headless timeout="240" log="/tmp/sotos-tpm-boot.log":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    @command -v swtpm >/dev/null || \
        (echo "swtpm not installed."; \
         echo "Install: apt install swtpm  |  pacman -S swtpm  |  dnf install swtpm"; \
         echo "Docs:    https://github.com/stefanberger/swtpm"; exit 1)
    pkill -9 -f '^qemu-system-x86_64 ' 2>/dev/null || true
    sleep 1
    @echo "Booting {{timeout}}s with swtpm · log → {{log}}"
    SWTPM_DIR=$(mktemp -d /tmp/sotos-swtpm-XXXXXX); \
    trap 'kill $SWTPM_PID 2>/dev/null; rm -rf $SWTPM_DIR' EXIT; \
    swtpm socket --tpmstate dir=$SWTPM_DIR \
        --ctrl type=unixio,path=$SWTPM_DIR/swtpm-sock \
        --tpm2 --daemon --pid file=$SWTPM_DIR/swtpm.pid; \
    SWTPM_PID=$(cat $SWTPM_DIR/swtpm.pid); \
    echo "swtpm started · pid=$SWTPM_PID · state=$SWTPM_DIR"; \
    timeout {{timeout}} qemu-system-x86_64 \
        -m 4096 -display none -serial stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        -chardev socket,id=chrtpm,path=$SWTPM_DIR/swtpm-sock \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-tis,tpmdev=tpm0 \
        > {{log}} 2>&1 || true
    @echo ""
    @echo "=== Quick summary ==="
    @grep -E "TPM|tpm|L11-γ.*stdlib loaded|hello from python|RANSOMWARE|LATERAL|tier2-auto|VMFault|Fatal Python" {{log}} | head -10 || echo "(no markers matched)"
    @echo ""
    @echo "Full log: {{log}} ($(wc -l < {{log}}) lines)"

# Boot headless · captures full log, exits on timeout, prints quick summary.
# Usage: just run-headless [timeout_s] [log_path]
run-headless timeout="240" log="/tmp/sotos-boot.log":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    pkill -9 -f '^qemu-system-x86_64 ' 2>/dev/null || true
    sleep 1
    @echo "Booting {{timeout}}s · log → {{log}}"
    timeout {{timeout}} qemu-system-x86_64 \
        -m 4096 -display none -serial stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        > {{log}} 2>&1 || true
    @echo ""
    @echo "=== Quick summary ==="
    @grep -E "L11-γ.*stdlib loaded|hello from python|RANSOMWARE|LATERAL|tier2-auto|VMFault|Fatal Python" {{log}} | head -10 || echo "(no markers matched)"
    @echo ""
    @echo "Full log: {{log}} ($(wc -l < {{log}}) lines)"

# Pillar-2 P2a · churn-harness boot · COPY of run-headless WITHOUT the
# `pkill -9 qemu-system-x86_64` (that would kill the operator's QEMU) and with a
# longer default timeout for the 1000-spawn loop.  The `churn` demo step runs
# LAST; the controller measures the per-spawn capability leak from {{log}}.
# Usage: just run-churn [timeout_s] [log_path]
run-churn timeout="400" log="/tmp/sotos-churn.log":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    @echo "Booting {{timeout}}s · log → {{log}}"
    timeout {{timeout}} qemu-system-x86_64 \
        -m 4096 -display none -serial stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        > {{log}} 2>&1 || true
    @echo ""
    @echo "=== Quick summary ==="
    @grep -E "L11-γ.*stdlib loaded|hello from python|RANSOMWARE|LATERAL|tier2-auto|VMFault|Fatal Python" {{log}} | head -10 || echo "(no markers matched)"
    @echo ""
    @echo "Full log: {{log}} ($(wc -l < {{log}}) lines)"

# Usage: just run-honeypot [timeout_s] [log_path]
# Boots with QEMU hostfwd tcp::18080-:80 so a real HOST client can connect
# INBOUND to the guest canary-service (spawned by the `canary-service` demo step,
# parked on accept).  NO `pkill` here — that would kill the operator's QEMU.
# If the sotfs.img write-lock is held the boot just fails; report BLOCKED.
# Turnkey SSH DECEPTION DEMO.
#   just demo-ssh           · STANDALONE: boot a host, attack it, narrate BOTH views
#                             (the lie the attacker saw + the truth sotOs recorded:
#                              credential capture, canary reads, write containment).
#   just demo-ssh attack    · COMBO: drive the attacker against your ALREADY-RUNNING
#                             `just run-interactive` window (no boot, no kill) — watch
#                             the operator window (F12 → `watch`) for the live TRUTH feed.
demo-ssh mode="":
    bash tools/demo-ssh.sh {{mode}}

run-honeypot timeout="150" log="/tmp/sottrace-honeypot.log":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    @echo "Booting {{timeout}}s · hostfwd tcp::18080-:80 · log → {{log}}"
    timeout {{timeout}} qemu-system-x86_64 \
        -m 4096 -display none -serial stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::18022-:22,hostfwd=tcp::18443-:443 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        > {{log}} 2>&1 || true
    @echo ""
    @echo "=== Quick summary ==="
    @grep -E "canary-svc\]|\[accept\] pid|INBOUND_ACCEPT|CONN_CLOSE|POWEROFF" {{log}} | head -10 || echo "(no markers matched)"
    @echo ""
    @echo "Full log: {{log}} ($(wc -l < {{log}}) lines)"

# Usage: just run-honeypot-pcap [timeout_s] [log_path]
# Same as run-honeypot (hostfwd :80/:22/:443, NO pkill — the operator's QEMU
# holds the sotfs.img write lock) PLUS a filter-dump pcap of net0 to
# /tmp/honeypot.pcap, so the inbound :443 ServerHello can be parsed by
# tools/ja3s.py.  If the image lock is held the boot just fails; report BLOCKED.
run-honeypot-pcap timeout="150" log="/tmp/sottrace-honeypot-pcap.log":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    @echo "Booting {{timeout}}s · hostfwd :80/:22/:443 · pcap → /tmp/honeypot.pcap · log → {{log}}"
    timeout {{timeout}} qemu-system-x86_64 \
        -m 4096 -display none -serial stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::18022-:22,hostfwd=tcp::18443-:443,hostfwd=tcp::18099-:99 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        -object filter-dump,id=f0,netdev=net0,file=/tmp/honeypot.pcap \
        > {{log}} 2>&1 || true
    @echo ""
    @echo "=== Quick summary ==="
    @grep -E "canary-svc\]|\[accept\] pid|INBOUND_ACCEPT|CONN_CLOSE|POWEROFF" {{log}} | head -10 || echo "(no markers matched)"
    @echo ""
    @echo "pcap: /tmp/honeypot.pcap · Full log: {{log}} ($(wc -l < {{log}}) lines)"

# Usage: just run-validate [timeout_s] [log_path]
# Pillar-4 P4a · headless validation run.  Clone of run-honeypot-pcap (so the
# C2/synth responder + a filter-dump pcap are live for the infostealer leg)
# but WITHOUT the closed-port :18099 forward (P4a doesn't need it) and the pcap
# is written to /tmp/validate.pcap.  NO pkill — the operator's QEMU holds the
# sotfs.img write lock; if the lock is held the boot just fails, report BLOCKED.
run-validate timeout="180" log="/tmp/p4a.log":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    @echo "Booting {{timeout}}s · hostfwd :80/:22/:443 · pcap → /tmp/validate.pcap · log → {{log}}"
    timeout {{timeout}} qemu-system-x86_64 \
        -m 4096 -display none -serial stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::18022-:22,hostfwd=tcp::18443-:443 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        -object filter-dump,id=f0,netdev=net0,file=/tmp/validate.pcap \
        > {{log}} 2>&1 || true
    @echo ""
    @echo "=== Quick summary ==="
    @grep -E "\[validate\] (START|spawn|DONE)|POWEROFF" {{log}} | head -10 || echo "(no markers matched)"
    @echo ""
    @echo "pcap: /tmp/validate.pcap · Full log: {{log}} ($(wc -l < {{log}}) lines)"

# Usage: just run-soak [timeout_s] [log_path]
# Pillar-4 P4b · soak / stability-over-time run.  Clone of run-validate (so the
# C2/synth responder + a filter-dump pcap are live) but the pcap is written to
# /tmp/soak.pcap and the default log is /tmp/p4b.log.  Drives cmd_soak (the scaled
# 24h proxy); orch emits [stats] every STATS_EVERY spawns for scripts/soak.sh.
# NO pkill — the operator's QEMU holds the sotfs.img write lock; if the lock is
# held the boot just fails, report BLOCKED.
run-soak timeout="240" log="/tmp/p4b.log":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    @echo "Booting {{timeout}}s · hostfwd :80/:22/:443 · pcap → /tmp/soak.pcap · log → {{log}}"
    timeout {{timeout}} qemu-system-x86_64 \
        -m 4096 -display none -serial stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::18022-:22,hostfwd=tcp::18443-:443 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        -object filter-dump,id=f0,netdev=net0,file=/tmp/soak.pcap \
        > {{log}} 2>&1 || true
    @echo ""
    @echo "=== Quick summary ==="
    @grep -E "\[soak\] (start|iter|STOP)|\[soak\] [0-9]+/[0-9]+ survived|\[stats\]|POWEROFF" {{log}} | head -10 || echo "(no markers matched)"
    @echo ""
    @echo "pcap: /tmp/soak.pcap · Full log: {{log}} ($(wc -l < {{log}}) lines)"

# Usage: just run-doom [timeout_s] [log_path]
# Doom-on-sotOs phase 1 · boot and trigger doomgeneric via the sotshell `doom` command.
# doom.bin + doom1.wad are bundled in the binstore; /doom1.wad served by the doom-wad
# VFS backend.  The controller verifies [doom] handler START/DONE in the serial log.
# NO pkill — the operator's QEMU holds the sotfs.img write lock; if the lock is
# held the boot just fails, report BLOCKED.
run-doom timeout="240" log="/tmp/doom.log":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    @echo "Booting {{timeout}}s · hostfwd :80/:22/:443 · pcap → /tmp/doom.pcap · log → {{log}}"
    timeout {{timeout}} qemu-system-x86_64 \
        -m 4096 -display none -serial stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::18022-:22,hostfwd=tcp::18443-:443 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        -object filter-dump,id=f0,netdev=net0,file=/tmp/doom.pcap \
        > {{log}} 2>&1 || true
    @echo ""
    @echo "=== Quick summary ==="
    @grep -E "\[doom\] (handler START|handler DONE|doom\.bin|spawn)" {{log}} | head -10 || echo "(no markers matched)"
    @echo ""
    @echo "pcap: /tmp/doom.pcap · Full log: {{log}} ($(wc -l < {{log}}) lines)"

# Usage: just run-gitdemo [timeout_s] [log_path]
# compat-host · REAL Alpine git (musl-dynamic) at Tier-0.  The auto-demo runs
# `gitdemo` EARLY (before sdlspike): git init -> commit --allow-empty -> log in
# /tmp/gitrepo.  Use tools/git-gate.sh for the pass/fail assertions; this is the
# raw boot + a focused summary.  NO pkill — if the operator's QEMU holds the
# lock the boot just fails; report BLOCKED.
run-gitdemo timeout="150" log="/tmp/gitdemo.log":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    @! ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1 || \
        (echo "ABORT · a QEMU is already running — it holds the sotfs.img lock, so this boot would get an EMPTY log. Exit it first."; exit 1)
    @echo "Booting {{timeout}}s · real git init/commit/log at Tier-0 · log → {{log}}"
    timeout {{timeout}} qemu-system-x86_64 \
        -m 4096 -display none -serial stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        > {{log}} 2>&1 || true
    @echo ""
    @echo "=== Quick summary ==="
    @test -s {{log}} || echo "EMPTY log — QEMU produced no output (image lock held? KVM busy?). Re-run."
    @LC_ALL=C grep -aE "Initialized empty Git repository|\(root-commit\)|first sotOs commit" {{log}} | head || echo "(no git markers)"
    @echo "real Tier-0 renames: $(LC_ALL=C grep -acE '\[mv\] .* · renamed' {{log}}) · object-write EINVAL: $(LC_ALL=C grep -ac 'unable to write file' {{log}}) · faults: $(LC_ALL=C grep -acE 'VMFault|CapFault' {{log}})"
    @echo "Full log: {{log}} ($(wc -l < {{log}}) lines)"

# Usage: just run-doomwl [timeout_s] [log_path]
# v2.3-M5 · Doom over REAL Wayland (wl_shm, no EGL).  The auto-demo runs `doomwl`
# EARLY (after `sdlspike`): doomgeneric over the patched DYNAMIC SDL2 (wayland
# backend, SOFTWARE renderer) → wl_shm commits on the honest compositor.  Use
# tools/doomwl-gate.sh for the pass/fail assertions; this is the raw boot + a
# focused summary.  NO pkill — if the operator's QEMU holds the lock, the boot
# just fails; report BLOCKED.
run-doomwl timeout="160" log="/tmp/doomwl.log":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    @echo "Booting {{timeout}}s · doomgeneric over real wayland/wl_shm · log → {{log}}"
    timeout {{timeout}} qemu-system-x86_64 \
        -m 4096 -display none -serial stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        > {{log}} 2>&1 || true
    @echo ""
    @echo "=== Quick summary ==="
    @LC_ALL=C grep -aE "\[doom-wl\] (spawned|SDL_Init|frames ticked|handler DONE)" {{log}} | head || echo "(no doom-wl markers)"
    @echo "640x400 wl_shm commits: $(LC_ALL=C grep -acE '\[wl-compositor\] commit .*640x400' {{log}})"
    @echo "Full log: {{log}} ($(wc -l < {{log}}) lines)"

# Usage: just run-gtk [timeout_s] [log_path]
# v2.4 · GTK3 over REAL Wayland (cairo software / wl_shm, no EGL).  The auto-demo
# runs `gtkspike` early: a real GTK3 app renders a cairo window over wl_shm.  Use
# tools/gtk-gate.sh for pass/fail; this is the raw boot + a focused summary.
run-gtk timeout="170" log="/tmp/gtk.log":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    @! ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1 || \
        (echo "ABORT · a QEMU is already running — it holds the sotfs.img lock, so this boot would get an EMPTY log. Exit it first."; exit 1)
    @echo "Booting {{timeout}}s · GTK3 over real wayland/wl_shm · log → {{log}}"
    timeout {{timeout}} qemu-system-x86_64 \
        -m 4096 -display none -serial stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        > {{log}} 2>&1 || true
    @echo ""
    @echo "=== Quick summary ==="
    @test -s {{log}} || echo "EMPTY log — QEMU produced no output (image lock held by another QEMU? KVM busy?). Re-run."
    @LC_ALL=C grep -aE "\[gtkspike\] (gtk_init OK|window shown)|\[gtk3-demo\] spawned|theme = Adwaita" {{log}} | head || echo "(no gtk markers)"
    @echo "gtkspike (our fixture) 412x383 commits: $(LC_ALL=C grep -acE '\[wl-compositor\] commit .*412x383' {{log}})"
    @echo "gtk3-demo (UNMODIFIED off-the-shelf app) 852x699 commits: $(LC_ALL=C grep -acE '\[wl-compositor\] commit .*852x699' {{log}})"
    @echo "faults: $(LC_ALL=C grep -acE 'VMFault|CapFault' {{log}}) · wl flush errors: $(LC_ALL=C grep -ac 'Error flushing display' {{log}})"
    @echo "Full log: {{log}} ($(wc -l < {{log}}) lines)"

# Boot in a GRAPHICAL QEMU window and WATCH the wayland apps render live.
# Unlike run-gtk (headless · -display none · just a log), this opens a real GTK
# window backed by virtio-gpu: the honest compositor blits each client's surface
# into the visible scanout.  NO virtio-keyboard → the scripted demo runs and
# auto-spawns the wayland apps in sequence — sdlspike → doom → gtkspike → the
# UNMODIFIED off-the-shelf gtk3-demo (its 852x699 demo-browser window).  Boot
# logs stream to this terminal; Ctrl-A X quits QEMU.  (For an INTERACTIVE shell
# instead — F12 → operator console → type `gtk3-demo` on demand — use
# `just run-interactive`, which adds a keyboard.)
run-gtk-window mem="4096":
    @test -f {{BUILD_DIR}}/images/sotfs.img || (echo "run 'just build' first"; exit 1)
    @! ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1 || \
        (echo "ABORT · a QEMU is already running (it holds the sotfs.img lock). Exit it first."; exit 1)
    @echo "INTERACTIVE graphical boot · real mouse + keyboard (virtio-tablet/keyboard)."
    @echo "  keyboard present → canary shell.  Press F12 → operator console, then type"
    @echo "  'gtk3-demo' (852x699, fits the screen) and click its demo list with the mouse."
    @echo "  (Move the mouse INTO the QEMU window first so the cursor sprite appears.)"
    qemu-system-x86_64 \
        -m {{mem}} -display gtk,show-cursor=on -vga none -serial stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci

# Build a TCG-compatible image (PCID compiled OUT — TCG cannot emulate PCID) into a
# SEPARATE build-tcg/ dir, so it never clobbers the KVM build/.  ~5 min.
build-tcg:
    @echo "Configuring + building a PCID-off (TCG) image in build-tcg/ …"
    rm -rf build-tcg && mkdir -p build-tcg
    cd build-tcg && ../init-build.sh -DKernelSupportPCID=OFF
    ninja -C build-tcg

# INTERACTIVE graphical boot under TCG software emulation (NOT KVM).  Why: with
# -enable-kvm the live display freezes when you move the mouse over a GTK app —
# orch's busy-poll loop never yields the host CPU, so QEMU's display iothread
# starves (the documented KVM iothread-starvation gotcha).  TCG schedules the
# iothread fairly, so the cursor/click/typing interaction is actually usable
# (just slower to boot).  Needs the PCID-off image: run `just build-tcg` first.
run-gtk-tcg mem="4096":
    @test -f build-tcg/images/sotfs.img || (echo "Run 'just build-tcg' first (TCG needs a PCID-off image)."; exit 1)
    @! ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1 || \
        (echo "ABORT · a QEMU is already running (it holds the img lock). Exit it first."; exit 1)
    @echo "INTERACTIVE TCG boot (slow · NO KVM freeze) · real mouse + keyboard."
    @echo "  Wait for the canary shell → F12 → operator console → type 'gtk3-demo'"
    @echo "  (852x699, fits) → move the mouse in → click a demo-list row."
    qemu-system-x86_64 \
        -m {{mem}} -display gtk,show-cursor=on -vga none -serial stdio -accel tcg -cpu max \
        -kernel build-tcg/images/kernel-x86_64-pc99 \
        -initrd build-tcg/images/sotOs-root-image-x86_64-pc99 \
        -drive file=build-tcg/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        -device virtio-gpu-pci -device virtio-keyboard-pci -device virtio-tablet-pci

# GRAPHICAL-path gate · gtk3-demo under the FULL interactive window stack
# (virtio-gpu + keyboard + tablet), driven HEADLESS via HMP `sendkey`: F12 →
# operator console → type `gtk3-demo`.  Catches the pointer-driven cursor wl_shm
# pool growth (ftruncate + wl_shm_pool.resize) that the headless gtk-gate cannot
# reach — the gap that hid the create_buffer out-of-pool-bounds EPROTO.
gate-gtk3-window:
    @bash tools/gtk3-demo-window-gate.sh

# Wine-prep gate · MAP_FIXED low-address reservation + commit semantics.
# Runs mapfixed.bin (the wine-preloader mmap PATTERN: reserve large PROT_NONE
# Windows ranges, commit sub-ranges via MAP_FIXED + mprotect, non-fixed mmaps
# skip reserved ranges).  De-risks the Wine loader's preloader before the swamp.
gate-mapfixed:
    @bash tools/mapfixed-gate.sh

# compat-host gate · REAL Alpine git (musl-dynamic) runs on sotOs.  The auto-demo
# drives git init/commit/log at Tier-0 in /tmp/gitrepo; the gate asserts a real
# commit is created + read back, the real rename() path fired, and 0 faults.
# Boots in the background and stops early once `[gitdemo] handler DONE` appears.
gate-git:
    @bash tools/git-gate.sh

# internet-egress Phase 1 gate · Tier-0e real DNS forward + Tier-2 canary synth.
# The auto-demo (orch egress-dns) spawns `dnsprobe` early: Tier-0e resolves
# example.com (real forward to 1.1.1.1 · LIVE, opt-in EGRESS_LIVE=1) and a
# Tier-2 box resolves the canary malicious-c2.example (hermetic synth 10.0.2.15).
# The gate asserts the hermetic canary leg + 0 faults; stops at `[egress-dns]
# handler DONE`.  Run `EGRESS_LIVE=1 just gate-egress-dns` (with internet) to
# also assert the real forward.
gate-egress-dns:
    @bash tools/egress-dns-gate.sh

# install-arc P0.2 gate · `dpkg-deb -x /tmp/hello.deb /tmp/root` extracts a real
# tree.  The auto-demo runs `dpkg-install` early; the gate asserts dpkg-deb ran,
# /tmp/root/usr/bin/hello appears in the ls listing (the extracted ELF), 0 faults.
gate-install:
    @bash tools/install-gate.sh

# compat-host gate · a glibc-static binary (real GNU/glibc libc, NOT musl) runs
# on sotOs.  The auto-demo spawns glibc-probe at Tier-0; the gate asserts its
# stdio/malloc/uname/fopen output + 0 faults.  Guards the static-binary AT_PHNUM
# fix that glibc's TLS setup needs.  Stops early at `[glibc] handler DONE`.
gate-glibc:
    @bash tools/glibc-gate.sh

# compat-host gate · real GNU tools (musl-dynamic): GNU coreutils 9.5 (ls/cat/wc),
# grep, sed, gawk run at Tier-0 on the honey /etc/passwd + /tmp.  The GNU userland
# (not busybox) runs on sotOs.  Stops early at `[gnu] handler DONE`.
gate-gnu:
    @bash tools/gnu-gate.sh

# compat-host gate · a glibc-DYNAMIC binary runs via the REAL ld-linux-x86-64.so.2
# (the glibc dynamic linker, not ld-musl).  The auto-demo spawns an off-the-shelf
# glibc PIE at Tier-0; the gate asserts the ld-linux interp + glibc-stdio output +
# 0 faults.  off-the-shelf Debian/Fedora binaries.  Stops early at handler DONE.
gate-glibcdyn:
    @bash tools/glibcdyn-gate.sh

# compat-host gate · real TUI editors (vim/nano/less) over the SSH honey-shell.
# The auto-demo runs each editor's --version at boot; then a real `ssh -tt` pages
# `less /etc/passwd` and the gate asserts the canary content + terminfo screen
# escapes (less DRAWS, not cat-dumps) + 0 faults.  Needs the :22 hostfwd boot line.
gate-tui:
    @bash tools/tui-gate.sh

# Phase 1b gate · disk-backed fs scales + persists (single virtio-blk · data
# region).  Reconfigures with -DSOTOS_FS_GATE=ON so orch boots the 50 MiB
# write/readback + write→simreboot→read self-test (compiled out of every other
# build so it never slows the clock/git/glibcdyn/tui gates), then restores OFF.
gate-fs:
    @bash tools/fs-gate.sh

# compat-host gate · the clock advances + fs metadata believable (no 1970 tell).
# Boots headless off the glibcdyn suite; asserts `date -u` shows a 202x persona
# year (rewired clock_gettime), no guest line shows the 1970 epoch, a listed file
# carries a 202x mtime (sotfs inode timestamps), and 0 faults.
gate-clock:
    @bash tools/clock-gate.sh

# apk-fs P4 Task 8 gate · end-to-end apk install acid test.
# Asserts I1-I4 (fidelity/contained-runs/base-immutable/isolation) + IOC.
# `apk add --allow-untrusted /root/fixture.apk` (bc-1.07.1-r4); session B
# proves the base stays pristine.  Set APK_SIGN=verify for the signed path.
gate-apk-install:
    @bash tools/apk-install-gate.sh

# resource-exhaustion gate · the light-arena mmap-leak that OOMed `ls` after churn.
# Boots headless to the canary shell and drives ~50 `ls` runs over populated dirs,
# then asserts on the serial log: (a) no `cspace exhausted`, (b) every ls exits
# code=0, (c) per-fork `region MMAP` page-count stays bounded (not monotonic), and
# (d) the regular arena actually reclaims (light-box `reused>0` + `[munmap] reclaimed`).
# Exit 3 if a qemu-system already holds the sotfs.img lock.
gate-ls-churn:
    @bash tools/ls-churn-oom-gate.sh

# Wine M1 gate · headless console PE (`wine /usr/lib/wine/hello.exe`).
# Drives the operator console via HMP sendkey (F12 → type `wine`).  Portable:
# auto-detects /dev/kvm (KVM) else TCG.  Classifies Wine-level failures (missing
# DLL, no wineserver, unimplemented) as PROGRESS (gate stays green) and HOST faults
# (#GP / CapFault / EPROTO) as blockers.  Expected RED until the Phase-2 bootstrap
# #GP is cleared; GREEN+string when M1 completes.  See docs/wine-spike.md.
wine-gate:
    @bash tools/wine-gate.sh

# Usage: just run-egress [timeout_s] [log_path]
run-egress timeout="90" log="/tmp/n1a.log":
    @test -f {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 || \
        (echo "Build first with 'just build'"; exit 1)
    @test -f {{BUILD_DIR}}/images/sotfs.img || \
        (echo "sotfs.img missing · run 'just build' to generate it"; exit 1)
    pkill -9 -f '^qemu-system-x86_64 ' 2>/dev/null || true
    sleep 1
    @echo "Booting {{timeout}}s · log → {{log}}"
    timeout {{timeout}} qemu-system-x86_64 \
        -m 4096 -display none -serial stdio \
        {{KVM_FLAGS}} \
        -kernel {{BUILD_DIR}}/images/kernel-x86_64-pc99 \
        -initrd {{BUILD_DIR}}/images/sotOs-root-image-x86_64-pc99 \
        -drive file={{BUILD_DIR}}/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        -object filter-dump,id=f0,netdev=net0,file=/tmp/egress.pcap \
        > {{log}} 2>&1 || true
    @echo ""
    @echo "=== Quick summary ==="
    @grep -E "L11-γ.*stdlib loaded|hello from python|RANSOMWARE|LATERAL|tier2-auto|VMFault|Fatal Python" {{log}} | head -10 || echo "(no markers matched)"
    @echo ""
    @echo "Full log: {{log}} ($(wc -l < {{log}}) lines)"

# L11-β-2 / δ-2 · fetch the static CPython 3.12 (~24 MB) + seed the stdlib
# cache — one download serves the binstore python demo AND the stdlib zip
# packer. Idempotent. Run BEFORE `just build` so sotfs.img embeds python.
fetch-python:
    bash scripts/fetch-python.sh

# Run smoke test suite (L1-L11 milestones + PR 8 STRESS + WAL-UNIT).
# Budget bumped to ~300s for PR 8 · 10x simreboot stress.
# The smoke suite greps completed-arc markers (TCC/RWBIN/binstore/simreboot-
# stress/…), so it builds the FULL demo battery first, then restores the fast
# LEAN default (so subsequent apt/ssh gates boot fast).
smoke:
    @test -f scripts/smoke-l1-l8.sh || (echo "scripts/smoke-l1-l8.sh missing"; exit 1)
    just build-full
    pkill -9 -f '^qemu-system-x86_64 ' 2>/dev/null || true
    sleep 1
    bash scripts/smoke-l1-l8.sh 2>&1 | tail -5; rc=$?; just build-lean; exit $rc

# world-#3 native runtime · host unit test for sotlibc's freestanding C core
# (mem/str/strtoul/printf engine).  The engine is platform-free, so this IS the
# code that runs in the native sotctl binary.
test-sotlibc-unit:
    cc -I include src/test/sotlibc_unit/sotlibc_unit.c src/sotlibc/sotlibc.c -o /tmp/sotlibc_unit
    /tmp/sotlibc_unit

# arc β · host unit test for the pure TCP/IP fingerprint logic (the primary β gate).
test-sotnet-fp-unit:
    cc -I include src/test/sotnet_fp_unit/sotnet_fp_unit.c src/sotnet/tcp_fp.c -o /tmp/sotnet_fp_unit
    /tmp/sotnet_fp_unit

# arc ζ1 · host unit test for the pure SSH wire encoders (byte-exact mpint/string/framer).
test-ssh-kex-unit:
    cc -I include src/test/ssh_kex_unit/ssh_kex_unit.c src/net-synth/ssh_wire.c -o /tmp/ssh_kex_unit
    /tmp/ssh_kex_unit

# Pillar 3 · host unit test for the sottrace ring + the v2.8 deception-monitor formatter.
test-sottrace-unit:
    cc -I include src/sottrace/trace.c src/test/sottrace_unit/sottrace_unit.c -o /tmp/sottrace_unit
    /tmp/sottrace_unit

# host unit test for the pure framebuffer text-console renderer.
test-console-fb-unit:
    cc -DCONSOLE_FB_HOST_TEST -I include src/test/console_fb_unit/console_fb_unit.c src/orch/console_fb.c -o /tmp/cfb
    /tmp/cfb

# host unit test for the pure keycode->ASCII translation.
test-virtio-input-unit:
    cc -DVIRTIO_INPUT_HOST_TEST -I include src/test/virtio_input_unit/virtio_input_unit.c src/orch/virtio_input.c -o /tmp/viu
    /tmp/viu

# host unit test for the pure virtio modern cap-chain parser.
test-virtio-modern-unit:
    cc -DVIRTIO_MODERN_HOST_TEST -I include src/test/virtio_modern_unit/virtio_modern_unit.c src/sotfs/virtio_pci_modern.c -o /tmp/vmu
    /tmp/vmu

# host unit test for the pure framebuffer scale-fill blit.
test-fb-blit-unit:
    cc -I include src/test/fb_blit_unit/fb_blit_unit.c src/orch/fb_blit.c -o /tmp/fbb
    /tmp/fbb

# host unit test for the pure tablet abs->screen mapping.
test-virtio-mouse-unit:
    cc -DVIRTIO_MOUSE_HOST_TEST -I include src/test/virtio_mouse_unit/virtio_mouse_unit.c src/orch/virtio_mouse.c -o /tmp/vmo
    /tmp/vmo

# host unit · per-session termios round-trip (TCSETS then TCGETS returns it)
test-tty-termios-unit:
    cc -I include src/test/tty_termios_unit/tty_termios_unit.c -o /tmp/ttu && /tmp/ttu

# host unit · SSH pty-req/window-change winsize decoders
test-tty-session-unit:
    cc -I include src/test/tty_session_unit/tty_session_unit.c src/lucas/tty_session.c -o /tmp/tsu && /tmp/tsu

# host unit · the SSH-session foreground console-reader predicate
test-tty-fg-unit:
    cc -I include src/test/tty_fg_unit/tty_fg_unit.c -o /tmp/tfu && /tmp/tfu

# ε1 · host unit test for the TLS 1.3 wire helpers (big-endian read/write).
test-tls13-unit:
    cd src/test/tls13_host && make clean && make CC=gcc

# v2-vfs · host round-trip gate for the recursive sysroot packer: files +
# subdirs + symlink LNK targets + determinism.  Pure host (scratch image in
# a tempdir) — no boot, no QEMU, never touches build/images/sotfs.img.
test-sysroot-pack:
    python3 tools/sysroot-pack-test.py

# v2-vfs · host unit test for the sysroot LNK runtime: bounded symlink follow
# (-ELOOP at the bound), relative/absolute target join, O_NOFOLLOW link
# handle, readlink semantics.  Compiles the REAL backends_sysroot.c against a
# synthetic in-memory image (virtio-blk stubbed) — no boot, no QEMU.
test-sysroot-lnk-unit:
    cc -I include src/test/sysroot_lnk_unit/sysroot_lnk_unit.c src/lucas/backends_sysroot.c -o /tmp/srlnk
    /tmp/srlnk

# host unit · lucas_clock TSC->walltime conversion (no seL4)
test-clock-unit:
    cc -I include src/test/clock_unit/clock_unit.c src/lucas/clock.c -o /tmp/clock_unit && /tmp/clock_unit

# host unit · apk-fs P4 PACKAGE_INSTALL path predicate
test-apk-ioc-unit:
    cc -I include -I src/lucas src/test/audit_ipc_unit/apk_ioc_unit.c src/lucas/apk_ioc.c -o /tmp/aiu && /tmp/aiu

# host unit · per-session COW-lite overlay (Tier-2 :w read-back)
test-cow-overlay-unit:
    cc -I include src/test/cow_overlay_unit/cow_overlay_unit.c src/lucas/cow_overlay.c -o /tmp/cou && /tmp/cou

# host unit · per-session sotfs-upper ownership map + reap (apk-fs Phase 1)
test-sotfs-session-unit:
    cc -I include src/test/sotfs_session_unit/sotfs_session_unit.c src/lucas/sotfs_session.c -o /tmp/ssu && /tmp/ssu

# host unit · M3 per-session persona context (set/get/clear keyed by cow_session)
test-persona-session-unit:
    cc -I include src/test/persona_session_unit/persona_session_unit.c src/lucas/persona_session.c -o /tmp/psu && /tmp/psu

# host unit · M4 sotabi render-stream wire codec (pack/unpack byte chunks ↔ words)
test-sotabi-wire-unit:
    cc -I include src/test/sotabi_wire_unit/sotabi_wire_unit.c -o /tmp/saw && /tmp/saw

# boot gate · 2nd-persona round-robin: session1=Alpine, session2=Ubuntu, coherent + diverging
test-second-persona:
    bash tools/second-persona-gate.sh

# apt arc · Phase 0 · real apt staged + loads (no network).
apt-version-gate:
    bash tools/apt-version-gate.sh

# apt arc · Phase 1 · `apt-get update` from the real Debian archive (network-gated).
apt-update-gate:
    bash tools/apt-update-gate.sh

# host unit · apk-fs P3 resolve_path VFS-read fallback (session-gate + upper-before-base)
test-execve-resolve-unit:
    cc -I src/test/execve_resolve_unit src/test/execve_resolve_unit/execve_resolve_unit.c -o /tmp/eru && /tmp/eru

# host unit · apk-fs P2 cross-mount tier-gate + I1/I2 visibility decision
test-sotfs-session-route-unit:
    cc -I include src/test/sotfs_session_route_unit/sotfs_session_route_unit.c src/lucas/sotfs_session.c src/lucas/backends_union.c -o /tmp/ssr && /tmp/ssr

# host unit · contained per-session symlink table (Tier-2 `ln -s` in /tmp)
test-symlink-table-unit:
    cc -I include src/test/symlink_table_unit/symlink_table_unit.c src/lucas/symlink_table.c -o /tmp/slt && /tmp/slt

# host KAT · vendored OpenSSH sntrup761 KEM self-consistency (SSH HASSH arc · phase A)
test-sntrup761-unit:
    cc -O2 -DUSE_SNTRUP761X25519 -DSNTRUP_HOST_KAT -I src/net-synth/sntrup761 src/net-synth/sntrup761/sntrup761.c src/test/sntrup761_unit/sntrup761_unit.c -lcrypto -o /tmp/sntrup && /tmp/sntrup

# host unit · sotfs_blkdev bitmap allocator + LRU buffer cache (no seL4)
test-blkdev-unit:
    cc -I include src/test/blkdev_unit/blkdev_unit.c src/sotfs/blkdev.c -o /tmp/blkdev_unit && /tmp/blkdev_unit

# host unit · pure /usr union resolution + whiteout + getdents-merge (no seL4)
test-union-unit:
    cc -I include src/test/union_unit/union_unit.c src/lucas/backends_union.c -o /tmp/uu && /tmp/uu

# ε1 · live-interop gate · openssl s_client -tls1_3 completes the hand-rolled
# TLS 1.3 handshake against the honeypot :443 (hostfwd :18443) + returns the
# nginx response_profile body, AND a -tls1_2 client falls back to mine2g.  Boots the
# full system headless; NO pkill (operator QEMU holds the sotfs.img write lock).
tls13-gate:
    bash tools/tls13-gate.sh

# v1.0.0-rc1 · validate the whole deception host (v0.84→v0.99 composes, no regress).
v1-rc1:
    bash scripts/v1.0-rc1-validate.sh

# v1.4.0-labyrinth · adversarial campaign: deceives / contains / endures (5 gates).
labyrinth-validate:
    bash scripts/labyrinth-validate.sh

# v1.5.0-24h-real-KVM · literal endurance run (default 24h) on real KVM.  Builds
# fresh, then relaunches the soak boot across a wall-clock window, archiving the
# evidence bundle (build-manifest · serial logs · memory/cslot timeseries · fault
# scan · restart rate · final state) under evidence/.  Needs /dev/kvm.
#   just v15-endurance                      # the real 24h run
#   DURATION=400 SKIP_BUILD=1 just v15-endurance     # a fast 2-boot smoke
v15-endurance:
    bash scripts/v1.5-endurance-run.sh

# Enable diagnostic traces (kernel + fs).  Rebuilds.
# Output prefixes: [k:mrs-fault] [k:iretq] [k:sysrt] [fs] ...
trace-on:
    @test -d {{BUILD_DIR}} || just configure
    cd {{BUILD_DIR}} && cmake -DKernelLucAsTrace=ON -DKernelLucAsFsTrace=ON ..
    ninja -C {{BUILD_DIR}} all
    @echo "Trace ON · 'just run' or 'just run-headless' to capture."

# Disable diagnostic traces (default · silent for STAR deception fidelity).
trace-off:
    @test -d {{BUILD_DIR}} || just configure
    cd {{BUILD_DIR}} && cmake -DKernelLucAsTrace=OFF -DKernelLucAsFsTrace=OFF ..
    ninja -C {{BUILD_DIR}} all
    @echo "Trace OFF · default operational state restored."

# Run TLA+ model checker on STO spec. -deadlock disables terminal-state
# detection: our spec has finite MaxTx so committing all txs is a natural
# end-of-trace, not a bug.
verify:
    @test -f formal/tla/STO.tla || (echo "Missing STO.tla"; exit 1)
    @command -v java >/dev/null || (echo "java not installed"; exit 1)
    @test -f ~/.local/share/tla2tools.jar || \
        (echo "Download tla2tools.jar to ~/.local/share/ from https://github.com/tlaplus/tlaplus/releases"; exit 1)
    cd formal/tla && java -jar ~/.local/share/tla2tools.jar -deadlock -config STO.cfg STO.tla

# Clean build artifacts (does not touch external/).
clean:
    rm -rf {{BUILD_DIR}}

# Wipe external/ too. Use with care.
clean-deps:
    rm -rf external/kernel external/seL4_libs external/util_libs \
        external/musllibc external/seL4_tools
    @echo "external/ wiped. Run 'just bootstrap' to repopulate."

# Check host prerequisites. On Windows this runs inside WSL — if it fails to
# even start, the default WSL distro is wrong (see the header of this file).
doctor:
    @echo "=== sotOs doctor · $(uname -srm) ==="
    @for c in bash git cmake ninja qemu-system-x86_64 python3 cc just; do \
        command -v $c >/dev/null 2>&1 && echo "✓ $c" || echo "✗ $c missing"; done
    @test -w /dev/kvm 2>/dev/null && echo "✓ /dev/kvm (hardware accel)" || \
        echo "△ /dev/kvm absent → QEMU will use TCG software emulation (slow)"
    @case "$(pwd)" in /mnt/*) echo "△ repo under /mnt/* (9p) — builds will be slow; consider cloning into ~/";; \
        *) echo "✓ repo on native filesystem";; esac

# Show project status.
status:
    @echo "=== sotOs status ==="
    @test -d external/kernel && echo "✓ seL4 kernel cloned" || echo "✗ kernel missing"
    @test -d external/seL4_libs && echo "✓ seL4_libs present"  || echo "✗ seL4_libs missing"
    @test -d external/util_libs && echo "✓ util_libs present"  || echo "✗ util_libs missing"
    @test -d external/musllibc && echo "✓ musllibc present"   || echo "✗ musllibc missing"
    @test -d {{BUILD_DIR}}     && echo "✓ Build dir present"  || echo "✗ Build dir absent"
    @git status --short
