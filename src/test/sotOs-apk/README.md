# sotOs-apk fixture

Real Alpine 3.20 `apk.static` binary + signing keys + a local `.apk` fixture,
committed to the repo so the OS build is hermetic (the build never calls podman).
Mirrors the `src/test/sotOs-curl/` layout.

## Source image

`alpine:3.20` (Docker Hub official image).

## Reproduce

```bash
bash scripts/source-apk-fixtures.sh
# or with Docker:
RT=docker bash scripts/source-apk-fixtures.sh
```

The script is idempotent/re-runnable and only needs podman (or docker) + network
access to pull `alpine:3.20`. The build does NOT invoke it.

## Contents

```
src/test/sotOs-apk/
  bin/apk.static     — real Alpine 3.20 apk.static (4.7 MB, static-musl ELF)
  keys/              — Alpine 3.20 signing public keys from /etc/apk/keys/
  deb/fixture.apk    — tiny leaf .apk (the install-gate fixture)
  strace/            — strace recon artifacts (Task 2, populated separately)
```

## apk.static — static-ness result (drives Task 3)

```
file:
  src/test/sotOs-apk/bin/apk.static:
    ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
    statically linked, BuildID[sha1]=b0ad6b977b67bba53eb08d3dfed161077bef2fa8, stripped

ldd:
  not a dynamic executable
```

**STATIC** — Task 3 does NOT need to stage a lib closure. No `src/test/sotOs-apk/lib/`
directory is needed (unlike `sotOs-curl/lib/`). The binstore entry for `apk.static`
is a single file.

## Signing keys

Five keys from `/etc/apk/keys/` are committed. The stable fixed-name key used by
Tasks 6 onward is:

| Filename in repo | Upstream source | Notes |
|-----------------|-----------------|-------|
| `alpine-3.20.rsa.pub` | copy of `alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub` | **PRIMARY** — used to sign Alpine 3.20 main/community packages; this is the key the fixture `.apk` is signed with (`.SIGN.RSA.alpine-devel@...6165ee59.rsa.pub`). CMake embeds this as symbol `apk_key_alpine_3_20`. |
| `alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub` | upstream original name (800 bytes) | same bytes as `alpine-3.20.rsa.pub` |
| `alpine-devel@lists.alpinelinux.org-61666e3f.rsa.pub` | upstream (800 bytes) | |
| `alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub` | upstream (451 bytes) | |
| `alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub` | upstream (451 bytes) | |
| `alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub` | upstream (451 bytes) | |

The CMake `xxd -i -n` symbol for the primary key is `apk_key_alpine_3_20`
(derived from the fixed filename `alpine-3.20.rsa.pub` with non-alnum chars
replaced by `_`).

## Fixture package

**Package:** `ncurses-terminfo-base-6.4_p20240420-r2` (Alpine 3.20/main)

**Type:** data-only package — ships `etc/terminfo/*` terminfo databases, **no ELF**.

**Why this one (NOT bc):** the fixture MUST have **zero shared-library (`so:`)
dependencies**. The canary base seeds an *empty* apk DB, so apk's solver cannot
satisfy any `so:` provider — e.g. `bc` fails with
`ERROR: unable to select packages: so:libc.musl-x86_64.so.1 (no such package)`,
`so:libreadline.so.8 ...`. Data-only packages (terminfo / tzdata / mailcap) install
cleanly against an empty DB. The *installed-binary-runs* proof (I3) is covered
separately + idempotently by `tools/apk-upperexec-gate.sh` (a dynamic-musl ELF
written into the per-session upper at runtime executes via `resolve_path`'s
VFS-upper fallback), so the apk-install gate here proves apk **installs + contains**
(extract + DB + I1/I2/I4 + IOC), not a runnable package binary.

### Installed file list (`tar -tzf deb/fixture.apk`)

```
.SIGN.RSA.alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub
.PKGINFO
etc/terminfo/a/alacritty
etc/terminfo/l/linux
etc/terminfo/v/vt100 … vt220 …   (≈40 terminfo databases across a/ d/ g/ … v/)
```

- `.SIGN.RSA.*.rsa.pub` — RSA signature block (the key apk verifies against in
  `APK_SIGN=verify` mode; staged at `/etc/apk/keys/` under this exact name).
- `.PKGINFO` — package metadata.
- `etc/terminfo/*` — terminfo database files (one of which, `vt220`, the package
  ships as a **hardlink** to `vt200` — exercising the link path of apk's atomic
  install).

**Gate (`tools/apk-install-gate.sh`):** asserts `apk add` runs to completion
(RC=0), `apk info` lists the package, `etc/terminfo/*` extract + read back
in-session, and a second session + the operator see a pristine base (I1/I2). Run
with `APK_SIGN=verify` to drop `--allow-untrusted` and exercise the real RSA
signature verify against the staged key.

## apk syscall set + handler status

Captured by stracing `apk add --allow-untrusted /fixture.apk` inside `alpine:3.20`
with our committed `bc-1.07.1-r4` fixture (`deb/fixture.apk`).  Full trace saved in
`strace/apk-syscalls.txt` (8173 lines).  Deduplication via:

```
grep -oE '^[a-z_0-9]+\(' strace/apk-syscalls.txt | tr -d '(' | sort -u
```

### Deduped syscall set (23 syscalls)

| Syscall | x86-64 # | dispatch.c case | Status |
|---------|-----------|-----------------|--------|
| `access` | 21 | `LX_SYS_access` | OK |
| `close` | 3 | `LX_SYS_close` | OK |
| `execve` | 59 | `LX_SYS_execve` | OK |
| `fcntl` | 72 | `LX_SYS_fcntl` | OK |
| `flock` | 73 | `LX_SYS_flock` (Tier-2 dispatch, line 538) | OK |
| `fstat` | 5 | `LX_SYS_fstat` | OK |
| `fstatfs` | 138 | `LX_SYS_fstatfs` | OK |
| `getdents64` | 217 | `LX_SYS_getdents64` | OK |
| `ioctl` | 16 | `LX_SYS_ioctl` | OK |
| `lseek` | 8 | `LX_SYS_lseek` | OK |
| `mmap` | 9 | `LX_SYS_mmap` | OK |
| `mprotect` | 10 | `LX_SYS_mprotect` | OK |
| `newfstatat` | 262 | `LX_SYS_newfstatat` | OK |
| `open` | 2 | `LX_SYS_open` | OK |
| `openat` | 257 | `LX_SYS_openat` | OK |
| `poll` | 7 | `LX_SYS_poll` | OK |
| `read` | 0 | `LX_SYS_read` | OK |
| `renameat` | 264 | `LX_SYS_renameat` (Tier-1 file mutations, line 503) | OK |
| `select` | 23 | `LX_SYS_select` | OK |
| `stat` | 4 | `LX_SYS_stat` | OK |
| `statfs` | 137 | `LX_SYS_statfs` | OK |
| `write` | 1 | `LX_SYS_write` | OK |
| `writev` | 20 | `LX_SYS_writev` | OK |

Note: `fsync` (74) and `fdatasync` (75) do NOT appear in the strace output for this
fixture install — they were expected candidates but apk does not call them during
`apk add --allow-untrusted`.  Both ARE covered anyway: `safe_noop[]` in dispatch.c
(lines 330-332) returns 0 for these durability hints.  Zero additional work needed.

### VERDICT

**GENUINE GAPS: none.**

All 23 syscalls exercised by `apk add --allow-untrusted /fixture.apk` (bc-1.07.1-r4)
are dispatched by the current LUCAS handler table.  **Task 5 is a no-op** — no new
handlers need to be added to run the apk-install gate.

## Build integration (Tasks 3 + 6)

- `src/CMakeLists.txt` adds `apk.static` to the binstore packer line and defines
  `SOTFS_APK_BIN` / `SOTFS_APK_DIR`.
- `src/lucas/CMakeLists.txt` embeds `fixture.apk` via `xxd -i -n apk_fixture` and
  the primary key via `xxd -i -n apk_key_alpine_3_20`, producing headers
  `build/include/lucas/apk_fixture.h` and `build/include/lucas/apk_keys.h`.
- `src/lucas/backends_static.c` uses `ENTRY_BLOB` to serve `/root/fixture.apk`
  and `/etc/apk/keys/alpine-3.20.rsa.pub` from the canary base.
- No `lib/` staging needed (apk.static is fully static).
