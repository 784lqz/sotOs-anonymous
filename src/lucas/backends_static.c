/*
 * sotOs · LUCAS L2 · static VFS backend.
 *
 * Hardcoded content for /etc/passwd, /etc/hostname, /etc/os-release,
 * /etc/group, /proc/version, etc.
 *
 * L5: profile system.  g_profile selects between Alpine 3.18 (default)
 * and Ubuntu 22.04 identity.  vfs_set_profile() switches the active
 * entries table globally.  Per-sotBox profiles would require threading
 * the profile pointer through every backend op (deferred to L5-T2+).
 */

#include <lucas/vfs.h>
#include <lucas/clock.h>
#include "state.h"
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <sottrace/trace.h>
#include "lucas/cow_overlay.h"   /* Phase C · per-session COW-lite read-merge */
#include "lucas/persona_session.h"  /* M3 · per-caller persona table resolution */
#include "lucas/sotfs_session_route.h"  /* apk-fs P2 · base-miss → shared graph */
#include <lucas/apk_fixture.h>   /* xxd · fixture.apk  → /root/fixture.apk */
#include <lucas/apk_keys.h>      /* xxd · Alpine 3.20 key → /etc/apk/keys/ */

/* === Static entries (path, content, size, mode, dirent_type). === */
typedef struct {
    const char *path;
    const char *content;
    size_t      size;
    uint32_t    mode;
    uint8_t     dirent_type;
} static_entry_t;

static const char etc_passwd[] =
    "root:x:0:0:root:/root:/bin/ash\n"
    "appuser:x:1000:1000:Linux user:/home/appuser:/bin/ash\n";

static const char etc_hostname[] = "alpine-host\n";

static const char etc_group[] =
    "root:x:0:\n"
    "wheel:x:10:root\n"
    "appuser:x:1000:\n"        /* per-user group · makes `id` resolve gid 1000 (was a bare "gid=1000" tell) */
    "users:x:100:appuser\n";

static const char etc_os_release[] =
    "NAME=\"Alpine Linux\"\n"
    "ID=alpine\n"
    "VERSION_ID=3.20.10\n"
    "PRETTY_NAME=\"Alpine Linux v3.20\"\n"
    "HOME_URL=\"https://alpinelinux.org/\"\n"
    "BUG_REPORT_URL=\"https://gitlab.alpinelinux.org/alpine/aports/-/issues\"\n";

static const char etc_resolv_conf[] =
    "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";

static const char proc_version[] =
    "Linux version 6.6.30-0-lts (buildozer@build-3-20-x86_64) (gcc) "
    "#1-Alpine SMP PREEMPT_DYNAMIC 2024-05-22 10:00:00\n";

static const char proc_cpuinfo[] =
    "processor\t: 0\n"
    "vendor_id\t: GenuineIntel\n"
    "model name\t: Intel(R) Xeon(R) CPU E5-2680 v3 @ 2.50GHz\n"
    "cpu family\t: 6\n"
    "cpu MHz\t\t: 2500.000\n"
    "cache size\t: 30720 KB\n"
    "siblings\t: 1\n"
    "cpu cores\t: 1\n"
    "\n";

static const char proc_meminfo[] =
    "MemTotal:        2097152 kB\n"
    "MemFree:         1572864 kB\n"
    "MemAvailable:    1572864 kB\n"
    "Buffers:               0 kB\n"
    "Cached:                0 kB\n";

static const char etc_alpine_release[] = "3.20.10\n";
static const char etc_shells[]         = "/bin/sh\n/bin/ash\n";

/* PR 10 · shell-hook rc files.  Source of [BASHRC-MARKER] when lucas's
 * execve handler rewrites argv to `sh -c 'source /etc/bashrc; ... exec sh'`.
 * Operator-visible serial line: the embedded echo runs as the wrapped
 * shell starts up.  Content is intentionally minimal · the marker is
 * the operator-grep-able token; the surrounding banner gives a human
 * a one-line "yes this fired" indicator.
 *
 * Used by all three profiles (alpine + ubuntu + canary) because the
 * shellhook whitelist is the same in every tier · only the underlying
 * rc-file content differs across profiles (alpine + ubuntu share the
 * canonical marker; canary re-uses it so a Tier-2 sotbox sees the same
 * shell experience after auto-promotion). */
static const char etc_bashrc[] =
    "# /etc/bashrc · sotOs static profile · sourced by lucas shellhook\n"
    "echo '[BASHRC-MARKER] /etc/bashrc sourced by shellhook'\n";
static const char root_bashrc[] =
    "# /root/.bashrc · sotOs static profile · sourced by lucas shellhook\n"
    "echo '[BASHRC-MARKER] /root/.bashrc sourced by shellhook'\n";

#define ENTRY(path_, content_, mode_, type_) \
    { (path_), (content_), sizeof(content_) - 1, (mode_), (type_) }

/* apk-local-install Task 6 · ENTRY variant for binary blobs (xxd arrays).
 * The default ENTRY() uses sizeof()-1 (string-literal only); a .apk has embedded
 * NULs so sizeof()-1 would give the wrong size.  Using sizeof(blob_) directly is
 * a compile-time constant (valid in a static initializer) and equals the xxd _len.
 * Field order matches static_entry_t: path, content, size, mode, dirent_type. */
#define ENTRY_BLOB(path_, blob_, mode_, type_) \
    { (path_), (const char *)(blob_), sizeof(blob_), (mode_), (type_) }

/* L3b-T6: stub content for busybox applet symlinks in /bin.
 * These appear as regular files (mode 0755 executable) so that access()
 * and stat() succeed.  The actual binary is loaded from CPIO by execve.c
 * (resolve_path maps them all to busybox-static.bin). */
static const char bin_busybox_stub[] = "";

/* fidelity · /sbin/apk facade.  A real Alpine ALWAYS has apk; its absence is a
 * 100% tell.  This #! script (run via execve's binfmt_script path) answers the
 * probes recon does first — `apk --version`/`info`/`list`/`policy` — with
 * byte-credible apk-tools 2.14 output, and makes mutating ops (add/del/update/
 * upgrade) fail with apk's real no-repo-cache error.  That reads as a normal
 * network-restricted box AND contains the attacker (no real package install). */
static const char bin_apk_facade[] =
"#!/bin/sh\n"
"_r=https://dl-cdn.alpinelinux.org/alpine/v3.20\n"
"_net(){\n"
"  echo \"fetch $_r/main/x86_64/APKINDEX.tar.gz\"\n"
"  echo \"WARNING: opening from cache $_r/main: No such file or directory\"\n"
"  echo \"fetch $_r/community/x86_64/APKINDEX.tar.gz\"\n"
"  echo \"WARNING: opening from cache $_r/community: No such file or directory\"\n"
"}\n"
"cmd=$1; [ $# -gt 0 ] && shift\n"
"case \"$cmd\" in\n"
"  --version|-V) echo \"apk-tools 2.14.4, compiled for x86_64.\" ;;\n"
"  info)\n"
"    if [ -z \"$1\" ]; then\n"
"      for p in alpine-baselayout alpine-baselayout-data alpine-keys apk-tools \\\n"
"               busybox busybox-binsh ca-certificates-bundle libcrypto3 libssl3 \\\n"
"               musl musl-utils scanelf ssl_client zlib; do echo \"$p\"; done\n"
"    else\n"
"      case \"$1\" in\n"
"        busybox) v=1.36.1-r29; d=\"Size optimized toolbox of many common UNIX utilities\" ;;\n"
"        musl) v=1.2.5-r0; d=\"the musl c library (libc) implementation\" ;;\n"
"        apk-tools) v=2.14.4-r0; d=\"Alpine Package Keeper - package manager\" ;;\n"
"        alpine-baselayout) v=3.6.5-r0; d=\"Alpine base dir structure and init scripts\" ;;\n"
"        ca-certificates-bundle) v=20240705-r0; d=\"Pre generated bundle of Mozilla certificates\" ;;\n"
"        zlib) v=1.3.1-r1; d=\"A compression/decompression Library\" ;;\n"
"        *) v=; d= ;;\n"
"      esac\n"
"      if [ -n \"$v\" ]; then echo \"$1-$v description:\"; echo \"$d\"; echo \"\"; fi\n"
"    fi ;;\n"
"  policy|stats) _net ;;\n"
"  list) echo \"WARNING: This apk-tools requires a repository index.\" ;;\n"
"  search) _net; echo \"ERROR: $_r: No such file or directory\" ;;\n"
"  update) _net; echo \"2 errors; 0 distinct packages available\" ;;\n"
"  add|del|fix|upgrade)\n"
"    _net\n"
"    echo \"ERROR: unable to select packages:\"\n"
"    echo \"  ${1:-world} (no such package):\"\n"
"    echo \"    required by: world[${1:-?}]\" ;;\n"
"  version) _net ;;\n"
"  \"\"|help|--help)\n"
"    echo \"apk-tools 2.14.4, compiled for x86_64.\"\n"
"    echo \"\"\n"
"    echo \"usage: apk [<OPTIONS>...] COMMAND [<ARGUMENTS>...]\" ;;\n"
"  *)\n"
"    echo \"apk-tools 2.14.4, compiled for x86_64.\"\n"
"    echo \"apk: invalid command: $cmd\" ;;\n"
"esac\n";

/* fidelity · /usr/bin/getconf facade.  getconf ships in Alpine's base; its
 * absence is a tell.  Answer the common single-variable queries exactly (the
 * recon path) and -a with a credible NAME=value subset. */
static const char bin_getconf_facade[] =
"#!/bin/sh\n"
"case \"$1\" in\n"
"  -a)\n"
"    echo \"PATH = /bin:/usr/bin\"\n"
"    echo \"POSIX2_BC_BASE_MAX = 99\"\n"
"    echo \"POSIX2_BC_DIM_MAX = 2048\"\n"
"    echo \"POSIX2_BC_SCALE_MAX = 99\"\n"
"    echo \"POSIX2_BC_STRING_MAX = 1000\"\n"
"    echo \"POSIX2_LINE_MAX = 2048\"\n"
"    echo \"_NPROCESSORS_CONF = 1\"\n"
"    echo \"_NPROCESSORS_ONLN = 1\"\n"
"    echo \"PAGESIZE = 4096\"\n"
"    echo \"PAGE_SIZE = 4096\"\n"
"    echo \"PATH_MAX = 4096\"\n"
"    echo \"NAME_MAX = 255\"\n"
"    echo \"ARG_MAX = 2097152\"\n"
"    echo \"LONG_BIT = 64\"\n"
"    echo \"CLK_TCK = 100\" ;;\n"
"  PAGESIZE|PAGE_SIZE) echo 4096 ;;\n"
"  PATH_MAX|_POSIX_PATH_MAX) echo 4096 ;;\n"
"  NAME_MAX) echo 255 ;;\n"
"  ARG_MAX) echo 2097152 ;;\n"
"  LONG_BIT) echo 64 ;;\n"
"  WORD_BIT) echo 32 ;;\n"
"  CLK_TCK) echo 100 ;;\n"
"  OPEN_MAX|_POSIX_OPEN_MAX) echo 1024 ;;\n"
"  _NPROCESSORS_ONLN|_NPROCESSORS_CONF) echo 1 ;;\n"
"  LINE_MAX) echo 2048 ;;\n"
"  *) echo \"getconf: $1: unknown variable\" >&2; exit 1 ;;\n"
"esac\n";

/* fidelity · /usr/bin/crontab facade.  busybox crontab refuses ("must be suid to
 * work properly") because the applet stub is not setuid; a #! facade serves the
 * common probe `crontab -l` (the persona root crontab) directly. */
static const char bin_crontab_facade[] =
"#!/bin/sh\n"
"cmd=-l\n"
"for a in \"$@\"; do case \"$a\" in -l|-e|-r) cmd=$a ;; esac; done\n"
"case \"$cmd\" in\n"
"  -l) cat /etc/crontabs/root 2>/dev/null || echo \"no crontab for root\" ;;\n"
"  -e) exec vi /etc/crontabs/root ;;\n"
"  -r) : ;;\n"
"esac\n";

/* =========================================================================
 * Alpine entries (L2 default · renamed from entries[] for L5).
 * ========================================================================= */
static const static_entry_t alpine_entries[] = {
    /* Directories first · listed for getdents on their parents. */
    /* The VFS root itself.  Without a "/" entry, find_entry("/") missed and
     * stat("/")/open("/") returned -ENOENT — busybox tolerated it but GNU
     * coreutils (`ls /`) aborts "cannot access '/'".  getdents("/") already
     * enumerates the top-level dirs (is_direct_child_of handles parent=="/"),
     * and "/" is not a child of itself, so this only adds the missing root. */
    ENTRY("/",                   "",                 LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc",                "",                 LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/proc",               "",                 LX_S_IFDIR | 0555, LX_DT_DIR),
    ENTRY("/bin",                "",                 LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/sbin",               "",                 LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/usr",                "",                 LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/usr/bin",            "",                 LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/home",               "",                 LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/home/appuser",       "",                 LX_S_IFDIR | 0755, LX_DT_DIR),
    /* MS-M5 scaffold · /lib for dynamic loader. The /lib/* file lookups are
     * served by the real /usr sysroot via the /lib->/usr/lib alias in
     * vfs_resolve(); only the directory entry remains here so stat("/lib") works. */
    ENTRY("/lib",                              "",                    LX_S_IFDIR | 0755, LX_DT_DIR),
    /* L11-γ scaffold · /install + /install/lib dir entries so stat() succeeds
     * along the path before resolution reaches the python_stdlib mount. */
    ENTRY("/install",                          "",                    LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/install/lib",                      "",                    LX_S_IFDIR | 0755, LX_DT_DIR),
    /* Standard top-level dirs · a believable Linux '/' for both the operator
     * console and a guest `ls /` (tmp is also the writable sotfs mount). */
    ENTRY("/tmp",                "",                 LX_S_IFDIR | 01777, LX_DT_DIR),
    ENTRY("/dev",                "",                 LX_S_IFDIR | 0755,  LX_DT_DIR),
    ENTRY("/var",                "",                 LX_S_IFDIR | 0755,  LX_DT_DIR),
    ENTRY("/run",                "",                 LX_S_IFDIR | 0755,  LX_DT_DIR),
    ENTRY("/mnt",                "",                 LX_S_IFDIR | 0755,  LX_DT_DIR),
    ENTRY("/opt",                "",                 LX_S_IFDIR | 0755,  LX_DT_DIR),
    /* sysfs · recon paths an attacker cross-checks against uname / /proc.
     * Coherent Alpine 3.20 · linux-lts 6.6.30 · hostname alpine-host. */
    ENTRY("/sys",                "",                 LX_S_IFDIR | 0555,  LX_DT_DIR),
    ENTRY("/sys/kernel",         "",                 LX_S_IFDIR | 0555,  LX_DT_DIR),
    ENTRY("/sys/kernel/osrelease", "6.6.30-0-lts\n",  LX_S_IFREG | 0444,  LX_DT_REG),
    ENTRY("/sys/kernel/ostype",    "Linux\n",         LX_S_IFREG | 0444,  LX_DT_REG),
    ENTRY("/sys/kernel/hostname",  "alpine-host\n",   LX_S_IFREG | 0444,  LX_DT_REG),
    /* /bin busybox applets (stub · execve maps them to busybox-static.bin). */
    ENTRY("/bin/busybox",        bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/sh",             bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/ash",            bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/ls",             bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/grep",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/cat",            bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/echo",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/printf",         bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/test",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/true",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    /* libsot · the operator's native CLI stub · PATH-found by the trusted shell
     * so `sotctl sessions` resolves + the execve intercept fires.  persona-hidden
     * from the attacker (lucas_persona_hides), so a honey session never sees it. */
    ENTRY("/usr/bin/sotctl",     bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/false",          bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    /* REAL-EXEC · recon + coreutils applet stubs.  A busybox `sh` PATH-search
     * resolves these (they exist), then execve-interception dispatches to
     * busybox-static.bin (argv[0] selects the applet).  Lets the operator (and
     * a guest) actually run uname/id/ps/ss/env/df/… instead of "not found". */
    ENTRY("/bin/uname",          bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/id",             bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/whoami",         bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/hostname",       bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/ps",             bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/env",            bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/df",             bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/free",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/mount",          bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/uptime",         bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/dmesg",          bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/netstat",        bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/ip",             bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/ifconfig",       bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/ss",             bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/find",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/wc",             bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    /* fidelity · busybox applets a recon battery expects (uptime/readlink). */
    ENTRY("/bin/uptime",         bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/readlink",       bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/uptime",     bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/readlink",   bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    /* fidelity · the apk package manager · a real Alpine always has it. */
    ENTRY("/sbin/apk",           bin_apk_facade,     LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/getconf",    bin_getconf_facade, LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/crontab",    bin_crontab_facade, LX_S_IFREG | 04755, LX_DT_REG),
    ENTRY("/bin/head",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/sort",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/date",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/du",             bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/stat",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/kill",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/pidof",          bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/sleep",          bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/which",          bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/wget",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/vi",             bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/base64",         bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/md5sum",         bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/sha256sum",      bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/seq",            bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/basename",       bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/dirname",        bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/xargs",          bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/tr",             bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/cut",            bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/sed",            bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/awk",            bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    /* M2 · 'doom' launcher · busybox PATH-search finds this stub + execve's it;
     * LUCAS intercepts the exec (basename "doom") → orch spawns the real Doom. */
    ENTRY("/bin/doom",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/games/doom",     bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/busybox",    bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/ls",         bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/grep",       bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    /* DECEPTION · python launcher · busybox PATH-search finds these stubs +
     * execve's them → LUCAS intercept (basename python/python3) spawns real
     * CPython into a fresh heavy arena (see orch_spawn_python_pool). */
    ENTRY("/usr/bin/python3",    bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/python3.12", bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/python",     bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/python3",        bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/python",         bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    /* pip · execve-intercepted (src/orch/execve.c): in the operator's `shell
     * --trusted` (Tier-0e · this alpine table) runs REAL `python3 -m pip`.  The
     * stub just makes PATH resolution succeed so the intercept fires.  (The
     * Tier-2 canary table has its own pip stubs → the synthetic facade.) */
    ENTRY("/usr/bin/pip",        bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/pip3",       bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/pip",            bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/pip3",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    /* TUI editors (Task A6) · the REAL off-the-shelf Debian glibc-dynamic
     * less/nano/vim (NOT busybox applets).  A busybox `sh` PATH-search stat()s
     * these stubs (so it does NOT print "not found"); execve-interception then
     * resolves the basename in the binstore (less/nano/vim are packed there) and
     * loads the real editor — which DRAWS via ncurses/terminfo over the SSH pty.
     * (/bin/vi above stays busybox vi; vim is its own basename so they coexist.) */
    ENTRY("/usr/bin/less",       bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/nano",       bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/vim",        bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/curl",       bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/less",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/nano",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/vim",            bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    /* Install-arc P0.1 · the real Debian dpkg toolchain (glibc-dynamic; NOT
     * busybox applets).  Same mechanism as the editors above: these stubs make a
     * PATH-search stat() succeed, then execve-interception resolves the basename
     * in the binstore → loads the real dpkg/dpkg-deb/tar/xz/zstd via ld-linux. */
    ENTRY("/usr/bin/dpkg",       bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/dpkg-deb",   bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/dpkg-split", bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/tar",        bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/xz",         bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/gzip",       bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/zstd",       bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    /* egress P2 · busybox `wget https://…` PATH-searches `openssl` (the TLS s_client
     * helper) · these stubs make the stat()/access(X_OK) succeed at the PATH dirs,
     * then execve resolves the basename `openssl` in the binstore → the REAL Alpine
     * OpenSSL 3.3.7 CLI via ld-musl (libssl/libcrypto staged in the sysroot). */
    ENTRY("/usr/bin/openssl",        bin_busybox_stub, LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/local/bin/openssl",  bin_busybox_stub, LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/local/sbin/openssl", bin_busybox_stub, LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/openssl",            bin_busybox_stub, LX_S_IFREG | 0755, LX_DT_REG),
    /* install-arc P1.4 · dpkg refuses to start unless these helpers are found in
     * PATH (it access(X_OK)s each).  rm/diff are busybox applets (execve runs
     * them); ldconfig/start-stop-daemon are existence-only for `hello` (no libs/
     * services to trigger), so the stub just satisfies the startup check. */
    ENTRY("/usr/bin/rm",                bin_busybox_stub, LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/diff",              bin_busybox_stub, LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/ldconfig",          bin_busybox_stub, LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/start-stop-daemon", bin_busybox_stub, LX_S_IFREG | 0755, LX_DT_REG),
    /* dpkg locates dpkg-deb via a FIXED dir list (/usr/local/sbin,/usr/local/bin,
     * /usr/sbin,/sbin,/bin · NOT /usr/bin or PATH), so a /usr/bin stub is invisible
     * to it.  Stub dpkg-deb in a dir dpkg actually searches; execve still loads the
     * REAL dpkg-deb by basename → binstore. */
    ENTRY("/usr/sbin/dpkg-deb",  bin_busybox_stub, LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/sbin/dpkg-deb",      bin_busybox_stub, LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/dpkg-deb",       bin_busybox_stub, LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/tar",            bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/gzip",           bin_busybox_stub,   LX_S_IFREG | 0755, LX_DT_REG),
    /* Files. */
    ENTRY("/etc/passwd",         etc_passwd,         LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/group",          etc_group,          LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/hostname",       etc_hostname,       LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/os-release",     etc_os_release,     LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/alpine-release", etc_alpine_release, LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/resolv.conf",    etc_resolv_conf,    LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/shells",         etc_shells,         LX_S_IFREG | 0644, LX_DT_REG),
    /* PR 10 · shell-hook rc files · sourced by lucas's execve wrapper. */
    ENTRY("/root",               "",                 LX_S_IFDIR | 0700, LX_DT_DIR),
    ENTRY("/etc/bashrc",         etc_bashrc,         LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/root/.bashrc",       root_bashrc,        LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/proc/version",       proc_version,       LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/proc/cpuinfo",       proc_cpuinfo,       LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/proc/1/cmdline",     "/sbin/init",       LX_S_IFREG | 0444, LX_DT_REG),  /* fidelity · init cmdline */
    ENTRY("/proc/meminfo",       proc_meminfo,       LX_S_IFREG | 0444, LX_DT_REG),
};
#define ALPINE_ENTRIES_COUNT (sizeof(alpine_entries) / sizeof(alpine_entries[0]))

/* =========================================================================
 * Debian GNU/Linux 13 (trixie) content strings · the glibc persona.
 * Sourced to match the staged glibc binaries (debian-bash + debian-* coreutils
 * are Debian 13 · glibc 2.41 · GNU coreutils 9.7), so os-release / ls --version /
 * libc / kernel all tell ONE Debian-13 story under inspection.
 * ========================================================================= */
/* Rich /etc/passwd · the Debian base system users + the bait operator accounts
 * (deploy/dbadmin/ops · the juicy targets), coherent with the prod-app-server
 * persona an attacker is meant to chase. */
static const char debian_passwd[] =
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\n"
    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
    "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
    "systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin\n"
    "systemd-resolve:x:997:997:systemd Resolver:/:/usr/sbin/nologin\n"
    "messagebus:x:100:101::/nonexistent:/usr/sbin/nologin\n"
    "sshd:x:101:65534::/run/sshd:/usr/sbin/nologin\n"
    "postgres:x:111:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    "deploy:x:1000:1000:Deploy Service,,,:/home/deploy:/bin/bash\n"
    "dbadmin:x:1001:1001:Database Admin,,,:/home/dbadmin:/bin/bash\n"
    "ops:x:1002:1002:Operations,,,:/home/ops:/bin/bash\n";

/* Honey hashes (anomaly tripwires · NOT real passwords · any crack attempt is
 * itself an indicator of compromise). */
static const char debian_shadow[] =
    "root:$6$doGf65fNamG9fRsP$XFlvZcOZeggIsbH433AjFmD65T9l7c0d1tMjSI8hoYdsvENzln26Dn4f.WpKHIK6MGOpQu2Wbxel9TWOMfqeA/:19712:0:99999:7:::\n"
    "deploy:$6$6RdmJaiQqz27JY7D$DjBfDKFjO.B/xVKhAfbi8/nBGznAzmV3EKyvJo6GTb2at0fWGbdsfhJVgg0PKqjpaw7uRCkoGJbr5NpjqZIKl.:19801:0:99999:7:::\n"
    "dbadmin:$6$CcdKU6Cw2gRRGKvm$P5btCOIMVnuX7P6/UbrEgaza4pkQK/RlQ.uDgsUMkIeMvfQBGva4dAk7apdM0kl3Ubf43G6ZfaDi.zaYGn9T..:19655:0:99999:7:::\n"
    "ops:$6$D63gsiRyBSi6K.Hg$mw7AObds8dwUg3ChfMm2fEq3tEHZvIKrCeK1GHNg8s6eSOy84hmHtPMyfLxmWmxL24gXQ0Ldvh8RFRKkmHNam1:19840:0:99999:7:::\n";

static const char debian_hostname[] = "debian-app-01\n";

static const char debian_group[] =
    "root:x:0:\n"
    "sudo:x:27:deploy,dbadmin\n"
    "www-data:x:33:\n"
    "postgres:x:117:\n"
    "docker:x:998:deploy\n"
    "users:x:100:deploy,ops\n";

/* recon-bait surface (synthetic honeytokens · the creds/hosts are tripwires).
 * Coherent with the Debian-13 prod-app-server persona: systemd (systemctl/
 * journalctl, NOT OpenRC), apt, docker, a postgres + a web app, deploy creds. */
static const char debian_bash_history[] =
    "ls -la\n"
    "systemctl status app.service\n"
    "journalctl -u app.service --since '1 hour ago' | tail -50\n"
    "docker ps\n"
    "PGPASSWORD='Pr0dDB!2024' psql -h 127.0.0.1 -U dbadmin prod_customers -c 'SELECT count(*) FROM accounts;'\n"
    "pg_dump -U postgres prod_customers | gzip > /var/backups/prod_customers_2025-08-19.sql.gz\n"
    "aws s3 cp /var/backups/prod_customers_2025-08-19.sql.gz s3://acme-prod-backups/\n"
    "ssh deploy@10.0.4.12\n"
    "curl -H \"Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmMtcGF5\" https://api.internal/v1/keys\n"
    "sudo vi /etc/postgresql/16/main/pg_hba.conf\n"
    "sudo systemctl restart postgresql\n"
    "history -c\n";
static const char debian_authlog[] =
    "Aug 19 02:14:07 debian-app-01 sshd[2291]: Accepted password for deploy from 10.0.4.12 port 51234 ssh2\n"
    "Aug 19 02:31:55 debian-app-01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart app.service\n"
    "Aug 19 03:02:11 debian-app-01 sshd[2410]: Failed password for root from 185.142.236.34 port 40221 ssh2\n";
static const char debian_sshd_config[] =
    "#\t$OpenBSD: sshd_config,v 1.104 2021/07/02 05:11:21 dtucker Exp $\n"
    "Include /etc/ssh/sshd_config.d/*.conf\n"
    "Port 22\n"
    "HostKey /etc/ssh/ssh_host_ed25519_key\n"
    "HostKey /etc/ssh/ssh_host_rsa_key\n"
    "SyslogFacility AUTH\n"
    "LogLevel INFO\n"
    "PermitRootLogin yes\n"
    "PubkeyAuthentication yes\n"
    "PasswordAuthentication yes\n"
    "PermitEmptyPasswords no\n"
    "KbdInteractiveAuthentication no\n"
    "UsePAM yes\n"
    "X11Forwarding no\n"
    "ClientAliveInterval 120\n"
    "Subsystem\tsftp\t/usr/lib/openssh/sftp-server\n";
/* Debian uses /etc/crontab (system-wide · the user/command column format). */
static const char debian_crontab[] =
    "# /etc/crontab: system-wide crontab\n"
    "SHELL=/bin/sh\n"
    "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
    "# m h dom mon dow user\tcommand\n"
    "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
    "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || run-parts --report /etc/cron.daily\n"
    "30 1\t* * *\tpostgres\tpg_dump prod_customers | gzip > /var/backups/prod_customers_$(date +\\%F).sql.gz\n"
    "45 1\t* * *\troot\taws s3 cp /var/backups/ s3://acme-prod-backups/ --recursive --quiet\n";
/* apt arc P0 · the FUNCTIONAL sources.list the real Debian apt reads at boot.
 * Single trixie line (Phase 1 later adds [trusted=yes]); still carries
 * "deb.debian.org" so the second-persona recon-bait gate keeps its signal.
 * Keep in sync with src/test/sotOs-apt/etc/apt/sources.list + apt_tree_seed.h. */
static const char debian_sources_list[] =
    "deb [trusted=yes] http://deb.debian.org/debian trixie main\n";
/* apt arc P0 · /etc/apt/apt.conf.d/99sotos · apt drop-in served from the honey
 * base (read-only). Keep in sync with src/test/sotOs-apt/etc/apt/apt.conf.d/99sotos
 * + apt_tree_seed.h (apt_conf_99sotos). */
static const char debian_apt_conf_99sotos[] =
    "Acquire::Languages \"none\";\n"
    "APT::Install-Recommends \"false\";\n"
    /* apt's DynamicMMap defaults to a 24 MiB (25165824 B) initial allocation
     * (APT::Cache-Start).  In a forked Tier-2 SSH session that single anonymous
     * mmap exhausts the client vspace's frame budget mid-allocation
     * ("new_pages_at_vaddr: Failed to allocate page number: 1950 out of 6144" →
     * "Couldn't make mmap of 25165824 bytes - DynamicMMap (12: Cannot allocate
     * memory)"), aborting `apt-get update`.  Shrink the initial cache + cap; apt
     * grows it on demand and the trixie/main index fits comfortably.  Real
     * Debian honours these knobs identically, so a recon attacker sees nothing
     * unusual. */
    /* Modest Cache-Start (8 MiB) · apt's DynamicMMap grows on demand via the
     * in-place mremap extend (handlers_mem.c), which is monotonic + leak-free, so
     * the ~50 MiB trixie/main binary cache builds without the old "Dynamic MMap
     * ran out of room" wall. */
    "APT::Cache-Start \"8388608\";\n"
    "APT::Cache-Grow \"1048576\";\n"
    "APT::Cache-Limit \"50331648\";\n"
    /* Disable the SOURCE package cache (srcpkgcache.bin · only used by
     * `apt-get source`).  Binary `apt install`/`apt-cache` do not need it, and
     * every apt invocation that rebuilds the cache writes a ~50 MiB srcpkgcache
     * TEMP alongside the existing one → the per-session upper's peak exceeded its
     * cap mid-rebuild ("Write error · No space left on device · IO Error saving
     * source cache").  Empty path = don't build/save it; pkgcache is built
     * directly from the Packages lists.  Halves the cache disk footprint. */
    "Dir::Cache::srcpkgcache \"\";\n"
    /* The sotOs guest clock advances from a believable 2026 epoch in-kernel, but
     * glibc reads wall time through the vDSO time page, which this environment
     * does not populate → apt sees ~1970 and rejects the (2026-dated) Release as
     * "not valid yet" / past its Valid-Until.  Disable the date/validity checks
     * (the standard config for a clockless / RTC-less host) so the index is
     * accepted; pairs with the [trusted=yes] floor.  Real Debian honours these
     * knobs identically — no recon tell. */
    "Acquire::Check-Valid-Until \"false\";\n"
    "Acquire::Check-Date \"false\";\n"
    /* gpgv-less acceptance · the repo is [trusted=yes], but apt still forks the
     * gpgv-sq method to verify InRelease, and over the KVM-iothread-paced egress
     * that pipe read intermittently returns EAGAIN ("OpenPGP signature
     * verification failed: … Read error - read (11: Resource temporarily
     * unavailable)") → apt then DISCARDS the just-downloaded Packages index (the
     * decompressed list never lands in /var/lib/apt/lists/, pkgcache stays the
     * dpkg-status stub) → `apt install` "Unable to locate package".  Mark the
     * archive insecure-but-allowed so the unverifiable InRelease can't void the
     * index — apt keeps + uses the Packages regardless.  Real Debian honours
     * these knobs (a [trusted=yes] local mirror is the canonical use). */
    "Acquire::AllowInsecureRepositories \"true\";\n"
    "Acquire::AllowDowngradeToInsecureRepositories \"true\";\n"
    "APT::Get::AllowUnauthenticated \"true\";\n"
    /* Disable the EIPP planner log (/var/log/apt/eipp.log.xz · a pure debug
     * artifact of the install planner).  Writing it spins up an xz encoder whose
     * dictionary + buffers add ~30 MiB of anonymous mmap RIGHT at the peak of
     * `apt install`'s working set — the final straw that tipped apt's 256 MiB
     * heavy arena over (retyped=255 MiB → orch abort just as it mmap'd the xz
     * buffers).  Empty path = no planner log; the install is functionally
     * identical (real Debian honours the knob · no recon tell). */
    "Dir::Log::Planner \"\";\n"
    /* Run dpkg DIRECTLY, not wrapped in a pty.  apt normally allocates a pty
     * (posix_openpt → /dev/ptmx) to capture dpkg's terminal output for
     * /var/log/apt/term.log; this guest has no /dev/ptmx, so posix_openpt fails
     * ("Can not write log (Is /dev/pts mounted?)") and apt aborts the dpkg step
     * before it ever execs `dpkg --unpack` → "Sub-process /usr/bin/dpkg returned
     * an error code (100)" with no real unpack attempted.  Use-Pty false makes
     * apt fork+exec dpkg directly (output inherited) — exactly how dpkg runs in a
     * non-tty/CI context · real Debian honours it · no recon tell. */
    "Dpkg::Use-Pty \"false\";\n";
static const char debian_proc_mounts[] =
    "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
    "/dev/vda1 / ext4 rw,relatime 0 0\n"
    "tmpfs /run tmpfs rw,nosuid,nodev,size=403728k,mode=755 0 0\n";

/* EXACT /etc/os-release from debian:13-slim (trixie). */
static const char debian_os_release[] =
    "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n"
    "NAME=\"Debian GNU/Linux\"\n"
    "VERSION_ID=\"13\"\n"
    "VERSION=\"13 (trixie)\"\n"
    "VERSION_CODENAME=trixie\n"
    "ID=debian\n"
    "HOME_URL=\"https://www.debian.org/\"\n"
    "SUPPORT_URL=\"https://www.debian.org/support\"\n"
    "BUG_REPORT_URL=\"https://bugs.debian.org/\"\n";

static const char debian_resolv_conf[] =
    "# Debian /etc/resolv.conf\n"
    "nameserver 1.1.1.1\n"
    "nameserver 8.8.8.8\n";

static const char debian_nsswitch_conf[] =
    "passwd:         files\ngroup:          files\nshadow:         files\n"
    "hosts:          files dns\nnetworks:       files\n"
    "protocols:      db files\nservices:       db files\n";
static const char debian_hosts[] =
    "127.0.0.1\tlocalhost\n127.0.1.1\tdebian-app-01\n"
    "::1\tlocalhost ip6-localhost ip6-loopback\n";

static const char debian_shells[] =
    "# /etc/shells: valid login shells\n"
    "/bin/sh\n/bin/bash\n/bin/rbash\n/bin/dash\n/usr/bin/sh\n/usr/bin/bash\n";

/* Debian 13 kernel identity (Linux 6.12 LTS).  uname's release/version
 * (handlers_proc.c) MUST match this /proc/version exactly. */
static const char debian_proc_version[] =
    "Linux version 6.12.43+deb13-amd64 (debian-kernel@lists.debian.org) "
    "(gcc-14 (Debian 14.2.0-19) 14.2.0, GNU ld (GNU Binutils for Debian) 2.44) "
    "#1 SMP PREEMPT_DYNAMIC Debian 6.12.43-1 (2025-08-21)\n";

/* /etc/debian_version · EXACT from debian:13-slim. */
static const char debian_etcver[] = "13.5\n";

static const char debian_issue[] =
    "Debian GNU/Linux 13 \\n \\l\n\n";

static const char debian_motd[] =
    "Linux debian-app-01 6.12.43+deb13-amd64 #1 SMP PREEMPT_DYNAMIC "
    "Debian 6.12.43-1 (2025-08-21) x86_64\n\n"
    "The programs included with the Debian GNU/Linux system are free software;\n"
    "the exact distribution terms for each program are described in the\n"
    "individual files in /usr/share/doc/*/copyright.\n\n";

static const char debian_proc_cpuinfo[] =
    "processor\t: 0\n"
    "vendor_id\t: GenuineIntel\n"
    "model name\t: Intel Xeon\n"
    "cpu cores\t: 1\n"
    "\n";

static const char debian_proc_meminfo[] =
    "MemTotal:        2097152 kB\n"
    "MemFree:         1572864 kB\n";

/* ── per-user /home bait (Debian canary · deploy / dbadmin / ops accounts) ──
 * Honeytokens an attacker recon's: a (synthetic) SSH private key (USE = an IOC
 * tripwire), known_hosts naming lateral targets, a .pgpass with prod DB creds,
 * a deploy git/docker history, an .aws/credentials.  All FAKE · systemd/apt/git
 * flavored to stay coherent with the Debian app-server persona. */
static const char deploy_bash_history[] =
    "cd /srv/app\n"
    "git pull origin main\n"
    "docker compose pull && docker compose up -d\n"
    "sudo systemctl restart app.service\n"
    "journalctl -u app.service -f\n"
    "ssh ops@10.0.4.20\n"
    "aws s3 sync ./dist s3://acme-app-assets/ --acl public-read\n"
    "history -c\n";
static const char deploy_ssh_id_rsa[] =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "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\n"
    "-----END OPENSSH PRIVATE KEY-----\n";
static const char deploy_known_hosts[] =
    "10.0.4.20 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCta/XGTBBToEMdG+1/bTTdaGmKj3iWNtSNeBkhU1AQyN+Gp49UCjsASb1HUj8AM78xTys18QxRupMDaSW5a/KtkZjnretOgiWCfkCRyk6+ExnlPnGpFdQ5GPiLkKwVmyPUdZeeViDZW+FEMqil13Pai5+AHMDBYDgjhPMWV5YAvUVrvHhdV6qtG8ydyMZz8sSMLH5YiawuEk0klmtXaiEh8q7XgOVtbvnTyU6nuzd3BD2NEizwC6SeGX9sQayrAVmAvLo/qNvgKV1S0AQS5MJt4jWB54KH+fpOhsTePSA3XlVZUZHTuKGvXsuqIHGo8Wl89ye60q134UjoseJKlqlOzwC0LgP8UZslyPkwloIJix7Xh/nkX2cUB+XnKgZSgA29CphP4vJQEfHG/UDlYbvzUEEjJzeShLCtQ+u+iDlVb+f6cd3BSrMOXA+J/gL17Mn6IkutlozuYn4PGCSEIn6CKXUNVxesOdCNgG/g4vrozCn72lEQqX9nG2JpTjETVqM=\n"
    "git.corp.internal ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCta/XGTBBToEMdG+1/bTTdaGmKj3iWNtSNeBkhU1AQyN+Gp49UCjsASb1HUj8AM78xTys18QxRupMDaSW5a/KtkZjnretOgiWCfkCRyk6+ExnlPnGpFdQ5GPiLkKwVmyPUdZeeViDZW+FEMqil13Pai5+AHMDBYDgjhPMWV5YAvUVrvHhdV6qtG8ydyMZz8sSMLH5YiawuEk0klmtXaiEh8q7XgOVtbvnTyU6nuzd3BD2NEizwC6SeGX9sQayrAVmAvLo/qNvgKV1S0AQS5MJt4jWB54KH+fpOhsTePSA3XlVZUZHTuKGvXsuqIHGo8Wl89ye60q134UjoseJKlqlOzwC0LgP8UZslyPkwloIJix7Xh/nkX2cUB+XnKgZSgA29CphP4vJQEfHG/UDlYbvzUEEjJzeShLCtQ+u+iDlVb+f6cd3BSrMOXA+J/gL17Mn6IkutlozuYn4PGCSEIn6CKXUNVxesOdCNgG/g4vrozCn72lEQqX9nG2JpTjETVqM=\n"
    "registry.corp.internal ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDYtJK0HTOX3tK3ALZU5sP89zANZkkcpQdSuPcDYRsnXMCOOWrD5M/+pGpVHIleNoTN6wRDfNE6kIlOH6fjJuej+mAzRKBBG7B79NYNt/mermJnRjg8KdxnbOciBfa61rI1Uc+VQ+AmvHwonnkFAR35uOVqtd1YAYJRj/rfuk7RawyxZCZNvjwqOpn9QZxhN/Y9887IakMmD28ae85e4/G5/oQ4KBXzw9S2Y0w9gFl97IkNbzZPGUHJ+Z1S+PUiLREBBKPbZImmq1C0n1f9hQ4o8ZTlwFOksObYVnBqluyeW+cwpYrlNhXkBIBFbcmM8+WeBO+OlQj2JGylZqv5MYSO9gfp15wCNYwZqd1ME2CkUcmK3HexWLsHuVqWCh1x4Sq69kayWKoXNNR4IQoJuNLgOWts7EWVMrFiC9fquYGEgG6brTQ9XkZFr3HyVb/tl6icQBttYAQ2/H0c1uIlEnMy/4NhdVpCIWTK114Jd+0a7IVV0YW8rpiwOO15sfpVNnM=\n";
static const char deploy_gitconfig[] =
    "[user]\n\tname = Deploy Service\n\temail = deploy@acme.internal\n"
    "[credential]\n\thelper = store\n"
    "[remote \"origin\"]\n\turl = https://oauth2:ghp_8Kd2mNp4Qr7vWx1aB3cE5fH9jL0nP6sT2uY@git.corp.internal/acme/app.git\n";
static const char dbadmin_pgpass[] =
    "# hostname:port:database:username:password\n"
    "127.0.0.1:5432:prod_customers:dbadmin:Pr0dDB!2024\n"
    "10.0.4.30:5432:billing:billing_rw:B1ll1ngRW!2024\n";
static const char dbadmin_bash_history[] =
    "psql -U dbadmin -h 127.0.0.1 prod_customers\n"
    "pg_dump -U dbadmin prod_customers > /var/backups/prod_customers.sql\n"
    "sudo systemctl status postgresql\n"
    "vacuumdb -U dbadmin -z prod_customers\n"
    "history -c\n";
static const char ops_bash_history[] =
    "sudo apt update && sudo apt upgrade -y\n"
    "docker ps -a\n"
    "systemctl list-units --failed\n"
    "tail -f /var/log/syslog\n"
    "history -c\n";

/* =========================================================================
 * Debian 13 (trixie) entries table (LUCAS_PROFILE_DEBIAN) · a rich tier-2
 * canary: a believable prod-app-server (debian-app-01) an attacker recon's —
 * systemd + apt + a postgres/web app, juicy honeytokens (DB creds, deploy host,
 * S3 backups, an internal API bearer).  Parallel to the Alpine prod-db-01 canary.
 * ========================================================================= */
static const static_entry_t debian_entries[] = {
    /* The VFS root itself.  alpine_entries + canary_entries have it but the
     * Debian persona table didn't → find_entry("/") missed → stat("/")/chdir("/")
     * returned ENOENT.  Harmless for most tools, but apt's forked dpkg child
     * does `chdir(DPkg::Run-Directory="/")` and `_exit(100)`s if it fails → the
     * "Sub-process /usr/bin/dpkg returned an error code (100)" with no unpack.
     * getdents("/") already enumerates top-level dirs via is_direct_child_of. */
    ENTRY("/",                   "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc",                "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/proc",               "",                   LX_S_IFDIR | 0555, LX_DT_DIR),
    ENTRY("/bin",                "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/sbin",               "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/home",               "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/home/deploy",        "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/home/deploy/.ssh",   "",                   LX_S_IFDIR | 0700, LX_DT_DIR),
    ENTRY("/home/dbadmin",       "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/home/ops",           "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    /* per-user /home bait · the recon payoff (synthetic honeytokens · systemd/git) */
    ENTRY("/home/deploy/.ssh/id_rsa",      deploy_ssh_id_rsa,   LX_S_IFREG | 0600, LX_DT_REG),
    ENTRY("/home/deploy/.ssh/known_hosts", deploy_known_hosts,  LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/home/deploy/.bash_history",    deploy_bash_history, LX_S_IFREG | 0600, LX_DT_REG),
    ENTRY("/home/deploy/.gitconfig",       deploy_gitconfig,    LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/home/dbadmin/.pgpass",         dbadmin_pgpass,      LX_S_IFREG | 0600, LX_DT_REG),
    ENTRY("/home/dbadmin/.bash_history",   dbadmin_bash_history,LX_S_IFREG | 0600, LX_DT_REG),
    ENTRY("/home/ops/.bash_history",       ops_bash_history,    LX_S_IFREG | 0600, LX_DT_REG),
    ENTRY("/var",                "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/var/log",            "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/var/backups",        "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/ssh",            "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/apt",            "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/apt/apt.conf.d", "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/apt/preferences.d", "",                LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/passwd",         debian_passwd,         LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/shadow",         debian_shadow,         LX_S_IFREG | 0640, LX_DT_REG),
    ENTRY("/etc/group",          debian_group,          LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/hostname",       debian_hostname,       LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/os-release",     debian_os_release,     LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/debian_version", debian_etcver,         LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/issue",          debian_issue,          LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/motd",           debian_motd,           LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/resolv.conf",    debian_resolv_conf,    LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/nsswitch.conf",  debian_nsswitch_conf,  LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/hosts",          debian_hosts,          LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/shells",         debian_shells,         LX_S_IFREG | 0644, LX_DT_REG),
    /* recon bait · the honeytoken surface (creds/hosts/S3 trail an attacker chases) */
    ENTRY("/etc/ssh/sshd_config",debian_sshd_config,    LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/apt/sources.list",debian_sources_list,  LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/apt/apt.conf.d/99sotos", debian_apt_conf_99sotos, LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/crontab",        debian_crontab,        LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/var/log/auth.log",   debian_authlog,        LX_S_IFREG | 0640, LX_DT_REG),
    ENTRY("/root/.bash_history", debian_bash_history,   LX_S_IFREG | 0600, LX_DT_REG),
    ENTRY("/proc/mounts",        debian_proc_mounts,    LX_S_IFREG | 0444, LX_DT_REG),
    /* PR 10 · shell-hook rc files · sourced by lucas's execve wrapper. */
    ENTRY("/root",               "",                    LX_S_IFDIR | 0700, LX_DT_DIR),
    ENTRY("/etc/bashrc",         etc_bashrc,            LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/root/.bashrc",       root_bashrc,           LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/proc/version",       debian_proc_version,   LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/proc/cpuinfo",       debian_proc_cpuinfo,   LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/proc/meminfo",       debian_proc_meminfo,   LX_S_IFREG | 0444, LX_DT_REG),
    /* 2nd-persona · the Debian package manager is present (stat-able in PATH) so
     * bash finds it and execve's it → the REAL apt binary loads by basename via
     * the binstore (resolve_path · the synthetic facade was retired).  A real
     * Debian has apt/apt-get; a real Alpine (canary_entries) does not. */
    ENTRY("/usr/bin/apt",        bin_busybox_stub,      LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/apt-get",    bin_busybox_stub,      LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/apt-cache",  bin_busybox_stub,      LX_S_IFREG | 0755, LX_DT_REG),
    /* dpkg present (the Debian dpkg facade fires · execve.c) — a real Debian box
     * has dpkg; a real Alpine (canary_entries) does not. */
    ENTRY("/usr/bin/dpkg",       bin_busybox_stub,      LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/dpkg-query", bin_busybox_stub,      LX_S_IFREG | 0755, LX_DT_REG),
    /* dpkg's checkpath() (src/main/help.c) verifies its helper programs are in
     * PATH + executable before unpacking: { sh, rm, tar, diff, dpkg-deb,
     * ldconfig, start-stop-daemon }.  tar/dpkg-deb live in the sysroot /usr/bin
     * (found via the /usr union); sh/rm/diff resolve as busybox applets; but
     * ldconfig + start-stop-daemon are neither → dpkg aborted "2 expected
     * programs not found in PATH or not executable".  dpkg searches /sbin too
     * (the static "/" backend), so stat-able executable stubs here satisfy the
     * check.  hello has no init script → they're never actually exec'd. */
    ENTRY("/sbin/ldconfig",          bin_busybox_stub,  LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/sbin/start-stop-daemon", bin_busybox_stub,  LX_S_IFREG | 0755, LX_DT_REG),
    /* sudo present (deploy is in the sudo group) — stat-able so the honey shell
     * execve's it; execve.c intercepts `sudo apt …` by basename, strips the
     * wrapper, and runs the apt pool euid-root.  Setuid bit (04755) for fidelity
     * (`ls -l /usr/bin/sudo` shows the real -rwsr-xr-x). */
    ENTRY("/usr/bin/sudo",       bin_busybox_stub,      LX_S_IFREG | 04755, LX_DT_REG),
};
#define DEBIAN_ENTRIES_COUNT (sizeof(debian_entries) / sizeof(debian_entries[0]))

/* =========================================================================
 * L7 · Tier 2 isolated-write path canary content.
 *
 * The synthetic content displayed to a sotBox that has been atomically
 * cap-swapped to the shadow STO server.  Designed to attract
 * malware: looks like a default admin account on an exposed box,
 * with a backup user named 'backer' (who has a weak shell config).
 * In a real engagement the anomaly would tail every read of
 * /etc/shadow or /etc/passwd from Tier 2 sotBoxes and signal SOC.
 * ========================================================================= */
/* fidelity · /etc/group coherent with canary_passwd (admin=1000, backer=1001,
 * ops=1002) so `groups`/`id -Gn` resolve the gids to names instead of
 * "groups: unknown ID 1000". */
static const char canary_group[] =
    "root:x:0:root\n"
    "bin:x:1:root,bin,daemon\n"
    "daemon:x:2:root,bin,daemon\n"
    "sys:x:3:root,bin\n"
    "adm:x:4:root,daemon\n"
    "tty:x:5:\n"
    "disk:x:6:root\n"
    "lp:x:7:lp\n"
    "kmem:x:9:\n"
    "wheel:x:10:root\n"
    "floppy:x:11:root\n"
    "mail:x:12:mail\n"
    "news:x:13:news\n"
    "uucp:x:14:uucp\n"
    "cron:x:16:cron\n"
    "audio:x:18:\n"
    "cdrom:x:19:\n"
    "dialout:x:20:root\n"
    "ftp:x:21:\n"
    "sshd:x:22:\n"
    "input:x:23:\n"
    "tape:x:26:root\n"
    "video:x:27:root\n"
    "netdev:x:28:\n"
    "kvm:x:34:kvm\n"
    "games:x:35:\n"
    "shadow:x:42:\n"
    "postgres:x:70:\n"
    "www-data:x:82:\n"
    "users:x:100:games\n"
    "ntp:x:123:\n"
    "admin:x:1000:\n"
    "backer:x:1001:\n"
    "ops:x:1002:\n";

/* Believable Alpine /etc/passwd · the system users a real box has, the postgres
 * service account (uid 70 · so `ps`/`id`/`getent` resolve the DB processes to
 * "postgres"), and the juicy persona users (admin/backer/ops). */
static const char canary_passwd[] =
    "root:x:0:0:root:/root:/bin/bash\n"
    "bin:x:1:1:bin:/bin:/sbin/nologin\n"
    "daemon:x:2:2:daemon:/sbin:/sbin/nologin\n"
    "adm:x:3:4:adm:/var/adm:/sbin/nologin\n"
    "lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\n"
    "sync:x:5:0:sync:/sbin:/bin/sync\n"
    "shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\n"
    "halt:x:7:0:halt:/sbin:/sbin/halt\n"
    "mail:x:8:12:mail:/var/mail:/sbin/nologin\n"
    "news:x:9:13:news:/usr/lib/news:/sbin/nologin\n"
    "uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin\n"
    "operator:x:11:0:operator:/root:/sbin/nologin\n"
    "man:x:13:15:man:/usr/man:/sbin/nologin\n"
    "cron:x:16:16:cron:/var/spool/cron:/sbin/nologin\n"
    "ftp:x:21:21::/var/lib/ftp:/sbin/nologin\n"
    "sshd:x:22:22:sshd:/dev/null:/sbin/nologin\n"
    "games:x:35:35:games:/usr/games:/sbin/nologin\n"
    "postgres:x:70:70::/var/lib/postgresql:/bin/sh\n"
    "ntp:x:123:123:NTP:/var/empty:/sbin/nologin\n"
    "guest:x:405:100:guest:/dev/null:/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/:/sbin/nologin\n"
    "admin:x:1000:1000:Administrator,,,:/home/admin:/bin/bash\n"
    "backer:x:1001:1001:Backup Service,,,:/var/backups:/bin/bash\n"
    "ops:x:1002:1002:OpsEng,,,:/home/ops:/bin/bash\n";

/* Synthetic /etc/shadow with canary hashes (these are not real passwords;
 * they're anomaly markers · any attempt to crack them is itself an
 * indicator of compromise the operator can act on). */
static const char canary_shadow[] =
    "root:$6$exfe8PX/Eml5Xq4/$fPMUmHOtwU2ctE8N2LhIto6D5k6wKWBmWtCjeRK7GxqkScl6e53CBeF0EEvYv.lQHeqLNnsGeDltEkb13mkmL.:19698:0:99999:7:::\n"
    "admin:$6$sNFD/TLOMaK7p59m$16YDS0sGtF/9mb5dJUWicy0VPmP7Kl5WjM3dzDE7U0mohM4U28m/.29iQwLKuR6J/1ep6hpsFkIY2FUHlx9c..:19777:0:99999:7:::\n"
    "backer:$6$NixrV4KtEQ8qcfyz$UGyiLLBTK2sHHyhMI6Bg4SbLsXIs1CDI5NlSySS.xHbGjINnJczoDgOaAKyYwMO7bwKGaBEMa8SyHFxxoI0Kq0:19620:0:99999:7:::\n"
    "ops:$6$pYZF3ge6lQt1TcVu$WHqNmsrcfch0Ot2LccLkpRBTSZ4/l2MPJDDv350QYnhh2oZaYuRfpYzHOt/TYWG/aM0PzZn4u/9JVV5zmR9FN1:19833:0:99999:7:::\n";

static const char canary_hostname[] = "prod-db-01\n";

/* Persona COHERENCE · the uname syscall + /sys/kernel/osrelease + the served
 * /proc/version are all Alpine 3.20 / linux-lts 6.6.30 / alpine-host.  A Ubuntu
 * os-release here contradicted all of them (a fidelity tell a recon script
 * catches instantly: `uname -r`=6.6.30-0-lts but os-release=Ubuntu).  Keep the
 * whole canary persona one coherent Alpine host. */
static const char canary_os_release[] =
    "NAME=\"Alpine Linux\"\n"
    "ID=alpine\n"
    "VERSION_ID=3.20.10\n"
    "PRETTY_NAME=\"Alpine Linux v3.20\"\n"
    "HOME_URL=\"https://alpinelinux.org/\"\n"
    "BUG_REPORT_URL=\"https://gitlab.alpinelinux.org/alpine/aports/-/issues\"\n";

static const char canary_resolv_conf[] =
    "nameserver 10.0.0.1\n"      /* lie · suggests internal network */
    "nameserver 10.0.0.2\n"
    "search corp.internal\n";

static const char canary_shells[] = "/bin/sh\n/bin/ash\n/bin/bash\n";

/* Fidelity · recon-surface canary files an attacker reaches via ls/cat.  All
 * SYNTHETIC canaries (the credentials/hosts are tripwires, not real secrets). */
/* Coherent with the prod-db-01 PostgreSQL persona (ps shows a postgres cluster)
 * + Alpine/OpenRC (rc-service, not systemctl) · juicy honeytokens (DB creds,
 * deploy host, S3 backups, an internal API bearer) an attacker will chase. */
static const char canary_bash_history[] =
    "ls -la\n"
    "free -m\n"
    "psql -U postgres -l\n"
    "PGPASSWORD='Pr0dDB!2023' psql -h 127.0.0.1 -U postgres prod_customers -c 'SELECT count(*) FROM accounts;'\n"
    "pg_dump -U postgres prod_customers | gzip > /var/backups/prod_customers_2024-05-28.sql.gz\n"
    "aws s3 cp /var/backups/prod_customers_2024-05-28.sql.gz s3://acme-prod-backups/\n"
    "ssh deploy@10.0.4.12\n"
    "curl -H \"Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmMtcGF5\" https://api.internal/v1/keys\n"
    "vi /var/lib/postgresql/16/data/pg_hba.conf\n"
    "rc-service postgresql restart\n"
    "history -c\n";
static const char canary_authlog[] =
    "May 28 02:14:07 prod-db-01 sshd[2291]: Accepted password for admin from 10.0.4.12 port 51234 ssh2\n"
    "May 28 02:31:55 prod-db-01 sudo:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash\n"
    "May 28 03:02:11 prod-db-01 sshd[2410]: Failed password for root from 185.142.236.34 port 40221 ssh2\n";
/* Believable OpenSSH server config · what recon reads to learn the auth posture
 * (root login allowed via password → consistent with the honeypot accepting). */
static const char canary_sshd_config[] =
    "#\t$OpenBSD: sshd_config,v 1.104 2021/07/02 05:11:21 dtucker Exp $\n"
    "Port 22\n"
    "AddressFamily any\n"
    "ListenAddress 0.0.0.0\n"
    "HostKey /etc/ssh/ssh_host_ed25519_key\n"
    "HostKey /etc/ssh/ssh_host_rsa_key\n"
    "SyslogFacility AUTH\n"
    "LogLevel INFO\n"
    "PermitRootLogin yes\n"
    "PubkeyAuthentication yes\n"
    "PasswordAuthentication yes\n"
    "PermitEmptyPasswords no\n"
    "ChallengeResponseAuthentication no\n"
    "UsePAM no\n"
    "AllowTcpForwarding yes\n"
    "X11Forwarding no\n"
    "ClientAliveInterval 120\n"
    "Subsystem sftp /usr/lib/ssh/sftp-server\n";
/* Root crontab · the Alpine /etc/crontabs/root template + a nightly pg_dump that
 * dangles the backup path / S3 trail (another honeytoken for the persona). */
static const char canary_crontab[] =
    "# do daily/weekly/monthly maintenance\n"
    "# min\thour\tday\tmonth\tweekday\tcommand\n"
    "*/15\t*\t*\t*\t*\trun-parts /etc/periodic/15min\n"
    "0\t*\t*\t*\t*\trun-parts /etc/periodic/hourly\n"
    "0\t2\t*\t*\t*\trun-parts /etc/periodic/daily\n"
    "0\t3\t*\t*\t6\trun-parts /etc/periodic/weekly\n"
    "0\t5\t1\t*\t*\trun-parts /etc/periodic/monthly\n"
    "30\t1\t*\t*\t*\tpg_dump -U postgres prod_customers | gzip > /var/backups/prod_customers_$(date +\\%F).sql.gz\n"
    "45\t1\t*\t*\t*\taws s3 cp /var/backups/ s3://acme-prod-backups/ --recursive --quiet\n";
/* apk-local-install · a coherent apk config matching the persona's Alpine 3.20.
 * With no APKINDEX cached, a bare `apk add <name>` fails like a no-network box,
 * while `apk add --allow-untrusted /root/fixture.apk` installs from the local
 * file into the per-session upper. */
static const char canary_apk_repositories[] =
    "https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n"
    "https://dl-cdn.alpinelinux.org/alpine/v3.20/community\n";
/* /etc/apk/world + /lib/apk/db/installed start EMPTY (nothing installed yet);
 * the `apk add` writes land in the per-session sotfs upper, not this base. */
static const char canary_apk_empty[] = "";

static const char canary_proc_mounts[] =
    "/dev/sda1 / ext4 rw,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec 0 0\n"
    "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n";
static const char canary_proc_loadavg[] = "0.08 0.03 0.01 1/214 2531\n";
static const char canary_proc_uptime[]  = "184726.43 1438209.11\n";
static const char canary_proc_nettcp[]  =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 14523 1\n";

/* ── per-user /home bait (Alpine canary · the admin DB-ops account) ──────────
 * Honeytokens an attacker recon's after landing: a (synthetic) SSH private key
 * (any USE of it is an IOC tripwire), known_hosts naming lateral targets, a
 * .pgpass with prod DB creds, and an admin-flavored shell history.  All FAKE. */
static const char admin_bash_history[] =
    "ls -la\n"
    "sudo -i\n"
    "psql -U postgres -h 127.0.0.1 prod_customers\n"
    "pg_dump -U postgres prod_customers | gzip > /var/backups/prod_customers.sql.gz\n"
    "ssh deploy@10.0.4.12\n"
    "scp /var/backups/prod_customers.sql.gz backup@10.0.4.30:/srv/backups/\n"
    "kubectl --kubeconfig ~/.kube/config get pods -n prod\n"
    "history -c\n";
static const char admin_ssh_id_rsa[] =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "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\n"
    "-----END OPENSSH PRIVATE KEY-----\n";
static const char admin_ssh_known_hosts[] =
    "10.0.4.20 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDYtJK0HTOX3tK3ALZU5sP89zANZkkcpQdSuPcDYRsnXMCOOWrD5M/+pGpVHIleNoTN6wRDfNE6kIlOH6fjJuej+mAzRKBBG7B79NYNt/mermJnRjg8KdxnbOciBfa61rI1Uc+VQ+AmvHwonnkFAR35uOVqtd1YAYJRj/rfuk7RawyxZCZNvjwqOpn9QZxhN/Y9887IakMmD28ae85e4/G5/oQ4KBXzw9S2Y0w9gFl97IkNbzZPGUHJ+Z1S+PUiLREBBKPbZImmq1C0n1f9hQ4o8ZTlwFOksObYVnBqluyeW+cwpYrlNhXkBIBFbcmM8+WeBO+OlQj2JGylZqv5MYSO9gfp15wCNYwZqd1ME2CkUcmK3HexWLsHuVqWCh1x4Sq69kayWKoXNNR4IQoJuNLgOWts7EWVMrFiC9fquYGEgG6brTQ9XkZFr3HyVb/tl6icQBttYAQ2/H0c1uIlEnMy/4NhdVpCIWTK114Jd+0a7IVV0YW8rpiwOO15sfpVNnM=\n"
    "db-replica-01.corp.internal ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDYtJK0HTOX3tK3ALZU5sP89zANZkkcpQdSuPcDYRsnXMCOOWrD5M/+pGpVHIleNoTN6wRDfNE6kIlOH6fjJuej+mAzRKBBG7B79NYNt/mermJnRjg8KdxnbOciBfa61rI1Uc+VQ+AmvHwonnkFAR35uOVqtd1YAYJRj/rfuk7RawyxZCZNvjwqOpn9QZxhN/Y9887IakMmD28ae85e4/G5/oQ4KBXzw9S2Y0w9gFl97IkNbzZPGUHJ+Z1S+PUiLREBBKPbZImmq1C0n1f9hQ4o8ZTlwFOksObYVnBqluyeW+cwpYrlNhXkBIBFbcmM8+WeBO+OlQj2JGylZqv5MYSO9gfp15wCNYwZqd1ME2CkUcmK3HexWLsHuVqWCh1x4Sq69kayWKoXNNR4IQoJuNLgOWts7EWVMrFiC9fquYGEgG6brTQ9XkZFr3HyVb/tl6icQBttYAQ2/H0c1uIlEnMy/4NhdVpCIWTK114Jd+0a7IVV0YW8rpiwOO15sfpVNnM=\n"
    "backup-01.corp.internal ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCta/XGTBBToEMdG+1/bTTdaGmKj3iWNtSNeBkhU1AQyN+Gp49UCjsASb1HUj8AM78xTys18QxRupMDaSW5a/KtkZjnretOgiWCfkCRyk6+ExnlPnGpFdQ5GPiLkKwVmyPUdZeeViDZW+FEMqil13Pai5+AHMDBYDgjhPMWV5YAvUVrvHhdV6qtG8ydyMZz8sSMLH5YiawuEk0klmtXaiEh8q7XgOVtbvnTyU6nuzd3BD2NEizwC6SeGX9sQayrAVmAvLo/qNvgKV1S0AQS5MJt4jWB54KH+fpOhsTePSA3XlVZUZHTuKGvXsuqIHGo8Wl89ye60q134UjoseJKlqlOzwC0LgP8UZslyPkwloIJix7Xh/nkX2cUB+XnKgZSgA29CphP4vJQEfHG/UDlYbvzUEEjJzeShLCtQ+u+iDlVb+f6cd3BSrMOXA+J/gL17Mn6IkutlozuYn4PGCSEIn6CKXUNVxesOdCNgG/g4vrozCn72lEQqX9nG2JpTjETVqM=\n";
static const char admin_pgpass[] =
    "# hostname:port:database:username:password\n"
    "127.0.0.1:5432:prod_customers:postgres:Pr0dDB!2023\n"
    "10.0.4.30:5432:billing:billing_ro:B1ll1ngR0!2023\n";

/* /proc entries · same generic Linux as the other profiles. */
/* Synthetic kernel boot log served at /var/log/dmesg (+ dmesg reads it).  A real
 * prod host always has a boot log; its total absence is a sandbox tell.  QEMU/KVM
 * cloud host is plausible (most prod is virtualized) — coherent with the DMI strings
 * below + uname 6.6.30-0-lts + hostname prod-db-01. */
static const char canary_boot_dmesg[] =
    "[    0.000000] Linux version 6.6.30-0-lts (buildozer@build-3-20-x86_64) (gcc (Alpine 13.2.1_git20240309) 13.2.1, GNU ld (GNU Binutils) 2.42) #1-Alpine SMP PREEMPT_DYNAMIC 2024-05-22 14:03:00\n"
    "[    0.000000] Command line: BOOT_IMAGE=vmlinuz-lts root=/dev/vda1 ro modules=sd-mod,usb-storage,ext4 console=ttyS0 quiet\n"
    "[    0.000000] BIOS-provided physical RAM map:\n"
    "[    0.000000] DMI: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2 04/01/2014\n"
    "[    0.012000] Memory: 2017364K/2097152K available\n"
    "[    0.214000] smpboot: Allowing 2 CPUs, 0 hotplug CPUs\n"
    "[    0.530000] virtio_blk virtio2: [vda] 41943040 512-byte logical blocks (21.5 GB/20.0 GiB)\n"
    "[    0.612000]  vda: vda1\n"
    "[    0.740000] EXT4-fs (vda1): mounted filesystem with ordered data mode\n"
    "[    1.020000] virtio_net virtio1 eth0: renamed from eth0\n"
    "[    1.340000] IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready\n"
    "[    2.118000] EXT4-fs (vda1): re-mounted. Quota mode: none.\n";

/* truncated prod_customers dump · resolves the exfil trail the canary history
 * + crontab reference (pg_dump > /var/backups/prod_customers_*.sql.gz) so the
 * referenced backup actually exists for the attacker to find/exfil. */
static const unsigned char canary_pgdump_gz[] = {
      0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x75, 0xd4,
      0x3d, 0x6b, 0xc3, 0x30, 0x10, 0x80, 0xe1, 0x39, 0xfe, 0x15, 0x1a, 0x5b,
      0x88, 0x8d, 0xef, 0x4e, 0xfe, 0x22, 0x14, 0x0a, 0xfd, 0x98, 0x5a, 0x92,
      0x36, 0x5d, 0x0a, 0x85, 0xe2, 0xd8, 0x6a, 0x31, 0xc4, 0x76, 0xb0, 0xe5,
      0xd2, 0x9f, 0xdf, 0x48, 0x17, 0xe8, 0xa2, 0x9b, 0x34, 0xbc, 0x48, 0xc3,
      0xc3, 0x9d, 0xe2, 0x58, 0xed, 0xc6, 0xd9, 0x7e, 0x4f, 0x66, 0xff, 0xf2,
      0xa4, 0xda, 0xda, 0xd6, 0x87, 0x7a, 0x36, 0xaa, 0x5d, 0xfa, 0x53, 0x14,
      0xc7, 0xea, 0xfe, 0x7c, 0x9a, 0x56, 0x7d, 0x4d, 0x63, 0xff, 0x1f, 0x7f,
      0xcc, 0x34, 0x77, 0xe3, 0xa0, 0x20, 0x4b, 0x74, 0xb4, 0x7f, 0x78, 0x53,
      0xb3, 0xad, 0xad, 0xe9, 0xcd, 0x60, 0x3f, 0x6d, 0xd7, 0x9b, 0x71, 0xb1,
      0xea, 0x46, 0xa5, 0x9b, 0xe8, 0x6e, 0xbb, 0x7b, 0x57, 0xa7, 0xe5, 0x70,
      0xec, 0x9a, 0xa4, 0x6e, 0x9a, 0x71, 0x19, 0xec, 0xac, 0xae, 0xba, 0x76,
      0xad, 0x4c, 0x5f, 0x77, 0xc7, 0xb5, 0x6a, 0x26, 0x73, 0xbe, 0xd8, 0x5e,
      0xab, 0xc7, 0xd7, 0xed, 0xf3, 0xf9, 0x95, 0xb6, 0x1b, 0x36, 0x11, 0xac,
      0x96, 0xd9, 0x4c, 0x70, 0x5b, 0x37, 0xbd, 0x49, 0xcc, 0x6f, 0xdd, 0x9f,
      0x8e, 0x66, 0x85, 0x29, 0xea, 0x38, 0xc5, 0x18, 0xb2, 0x08, 0x7d, 0xc7,
      0x50, 0x27, 0xd7, 0xc9, 0x77, 0x0a, 0x75, 0xed, 0xba, 0xf6, 0x5d, 0x87,
      0x7a, 0xe6, 0x7a, 0xe6, 0x7b, 0x16, 0xea, 0xb9, 0xeb, 0xb9, 0xef, 0x79,
      0xa8, 0x17, 0xae, 0x17, 0xbe, 0x17, 0xa1, 0x5e, 0xba, 0x5e, 0xfa, 0x5e,
      0x86, 0x7a, 0xe5, 0x7a, 0xe5, 0x7b, 0x15, 0xea, 0xe0, 0x3a, 0xa4, 0x0c,
      0x94, 0x8a, 0x42, 0x70, 0x21, 0x04, 0xd1, 0x08, 0x18, 0x11, 0x50, 0x54,
      0x02, 0x66, 0x04, 0x12, 0x9d, 0x80, 0x21, 0x41, 0x8b, 0x52, 0xc0, 0x94,
      0x90, 0x89, 0x56, 0xc0, 0x98, 0x90, 0x8b, 0x5a, 0xc0, 0x9c, 0x50, 0x88,
      0x5e, 0xc0, 0xa0, 0x50, 0xca, 0x62, 0x4c, 0x0a, 0x95, 0x3c, 0x53, 0x6c,
      0x8a, 0xa9, 0x28, 0x86, 0x6c, 0x8a, 0x20, 0x8a, 0xe1, 0x65, 0x30, 0x51,
      0x14, 0x43, 0x36, 0x45, 0x12, 0xc5, 0x90, 0x4d, 0x51, 0x8b, 0x62, 0xc8,
      0xa6, 0x98, 0x89, 0x62, 0xc8, 0xa6, 0x98, 0x8b, 0x62, 0xc8, 0xa6, 0x58,
      0x88, 0x62, 0xc8, 0xa6, 0x58, 0xca, 0x62, 0x6c, 0x8a, 0x95, 0xbc, 0x87,
      0x6c, 0x4a, 0xa9, 0x28, 0x46, 0x6c, 0x4a, 0x20, 0x8a, 0x11, 0x9b, 0x12,
      0x8a, 0x62, 0x74, 0x59, 0x77, 0x12, 0xc5, 0x88, 0x4d, 0x49, 0x8b, 0x62,
      0xc4, 0xa6, 0x94, 0x89, 0x62, 0xc4, 0xa6, 0x94, 0x8b, 0x62, 0xc4, 0xa6,
      0x54, 0x88, 0x62, 0xc4, 0xa6, 0x54, 0xca, 0x62, 0x6c, 0x4a, 0x95, 0xfc,
      0x77, 0xb1, 0xa9, 0x4e, 0x45, 0xb1, 0x8f, 0x24, 0xfa, 0x03, 0x38, 0xa2,
      0x38, 0x51, 0xd3, 0x05, 0x00, 0x00
};

static const static_entry_t canary_entries[] = {
    ENTRY("/",                   "",                  LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc",                "",                  LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/proc",               "",                  LX_S_IFDIR | 0555, LX_DT_DIR),
    ENTRY("/proc/net",           "",                  LX_S_IFDIR | 0555, LX_DT_DIR),
    ENTRY("/bin",                "",                  LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/usr",                "",                  LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/usr/bin",            "",                  LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/sbin",               "",                  LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/lib",                "",                  LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/tmp",                "",                  LX_S_IFDIR | 01777, LX_DT_DIR),
    ENTRY("/home",               "",                  LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/home/admin",         "",                  LX_S_IFDIR | 0750, LX_DT_DIR),
    ENTRY("/home/admin/.ssh",    "",                  LX_S_IFDIR | 0700, LX_DT_DIR),
    /* per-user /home bait · the juicy recon payoff (synthetic honeytokens) */
    ENTRY("/home/admin/.ssh/id_rsa",      admin_ssh_id_rsa,     LX_S_IFREG | 0600, LX_DT_REG),
    ENTRY("/home/admin/.ssh/known_hosts", admin_ssh_known_hosts,LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/home/admin/.bash_history",    admin_bash_history,   LX_S_IFREG | 0600, LX_DT_REG),
    ENTRY("/home/admin/.pgpass",          admin_pgpass,         LX_S_IFREG | 0600, LX_DT_REG),
    ENTRY("/var",                "",                  LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/var/backups",        "",                  LX_S_IFDIR | 0750, LX_DT_DIR),
    ENTRY_BLOB("/var/backups/prod_customers.sql.gz",            canary_pgdump_gz, LX_S_IFREG | 0640, LX_DT_REG),
    ENTRY_BLOB("/var/backups/prod_customers_2024-05-28.sql.gz", canary_pgdump_gz, LX_S_IFREG | 0640, LX_DT_REG),
    ENTRY("/var/log",            "",                  LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/passwd",         canary_passwd,        LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/group",          canary_group,         LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/shadow",         canary_shadow,        LX_S_IFREG | 0640, LX_DT_REG),
    ENTRY("/etc/hostname",       canary_hostname,      LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/os-release",     canary_os_release,    LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/alpine-release", "3.20.10\n",       LX_S_IFREG | 0644, LX_DT_REG),  /* fidelity · Alpine fingerprint */
    ENTRY("/etc/resolv.conf",    canary_resolv_conf,   LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/shells",         canary_shells,        LX_S_IFREG | 0644, LX_DT_REG),
    /* PR 10 · shell-hook rc files · same canonical marker as alpine + ubuntu
     * so a Tier-2 promotion does not silently disable the hook evidence. */
    ENTRY("/root",               "",                  LX_S_IFDIR | 0700, LX_DT_DIR),
    ENTRY("/etc/bashrc",         etc_bashrc,          LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/root/.bashrc",       root_bashrc,         LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/root/.bash_history", canary_bash_history,  LX_S_IFREG | 0600, LX_DT_REG),
    ENTRY("/var/log/auth.log",   canary_authlog,       LX_S_IFREG | 0640, LX_DT_REG),
    ENTRY("/var/log/dmesg",      canary_boot_dmesg,    LX_S_IFREG | 0644, LX_DT_REG),
    /* /dev device nodes · a real host's /dev is full; an empty /dev (a file you can
     * open() but not stat) is an instant sandbox tell.  Char + block nodes, statable
     * with the right st_rdev (op_stat fills it via LX_MAKEDEV) + enumerable in `ls
     * /dev`.  (stdin/out/err are symlinks in real Linux — skipped until symlink
     * support; busybox opens them via the proc-fd fallback anyway.) */
    ENTRY("/dev",                "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/dev/null",           "",                   LX_S_IFCHR | 0666, LX_DT_CHR),
    ENTRY("/dev/zero",           "",                   LX_S_IFCHR | 0666, LX_DT_CHR),
    ENTRY("/dev/full",           "",                   LX_S_IFCHR | 0666, LX_DT_CHR),
    ENTRY("/dev/random",         "",                   LX_S_IFCHR | 0666, LX_DT_CHR),
    ENTRY("/dev/urandom",        "",                   LX_S_IFCHR | 0666, LX_DT_CHR),
    ENTRY("/dev/tty",            "",                   LX_S_IFCHR | 0666, LX_DT_CHR),
    ENTRY("/dev/console",        "",                   LX_S_IFCHR | 0600, LX_DT_CHR),
    ENTRY("/dev/ptmx",           "",                   LX_S_IFCHR | 0666, LX_DT_CHR),
    ENTRY("/dev/kmsg",           "",                   LX_S_IFCHR | 0644, LX_DT_CHR),
    ENTRY("/dev/vda",            "",                   LX_S_IFBLK | 0660, LX_DT_BLK),
    ENTRY("/dev/vda1",           "",                   LX_S_IFBLK | 0660, LX_DT_BLK),
    /* lateral-pivot bait · ssh/scp must EXIST so bash's PATH lookup finds them and
     * the execve intercept fires (the bash_history references `ssh deploy@10.0.4.12`
     * / `scp ... backup@10.0.4.30` · "command not found" would be a coherence tell).
     * Content is never loaded — the execve intercept catches the name pre-load. */
    ENTRY("/usr/bin/ssh",        bin_busybox_stub,     LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/scp",        bin_busybox_stub,     LX_S_IFREG | 0755, LX_DT_REG),
    /* persona DEPTH · sshd config, root crontab (both Alpine /etc/crontabs and the
     * busybox /var/spool path), the postgres data dir + periodic dirs referenced
     * by ps/history/crontab — so recon (`cat /etc/ssh/sshd_config`, `crontab -l`,
     * `ls /var/lib/postgresql/16/data`) sees a coherent prod-db-01 box. */
    ENTRY("/etc/ssh",            "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/ssh/sshd_config", canary_sshd_config,  LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/crontabs",       "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/crontabs/root",  canary_crontab,       LX_S_IFREG | 0600, LX_DT_REG),
    ENTRY("/etc/periodic",       "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/periodic/15min", "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/periodic/hourly","",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/periodic/daily", "",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/periodic/weekly","",                   LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/periodic/monthly","",                  LX_S_IFDIR | 0755, LX_DT_DIR),
    /* apk-local-install · apk DB + config skeleton (pristine, empty = "nothing
     * installed"). Dirs let apk resolve its paths; all `apk add` writes route to
     * the per-session sotfs upper (Phase 2) — these base files stay empty. */
    ENTRY("/etc/apk",                "",                       LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/apk/keys",           "",                       LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/etc/apk/repositories",   canary_apk_repositories,  LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/apk/world",          canary_apk_empty,         LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/etc/apk/arch",           "x86_64\n",               LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/lib/apk",                "",                       LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/lib/apk/db",             "",                       LX_S_IFDIR | 0755, LX_DT_DIR),
    ENTRY("/lib/apk/db/installed",   canary_apk_empty,         LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/lib/apk/db/scripts.tar", canary_apk_empty,         LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/lib/apk/db/triggers",    canary_apk_empty,         LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/lib/apk/db/lock",        canary_apk_empty,         LX_S_IFREG | 0644, LX_DT_REG),
    /* apk-local-install Task 6 · the local .apk (the attacker's install source) +
     * the Alpine signing key, in the PRISTINE base (read-only; the install lands in
     * the per-session upper).  --allow-untrusted skips the key; the opt-in verify
     * gate (Task 9) uses it.  Binary blobs use ENTRY_BLOB (explicit length) because
     * the .apk has embedded NULs that sizeof()-1 would truncate. */
    ENTRY_BLOB("/root/fixture.apk",
               apk_fixture,
               LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY_BLOB("/etc/apk/keys/alpine-3.20.rsa.pub",
               apk_key_alpine_3_20,
               LX_S_IFREG | 0644, LX_DT_REG),
    /* apk-fs Task 9 · the SAME key under the EXACT name apk looks up during real
     * signature verify (the fixture's `.SIGN.RSA.alpine-devel@...6165ee59.rsa.pub`
     * → /etc/apk/keys/<that name>).  `apk add` WITHOUT --allow-untrusted globs
     * /etc/apk/keys and verifies the RSA sig against this; the alpine-3.20.rsa.pub
     * alias above is the same bytes (the stable xxd symbol). */
    ENTRY_BLOB("/etc/apk/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub",
               apk_key_alpine_3_20,
               LX_S_IFREG | 0644, LX_DT_REG),
    ENTRY("/proc/version",       "Linux version 6.6.30-0-lts (buildozer@build-3-20-x86_64) (gcc (Alpine 13.2.1_git20240309) 13.2.1 20240309, GNU ld (GNU Binutils) 2.42) #1-Alpine SMP PREEMPT_DYNAMIC 2024-05-22 10:00:00\n", LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/proc/cpuinfo",       "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel Xeon Gold 6248\n\n", LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/proc/1/cmdline",     "/sbin/init",       LX_S_IFREG | 0444, LX_DT_REG),  /* fidelity · init cmdline */
    ENTRY("/proc/meminfo",       "MemTotal:       16777216 kB\nMemFree:        14680064 kB\n", LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/proc/mounts",        canary_proc_mounts,   LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/proc/loadavg",       canary_proc_loadavg,  LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/proc/uptime",        canary_proc_uptime,   LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/proc/net/tcp",       canary_proc_nettcp,   LX_S_IFREG | 0444, LX_DT_REG),
    /* /sys/kernel · coherent with uname + /etc/hostname (prod-db-01) · the
     * canary persona's sysfs identity (matches the Tier-2 uname nodename). */
    ENTRY("/sys",                "",                   LX_S_IFDIR | 0555, LX_DT_DIR),
    ENTRY("/sys/kernel",         "",                   LX_S_IFDIR | 0555, LX_DT_DIR),
    ENTRY("/sys/kernel/osrelease", "6.6.30-0-lts\n",   LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/sys/kernel/ostype",    "Linux\n",          LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/sys/kernel/hostname",  "prod-db-01\n",     LX_S_IFREG | 0444, LX_DT_REG),
    /* DMI · a real host exposes /sys/class/dmi/id/*; their absence is a sandbox
     * tell.  QEMU/KVM cloud-host strings (coherent with the dmesg DMI line above). */
    ENTRY("/sys/class",          "",                   LX_S_IFDIR | 0555, LX_DT_DIR),
    ENTRY("/sys/class/dmi",      "",                   LX_S_IFDIR | 0555, LX_DT_DIR),
    ENTRY("/sys/class/dmi/id",   "",                   LX_S_IFDIR | 0555, LX_DT_DIR),
    ENTRY("/sys/class/dmi/id/sys_vendor",    "QEMU\n",                                  LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/sys/class/dmi/id/product_name",  "Standard PC (Q35 + ICH9, 2009)\n",        LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/sys/class/dmi/id/board_vendor",  "QEMU\n",                                  LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/sys/class/dmi/id/board_name",    "Standard PC (Q35 + ICH9, 2009)\n",        LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/sys/class/dmi/id/bios_vendor",   "EFI Development Kit II / OVMF\n",          LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/sys/class/dmi/id/bios_version",  "edk2-stable202302-for-qemu\n",            LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/sys/class/dmi/id/chassis_vendor","QEMU\n",                                  LX_S_IFREG | 0444, LX_DT_REG),
    ENTRY("/sys/class/dmi/id/product_uuid",  "00000000-0000-0000-0000-000000000000\n",  LX_S_IFREG | 0400, LX_DT_REG),
    /* sotFS-ε: reads at Tier 2 unaffected · busybox applet stubs must be
     * present so that shell commands (cat, echo, sh) can be found.
     * Executable resolution routes to busybox-static.bin via execve.c.
     * Fidelity · the common recon set (id/uname/ps/...) so a bare applet name
     * resolves via PATH (busybox is multi-call → needs /bin/<applet>). */
    ENTRY("/bin/busybox",        bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/sh",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/ash",            bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/bash",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),  /* honey shell IS bash · which/ls find it */
    ENTRY("/bin/cat",            bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/echo",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/ls",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/grep",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/id",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    /* M2 · 'doom' launcher (Tier-2 canary shell uses THIS table) · busybox PATH-
     * finds it + execs it → LUCAS intercept (basename "doom") spawns the real Doom. */
    ENTRY("/bin/doom",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    /* DECEPTION · python launcher (LUCAS intercept → real CPython heavy box). */
    ENTRY("/usr/bin/python3",    bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/python3.12", bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/python",     bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/python3",        bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/python",         bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    /* pip · execve-intercepted (src/orch/execve.c): in a TRUSTED-egress shell it
     * runs real `python3 -m pip`; in the Tier-2 canary it emits a synthetic
     * install transcript (deception · no 'pip: not found' / no-egress tell).
     * The stub just makes PATH resolution succeed so the intercept fires. */
    ENTRY("/usr/bin/pip",        bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/pip3",       bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/pip",            bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/pip3",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/uname",          bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/whoami",         bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/hostname",       bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/w",              bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/env",            bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/date",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/head",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/tail",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/wc",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/find",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    /* fidelity · busybox applets a recon battery expects (uptime/readlink). */
    ENTRY("/bin/uptime",         bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/readlink",       bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/uptime",     bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/readlink",   bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    /* apk-local-install · canary /sbin/apk is now the REAL Alpine 3.20 apk.static
     * (binstore basename apk.static; resolve_path maps /sbin/apk → it via the
     * `apk`→`apk.static` alias). The stub just makes stat()/PATH-search succeed so
     * the execve intercept fires. */
    ENTRY("/sbin/apk",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/getconf",    bin_getconf_facade,  LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/crontab",    bin_crontab_facade,  LX_S_IFREG | 04755, LX_DT_REG),
    ENTRY("/bin/du",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/df",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/free",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/mount",          bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/ps",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/netstat",        bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/mkdir",          bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/touch",          bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/printf",         bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/test",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/true",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/false",          bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/sleep",          bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    /* Linux-ABI deception · the file-mutation + common util applets an attacker
     * expects to exist (chmod/ln/mv/rm/...).  Their busybox execs hit the Tier-1
     * syscall handlers (mkdir/rename/chmod/symlink/...) instead of "not found". */
    ENTRY("/bin/chmod",          bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/chown",          bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/chgrp",          bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/ln",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/mv",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/cp",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/rm",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/rmdir",          bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/stat",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/truncate",       bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/sed",            bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/awk",            bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/sort",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/cut",            bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/tr",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/xargs",          bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/which",          bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/kill",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/basename",       bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/dirname",        bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/vi",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/wget",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/nc",             bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    /* Tier-3 capture surface · the tools an intruder reaches for (kernel-module
     * load, chroot escape, capability set).  Their syscalls hit [abi-capture]. */
    ENTRY("/sbin/insmod",        bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/sbin/rmmod",         bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/sbin/modprobe",      bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/sbin/chroot",        bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/sbin/chroot",    bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/sbin/setcap",        bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/sbin/lsmod",         bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/busybox",    bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/cat",        bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/id",         bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/whoami",     bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/env",        bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    /* TUI editors (Task A6) · the REAL off-the-shelf Debian glibc-dynamic
     * less/nano/vim (NOT busybox applets).  This Tier-2 canary table is what the
     * SSH honey-shell uses, so the stubs MUST live here too (the Tier-0 alpine
     * table is a separate copy).  busybox `sh` PATH-search stat()s these (no
     * "not found"); execve-interception resolves the basename in the binstore +
     * loads the real editor, which DRAWS via ncurses/terminfo over the SSH pty.
     * (/bin/vi above stays busybox vi; vim is its own basename so they coexist.) */
    ENTRY("/usr/bin/less",       bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/nano",       bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/vim",        bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/curl",       bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/less",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/nano",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/vim",            bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    /* Install-arc P0.1 · the real Debian dpkg toolchain · Tier-2 canary table
     * (mirrors the editors above: stub stat() succeeds → execve resolves the
     * binstore basename → real dpkg/dpkg-deb/tar/xz/zstd via ld-linux). */
    ENTRY("/usr/bin/dpkg",       bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/dpkg-deb",   bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/dpkg-split", bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/tar",        bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/xz",         bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/gzip",       bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/usr/bin/zstd",       bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/tar",            bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
    ENTRY("/bin/gzip",           bin_busybox_stub,    LX_S_IFREG | 0755, LX_DT_REG),
};
#define CANARY_ENTRIES_COUNT (sizeof(canary_entries) / sizeof(canary_entries[0]))

/* =========================================================================
 * L5 profile selector · global · single-profile-at-a-time.
 * vfs_set_profile() is called by orch before sotbox_init so the VFS
 * reflects the correct identity from the very first syscall.
 * Limitation: all concurrent sotBoxes share the same profile.
 * Per-sotBox profiles would need the profile threaded through every
 * backend op (deferred to L5-T2+).
 * ========================================================================= */
/* lucas_profile_t is declared in <lucas/vfs.h> (already included above). */
static lucas_profile_t        g_profile       = LUCAS_PROFILE_ALPINE;
static int                    g_active_tier   = 0;
static const static_entry_t  *active_entries  = NULL;
static size_t                  active_count    = 0;

void vfs_set_profile(lucas_profile_t p) {
    g_profile = p;
    if (g_active_tier == 2) return;  /* canary overrides */
    if (p == LUCAS_PROFILE_DEBIAN) {
        active_entries = debian_entries;
        active_count   = DEBIAN_ENTRIES_COUNT;
        printf("[vfs] profile = UBUNTU\n");
    } else {
        active_entries = alpine_entries;
        active_count   = ALPINE_ENTRIES_COUNT;
        printf("[vfs] profile = ALPINE\n");
    }
}

/* L7: tier-aware content selection.  Tier 2 selects canary_entries regardless
 * of profile; other tiers fall back to profile selection. */
void vfs_set_tier(int tier) {
    g_active_tier = tier;
    if (tier == 2) {
        active_entries = canary_entries;
        active_count   = CANARY_ENTRIES_COUNT;
        printf("[vfs] TIER 2 · canary content active\n");
    } else {
        /* Fall back to profile selection. */
        vfs_set_profile(g_profile);
    }
}

/* Ensure the active table is initialised before any lookup. */
static void ensure_init(void) {
    if (active_entries == NULL) vfs_set_profile(LUCAS_PROFILE_ALPINE);
}

/* M3 · per-caller persona table resolution — the read-path seam.  A live SSH
 * session resolves its OWN static table from its per-session persona context
 * (profile + tier), so concurrent sessions can wear different personas instead
 * of sharing the global mask.  The operator (cow_session 0) and compat guests
 * with no ctx keep the global `active_entries`.  Behavior-preserving today: an
 * SSH session's ctx is {alpine, tier 2} → canary_entries, EXACTLY what the
 * global vfs_set_tier(2) flip selected — but now sourced per-caller, so a future
 * second persona coexists without a global flip. */
/* The persona → static-table mapping (profile + tier → table).  Tier-2 is the
 * canary surface regardless of profile; otherwise the profile picks the base. */
static const static_entry_t *persona_table(uint8_t profile, uint8_t tier,
                                           size_t *count_out) {
    /* The Ubuntu persona serves its OWN coherent surface (glibc · apt) regardless
     * of tier — the Alpine canary bait (prod-db-01) is a different story. */
    if (profile == LUCAS_PROFILE_DEBIAN) { *count_out = DEBIAN_ENTRIES_COUNT; return debian_entries; }
    if (tier == 2)                       { *count_out = CANARY_ENTRIES_COUNT; return canary_entries; }
    *count_out = ALPINE_ENTRIES_COUNT;    return alpine_entries;
}

static const static_entry_t *caller_entries(size_t *count_out) {
    ensure_init();
    lucas_state_t *c = lucas_get_current_caller();
    if (c && c->cow_session != 0) {
        lucas_persona_t pc;
        if (lucas_persona_session_get(c->cow_session, &pc))
            return persona_table(pc.profile, pc.tier, count_out);
    }
    *count_out = active_count;
    return active_entries;
}

/* M3 seam proof (boot self-test) · resolve the /etc/hostname a session's persona
 * context WOULD serve, BY its registered persona (not the thread-local caller),
 * via the SAME persona_table mapping the live read path uses.  Two sessions with
 * different ctx → different tables → different hostnames, proving the read path
 * is genuinely per-session (not the global flip).  Returns a static string. */
const char *lucas_static_persona_probe(uint32_t session) {
    lucas_persona_t pc;
    if (!lucas_persona_session_get(session, &pc)) return "(no-ctx)";
    size_t n;
    const static_entry_t *tbl = persona_table(pc.profile, pc.tier, &n);
    for (size_t i = 0; i < n; ++i)
        if (strcmp(tbl[i].path, "/etc/hostname") == 0) return tbl[i].content;
    return "(no-hostname)";
}

/* Open handle: pointer to the matched entry · cursor lives in fds[fd].cursor. */
typedef struct {
    const static_entry_t *entry;
    size_t                next_child_idx;  /* getdents iterator state */
    uint32_t              route_session;   /* apk-fs P2 · base-miss handle (0 = base) */
    char                  route_path[256];
} static_handle_t;

/* Bounded pool of open handles. */
#define LUCAS_STATIC_MAX_OPEN  16
static static_handle_t handle_pool[LUCAS_STATIC_MAX_OPEN];

/* busybox 1.36 applet INSTALL PATHS (Alpine 3.20 · busybox --list-full) ·
 * generated.  Fidelity: /bin/<x> stat succeeds iff that EXACT path is where
 * busybox installs the applet — so `ls` is /bin/ls (not /usr/sbin/ls), exactly
 * like Alpine, and unknown names still 404 → realistic "not found". */
static const char *const g_busybox_paths[] = {
"/bin/arch","/bin/ash","/bin/base64","/bin/bbconfig","/bin/cat","/bin/chattr",
"/bin/chgrp","/bin/chmod","/bin/chown","/bin/cp","/bin/date","/bin/dd",
"/bin/df","/bin/dmesg","/bin/dnsdomainname","/bin/dumpkmap","/bin/echo","/bin/egrep",
"/bin/false","/bin/fatattr","/bin/fdflush","/bin/fgrep","/bin/fsync","/bin/getopt",
"/bin/grep","/bin/gunzip","/bin/gzip","/bin/hostname","/bin/ionice","/bin/iostat",
"/bin/ipcalc","/bin/kbd_mode","/bin/kill","/bin/link","/bin/linux32","/bin/linux64",
"/bin/ln","/bin/login","/bin/ls","/bin/lsattr","/bin/lzop","/bin/makemime",
"/bin/mkdir","/bin/mknod","/bin/mktemp","/bin/more","/bin/mount","/bin/mountpoint",
"/bin/mpstat","/bin/mv","/bin/netstat","/bin/nice","/bin/pidof","/bin/ping",
"/bin/ping6","/bin/pipe_progress","/bin/printenv","/bin/ps","/bin/pwd","/bin/reformime",
"/bin/rev","/bin/rm","/bin/rmdir","/bin/run-parts","/bin/sed","/bin/setpriv",
"/bin/setserial","/bin/sh","/bin/sleep","/bin/stat","/bin/stty","/bin/su",
"/bin/sync","/bin/tar","/bin/touch","/bin/true","/bin/umount","/bin/uname",
"/bin/usleep","/bin/watch","/bin/zcat","/sbin/acpid","/sbin/adjtimex","/sbin/arp",
"/sbin/blkid","/sbin/blockdev","/sbin/depmod","/sbin/fbsplash","/sbin/fdisk","/sbin/findfs",
"/sbin/fsck","/sbin/fstrim","/sbin/getty","/sbin/halt","/sbin/hwclock","/sbin/ifconfig",
"/sbin/ifdown","/sbin/ifenslave","/sbin/ifup","/sbin/init","/sbin/inotifyd","/sbin/insmod",
"/sbin/ip","/sbin/ipaddr","/sbin/iplink","/sbin/ipneigh","/sbin/iproute","/sbin/iprule",
"/sbin/iptunnel","/sbin/klogd","/sbin/loadkmap","/sbin/logread","/sbin/losetup","/sbin/lsmod",
"/sbin/mdev","/sbin/mkdosfs","/sbin/mkfs.vfat","/sbin/mkswap","/sbin/modinfo","/sbin/modprobe",
"/sbin/nameif","/sbin/nologin","/sbin/pivot_root","/sbin/poweroff","/sbin/raidautorun","/sbin/reboot",
"/sbin/rmmod","/sbin/route","/sbin/setconsole","/sbin/slattach","/sbin/swapoff","/sbin/swapon",
"/sbin/switch_root","/sbin/sysctl","/sbin/syslogd","/sbin/tunctl","/sbin/udhcpc","/sbin/vconfig",
"/sbin/watchdog","/sbin/zcip","/usr/bin/[","/usr/bin/[[","/usr/bin/awk","/usr/bin/basename",
"/usr/bin/bc","/usr/bin/beep","/usr/bin/blkdiscard","/usr/bin/bunzip2","/usr/bin/bzcat","/usr/bin/bzip2",
"/usr/bin/cal","/usr/bin/chvt","/usr/bin/cksum","/usr/bin/clear","/usr/bin/cmp","/usr/bin/comm",
"/usr/bin/cpio","/usr/bin/crontab","/usr/bin/cryptpw","/usr/bin/cut","/usr/bin/dc","/usr/bin/deallocvt",
"/usr/bin/diff","/usr/bin/dirname","/usr/bin/dos2unix","/usr/bin/du","/usr/bin/eject","/usr/bin/env",
"/usr/bin/expand","/usr/bin/expr","/usr/bin/factor","/usr/bin/fallocate","/usr/bin/find","/usr/bin/flock",
"/usr/bin/fold","/usr/bin/free","/usr/bin/fuser","/usr/bin/groups","/usr/bin/hd","/usr/bin/head",
"/usr/bin/hexdump","/usr/bin/hostid","/usr/bin/id","/usr/bin/install","/usr/bin/ipcrm","/usr/bin/ipcs",
"/usr/bin/killall","/usr/bin/last","/usr/bin/less","/usr/bin/logger","/usr/bin/lsof","/usr/bin/lsusb",
"/usr/bin/lzcat","/usr/bin/lzma","/usr/bin/lzopcat","/usr/bin/md5sum","/usr/bin/mesg","/usr/bin/microcom",
"/usr/bin/mkfifo","/usr/bin/mkpasswd","/usr/bin/nc","/usr/bin/nl","/usr/bin/nmeter","/usr/bin/nohup",
"/usr/bin/nproc","/usr/bin/nsenter","/usr/bin/nslookup","/usr/bin/od","/usr/bin/openvt","/usr/bin/passwd",
"/usr/bin/paste","/usr/bin/pgrep","/usr/bin/pkill","/usr/bin/pmap","/usr/bin/printf","/usr/bin/pscan",
"/usr/bin/pstree","/usr/bin/pwdx","/usr/bin/readlink","/usr/bin/realpath","/usr/bin/renice","/usr/bin/reset",
"/usr/bin/resize","/usr/bin/seq","/usr/bin/setkeycodes","/usr/bin/setsid","/usr/bin/sha1sum","/usr/bin/sha256sum",
"/usr/bin/sha3sum","/usr/bin/sha512sum","/usr/bin/showkey","/usr/bin/shred","/usr/bin/shuf","/usr/bin/sort",
"/usr/bin/split","/usr/bin/strings","/usr/bin/sum","/usr/bin/tac","/usr/bin/tail","/usr/bin/tee",
"/usr/bin/test","/usr/bin/time","/usr/bin/timeout","/usr/bin/top","/usr/bin/tr","/usr/bin/traceroute",
"/usr/bin/traceroute6","/usr/bin/tree","/usr/bin/truncate","/usr/bin/tty","/usr/bin/ttysize","/usr/bin/udhcpc6",
"/usr/bin/unexpand","/usr/bin/uniq","/usr/bin/unix2dos","/usr/bin/unlink","/usr/bin/unlzma","/usr/bin/unlzop",
"/usr/bin/unshare","/usr/bin/unxz","/usr/bin/unzip","/usr/bin/uptime","/usr/bin/uudecode","/usr/bin/uuencode",
"/usr/bin/vi","/usr/bin/vlock","/usr/bin/volname","/usr/bin/wc","/usr/bin/wget","/usr/bin/which",
"/usr/bin/who","/usr/bin/whoami","/usr/bin/whois","/usr/bin/xargs","/usr/bin/xxd","/usr/bin/xzcat",
"/usr/bin/yes","/usr/sbin/addgroup","/usr/sbin/add-shell","/usr/sbin/adduser","/usr/sbin/arping","/usr/sbin/brctl",
"/usr/sbin/chpasswd","/usr/sbin/chroot","/usr/sbin/crond","/usr/sbin/delgroup","/usr/sbin/deluser","/usr/sbin/ether-wake",
"/usr/sbin/fbset","/usr/sbin/killall5","/usr/sbin/loadfont","/usr/sbin/nanddump","/usr/sbin/nandwrite","/usr/sbin/nbd-client",
"/usr/sbin/ntpd","/usr/sbin/partprobe","/usr/sbin/rdate","/usr/sbin/rdev","/usr/sbin/readahead","/usr/sbin/remove-shell",
"/usr/sbin/rfkill","/usr/sbin/sendmail","/usr/sbin/setfont","/usr/sbin/setlogcons",
};
static int is_busybox_path(const char *path){
    for (size_t i=0;i<sizeof(g_busybox_paths)/sizeof(g_busybox_paths[0]);++i)
        if (strcmp(g_busybox_paths[i], path)==0) return 1;
    return 0;
}

static static_entry_t g_bb_applet_entry = { 0, bin_busybox_stub, 0, 0100755u, 8 /*LX_DT_REG*/ };
static const static_entry_t *find_entry(const char *path) {
    size_t n;
    const static_entry_t *tbl = caller_entries(&n);
    for (size_t i = 0; i < n; ++i) {
        if (strcmp(tbl[i].path, path) == 0) return &tbl[i];
    }
    /* Fidelity fallback · /bin/<applet> (etc.) with no explicit ENTRY → resolve
     * it iff <applet> is a real busybox applet (so seq/expr/basename/... all
     * stat OK like Alpine; truly-unknown names still 404 → realistic "not found"). */
    if (is_busybox_path(path)) { g_bb_applet_entry.path = path; return &g_bb_applet_entry; }
    return NULL;
}

/* For directory iteration: enumerate entries whose path is "<dir>/X"
 * where X has no further '/'. */
static bool is_direct_child_of(const char *parent, const char *path) {
    size_t plen = strlen(parent);
    if (plen == 1 && parent[0] == '/') {
        if (path[0] != '/') return false;
        const char *rest = path + 1;
        return *rest != '\0' && strchr(rest, '/') == NULL;
    }
    if (strncmp(path, parent, plen) != 0) return false;
    if (path[plen] != '/') return false;
    const char *rest = path + plen + 1;
    return *rest != '\0' && strchr(rest, '/') == NULL;
}

static const char *basename_of(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static uint32_t tier2_route_session(void)
{
    lucas_state_t *caller = lucas_get_current_caller();
    /* apk-fs · gate on cow_session alone (NOT is_isolated && cow_session) to
     * match the sotfs op_open session gate (backends_sotfs.c:839 ·
     * `caller->cow_session != 0`).  A forked child of an SSH session inherits
     * cow_session at fork but is not yet flagged is_isolated until its first
     * Tier-2 promotion, so the old is_isolated guard routed its base-miss
     * creates inconsistently (sotfs upper would take them, static base would
     * drop them).  cow_session != 0 is set only on a real SSH session and is
     * reaped on disconnect, so this stays contained + operator-invisible. */
    if (caller && caller->cow_session != 0)
        return caller->cow_session;
    return 0;
}

static int op_open(void *backend, const char *path, int flags, uint32_t mode,
                    void **out_handle) {
    (void)backend;
    const static_entry_t *e = find_entry(path);
    if (!e) {
        /* apk-fs P2 · base-miss → route into the shared graph for Tier-2 sessions. */
        uint32_t sess = tier2_route_session();
        if (sess != 0) {
            int has = lucas_sotfs_route_has(sess, path);
            if (!has && (flags & 0x40 /* O_CREAT */)) {
                int crc = lucas_sotfs_route_create(sess, path, mode ? mode : 0644);
                if (crc != 0) return crc;
                has = 1;
            }
            if (has) {
                for (size_t i = 0; i < LUCAS_STATIC_MAX_OPEN; ++i) {
                    if (handle_pool[i].entry == NULL && handle_pool[i].route_session == 0) {
                        handle_pool[i].entry          = &g_bb_applet_entry; /* non-NULL sentinel */
                        handle_pool[i].next_child_idx = 0;
                        handle_pool[i].route_session  = sess;
                        strncpy(handle_pool[i].route_path, path,
                                sizeof(handle_pool[i].route_path) - 1);
                        handle_pool[i].route_path[sizeof(handle_pool[i].route_path) - 1] = '\0';
                        *out_handle = &handle_pool[i];
                        return 0;
                    }
                }
                /* Safe to retry after the caller frees an fd: lucas_sotfs_route_create is
                 * idempotent (no-op if the key already exists), so a re-open finds the
                 * node via route_has and skips the create. The node is reaped on
                 * disconnect regardless, so a create+EMFILE is not a leak. */
                return -24; /* -EMFILE */
            }
        }
        return -2;  /* -ENOENT */
    }
    for (size_t i = 0; i < LUCAS_STATIC_MAX_OPEN; ++i) {
        if (handle_pool[i].entry == NULL) {
            handle_pool[i].entry = e;
            handle_pool[i].next_child_idx = 0;
            handle_pool[i].route_session  = 0;
            handle_pool[i].route_path[0]  = '\0';
            *out_handle = &handle_pool[i];
            /* sottrace · P3 · FS_OPEN with the resolved path (the handle's). */
            {
                lucas_state_t *caller = lucas_get_current_caller();
                trace_emit_fs(caller ? caller->slot_index : -1,
                              caller ? (uint32_t)caller->synthetic_pid : 0u,
                              SG_EV_FS_OPEN, e->size, e->path);
            }
            return 0;
        }
    }
    return -24;  /* -EMFILE */
}

static int op_close(void *backend, void *handle) {
    (void)backend;
    static_handle_t *h = handle;
    if (!h) return -9;  /* -EBADF */
    h->entry = NULL;
    h->route_session = 0;
    h->route_path[0] = '\0';
    return 0;
}

/* ── op_dup_handle ────────────────────────────────────────────────────────
 * Allocate a fresh, independent pool slot mirroring `src` (same entry / route /
 * iterator).  Without this, fork's lucas_dup_vfs_handles SKIPPED static-backed
 * fds (the static ops had no dup_handle), so parent + child ALIASED one pooled
 * static_handle_t — the child's fd-table teardown op_close()d it (entry=NULL),
 * and the parent's next read saw `!h->entry` → -EBADF.  This is exactly the
 * dpkg-deb shared-handle bug (fork.c:403) but for the STATIC backend: apt-get
 * opens /etc/apt/sources.list (a static honey file), forks the
 * `dpkg --print-foreign-architectures` child, the child closes its inherited
 * sources.list fd → the parent's re-read failed "read (9: Bad file descriptor)"
 * → `apt-get update` aborted RC=100.  Mirror sotfs/op_dup_handle. */
static void *op_dup_handle(void *backend, void *src) {
    (void)backend;
    static_handle_t *s = src;
    if (!s) return NULL;
    for (size_t i = 0; i < LUCAS_STATIC_MAX_OPEN; ++i) {
        if (handle_pool[i].entry == NULL && handle_pool[i].route_session == 0) {
            handle_pool[i] = *s;   /* copy entry/next_child_idx/route_session/route_path */
            return &handle_pool[i];
        }
    }
    return NULL;  /* pool full · caller keeps the shared pointer (degraded) */
}

static int64_t op_read(void *backend, void *handle, void *buf,
                        size_t count, int64_t cursor) {
    (void)backend;
    static_handle_t *h = handle;
    /* apk-fs P2 · route handle: delegate entirely to the shared graph. */
    if (h && h->route_session != 0)
        return lucas_sotfs_route_read(h->route_session, h->route_path, buf, count, cursor);
    if (!h || !h->entry) return -9;
    const static_entry_t *e = h->entry;
    if ((e->mode & LX_S_IFMT) == LX_S_IFDIR) {
        return -21;  /* -EISDIR · client must use getdents */
    }

    /* Phase C · per-session COW-lite read-merge.  If this caller belongs to an
     * SSH session (cow_session != 0) and has previously `:w`-written this exact
     * path into its session overlay, serve the OVERLAY bytes instead of the
     * pristine base canary.  The base static table is NEVER mutated; Tier-0 and
     * any caller with cow_session==0 take the unchanged base path below.  Until
     * C3 (the write side) lands the overlay is always empty, so this is a
     * functional no-op that must not regress the base read. */
    {
        lucas_state_t *cow_caller = lucas_get_current_caller();
        if (cow_caller && cow_caller->cow_session != 0 &&
            lucas_cow_has(cow_caller->cow_session, e->path)) {
            static uint8_t cow_scratch[LUCAS_COW_MAX_BYTES];
            int total = lucas_cow_read(cow_caller->cow_session, e->path,
                                       cow_scratch, sizeof(cow_scratch));
            if (total < 0) total = 0;
            if (cursor >= (int64_t)total) return 0;
            size_t avail   = (size_t)total - (size_t)cursor;
            size_t to_copy = count < avail ? count : avail;
            memcpy(buf, cow_scratch + cursor, to_copy);
            return (int64_t)to_copy;
        }
    }

    if (cursor >= (int64_t)e->size) return 0;
    size_t avail = e->size - (size_t)cursor;
    size_t to_copy = count < avail ? count : avail;
    memcpy(buf, e->content + cursor, to_copy);

    /* sottrace · P3 · FS_READ once per open (cursor==0) for any static file. */
    if (cursor == 0) {
        lucas_state_t *rc_caller = lucas_get_current_caller();
        trace_emit_fs(rc_caller ? rc_caller->slot_index : -1,
                      rc_caller ? (uint32_t)rc_caller->synthetic_pid : 0u,
                      SG_EV_FS_READ, e->size, h->entry->path);
    }

    /* L8: canary access tracking.
     * When the active VFS is serving canary_entries (Tier 2) and a caller
     * state is registered, increment the per-sotBox canary_read_count and
     * emit a [canary] operator log.  Only log on the FIRST read chunk of
     * each file (cursor == 0) to avoid duplicate lines for large reads. */
    size_t ctbl_n;
    if (caller_entries(&ctbl_n) == canary_entries && cursor == 0) {
        lucas_state_t *caller = lucas_get_current_caller();
        if (caller != NULL) {
            caller->canary_read_count++;
            const char *fname = h->entry->path
                ? (strrchr(h->entry->path, '/') ? strrchr(h->entry->path, '/') + 1
                                                 : h->entry->path)
                : "?";
            printf("[canary] pid=%d read /etc/%s · count=%d\n",
                   caller->synthetic_pid, fname, caller->canary_read_count);
            /* sottrace · first-ever SG_EV_CANARY_READ producer */
            trace_emit_canary(caller->slot_index, (uint32_t)caller->synthetic_pid,
                             h->entry->path);
        }
    }

    return (int64_t)to_copy;
}

/* Credible binary sizes for the size-0 /bin·/usr/bin applet STUBS (content is the
 * shared empty sentinel; the real binary loads from the binstore at execve).  ls
 * -la / stat showing "0" on every /bin/* is a glaring tell — report a believable
 * busybox-applet size (and bash's own size for /bin/bash). */
static size_t facade_size(const static_entry_t *e) {
    if (e->size > 0 || e->content != bin_busybox_stub) return e->size;
    if (strcmp(e->path, "/bin/bash") == 0)      return 1265648;  /* GNU bash 5.2 */
    if (strcmp(e->path, "/usr/bin/curl") == 0)  return 256216;   /* curl 8.x */
    return 841392;                                          /* busybox 1.36 (Alpine) */
}

static int op_stat(void *backend, const char *path, struct lx_stat *out) {
    (void)backend;
    const static_entry_t *e = find_entry(path);
    if (!e) {
        /* apk-fs P2 · base-miss → check the shared graph for this session. */
        uint32_t sess = tier2_route_session();
        if (sess != 0 && lucas_sotfs_route_has(sess, path))
            return lucas_sotfs_route_stat(sess, path, out);
        return -2;  /* -ENOENT */
    }
    size_t sz = facade_size(e);
    memset(out, 0, sizeof(*out));
    out->st_mode    = e->mode;
    /* device nodes · synthesize st_rdev (major:minor) so `stat /dev/*` is coherent
     * (a node that opens but reports rdev 0 is a tell).  Legacy maj<<8|min encoding. */
    if ((e->mode & LX_S_IFMT) == LX_S_IFCHR || (e->mode & LX_S_IFMT) == LX_S_IFBLK) {
        const char *p = e->path; unsigned maj = 0, mn = 0;
        if      (!strcmp(p, "/dev/null"))    { maj = 1;   mn = 3;  }
        else if (!strcmp(p, "/dev/zero"))    { maj = 1;   mn = 5;  }
        else if (!strcmp(p, "/dev/full"))    { maj = 1;   mn = 7;  }
        else if (!strcmp(p, "/dev/random"))  { maj = 1;   mn = 8;  }
        else if (!strcmp(p, "/dev/urandom")) { maj = 1;   mn = 9;  }
        else if (!strcmp(p, "/dev/kmsg"))    { maj = 1;   mn = 11; }
        else if (!strcmp(p, "/dev/tty"))     { maj = 5;   mn = 0;  }
        else if (!strcmp(p, "/dev/console")) { maj = 5;   mn = 1;  }
        else if (!strcmp(p, "/dev/ptmx"))    { maj = 5;   mn = 2;  }
        else if (!strcmp(p, "/dev/vda"))     { maj = 254; mn = 0;  }
        else if (!strcmp(p, "/dev/vda1"))    { maj = 254; mn = 1;  }
        out->st_rdev = LX_MAKEDEV(maj, mn);
    }
    out->st_size    = (int64_t)sz;
    out->st_blksize = 4096;
    out->st_blocks  = ((int64_t)sz + 511) / 512;
    out->st_nlink   = 1;
    out->st_uid     = 0;
    out->st_gid     = 0;
    out->st_dev     = 1;
    /* M3 · inode = index within the CALLER's table (the same table find_entry
     * resolved `e` from), so it stays stable per-caller across stat calls. */
    { size_t sn; const static_entry_t *stbl = caller_entries(&sn);
      out->st_ino = (uint64_t)(e - stbl) + 1; }
    /* clock-fidelity · a real multi-year host has files of WIDELY varying ages;
     * a uniform mtime == boot wall-clock across the ENTIRE tree (`ls -la /etc`
     * showing every file at the same current minute) is a single fingerprint of a
     * freshly-synthesized FS — a whole-tree honeypot tell.  Spread each entry over
     * a plausible ~2-year install window, DETERMINISTICALLY by inode so it is
     * stable across repeated stats.  atime lands a little after mtime (read after
     * write); ctime == mtime. */
    { int64_t s, n; lucas_now_realtime(&s, &n); (void)n;
      uint64_t h = out->st_ino * 2654435761ull + 1013904223ull;   /* Knuth mult hash */
      uint64_t age = (30ull + (h % 700ull)) * 86400ull + (h % 86400ull); /* 30..730d */
      uint64_t mt = (s > (int64_t)age) ? (uint64_t)s - age : (uint64_t)s;
      out->st_mtime = mt;
      out->st_ctime = mt;
      out->st_atime = mt + ((h >> 11) % (3ull * 86400ull));        /* read 0..3d later */
    }
    return 0;
}

static int op_fstat(void *backend, void *handle, struct lx_stat *out) {
    (void)backend;
    static_handle_t *h = handle;
    /* apk-fs P2 · route handle: stat via the shared graph. */
    if (h && h->route_session != 0)
        return lucas_sotfs_route_stat(h->route_session, h->route_path, out);
    if (!h || !h->entry) return -9;
    return op_stat(backend, h->entry->path, out);
}

/* ── Operator-side merged-root accessors ──────────────────────────────────
 * Let the operator console (sotShell) list/read the synthetic top-level tree
 * (/, /etc, /bin, /proc/version…) it serves, so `ls /` / `cat /etc/passwd`
 * reflect the SAME deception surface a guest sees.  Emit the compact operator
 * dirent (name/size/kind) the ORCH_OP_SOTFS_LS reply uses. */
typedef struct { char name[32]; uint32_t size; uint8_t kind; uint8_t pad[3]; } op_dirent_t;

int lucas_static_list_dir(const char *path, void *out_v, int max) {
    op_dirent_t *out = (op_dirent_t *)out_v;
    if (!path || !out || max <= 0) return -22;
    ensure_init();
    int count = 0;
    for (size_t i = 0; i < active_count && count < max; ++i) {
        if (!is_direct_child_of(path, active_entries[i].path)) continue;
        const char *nm = basename_of(active_entries[i].path);
        strncpy(out[count].name, nm, 31);
        out[count].name[31] = '\0';
        out[count].size = (uint32_t)facade_size(&active_entries[i]);
        out[count].kind = ((active_entries[i].mode & LX_S_IFMT) == LX_S_IFDIR) ? 2 : 1;
        out[count].pad[0] = out[count].pad[1] = out[count].pad[2] = 0;
        count++;
    }
    return count;
}

int lucas_static_read_file(const char *path, void *buf, size_t max) {
    if (!path || !buf || max == 0) return -22;
    const static_entry_t *e = find_entry(path);
    if (!e) return -2;                               /* -ENOENT */
    if ((e->mode & LX_S_IFMT) == LX_S_IFDIR) return -21; /* -EISDIR */
    size_t n = e->size < max ? e->size : max;
    memcpy(buf, e->content, n);
    return (int)n;
}

static int64_t op_getdents(void *backend, void *handle, void *dirp,
                            size_t count, int64_t *cursor) {
    (void)backend; (void)cursor;
    static_handle_t *h = handle;
    if (!h || !h->entry) return -9;

    uint8_t *out = dirp;
    size_t written = 0;

    /* apk-fs P2 · route-dir handle: the base has no matching entry (sentinel
     * entry is a regular-file stub).  Skip the static-children loop; serve only
     * the shared-graph children. */
    if (h->route_session != 0) {
        char    names[96][32];
        uint8_t types[96];
        int total = lucas_sotfs_route_list_children(h->route_session, h->route_path,
                                                    names, types, 0, 96);
        for (int i = 0; i < total; i++) {
            size_t name_len = strlen(names[i]) + 1;
            size_t reclen = (offsetof(struct lx_dirent64, d_name) + name_len + 7) & ~7UL;
            if (written + reclen > count) break;
            struct lx_dirent64 *de = (struct lx_dirent64 *)(out + written);
            de->d_ino    = (uint64_t)(300000 + i);
            /* d_off here is a byte offset into the output buffer; the static loop
             * above uses an entry-table index instead.  The two schemes coexist in
             * one buffer because getdents returns everything in a single call here
             * (cursor is ignored) — DO NOT add incremental/resumable getdents without
             * unifying d_off across both branches first. */
            de->d_off    = (int64_t)(written + reclen);
            de->d_reclen = (uint16_t)reclen;
            de->d_type   = types[i];
            memcpy(de->d_name, names[i], name_len);
            written += reclen;
        }
        return (int64_t)written;
    }

    if ((h->entry->mode & LX_S_IFMT) != LX_S_IFDIR) return -20;  /* -ENOTDIR */

    size_t gd_n;
    const static_entry_t *gd_tbl = caller_entries(&gd_n);
    while (h->next_child_idx < gd_n) {
        const static_entry_t *child = &gd_tbl[h->next_child_idx];
        if (!is_direct_child_of(h->entry->path, child->path)) {
            ++h->next_child_idx;
            continue;
        }
        const char *name = basename_of(child->path);
        size_t name_len = strlen(name) + 1;
        size_t reclen = (offsetof(struct lx_dirent64, d_name) + name_len + 7) & ~7UL;
        if (written + reclen > count) break;
        struct lx_dirent64 *de = (struct lx_dirent64 *)(out + written);
        de->d_ino    = (uint64_t)(child - gd_tbl) + 1;
        de->d_off    = (int64_t)(h->next_child_idx + 1);
        de->d_reclen = (uint16_t)reclen;
        de->d_type   = child->dirent_type;
        memcpy(de->d_name, name, name_len);
        written += reclen;
        ++h->next_child_idx;
    }

    /* apk-fs P2 · merge this Tier-2 session's route children of the static dir. */
    /* apk-fs P2 · merge this Tier-2 session's route children into a static-base
     * dir listing.  BOUND: the dedup set caps at 96 entries / 31-char names; a
     * base dir with >=96 children would suppress route children here.  No canary
     * base dir approaches that today (largest is well under 96).  Revisit if a
     * base dir grows, or if route filenames exceed 31 chars (names[][32]). */
    uint32_t sess = tier2_route_session();
    if (sess != 0 && h->entry && h->entry->path) {
        char    names[96][32];
        uint8_t types[96];
        int have = 0; size_t scan = 0;
        while (scan < written && have < 96) {
            struct lx_dirent64 *de = (struct lx_dirent64 *)(out + scan);
            if (de->d_reclen == 0) break;
            strncpy(names[have], de->d_name, 31); names[have][31] = '\0';
            types[have] = de->d_type; have++;
            scan += de->d_reclen;
        }
        int total = lucas_sotfs_route_list_children(sess, h->entry->path,
                                                    names, types, have, 96);
        for (int i = have; i < total; i++) {
            size_t name_len = strlen(names[i]) + 1;
            size_t reclen = (offsetof(struct lx_dirent64, d_name) + name_len + 7) & ~7UL;
            if (written + reclen > count) break;
            struct lx_dirent64 *de = (struct lx_dirent64 *)(out + written);
            de->d_ino    = (uint64_t)(300000 + i);
            de->d_off    = (int64_t)(written + reclen);
            de->d_reclen = (uint16_t)reclen;
            de->d_type   = types[i];
            memcpy(de->d_name, names[i], name_len);
            written += reclen;
        }
    }
    return (int64_t)written;
}

static int op_readlink(void *backend, const char *path, char *buf, size_t size) {
    (void)backend; (void)path; (void)buf; (void)size;
    return -22;  /* -EINVAL · no symlinks in static_vfs L2 */
}

static int64_t op_write_stub(void *backend, void *handle, const void *buf,
                              size_t count, int64_t cursor) {
    (void)backend;
    static_handle_t *h = handle;
    /* apk-fs P2 · route handle: delegate to the shared graph. */
    if (h && h->route_session != 0)
        return lucas_sotfs_route_write(h->route_session, h->route_path, buf, count, cursor);
    if (!h || !h->entry) return -9;  /* -EBADF */
    /* Phase C / F2 · a Tier-2 (isolated) SSH session writing a canary file: land
     * the bytes in the per-session COW overlay (keyed by the full path
     * h->entry->path — the same key C2's read-merge uses) so vim's `:w` reads back
     * coherently while the base static table is NEVER mutated.  Non-isolated /
     * no-session callers keep the read-only -1 (the static surface is immutable). */
    lucas_state_t *caller = lucas_get_current_caller();
    if (caller && caller->functor && caller->functor->is_isolated &&
        caller->cow_session != 0) {
        printf("[isolated] pid=%d tier=2 · static write %s len=%zu → session overlay (base intact)\n",
               caller->synthetic_pid, h->entry->path, count);
        trace_emit_isolated_write_drop(caller->slot_index,
                                       (uint32_t)caller->synthetic_pid, h->entry->path);
        static uint8_t cow_merge[LUCAS_COW_MAX_BYTES];
        uint32_t cur_len = 0;
        if (lucas_cow_has(caller->cow_session, h->entry->path)) {
            int got = lucas_cow_read(caller->cow_session, h->entry->path,
                                     cow_merge, sizeof(cow_merge));
            if (got > 0) cur_len = (uint32_t)got;
        }
        uint64_t off = (cursor > 0) ? (uint64_t)cursor : 0;
        uint64_t end = off + (uint64_t)count;
        if (end > (uint64_t)LUCAS_COW_MAX_BYTES) return -28; /* -ENOSPC */
        if (off > cur_len) memset(cow_merge + cur_len, 0, (size_t)(off - cur_len));
        memcpy(cow_merge + off, buf, count);
        uint32_t new_len = (uint32_t)end;
        if (new_len < cur_len) new_len = cur_len;  /* partial overwrite keeps tail (F3 fixes shrink) */
        int wrc = lucas_cow_write(caller->cow_session, h->entry->path,
                                  cow_merge, new_len);
        if (wrc != 0) return (int64_t)wrc;
        return (int64_t)count;
    }
    return -1;  /* read-only · the static surface is immutable for non-session callers */
}

static int op_truncate(void *backend, void *handle, int64_t newlen) {
    (void)backend;
    static_handle_t *h = handle;
    /* apk-fs P2 · route handle truncation not yet needed (route files are small);
     * treat as success to avoid breaking the ftruncate contract. */
    if (h && h->route_session != 0) return 0;
    if (!h || !h->entry) return -9;  /* -EBADF */
    /* F3 · COW shrink-on-resave · a Tier-2 session caller truncates its per-session
     * overlay entry (keyed by the full path h->entry->path — the SAME key op_read's
     * read-merge and op_write_stub use).  The base static table is NEVER mutated. */
    lucas_state_t *caller = lucas_get_current_caller();
    if (caller && caller->cow_session != 0)
        return lucas_cow_truncate(caller->cow_session, h->entry->path,
                                  newlen > 0 ? (uint32_t)newlen : 0);
    return 0;  /* no session overlay → success-silently (matches ftruncate contract) */
}

/* apk-fs P2 · mkdir / unlink via the shared-graph route for Tier-2 sessions. */
static int op_mkdir(void *backend, const char *path, uint32_t mode)
{
    (void)backend;
    uint32_t sess = tier2_route_session();
    if (sess == 0) return -30;   /* -EROFS · base immutable */
    return lucas_sotfs_route_mkdir(sess, path, mode ? mode : 0755);
}

static int op_unlink(void *backend, const char *path)
{
    (void)backend;
    uint32_t sess = tier2_route_session();
    if (sess == 0) return -30;   /* -EROFS */
    if (!lucas_sotfs_route_has(sess, path)) return -2; /* base never removed */
    return lucas_sotfs_route_unlink(sess, path);
}

const vfs_ops_t vfs_static_ops = {
    .open     = op_open,
    .close    = op_close,
    .read     = op_read,
    .write    = op_write_stub,
    .stat     = op_stat,
    .fstat    = op_fstat,
    .getdents = op_getdents,
    .readlink = op_readlink,
    .truncate = op_truncate,
    .mkdir    = op_mkdir,
    .unlink   = op_unlink,
    .dup_handle = op_dup_handle,
};

void *vfs_static_state(void) {
    /* Backend state is file-scope global (handle_pool, entries).
     * Return non-NULL so 'absent backend' checks don't fire. */
    return (void *)1;
}
