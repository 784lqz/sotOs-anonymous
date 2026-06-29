/* Host unit test for the sysroot LNK runtime (backends_sysroot.c).
 *   cc -I include src/test/sysroot_lnk_unit/sysroot_lnk_unit.c \
 *      src/lucas/backends_sysroot.c -o /tmp/srlnk && /tmp/srlnk
 * Compiles the REAL backend against a synthetic in-memory sysroot region
 * (virtio_blk_read_sector stubbed below) and drives it through the public
 * vfs_ops surface (lucas_sysroot_mount).  Covers: bounded symlink follow
 * (chain of 7 resolves, 8 → -ELOOP, a↔b loop → -ELOOP), relative targets
 * (same dir + subdir parent join), absolute /usr/... + /lib/... alias
 * targets, "." / ".." normalization, link-to-DIR (stat + getdents through
 * it), dangling links (stat ENOENT but readlink verbatim), readlink
 * semantics (exact bytes, silent truncate, EINVAL on non-link, ENOENT),
 * open+read through a link (content + EOF clamp), open(O_NOFOLLOW) handle
 * to the link itself (fstat → IFLNK · the fill_stat LNK branch), and
 * getdents d_type REG/DIR/LNK. */
#include <lucas/backends_sysroot.h>
#include <lucas/vfs.h>
#include <sotfs/layout.h>
#include <sotfs/sysroot.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

static int fails = 0;
#define CHECK(c) do{ if(!(c)){printf("FAIL: %s (line %d)\n",#c,__LINE__);fails++;} }while(0)

#define LX_ENOENT  (-2)
#define LX_ENOTDIR (-20)
#define LX_EINVAL  (-22)
#define LX_ELOOP   (-40)

/* ── synthetic in-memory sysroot region ─────────────────────────────────────
 * Models sotfs.img bytes [SYSROOT_OFFSET, SYSROOT_OFFSET + 512K table area
 * + 128K data ⇒ 32 4-KiB blob slots).  The blk stub serves zeroes outside it
 * (never fails), so the backend's sector math is exercised for real,
 * absolute offsets included. */
static uint8_t g_region[(512u + 128u) * 1024u];
#define REGION_BASE ((uint64_t)SOTFS_SYSROOT_OFFSET)

int virtio_blk_read_sector(uint64_t sector, void *out)
{
    uint64_t off = sector * 512u;
    memset(out, 0, 512);
    if (off >= REGION_BASE && off + 512u <= REGION_BASE + sizeof(g_region))
        memcpy(out, g_region + (off - REGION_BASE), 512);
    return 0;
}

void lucas_doom_probe(const char *tag) { (void)tag; }   /* op_read probe stub */

/* ── fixture builder · same wire shape as scripts/build-sysroot.sh ────────── */
static uint32_t g_count;
static uint64_t g_next_blob = (uint64_t)SOTFS_SYSROOT_DATA_OFFSET;

static void die(const char *msg)
{ printf("FATAL fixture overflow: %s\n", msg); __builtin_trap(); }

static void add_entry(const char *path, uint32_t type, uint64_t off, uint64_t size)
{
    size_t end = sizeof(sotfs_sysroot_header_t)
               + ((size_t)g_count + 1) * sizeof(sotfs_sysroot_entry_t);
    if (end > 512u * 1024u) die("entry table past the 512K header area");
    sotfs_sysroot_entry_t *e = (sotfs_sysroot_entry_t *)
        (g_region + sizeof(sotfs_sysroot_header_t)) + g_count++;
    memset(e, 0, sizeof(*e));
    snprintf(e->path, sizeof(e->path), "%s", path);
    e->type = type; e->offset = off; e->size = size;
}

static void add_dir(const char *path) { add_entry(path, SOTFS_SYSROOT_TYPE_DIR, 0, 0); }

static void add_blob(const char *path, uint32_t type, const void *data, size_t n)
{
    if (g_next_blob - REGION_BASE + n > sizeof(g_region))
        die("blob data past the synthetic region");
    memcpy(g_region + (g_next_blob - REGION_BASE), data, n);
    add_entry(path, type, g_next_blob, n);
    g_next_blob = (g_next_blob + n + 4095u) & ~4095ull;   /* 4 KiB-align next */
}

static void add_file(const char *path, const void *data, size_t n)
{ add_blob(path, SOTFS_SYSROOT_TYPE_FILE, data, n); }

static void add_link(const char *path, const char *target)
{ add_blob(path, SOTFS_SYSROOT_TYPE_LNK, target, strlen(target)); }

static void fixture_finalize(void)
{
    sotfs_sysroot_header_t *h = (sotfs_sysroot_header_t *)g_region;
    h->magic = SOTFS_SYSROOT_MAGIC; h->version = SOTFS_SYSROOT_VERSION;
    h->count = g_count;
}

/* ── getdents harness ───────────────────────────────────────────────────────
 * Open `path` with `flags`, drain it via repeated getdents calls of `bufsz`
 * bytes (exercising cursor resumption when bufsz is small), close.  Returns
 * the entry count, or the negative errno of the first failing call.
 * Callers must size `max` >= the expected count: entries past `max` are
 * counted but not stored (the n==K count asserts flip first regardless). */
struct dent { char name[64]; uint8_t type; };

static int64_t list_dir(const vfs_ops_t *ops, void *b, const char *path,
                        int flags, size_t bufsz, struct dent *out, int max)
{
    void *h = NULL;
    int rc = ops->open(b, path, flags, 0, &h);
    if (rc != 0) return rc;
    uint8_t buf[4096];
    if (bufsz > sizeof(buf)) bufsz = sizeof(buf);
    int64_t cur = 0; int n = 0;
    for (;;) {
        int64_t got = ops->getdents(b, h, buf, bufsz, &cur);
        if (got < 0) { ops->close(b, h); return got; }
        if (got == 0) break;
        for (int64_t off = 0; off < got;) {
            struct lx_dirent64 *de = (struct lx_dirent64 *)(buf + off);
            if (n < max) {
                snprintf(out[n].name, sizeof(out[n].name), "%s", de->d_name);
                out[n].type = de->d_type;
            }
            n++;
            off += de->d_reclen;
        }
    }
    ops->close(b, h);
    return n;
}

static int find_dent(const struct dent *d, int64_t n, const char *name)
{
    for (int64_t i = 0; i < n; i++)
        if (strcmp(d[i].name, name) == 0) return (int)i;
    return -1;
}

static int count_dent(const struct dent *d, int64_t n, const char *name)
{
    int c = 0;
    for (int64_t i = 0; i < n; i++)
        if (strcmp(d[i].name, name) == 0) c++;
    return c;
}

int main(void)
{
    /* 700-byte payload mirrors the packer round-trip fixture */
    static uint8_t payload[700];
    for (int i = 0; i < 700; i++) payload[i] = "ELFDATA"[i % 7];

    add_dir("include");
    add_dir("lib");
    add_dir("lib/sub");
    add_file("lib/libvfsprobe.so.1", payload, sizeof(payload));
    add_link("lib/libvfsprobe.so", "libvfsprobe.so.1");        /* relative, same dir */
    add_file("lib/sub/nested.so", "NESTED", 6);
    add_link("lib/sub/nested-link.so", "nested.so");           /* relative, subdir */
    add_link("lib/sublink", "sub");                            /* link to a DIR */
    add_link("lib/abs", "/usr/lib/libvfsprobe.so.1");          /* absolute /usr */
    add_link("lib/alias", "/lib/libvfsprobe.so.1");            /* /lib alias */
    add_link("lib/updown", "sub/../libvfsprobe.so.1");         /* ".." collapse */
    add_link("lib/dotty", "./libvfsprobe.so.1");               /* "." drop */
    add_link("lib/dangling", "missing.so");                    /* dangling */
    add_link("lib/empty", "");                                 /* empty target */
    add_link("lib/h1", "libvfsprobe.so.1");                    /* chain h8→…→h1→file */
    add_link("lib/h2", "h1");
    add_link("lib/h3", "h2");
    add_link("lib/h4", "h3");
    add_link("lib/h5", "h4");
    add_link("lib/h6", "h5");
    add_link("lib/h7", "h6");                                  /* 7 hops · resolves */
    add_link("lib/h8", "h7");                                  /* 8 hops · ELOOP */
    add_link("lib/loop-a", "loop-b");                          /* a↔b loop */
    add_link("lib/loop-b", "loop-a");
    fixture_finalize();

    vfs_mount_t m = lucas_sysroot_mount();
    const vfs_ops_t *ops = m.ops;
    void *b = m.backend_state;
    struct lx_stat st;

    /* ── stat follows links (relative, subdir, absolute, normalized) ─────── */
    CHECK(ops->stat(b, "/lib/libvfsprobe.so", &st) == 0);
    CHECK((st.st_mode & LX_S_IFMT) == LX_S_IFREG && st.st_size == 700);
    CHECK(ops->stat(b, "/lib/sub/nested-link.so", &st) == 0);
    CHECK((st.st_mode & LX_S_IFMT) == LX_S_IFREG && st.st_size == 6);
    CHECK(ops->stat(b, "/lib/abs", &st) == 0 && st.st_size == 700);
    CHECK(ops->stat(b, "/lib/alias", &st) == 0 && st.st_size == 700);
    CHECK(ops->stat(b, "/lib/updown", &st) == 0 && st.st_size == 700);
    CHECK(ops->stat(b, "/lib/dotty", &st) == 0 && st.st_size == 700);

    /* link to a DIR · stat reports the directory */
    CHECK(ops->stat(b, "/lib/sublink", &st) == 0);
    CHECK((st.st_mode & LX_S_IFMT) == LX_S_IFDIR);

    /* mount root + plain dir + ENOENT */
    CHECK(ops->stat(b, "/", &st) == 0 && (st.st_mode & LX_S_IFMT) == LX_S_IFDIR);
    CHECK(ops->stat(b, "/lib/sub", &st) == 0 && (st.st_mode & LX_S_IFMT) == LX_S_IFDIR);
    CHECK(ops->stat(b, "/lib/missing", &st) == LX_ENOENT);

    /* ── bounded follow · exact boundary + loops + dangling ──────────────── */
    CHECK(ops->stat(b, "/lib/h7", &st) == 0 && st.st_size == 700);  /* 7 hops OK */
    CHECK(ops->stat(b, "/lib/h8", &st) == LX_ELOOP);                /* 8 hops → ELOOP */
    CHECK(ops->stat(b, "/lib/loop-a", &st) == LX_ELOOP);
    CHECK(ops->stat(b, "/lib/dangling", &st) == LX_ENOENT);         /* dangling ≠ ELOOP */
    CHECK(ops->stat(b, "/lib/empty", &st) == LX_ENOENT);            /* empty target ≠ parent dir */

    /* ── readlink · NO follow · verbatim target bytes ─────────────────────── */
    char buf[64];
    memset(buf, 0xAA, sizeof(buf));
    CHECK(ops->readlink(b, "/lib/libvfsprobe.so", buf, sizeof(buf)) == 16);
    CHECK(memcmp(buf, "libvfsprobe.so.1", 16) == 0);
    memset(buf, 0xAA, sizeof(buf));
    CHECK(ops->readlink(b, "/lib/libvfsprobe.so", buf, 4) == 4);    /* silent truncate */
    CHECK(memcmp(buf, "libv", 4) == 0 && (uint8_t)buf[4] == 0xAA);  /* no overwrite past size */
    CHECK(ops->readlink(b, "/lib/dangling", buf, sizeof(buf)) == 10);
    CHECK(memcmp(buf, "missing.so", 10) == 0);                      /* dangling still readable */
    CHECK(ops->readlink(b, "/lib/h8", buf, sizeof(buf)) == 2);      /* the link itself, no follow */
    CHECK(memcmp(buf, "h7", 2) == 0);
    CHECK(ops->readlink(b, "/lib/libvfsprobe.so.1", buf, sizeof(buf)) == LX_EINVAL);
    CHECK(ops->readlink(b, "/lib", buf, sizeof(buf)) == LX_EINVAL);
    CHECK(ops->readlink(b, "/lib/missing", buf, sizeof(buf)) == LX_ENOENT);
    memset(buf, 0xAA, sizeof(buf));
    CHECK(ops->readlink(b, "/lib/libvfsprobe.so", buf, 0) == 0);    /* size=0 · no write */
    CHECK((uint8_t)buf[0] == 0xAA);
    CHECK(ops->readlink(b, "/lib/empty", buf, sizeof(buf)) == 0);   /* empty target readable */

    /* ── open + read through a link · content + EOF clamp ─────────────────── */
    void *h = NULL;
    CHECK(ops->open(b, "/lib/dangling", 0, 0, &h) == LX_ENOENT);    /* dangling open */
    CHECK(ops->open(b, "/lib/libvfsprobe.so", 0, 0, &h) == 0 && h);
    CHECK(ops->fstat(b, h, &st) == 0);
    CHECK((st.st_mode & LX_S_IFMT) == LX_S_IFREG && st.st_size == 700);
    static uint8_t rd[700];
    CHECK(ops->read(b, h, rd, sizeof(rd), 0) == 700);
    CHECK(memcmp(rd, payload, 700) == 0);
    CHECK(ops->read(b, h, rd, 16, 696) == 4);                       /* EOF clamp */
    CHECK(ops->read(b, h, rd, 16, 700) == 0);                       /* at EOF */
    CHECK(ops->close(b, h) == 0);

    /* ── O_NOFOLLOW · handle to the link itself (fill_stat LNK branch) ───── */
    CHECK(ops->open(b, "/lib/libvfsprobe.so", LX_O_NOFOLLOW, 0, &h) == 0);
    CHECK(ops->fstat(b, h, &st) == 0);
    CHECK((st.st_mode & LX_S_IFMT) == LX_S_IFLNK && st.st_size == 16);
    CHECK(ops->close(b, h) == 0);
    /* O_NOFOLLOW on a non-link is unaffected (Linux semantics) */
    CHECK(ops->open(b, "/lib/libvfsprobe.so.1", LX_O_NOFOLLOW, 0, &h) == 0);
    CHECK(ops->fstat(b, h, &st) == 0 && (st.st_mode & LX_S_IFMT) == LX_S_IFREG);
    CHECK(ops->close(b, h) == 0);
    /* loops: plain open → ELOOP; O_NOFOLLOW open of the link succeeds */
    CHECK(ops->open(b, "/lib/h8", 0, 0, &h) == LX_ELOOP);
    CHECK(ops->open(b, "/lib/h8", LX_O_NOFOLLOW, 0, &h) == 0);
    CHECK(ops->fstat(b, h, &st) == 0 && (st.st_mode & LX_S_IFMT) == LX_S_IFLNK);
    CHECK(ops->close(b, h) == 0);

    /* ── getdents64 hierarchy · exact child sets + d_type ─────────────────── */
    struct dent d[32], d2[32], s[8], r[8];
    /* root: exactly {include DIR, lib DIR} · nothing deeper */
    int64_t n = list_dir(ops, b, "/", 0, 4096, r, 8);
    CHECK(n == 2);
    CHECK(find_dent(r, n, "include") >= 0 && r[find_dent(r, n, "include")].type == LX_DT_DIR);
    CHECK(find_dent(r, n, "lib") >= 0 && r[find_dent(r, n, "lib")].type == LX_DT_DIR);

    /* lib: exactly its 20 immediate children · grandchildren excluded ·
     * no self entry · every name exactly once (no duplicates) */
    n = list_dir(ops, b, "/lib", 0, 4096, d, 32);
    CHECK(n == 20);
    CHECK(find_dent(d, n, "nested.so") < 0);          /* grandchild NOT listed */
    CHECK(find_dent(d, n, "nested-link.so") < 0);
    CHECK(find_dent(d, n, "lib") < 0 && find_dent(d, n, "") < 0);   /* not self */
    {
        int dups = 0;
        for (int64_t i = 0; i < n; i++)
            if (count_dent(d, n, d[i].name) != 1) dups++;
        CHECK(dups == 0);
    }
    {
        int ix;   /* guarded: a missing name is a clean FAIL, never d[-1] UB */
        CHECK((ix = find_dent(d, n, "sub")) >= 0 && d[ix].type == LX_DT_DIR);
        CHECK((ix = find_dent(d, n, "libvfsprobe.so.1")) >= 0 && d[ix].type == LX_DT_REG);
        CHECK((ix = find_dent(d, n, "libvfsprobe.so")) >= 0 && d[ix].type == LX_DT_LNK);
        CHECK((ix = find_dent(d, n, "h8")) >= 0 && d[ix].type == LX_DT_LNK);
        CHECK((ix = find_dent(d, n, "dangling")) >= 0 && d[ix].type == LX_DT_LNK);
    }
    /* stable order: entries emit in table order (deterministic packer walk) */
    CHECK(strcmp(d[0].name, "sub") == 0);
    CHECK(strcmp(d[1].name, "libvfsprobe.so.1") == 0);
    CHECK(strcmp(d[2].name, "libvfsprobe.so") == 0);

    /* nested subdir: exactly {nested.so REG, nested-link.so LNK} */
    n = list_dir(ops, b, "/lib/sub", 0, 4096, s, 8);
    CHECK(n == 2);
    CHECK(find_dent(s, n, "nested.so") >= 0 && s[find_dent(s, n, "nested.so")].type == LX_DT_REG);
    CHECK(find_dent(s, n, "nested-link.so") >= 0 && s[find_dent(s, n, "nested-link.so")].type == LX_DT_LNK);

    /* symlink-to-dir: opening the link lists the TARGET dir's children */
    n = list_dir(ops, b, "/lib/sublink", 0, 4096, s, 8);
    CHECK(n == 2);
    CHECK(find_dent(s, n, "nested.so") >= 0 && find_dent(s, n, "nested-link.so") >= 0);

    /* partial reads: a 64-byte buffer (~1 dirent per call) resumes via the
     * cursor and yields the SAME sequence as the one-shot 4096 listing */
    n = list_dir(ops, b, "/lib", 0, 4096, d, 32);
    int64_t n2 = list_dir(ops, b, "/lib", 0, 64, d2, 32);
    CHECK(n2 == n);
    {
        int same = 1;
        for (int64_t i = 0; i < n && i < 32; i++)
            if (strcmp(d[i].name, d2[i].name) != 0 || d[i].type != d2[i].type) same = 0;
        CHECK(same);
    }

    /* buffer smaller than the first dirent → EINVAL (Linux getdents64) */
    CHECK(ops->open(b, "/lib", 0, 0, &h) == 0);
    {
        uint8_t tiny[8]; int64_t cur = 0;
        CHECK(ops->getdents(b, h, tiny, sizeof(tiny), &cur) == LX_EINVAL);
    }
    CHECK(ops->close(b, h) == 0);

    /* mid-listing EINVAL must NOT consume the unsent entry: Linux leaves the
     * dir position unchanged, so a bigger-buffer retry still returns it */
    CHECK(ops->open(b, "/lib", 0, 0, &h) == 0);
    {
        uint8_t big[4096]; uint8_t tiny[8]; int64_t cur = 0;
        int64_t got = ops->getdents(b, h, big, 24, &cur);   /* exactly "sub" (reclen 24) */
        struct lx_dirent64 *de = (struct lx_dirent64 *)big;
        CHECK(got == 24 && strcmp(de->d_name, "sub") == 0);
        CHECK(ops->getdents(b, h, tiny, sizeof(tiny), &cur) == LX_EINVAL);
        got = ops->getdents(b, h, big, sizeof(big), &cur);  /* retry, big buffer */
        CHECK(got > 0);
        CHECK(strcmp(de->d_name, "libvfsprobe.so.1") == 0); /* NOT silently lost */
    }
    CHECK(ops->close(b, h) == 0);

    /* getdents on a non-directory fd → ENOTDIR */
    CHECK(ops->open(b, "/lib/libvfsprobe.so.1", 0, 0, &h) == 0);
    {
        uint8_t dents[256]; int64_t cur = 0;
        CHECK(ops->getdents(b, h, dents, sizeof(dents), &cur) == LX_ENOTDIR);
    }
    CHECK(ops->close(b, h) == 0);
    CHECK(ops->open(b, "/lib/h8", LX_O_NOFOLLOW, 0, &h) == 0);   /* LNK handle */
    {
        uint8_t dents[256]; int64_t cur = 0;
        CHECK(ops->getdents(b, h, dents, sizeof(dents), &cur) == LX_ENOTDIR);
    }
    CHECK(ops->close(b, h) == 0);

    /* O_DIRECTORY honored at open (musl opendir's non-dir detection) */
    CHECK(ops->open(b, "/lib/libvfsprobe.so.1", LX_O_DIRECTORY, 0, &h) == LX_ENOTDIR);
    CHECK(ops->open(b, "/lib/h8", LX_O_NOFOLLOW | LX_O_DIRECTORY, 0, &h) == LX_ENOTDIR);
    CHECK(ops->open(b, "/lib/nope", LX_O_DIRECTORY, 0, &h) == LX_ENOENT);
    CHECK(ops->open(b, "/lib", LX_O_DIRECTORY, 0, &h) == 0);
    CHECK(ops->close(b, h) == 0);
    CHECK(ops->open(b, "/lib/sublink", LX_O_DIRECTORY, 0, &h) == 0);  /* follows to DIR */
    CHECK(ops->close(b, h) == 0);
    CHECK(ops->open(b, "/", LX_O_DIRECTORY, 0, &h) == 0);             /* mount root */
    CHECK(ops->close(b, h) == 0);

    if (fails == 0) printf("sysroot_lnk_unit: ALL PASS\n");
    return fails ? 1 : 0;
}
