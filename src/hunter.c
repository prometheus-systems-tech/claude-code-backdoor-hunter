/*
 * Copyright (c) 2026 Ross WD Cameron <rwd.cameron@prometheus-systems.co.za>
 * Licensed under the GNU General Public License, version 2.
 *
 * Read-only check for the trojanized anthropic.claude-code 2.1.313 (Cursor marketplace)
 * SSH backdoor, disclosed 30 Oct 2026. Makes no changes to the system.
 *
 * Builds on Linux, FreeBSD, macOS and Windows.
 * Exit codes: 0 = no indicators, 1 = indicators found, 2 = nothing definite, items need review.
 */

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define popen _popen
#define pclose _pclose
#define PLATFORM_WIN 1
#ifndef strndup
static char *strndup(const char *s, size_t n)
{
    size_t l = strlen(s);
    char *r;
    if (l > n) l = n;
    r = malloc(l + 1);
    if (r) { memcpy(r, s, l); r[l] = 0; }
    return r;
}
#endif
#else
#include <dirent.h>
#include <glob.h>
#include <limits.h>
#include <unistd.h>
#define PLATFORM_WIN 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define C2_IP     "134.209.82.225"
#define KEY_LABEL "svc-telemetry"
#define BAD_VER   "2.1.313"
#define BAD_VER2  "2.1.312"
#define KEY_BLOB  "AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P"
#define SINCE_STR "2026-10-29"
#define TOTAL_STEPS 8

static int g_found, g_review;
static time_t g_since;
static char g_home[PATH_MAX];
static char g_tmo[32];          /* "timeout" or "gtimeout" or "" */
static int g_is_mac, g_is_bsd, g_is_win;
static int g_sshd_ok;           /* --sshd-ok: a running sshd is expected */
static long g_budget;

/* ------------------------------------------------------------ output */

static void vsay(const char *tag, const char *fmt, va_list ap)
{
    printf("%s ", tag);
    vprintf(fmt, ap);
    putchar('\n');
}
static void warn(const char *fmt, ...) { va_list ap; va_start(ap, fmt); vsay("[!]", fmt, ap); va_end(ap); g_found = 1; }
static void note(const char *fmt, ...) { va_list ap; va_start(ap, fmt); vsay("[?]", fmt, ap); va_end(ap); g_review = 1; }
static void ok(const char *fmt, ...)   { va_list ap; va_start(ap, fmt); vsay("[ok]", fmt, ap); va_end(ap); }

static void progress(int step)
{
    int width = 30, filled = step * width / TOTAL_STEPS, i;
    char bar[64];
    for (i = 0; i < width; i++) bar[i] = i < filled ? '#' : '-';
    bar[width] = 0;
    printf("[%s] %d/%d (%d%%)\n", bar, step, TOTAL_STEPS, step * 100 / TOTAL_STEPS);
}

/* ------------------------------------------------------------ strings and buffers */

typedef struct { char *p; size_t n, cap; } Buf;

static void buf_add(Buf *b, const char *s, size_t n)
{
    if (b->n + n + 1 > b->cap) {
        b->cap = (b->n + n + 1) * 2;
        b->p = realloc(b->p, b->cap);
        if (!b->p) { fputs("out of memory\n", stderr); exit(3); }
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
}
static void buf_line(Buf *b, const char *s) { buf_add(b, s, strlen(s)); buf_add(b, "\n", 1); }
static void buf_free(Buf *b) { free(b->p); b->p = NULL; b->n = b->cap = 0; }

static char lc(char c) { return (char)tolower((unsigned char)c); }

static const char *ci_find(const char *h, const char *n)
{
    size_t nl = strlen(n), i;
    if (!nl) return h;
    for (; *h; h++) {
        for (i = 0; i < nl && h[i] && lc(h[i]) == lc(n[i]); i++) ;
        if (i == nl) return h;
    }
    return NULL;
}
static int ci_starts(const char *s, const char *p)
{
    for (; *p; s++, p++) if (lc(*s) != lc(*p)) return 0;
    return 1;
}
static int ci_ends(const char *s, const char *e)
{
    size_t sl = strlen(s), el = strlen(e);
    return sl >= el && ci_starts(s + sl - el, e);
}
static const char *basename_of(const char *p)
{
    const char *a = strrchr(p, '/');
#ifdef _WIN32
    const char *b = strrchr(p, '\\');
    if (b && (!a || b > a)) a = b;
#endif
    return a ? a + 1 : p;
}
static const void *mem_find(const void *h, size_t hn, const char *n)
{
    size_t nn = strlen(n), i;
    const unsigned char *p = h;
    if (!nn || hn < nn) return NULL;
    for (i = 0; i + nn <= hn; i++) {
        const unsigned char *q = memchr(p + i, (unsigned char)n[0], hn - i - nn + 1);
        if (!q) return NULL;
        i = (size_t)(q - p);
        if (!memcmp(q, n, nn)) return q;
    }
    return NULL;
}

/* Does any '|'-separated needle match (case-insensitively) the line? */
static int needle_match(const char *line, const char *needles, int anchored)
{
    char tmp[256];
    const char *s = needles;
    if (anchored) while (*line == ' ' || *line == '\t') line++;
    while (*s) {
        size_t n = strcspn(s, "|");
        if (n >= sizeof tmp) n = sizeof tmp - 1;
        memcpy(tmp, s, n);
        tmp[n] = 0;
        if (anchored ? ci_starts(line, tmp) : ci_find(line, tmp) != NULL) return 1;
        s += strcspn(s, "|");
        if (*s == '|') s++;
    }
    return 0;
}

typedef struct { char **v; int n; } SL;
static void sl_add(SL *l, const char *s)
{
    l->v = realloc(l->v, sizeof(char *) * (size_t)(l->n + 1));
    l->v[l->n++] = strdup(s);
}
static int sl_has(const SL *l, const char *s)
{
    int i;
    for (i = 0; i < l->n; i++) if (!strcmp(l->v[i], s)) return 1;
    return 0;
}

/* Print up to max lines of text, indented, each cut to cols. A negative max prints the last -max lines. */
static void print_lines(const char *text, int max, int cols)
{
    const char *s = text;
    int total = 0, skip = 0, shown = 0;
    while (*s) { total++; s = strchr(s, '\n'); if (!s) break; s++; }
    if (max < 0) { skip = total + max; if (skip < 0) skip = 0; max = -max; }
    s = text;
    while (*s && shown < max) {
        size_t n = strcspn(s, "\n");
        if (skip > 0) skip--;
        else {
            printf("    %.*s\n", (int)(n > (size_t)cols ? (size_t)cols : n), s);
            shown++;
        }
        s += n;
        if (*s == '\n') s++;
    }
}

/* ------------------------------------------------------------ SHA-256 */

typedef struct { uint32_t h[8]; uint64_t len; unsigned char blk[64]; size_t n; } Sha;
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha_block(Sha *s, const unsigned char *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i*4] << 24 | (uint32_t)p[i*4+1] << 16 | (uint32_t)p[i*4+2] << 8 | p[i*4+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (i = 0; i < 64; i++) {
        t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}
static void sha_init(Sha *s)
{
    static const uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(s->h, iv, sizeof iv);
    s->len = 0; s->n = 0;
}
static void sha_update(Sha *s, const unsigned char *p, size_t n)
{
    s->len += n;
    while (n) {
        size_t c = 64 - s->n;
        if (c > n) c = n;
        memcpy(s->blk + s->n, p, c);
        s->n += c; p += c; n -= c;
        if (s->n == 64) { sha_block(s, s->blk); s->n = 0; }
    }
}
static void sha_final(Sha *s, char out[65])
{
    uint64_t bits = s->len * 8;
    unsigned char pad = 0x80, z = 0, l[8];
    int i;
    sha_update(s, &pad, 1);
    while (s->n != 56) sha_update(s, &z, 1);
    for (i = 0; i < 8; i++) l[i] = (unsigned char)(bits >> (56 - 8 * i));
    sha_update(s, l, 8);
    for (i = 0; i < 8; i++) snprintf(out + i * 8, 9, "%08x", s->h[i]);
}

static int sha256_file(const char *path, char out[65])
{
    unsigned char buf[65536];
    size_t n;
    Sha s;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    sha_init(&s);
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) sha_update(&s, buf, n);
    fclose(f);
    sha_final(&s, out);
    return 1;
}

static const char *ioc_hash_name(const char *h)
{
    static const char *t[][2] = {
        {"ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15", "trojanized extension.js (2.1.312/2.1.313)"},
        {"fcbb327e38e61c4fec795e0d0591f52cd1014b813d20a5912104953c3a17c364", "malicious VSIX 2.1.312 darwin-arm64"},
        {"3de1722901165769893bef57c72594e9a54459faa23f3091b136b79966edd081", "malicious VSIX 2.1.312 win32-x64"},
        {"80402fdcad8799285fd93044976973ca000da7995fb93363f819bb8e4f84ee6c", "malicious VSIX 2.1.313 darwin-arm64"},
        {"6786ec90cbd45949695bd7805c9fbb26cfc91bc5fc897de0183d9bcb9cb21731", "malicious VSIX 2.1.313 win32-x64"},
        {"432ccdee3801f99e52b8fe31f69ea9870118e96ea7ef9ecabed1479621b5ab62", "malicious VSIX (reported by Corgea)"},
        {"7e0a52885fadee05544a9e99eb18c792bec05900a5e1a66d68f8383decb0e278", "dropped reverse-tunnel private key"},
        {"22f682d9ff55264e934d0f43fcfbb46d58be5cfb8fe1b3a7cbb38fe089c818b0", "dropped smt.cmd persistence script"},
    };
    size_t i;
    for (i = 0; i < sizeof t / sizeof t[0]; i++) if (!strcmp(h, t[i][0])) return t[i][1];
    return NULL;
}

/* Returns 1 and prints a warning when the file's hash is a known IOC. */
static int check_hash(const char *path)
{
    char h[65];
    const char *n;
    if (!sha256_file(path, h)) return 0;
    n = ioc_hash_name(h);
    if (!n) return 0;
    warn("Known-malicious file hash (%s): %s", n, path);
    return 1;
}

/* ------------------------------------------------------------ files and walking */

static int path_kind(const char *p, long long *size, time_t *mtime)
{
    struct stat st;
    if (stat(p, &st)) return 0;
    if (size) *size = (long long)st.st_size;
    if (mtime) *mtime = st.st_mtime;
    return S_ISDIR(st.st_mode) ? 2 : (S_ISREG(st.st_mode) ? 1 : 3);
}
static int dir_exists(const char *p) { return path_kind(p, NULL, NULL) == 2; }
static int file_exists(const char *p) { return path_kind(p, NULL, NULL) != 0; }

static int readable(const char *p)
{
#ifdef _WIN32
    return _access(p, 4) == 0;
#else
    return access(p, R_OK) == 0;
#endif
}

typedef struct {
    const char *path, *name;
    int is_dir, is_exec;
    long long size;
    time_t mtime;
} Ent;
/* Return 0 to continue, 1 to not descend into this directory, 2 to abort the walk. */
typedef int (*walk_cb)(const Ent *e, void *ud);

static int walk_rec(const char *dir, int depth, int maxd, walk_cb cb, void *ud)
{
    char path[PATH_MAX];
#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    HANDLE h;
    snprintf(path, sizeof path, "%s/*", dir);
    h = FindFirstFileA(path, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        Ent e;
        ULARGE_INTEGER ft;
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (g_budget-- <= 0) { FindClose(h); return 2; }
        snprintf(path, sizeof path, "%s/%s", dir, fd.cFileName);
        ft.LowPart = fd.ftLastWriteTime.dwLowDateTime;
        ft.HighPart = fd.ftLastWriteTime.dwHighDateTime;
        e.path = path; e.name = fd.cFileName;
        e.is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        e.size = ((long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        e.mtime = (time_t)(ft.QuadPart / 10000000ULL - 11644473600ULL);
        e.is_exec = !e.is_dir && ci_ends(fd.cFileName, ".exe");
        {
            int r = cb(&e, ud);
            if (r == 2) { FindClose(h); return 2; }
            if (e.is_dir && r == 0 && depth < maxd && walk_rec(path, depth + 1, maxd, cb, ud) == 2) {
                FindClose(h);
                return 2;
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(dir);
    struct dirent *de;
    if (!d) return 0;
    while ((de = readdir(d))) {
        struct stat st;
        Ent e;
        int r;
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (g_budget-- <= 0) { closedir(d); return 2; }
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        if (lstat(path, &st)) continue;
        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) continue;
        e.path = path; e.name = de->d_name;
        e.is_dir = S_ISDIR(st.st_mode);
        e.size = (long long)st.st_size;
        e.mtime = st.st_mtime;
        e.is_exec = !e.is_dir && (st.st_mode & S_IXUSR);
        r = cb(&e, ud);
        if (r == 2) { closedir(d); return 2; }
        if (e.is_dir && r == 0 && depth < maxd && walk_rec(path, depth + 1, maxd, cb, ud) == 2) {
            closedir(d);
            return 2;
        }
    }
    closedir(d);
#endif
    return 0;
}

/* Walk dir to a maximum depth (1 = direct children only). A budget stands in for find's timeout. */
static void walk(const char *dir, int maxd, walk_cb cb, void *ud)
{
    g_budget = 400000;
    walk_rec(dir, 1, maxd, cb, ud);
}

static char *read_file(const char *path, long long maxsize, size_t *len)
{
    long long sz = 0;
    FILE *f;
    char *b;
    if (path_kind(path, &sz, NULL) != 1 || sz > maxsize) return NULL;
    f = fopen(path, "rb");
    if (!f) return NULL;
    b = malloc((size_t)sz + 1);
    if (!b) { fclose(f); return NULL; }
    *len = fread(b, 1, (size_t)sz, f);
    b[*len] = 0;
    fclose(f);
    return b;
}

static int file_contains(const char *path, long long maxsize, const char *needle)
{
    size_t n = 0;
    char *b = read_file(path, maxsize, &n);
    int r;
    if (!b) return 0;
    r = mem_find(b, n, needle) != NULL;
    free(b);
    return r;
}

/* Read one line (without the newline) into b. Returns 0 at EOF. */
static int read_line(FILE *f, Buf *b)
{
    char chunk[4096];
    int got = 0;
    b->n = 0;
    if (!b->p) buf_add(b, "", 0);
    b->p[0] = 0;
    while (fgets(chunk, sizeof chunk, f)) {
        size_t n = strlen(chunk);
        got = 1;
        buf_add(b, chunk, n);
        if (chunk[n - 1] == '\n') break;
    }
    while (b->n && (b->p[b->n - 1] == '\n' || b->p[b->n - 1] == '\r')) b->p[--b->n] = 0;
    return got;
}

typedef void (*line_cb)(const char *line, void *ud);

static void file_lines(const char *path, line_cb cb, void *ud)
{
    FILE *f = fopen(path, "rb");
    Buf b = {0};
    if (!f) return;
    while (read_line(f, &b)) cb(b.p, ud);
    fclose(f);
    buf_free(&b);
}

/* Run a command (stderr discarded) and feed each output line to cb. */
static int run_lines(const char *cmd, int tmo, line_cb cb, void *ud)
{
    char full[4096];
    FILE *p;
    Buf b = {0};
    if (tmo && g_tmo[0])
        snprintf(full, sizeof full, "%s %d %s 2>/dev/null", g_tmo, tmo, cmd);
    else
        snprintf(full, sizeof full, "%s %s", cmd, PLATFORM_WIN ? "2>nul" : "2>/dev/null");
    fflush(stdout);
    p = popen(full, "r");
    if (!p) return 0;
    while (read_line(p, &b)) cb(b.p, ud);
    buf_free(&b);
    pclose(p);
    return 1;
}

static int have(const char *c)
{
    char cmd[256];
    snprintf(cmd, sizeof cmd, PLATFORM_WIN ? "where %s >nul 2>&1" : "command -v %s >/dev/null 2>&1", c);
    return system(cmd) == 0;
}
static int cmd_ok(const char *cmd)
{
    char full[1024];
    snprintf(full, sizeof full, PLATFORM_WIN ? "%s >nul 2>&1" : "%s >/dev/null 2>&1", cmd);
    return system(full) == 0;
}

/* ------------------------------------------------------------ line collectors */

typedef struct {
    Buf out;
    const char *needles;
    int anchored;
    const char *exclude;
} Collect;

static void col_needles(const char *line, void *ud)
{
    Collect *c = ud;
    if (c->exclude && strstr(line, c->exclude)) return;
    if (needle_match(line, c->needles, c->anchored)) buf_line(&c->out, line);
}
static void col_all(const char *line, void *ud) { buf_line(&((Collect *)ud)->out, line); }
static void col_c2(const char *line, void *ud) { if (strstr(line, C2_IP)) buf_line(&((Collect *)ud)->out, line); }
static void col_login(const char *line, void *ud)
{
    if (strstr(line, "Accepted publickey") || strstr(line, "Accepted password")) buf_line(&((Collect *)ud)->out, line);
}

/* ------------------------------------------------------------ path helpers */

static char *join(char *dst, size_t n, const char *a, const char *b)
{
    snprintf(dst, n, "%s/%s", a, b);
    return dst;
}
static const char *env_or(const char *name, const char *dflt)
{
    const char *v = getenv(name);
    return v && *v ? v : dflt;
}

static void add_existing_dir(SL *l, const char *base, const char *rel)
{
    char p[PATH_MAX];
    if (rel) join(p, sizeof p, base, rel); else snprintf(p, sizeof p, "%s", base);
    if (dir_exists(p)) sl_add(l, p);
}

/* ------------------------------------------------------------ section 1 helpers */

typedef struct { SL found; const char *prefix; } NameFind;

static int cb_extdirs(const Ent *e, void *ud)
{
    NameFind *nf = ud;
    if (e->is_dir && ci_starts(e->name, nf->prefix)) { sl_add(&nf->found, e->path); return 1; }
    return 0;
}

static int cb_scan_c2(const Ent *e, void *ud)
{
    if (!e->is_dir && e->size <= 5 * 1024 * 1024 && file_contains(e->path, 5 * 1024 * 1024, C2_IP)) {
        *(int *)ud = 1;
        return 2;
    }
    return 0;
}

typedef struct { SL hits; int max; } Hits;

static int cb_logs(const Ent *e, void *ud)
{
    Hits *h = ud;
    size_t n = 0;
    char *b;
    const char *p;
    if (e->is_dir || e->size > 5 * 1024 * 1024) return 0;
    b = read_file(e->path, 5 * 1024 * 1024, &n);
    if (!b) return 0;
    p = b;
    while ((p = mem_find(p, n - (size_t)(p - b), BAD_VER)) != NULL) {
        const char *ls = p, *le = p;
        char line[1024];
        size_t ll;
        while (ls > b && ls[-1] != '\n') ls--;
        while (*le && *le != '\n') le++;
        ll = (size_t)(le - ls);
        if (ll >= sizeof line) ll = sizeof line - 1;
        memcpy(line, ls, ll);
        line[ll] = 0;
        if (strstr(line, "claude-code") &&
            !strstr(line, "RunInTerminalTool") && !strstr(line, "terminal.log") &&
            !strstr(line, "mkdir ") && !strstr(line, "grep ") && !strstr(line, "echo ") &&
            !strstr(line, "ls ") && !strstr(line, "rm ")) {
            sl_add(&h->hits, e->path);
            break;
        }
        p = le;
    }
    free(b);
    return h->hits.n >= h->max ? 2 : 0;
}

static void pm_check(const char *label, const char *cmd, const char *needles, int anchored)
{
    Collect c = {{0}, needles, anchored, "claude-code-backdoor-hunter"};
    run_lines(cmd, 20, col_needles, &c);
    if (c.out.n) {
        note("%s install found, confirm the extension version separately:", label);
        print_lines(c.out.p, 1000, 1000);
    }
    buf_free(&c.out);
}

static int cb_manual(const Ent *e, void *ud)
{
    Hits *h = ud;
    const char *n = e->name;
    int match = 0;
    if (h->hits.n >= h->max) return 2;
    if (ci_ends(n, ".appimage") && ci_find(n, "cursor")) match = 1;
    else if (ci_starts(n, "cursor")) {
        if (e->is_dir || e->is_exec) match = 1;
        else if (ci_find(n, ".tar") || ci_ends(n, ".tgz") || ci_ends(n, ".zip")) match = 1;
    }
    if (match) { sl_add(&h->hits, e->path); return e->is_dir ? 1 : 0; }
    return 0;
}

static int cb_vsix(const Ent *e, void *ud)
{
    Hits *h = ud;
    if (h->hits.n >= h->max) return 2;
    if (!e->is_dir && ci_find(e->name, "claude-code") && ci_ends(e->name, ".vsix")) sl_add(&h->hits, e->path);
    return 0;
}

static int cb_desktop(const Ent *e, void *ud)
{
    (void)ud;
    if (!e->is_dir && ci_find(e->name, "cursor") && ci_ends(e->name, ".desktop")) {
        Buf b = {0};
        FILE *f = fopen(e->path, "rb");
        char exec[512] = "";
        if (f) {
            while (read_line(f, &b)) if (!strncmp(b.p, "Exec=", 5)) { snprintf(exec, sizeof exec, "%s", b.p); break; }
            fclose(f);
        }
        buf_free(&b);
        note("Desktop entry %s -> %s", e->path, exec);
    }
    return 0;
}

static void check_extensions_json(void)
{
    static const char *dirs[] = {".cursor", ".vscode", ".vscode-insiders", ".vscode-oss", ".vscodium", ".vscode-server"};
    size_t i;
    for (i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        char p[PATH_MAX], rel[128];
        size_t n = 0;
        char *b;
        const char *s;
        snprintf(rel, sizeof rel, "%s/extensions/extensions.json", dirs[i]);
        join(p, sizeof p, g_home, rel);
        b = read_file(p, 64 * 1024 * 1024, &n);
        if (!b) continue;
        s = b;
        while ((s = mem_find(s, n - (size_t)(s - b), "anthropic.claude-code")) != NULL) {
            size_t rem = n - (size_t)(s - b), win = rem < 250 ? rem : 250;
            if (mem_find(s, win, BAD_VER)) {
                warn("extensions.json lists claude-code %s: %s", BAD_VER, p);
                break;
            }
            s += 21;
        }
        free(b);
    }
}

static void section1(void)
{
    SL roots = {0}, logs = {0}, mroots = {0};
    NameFind nf = {{0}, "anthropic.claude-code-"};
    Hits h = {{0}, 20};
    int i;
    char p[PATH_MAX];
    const char *appdata = getenv("APPDATA"), *local = getenv("LOCALAPPDATA");

    puts("== 1. Installs and extensions (packages, Flatpak, Snap, AppImage, tarball, VSIX) ==");

    {
        static const char *rel[] = {".cursor", ".cursor-server", ".config/Cursor", ".vscode", ".vscode-insiders",
            ".vscode-oss", ".vscodium", ".vscode-server", ".var/app", "snap", ".cursor-linux",
            "Library/Application Support/Cursor", "Library/Application Support/Code",
            "Library/Application Support/Code - Insiders", "Library/Application Support/VSCodium"};
        for (i = 0; i < (int)(sizeof rel / sizeof rel[0]); i++) add_existing_dir(&roots, g_home, rel[i]);
        add_existing_dir(&roots, "/compat/linux/root/.cursor", NULL);
        if (appdata) {
            add_existing_dir(&roots, appdata, "Cursor");
            add_existing_dir(&roots, appdata, "Code");
            add_existing_dir(&roots, appdata, "Code - Insiders");
            add_existing_dir(&roots, appdata, "VSCodium");
        }
        if (local) {
            add_existing_dir(&roots, local, "Programs/cursor");
            add_existing_dir(&roots, local, "Programs/Microsoft VS Code");
        }
    }
    for (i = 0; i < roots.n; i++) walk(roots.v[i], 6, cb_extdirs, &nf);

    if (!nf.found.n) {
        ok("No anthropic.claude-code extension folders found.");
    } else {
        for (i = 0; i < nf.found.n; i++) {
            const char *d = nf.found.v[i];
            int c2 = 0;
            if (strstr(d, BAD_VER)) warn("Malicious version installed: %s", d);
            else if (strstr(d, BAD_VER2))
                note("Extension %s present: malicious only if from Cursor's marketplace, check the hash result below: %s", BAD_VER2, d);
            else note("Extension present (not %s), confirm it was never %s: %s", BAD_VER, BAD_VER, d);
            check_hash(join(p, sizeof p, d, "extension.js"));
            walk(d, 12, cb_scan_c2, &c2);
            if (c2) warn("C2 IP found inside extension files: %s", d);
        }
    }

    check_extensions_json();

    /* editor logs can show past installs/updates even if the extension is gone */
    {
        static const char *rel[] = {".config/Cursor/logs", ".config/Code/logs", ".cursor/logs",
            "Library/Application Support/Cursor/logs", "Library/Application Support/Code/logs", "Library/Logs"};
        for (i = 0; i < (int)(sizeof rel / sizeof rel[0]); i++) add_existing_dir(&logs, g_home, rel[i]);
        if (appdata) { add_existing_dir(&logs, appdata, "Cursor/logs"); add_existing_dir(&logs, appdata, "Code/logs"); }
    }
    h.max = 5;
    for (i = 0; i < logs.n; i++) walk(logs.v[i], 12, cb_logs, &h);
    if (h.hits.n) {
        warn("Editor logs mention claude-code %s:", BAD_VER);
        for (i = 0; i < h.hits.n; i++) printf("    %s\n", h.hits.v[i]);
    }

    puts("");
    puts("-- Package managers (the malicious item is the extension " BAD_VER ", not the app itself) --");
    if (have("dpkg-query"))
        pm_check("dpkg/apt", "dpkg-query -W -f='${Package} ${Version}\\n'", "cursor|claude-code|anysphere", 1);
    if (have("pkg"))     pm_check("FreeBSD pkg", "pkg info", "cursor|claude-code|anysphere|vscode|code-oss|vscodium", 1);
    if (have("rpm"))     pm_check("rpm/dnf", "rpm -qa", "cursor|claude-code|anysphere", 1);
    if (have("dnf"))     pm_check("dnf history", "dnf -q history list", "cursor|claude-code|anysphere", 0);
    if (have("pacman"))  pm_check("pacman/AUR", "pacman -Q", "cursor|claude-code", 1);
    if (have("snap"))    pm_check("snap", "snap list", "cursor|claude", 1);
    if (have("flatpak")) pm_check("flatpak", "flatpak list --app --columns=application,version,installation", "cursor|claude|anysphere", 0);
    if (have("brew")) {
        pm_check("Homebrew", "brew list --versions", "cursor|claude", 1);
        pm_check("Homebrew cask", "brew list --cask --versions", "cursor|claude|visual-studio-code|vscodium", 1);
    }
    if (have("pkgutil")) pm_check("macOS pkgutil", "pkgutil --pkgs", "cursor|claude-code|anysphere|todesktop", 0);
    if (have("nix-env")) pm_check("nix", "nix-env -q", "cursor|claude", 0);
    if (have("npm"))     pm_check("npm global", "npm ls -g --depth=0", "claude-code", 0);
    if (have("pnpm"))    pm_check("pnpm global", "pnpm ls -g --depth=0", "claude-code", 0);
    if (g_is_win && have("winget"))
        pm_check("winget", "winget list --accept-source-agreements", "cursor|claude|anysphere", 0);

    puts("-- AppImage, tarball and manual installs --");
    {
        static const char *rel[] = {"Applications", "Downloads", "Desktop", "Documents", "bin", "opt", ".local/bin",
            ".local/opt", ".local/share/appimagekit"};
        static const char *abs[] = {"/Applications", "/Users/Shared", "/opt", "/usr/local", "/compat/linux/opt",
            "/tmp", "/var/tmp", "/mnt", "/media"};
        for (i = 0; i < (int)(sizeof rel / sizeof rel[0]); i++) add_existing_dir(&mroots, g_home, rel[i]);
        for (i = 0; i < (int)(sizeof abs / sizeof abs[0]); i++) add_existing_dir(&mroots, abs[i], NULL);
        if (local) add_existing_dir(&mroots, local, "Programs");
        add_existing_dir(&mroots, env_or("ProgramFiles", "/nonexistent"), NULL);
        add_existing_dir(&mroots, env_or("TEMP", "/nonexistent"), NULL);
    }
    memset(&h, 0, sizeof h);
    h.max = 20;
    for (i = 0; i < mroots.n; i++) walk(mroots.v[i], 4, cb_manual, &h);
    if (h.hits.n) {
        int j;
        note("Possible AppImage/tarball/manual Cursor installs:");
        for (i = 0; i < h.hits.n; i++) printf("    %s\n", h.hits.v[i]);
        for (i = 0; i < h.hits.n; i++) {
            NameFind inner = {{0}, "anthropic.claude-code-"};
            if (!dir_exists(h.hits.v[i])) continue;
            walk(h.hits.v[i], 6, cb_extdirs, &inner);
            for (j = 0; j < inner.found.n; j++) {
                if (strstr(inner.found.v[j], BAD_VER)) warn("Malicious version in portable install: %s", inner.found.v[j]);
                else note("Extension inside portable install: %s", inner.found.v[j]);
            }
        }
    } else {
        ok("No AppImage or tarball Cursor installs found in common locations.");
    }

    {
        const char *path = getenv("PATH");
        const char *exe = g_is_win ? "cursor.cmd" : "cursor";
        if (path) {
            const char *s = path;
            while (*s) {
                size_t n = strcspn(s, g_is_win ? ";" : ":");
                char dir[PATH_MAX], cand[PATH_MAX];
                if (n && n < sizeof dir) {
                    memcpy(dir, s, n);
                    dir[n] = 0;
                    join(cand, sizeof cand, dir, exe);
                    if (file_exists(cand)) {
#ifndef _WIN32
                        char real[PATH_MAX];
                        if (realpath(cand, real)) snprintf(cand, sizeof cand, "%s", real);
#endif
                        note("cursor on PATH: %s", cand);
                        break;
                    }
                }
                s += n;
                if (*s) s++;
            }
        }
    }
    {
        static const char *ddirs[] = {"/usr/share/applications", "/usr/local/share/applications",
            "/var/lib/flatpak/exports/share/applications"};
        for (i = 0; i < (int)(sizeof ddirs / sizeof ddirs[0]); i++) walk(ddirs[i], 1, cb_desktop, NULL);
        join(p, sizeof p, g_home, ".local/share/applications");
        walk(p, 1, cb_desktop, NULL);
        join(p, sizeof p, g_home, ".local/share/flatpak/exports/share/applications");
        walk(p, 1, cb_desktop, NULL);
    }

    {
        static const char *rel[] = {"Downloads", "Desktop", "Documents", ".cache"};
        Hits v = {{0}, 10};
        for (i = 0; i < (int)(sizeof rel / sizeof rel[0]); i++) {
            join(p, sizeof p, g_home, rel[i]);
            walk(p, 4, cb_vsix, &v);
        }
        walk("/tmp", 4, cb_vsix, &v);
        for (i = 0; i < v.hits.n; i++) {
            if (check_hash(v.hits.v[i])) continue;
            if (strstr(v.hits.v[i], BAD_VER)) warn("Malicious VSIX file: %s", v.hits.v[i]);
            else note("VSIX file (check its version): %s", v.hits.v[i]);
        }
    }
}

/* ------------------------------------------------------------ section 2 */

static void list_homes(SL *homes)
{
    static const char *bases[] = {"/home", "/Users", "C:/Users"};
    size_t b;
    sl_add(homes, g_home);
    for (b = 0; b < sizeof bases / sizeof bases[0]; b++) {
        NameFind nf = {{0}, ""};   /* empty prefix: every direct subdirectory */
        int i;
        walk(bases[b], 1, cb_extdirs, &nf);
        for (i = 0; i < nf.found.n; i++) if (!sl_has(homes, nf.found.v[i])) sl_add(homes, nf.found.v[i]);
    }
    if (!sl_has(homes, "/root")) sl_add(homes, "/root");
    if (!sl_has(homes, "/var/root")) sl_add(homes, "/var/root");
}

typedef struct { SL files; } KeyFiles;
static int cb_keyfiles(const Ent *e, void *ud)
{
    if (!e->is_dir) sl_add(&((KeyFiles *)ud)->files, e->path);
    return 0;
}

static void section2(void)
{
    SL homes = {0}, files = {0};
    KeyFiles kf = {{0}};
    int i, checked = 0;
    char p[PATH_MAX];
    static const char *names[] = {".ssh/authorized_keys", ".ssh/authorized_keys2"};
    const char *pd = getenv("ProgramData");

    puts("== 2. SSH authorized_keys (all readable users) ==");
    list_homes(&homes);
    for (i = 0; i < homes.n; i++) {
        int j;
        for (j = 0; j < 2; j++) {
            join(p, sizeof p, homes.v[i], names[j]);
            if (readable(p) && file_exists(p) && !sl_has(&files, p)) sl_add(&files, p);
        }
    }
    walk("/etc/ssh/authorized_keys.d", 1, cb_keyfiles, &kf);
    for (i = 0; i < kf.files.n; i++) if (readable(kf.files.v[i])) sl_add(&files, kf.files.v[i]);
    if (pd) {
        join(p, sizeof p, pd, "ssh/administrators_authorized_keys");
        if (readable(p) && file_exists(p)) sl_add(&files, p);
    }

    for (i = 0; i < files.n; i++) {
        const char *kf_path = files.v[i];
        size_t n = 0;
        char *b = read_file(kf_path, 16 * 1024 * 1024, &n);
        time_t mt = 0;
        const char *s;
        int ln = 0;
        if (!b) continue;
        checked = 1;
        s = b;
        while (*s) {
            size_t l = strcspn(s, "\n");
            char *line = strndup(s, l);
            ln++;
            if (strstr(line, KEY_LABEL)) printf("%d:%s\n", ln, line);
            free(line);
            s += l;
            if (*s) s++;
        }
        if (strstr(b, KEY_LABEL)) warn("Key labelled '%s' in %s", KEY_LABEL, kf_path);
        if (mem_find(b, n, KEY_BLOB)) warn("Attacker public key material (fingerprint SHA256:0Z6R+DF6...) in %s", kf_path);
        if (path_kind(kf_path, NULL, &mt) && mt >= g_since)
            note("%s modified since %s. Review its keys:", kf_path, SINCE_STR);
        s = b;
        while (*s) {
            size_t l = strcspn(s, "\n");
            const char *e = s + l, *w = e;
            while (w > s && (w[-1] == '\r' || w[-1] == ' ' || w[-1] == '\t')) w--;
            if (w > s) {
                const char *st = w;
                while (st > s && st[-1] != ' ' && st[-1] != '\t') st--;
                printf("    - %.*s\n", (int)(w - st), st);
            }
            s = e;
            if (*s) s++;
        }
        free(b);
    }
    if (!checked) ok("No authorized_keys files found.");
    {
        static const char *dirs[] = {"/root/.ssh", "/etc/ssh/sshd_config.d"};
        for (i = 0; i < 2; i++)
            if (dir_exists(dirs[i]) && !readable(dirs[i])) note("Cannot read %s (run with sudo for a full check).", dirs[i]);
    }
}

/* ------------------------------------------------------------ section 3 */

typedef struct { SL hits; } Persist;

static int cb_persist(const Ent *e, void *ud)
{
    if (!e->is_dir && e->size <= 1024 * 1024) {
        size_t n = 0;
        char *b = read_file(e->path, 1024 * 1024, &n);
        if (b) {
            if (mem_find(b, n, C2_IP) || mem_find(b, n, KEY_LABEL)) sl_add(&((Persist *)ud)->hits, e->path);
            free(b);
        }
    }
    return 0;
}

static void scan_persist_path(const char *p, Persist *ps)
{
    Ent e;
    int k = path_kind(p, &e.size, &e.mtime);
    if (!k || !readable(p)) return;
    if (k == 2) { walk(p, 6, cb_persist, ps); return; }
    e.path = p; e.name = basename_of(p); e.is_dir = 0; e.is_exec = 0;
    cb_persist(&e, ps);
}

static int cb_artefact(const Ent *e, void *ud)
{
    int *art = ud;
    if (e->is_dir) return 0;
    if (!strcmp(e->name, ".smt") || !strcmp(e->name, ".smtk") || !strcmp(e->name, "smt.cmd") ||
        (!strncmp(e->name, ".stk_", 5))) {
        *art = 1;
        warn("Known malware artefact present: %s", e->path);
        check_hash(e->path);
    }
    return 0;
}

static int cb_recent(const Ent *e, void *ud)
{
    Hits *h = ud;
    if (h->hits.n >= h->max) return 2;
    if (!e->is_dir && e->mtime >= g_since) sl_add(&h->hits, e->path);
    return 0;
}

static void section3(void)
{
    static const char *hrel[] = {".config/systemd", ".config/autostart", ".local/bin", ".bashrc", ".profile",
        ".bash_profile", ".zshrc", ".zprofile", ".bash_logout", ".config/fish", ".bashrc.d", ".cshrc", ".login",
        ".shrc", ".tcshrc", ".zshenv", "Library/LaunchAgents"};
    static const char *abs[] = {"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly",
        "/etc/cron.monthly", "/etc/crontab", "/etc/systemd/system", "/etc/systemd/user", "/var/spool/cron",
        "/var/spool/cron/crontabs", "/var/cron/tabs", "/usr/local/etc/cron.d", "/etc/rc.conf", "/etc/rc.conf.d",
        "/etc/rc.local.d", "/usr/local/etc/rc.d", "/etc/periodic", "/usr/local/etc/periodic", "/etc/csh.cshrc",
        "/etc/csh.login", "/etc/profile.d", "/etc/profile", "/etc/bashrc", "/etc/bash.bashrc", "/etc/rc.local",
        "/etc/rc.d/rc.local", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d", "/Library/LaunchAgents",
        "/Library/LaunchDaemons", "/usr/lib/cron/tabs", "/etc/zshenv", "/etc/zprofile", "/etc/zshrc",
        "/etc/paths.d"};
    Persist ps = {{0}};
    Collect c = {{0}, NULL, 0, NULL};
    Hits rec = {{0}, 20};
    int i, art = 0;
    char p[PATH_MAX];
    const char *appdata = getenv("APPDATA"), *pd = getenv("ProgramData");

    puts("");
    progress(2);
    puts("== 3. Persistence: cron, systemd, autostart, shell profiles ==");

    if (!g_is_win) {
        run_lines("crontab -l", 10, col_all, &c);
        if (c.out.n) {
            const char *s = c.out.p;
            Buf hit = {0};
            while (*s) {
                size_t l = strcspn(s, "\n");
                char *line = strndup(s, l);
                if (strstr(line, C2_IP) || strstr(line, KEY_LABEL) || strstr(line, ".config/.smt")) buf_line(&hit, line);
                free(line);
                s += l;
                if (*s) s++;
            }
            if (hit.n) { printf("%s", hit.p); warn("User crontab references the C2 IP or key label."); }
            else ok("User crontab clean.");
            buf_free(&hit);
        } else ok("User crontab clean.");
        buf_free(&c.out);
    } else {
        Collect t = {{0}, NULL, 0, NULL};
        run_lines("schtasks /query /v /fo list", 60, col_all, &t);
        if (t.out.n && (strstr(t.out.p, C2_IP) || strstr(t.out.p, KEY_LABEL)))
            warn("Scheduled tasks reference the C2 IP or key label.");
        else ok("Scheduled tasks clean.");
        buf_free(&t.out);
    }

    for (i = 0; i < (int)(sizeof hrel / sizeof hrel[0]); i++) {
        join(p, sizeof p, g_home, hrel[i]);
        scan_persist_path(p, &ps);
    }
    for (i = 0; i < (int)(sizeof abs / sizeof abs[0]); i++) scan_persist_path(abs[i], &ps);
    if (appdata) {
        join(p, sizeof p, appdata, "Microsoft/Windows/Start Menu/Programs/Startup");
        scan_persist_path(p, &ps);
    }
    if (pd) {
        join(p, sizeof p, pd, "Microsoft/Windows/Start Menu/Programs/StartUp");
        scan_persist_path(p, &ps);
    }
    if (g_is_win) scan_persist_path("C:/Windows/System32/Tasks", &ps);
    if (ps.hits.n) {
        warn("Persistence files reference the C2 IP or key label:");
        for (i = 0; i < ps.hits.n; i++) printf("    %s\n", ps.hits.v[i]);
    } else ok("No persistence files reference the C2 IP or key label.");

    /* Known dropped artefacts (reverse-tunnel script and key, fake LaunchAgent) */
    join(p, sizeof p, g_home, ".config");
    walk(p, 1, cb_artefact, &art);
    {
        const char *tmpdir = env_or("TMPDIR", env_or("TEMP", "/tmp"));
        walk(tmpdir, 1, cb_artefact, &art);
        walk("/tmp", 1, cb_artefact, &art);
        walk("/var/tmp", 1, cb_artefact, &art);
    }
    join(p, sizeof p, g_home, "Library/LaunchAgents/com.apple.sysmond.plist");
    if (file_exists(p)) { art = 1; warn("Known malware artefact present: %s", p); check_hash(p); }
    if (!art) ok("No known dropped artefacts (.smt, .smtk, .stk_*, com.apple.sysmond.plist).");

    for (i = 0; i < (int)(sizeof hrel / sizeof hrel[0]); i++) {
        if (i < 3 || i == 16) { join(p, sizeof p, g_home, hrel[i]); walk(p, 6, cb_recent, &rec); }
    }
    walk("/Library/LaunchAgents", 6, cb_recent, &rec);
    walk("/Library/LaunchDaemons", 6, cb_recent, &rec);
    walk("/etc/cron.d", 6, cb_recent, &rec);
    walk("/etc/systemd/system", 6, cb_recent, &rec);
    if (rec.hits.n) {
        note("Persistence files created or changed since %s (verify you made them):", SINCE_STR);
        for (i = 0; i < rec.hits.n; i++) printf("    %s\n", rec.hits.v[i]);
    }
}

/* ------------------------------------------------------------ section 4 */

/* Lines where the IP or label was only being searched for (grep, journalctl, this tool, ...) */
static int history_benign(const char *line)
{
    static const char *words = "grep|egrep|fgrep|zgrep|rg|ag|journalctl|ausearch|less|cat|tail|head|"
                               "claude-code-backdoor-hunter|check_claude_code_backdoor";
    const char *s = line;
    size_t n;
    char tok[PATH_MAX];
    if (s[0] == ':' && s[1] == ' ') { /* zsh extended history ": 1700000000:0;cmd" */
        const char *semi = strchr(s, ';');
        if (semi) s = semi + 1;
    }
    while (*s == ' ' || *s == '\t') s++;
    if (!strncmp(s, "sudo", 4) && (s[4] == ' ' || s[4] == '\t')) {
        s += 4;
        while (*s == ' ' || *s == '\t') s++;
    }
    n = strcspn(s, " \t");
    if (n >= sizeof tok) n = sizeof tok - 1;
    memcpy(tok, s, n);
    tok[n] = 0;
    return needle_match(basename_of(tok), words, 1);
}

static void section4(void)
{
    static const char *rel[] = {".bash_history", ".zsh_history", ".local/share/fish/fish_history", ".history",
        ".sh_history", "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"};
    int i, hist = 0;
    char p[PATH_MAX];

    puts("");
    progress(3);
    puts("== 4. Shell history ==");
    for (i = 0; i < (int)(sizeof rel / sizeof rel[0]); i++) {
        Collect c = {{0}, NULL, 0, NULL};
        Buf hit = {0};
        const char *s;
        join(p, sizeof p, g_home, rel[i]);
        if (!file_exists(p)) continue;
        file_lines(p, col_all, &c);
        s = c.out.p ? c.out.p : "";
        while (*s) {
            size_t l = strcspn(s, "\n");
            char *line = strndup(s, l);
            if ((strstr(line, C2_IP) || strstr(line, KEY_LABEL)) && !history_benign(line)) buf_line(&hit, line);
            free(line);
            s += l;
            if (*s) s++;
        }
        if (hit.n) {
            warn("C2 IP or key label in %s:", p);
            print_lines(hit.p, 5, 200);
            hist = 1;
        }
        buf_free(&hit);
        buf_free(&c.out);
    }
    if (!hist) ok("No references in shell history.");
}

/* ------------------------------------------------------------ section 5 */

static int has_ssh_R_port(const char *line)
{
    const char *s = line;
    while ((s = strstr(s, "ssh")) != NULL) {
        const char *q = s + 3;
        while ((q = strstr(q, " -")) != NULL) {
            const char *r = q + 2;
            while (isalpha((unsigned char)*r)) r++;
            if (r > q + 2 && r[-1] == 'R') {
                if (*r == ' ') r++;
                if (isdigit((unsigned char)*r)) {
                    while (isdigit((unsigned char)*r)) r++;
                    if (*r == ':') return 1;
                }
            }
            q += 2;
        }
        s += 3;
    }
    return 0;
}

static int has_R_wildcard(const char *line)
{
    const char *s = line;
    while ((s = strstr(s, "*:0:localhost:22")) != NULL) {
        const char *q = s;
        if (q > line && q[-1] == '\'') q--;
        if (q > line && q[-1] == ' ') q--;
        if (q - line >= 2 && q[-2] == '-' && q[-1] == 'R') return 1;
        s++;
    }
    return 0;
}

static int has_stk_name(const char *line)
{
    const char *s = line;
    while ((s = strstr(s, ".stk_")) != NULL) {
        int i, okh = 1;
        for (i = 0; i < 10; i++) if (!isxdigit((unsigned char)s[5 + i]) || isupper((unsigned char)s[5 + i])) { okh = 0; break; }
        if (okh) return 1;
        s++;
    }
    return 0;
}

static void col_procs(const char *line, void *ud)
{
    if (strstr(line, "grep")) return;
    if (strstr(line, C2_IP) || has_ssh_R_port(line) || has_R_wildcard(line) || strstr(line, ".config/.smt") ||
        has_stk_name(line))
        buf_line(&((Collect *)ud)->out, line);
}

static void section5(void)
{
    Collect c = {{0}, NULL, 0, NULL};
    puts("");
    progress(4);
    puts("== 5. Running processes (reverse tunnels) ==");
    if (g_is_win) {
        run_lines("powershell -NoProfile -Command \"Get-CimInstance Win32_Process | Select-Object -ExpandProperty CommandLine\"",
                  60, col_procs, &c);
    } else if (!run_lines("ps -axww -o pid,user,args", 20, col_procs, &c) || !c.out.n) {
        buf_free(&c.out);
        run_lines("ps -ef", 20, col_procs, &c);
    }
    if (c.out.n) {
        warn("Suspicious process(es):");
        print_lines(c.out.p, 1000, 1000);
    } else ok("No suspicious ssh tunnel processes.");
    buf_free(&c.out);
}

/* ------------------------------------------------------------ section 6 */

static void section6(void)
{
    Collect c = {{0}, NULL, 0, NULL};
    int tried = 1;
    puts("");
    progress(5);
    puts("== 6. Network connections ==");
    if (g_is_bsd || g_is_mac) {
        run_lines("sockstat -c", 20, col_c2, &c);
        run_lines("netstat -an -p tcp", 20, col_c2, &c);
        run_lines("lsof -nP -i", 30, col_c2, &c);
    } else if (g_is_win) run_lines("netstat -ano", 20, col_c2, &c);
    else if (have("ss")) run_lines("ss -tnp", 20, col_c2, &c);
    else if (have("netstat")) run_lines("netstat -tnp", 20, col_c2, &c);
    else tried = 0;
    if (!tried) note("Neither 'ss' (iproute2/iproute) nor 'netstat' available, connection check skipped.");
    else if (c.out.n) {
        warn("Active connection to %s", C2_IP);
        print_lines(c.out.p, 1000, 1000);
    } else ok("No active connection to %s.", C2_IP);
    buf_free(&c.out);
}

/* ------------------------------------------------------------ section 7 */

static void print_logins(const char *src_desc, Collect *c)
{
    if (c->out.n) {
        note("%s (verify they were you):", src_desc);
        print_lines(c->out.p, -5, 1000);
    }
}

static void section7(void)
{
    static const char *auth[] = {"/var/log/auth.log", "/var/log/secure"};
    char cmd[512], desc[512];
    int running = 0, i;
    Collect c;

    puts("");
    progress(6);
    puts("== 7. Local SSH service and recent logins ==");
    if (g_is_win) running = cmd_ok("sc query sshd | find \"RUNNING\"");
    else {
        running = cmd_ok("systemctl is-active --quiet ssh") || cmd_ok("systemctl is-active --quiet sshd") ||
                  cmd_ok("systemctl is-active --quiet ssh.socket");
        if (!running && g_is_bsd) running = cmd_ok("service sshd onestatus");
        if (!running && g_is_mac) {
            Collect l = {{0}, "com.openssh.sshd", 0, NULL};
            run_lines("launchctl print-disabled system", 20, col_needles, &l);
            if (l.out.n && (strstr(l.out.p, "=> enabled") || strstr(l.out.p, "=> false"))) running = 1;
            buf_free(&l.out);
        }
    }
    if (running && g_sshd_ok) ok("sshd is running (confirmed as intentional with --sshd-ok).");
    else if (running) note("sshd is running. Confirm this is intentional (rerun with --sshd-ok to accept it).");
    else ok("sshd not running.");

    if (have("journalctl")) {
        memset(&c, 0, sizeof c);
        snprintf(cmd, sizeof cmd, "journalctl _COMM=sshd --since \"%s\" --no-pager", SINCE_STR);
        run_lines(cmd, 0, col_login, &c);
        snprintf(desc, sizeof desc, "SSH logins since %s", SINCE_STR);
        print_logins(desc, &c);
        buf_free(&c.out);
    }
    if (g_is_mac && have("log")) {
        memset(&c, 0, sizeof c);
        snprintf(cmd, sizeof cmd, "log show --start \"%s\" --style compact --predicate "
                 "'process == \"sshd\" AND eventMessage CONTAINS \"Accepted\"'", SINCE_STR);
        run_lines(cmd, 120, col_login, &c);
        snprintf(desc, sizeof desc, "SSH logins since %s", SINCE_STR);
        print_logins(desc, &c);
        buf_free(&c.out);
    }
    memset(&c, 0, sizeof c);
    desc[0] = 0;
    for (i = 0; i < 2; i++) {
        if (!readable(auth[i]) || !file_exists(auth[i])) continue;
        file_lines(auth[i], col_login, &c);
        strncat(desc, " ", sizeof desc - strlen(desc) - 1);
        strncat(desc, auth[i], sizeof desc - strlen(desc) - 1);
    }
    if (c.out.n) {
        char d2[600];
        snprintf(d2, sizeof d2, "Recent SSH logins in%s", desc);
        print_logins(d2, &c);
    }
    buf_free(&c.out);
}

/* ------------------------------------------------------------ section 8 */

static int in_order(const char *line, const char *a, const char *b)
{
    const char *x = strstr(line, a);
    return x && strstr(x + strlen(a), b);
}

static int is_benign_log(const char *l)
{
    static const char *words = "grep|egrep|fgrep|zgrep|rg|ag|journalctl|ausearch|less|cat|tail|head|"
                               "claude-code-backdoor-hunter|check_claude_code_backdoor";
    const char *cmd = strstr(l, "COMMAND=");
    if (cmd) {
        char tok[PATH_MAX];
        size_t n;
        cmd += 8;
        n = strcspn(cmd, " ");
        if (n >= sizeof tok) n = sizeof tok - 1;
        memcpy(tok, cmd, n);
        tok[n] = 0;
        if (needle_match(basename_of(tok), words, 1)) return 1;
    }
    return strstr(l, "Failed to load URL") || strstr(l, "syndicatedsearch.goog") || strstr(l, "net::ERR_");
}

static int is_strong_log(const char *l)
{
    static const char *kw[] = {"Accepted", "Connection from", "Connection closed", "Failed", "Invalid user",
                               "Disconnected from"};
    char t[64];
    size_t i;
    if (in_order(l, "sshd", C2_IP) || in_order(l, C2_IP, "sshd")) {
        const char *s = strstr(l, "sshd");
        for (i = 0; s && i < sizeof kw / sizeof kw[0]; i++) {
            const char *k = strstr(s, kw[i]);
            if (k && strstr(k, C2_IP)) return 1;
        }
        if (strstr(l, C2_IP) < strstr(l, "sshd") || in_order(l, C2_IP, "sshd")) return 1;
    }
    snprintf(t, sizeof t, "SRC=%s", C2_IP); if (strstr(l, t)) return 1;
    snprintf(t, sizeof t, "DST=%s", C2_IP); if (strstr(l, t)) return 1;
    snprintf(t, sizeof t, "tunnel@%s", C2_IP); if (strstr(l, t)) return 1;
    return has_R_wildcard(l) || strstr(l, ".config/.smt") != NULL;
}

static void triage(const char *src, const Buf *all)
{
    Buf rest = {0}, strong = {0};
    int ign = 0;
    const char *s = all->p ? all->p : "";
    if (!all->n) { ok("No mentions of %s in %s.", C2_IP, src); return; }
    while (*s) {
        size_t n = strcspn(s, "\n");
        char *line = strndup(s, n);
        if (is_benign_log(line)) ign++;
        else {
            buf_line(&rest, line);
            if (is_strong_log(line)) buf_line(&strong, line);
        }
        free(line);
        s += n;
        if (*s) s++;
    }
    if (strong.n) {
        warn("Log entries in %s show activity involving %s:", src, C2_IP);
        print_lines(strong.p, 5, 220);
    } else if (rest.n) {
        note("Log entries in %s mention %s but show no connection activity, review:", src, C2_IP);
        print_lines(rest.p, 5, 220);
    } else {
        ok("No contact with %s in %s (%d line(s) were only searches for it or browser URL errors).", C2_IP, src, ign);
    }
    buf_free(&rest);
    buf_free(&strong);
}

static void section8(void)
{
    static const char *logs[] = {"/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages",
                                 "/var/log/kern.log", "/var/log/system.log"};
    Collect c = {{0}, NULL, 0, NULL};
    char cmd[512], src[1024];
    int i, any = 0;

    puts("");
    progress(7);
    puts("== 8. System logs for the C2 IP ==");
    if (have("journalctl")) {
        snprintf(cmd, sizeof cmd, "journalctl --since \"%s\" --no-pager", SINCE_STR);
        run_lines(cmd, 0, col_c2, &c);
        snprintf(src, sizeof src, "the system journal since %s", SINCE_STR);
        triage(src, &c.out);
    } else if (g_is_mac && have("log")) {
        snprintf(cmd, sizeof cmd, "log show --start \"%s\" --style compact --predicate "
                 "'eventMessage CONTAINS \"%s\"'", SINCE_STR, C2_IP);
        run_lines(cmd, 180, col_c2, &c);
        snprintf(src, sizeof src, "the unified log since %s", SINCE_STR);
        triage(src, &c.out);
    } else if (g_is_win) {
        puts("    (Windows event logs are not scanned, relying on the checks above)");
    } else {
        puts("    (journalctl not available, relying on classic log files)");
    }
    buf_free(&c.out);

    memset(&c, 0, sizeof c);
    src[0] = 0;
    for (i = 0; i < 6; i++) {
        if (!readable(logs[i]) || !file_exists(logs[i])) continue;
        any = 1;
        file_lines(logs[i], col_c2, &c);
        strncat(src, " ", sizeof src - strlen(src) - 1);
        strncat(src, logs[i], sizeof src - strlen(src) - 1);
    }
    if (any) triage(src, &c.out);
    else if (!g_is_mac && !g_is_win) note("No readable classic log files (run with sudo for a complete check).");
    buf_free(&c.out);
}

/* ------------------------------------------------------------ OS detection */

static void os_release_value(const char *key, char *out, size_t n)
{
    FILE *f = fopen("/etc/os-release", "r");
    Buf b = {0};
    size_t kl = strlen(key);
    out[0] = 0;
    if (!f) return;
    while (read_line(f, &b)) {
        if (!strncmp(b.p, key, kl) && b.p[kl] == '=') {
            const char *v = b.p + kl + 1;
            size_t l;
            if (*v == '"' || *v == '\'') v++;
            snprintf(out, n, "%s", v);
            l = strlen(out);
            if (l && (out[l - 1] == '"' || out[l - 1] == '\'')) out[l - 1] = 0;
            break;
        }
    }
    fclose(f);
    buf_free(&b);
}

#if defined(__APPLE__) || defined(__FreeBSD__)
static void first_line(const char *cmd, char *out, size_t n)
{
    Collect c = {{0}, NULL, 0, NULL};
    out[0] = 0;
    run_lines(cmd, 10, col_all, &c);
    if (c.out.n) { snprintf(out, n, "%.*s", (int)strcspn(c.out.p, "\n"), c.out.p); }
    buf_free(&c.out);
}
#endif

static void detect_os(void)
{
#if defined(_WIN32)
    g_is_win = 1;
    puts("Detected: Windows (family: windows)");
#elif defined(__APPLE__)
    char v[64];
    g_is_mac = 1;
    first_line("sw_vers -productVersion", v, sizeof v);
    if (atoi(v) < 12) printf("[?] macOS %s is older than the supported macOS 12+.\n", v);
    printf("Detected: macOS %s (family: macos)\n", v);
#elif defined(__FreeBSD__)
    char v[64];
    g_is_bsd = 1;
    first_line("freebsd-version -u", v, sizeof v);
    if (atoi(v) < 14) printf("[?] FreeBSD %s is older than the supported FreeBSD 14+.\n", v);
    printf("Detected: FreeBSD %s (family: freebsd)\n", v);
#else
    char id[64], like[128], ver[64], pretty[128], ids[256];
    const char *family = "other";
    int major;
    os_release_value("ID", id, sizeof id);
    os_release_value("ID_LIKE", like, sizeof like);
    os_release_value("VERSION_ID", ver, sizeof ver);
    os_release_value("PRETTY_NAME", pretty, sizeof pretty);
    major = atoi(ver);
    snprintf(ids, sizeof ids, " %s %s ", id, like);
    if (strstr(ids, " debian ") || strstr(ids, " ubuntu ")) {
        family = "debian";
        if (!strcmp(id, "debian") && major < 12) printf("[?] Debian %s is older than the supported Debian 12+.\n", ver);
        if (!strcmp(id, "ubuntu") && major < 24) printf("[?] Ubuntu %s is older than the supported Ubuntu 24.04+.\n", ver);
    } else if (strstr(ids, " rhel ") || strstr(ids, " fedora ") || strstr(ids, " centos ")) {
        family = "rhel";
        if (strcmp(id, "fedora") && major < 9)
            printf("[?] %s is older than the supported RHEL 9+.\n", pretty[0] ? pretty : "RHEL-family");
    }
    if (id[0]) printf("Detected: %s (family: %s)\n", pretty[0] ? pretty : "unknown", family);
#endif
}

/* ------------------------------------------------------------ main */

int main(int argc, char **argv)
{
    struct tm tm;
    const char *h;
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--sshd-ok")) g_sshd_ok = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            puts("Usage: claude-code-backdoor-hunter [--sshd-ok]\n"
                 "  --sshd-ok   treat a running sshd as intentional (no review item)\n"
                 "Exit codes: 0 = no indicators, 1 = indicators found, 2 = items need review.");
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s (try --help)\n", argv[i]);
            return 3;
        }
    }
    setvbuf(stdout, NULL, _IOLBF, 0);

    memset(&tm, 0, sizeof tm);
    tm.tm_year = 2026 - 1900; tm.tm_mon = 9; tm.tm_mday = 29; tm.tm_isdst = -1;
    g_since = mktime(&tm);

    h = getenv("HOME");
    if (!h || !*h) h = getenv("USERPROFILE");
    snprintf(g_home, sizeof g_home, "%s", h ? h : ".");
    {
        size_t l = strlen(g_home);
        while (l > 1 && (g_home[l - 1] == '/' || g_home[l - 1] == '\\')) g_home[--l] = 0;
    }
    if (!PLATFORM_WIN) {
        if (have("timeout")) snprintf(g_tmo, sizeof g_tmo, "timeout");
        else if (have("gtimeout")) snprintf(g_tmo, sizeof g_tmo, "gtimeout");
    }

    detect_os();

    progress(0);
    section1();
    puts("");
    progress(1);
    section2();
    section3();
    section4();
    section5();
    section6();
    section7();
    section8();

    puts("");
    progress(8);
    puts("");
    if (g_found) {
        puts("RESULT: indicators of compromise found. Isolate the machine, remove the key/persistence, rotate credentials.");
        return 1;
    }
    if (g_review) {
        puts("RESULT: no definite indicators, but [?] items need manual review.");
        return 2;
    }
    puts("RESULT: no indicators found.");
    return 0;
}

