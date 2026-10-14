/* mb_demo_master.c -- the SCRIPTED MASTER for the lovelace-mb W4 demo (TEST FIXTURE, never product; R-MB-1).
 *
 * Reads a script (default demo/script.txt), sends each step to the gateway and writes a transcript TSV of what came
 * back. Library steps go through libmodbus's PUBLIC client API (linked unmodified, unit id 1); RAW steps are sent
 * on a plain TCP socket, so the bytes on the wire are exactly the script's hex.
 * Every step uses a FRESH TCP connection (slot identity is peer address + gateway port, R-MB-20, so gate state
 * such as the rate window and the sequence rule does not depend on the connection).
 *
 * Usage: mb_demo_master [--script FILE] [--out FILE.tsv] [--timeout-ms N] [--direct PORT] [--no-pause] HOST
 *   HOST         the gateway address (127.0.0.1 for the demo); each step's port comes from the script
 *   --direct P   self-test: send EVERY step to HOST:P (the plc-sim), ignoring the script's port and expectations
 *   --timeout-ms no reply within N ms -> "silent" (default 2000; the gateway's own PLC timeout is 1000 ms, R-MB-14)
 *   --no-pause   skip "sleep" steps (self-test speed-up)
 * Exit 0 when every step ran (whatever it got back); 1 on a script or I/O error. Judging is demo-check.bb's job.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <modbus.h>

#define MAXV 130

static long long now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\n' || e[-1] == '\r')) *--e = 0;
    return s;
}

static int parse_list(const char *s, long *v, int max)
{
    int n = 0;
    char buf[1024];
    snprintf(buf, sizeof buf, "%s", s);
    for (char *t = strtok(buf, ","); t && n < max; t = strtok(NULL, ",")) v[n++] = strtol(trim(t), NULL, 0);
    return n;
}

static int parse_hex(const char *s, uint8_t *out, int max)
{
    int n = 0, hi = -1;
    for (; *s; s++) {
        int d;
        if (*s >= '0' && *s <= '9') d = *s - '0';
        else if (*s >= 'a' && *s <= 'f') d = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F') d = *s - 'A' + 10;
        else if (*s == ' ' || *s == '\t') continue;
        else return -1;
        if (hi < 0) hi = d;
        else { if (n >= max) return -1; out[n++] = (uint8_t)(hi * 16 + d); hi = -1; }
    }
    return hi < 0 ? n : -1;
}

static void hex_of(const uint8_t *b, int n, char *out, size_t cap)
{
    size_t o = 0;
    if (n <= 0) { snprintf(out, cap, "-"); return; }
    for (int i = 0; i < n && o + 3 < cap; i++) o += snprintf(out + o, cap - o, "%02x", b[i]);
}

/* outcome text for a libmodbus error: exc NN for a Modbus exception, silent for no reply, else error <name> */
static void lib_error(int err, char *outcome, size_t cap, const char **closed)
{
    if (err > MODBUS_ENOBASE && err <= EMBXGTAR) {
        snprintf(outcome, cap, "exc %02d", err - MODBUS_ENOBASE);
        *closed = "no";
    } else if (err == ETIMEDOUT) {
        snprintf(outcome, cap, "silent");
        *closed = "no";
    } else if (err == ECONNRESET || err == EPIPE || err == ENOTCONN) {
        snprintf(outcome, cap, "silent");
        *closed = "yes";
    } else {
        snprintf(outcome, cap, "error %s", modbus_strerror(err));
        *closed = "?";
    }
}

/* RAW step: connect, write exactly the bytes, read until a whole MBAP ADU, close, or timeout. */
static void run_raw(const char *host, int port, const uint8_t *adu, int n, int timeout_ms,
                    char *outcome, size_t cap, const char **closed, char *reply_hex, size_t rcap)
{
    *closed = "?";
    snprintf(reply_hex, rcap, "-");
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (fd < 0 || inet_pton(AF_INET, host, &a.sin_addr) != 1 || connect(fd, (struct sockaddr *)&a, sizeof a) < 0) {
        snprintf(outcome, cap, "noconnect");
        if (fd >= 0) close(fd);
        return;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (write(fd, adu, (size_t)n) != n) {
        snprintf(outcome, cap, "error write");
        close(fd);
        return;
    }
    uint8_t r[300];
    int got = 0;
    long long deadline = now_ms() + timeout_ms;
    int eof = 0;
    for (;;) {
        if (got >= 6 && got >= 6 + ((r[4] << 8) | r[5])) break;    /* a whole ADU */
        long long left = deadline - now_ms();
        if (left <= 0) break;
        struct pollfd p = { fd, POLLIN, 0 };
        int pr = poll(&p, 1, (int)left);
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) break;
        ssize_t k = read(fd, r + got, sizeof r - (size_t)got);
        if (k <= 0) { eof = 1; break; }
        got += (int)k;
        if (got == (int)sizeof r) break;
    }
    if (!eof) {     /* did the peer close right after (or instead of) its reply? a short look */
        struct pollfd p = { fd, POLLIN, 0 };
        if (poll(&p, 1, 50) > 0) {
            uint8_t extra[16];
            if (read(fd, extra, sizeof extra) == 0) eof = 1;
        }
    }
    *closed = eof ? "yes" : "no";
    hex_of(r, got, reply_hex, rcap);
    if (got == 0) snprintf(outcome, cap, "silent");
    else if (got >= 9 && (r[7] & 0x80)) snprintf(outcome, cap, "exc %02d", r[8]);
    else if (got >= 8) snprintf(outcome, cap, "ok");
    else snprintf(outcome, cap, "partial");
    close(fd);
}

/* library step: one libmodbus client call on a fresh context */
static void run_lib(const char *host, int port, const char *verb, char **arg, int nargs, int timeout_ms,
                    char *outcome, size_t cap, const char **closed)
{
    *closed = "no";
    modbus_t *ctx = modbus_new_tcp(host, port);
    if (!ctx) { snprintf(outcome, cap, "error new"); return; }
    modbus_set_slave(ctx, 1);
    modbus_set_response_timeout(ctx, (uint32_t)(timeout_ms / 1000), (uint32_t)(timeout_ms % 1000) * 1000);
    if (modbus_connect(ctx) < 0) {
        snprintf(outcome, cap, "noconnect");
        modbus_free(ctx);
        return;
    }
    long a = nargs > 0 ? strtol(arg[0], NULL, 0) : 0;
    long b = nargs > 1 ? strtol(arg[1], NULL, 0) : 0;
    uint8_t bits[2048];
    uint16_t regs[MAXV];
    long lv[MAXV];
    int rc = -1, kind = 0;   /* kind: 0 write, 1 bits, 2 regs */
    errno = 0;
    if (!strcmp(verb, "rb") && nargs == 2 && b <= 2000) { rc = modbus_read_bits(ctx, (int)a, (int)b, bits); kind = 1; }
    else if (!strcmp(verb, "rib") && nargs == 2 && b <= 2000) { rc = modbus_read_input_bits(ctx, (int)a, (int)b, bits); kind = 1; }
    else if (!strcmp(verb, "rr") && nargs == 2 && b <= 125) { rc = modbus_read_registers(ctx, (int)a, (int)b, regs); kind = 2; }
    else if (!strcmp(verb, "rir") && nargs == 2 && b <= 125) { rc = modbus_read_input_registers(ctx, (int)a, (int)b, regs); kind = 2; }
    else if (!strcmp(verb, "wb") && nargs == 2) rc = modbus_write_bit(ctx, (int)a, (int)b);
    else if (!strcmp(verb, "wr") && nargs == 2) rc = modbus_write_register(ctx, (int)a, (uint16_t)b);
    else if (!strcmp(verb, "wbs") && nargs == 2) {
        int n = parse_list(arg[1], lv, MAXV);
        for (int i = 0; i < n; i++) bits[i] = lv[i] ? 1 : 0;
        rc = modbus_write_bits(ctx, (int)a, n, bits);
    } else if (!strcmp(verb, "wrs") && nargs == 2) {
        int n = parse_list(arg[1], lv, MAXV);
        for (int i = 0; i < n; i++) regs[i] = (uint16_t)lv[i];
        rc = modbus_write_registers(ctx, (int)a, n, regs);
    } else if (!strcmp(verb, "mwr") && nargs == 3) {
        rc = modbus_mask_write_register(ctx, (int)a, (uint16_t)b, (uint16_t)strtol(arg[2], NULL, 0));
    } else {
        snprintf(outcome, cap, "error badstep");
        modbus_close(ctx);
        modbus_free(ctx);
        return;
    }
    int err = errno;
    if (rc < 0) {
        lib_error(err, outcome, cap, closed);
    } else if (kind == 0) {
        snprintf(outcome, cap, "ok");
    } else {
        size_t o = (size_t)snprintf(outcome, cap, "ok ");
        for (int i = 0; i < rc && o + 8 < cap; i++)
            o += (size_t)snprintf(outcome + o, cap - o, "%s%u", i ? "," : "", kind == 1 ? bits[i] : regs[i]);
    }
    modbus_close(ctx);
    modbus_free(ctx);
}

int main(int argc, char **argv)
{
    const char *script = "demo/script.txt", *outp = "demo/transcript.tsv", *host = NULL;
    int timeout_ms = 2000, direct = 0, no_pause = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--script") && i + 1 < argc) script = argv[++i];
        else if (!strcmp(argv[i], "--out") && i + 1 < argc) outp = argv[++i];
        else if (!strcmp(argv[i], "--timeout-ms") && i + 1 < argc) timeout_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--direct") && i + 1 < argc) direct = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--no-pause")) no_pause = 1;
        else if (argv[i][0] != '-' && !host) host = argv[i];
        else { host = NULL; break; }
    }
    if (!host) {
        fprintf(stderr, "usage: %s [--script F] [--out F.tsv] [--timeout-ms N] [--direct PORT] [--no-pause] HOST\n", argv[0]);
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    FILE *sf = fopen(script, "r");
    if (!sf) { fprintf(stderr, "master: cannot open script %s: %s\n", script, strerror(errno)); return 1; }
    FILE *tf = fopen(outp, "w");
    if (!tf) { fprintf(stderr, "master: cannot write %s: %s\n", outp, strerror(errno)); fclose(sf); return 1; }
    fprintf(tf, "step\tport\trequest\texpect\toutcome\tclosed\treply_hex\tms\n");
    if (direct) fprintf(stderr, "master: DIRECT self-test to %s:%d -- no gateway, expectations ignored\n", host, direct);

    char line[2048];
    int lineno = 0, steps = 0, rc_exit = 0;
    while (fgets(line, sizeof line, sf)) {
        lineno++;
        char *l = trim(line);
        if (!*l || *l == '#') continue;
        char *f[4];
        int nf = 0;
        for (char *p = l; nf < 4;) {
            char *bar = strchr(p, '|');
            f[nf++] = p;
            if (!bar) break;
            *bar = 0;
            p = bar + 1;
        }
        if (nf != 4) { fprintf(stderr, "master: %s:%d: need 4 fields name|port|request|expect\n", script, lineno); rc_exit = 1; break; }
        for (int i = 0; i < 4; i++) f[i] = trim(f[i]);
        char *name = f[0], *req = f[2], *expect = f[3];
        int port = direct ? direct : atoi(f[1]);

        char reqcopy[1024], outcome[1024], reply_hex[700];
        const char *closed = "-";
        snprintf(reqcopy, sizeof reqcopy, "%s", req);
        snprintf(reply_hex, sizeof reply_hex, "-");
        char *verb = strtok(reqcopy, " \t");
        long long t0 = now_ms();
        if (!verb) { fprintf(stderr, "master: %s:%d: empty request\n", script, lineno); rc_exit = 1; break; }
        if (!strcmp(verb, "sleep")) {
            char *ms = strtok(NULL, " \t");
            long w = ms ? strtol(ms, NULL, 0) : 0;
            if (!no_pause && w > 0) usleep((useconds_t)(w * 1000));
            snprintf(outcome, sizeof outcome, no_pause ? "skipped" : "paused");
        } else if (!strcmp(verb, "raw")) {
            uint8_t adu[300];
            int n = parse_hex(req + 3, adu, (int)sizeof adu);
            if (n < 1) { fprintf(stderr, "master: %s:%d: bad raw hex\n", script, lineno); rc_exit = 1; break; }
            run_raw(host, port, adu, n, timeout_ms, outcome, sizeof outcome, &closed, reply_hex, sizeof reply_hex);
        } else {
            char *arg[4];
            int nargs = 0;
            for (char *t = strtok(NULL, " \t"); t && nargs < 4; t = strtok(NULL, " \t")) arg[nargs++] = t;
            run_lib(host, port, verb, arg, nargs, timeout_ms, outcome, sizeof outcome, &closed);
        }
        long long dt = now_ms() - t0;
        fprintf(tf, "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%lld\n", name, port, req, expect, outcome, closed,
                reply_hex, dt);
        fflush(tf);
        fprintf(stderr, "  %-28s %-5d %-44s -> %s\n", name, port, req, outcome);
        steps++;
    }
    fclose(sf);
    fclose(tf);
    fprintf(stderr, "master: %d steps, transcript %s\n", steps, outp);
    return rc_exit;
}
