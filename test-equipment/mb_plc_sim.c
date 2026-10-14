/* mb_plc_sim.c -- the SIMULATED PLC for the lovelace-mb W4 demo (TEST FIXTURE, never product; R-MB-1).
 *
 * libmodbus a9b025d (v3.2.0, LGPL-2.1) is linked UNMODIFIED from the oracle's objects and used through its
 * PUBLIC API only (modbus_new_tcp, modbus_tcp_listen/accept, modbus_set_socket, modbus_receive, modbus_reply,
 * modbus_mapping_new_start_address). Nothing of libmodbus is copied here.
 *
 * The plant is the R-MB-19 map, unit id 1:
 *   coils 0..2          0 intake pump RUN, 1 inlet valve OPEN, 2 backwash valve
 *   discrete inputs 0..3  0 pump running, 1 valve open, 2 low level, 3 high level   (mirrored from coils 0/1)
 *   holding 100..119    100 chlorine setpoint (0.01 mg/L), 101 flow setpoint m3/h, 102 pH alarm x100, 110..119 spare
 *   input 0..3          0 measured flow (200 while the pump runs, 0 when stopped), 1 chlorine residual,
 *                       2 turbidity, 3 tank level
 * The sim itself enforces NOTHING beyond libmodbus's own map bounds: it is the plant the gateway protects.
 *
 * Usage: mb_plc_sim [--port N] [--host A] [--log FILE] [--max-requests N] [--once] [--quiet]
 *   --log FILE       append one TAB line per WRITE request received (fc 5,6,15,16,22,23); see FIXTURES-NOTES.txt
 *   --max-requests N exit after N requests have been served (0 = no limit)
 *   --once           exit when the first connection closes
 * Several connections are served concurrently (poll); each request is answered in full before the next.
 * SIGTERM / SIGINT: clean exit (closes sockets, frees the map, prints a one-line summary to stderr).
 */
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include <modbus.h>

#define MAX_CLIENTS 16

static volatile sig_atomic_t stop_flag = 0;

static void on_signal(int sig) { (void)sig; stop_flag = 1; }

static long long now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void plant_initial(modbus_mapping_t *m)
{
    m->tab_bits[0] = 1;                  /* pump running */
    m->tab_bits[1] = 1;                  /* inlet valve open */
    m->tab_bits[2] = 0;                  /* backwash valve shut */
    m->tab_input_bits[2] = 0;            /* low level */
    m->tab_input_bits[3] = 0;            /* high level */
    m->tab_registers[0] = 50;            /* 100: chlorine setpoint 0.50 mg/L */
    m->tab_registers[1] = 200;           /* 101: flow setpoint 200 m3/h */
    m->tab_registers[2] = 850;           /* 102: pH alarm threshold 8.50 */
    m->tab_input_registers[1] = 45;      /* chlorine residual 0.45 mg/L */
    m->tab_input_registers[2] = 12;      /* turbidity 0.12 NTU */
    m->tab_input_registers[3] = 650;     /* tank level 65.0 % */
}

/* The plant reacts: the status inputs follow the coils, the flow follows the pump. */
static void plant_react(modbus_mapping_t *m)
{
    m->tab_input_bits[0] = m->tab_bits[0];
    m->tab_input_bits[1] = m->tab_bits[1];
    m->tab_input_registers[0] = m->tab_bits[0] ? 200 : 0;
}

static unsigned be16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }

/* Is the write inside the sim's map (the only bounds the sim has)? Used only to label the log line. */
static int in_map(int fc, unsigned addr, unsigned nb)
{
    switch (fc) {
    case 5: case 15: return nb >= 1 && addr + nb <= 3;
    case 6: case 16: case 22: case 23: return nb >= 1 && addr >= 100 && addr + nb <= 120;
    default: return 0;
    }
}

/* Append one line per write request received. Columns (TAB): ms conn tid unit fc addr values result
 * values: decimal, comma separated; FC5 coil 1/0 (raw 0xNNNN if neither FF00 nor 0000); FC15 one 0/1 per coil;
 * FC22 "and=0xAAAA,or=0xOOOO"; FC23 the write part. result: exec (inside the sim's map) or outside-map. */
static void log_write(FILE *lf, int conn, const uint8_t *q, int len)
{
    if (len < 8) return;
    unsigned tid = be16(q), unit = q[6];
    int fc = q[7];
    if (fc != 5 && fc != 6 && fc != 15 && fc != 16 && fc != 22 && fc != 23) return;
    char vals[2048] = "";
    size_t vl = 0;
    unsigned addr = len >= 10 ? be16(q + 8) : 0, nb = 1;
    if ((fc == 5 || fc == 6) && len >= 12) {
        unsigned v = be16(q + 10);
        if (fc == 5 && v == 0xFF00) vl += snprintf(vals, sizeof vals, "1");
        else if (fc == 5 && v == 0) vl += snprintf(vals, sizeof vals, "0");
        else if (fc == 5) vl += snprintf(vals, sizeof vals, "0x%04x", v);
        else vl += snprintf(vals, sizeof vals, "%u", v);
    } else if (fc == 15 && len >= 13) {
        nb = be16(q + 10);
        for (unsigned i = 0; i < nb && 13 + (int)(i / 8) < len && vl + 3 < sizeof vals; i++)
            vl += snprintf(vals + vl, sizeof vals - vl, "%s%d", i ? "," : "", (q[13 + i / 8] >> (i % 8)) & 1);
    } else if (fc == 16 && len >= 13) {
        nb = be16(q + 10);
        for (unsigned i = 0; i < nb && 14 + 2 * (int)i < len && vl + 8 < sizeof vals; i++)
            vl += snprintf(vals + vl, sizeof vals - vl, "%s%u", i ? "," : "", be16(q + 13 + 2 * i));
    } else if (fc == 22 && len >= 14) {
        vl += snprintf(vals, sizeof vals, "and=0x%04x,or=0x%04x", be16(q + 10), be16(q + 12));
    } else if (fc == 23 && len >= 17) {
        addr = be16(q + 12);
        nb = be16(q + 14);
        for (unsigned i = 0; i < nb && 18 + 2 * (int)i < len && vl + 8 < sizeof vals; i++)
            vl += snprintf(vals + vl, sizeof vals - vl, "%s%u", i ? "," : "", be16(q + 17 + 2 * i));
    }
    if (vl == 0) snprintf(vals, sizeof vals, "-");
    fprintf(lf, "%lld\t%d\t%u\t%u\t%d\t%u\t%s\t%s\n", now_ms(), conn, tid, unit, fc, addr, vals,
            in_map(fc, addr, nb) ? "exec" : "outside-map");
    fflush(lf);
}

int main(int argc, char **argv)
{
    const char *host = "127.0.0.1", *logpath = NULL;
    int port = 1502, quiet = 0, once = 0;
    long max_requests = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--host") && i + 1 < argc) host = argv[++i];
        else if (!strcmp(argv[i], "--log") && i + 1 < argc) logpath = argv[++i];
        else if (!strcmp(argv[i], "--max-requests") && i + 1 < argc) max_requests = atol(argv[++i]);
        else if (!strcmp(argv[i], "--once")) once = 1;
        else if (!strcmp(argv[i], "--quiet")) quiet = 1;
        else {
            fprintf(stderr, "usage: %s [--port N] [--host A] [--log FILE] [--max-requests N] [--once] [--quiet]\n", argv[0]);
            return 2;
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;            /* no SA_RESTART: poll returns EINTR */
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    FILE *lf = NULL;
    if (logpath && !(lf = fopen(logpath, "a"))) {
        fprintf(stderr, "plc-sim: cannot open log %s: %s\n", logpath, strerror(errno));
        return 1;
    }

    modbus_t *ctx = modbus_new_tcp(host, port);
    modbus_mapping_t *map = modbus_mapping_new_start_address(0, 3, 0, 4, 100, 20, 0, 4);
    if (!ctx || !map) {
        fprintf(stderr, "plc-sim: init failed: %s\n", modbus_strerror(errno));
        return 1;
    }
    plant_initial(map);
    plant_react(map);
    /* a frame already started must complete within the byte timeout; an idle wait is never made inside libmodbus
       (poll below calls modbus_receive only when bytes are ready) */
    modbus_set_byte_timeout(ctx, 0, 500000);

    int ls = modbus_tcp_listen(ctx, 8);
    if (ls < 0) {
        fprintf(stderr, "plc-sim: listen %s:%d failed: %s\n", host, port, modbus_strerror(errno));
        return 1;
    }
    if (!quiet) fprintf(stderr, "plc-sim: listening on %s:%d unit 1 (R-MB-19 map)\n", host, port);

    int cl[MAX_CLIENTS], cid[MAX_CLIENTS], ncl = 0, next_conn = 1, rc_exit = 0;
    long served = 0, writes = 0;
    uint8_t q[MODBUS_TCP_MAX_ADU_LENGTH];

    while (!stop_flag) {
        struct pollfd pf[MAX_CLIENTS + 1];
        pf[0].fd = ls; pf[0].events = POLLIN; pf[0].revents = 0;
        for (int i = 0; i < ncl; i++) { pf[i + 1].fd = cl[i]; pf[i + 1].events = POLLIN; pf[i + 1].revents = 0; }
        int pr = poll(pf, (nfds_t)ncl + 1, 500);
        if (pr < 0) { if (errno == EINTR) continue; perror("plc-sim: poll"); rc_exit = 1; break; }
        if (pr == 0) continue;

        int nold = ncl;
        if ((pf[0].revents & POLLIN) && ncl < MAX_CLIENTS) {
            int s = ls;
            int fd = modbus_tcp_accept(ctx, &s);
            if (fd >= 0) {
                cl[ncl] = fd; cid[ncl] = next_conn++; ncl++;
                if (!quiet) fprintf(stderr, "plc-sim: conn %d open\n", cid[ncl - 1]);
            }
        }
        for (int i = nold - 1; i >= 0; i--) {
            if (!(pf[i + 1].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            modbus_set_socket(ctx, cl[i]);
            int n = modbus_receive(ctx, q);
            if (n > 0) {
                if (lf) log_write(lf, cid[i], q, n);
                if (q[7] == 5 || q[7] == 6 || q[7] == 15 || q[7] == 16 || q[7] == 22 || q[7] == 23) writes++;
                if (modbus_reply(ctx, q, n, map) >= 0) plant_react(map);
                served++;
                if (max_requests > 0 && served >= max_requests) stop_flag = 1;
                continue;
            }
            if (n == 0) continue;     /* not for us (RTU only); never on TCP */
            if (!quiet) fprintf(stderr, "plc-sim: conn %d closed (%s)\n", cid[i], modbus_strerror(errno));
            close(cl[i]);
            cl[i] = cl[ncl - 1]; cid[i] = cid[ncl - 1]; ncl--;
            if (once) stop_flag = 1;
        }
    }

    for (int i = 0; i < ncl; i++) close(cl[i]);
    close(ls);
    modbus_set_socket(ctx, -1);
    modbus_free(ctx);
    if (!quiet)
        fprintf(stderr, "plc-sim: exit: served %ld requests, %ld write requests; coils %d%d%d hr100..102 %u %u %u\n",
                served, writes, map->tab_bits[0], map->tab_bits[1], map->tab_bits[2],
                map->tab_registers[0], map->tab_registers[1], map->tab_registers[2]);
    modbus_mapping_free(map);
    if (lf) fclose(lf);
    return rc_exit;
}
