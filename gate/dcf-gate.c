/* gate/dcf-gate.c -- the command-line host for the vendored dcf_net_gate unit.
 *
 * The unit (dcf_net_gate.gen.c, emitted by exsc from examples/dcf_net_gate in
 * the Exsecutor repository; see PROVENANCE.md) is the one definition of "an
 * IPv4 address", "a port" and "a sync interval" that DCF-ID and this watchdog
 * share. This file only feeds it bytes and acts on its verdicts. It does no
 * parsing of its own on the way in: every byte of a candidate goes to the gate
 * with an explicit length, never through a C string, so a NUL inside a value
 * is a rejected value and not a shorter, admitted one.
 *
 *   dcf-gate ipv4 [--hex] [--max N] [--report N]
 *       stdin: one candidate per line. With --hex a line is the candidate's
 *       bytes in hex (what sqlite's hex() prints), so a value that contains
 *       a newline, CR or NUL is still ONE candidate and is judged as such.
 *       stdout: the admitted addresses, canonical, one per line, first-seen
 *       order, de-duplicated, at most N (default 4096), written only once
 *       all of stdin has been read.
 *       stderr: a summary line and, if --report is given, a few rejected
 *       values, escaped. Every stderr line starts with "dcf-gate: ".
 *       Admitted classes: global (0), private (6), shared 100.64/10 (7).
 *       Refused: this-net, loopback, link-local, multicast, reserved.
 *       A final line with no terminating newline is refused: it may be a
 *       truncated one, and a prefix of an address is another address.
 *   dcf-gate port VALUE        exit 0 and echo VALUE if it is 1..65535
 *   dcf-gate interval VALUE    exit 0 and echo VALUE if it is 1..3600
 *   dcf-gate number VALUE      exit 0 and echo VALUE if it is a JSON integer of 1..20 digits
 *   dcf-gate load VALUE        exit 0 and echo VALUE if it is a load average (0.42, 12.5, 3)
 *                              (the last two: watchdawg_gate, for dcf-telemetry.sh's JSON)
 *   dcf-gate selftest          known vectors through the same code
 *
 * Exit: 0 ok, 1 value refused (port/interval/number/load/selftest), 2 usage, 3 I/O error,
 * 70 the gate trapped (exsrt_abortus). The gate is written not to trap; if it
 * ever does, this host fails closed.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dcf_net_gate.gen.h"
#include "watchdawg_gate.gen.h"

#define DEFAULT_MAX 4096u
#define LIMIT_MAX (1u << 20)

/* ------------------------------------------------------------------ trap */

_Noreturn void exsrt_abortus(unsigned kind)
{
  char m[96];
  int n = snprintf(m, sizeof m, "dcf-gate: the gate trapped (exsrt_abortus kind %u); failing closed\n", kind);
  if (n > 0) {
    ssize_t r = write(2, m, (size_t)n);
    (void)r;
  }
  _exit(70);
}

/* ------------------------------------------------------------ the gate */

/* The gate wants a buffer of exactly 16 (addresses) or 8 (numbers) readable
 * bytes and the true length separately. `head` holds the first up-to-16 bytes
 * of the candidate, zero padded; `n` is its full length. */
static uint64_t gate_ipv4(const unsigned char head[16], uint64_t n)
{
  unsigned char buf[16];
  memcpy(buf, head, 16);
  return exs_admitte_ipv4(buf, n);
}

static uint64_t gate_class(const unsigned char head[16], uint64_t n)
{
  unsigned char buf[16];
  memcpy(buf, head, 16);
  return exs_ordo_ipv4(buf, n);
}

/* which: 0 port, 1 interval (dcf_net_gate, 8-byte buffers); 2 number (20 bytes),
 * 3 load (16 bytes) (watchdawg_gate). */
static uint64_t gate_number(int which, const unsigned char *s, uint64_t n)
{
  /* one buffer per kind, exactly the size its gate reads */
  unsigned char b8[8] = {0}, b16[16] = {0}, b20[20] = {0};
  switch (which) {
  case 0: memcpy(b8, s, n < 8 ? (size_t)n : 8); return exs_admitte_portum(b8, n);
  case 1: memcpy(b8, s, n < 8 ? (size_t)n : 8); return exs_admitte_intervallum(b8, n);
  case 2: memcpy(b20, s, n < 20 ? (size_t)n : 20); return exs_admitte_numerum(b20, n);
  default: memcpy(b16, s, n < 16 ? (size_t)n : 16); return exs_admitte_onus(b16, n);
  }
}

/* ------------------------------------------------------------ ipv4 mode */

struct report {
  unsigned want, have;
  char lines[100][160];
};

struct state {
  uint32_t *ips;       /* admitted, first-seen order */
  uint32_t *table;     /* open-addressing membership, 0 = empty (0.0.0.0 is never admitted) */
  uint32_t mask;
  unsigned shift;      /* 32 - log2(table size): the multiplicative hash keeps the HIGH bits */
  uint32_t count, max;
  uint64_t read, rejected, duplicate, capped, unterminated;
  uint64_t by_reason[16];
  struct report rep;
};

static const char *const policy_name[] = {
  "empty", "too_long", "bad_byte", "not_four_octets", "octet_digits", "leading_zero", "octet_range",
  "this_network", "loopback", "link_local", "multicast", "reserved", "bad_hex", "unterminated"
};
enum { R_EMPTY, R_LONG, R_BYTE, R_OCTETS, R_DIGITS, R_ZERO, R_RANGE, R_THISNET, R_LOOP, R_LINK, R_MCAST, R_RESV, R_HEX, R_UNTERM, R_N };

static void sample(struct state *st, int reason, const unsigned char *head, uint64_t n)
{
  if (st->rep.have >= st->rep.want) return;
  char esc[16 * 4 + 1];
  size_t o = 0;
  size_t take = n < 16 ? (size_t)n : 16;
  for (size_t i = 0; i < take; i++) {
    unsigned char c = head[i];
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == ':' || c == '/' || c == '-' || c == '_')
      esc[o++] = (char)c;
    else
      o += (size_t)snprintf(esc + o, 5, "\\x%02x", c);
  }
  esc[o] = 0;
  snprintf(st->rep.lines[st->rep.have++], sizeof st->rep.lines[0],
           "dcf-gate: reject reason=%s len=%llu head=%s", policy_name[reason], (unsigned long long)n, esc);
}

static void reject(struct state *st, int reason, const unsigned char *head, uint64_t n)
{
  st->rejected++;
  st->by_reason[reason]++;
  sample(st, reason, head, n);
}

static int host_hex(int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* One complete candidate: head[0..16) zero padded, n bytes long. */
static void judge(struct state *st, const unsigned char head[16], uint64_t n)
{
  st->read++;
  uint64_t v = gate_ipv4(head, n);
  if (v != 0) {
    reject(st, (int)v - 1, head, n);          /* verdicts 1..7 -> R_EMPTY..R_RANGE */
    return;
  }
  uint64_t cls = gate_class(head, n);
  if (cls != 0 && cls != 6 && cls != 7) {
    reject(st, cls == 1 ? R_THISNET : cls == 2 ? R_LOOP : cls == 3 ? R_LINK : cls == 4 ? R_MCAST : R_RESV, head, n);
    return;
  }
  /* admitted by the gate: the text is a canonical dotted quad of at most 15 bytes */
  uint32_t a = 0, oct = 0;
  for (uint64_t i = 0; i < n; i++) {
    if (head[i] == '.') { a = (a << 8) | oct; oct = 0; }
    else oct = oct * 10 + (uint32_t)(head[i] - '0');
  }
  a = (a << 8) | oct;
  uint32_t h = (uint32_t)(a * 2654435761u) >> st->shift;
  while (st->table[h] != 0) {
    if (st->table[h] == a) { st->duplicate++; return; }
    h = (h + 1) & st->mask;
  }
  if (st->count >= st->max) { st->capped++; return; }
  st->table[h] = a;
  st->ips[st->count++] = a;
}

static int write_all(int fd, const char *p, size_t n)
{
  while (n > 0) {
    ssize_t w = write(fd, p, n);
    if (w < 0) { if (errno == EINTR) continue; return -1; }
    p += w; n -= (size_t)w;
  }
  return 0;
}

static int parse_count(const char *s, unsigned lo, unsigned hi, unsigned *out)
{
  if (!*s || strlen(s) > 7) return -1;
  unsigned long v = 0;
  for (; *s; s++) {
    if (*s < '0' || *s > '9') return -1;
    v = v * 10 + (unsigned long)(*s - '0');
  }
  if (v < lo || v > hi) return -1;
  *out = (unsigned)v;
  return 0;
}

static int mode_ipv4(int argc, char **argv)
{
  int hex = 0;
  unsigned max = DEFAULT_MAX, want = 0;
  for (int i = 2; i < argc; i++) {
    if (!strcmp(argv[i], "--hex")) hex = 1;
    else if (!strcmp(argv[i], "--max") && i + 1 < argc) {
      if (parse_count(argv[++i], 1, LIMIT_MAX, &max)) { fprintf(stderr, "dcf-gate: --max wants 1..%u\n", LIMIT_MAX); return 2; }
    } else if (!strcmp(argv[i], "--report") && i + 1 < argc) {
      if (parse_count(argv[++i], 0, 100, &want)) { fprintf(stderr, "dcf-gate: --report wants 0..100\n"); return 2; }
    } else { fprintf(stderr, "dcf-gate: ipv4: unknown option '%s'\n", argv[i]); return 2; }
  }

  int rc = 3;
  char *out = NULL;
  struct state *st = calloc(1, sizeof *st);
  uint32_t tsize = 16;
  while (tsize < max * 2u) tsize <<= 1;
  if (!st) return 3;
  st->ips = calloc(max, sizeof *st->ips);
  st->table = calloc(tsize, sizeof *st->table);
  if (!st->ips || !st->table) { fprintf(stderr, "dcf-gate: out of memory\n"); goto done; }
  st->mask = tsize - 1;
  st->shift = 32;
  for (uint32_t t = tsize; t > 1; t >>= 1) st->shift--;
  st->max = max;
  st->rep.want = want;

  static unsigned char rd[65536];
  unsigned char head[16] = {0};
  uint64_t len = 0;           /* bytes of this candidate (hex chars, in hex mode) */
  int badhex = 0;
  for (;;) {
    ssize_t got = read(0, rd, sizeof rd);
    if (got < 0) { if (errno == EINTR) continue; fprintf(stderr, "dcf-gate: read: %s\n", strerror(errno)); goto done; }
    if (got == 0) break;
    for (ssize_t i = 0; i < got; i++) {
      unsigned char c = rd[i];
      if (c == '\n') {
        if (!hex) {
          judge(st, head, len);
        } else if (badhex || (len & 1u)) {
          st->read++;
          reject(st, R_HEX, head, len / 2);
        } else {
          judge(st, head, len / 2);
        }
        memset(head, 0, sizeof head);
        len = 0; badhex = 0;
        continue;
      }
      if (!hex) {
        if (len < 16) head[len] = c;
        if (len != UINT64_MAX) len++;
      } else {
        int h = host_hex(c);
        if (h < 0) { badhex = 1; continue; }
        if (len < 32) {
          if (len & 1u) head[len / 2] = (unsigned char)(head[len / 2] | h);
          else head[len / 2] = (unsigned char)(h << 4);
        }
        if (len != UINT64_MAX) len++;
      }
    }
  }
  if (len > 0 || badhex) {          /* input ended inside a line */
    st->read++; st->unterminated = 1;
    reject(st, R_UNTERM, head, hex ? len / 2 : len);
  }

  /* stdout last, and only if everything was read: all or nothing */
  size_t cap = (size_t)st->count * 16 + 1;
  out = malloc(cap);
  if (!out) goto done;
  size_t o = 0;
  for (uint32_t i = 0; i < st->count; i++) {
    uint32_t a = st->ips[i];
    o += (size_t)snprintf(out + o, cap - o, "%u.%u.%u.%u\n", a >> 24, (a >> 16) & 255u, (a >> 8) & 255u, a & 255u);
  }
  if (write_all(1, out, o)) goto done;

  fprintf(stderr, "dcf-gate: ipv4 read=%llu admitted=%u rejected=%llu duplicate=%llu capped=%llu unterminated=%llu\n",
          (unsigned long long)st->read, st->count, (unsigned long long)st->rejected,
          (unsigned long long)st->duplicate, (unsigned long long)st->capped, (unsigned long long)st->unterminated);
  if (st->rejected) {
    fputs("dcf-gate: rejected-by", stderr);
    for (int r = 0; r < R_N; r++)
      if (st->by_reason[r]) fprintf(stderr, " %s=%llu", policy_name[r], (unsigned long long)st->by_reason[r]);
    fputc('\n', stderr);
  }
  for (unsigned i = 0; i < st->rep.have; i++) fprintf(stderr, "%s\n", st->rep.lines[i]);
  rc = 0;
done:
  free(out);
  if (st) { free(st->ips); free(st->table); }
  free(st);
  return rc;
}

/* ------------------------------------------------- port / interval / test */

static int mode_number(int which, const char *name, int argc, char **argv)
{
  if (argc != 3) { fprintf(stderr, "usage: dcf-gate %s VALUE\n", name); return 2; }
  const char *v = argv[2];
  size_t n = strlen(v);
  uint64_t verdict = gate_number(which, (const unsigned char *)v, n);
  if (verdict != 0) {
    static const char *const why_dcf[6] = { "admitted", "empty", "too long", "not all digits", "leading zero",
                                            "out of range" };
    static const char *const why_num[5] = { "admitted", "empty", "too long", "not all digits", "leading zero" };
    static const char *const why_onus[8] = { "admitted", "empty", "too long", "a byte outside [0-9.]",
                                             "no digit before the dot", "leading zero",
                                             "more than six integer digits", "bad fraction" };
    const char *w = "?";
    if (which <= 1 && verdict < 6) w = why_dcf[verdict];
    else if (which == 2 && verdict < 5) w = why_num[verdict];
    else if (which == 3 && verdict < 8) w = why_onus[verdict];
    const char *want = which == 0 ? "want 1..65535" : which == 1 ? "want 1..3600 seconds"
                     : which == 2 ? "want 1..20 digits, no leading zero" : "want digits, optionally . and 1..6 digits";
    fprintf(stderr, "dcf-gate: %s refused (%s); %s\n", name, w, want);
    return 1;
  }
  printf("%s\n", v);
  return 0;
}

struct vec { int fn; const char *in; size_t len; unsigned want; };
/* fn 0 ipv4 verdict, 1 ordo class (255 = refused), 2 port, 3 interval, 4 number, 5 load */
static const struct vec vecs[] = {
  {0, "1.2.3.4", 7, 0}, {0, "255.255.255.255", 15, 0}, {0, "0.0.0.0", 7, 0}, {0, "", 0, 1},
  {0, "1.2.3.04", 8, 6}, {0, "1.2.3.08", 8, 6}, {0, "01.2.3.4", 8, 6}, {0, "1.2.3.256", 9, 7},
  {0, "1.2.3", 5, 4}, {0, "1.2.3.4.5", 9, 4}, {0, "1..3.4", 6, 4}, {0, "1.2.3.1000", 10, 5},
  {0, "1.2.3.4 ", 8, 3}, {0, " 1.2.3.4", 8, 3}, {0, "1.2.3.4\n", 8, 3}, {0, "1.2.3.4\r", 8, 3},
  {0, "1.2.3.4\0", 8, 3}, {0, "1.2.3.4/32", 10, 3}, {0, "0x7f.0.0.1", 10, 3}, {0, "1234567890123456", 16, 2},
  {1, "8.8.8.8", 7, 0}, {1, "10.0.0.1", 8, 6}, {1, "172.16.0.1", 10, 6}, {1, "172.32.0.1", 10, 0},
  {1, "192.168.1.1", 11, 6}, {1, "100.64.0.1", 10, 7}, {1, "100.128.0.1", 11, 0}, {1, "127.0.0.1", 9, 2},
  {1, "0.1.2.3", 7, 1}, {1, "169.254.1.1", 11, 3}, {1, "224.0.0.1", 9, 4}, {1, "240.0.0.1", 9, 5},
  {1, "255.255.255.255", 15, 5}, {1, "1.2.3.08", 8, 255},
  {2, "7777", 4, 0}, {2, "1", 1, 0}, {2, "65535", 5, 0}, {2, "0", 1, 5}, {2, "65536", 5, 5},
  {2, "07777", 5, 4}, {2, "7777 accept", 11, 2}, {2, "", 0, 1}, {2, "-1", 2, 3}, {2, "777777", 6, 2},
  {3, "10", 2, 0}, {3, "1", 1, 0}, {3, "3600", 4, 0}, {3, "0", 1, 5}, {3, "3601", 4, 5}, {3, "010", 3, 4},
  {4, "0", 1, 0}, {4, "18446744073709551615", 20, 0}, {4, "", 0, 1}, {4, "007", 3, 4}, {4, "1e5", 3, 3},
  {4, "-1", 2, 3}, {4, "1,\"x\":2", 7, 3}, {4, "100000000000000000000", 21, 2}, {4, "1\n", 2, 3},
  {5, "0.42", 4, 0}, {5, "12.5", 4, 0}, {5, "104.50", 6, 0}, {5, "3", 1, 0}, {5, ".5", 2, 4}, {5, "00.5", 4, 5},
  {5, "1234567.1", 9, 6}, {5, "1.", 2, 7}, {5, "1.2.3", 5, 7}, {5, "1.1234567", 9, 7}, {5, "nan", 3, 3},
  {5, "0.42,\"injected\":true", 20, 2},
};

static int mode_selftest(void)
{
  unsigned bad = 0;
  size_t n = sizeof vecs / sizeof vecs[0];
  for (size_t i = 0; i < n; i++) {
    const struct vec *v = &vecs[i];
    uint64_t got;
    unsigned char head[16] = {0};
    if (v->fn <= 1) {
      memcpy(head, v->in, v->len < 16 ? v->len : 16);
      got = v->fn == 0 ? gate_ipv4(head, v->len) : gate_class(head, v->len);
    } else {
      got = gate_number(v->fn - 2, (const unsigned char *)v->in, v->len);
    }
    if (got != v->want) {
      fprintf(stderr, "dcf-gate: selftest: vector %zu (fn %d, \"%s\") gave %llu, wanted %u\n", i, v->fn, v->in,
              (unsigned long long)got, v->want);
      bad++;
    }
  }
  /* a pathological length is answered without reading past the 16 bytes */
  unsigned char head[16] = "1.2.3.4";
  if (gate_ipv4(head, UINT64_MAX) != 2 || gate_ipv4(head, 16) != 2) { fprintf(stderr, "dcf-gate: selftest: long length\n"); bad++; }
  if (bad) return 1;
  fprintf(stderr, "dcf-gate: selftest ok (%zu vectors)\n", n + 2);
  return 0;
}

int main(int argc, char **argv)
{
  if (argc >= 2) {
    if (!strcmp(argv[1], "ipv4")) return mode_ipv4(argc, argv);
    if (!strcmp(argv[1], "port")) return mode_number(0, "port", argc, argv);
    if (!strcmp(argv[1], "interval")) return mode_number(1, "interval", argc, argv);
    if (!strcmp(argv[1], "number")) return mode_number(2, "number", argc, argv);
    if (!strcmp(argv[1], "load")) return mode_number(3, "load", argc, argv);
    if (!strcmp(argv[1], "selftest")) return mode_selftest();
  }
  fputs("usage: dcf-gate ipv4 [--hex] [--max N] [--report N] < lines\n"
        "       dcf-gate port VALUE | interval VALUE | number VALUE | load VALUE | selftest\n", stderr);
  return 2;
}
