#!/usr/bin/env python3
"""t_gate_cli.py -- gate/dcf-gate against an oracle that shares no code with it.

The oracle for "an IPv4 address" is three independent definitions that must agree
with each other first (a regex, Python's ipaddress, libc's inet_pton); the oracle
for the class policy is a table of CIDR blocks. dcf-gate is run on corpora and
on single hostile inputs, plain and --hex, plain build and ASan+UBSan build.
Output: TAP-ish lines, then "# t_gate_cli.py: pass= fail= skip=".
"""
import ipaddress
import itertools
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE_DIR = os.environ.get("DCF_GATE_DIR", os.path.join(ROOT, "gate"))
QUICK = os.environ.get("DCF_GATE_QUICK") == "1"       # mutant runs: plain build only
GATE = os.environ.get("DCF_GATE_BIN", os.path.join(GATE_DIR, "dcf-gate"))
pass_n = fail_n = skip_n = 0


def ok(name):
    global pass_n
    pass_n += 1
    print("ok - " + name)


def bad(name, detail=""):
    global fail_n
    fail_n += 1
    print("not ok - " + name)
    for line in str(detail).splitlines()[:12]:
        print("#   " + line)


def skip(name, why):
    global skip_n
    skip_n += 1
    print("skip - %s (%s)" % (name, why))


def check(name, cond, detail=""):
    ok(name) if cond else bad(name, detail)


# ------------------------------------------------------------------ oracle
CANON = re.compile(rb"(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}")
# classes the watchdog refuses: this-network, loopback, link-local, multicast, reserved (incl. broadcast)
REFUSED_NETS = [ipaddress.ip_network(n) for n in
                ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4")]


def syntax_ok(b):
    """Canonical dotted quad: three independent definitions, which must agree."""
    m = CANON.fullmatch(b) is not None and all(int(x) <= 255 for x in b.split(b"."))
    try:
        s = b.decode("ascii")
        p = True
        try:
            ipaddress.IPv4Address(s)
        except ValueError:
            p = False
        try:
            socket.inet_pton(socket.AF_INET, s)
            q = True
        except OSError:
            q = False
        except ValueError:      # embedded NUL
            q = False
    except UnicodeDecodeError:
        p = q = False
    if not (m == p == q):
        raise SystemExit("ORACLE DISAGREES with itself on %r: regex=%s ipaddress=%s inet_pton=%s" % (b, m, p, q))
    return m


def admitted(b):
    if not syntax_ok(b):
        return False
    a = ipaddress.IPv4Address(b.decode("ascii"))
    return not any(a in n for n in REFUSED_NETS)


def expected_lines(values):
    seen, out = set(), []
    for v in values:
        if admitted(v) and v not in seen:
            seen.add(v)
            out.append(v)
    return out


# ------------------------------------------------------------------ running the CLI
def run(args, data=b"", binary=None):
    p = subprocess.run([binary or GATE] + args, input=data, capture_output=True, timeout=120)
    return p.returncode, p.stdout, p.stderr


def lines_in(values, hexmode=False):
    out = []
    for v in values:
        out.append((v.hex().encode() if hexmode else v) + b"\n")
    return b"".join(out)


def summary(err):
    m = re.search(rb"dcf-gate: ipv4 read=(\d+) admitted=(\d+) rejected=(\d+) duplicate=(\d+) capped=(\d+) unterminated=(\d+)", err)
    return tuple(int(x) for x in m.groups()) if m else None


def compare(name, values, binary=None, extra=()):
    """Run `values` through both modes, expect exactly the oracle's admitted, de-duplicated list."""
    want = expected_lines(values)
    for hexmode in (False, True):
        if not hexmode and any(b"\n" in v for v in values):
            continue                      # a newline splits plain-mode candidates by definition
        args = ["ipv4", "--max", "1048576"] + (["--hex"] if hexmode else []) + list(extra)
        rc, out, err = run(args, lines_in(values, hexmode), binary)
        got = out.split(b"\n")[:-1] if out else []
        s = summary(err)
        label = "%s [%s]" % (name, "hex" if hexmode else "plain")
        good = rc == 0 and got == want and s is not None and s[0] == len(values) and s[1] == len(want)
        if good:
            ok(label)
        else:
            extra_gt = [x for x in got if x not in set(want)][:5]
            missing = [x for x in want if x not in set(got)][:5]
            bad(label, "rc=%s summary=%s want %d lines got %d\nextra: %r\nmissing: %r\n%s"
                % (rc, s, len(want), len(got), extra_gt, missing, err[:300]))


# ------------------------------------------------------------------ build
if not (os.path.isfile(GATE) and os.access(GATE, os.X_OK)):
    r = subprocess.run(["make", "-s", "-C", GATE_DIR], capture_output=True, text=True)
    if r.returncode != 0:
        print("Bail out! cannot build gate/dcf-gate:\n" + r.stdout + r.stderr)
        sys.exit(2)

tmp = tempfile.mkdtemp(prefix="dcfgate.")


def sanitised_build():
    """A second build with ASan+UBSan, for the overflow-prone inputs."""
    out = os.path.join(tmp, "dcf-gate-asan")
    cmd = ["gcc", "-std=c11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
           "-I", GATE_DIR, os.path.join(GATE_DIR, "dcf-gate.c"), os.path.join(GATE_DIR, "dcf_net_gate.gen.c"),
           "-o", out]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return out if r.returncode == 0 else None


ASAN = None if QUICK else sanitised_build()
if ASAN is None and not QUICK:
    skip("ASan+UBSan build", "gcc -fsanitize=address,undefined unavailable")

# ------------------------------------------------------------------ corpora
alphabet = b"0159."
corpus = []
for n in range(0, 7):
    for t in itertools.product(alphabet, repeat=n):
        corpus.append(bytes(t))
random.seed(20261009)
for _ in range(20000):
    k = random.randint(1, 20)
    corpus.append(bytes(random.choice(b"0123456789./:@a -\x00\r\t\xff") for _ in range(k)))
octs = [b"0", b"1", b"9", b"255", b"256", b"08", b"999", b"00", b"10", b"100", b"127", b"169", b"172", b"224", b"240"]
for n in range(1, 6):
    for t in itertools.product(octs, repeat=n) if n <= 4 else []:
        corpus.append(b".".join(t))
for o in range(0, 300):
    for pos in range(4):
        v = [b"1", b"2", b"3", b"4"]
        v[pos] = str(o).encode()
        corpus.append(b".".join(v))
for a in range(0, 256):
    for b2 in (0, 1, 15, 16, 31, 32, 63, 64, 100, 127, 128, 168, 169, 253, 254, 255):
        corpus.append(b"%d.%d.0.1" % (a, b2))
corpus = [c for c in corpus if b"\n" not in c]
check("oracle self-consistency over the corpus (regex == ipaddress == inet_pton)", True)  # SystemExit otherwise
compare("corpus of %d candidates (all strings over '0159.' to 6 bytes, random bytes, octet grids, class boundaries)" % len(corpus),
        corpus)

hostile = [
    b"1.2.3.08", b"1.2.3.4 ", b" 1.2.3.4", b"1.2. 3.4", b"1.2.3.4\r", b"1.2.3.4\t", b"1.2.3.4\x00", b"\x001.2.3.4",
    b"1.2.3.4\x00junk", b"1.2.3.4\x008.8.8.8", b"010.2.3.4", b"01.2.3.4", b"0x7f.0.0.1", b"127.1", b"1.2.3.4/32",
    b"1.2.3.4 accept", b"1.2.3.4}; flush ruleset; #", b"1.2.3.4,5.6.7.8", b"1.2.3.4-1.2.3.9", b"+1.2.3.4",
    "１.２.３.４".encode(), b"1.2.3.4.", b".1.2.3.4", b"1..2.3", b"", b"8.8.8.8", b"1.2.3.4", b"255.255.255.255",
    b"0.0.0.0", b"127.0.0.1", b"224.0.0.1", b"169.254.0.1", b"10.0.0.1", b"100.64.0.1", b"::1", b"localhost",
    b"1.2.3.4" + b"\x00" * 20, b"9" * 15, b"1" * 16, b"1.2.3.4" + b" " * 100,
    # a valid 15-byte address with something after it: the length contract, not the content, refuses these
    b"255.255.255.2551", b"192.168.100.1000", b"223.255.255.255\x00", b"223.255.255.255.", b"223.255.255.255\n".rstrip(b"\n") + b"x",
]
for h in hostile:
    for hexmode in (False, True):
        rc, out, err = run(["ipv4"] + (["--hex"] if hexmode else []), lines_in([h], hexmode))
        want = [h] if admitted(h) else []
        got = out.split(b"\n")[:-1]
        check("hostile %r [%s]: %s" % (h[:40], "hex" if hexmode else "plain", "admitted" if want else "refused"),
              rc == 0 and got == want, "rc=%s out=%r err=%r" % (rc, out, err))

# a hostile value must not hide behind good neighbours, nor poison them
mixed = [b"8.8.4.4", b"1.2.3.08", b"8.8.8.8", b"1.2.3.4\x00", b"9.9.9.9", b"1.2.3.4 ", b"1.1.1.1"]
compare("good lines around hostile ones survive, hostile ones do not", mixed)

# ------------------------------------------------------------------ framing
rc, out, err = run(["ipv4"], b"8.8.8.8\r\n9.9.9.9\r\n")
check("CRLF: both lines refused (the CR is a byte outside [0-9.]), nothing stripped",
      rc == 0 and out == b"" and summary(err)[:3] == (2, 0, 2), (rc, out, err))
rc, out, err = run(["ipv4"], b"8.8.8.8\n9.9.9.9")
check("no trailing newline: the last line is refused as truncated, earlier lines kept",
      rc == 0 and out == b"8.8.8.8\n" and summary(err) == (2, 1, 1, 0, 0, 1), (rc, out, err))
rc, out, err = run(["ipv4"], b"")
check("empty input: nothing, read=0, exit 0", rc == 0 and out == b"" and summary(err) == (0, 0, 0, 0, 0, 0), (rc, out, err))
rc, out, err = run(["ipv4"], b"\n\n\n")
check("blank lines are refused as empty", rc == 0 and out == b"" and summary(err)[:3] == (3, 0, 3), (rc, out, err))
rc, out, err = run(["ipv4"], b"8.8.8.8\x00\n9.9.9.9\n")
check("NUL after a valid prefix: that line refused, the next admitted",
      rc == 0 and out == b"9.9.9.9\n" and b"bad_byte=1" in err, (rc, out, err))
rc, out, err = run(["ipv4"], b"1.1.1.1\n8.8.8.8\n1.1.1.1\n9.9.9.9\n8.8.8.8\n")
check("duplicates collapse, first-seen order is kept",
      out == b"1.1.1.1\n8.8.8.8\n9.9.9.9\n" and summary(err) == (5, 3, 0, 2, 0, 0), (out, err))
vals = [b"%d.0.0.1" % i for i in range(20, 30)]
rc, out, err = run(["ipv4", "--max", "3"], lines_in(vals + vals[:2]))
check("--max 3: the first three in input order, the rest counted as capped, duplicates of kept ones are duplicates",
      out == b"20.0.0.1\n21.0.0.1\n22.0.0.1\n" and summary(err) == (12, 3, 0, 2, 7, 0), (out, err))
rc, out, err = run(["ipv4"], lines_in([b"%d.%d.%d.1" % (20 + i // 65536, i // 256 % 256, i % 256) for i in range(5000)]))
check("default cap is 4096", out.count(b"\n") == 4096 and summary(err) == (5000, 4096, 0, 0, 904, 0), summary(err))
rc, out, err = run(["ipv4", "--report", "2"], lines_in([b"1.2.3.08", b"127.0.0.1", b"x y", b"8.8.8.8"]))
check("--report N prints at most N escaped samples",
      err.count(b"dcf-gate: reject ") == 2 and b"head=1.2.3.08" in err, err)
rc, out, err = run(["ipv4", "--report", "3"], lines_in([b"a b\x01\"\\;"]))
check("samples are escaped to a safe alphabet", re.search(rb"head=a\\x20b\\x01\\x22\\x5c\\x3b$", err.strip().split(b"\n")[-1]), err)

# --hex framing
rc, out, err = run(["ipv4", "--hex"], b"382e382e382e38\n382E382E342E34\n")
check("--hex accepts upper and lower case", out == b"8.8.8.8\n8.8.4.4\n", (out, err))
rc, out, err = run(["ipv4", "--hex"], b"382e382e382e3\n3g2e\n\n")
check("--hex: odd length, non-hex byte and an empty line are all refused",
      out == b"" and summary(err)[:3] == (3, 0, 3) and b"bad_hex=2" in err and b"empty=1" in err, (out, err))
nl = (b"8.8.4.4\n9.9.9.9").hex().encode() + b"\n"
rc, out, err = run(["ipv4", "--hex"], nl)
check("--hex: one value that CONTAINS a newline is one refused candidate", out == b"" and summary(err)[:3] == (1, 0, 1), (out, err))
rc, out, err = run(["ipv4", "--hex"], (b"8.8.4.4\x00").hex().encode() + b"\n" + (b"8.8.4.4").hex().encode() + b"\n")
check("--hex: a value ending in NUL is refused, the clean one admitted", out == b"8.8.4.4\n", (out, err))
# a non-hex byte must refuse the record even when the hex digits that remain happen to spell an address
for tag, rec in (("g", b"382e38g2e382e38"), ("space", b"382e382e 382e38"), ("tab", b"382e382e\t382e38"),
                 ("colon", b"382e382e:382e38"), ("0x", b"0x382e382e382e38"), ("dash", b"382e-382e382e38")):
    rc, out, err = run(["ipv4", "--hex"], rec + b"\n")
    check("--hex: a %s inside an otherwise valid record refuses it" % tag, out == b"" and b"bad_hex=1" in err, (rec, out, err))
rc, out, err = run(["ipv4", "--hex"], b"382e382e342e34")
check("--hex: unterminated final record refused", out == b"" and summary(err)[5] == 1, (out, err))

# ------------------------------------------------------------------ big inputs (both builds)
builds = [("plain", GATE)] + ([("asan+ubsan", ASAN)] if ASAN else [])
for label, binary in builds:
    big = b"8.8.8.8\n" + b"9" * (1 << 20) + b"\n9.9.9.9\n"
    rc, out, err = run(["ipv4"], big, binary)
    check("[%s] a 1 MiB line is refused as too long; neighbours kept" % label,
          rc == 0 and out == b"8.8.8.8\n9.9.9.9\n" and b"too_long=1" in err, (rc, out[:50], err[:300]))
    rc, out, err = run(["ipv4"], b"1.2.3.4" + b"\x00" * (1 << 20) + b"\n8.8.8.8\n", binary)
    check("[%s] a 1 MiB line of NULs is refused without truncating into '1.2.3.4'" % label,
          rc == 0 and out == b"8.8.8.8\n", (rc, out[:50], err[:300]))
    rc, out, err = run(["ipv4", "--hex"], b"38" * (1 << 20) + b"\n" + b"38" * (1 << 20) + b"zz\n", binary)
    check("[%s] a 1 MiB hex line, and one with a bad digit past the 16-byte window, are refused" % label,
          rc == 0 and out == b"" and summary(err)[:3] == (2, 0, 2), (rc, out[:50], err[:300]))
    many = [bytes(random.choice(b"0123456789.") for _ in range(random.randint(0, 17))) for _ in range(100000)]
    many += [b"%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255), random.randint(0, 255), random.randint(1, 254))
             for _ in range(50000)]
    random.shuffle(many)
    t0 = time.time()
    rc, out, err = run(["ipv4", "--max", "1048576"], lines_in(many), binary)
    dt = time.time() - t0
    got = out.split(b"\n")[:-1]
    check("[%s] 150000 lines: exact oracle match (%.2fs)" % (label, dt), rc == 0 and got == expected_lines(many) and summary(err)[0] == len(many),
          (rc, len(got), len(expected_lines(many)), err[:200]))
    # one tiny read() per byte boundary: the same input fed in 1-byte writes
    p = subprocess.Popen([binary, "ipv4"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data = b"8.8.8.8\n1.2.3.08\n9.9.9.9\n"
    for i in range(len(data)):
        p.stdin.write(data[i:i + 1]); p.stdin.flush()
    p.stdin.close()
    o = p.stdout.read(); p.wait()
    check("[%s] input arriving one byte at a time gives the same answer" % label, o == b"8.8.8.8\n9.9.9.9\n", o)

# ------------------------------------------------------------------ port / interval
def num_ok(s, hi):
    return re.fullmatch(r"[1-9][0-9]{0,4}", s) is not None and 1 <= int(s) <= hi


bad_cases = []
cands = [str(i) for i in range(0, 301)] + [str(i) for i in range(3590, 3612)] + [str(i) for i in range(65525, 65545)] + \
        ["", " ", "0", "00", "007", "07777", "7777 ", " 7777", "7777\n", "7777\naccept", "7777 accept", "7777 accept #", "7777;flush ruleset",
         "-1", "+1", "1.5", "1e3", "0x10", "٣", "７７７７", "99999", "100000", "99999999999999999999", "7777" + "\t", "1_000",
         "0-65535", "1-2", "a", "7777a"] + [str(random.randint(0, 120000)) for _ in range(400)] + \
        ["".join(random.choice("0123456789 -+.") for _ in range(random.randint(1, 7))) for _ in range(400)]
for which, name, hi in (("port", "port", 65535), ("interval", "interval", 3600)):
    for s in cands:
        rc, out, err = run([which, s])
        want = num_ok(s, hi)
        got = rc == 0
        if got != want or (got and out != s.encode() + b"\n"):
            bad_cases.append((name, s, rc, out))
    check("%s: %d candidates agree with the oracle (1..%d, no leading zero, digits only)" % (name, len(cands), hi),
          not bad_cases, bad_cases[:5])
    bad_cases = []
rc, out, err = run(["port", "7777", "accept"])
check("port: extra arguments are a usage error", rc == 2, (rc, err))
rc, out, err = run(["port", "7777\0".replace("\0", "")])
check("port 7777 echoes the value", rc == 0 and out == b"7777\n", (rc, out))

# ------------------------------------------------------------------ usage, selftest, trap
rc, out, err = run([])
check("no arguments: usage, exit 2", rc == 2 and b"usage" in err, (rc, err))
rc, out, err = run(["bogus"])
check("unknown subcommand: exit 2", rc == 2, (rc, err))
for a in (["ipv4", "--max", "0"], ["ipv4", "--max", "x"], ["ipv4", "--max"], ["ipv4", "--max", "9999999"], ["ipv4", "--report", "101"], ["ipv4", "--nope"]):
    rc, out, err = run(a)
    check("bad option %r: exit 2" % (a,), rc == 2, (rc, err))
rc, out, err = run(["selftest"])
check("selftest passes", rc == 0 and b"selftest ok" in err, (rc, err))

# the host fails closed if the gate ever traps: build the host against a unit that traps
stub = os.path.join(tmp, "trapping.c")
with open(stub, "w") as f:
    f.write('#include <stdint.h>\n#include "dcf_net_gate.gen.h"\n'
            'uint64_t exs_admitte_ipv4(unsigned char *p, uint64_t n){(void)p;(void)n;exsrt_abortus(1);}\n'
            'uint64_t exs_ordo_ipv4(unsigned char *p, uint64_t n){(void)p;(void)n;return 0;}\n'
            'uint64_t exs_admitte_portum(unsigned char *p, uint64_t n){(void)p;(void)n;return 0;}\n'
            'uint64_t exs_admitte_intervallum(unsigned char *p, uint64_t n){(void)p;(void)n;return 0;}\n')
trap_bin = os.path.join(tmp, "dcf-gate-trap")
r = subprocess.run(["gcc", "-std=c11", "-O2", "-I", GATE_DIR, os.path.join(GATE_DIR, "dcf-gate.c"), stub, "-o", trap_bin],
                   capture_output=True, text=True)
if r.returncode == 0:
    rc, out, err = run(["ipv4"], b"8.8.8.8\n", trap_bin)
    check("a trap in the gate is fail-closed: exit 70, nothing on stdout", rc == 70 and out == b"" and b"exsrt_abortus" in err, (rc, out, err))
else:
    bad("build a host against a trapping stub", r.stderr)

shutil.rmtree(tmp, ignore_errors=True)
print("# t_gate_cli.py: pass=%d fail=%d skip=%d" % (pass_n, fail_n, skip_n))
sys.exit(1 if fail_n else 0)
