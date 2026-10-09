#!/usr/bin/env python3
"""t_gate_mutants.py -- does tests/t_gate_cli.py notice when dcf-gate.c is wrong?

Each mutant is a one-line behavioural change to the host. It must BUILD (a mutant
that does not compile proves nothing) and then FAIL t_gate_cli.py. A mutant that
passes means the corpus is too thin: strengthen the corpus, do not drop the mutant.
(The gate unit itself is mutated by Exsecutor's own proba_c.sh, not here.)
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "gate")
src = open(os.path.join(GATE, "dcf-gate.c")).read()

MUTANTS = [
    ("admit every class, not just global/private/shared",
     "if (cls != 0 && cls != 6 && cls != 7) {", "if (0) {"),
    ("admit loopback as well",
     "if (cls != 0 && cls != 6 && cls != 7) {", "if (cls != 0 && cls != 6 && cls != 7 && cls != 2) {"),
    ("admit reserved/broadcast as well",
     "if (cls != 0 && cls != 6 && cls != 7) {", "if (cls != 0 && cls != 6 && cls != 7 && cls != 5) {"),
    ("refuse private addresses",
     "if (cls != 0 && cls != 6 && cls != 7) {", "if (cls != 0 && cls != 7) {"),
    ("refuse shared 100.64/10",
     "if (cls != 0 && cls != 6 && cls != 7) {", "if (cls != 0 && cls != 6) {"),
    ("an unterminated last line is admitted",
     "if (len > 0 || badhex) {          /* input ended inside a line */",
     "if (len > 0 && !hex) judge(st, head, len);\n  if (0) {"),
    ("truncate a candidate at its first NUL (C-string semantics)",
     "        if (!hex) {\n          judge(st, head, len);",
     "        if (!hex) {\n          if (len <= 16) { uint64_t z = 0; while (z < len && head[z]) z++; len = z; }\n          judge(st, head, len);"),
    ("strip a trailing CR",
     "        if (!hex) {\n          judge(st, head, len);",
     "        if (!hex) {\n          if (len > 0 && len <= 16 && head[len - 1] == '\\r') len--;\n          judge(st, head, len);"),
    ("skip spaces inside a candidate",
     "      if (!hex) {\n        if (len < 16) head[len] = c;",
     "      if (!hex) {\n        if (c == ' ') continue;\n        if (len < 16) head[len] = c;"),
    ("no de-duplication",
     "    if (st->table[h] == a) { st->duplicate++; return; }", "    if (st->table[h] == a) { st->duplicate++; }"),
    ("the cap is not applied",
     "  if (st->count >= st->max) { st->capped++; return; }", "  if (st->count >= st->max + 100000u) { st->capped++; return; }"),
    ("the default cap is 5000",
     "#define DEFAULT_MAX 4096u", "#define DEFAULT_MAX 5000u"),
    ("hex mode ignores an odd trailing digit",
     "} else if (badhex || (len & 1u)) {", "} else if (badhex) {"),
    ("hex mode ignores a bad digit",
     "} else if (badhex || (len & 1u)) {", "} else if ((len & 1u)) {"),
    ("an over-long candidate is clipped to 15 bytes before the gate",
     "static uint64_t gate_ipv4(const unsigned char head[16], uint64_t n)\n{",
     "static uint64_t gate_ipv4(const unsigned char head[16], uint64_t n)\n{\n  if (n > 15) n = 15;"),
    ("hex length counts characters, not bytes",
     "          judge(st, head, len / 2);", "          judge(st, head, len);"),
    ("output is not written when rejects exist",
     "  if (write_all(1, out, o)) goto done;", "  if (st->rejected == 0 && write_all(1, out, o)) goto done;"),
    ("port accepts a leading zero",
     "  uint64_t verdict = gate_number(which, (const unsigned char *)v, n);\n  if (verdict != 0) {",
     "  uint64_t verdict = gate_number(which, (const unsigned char *)v, n);\n  if (verdict == 4) verdict = 0;\n  if (verdict != 0) {"),
    ("an over-long port value is clipped to 5 bytes before the gate",
     "  uint64_t verdict = gate_number(which, (const unsigned char *)v, n);",
     "  uint64_t verdict = gate_number(which, (const unsigned char *)v, n > 5 ? 5 : n);"),
    ("an unknown option is ignored",
     "else { fprintf(stderr, \"dcf-gate: ipv4: unknown option '%s'\\n\", argv[i]); return 2; }",
     "else { }"),
    ("the host's trap handler returns 0 instead of failing closed",
     "  _exit(70);", "  _exit(0);"),
]

import concurrent.futures


def one(i, name, old, new, tmp):
    """-> (ok, line)"""
    if src.count(old) != 1:
        return False, "not ok - mutant %d (%s): the anchor text occurs %d times in dcf-gate.c" % (i, name, src.count(old))
    d = os.path.join(tmp, "m%d" % i)
    shutil.copytree(GATE, d, ignore=shutil.ignore_patterns("dcf-gate", "*.o"))
    with open(os.path.join(d, "dcf-gate.c"), "w") as f:
        f.write(src.replace(old, new))
    b = subprocess.run(["make", "-s", "-C", d, "CFLAGS=-O1"], capture_output=True, text=True)
    if not os.path.exists(os.path.join(d, "dcf-gate")):
        # the selftest in the Makefile may itself be what notices
        if "selftest" in b.stderr or "selftest" in b.stdout:
            return True, "ok - mutant %d (%s): killed by the build's selftest" % (i, name)
        return False, "not ok - mutant %d (%s): does not build\n#   %s" % (i, name, b.stderr.strip()[:300])
    env = dict(os.environ, DCF_GATE_DIR=d, DCF_GATE_BIN=os.path.join(d, "dcf-gate"), DCF_GATE_QUICK="1")
    t = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "t_gate_cli.py")], capture_output=True, text=True, env=env)
    fails = [l for l in t.stdout.splitlines() if l.startswith("not ok")]
    if t.returncode != 0 and fails:
        return True, "ok - mutant %d (%s): killed (%d checks fail; first: %s)" % (i, name, len(fails), fails[0][:90])
    return False, "not ok - mutant %d (%s): SURVIVED the suite" % (i, name)


tmp = tempfile.mkdtemp(prefix="dcfgate-mut.")
results = []
try:
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, os.cpu_count() or 1)) as ex:
        futs = [ex.submit(one, i, n, o, w, tmp) for i, (n, o, w) in enumerate(MUTANTS)]
        results = [f.result() for f in futs]
finally:
    shutil.rmtree(tmp, ignore_errors=True)
survivors = [r for r in results if not r[0]]
unbuilt = []
for _, line in results:
    print(line)

print("# t_gate_mutants.py: pass=%d fail=%d skip=0" % (len(MUTANTS) - len(survivors) - len(unbuilt), len(survivors) + len(unbuilt)))
sys.exit(1 if survivors or unbuilt else 0)
