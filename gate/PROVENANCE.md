# Provenance of the vendored gate

`dcf_net_gate.gen.c` and `dcf_net_gate.gen.h` are the output of the Exsecutor
compiler, committed here unmodified so that building this repository needs a C
compiler and nothing else (no `exsc`, no `fasmg`).

| | |
|---|---|
| source unit | `examples/dcf_net_gate/dcf_net_gate.exsc` in the Exsecutor repository |
| Exsecutor HEAD when emitted | `0d7cf933c3b8df3967bade4c47e87b7f9055dfc7` |
| last commit touching the unit | `0d7cf933c3b8df3967bade4c47e87b7f9055dfc7` |
| `build/exsc` sha256 | `2196c34746c1fa1f68330bb84a3bdbd09f199024a86def3c967f3ddbf1931731` |
| `dcf_net_gate.exsc` sha256 | `1e8694c9ecb6eec723ca347f51b2f33f12c4042b642efd2df5dc16bb1ec7df7a` |
| `dcf_net_gate.gen.c` sha256 | `c21f4690bacc7819a0a00d33be7212ea5d5c50d15c980912f69470ed2c107e95` |
| `dcf_net_gate.gen.h` sha256 | `b5e8983e164024b74b03fb9ea5d4d53373d150ad96a57b326e9733f21aa20139` |
| emitted | 2026-10-09 |

Command lines (run from an Exsecutor checkout; `exsc` is the file above):

```
exsc aedifica --hospes x86_64-linux --emitte c examples/dcf_net_gate/dcf_net_gate.exsc -o gate/dcf_net_gate.gen.c
exsc aedifica --hospes x86_64-linux --emitte h examples/dcf_net_gate/dcf_net_gate.exsc -o gate/dcf_net_gate.gen.h
```

`scripts/check-gate-fresh.sh` re-emits both and compares them byte for byte
(`EXSECUTOR=/path/to/exsecutor scripts/check-gate-fresh.sh`); without a checkout
it prints `[skip]`. `make check-gate` runs it. The `--emitte rs` face is not
vendored: this repository has no Rust consumer (DCF-ID vendors its own).

## What the unit is, and what is not claimed

A pure, total function set: `admitte_ipv4`, `ordo_ipv4`, `admitte_portum`,
`admitte_intervallum`. Its verdict tables are in the header comment of the
`.exsc` and in `examples/dcf_net_gate/README.md` in the Exsecutor repository,
where its 1,042,480-case differential run against three independent definitions
of "IPv4 address" and its 14 behaviour mutants are described. **This repository
did not re-run that suite**; what it ran is `tests/t_gate_cli.py` (the CLI
against its own oracle over about 99,000 candidates, hostile inputs, framing and
size cases, plain and under ASan+UBSan) and `dcf-gate selftest`.

`gate/dcf-gate.c` is hand-written host code (not emitted): it supplies
`exsrt_abortus` (log, then `_exit(70)`; the process is single-threaded, so no
guard is needed and the unit's `tutela` guard is not used) and feeds the gate
bytes with explicit lengths. The emitted unit compiles warning-free with
`gcc -std=c11 -O2 -Wall -Wextra -Werror`; clang's `-Wunused-function` objects to
unused `static inline` helpers in the emitted prologue, so the Makefile passes
`-Wno-unused-function` for that one file only.

## Licence status

The `.exsc` source is GPL-3.0-or-later. `LICENSE.EXCEPTION` Exception A frees
only the compiler's own contribution to emitted C; it does not relicense the
unit's source, and the emitted C carries that source's logic. This repository is
BSD-3-Clause. A relicensing grant for this unit, of the kind `LICENSE.GRANTS`
GRANT 1 gives custos, **is pending owner decision**; until it exists, treat the
two `gate/dcf_net_gate.gen.*` files as GPL-3.0-or-later and do not ship binaries
built from them under BSD-3 terms alone.
