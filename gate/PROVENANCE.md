# Provenance of the vendored gate

`dcf_net_gate.gen.[ch]` and `watchdawg_gate.gen.[ch]` are the output of the
Exsecutor compiler, committed here unmodified so that building this repository
needs a C compiler and nothing else (no `exsc`, no `fasmg`).

| | `dcf_net_gate` (shared with DCF-ID) | `watchdawg_gate` (telemetry numbers) |
|---|---|---|
| source unit | `examples/dcf_net_gate/dcf_net_gate.exsc` | `examples/watchdawg_gate/watchdawg_gate.exsc` |
| last commit touching the unit | `0d7cf933c3b8df3967bade4c47e87b7f9055dfc7` | `c817af0fd7bd08e108827956115bd163e0dfe880` |
| `.exsc` sha256 | `1e8694c9ecb6eec723ca347f51b2f33f12c4042b642efd2df5dc16bb1ec7df7a` | `48715733e00a511296b34688b61ddef980f7967ac96c0c397c9e309fc7d60a80` |
| `.gen.c` sha256 | `c21f4690bacc7819a0a00d33be7212ea5d5c50d15c980912f69470ed2c107e95` | `0c27e333e8860e73bfed9e33f5bcfddd74ea13fe36f422ca2455dbf2c7938baf` |
| `.gen.h` sha256 | `b5e8983e164024b74b03fb9ea5d4d53373d150ad96a57b326e9733f21aa20139` | `123c9aba89da4d46d80dd4f2302102c40f1636916da2fa7da6e3694566a6acce` |

| | |
|---|---|
| Exsecutor HEAD when emitted | `c817af0fd7bd08e108827956115bd163e0dfe880` |
| `build/exsc` sha256 | `2196c34746c1fa1f68330bb84a3bdbd09f199024a86def3c967f3ddbf1931731` |
| emitted | 2026-10-09 |

Command lines (run from an Exsecutor checkout; `exsc` is the file above), one
unit per translation unit:

```
exsc aedifica --hospes x86_64-linux --emitte c examples/dcf_net_gate/dcf_net_gate.exsc   -o gate/dcf_net_gate.gen.c
exsc aedifica --hospes x86_64-linux --emitte h examples/dcf_net_gate/dcf_net_gate.exsc   -o gate/dcf_net_gate.gen.h
exsc aedifica --hospes x86_64-linux --emitte c examples/watchdawg_gate/watchdawg_gate.exsc -o gate/watchdawg_gate.gen.c
exsc aedifica --hospes x86_64-linux --emitte h examples/watchdawg_gate/watchdawg_gate.exsc -o gate/watchdawg_gate.gen.h
```

`dcf_net_gate.gen.c` is byte-identical to a standalone emission of the shared
module, so DCF-ID and this repository vendor the same bytes. The two units
export disjoint names (`exs_admitte_ipv4`, `exs_ordo_ipv4`, `exs_admitte_portum`,
`exs_admitte_intervallum`; `exs_admitte_numerum`, `exs_admitte_onus`) and their
header guards differ, so they link into one binary.

`scripts/check-gate-fresh.sh` re-emits all four files and compares them byte for
byte (`EXSECUTOR=/path/to/exsecutor scripts/check-gate-fresh.sh`); without a
checkout it prints `[skip]`. `make check-gate` runs it. The `--emitte rs` faces
are not vendored: this repository has no Rust consumer.

## What the unit is, and what is not claimed

Two pure, total function sets: `dcf_net_gate` (`admitte_ipv4`, `ordo_ipv4`,
`admitte_portum`, `admitte_intervallum`) and `watchdawg_gate`
(`admitte_numerum`, `admitte_onus`). The verdict tables are in the header
comments of the `.exsc` files and in each `README.md` in the Exsecutor
repository, where the differential runs against three independent definitions
(1,042,480 cases and 14 gate mutants for the first; 696,610 cases and 16 for the
second) are described. Those suites live in Exsecutor (`proba_c.sh` in each
example directory); both were run against the compiler build above on the day
the C was vendored, and passed. What **this** repository ran is
`tests/t_gate_cli.py` (the CLI against its own oracle: about 99,000 IPv4
candidates, number and load corpora, hostile inputs, framing and size cases,
plain and under ASan+UBSan) and `dcf-gate selftest`.

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
