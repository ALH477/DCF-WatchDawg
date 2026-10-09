# DCF-Watchdog: Firewall Sync & Telemetry

A lightweight daemon that synchronizes user authentication state with kernel-level firewall rules. Enables real-time IP whitelisting for authenticated game clients.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/F1F11PNYX4)

## Features

- **Firewall Synchronization**: Syncs SQLite user database with nftables rules
- **Dynamic Whitelisting**: Authenticated users' IPs are automatically allowed
- **VIP Bypass**: Permanent whitelist for privileged users
- **Telemetry Generation**: Produces `status.json` for dashboard consumption
- **Low Overhead**: Shell-based, minimal resource usage
- **Automatic Cleanup**: Expired sessions removed from whitelist; revoked users and VIPs are removed on the next sync
- **Validated Input**: every address from the database and every configuration value goes through a gate (`gate/dcf-gate`, an Exsecutor unit compiled to C) before it reaches `nft`

## Quick Start

### Docker

```bash
docker pull alh477/dcf-watchdog:latest

docker run -d \
  --cap-drop ALL --cap-add NET_ADMIN \
  --security-opt no-new-privileges \
  --read-only --tmpfs /tmp \
  --network host \
  -e DB_PATH=/data/identity.db \
  -e WEB_ROOT=/data/public \
  -e DCF_PORT=7777 \
  -v dcf-data:/data \
  alh477/dcf-watchdog:latest
```

`NET_ADMIN` is the only capability the watchdog needs; `NET_RAW` (raw sockets) is
not used (measured: see "What was run"). `--read-only` works because everything
the watchdog writes goes to the `/data` volume (`status.json`) or `/tmp`.

### Docker Compose

```yaml
services:
  dcf-watchdog:
    image: alh477/dcf-watchdog:latest
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    network_mode: host
    environment:
      - DB_PATH=/data/identity.db
      - WEB_ROOT=/data/public
      - DCF_PORT=7777
      - SYNC_INTERVAL=10
    volumes:
      - dcf-data:/data
    depends_on:
      - dcf-id

volumes:
  dcf-data:
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `DB_PATH` | `/var/lib/demod/identity.db` | Path to DCF-ID SQLite database |
| `WEB_ROOT` | `/var/lib/demod/public` | Output directory for `status.json` |
| `DCF_PORT` | `7777` | UDP port to protect with firewall rules |
| `SYNC_INTERVAL` | `10` | Seconds between firewall sync cycles |
| `LOG_LEVEL` | `info` | Logging verbosity: exactly `debug`, `info`, `warn` or `error` (anything else: exit 64) |
| `TELEMETRY_SCRIPT` | unset | Absolute path of the telemetry script to run each cycle (in the image: `/scripts/dcf-telemetry.sh`). Unset: no telemetry. It must be a file only root can change (see below) |
| `TELEMETRY_PEERS` | `names` | What `status.json` says about users: `names` (name, tier, VIP flag, online), `count` (totals only), `off` (nothing). **`names` publishes every username to whoever can read `status.json`** |
| `DCF_GATE` | `/usr/local/bin/dcf-gate`, then `gate/dcf-gate` beside the script | Path of the gate binary |
| `DCF_WATCHDOG_ONCE` | unset | `1`: run exactly one init + sync cycle, then exit (0, or 1 if a sync failed). For tests |

`DCF_PORT` must be 1..65535 and `SYNC_INTERVAL` 1..3600 seconds, decimal, no sign,
no leading zero, nothing else; the watchdog checks both with `dcf-gate` before it
touches the firewall and exits **64** if either (or `LOG_LEVEL`, or
`TELEMETRY_SCRIPT`) is refused. An empty variable still means "use the default".

`TELEMETRY_SCRIPT`, and the `dcf-gate` binary, are executed as root. Each must be
an absolute path to an executable regular file owned by root (or the running
user) that nobody else can write, in a directory chain that nobody else can
rename entries in (a root-owned sticky directory such as `/tmp` is accepted).
The check runs at start and again every cycle. Otherwise it is refused and an
`error` is logged.

## How It Works

### Firewall Architecture

```
                    ┌─────────────────┐
                    │   Internet      │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  nftables       │
                    │  dcf_firewall   │
                    │                 │
                    │  ┌───────────┐  │
                    │  │ whitelist │◄─┼── dcf-watchdog syncs IPs
                    │  └───────────┘  │
                    │  ┌───────────┐  │
                    │  │ vip_perm  │◄─┼── Permanent VIP IPs
                    │  └───────────┘  │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  DCF-SDK        │
                    │  UDP :7777      │
                    └─────────────────┘
```

### Sync Cycle

Every `SYNC_INTERVAL` seconds:

1. Query active users from SQLite: seen in the last hour, and (VIP OR within the
   free tier OR balance covers the overage). "Seen in the last hour" compares
   instants (`datetime(last_seen) >= datetime('now','-1 hour')`), not text.
2. Pass each user's `last_ip`, byte for byte, through `dcf-gate`. It admits
   canonical IPv4 addresses only, of the global, private and shared (100.64/10)
   classes; everything else is counted and refused.
3. Replace the whitelist set with the admitted addresses in one atomic nft
   transaction (`flush set` + `add element`). The same for `vip_permanent`
   (VIP users, no freshness requirement).
4. Run the telemetry script if `TELEMETRY_SCRIPT` is set.

Both sets are **reconciled**, not accumulated: if the query succeeds and nobody
qualifies, the set is flushed. If the query or the gate *fails*, the set is left
as it was (fail-static) and an `error` is logged with the reason. Whitelist
entries still expire on their own (the set has a 1 hour timeout, refreshed every
successful sync); `vip_permanent` has no timeout, so a database that stays
unreadable keeps the last VIP list until a sync succeeds.

### Firewall Rules

One `nft -f -` transaction on every start (all or nothing; safe to re-run):

```
add table ip dcf_firewall
add chain ip dcf_firewall input { type filter hook input priority 0; policy accept; }
add set ip dcf_firewall whitelist { type ipv4_addr; flags interval; timeout 1h; }
add set ip dcf_firewall vip_permanent { type ipv4_addr; flags interval; }
flush chain ip dcf_firewall input
add rule ip dcf_firewall input udp dport 7777 ip saddr @vip_permanent accept
add rule ip dcf_firewall input udp dport 7777 ip saddr @whitelist accept
add rule ip dcf_firewall input udp dport 7777 drop
```

The chain is rebuilt from scratch each start, so it is always exactly these three
rules for the current `DCF_PORT`; the sets keep their elements. The chain is the
watchdog's: rules added to it by hand are removed at the next start.

## Telemetry Output

Generates `/data/public/status.json` when `TELEMETRY_SCRIPT` is set:

```json
{
  "meta": {
    "updated_at": "2025-01-02T12:00:00Z",
    "node_role": "GATEWAY-01",
    "version": "2.4.0"
  },
  "system": {
    "load_avg": 0.42,
    "memory_pct": 35,
    "rx_bytes": 1234567890,
    "tx_bytes": 987654321,
    "uptime_secs": 86400
  },
  "network": {
    "active_tunnels": 12
  },
  "peers": [
    {
      "username": "player1",
      "is_vip": false,
      "tier": "paid",
      "status": "online"
    }
  ]
}
```

With `TELEMETRY_PEERS=count` the `peers` array is empty and a
`"peer_counts": {"total": 3, "online": 2}` object follows it; with `off`, `peers`
is empty and nothing else is said about users. Every number in the file is
checked against the JSON number grammar before it is written (a bad reading is
published as `0`, with a note on stderr), `WEB_ROOT` must be a real directory
owned by the running user that nobody else can write (otherwise the script
refuses), the file is written through `mktemp` and renamed into place with mode
644, and the database is opened read-only. "online" means seen in the last five
minutes, compared as instants.

## Requirements

- Linux with nftables support
- `CAP_NET_ADMIN` (and nothing else; no `NET_RAW`)
- Host network mode (for firewall access)
- Shared volume with DCF-ID (for SQLite database)
- A C compiler to build `gate/dcf-gate` (`make -C gate`), or the Docker image, which does it

### Dependencies

- bash
- nftables
- sqlite3
- gawk
- coreutils
- iproute2
- jq (optional, for JSON validation)
- `dcf-gate` (built from `gate/`)

## Integration with DCF-ID

DCF-Watchdog reads from the same SQLite database as DCF-ID:

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   DCF-ID    │────▶│   SQLite     │◀────│ DCF-Watchdog│
│  (writes)   │     │  identity.db │     │   (reads)   │
└─────────────┘     └──────────────┘     └─────────────┘
```

User flow:
1. User registers/logs in via DCF-ID
2. DCF-ID records user's IP in `last_ip` column
3. DCF-Watchdog reads active users and their IPs
4. Watchdog updates nftables whitelist
5. User's game client can now connect to DCF-SDK on port 7777

## Standalone Usage

```bash
# Build the gate once, then run directly (requires root for nftables)
make -C gate
sudo DB_PATH=/path/to/identity.db \
     WEB_ROOT=/var/www/html \
     DCF_PORT=7777 \
     ./dcf-watchdog.sh
```

## Troubleshooting

### Check firewall rules
```bash
nft list table ip dcf_firewall
nft list set ip dcf_firewall whitelist
```

### View logs
```bash
docker logs dcf-watchdog -f
```

### Manual whitelist add
```bash
nft add element ip dcf_firewall whitelist { 192.168.1.100 }
```
(Lasts until the next sync: the whitelist is replaced from the database every cycle.)

### Clear whitelist
```bash
nft flush set ip dcf_firewall whitelist
```

## Security changes

What changed in behaviour, in one place (each has a regression test in `tests/`;
the ids are the findings they answer):

| id | before | now |
|---|---|---|
| W1 | rules added one `nft add rule` at a time behind a `grep "udp dport $DCF_PORT"`; a kill between the accept rules and the `drop` left a chain that accepts, and every later start saw the grep hit and never added the drop; port 777 matched 7777 | one `nft -f -` transaction per start (table, chain, sets, `flush chain`, the three rules). All or nothing, re-runnable, and a start on top of a half-built chain completes it. The chain is rebuilt each start (see "Firewall Rules") |
| W2 | `vip_permanent` was only rewritten while at least one VIP remained: the last revoked VIP stayed whitelisted forever; nft errors were discarded (`2>/dev/null`, `\|\| true`) | both sets are reconciled every cycle (VIP was every 6th: revocation now takes one `SYNC_INTERVAL`, not six). A successful empty result flushes; a failed query or gate keeps the previous set and logs `error`; every nft failure is logged with nft's own text (bounded) |
| W3 | `validate_ipv4` accepted `1.2.3.08` (bash arithmetic on `08` errors and the error reads as "not above 255"); nft then rejected the whole batch, silently, and the whitelist stopped updating for everyone; `010.2.3.4` passed and nft read it as octal, **8.2.3.4**; whitespace was stripped from inside the value; loopback, multicast, `0.0.0.0` and broadcast were whitelisted | `last_ip` goes to `dcf-gate` byte for byte (as hex, so a newline or NUL inside a value cannot split or truncate it). Only canonical dotted quads of the global, private and shared classes pass; nothing is stripped; duplicates collapse; at most 4096 addresses per batch (the rest are counted and logged at `error`); rejected counts are logged |
| W4 | `DCF_PORT="7777 accept #"` turned all three rules into an unconditional accept (nft joins its argument words and `#` starts a comment); `SYNC_INTERVAL=0` busy-looped (67 syncs in 2 s measured); `LOG_LEVEL` unchecked | `DCF_PORT`, `SYNC_INTERVAL`, `LOG_LEVEL` are validated first; a bad value exits 64 before nft is touched |
| W5 | `last_seen >= datetime('now','-1 hour')` compared RFC 3339 text (`...T...+00:00`) with SQLite's `YYYY-MM-DD HH:MM:SS` as strings: `T` sorts above the space, so any row dated today looked fresh, and `last_seen = 'garbage'` did too | `datetime(last_seen) >= datetime('now','-1 hour')`; NULL and unparseable values are stale. The same fix for "online" in the telemetry |
| W6 | temp file `.status.json.tmp.$$` (predictable) written by root into the web volume through `cat >` (follows a pre-created symlink); `status.json` always listed every username; numbers from `/proc`, `free`, `/sys` and `nft` were pasted into the JSON unchecked | `mktemp` (unpredictable name, 0600), `WEB_ROOT` must be a real directory owned by the running user and not group/world-writable (else exit 1; this is stricter than the symlink check alone, deliberately), numbers validated, `TELEMETRY_PEERS=names\|count\|off` (default `names`, unchanged), `sqlite3 -readonly` |
| W7 | log lines were built by interpolation (a quote, backslash or newline in a value broke the JSON or forged a second record); `TELEMETRY_SCRIPT` ran as root if it was merely executable; the image carried `curl` and `python3` unused, built nothing, had no health check, and the README asked for `NET_RAW` | `log()` escapes `"`, `\`, newline, CR, tab and all other control characters; `TELEMETRY_SCRIPT` must pass the file check above (and exit 64 at start if not); multi-stage Dockerfile building the single static `dcf-gate`, no `curl`/`python3`, `HEALTHCHECK` (`dcf-healthcheck.sh`); README no longer asks for `NET_RAW` |

Other behaviour a caller may notice: the first sync now happens once, at the top
of the loop (it used to run once before the loop and again at its first turn);
a failed sync no longer ends the process at startup, it is logged and retried;
`init_firewall` no longer says "Created table/chain/set" (one line says the
ruleset was installed); `DCF_WATCHDOG_ONCE=1` and sourcing `dcf-watchdog.sh` /
`dcf-telemetry.sh` are new; both scripts are now executable in git.

## The quota rule exists twice

"Within the free tier, or the balance covers the overage" is decided here, in
SQL, and in DCF-ID, in Rust. They must agree, and nothing makes them. The
constants, as they stand in DCF-ID's committed `src/main.rs` (its hardening work
moves them to a `billing` module; the values are the same there):

| meaning | DCF-ID | here |
|---|---|---|
| free tier | `FREE_TIER_BYTES = 134_217_728` (128 MiB) | `FREE_BYTES="134217728"` |
| price | `PRICE_PER_GB = 0.05` per `BYTES_PER_GB = 1_073_741_824.0` | `PRICE_FACTOR="4.65661287e-11"` |
| per byte | `PRICE_PER_BYTE = 0.05 / 1073741824.0` = `4.656612873077393e-11` | `4.65661287e-11` |

The shell constant is the Rust one **truncated to nine significant digits**: it
is smaller by `3.08e-20` per byte (a relative `6.6e-10`). The watchdog therefore
under-charges very slightly: one byte past the free tier costs `4.65661287e-11`
here against `4.656612873077393e-11` there, 1 TiB of overage costs `$51.199999966`
here against `$51.200000000` there (`$3.4e-8` apart), and a balance of `$1.00`
admits about 14 bytes more here than DCF-ID would. That is far below anything
billing resolves; it is documented, not "fixed", because the real defect is that
the number is written twice. Any change to either side must change both
(`[OPEN]`: have DCF-ID publish the constants, or pass them to the query as bound
parameters).

## Building and testing

```bash
make -C gate            # build gate/dcf-gate with a C compiler; runs its selftest
make test               # = tests/run.sh: the whole suite
tests/run.sh t_sync     # one file
make check-gate         # re-emit the vendored C and compare (needs EXSECUTOR=...; else [skip])
```

`tests/run.sh` needs bash, python3, the `sqlite3` CLI (it fetches one from
nixpkgs if missing and nix is present), `jq`, `gcc`, and `nft`. If a throwaway
network namespace with a working nf_tables is available (`unshare -n nft add
table ip x`), every nft test runs against the **real kernel** in its own
namespace and cannot touch the host's rules (mode `real`). Otherwise the suite
runs in mode `shim`, with `nft` replaced by a recorder: it then checks what the
scripts *send*, skips the rest and says so. Each test file prints its mode.

## What was run, and what was not

Run (mode `real`, nft 1.0.9, kernel 6.18, bash 5.2, sqlite3 CLI 3.53.3 and
python's libsqlite 3.45.1, jq 1.7, shellcheck 0.11): `tests/run.sh`, whole suite,
see the commit that finishes this work for the totals; the tests for W1-W7 were
written first and **failed** on the unmodified scripts (94 failing checks), then
passed after the fixes. Also measured, with the real nft in a namespace:

* nft **rejects** `1.2.3.08` ("Could not resolve hostname"); it **accepts**
  `1.2.3.4 ` with a trailing space and `01.2.3.4`; it reads `010.2.3.4` as
  `8.2.3.4` and `011.2.3.4` as `9.2.3.4`; one rejected element fails the whole
  `nft -f -` batch and leaves the set as it was (`tests/t_nft_facts.sh`);
* a full cycle (init, both syncs, telemetry) succeeds with `CAP_NET_ADMIN` as the
  only capability in the permitted, effective and bounding sets
  (`tests/t_caps.sh`, via `setpriv`), against a database owned by another uid.
  `NET_RAW` is not needed;
* SQLite's `datetime()` parses chrono's `2026-10-09T01:22:33.123456789+00:00`
  (nine digits, `+00:00`), `Z` and other offsets, in the 3.53.3 CLI and in 3.45.1.

Not run:

* `[UNTESTED]` the Docker image: there is no docker here. The Dockerfile's build
  (musl, `-static-pie`) and `HEALTHCHECK` are unbuilt; the same `make` was
  linked `-static-pie` against glibc and `dcf-healthcheck.sh` is tested directly.
* `[UNTESTED]` Alpine's own versions (sqlite 3.48, nftables 1.0.9 is the one
  measured, bash 5.2).
* `[UNTESTED]` a database in WAL mode opened `-readonly` by a root with
  `--cap-drop ALL` (no `DAC_OVERRIDE`): a database file or directory that only
  its writer (DCF-ID's uid) can read will not be readable. The test used a 0644
  database owned by uid 1000.
* `[UNTESTED]` more than one watchdog on one host, and the daemon's signal
  handling (`SIGTERM` during a `sleep` is delivered when the sleep ends, as
  before).
* The vendored gate was exercised here through the CLI only
  (`tests/t_gate_cli.py`: 99,067-candidate corpus, hostile inputs, framing,
  1 MiB lines, 150,000 lines, ASan+UBSan; `tests/t_gate_mutants.py`: 21 host
  mutants, all killed). Its own differential suite (1,042,480 cases, 14 gate
  mutants) is Exsecutor's `examples/dcf_net_gate/proba_c.sh`; it was run
  against the same compiler build as the vendored C and passed.

Known limits, unchanged:

* The chain is `ip` (IPv4) only. UDP over IPv6 is not filtered by this table at
  all. `[OPEN]`
* `policy accept` with a `drop` for one port: while the watchdog has not yet
  installed its ruleset (or after someone deletes the table), the port is open.
  The health check notices a missing drop rule; nothing re-installs it until the
  next start.
* A `last_seen` in the future counts as fresh. `[OPEN]`
* `log()` escapes control characters, quote and backslash but does not validate
  UTF-8: bytes that are not valid UTF-8 pass through (everything the watchdog
  itself logs from the database is ASCII-escaped by the gate). `[OPEN]`
* A pre-existing `dcf_firewall` chain with a different hook priority, or a set
  with different flags, makes the install transaction fail (nft: "File exists");
  the failure is logged and the start is refused. Delete the table
  (`nft delete table ip dcf_firewall`) to let the watchdog recreate it.
* Licence: the vendored C is derived from GPL-3.0-or-later Exsecutor source.
  Whether it may ship in this BSD-3-Clause repository is the owner's decision,
  **pending** (`gate/PROVENANCE.md`).

## License

BSD 3-Clause License

Copyright (c) 2024-2025, DeMoD LLC

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
