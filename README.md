# DCF-Watchdog: Firewall Sync & Telemetry

A lightweight daemon that synchronizes user authentication state with kernel-level firewall rules. Enables real-time IP whitelisting for authenticated game clients.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/F1F11PNYX4)

## Features

- **Firewall Synchronization**: Syncs SQLite user database with nftables rules
- **Dynamic Whitelisting**: Authenticated users' IPs are automatically allowed
- **VIP Bypass**: Permanent whitelist for privileged users
- **Telemetry Generation**: Produces `status.json` for dashboard consumption
- **Low Overhead**: Shell-based, minimal resource usage
- **Automatic Cleanup**: Expired sessions removed from whitelist

## Quick Start

### Docker

```bash
docker pull alh477/dcf-watchdog:latest

docker run -d \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --network host \
  -e DB_PATH=/data/identity.db \
  -e WEB_ROOT=/data/public \
  -e DCF_PORT=7777 \
  -v dcf-data:/data \
  alh477/dcf-watchdog:latest
```

### Docker Compose

```yaml
services:
  dcf-watchdog:
    image: alh477/dcf-watchdog:latest
    cap_add:
      - NET_ADMIN
      - NET_RAW
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
| `LOG_LEVEL` | `info` | Logging verbosity (debug/info/warn/error) |

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

1. Query active users from SQLite (balance > 0 OR within free tier OR VIP)
2. Get their last known IP addresses
3. Update nftables whitelist set
4. Generate `status.json` with system metrics

### Firewall Rules

```bash
# Table structure created on startup
nft add table ip dcf_firewall
nft add set ip dcf_firewall whitelist { type ipv4_addr; flags interval; timeout 1h; }
nft add set ip dcf_firewall vip_permanent { type ipv4_addr; flags interval; }

# Rules
nft add rule ip dcf_firewall input udp dport 7777 ip saddr @vip_permanent accept
nft add rule ip dcf_firewall input udp dport 7777 ip saddr @whitelist accept
nft add rule ip dcf_firewall input udp dport 7777 drop
```

## Telemetry Output

Generates `/data/public/status.json`:

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

## Requirements

- Linux with nftables support
- `NET_ADMIN` and `NET_RAW` capabilities
- Host network mode (for firewall access)
- Shared volume with DCF-ID (for SQLite database)

### Dependencies

- bash
- nftables
- sqlite3
- gawk
- coreutils
- iproute2
- jq (optional, for JSON validation)

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
# Run directly (requires root for nftables)
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

### Clear whitelist
```bash
nft flush set ip dcf_firewall whitelist
```

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
