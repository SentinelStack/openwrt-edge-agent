# openwrt-c

`openwrt-c` is the OpenWrt router-side traffic processing agent for a bachelor thesis IDS/IPS project.

The agent processes traffic locally on the OpenWrt device and uploads processed
telemetry to the `ids-platform-backend` REST API. AI, MISP, web dashboard, iOS
app, CI/CD expansion, and Nexus integration are future extensions.

## Current Features (Router-Side)
- Raw packet capture with `AF_PACKET` + `SOCK_RAW`
- Ethernet/IPv4/TCP/UDP parsing
- Local TCP/UDP traffic processing directly on router
- Local traffic statistics every 5 seconds
- Per-flow (source/destination/port) top-talker tracking per window
- Local anomaly detection with lightweight threshold rules
- Local stdout alerts/logs
- Telemetry upload to the `ids-platform-backend` REST API (device registration,
  traffic windows, alerts with full source/destination, heartbeats)

## Target Environment
- Router: Linksys WRT3200ACM
- OpenWrt: 23.05.3
- Target: `mvebu/cortexa9`
- Architecture package target: `arm_cortex-a9_vfpv3-d16`
- Runtime `uname -m`: `armv7l`

## Repository Structure
```text
openwrt-c/
├── src/
│   ├── main.c
│   ├── packet_capture.c
│   ├── packet_capture.h
│   ├── packet_parser.c
│   ├── packet_parser.h
│   ├── traffic_stats.c
│   ├── traffic_stats.h
│   ├── anomaly_detector.c
│   ├── anomaly_detector.h
│   ├── flow_table.c
│   ├── flow_table.h
│   ├── http_client.c
│   ├── http_client.h
│   ├── backend_client.c
│   ├── backend_client.h
│   ├── iso_time.c
│   ├── iso_time.h
│   ├── logger.c
│   └── logger.h
├── scripts/
│   ├── deploy.sh
│   └── run.sh
├── docs/
│   ├── architecture.md
│   └── development-notes.md
├── Dockerfile
├── Makefile
├── README.md
├── .gitignore
└── LICENSE
```

## Why Docker Is Used
OpenWrt toolchains are Linux x86_64 based, while development is done on macOS. Docker provides reproducible cross-compilation and avoids dependency drift on host machines.

## Why Processing Is Done On Router
The OpenWrt router performs first-layer analysis at the edge. This reduces backend load and network bandwidth by processing packets where traffic is observed.

## What Traffic The Router Can See
The router can analyze only traffic that passes through it or traffic generated locally on the router itself.

## Prerequisites
- Docker Desktop
- SSH access to router (`root@192.168.1.1` by default)
- OpenWrt installed on target router

## Router Connection Settings
Create a local settings file:

```sh
cp config/router.env.example config/router.env
```

Default values:
- `ROUTER=root@192.168.1.1`
- `ROUTER_AUTH_MODE=key` (recommended)

If using password mode, install `sshpass` and set `ROUTER_PASSWORD`.

## Build
```sh
make docker-build
make build
make check
```

Build output binary:
- `openwrt-agent`

## Deploy
```sh
make deploy
```

Deploy copies binary using `scp -O` to:
- `root@192.168.1.1:/root/openwrt-agent`

Then remote chmod:
- `chmod +x /root/openwrt-agent`

## Backend Integration

When `BACKEND_HOST` is set, the agent uploads processed telemetry to the
`ids-platform-backend` REST API. When it is unset, the agent runs in local-only
mode (stdout logging, no HTTP). Networking failures never stop packet capture —
the agent degrades to local-only mode and keeps running.

### Configuration

Add the backend variables to `config/router.env` (see `config/router.env.example`).
`scripts/run.sh` forwards any that are set to the agent process on the router.

| Variable          | Required | Default                 | Purpose                                             |
| ----------------- | -------- | ----------------------- | --------------------------------------------------- |
| `BACKEND_HOST`    | yes      | —                       | Backend host/IP. Enables uploads. Use the LAN IP of the backend machine, not `localhost`. |
| `BACKEND_PORT`    | no       | `8080`                  | Backend port                                        |
| `DEVICE_ID`       | no       | assigned by backend     | Pre-assigned device id; otherwise the backend issues one at registration |
| `DEVICE_ID_FILE`  | no       | `/etc/openwrt-agent.id` | File the assigned `deviceId` is persisted to and reloaded from, giving a stable identity across restarts |
| `DEVICE_NAME`     | no       | `OpenWrt Edge Agent`    | Human-readable device name                          |
| `DEVICE_IP`       | no       | `192.168.1.1`           | Router IP reported to the backend                   |
| `DEVICE_FIRMWARE` | no       | `OpenWrt 23.05.3`       | Firmware version string                             |
| `DEVICE_MODEL`    | no       | `Linksys WRT3200ACM`    | Hardware model string                               |

### What gets sent

On startup the agent calls `POST /api/devices/register` and stores the returned
`deviceId`, persisting it to `DEVICE_ID_FILE` so the next start reuses the same
identity instead of registering a brand-new device. Then, once per stats window
(every 5 seconds), it sends:

- `POST /api/traffic/stats` — the aggregated traffic window
- `POST /api/alerts` — one request per detected anomaly, including the
  **source/destination IP and ports** of the busiest matching flow (top talker)
  in that window, plus packet/byte counts and a description
- `POST /api/devices/{deviceId}/heartbeat` — liveness signal

Anomaly types map directly to the backend `AlertType` enum:

| Condition                        | `type`                | `severity` | `protocol` |
| -------------------------------- | --------------------- | ---------- | ---------- |
| UDP packets over threshold       | `UDP_FLOOD_SUSPECTED` | `HIGH`     | `UDP`      |
| TCP packets over threshold       | `TCP_SPIKE_SUSPECTED` | `MEDIUM`   | `TCP`      |
| Total bytes over threshold       | `HIGH_TRAFFIC_VOLUME` | `MEDIUM`   | `UNKNOWN`  |

The HTTP client is dependency-free (raw sockets, plain HTTP, no TLS) to match
the rest of the agent and keep the OpenWrt binary small.

## Run
Process TCP and UDP:
```sh
make run
```

Process TCP only:
```sh
make run-tcp
```

Process UDP only:
```sh
make run-udp
```

Direct CLI usage:
```sh
./openwrt-agent
./openwrt-agent --tcp
./openwrt-agent --udp
./openwrt-agent --help
```

## Example Output
Packet logs:
```text
[TCP] 192.168.1.100:52341 -> 93.184.216.34:80 size=74
[UDP] 192.168.1.1:48722 -> 8.8.8.8:53 size=90
```

5-second summary:
```text
[INFO] [STATS] total_packets=120 tcp=80 udp=40 total_bytes=64000 tcp_bytes=50000 udp_bytes=14000
```

Anomaly alerts:
```text
[ALERT] Possible UDP flood detected: udp_packets=230 in window
```

Backend telemetry (when `BACKEND_HOST` is set):
```text
[INFO] [BACKEND] target http://192.168.1.100:8080
[INFO] [BACKEND] device registered deviceId=7c9e6679-7425-40de-944b-e07fc1f90ae7
```
