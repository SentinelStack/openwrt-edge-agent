# openwrt-c

`openwrt-c` is the OpenWrt router-side traffic processing agent for a bachelor thesis IDS/IPS project.

The current focus is local processing on the OpenWrt device itself. Backend, AI, MISP, web dashboard, iOS app, CI/CD expansion, and Nexus integration are future extensions.

## Current Features (Router-Side)
- Raw packet capture with `AF_PACKET` + `SOCK_RAW`
- Ethernet/IPv4/TCP/UDP parsing
- Local TCP/UDP traffic processing directly on router
- Local traffic statistics every 5 seconds
- Local anomaly detection with lightweight threshold rules
- Local stdout alerts/logs

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
[ALERT] Possible UDP flood detected: udp_packets=230 in last 5 seconds
```
