# openwrt-c

`openwrt-c` is the OpenWrt embedded traffic analysis agent for a bachelor thesis project focused on an intelligent IDS/IPS platform.

Current feature set (first milestone):
- Raw socket packet capture on OpenWrt
- TCP/UDP packet filtering
- Basic flow line output:
  - source IP
  - source port
  - destination IP
  - destination port

Target environment:
- Router: Linksys WRT3200ACM
- OpenWrt: 23.05.3
- Target: `mvebu/cortexa9`
- Architecture package target: `arm_cortex-a9_vfpv3-d16`
- Runtime `uname -m`: `armv7l`

## Repository Structure
```text
openwrt-c/
├── .github/
│   └── workflows/
│       └── openwrt-agent-ci.yml
├── config/
│   └── router.env.example
├── docs/
│   ├── architecture.md
│   └── development-notes.md
├── scripts/
│   ├── deploy.sh
│   └── run.sh
├── src/
│   └── net_filter.c
├── .gitignore
├── Dockerfile
├── LICENSE
├── Makefile
└── README.md
```

## Prerequisites
- Docker Desktop
- SSH access to router (`root@192.168.1.1` by default)
- OpenWrt installed on target router

## Router Connection Settings
Create a local settings file:

```sh
cp config/router.env.example config/router.env
```

Then edit `config/router.env` as needed (router host, auth mode).

Notes:
- `ROUTER_AUTH_MODE=key` is recommended.
- `ROUTER_AUTH_MODE=password` requires `sshpass` installed locally.
- `config/router.env` is ignored by Git and should never contain production secrets in version control.

## Build
```sh
make docker-build
make build
make check
```

## CI (GitHub Actions)
On every push and pull request to `main`, GitHub Actions:
- builds the Docker toolchain image
- cross-compiles `net_filter`
- runs `file net_filter`
- uploads `net_filter` as a workflow artifact

## Deploy
```sh
make deploy
```

## Run
```sh
make run-tcp
make run-udp
```

## Test Traffic
Generate TCP traffic:
```sh
wget -O - http://example.com
```

Generate UDP traffic:
```sh
nslookup google.com 8.8.8.8
```

If traffic generated from your Mac does not appear, the Mac may not be routing through the OpenWrt device. The sensor sees traffic that passes through the router (or is generated locally on it).

## Roadmap
- Packet counters per second
- Per-port statistics
- Simple anomaly detection
- JSON export
- Backend integration
- AI summarization
- MISP integration
- Web dashboard
- iOS app
- CI/CD
- Nexus repository
