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
openwrt-edge-agent/
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

## Automated Releases (GitHub Actions)
Release workflow:
- file: `.github/workflows/release.yml`
- trigger: push a tag like `v0.1.0`
- result: GitHub Release with attached assets:
  - `net_filter-armv7`
  - `net_filter-armv7.sha256`

Create a new release tag from local:
```sh
git tag v0.1.0
git push origin v0.1.0
```

Manual deployment option:
- `workflow_dispatch` supports `deploy_to_router=true`
- deploy job is designed for a self-hosted runner inside the same network as the router
- required GitHub secrets for deploy job:
  - `ROUTER_SSH_TARGET` (example: `root@192.168.1.1`)
  - `ROUTER_AUTH_MODE` (`key` or `password`)
  - `ROUTER_PASSWORD` (only if password mode is used)

### Self-Hosted Runner Deployment (Validated Setup)
1. In GitHub repo settings, add secrets:
   - `ROUTER_SSH_TARGET=root@192.168.1.1`
   - `ROUTER_AUTH_MODE=key`
   - `ROUTER_PASSWORD` optional (not needed for key mode)
2. Create and start a self-hosted runner for this repository on a machine in the same LAN as router (macOS/Linux).
3. Configure SSH key auth from runner machine to OpenWrt.
4. Run workflow manually with `deploy_to_router=true`.

Important OpenWrt note:
- On this setup, Dropbear uses `/etc/dropbear/authorized_keys`.
- Copy public key from runner machine using:

```sh
cat ~/.ssh/id_ed25519.pub | ssh root@192.168.1.1 "umask 077; mkdir -p /etc/dropbear; cat > /etc/dropbear/authorized_keys; chmod 600 /etc/dropbear/authorized_keys"
ssh root@192.168.1.1 "/etc/init.d/dropbear restart"
```

Verify key-only auth:
```sh
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes root@192.168.1.1 "echo ok"
```

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
