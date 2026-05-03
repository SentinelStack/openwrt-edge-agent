# Development Notes

## Cross-Compilation Strategy
The agent is built on macOS using Docker and the OpenWrt toolchain for:
- OpenWrt 23.05.3
- target `mvebu/cortexa9`
- arch `arm_cortex-a9_vfpv3-d16`

This ensures generated binaries are compatible with router runtime (`armv7l`).

## Why Build Is Not Done Directly On Router
OpenWrt router images are lightweight and usually do not include full build toolchains (`gcc`, `make`, headers). Building directly on router is less reproducible and can consume limited device resources.

## Why Docker Uses `--platform linux/amd64` On Apple Silicon
The OpenWrt toolchain archive used in this project is Linux x86_64. On Apple Silicon hosts, Docker must run amd64 containers to execute the toolchain binaries correctly.

## Why `scp -O` Is Used
OpenWrt commonly lacks `/usr/libexec/sftp-server` by default. Modern `scp` may attempt SFTP mode first and fail. `scp -O` forces legacy SCP protocol, which works reliably for this environment.

## Why Local Router Processing Matters
Running capture, parsing, statistics, and anomaly detection on the router:
- reduces backend compute load
- reduces network bandwidth for telemetry export
- enables immediate local detection/alerting even without backend connectivity

## Useful Commands
```sh
ssh root@192.168.1.1
ip a
opkg update
tcpdump -D
/root/openwrt-agent
/root/openwrt-agent --tcp
/root/openwrt-agent --udp
```
