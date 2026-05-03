# OpenWrt IDS/IPS Thesis Architecture

This repository contains the first module of a larger OpenWrt-based intelligent IDS/IPS platform.

## 1) OpenWrt Agent (C)
- Captures packets using raw sockets on the router
- Filters TCP/UDP traffic
- Extracts lightweight traffic features for later analysis

## 2) Backend
- Receives metrics and alert events from the agent
- Stores events for querying and history
- Integrates MISP threat intelligence for enrichment

## 3) AI Component
- Summarizes alerts into short incident reports
- Categorizes attack patterns
- Explains incidents in human-readable language

## 4) Web Dashboard
- Shows latest attacks
- Displays traffic statistics
- Provides detailed alert views

## 5) iOS App
- Mobile-friendly operational view
- Push notifications for important alerts

## 6) DevOps
- Docker-based reproducible cross-compilation
- GitHub Actions planned for CI/CD
- Nexus planned for versioned artifact storage

## High-Level Diagram

```text
                     +--------------------+
                     |    iOS App         |
                     | notifications/view |
                     +---------+----------+
                               |
                               v
 +------------------+   +------+-------+   +----------------------+
 | OpenWrt Agent C  +-->+   Backend    +<->+ MISP Threat Intel    |
 | capture/filter   |   | API + Store  |   | enrichment context   |
 +--------+---------+   +------+-------+   +----------------------+
          |                    |
          |                    v
          |            +-------+--------+
          |            | AI Component   |
          |            | summarize/class|
          |            +-------+--------+
          |                    |
          v                    v
      Router Traffic     +-----+------+
                         | Web Dashboard|
                         | attacks/stats|
                         +-------------+
```
