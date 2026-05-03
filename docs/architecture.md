# Edge-First Architecture (Current Scope)

This stage focuses on router-side processing. The OpenWrt agent performs the first analysis layer locally and generates immediate statistics and alerts.

Current in-scope components:
1. Packet capture on OpenWrt (`AF_PACKET`, `SOCK_RAW`)
2. Packet parser (Ethernet + IPv4 + TCP/UDP headers)
3. Local traffic statistics
4. Local anomaly detector
5. Local alert output (stdout logger)

Future components (out of current implementation scope):
- Backend API and storage
- AI summarization/classification
- MISP integration
- Web dashboard
- iOS app

## Data Flow

```text
OpenWrt Router
  -> Packet Capture
  -> Packet Parser
  -> Local Statistics
  -> Local Anomaly Detector
  -> Alerts
  -> Future Backend / AI / MISP / Web / iOS
```

## Notes
- Analysis happens on router first to reduce backend load and unnecessary traffic export.
- Later backend services should receive compact alerts/statistics instead of raw packet streams.
