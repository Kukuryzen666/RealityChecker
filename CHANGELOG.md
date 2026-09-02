# 📋 Changelog

All notable changes to **RealityChecker** are documented in this file.

## [v2.8.0] - 2026-09-02

### 🚀 Added
- **ASN Scanning (`--asn <number>`)**: Automatically query BGP routing tables via RIPE Stat and BGPView API to discover and scan all IPv4 prefixes for an entire Autonomous System.
- **Stealth & Anti-Detection Engine**:
  - `--delay <seconds>`: Adjustable rate-limiting with random jitter between connections.
  - `--shuffle`: Randomized IP target ordering to bypass firewall sequential port-scan heuristics (IDS/IPS).
- **Multi-TLS Version Support**: Detection of both modern **TLS 1.3** (VLESS-Reality) and **TLS 1.2** (Trojan, Shadowsocks-TLS, SNI Proxies).
- **Fix & Change Audit (`--check-fixed`)**: Dedicated inspection mode to audit whether previously identified hosts have fixed their SSL/TLS certificates, gone offline, or switched camouflage SNI domains.
- **Intelligent CDN Filter**: Automatic recognition and filtering of global Anycast/CDN edge nodes (Akamai, Cloudflare, Fastly, AWS CloudFront, Google, Microsoft, Qrator).
- **Batch SQLite Database**: High-efficiency batched writes storing strictly confirmed Reality/VPN hosts with hit counters (`hits`) and status tracking.
