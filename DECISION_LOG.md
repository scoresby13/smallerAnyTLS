# Project Architecture & Decision Log

> [!NOTE]
> This document tracks the core problems, goals, architectural decisions, and current runtime state for the OpenWrt router transparent gateway and `smallerAnyTLS` client. It is updated continuously across sessions to preserve context across compactions.

---

## 1. System Overview & Context

- **Router**: Netgear EX7300 v2 running **OpenWrt 23.05.5**
  - Architecture: MIPS 24Kc (`mips_24kc`), 128 MB RAM, 16 MB Flash
  - LAN Gateway: `192.168.2.1`
  - WAN / Parent Network: `192.168.0.0/24` (Apartment upstream)
- **Host Workstation**: Windows 11 PC (`192.168.2.165` / `192.168.2.215`)
- **Core Proxy**: [`smallerAnyTLS`](https://github.com/scoresby13/smallerAnyTLS) (`/usr/bin/anytls-tiny`)
  - Ultra-lightweight AnyTLS v2 client written in pure C (< 30 KB stripped binary).
  - Dynamically links OpenSSL runtime (`libssl.so.1.1` / `libcrypto.so.1.1`) from OpenWrt ROM.
  - Implements session pooling, non-blocking TLS I/O, SOCKS5 (port 1080), TCP Redir (port 1100), and DNS-over-TCP proxy (port 5353).

---

## 2. Main Goals

1. **Seamless Transparent Gateway**: Route non-China traffic through high-speed AnyTLS nodes while strictly bypassing domestic Chinese traffic, CDNs, and internal LANs.
2. **AI & Cloud Service Compatibility**: Ensure Google Cloud AI (Antigravity Companion), Anthropic Claude, Docker Hub, and Meta AI (muse.ai) connect reliably without regional blocks or DNS poisoning.
3. **Domestic Tool Compatibility**: Ensure remote access software (ToDesk, WeChat, Tencent services) connects directly inside China to prevent cross-border free-tier penalties.
4. **Embedded Resource Efficiency**: Maintain binary footprint under 30 KB and minimal RAM/CPU consumption without connection leaks.
5. **Privacy & Anonymity**: Ensure all public code and commits remain strictly anonymous (`scoresby13`).

---

## 3. Decision & Incident Log

### Incident 1: Docker Desktop & Muse.ai (Meta AI) Connection Failure
- **Problem**: `hub.docker.com/auth/desktop/redirect` timed out; `muse.ai` chat remained stuck at "Still sending".
- **Root Cause**: GFW DNS poisoning on foreign endpoints. Router's `dnsmasq` was falling back to ISP DNS (`192.168.1.1`).
- **Method/Fix**: Configured `dnsmasq` default upstream to the clean AnyTLS tunnel DNS (`127.0.0.1#5353` $\to$ Google DNS `8.8.8.8`) with `noresolv 1`.
- **Status**: **RESOLVED**. Verified `docker pull hello-world` and clean HTTP 200 responses.

### Incident 2: ToDesk Cross-Border Detection Block
- **Problem**: ToDesk displayed error: *"The current global connection free node is busy, please try later"* (当前跨国连接免费节点繁忙).
- **Root Cause**: Resolving `todesk.com` via foreign DNS assigned Tencent Cloud EdgeOne Hong Kong IPs (`43.135.x.x`), which diverted through the US VPN. ToDesk flagged the remote session as an international connection and blocked free users.
- **Method/Fix**:
  1. Created `/etc/dnsmasq.d/direct-domains.conf` pinning `todesk.com`, `todesk.cn`, `youqu.com`, and domestic platforms to AliDNS (`223.5.5.5`).
  2. Added Tencent Cloud EdgeOne CIDRs (`43.135.0.0/16`, `43.174.0.0/16`) to the `nftables` direct bypass set.
- **Status**: **RESOLVED**. ToDesk connects directly to Tencent Cloud Guangzhou (`106.55.81.126`) and local LAN (`192.168.2.170`).

### Incident 3: Antigravity `HTTP 400: User location is not supported`
- **Problem**: Antigravity agent queries failed with:
  ```json
  {
    "error": {
      "code": 400,
      "message": "User location is not supported for the API use.",
      "status": "FAILED_PRECONDITION"
    }
  }
  ```
- **Root Cause**: Failover in `anytls-tiny` cycled down to node `38.63.204.3:26014`, which exits via Tokyo, Japan (`203.10.99.76`, AS137409). Google Cloud AI Companion rejects Japan exit IPs for this API tier.
- **Method/Fix**: Audited all 0dcloud nodes from Clash configuration; identified 7 verified US nodes (Santa Clara, CA). Purged Japan and Singapore nodes from `/etc/config/anytls`.
- **Status**: **RESOLVED**. Router only cycles among 7 verified US California endpoints.

### Incident 4: Stream Table Saturation & Connection Drops
- **Problem**: Connections dropped intermittently; router syslog logged: `[anytls-tiny] Stream table full (256), dropping connection`.
- **Root Cause**: `anytls-tiny` only reaped idle streams when `pending > 0` (unwritten downstream buffer). Idle HTTP keep-alive connections (`pending == 0`) remained open indefinitely, filling all 256 slots and dropping new connection requests.
- **Method/Fix**:
  1. Doubled `MAX_STREAMS` from **256 to 512**.
  2. Added `time_t last_active` tracking to `stream_t` across all client/remote read, write, and flush calls.
  3. Added an automatic stream reaper in `periodic_tick()`: closes any stream idle for $\ge$ 180s (3 minutes) or stuck in handshake for $\ge$ 30s.
  4. Cross-compiled with MIPS musl toolchain in WSL (**28 KB** stripped), deployed to `/usr/bin/anytls-tiny`, and pushed to GitHub.
- **Status**: **RESOLVED**. Stream slots recycle automatically.

### Incident 5: 3-Minute Upstream Disconnection & Stalled Browsing
- **Problem**: ToDesk worked normally, but foreign websites (Google, Bing, Claude) intermittently stalled or timed out.
- **Root Cause**: Router syslog showed `upstream disconnected (err=1)` every 180 seconds. In `anytls-tiny.c`, heartbeats (`CMD_HEART_REQ`) were gated on `peer_version >= 2`. Since the upstream server does not send `CMD_SERVER_SETTINGS`, `peer_version` remained `0`, preventing keepalive heartbeats. The 0dcloud server dropped silent sessions after 180s, disrupting in-flight streams and DNS proxy queries.
- **Method/Fix**:
  1. Initialized `s->peer_version = 2` by default in `session_create()`.
  2. Added immediate `flush_tx(s)` on heartbeat queuing to keep sessions warm every 15s.
  3. Recompiled binary, deployed to `/usr/bin/anytls-tiny`, and pushed to GitHub (`10125fa`).
- **Status**: **RESOLVED**. Sessions remain permanently established.

### Incident 6: Upstream Entry IP Rotation & Dynamic DDNS Deadlock
- **Problem**: Next morning (Oct 28), all foreign sites stopped loading; `anytls-tiny` logs showed continuous `connect/handshake timed out` across all configured ports.
- **Root Cause**: 
  1. 0dcloud rotated its entry server cluster away from `38.63.204.3` to new IPs (`38.63.204.4`, `38.63.204.18`, `38.63.205.216`, etc.) managed under the DDNS hostname `v1ab.allidns.com`. Because `/etc/config/anytls` had static `38.63.204.3` hardcoded, all connections timed out.
  2. When attempting to use `v1ab.allidns.com` as server host, `anytls-tiny` deadlocked: `dnsmasq` forwarded all queries to `127.0.0.1#5353` (the AnyTLS tunnel), which could not resolve the upstream domain until the tunnel itself was connected.
- **Method/Fix**:
  1. Added `server=/allidns.com/223.5.5.5` to `/etc/dnsmasq.d/direct-domains.conf` so 0dcloud DDNS resolves immediately via AliDNS without relying on the tunnel.
  2. Updated `/etc/config/anytls` server entries to use `v1ab.allidns.com:<port>:www.apple.com`.
  3. Verified `38.63.204.0/22` in `nftables` already covers all dynamic entry IPs (`38.63.204.x` and `38.63.205.x`).
- **Status**: **RESOLVED**. Connected instantly to `38.63.205.216:26022` (Santa Clara CA); Google and Bing returning HTTP/2 200.

### Incident 7: 45-Second False "Dead Session" Drops & Premature Node Failover
- **Problem**: Connection struggled intermittently; browsing/API requests would stall every few seconds with dropped connections, requiring repeated retries.
- **Root Cause**:
  1. In `anytls-tiny.c`, `periodic_tick()` enforced a hardcoded `DEAD_TIMEOUT` of 45 seconds (`now - s->last_rx >= DEAD_TIMEOUT`).
  2. While `anytls-tiny` actively transmits `CMD_HEART_REQ` every 15s to keep the upstream carrier NAT mapping open, the 0dcloud AnyTLS server consumes keepalive frames without returning a response (`CMD_HEART_RESP`).
  3. Consequently, during any 45-second lull in incoming web payload (idle tabs, reading pages, or slow stream drains), `now - s->last_rx` exceeded 45s.
  4. `anytls-tiny` erroneously declared healthy sessions "dead" (`no data from server for 45s`), killed all multiplexed in-flight streams (5–11 client connections per kill), and repeatedly triggered upstream node failover.
  5. Additionally, `v1ab.allidns.com` resolved to expanded subnets (`38.6.0.0/16`, `38.12.0.0/16`) beyond the original `38.63.204.0/22` bypass range.
- **Method/Fix**:
  1. Removed `DEAD_TIMEOUT` from `anytls-tiny.c`. Silent/dead server detection is properly deferred to kernel TCP keepalive (`SO_KEEPALIVE`, `TCP_KEEPIDLE=30`, `TCP_KEEPINTVL=10`, `TCP_KEEPCNT=3`), write failures in `flush_tx()`, and clean idle session reaping via `expire_idle_sessions()` after 60s.
  2. Cross-compiled stripped 28 KB binary with MIPS musl toolchain in WSL (`27,908 bytes`) and deployed to `/usr/bin/anytls-tiny` on OpenWrt.
  3. Updated `/etc/nftables.d/20-anytls.nft` bypass range to `{ 38.6.0.0/16, 38.12.0.0/16, 38.63.0.0/16 }` and reloaded firewall.
- **Status**: **RESOLVED**. Sessions remain permanently stable; zero drops observed across idle cycles. Google and public endpoints returning clean HTTP 200 via verified US exit IP (`92.223.71.246`).

---

## 4. Current Configuration State

### Verified US Upstream Nodes (`/etc/config/anytls`)
| Port | Region | Exit IP | Provider |
| :--- | :--- | :--- | :--- |
| `26022` | Santa Clara, CA (US) | `92.223.71.246` | G-Core Labs |
| `26023` | Santa Clara, CA (US) | `217.28.137.42` | G-Core Labs |
| `26024` | Santa Clara, CA (US) | `92.223.71.148` | G-Core Labs |
| `26009` | Santa Clara, CA (US) | `37.9.33.40` | G-Core Labs |
| `26010` | Santa Clara, CA (US) | `217.28.137.235` | G-Core Labs |
| `26011` | Santa Clara, CA (US) | `37.9.33.86` | G-Core Labs |
| `26012` | Santa Clara, CA (US) | `92.223.71.89` | G-Core Labs |

### Firewall Direct Bypass Ranges (`/etc/nftables.d/20-anytls.nft`)
- `chnroute` (Mainland China IP blocks)
- Local subnets (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- AnyTLS server ranges (`38.6.0.0/16`, `38.12.0.0/16`, `38.63.0.0/16`)
- Tencent Cloud EdgeOne CDN (`43.135.0.0/16`, `43.174.0.0/16`)

---

## 5. Ongoing Tasks & Next Steps

1. **Long-Term Monitoring**: Verify `anytls-tiny` memory footprint and stream table health during prolonged high-connection workloads.
2. **Local Repository Synchronization**: Maintain `smallerAnyTLS` repository in sync with any upstream updates or feature enhancements.
3. **Periodic Decision Log Update**: Keep this document updated after every major configuration change or troubleshooting session.
