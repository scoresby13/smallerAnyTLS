# smallerAnyTLS (`anytls-tiny`)

An ultra-compact (~35 KB) **AnyTLS v2** client written in pure C, specifically engineered for embedded Linux routers (such as OpenWrt) with strict flash storage and RAM constraints.

---

## 🌟 Why smallerAnyTLS?

Modern proxy clients (Sing-box, Xray, Clash, Mihomo, v2ray-core) are written in Go or Rust and compile to massive binaries ranging between **20 MB and 45 MB**.

Many legacy or compact consumer routers (e.g. Netgear, TP-Link, Xiaomi, GL.iNet) have only **4 MB, 8 MB, or 16 MB** total SPI flash memory, leaving merely **1 MB to 3 MB** of writable `/overlay` storage. On such devices, running standard Go/Rust proxy clients is completely impossible without external USB drives or extroot.

**smallerAnyTLS** solves this problem from scratch:
- **Binary Footprint**: **~35 KB** stripped (x86_64; about 14 KB once compressed in flash). Exact size varies by architecture.
- **Low RAM**: a few MB resident, most of it the shared OpenSSL libraries.
- **No Bundled TLS Library**: Loads the system OpenSSL (`libssl.so.3` or `libssl.so.1.1`) at runtime via `dlopen`, so the binary itself carries no crypto code.
- **All-in-One Networking**: Built-in SOCKS5 proxy, transparent TCP proxy (`SO_ORIGINAL_DST`), and anti-poisoning DNS-over-TCP forwarder.

---

## 🚀 Features

- **AnyTLS v2 Protocol**: Stream multiplexing over a session pool, SHA-256 password authentication, settings negotiation, `cmdSYNACK` error handling, server alerts, and heartbeats with dead-session detection (see [Limitations](#-limitations)).
- **SOCKS5 Server**: Standard SOCKS5 listener (default port `1080`).
- **Transparent TCP Redirection (`SO_ORIGINAL_DST`)**: Seamlessly redirects outbound LAN/Wi-Fi TCP connections to port `1100` without requiring any client-side app on user devices.
- **Clean DNS Forwarder**: Listens on UDP port `5353` and tunnels DNS queries over TCP to a clean resolver (default `8.8.8.8:53`, configurable with `-n`) via AnyTLS, defeating DNS poisoning.
- **Built for slow links and busy LANs**: non-blocking I/O in both directions, frames batched into full TLS records, per-client buffering with backpressure (a slow Wi-Fi client no longer gets its downloads cut off mid-transfer), and automatic reconnect with backoff.
- **Session pool**: like the reference client, each concurrent connection gets its own TLS session (an idle one is reused, newest first), so packet loss or a slow LAN client on one connection doesn't hold up the others. Sessions are capped (`-m`, default 8) and closed after sitting idle (`-i`, default 60 s); past the cap, connections share the least-busy session. DNS queries share a single session.
- **Full OpenWrt Integration**: Ready-to-use `procd` init script (`/etc/init.d/anytls`), UCI configuration (`/etc/config/anytls`), and `nftables` / `fw4` rule integration with `chnroute` bypass.

---

## 📦 Building

### 1. Native Build (Linux / x86_64)

```bash
git clone https://github.com/scoresby13/smallerAnyTLS.git
cd smallerAnyTLS
make
```

### 2. Cross-Compiling for OpenWrt (MIPS, ARM, AArch64)

**Option A, OpenWrt SDK package (recommended):** link the `openwrt/` directory into the SDK and build it as a normal package:

```bash
ln -s /path/to/smallerAnyTLS/openwrt /path/to/openwrt-sdk/package/anytls-tiny
cd /path/to/openwrt-sdk && make package/anytls-tiny/compile V=s
```

**Option B, toolchain directly:**

Point `CC` and `STAGING_DIR` to your OpenWrt SDK or toolchain:

```bash
# Example for MIPS 24Kc (ath79):
TOOLCHAIN="/path/to/toolchain-mips_24kc_gcc-12.3.0_musl"
export STAGING_DIR="$TOOLCHAIN"
export PATH="$TOOLCHAIN/bin:$PATH"

mips-openwrt-linux-musl-gcc -Os -pipe -mno-branch-likely -mips32r2 -mtune=24kc -msoft-float -s \
    -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wl,--gc-sections \
    src/anytls-tiny.c -ldl -o anytls-tiny
```

---

## 🔧 CLI Usage

```
smallerAnyTLS - Ultra-lightweight AnyTLS v2 Client with Multi-Server Pool

Usage: anytls-tiny -s <host[:port[:sni]]> [-s ...] -k <password> [options]

Required options:
  -s <server>     Upstream AnyTLS server address (host[:port[:sni]], repeatable)
  -k <password>   AnyTLS authentication password or UUID

Optional:
  -p <port>       Port for servers given without one (default: 443)
  -h <sni>        SNI for servers given without one (default: the server host)
  -l <port>       Local SOCKS5 proxy port (default: 1080, 0 = off)
  -r <port>       Transparent redirect port (SO_ORIGINAL_DST, default: 1100, 0 = off)
  -u <port>       DNS-over-TCP UDP listening port (default: 5353, 0 = off)
  -n <ip[:port]>  DNS resolver reached through the tunnel (default: 8.8.8.8:53)
  -b <ip>         Listen address for SOCKS5 and DNS (default: 0.0.0.0)
  -m <n>          Max TLS sessions to the server (1-32, default: 8)
  -i <seconds>    Close sessions idle for this long (default: 60)
  -w <n>          Idle sessions kept open past the timeout (default: 1)
  -d              Run as background daemon
```

**Examples:**
```bash
# One server
./anytls-tiny -s your-server.com -p 443 -k your-uuid -h www.microsoft.com -d

# Several servers with automatic failover, each as host:port:sni
./anytls-tiny -s us.example.com:443:www.microsoft.com -s sg.example.com:8443 -k your-uuid -d
```

**Failover:** new connections go to the first server until connecting to it fails, a session drops right after connecting, or a session gets no reply for 45 s; then they move to the next one. When every server has failed in a row, it waits 1, 2, 4 … up to 30 s between rounds. It does not switch back to the first server on its own.

---

## 🌐 OpenWrt Deployment Guide

### Step 0: Check for OpenSSL
`anytls-tiny` needs the OpenSSL shared libraries on the router:
```bash
ls /usr/lib/libssl.so* /usr/lib/libcrypto.so*
```
Many stock OpenWrt images ship mbedTLS or wolfSSL instead. If nothing is listed, install `libopenssl3` (`opkg install libopenssl3`, or `apk add libopenssl3` on newer releases). It needs much more flash than `anytls-tiny` itself, so check free space with `df -h /overlay` first.

### Step 1: Install Binary
Copy `anytls-tiny` to your router's `/usr/bin/anytls-tiny`:
```bash
scp anytls-tiny root@192.168.1.1:/usr/bin/anytls-tiny
ssh root@192.168.1.1 "chmod +x /usr/bin/anytls-tiny"
```

### Step 2: Install Configuration & Service
Copy the included files to the router:
```bash
scp openwrt/files/etc/config/anytls root@192.168.1.1:/etc/config/anytls
scp openwrt/files/etc/init.d/anytls root@192.168.1.1:/etc/init.d/anytls
ssh root@192.168.1.1 "chmod +x /etc/init.d/anytls"
```

Edit `/etc/config/anytls` on the router with your node details:
```uci
config anytls 'main'
	option enabled '1'
	option server 'your-server.com'
	option port '443'
	option password 'your-password'
	option sni 'www.apple.com'
	# For failover, replace server/port/sni with one line per server:
	# list server 'us.example.com:443:www.apple.com'
	# list server 'sg.example.com:443:www.apple.com'
	option socks_port '1080'
	option redir_port '1100'
	option dns_port '5353'
	option dns_server '8.8.8.8:53'
	option listen_addr '0.0.0.0'
	option max_sessions '8'
	option idle_timeout '60'
	option min_idle '1'
```

> The SOCKS5 port has no authentication. OpenWrt's default firewall blocks it from the WAN side. On other machines, set `listen_addr` / `-b` to `127.0.0.1` unless LAN devices need it.

Enable and start the service:
```bash
/etc/init.d/anytls enable
/etc/init.d/anytls start
```

---

### Step 3: Transparent Proxying & DNS Split

#### 1. Anti-Poisoning DNS (via `dnsmasq`)
In `/etc/config/dhcp`, ensure dnsmasq reads configuration snippets:
```uci
set dhcp.@dnsmasq[0].confdir='/etc/dnsmasq.d'
commit dhcp
```
Place gfwlist domain rules in `/etc/dnsmasq.d/gfwlist.conf` pointing to `127.0.0.1#5353`:
```
server=/.google.com/127.0.0.1#5353
server=/.youtube.com/127.0.0.1#5353
server=/.github.com/127.0.0.1#5353
```
Restart dnsmasq:
```bash
/etc/init.d/dnsmasq restart
```

> **Don't route the AnyTLS server's own domain through `127.0.0.1#5353`.** The tunnel has to resolve that name before it is up, so it would wait on itself. Leave the server domain out of the list, or put its IP address in `server`.

#### 2. nftables / firewall4 Redirection
Generate `/etc/nftables.d/20-anytls.nft` using the included script and your domestic IP CIDR list (`chnroute.txt`):
```bash
python3 openwrt/scripts/gen-nft-chnroute.py chnroute.txt /etc/nftables.d/20-anytls.nft <your_server_ip>
fw4 reload
```

Now, all non-domestic IPv4 TCP traffic from Wi-Fi and LAN clients will transparently route through `anytls-tiny`! IPv6 traffic is left untouched (it goes out directly), so disable IPv6 on the LAN if everything must go through the tunnel.

---

## ⚠️ Limitations

- **Bounded session pool.** Like the reference client (used by Mihomo / sing-box), each concurrent connection gets its own TLS session, but only up to `-m` sessions (default 8) to keep router RAM in check. Past that, connections share sessions and the old trade-offs come back for the ones that share: packet loss on that TCP connection slows all of them, and a LAN client that falls more than 256 KB behind pauses its session until it catches up. Any client that stays that far behind for 10 s is dropped. Each busy session costs OpenSSL's per-connection state, 128 KB of frame buffers (released once it goes idle) and up to 256 KB of backlog per slow client (about 2 MB in total). In testing, 8 busy sessions peaked about 5 MB above the single-session version, so lower `-m` on routers with very little free RAM.
- **Blocking DNS lookup of the server.** The server's hostname is resolved with `getaddrinfo`, which blocks the event loop while it runs. The result is cached for 10 minutes (and refreshed after a failed connect), so this is rare. Using the server's IP address avoids it.
- **TLS ClientHello fingerprint.** The client uses OpenSSL's ClientHello rather than a browser fingerprint (uTLS). Traffic is therefore easier to classify than with Mihomo, though the AnyTLS padding scheme (`cmdWaste`, packet splitting, runtime updates) is fully implemented to resist record-size analysis.
- **No certificate verification.** The server certificate is not checked (like `skip-cert-verify: true`). Someone who can intercept the connection could capture the password hash.
- **IPv4 and TCP only** (plus DNS). No IPv6 listener, no general UDP relay.

---

## 📄 License
Released under the [MIT License](LICENSE).
