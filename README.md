# smallerAnyTLS (`anytls-tiny`)

An ultra-compact (~25 KB) **AnyTLS v2** client written in pure C, specifically engineered for embedded Linux routers (such as OpenWrt) with strict flash storage and RAM constraints.

---

## 🌟 Why smallerAnyTLS?

Modern proxy clients (Sing-box, Xray, Clash, Mihomo, v2ray-core) are written in Go or Rust and compile to massive binaries ranging between **20 MB and 45 MB**.

Many legacy or compact consumer routers (e.g. Netgear, TP-Link, Xiaomi, GL.iNet) have only **4 MB, 8 MB, or 16 MB** total SPI flash memory, leaving merely **1 MB to 3 MB** of writable `/overlay` storage. On such devices, running standard Go/Rust proxy clients is completely impossible without external USB drives or extroot.

**smallerAnyTLS** solves this problem from scratch:
- **Binary Footprint**: **~25 KB** stripped (x86_64; about 10 KB once compressed in flash). Exact size varies by architecture.
- **Low RAM**: a few MB resident, most of it the shared OpenSSL libraries.
- **No Bundled TLS Library**: Loads the system OpenSSL (`libssl.so.3` or `libssl.so.1.1`) at runtime via `dlopen`, so the binary itself carries no crypto code.
- **All-in-One Networking**: Built-in SOCKS5 proxy, transparent TCP proxy (`SO_ORIGINAL_DST`), and anti-poisoning DNS-over-TCP forwarder.

---

## 🚀 Features

- **AnyTLS v2 Protocol**: Stream multiplexing, SHA-256 password authentication, settings negotiation, `cmdSYNACK` error handling, server alerts, and heartbeats with dead-session detection (see [Limitations](#-limitations)).
- **SOCKS5 Server**: Standard SOCKS5 listener (default port `1080`).
- **Transparent TCP Redirection (`SO_ORIGINAL_DST`)**: Seamlessly redirects outbound LAN/Wi-Fi TCP connections to port `1100` without requiring any client-side app on user devices.
- **Clean DNS Forwarder**: Listens on UDP port `5353` and tunnels DNS queries over TCP to a clean resolver (default `8.8.8.8:53`, configurable with `-n`) via AnyTLS, defeating DNS poisoning.
- **Built for slow links and busy LANs**: non-blocking I/O in both directions, frames batched into full TLS records, per-client buffering with backpressure (a slow Wi-Fi client no longer gets its downloads cut off mid-transfer), and automatic reconnect with backoff.
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
smallerAnyTLS - Ultra-lightweight AnyTLS v2 Client

Usage: anytls-tiny -s <server> -p <port> -k <password> -h <sni> [options]

Required:
  -s <host/ip>    Upstream AnyTLS server address or domain
  -p <port>       Upstream AnyTLS server port (e.g. 443)
  -k <password>   AnyTLS authentication password or UUID
  -h <sni>        TLS Server Name Indication (SNI, e.g. www.apple.com)

Optional:
  -l <port>       Local SOCKS5 proxy port (default: 1080, 0 = off)
  -r <port>       Transparent redirect port (SO_ORIGINAL_DST, default: 1100, 0 = off)
  -u <port>       DNS-over-TCP UDP listening port (default: 5353, 0 = off)
  -n <ip[:port]>  DNS resolver reached through the tunnel (default: 8.8.8.8:53)
  -b <ip>         Listen address for SOCKS5 and DNS (default: 0.0.0.0)
  -d              Run as background daemon
```

**Example:**
```bash
./anytls-tiny -s your-server.com -p 443 -k your-uuid -h www.microsoft.com -d
```

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
	option socks_port '1080'
	option redir_port '1100'
	option dns_port '5353'
	option dns_server '8.8.8.8:53'
	option listen_addr '0.0.0.0'
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

- **One TLS session for all connections.** The reference AnyTLS client (used by Mihomo / sing-box) keeps a pool of sessions and gives each concurrent connection its own. Here every connection shares one TCP connection, so packet loss on that link slows everything at once. A client that stops reading for long (over 256 KB behind for 10 s) is dropped so it can't stall the rest.
- **No padding scheme.** AnyTLS's traffic-shaping padding (`cmdWaste`, packet splitting) is not implemented, and the TLS ClientHello is OpenSSL's rather than a browser fingerprint. Traffic is therefore easier to classify than with Mihomo.
- **No certificate verification.** The server certificate is not checked (like `skip-cert-verify: true`). Someone who can intercept the connection could capture the password hash.
- **IPv4 and TCP only** (plus DNS). No IPv6 listener, no general UDP relay.

---

## 📄 License
Released under the [MIT License](LICENSE).
