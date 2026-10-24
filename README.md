# smallerAnyTLS (`anytls-tiny`)

An ultra-compact (~15 KB) **AnyTLS v2** client written in pure C, specifically engineered for embedded Linux routers (such as OpenWrt) with strict flash storage and RAM constraints.

---

## 🌟 Why smallerAnyTLS?

Modern proxy clients (Sing-box, Xray, Clash, Mihomo, v2ray-core) are written in Go or Rust and compile to massive binaries ranging between **20 MB and 45 MB**.

Many legacy or compact consumer routers (e.g. Netgear, TP-Link, Xiaomi, GL.iNet) have only **4 MB, 8 MB, or 16 MB** total SPI flash memory, leaving merely **1 MB to 3 MB** of writable `/overlay` storage. On such devices, running standard Go/Rust proxy clients is completely impossible without external USB drives or extroot.

**smallerAnyTLS** solves this problem from scratch:
- **Binary Footprint**: **~15 KB** (stripped MIPS/ARM/x86 executable).
- **Runtime RAM**: **< 2 MB** resident set size (RSS).
- **Zero External Dependencies**: Dynamically links to the OpenSSL shared libraries already present in router firmware ROM (`/usr/lib/libssl.so.3` or `libssl.so.1.1`) using `dlopen`.
- **All-in-One Networking**: Built-in SOCKS5 proxy, transparent TCP proxy (`SO_ORIGINAL_DST`), and anti-poisoning DNS-over-TCP forwarder.

---

## 🚀 Features

- **AnyTLS v2 Protocol**: Full implementation of AnyTLS v2 stream multiplexing, token hashing (SHA-256), settings negotiation, frame padding, and periodic heartbeats.
- **SOCKS5 Server**: Standard SOCKS5 listener (default port `1080`).
- **Transparent TCP Redirection (`SO_ORIGINAL_DST`)**: Seamlessly redirects outbound LAN/Wi-Fi TCP connections to port `1100` without requiring any client-side app on user devices.
- **Clean DNS Forwarder**: Listens on UDP port `5353` and tunnels DNS queries over TCP to upstream clean resolvers (`8.8.8.8:53`) via AnyTLS, defeating DNS poisoning.
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

Point `CC` and `STAGING_DIR` to your OpenWrt SDK or toolchain:

```bash
# Example for MIPS 24Kc (ath79):
TOOLCHAIN="/path/to/toolchain-mips_24kc_gcc-12.3.0_musl"
export STAGING_DIR="$TOOLCHAIN"
export PATH="$TOOLCHAIN/bin:$PATH"

mips-openwrt-linux-musl-gcc -Os -pipe -mno-branch-likely -mips32r2 -mtune=24kc -msoft-float -s \
    src/anytls-tiny.c -ldl -o anytls-tiny
```

---

## 🔧 CLI Usage

```
smallerAnyTLS - Ultra-lightweight AnyTLS v2 Client (~15 KB)

Usage: anytls-tiny -s <server> -p <port> -k <password> -h <sni> [options]

Required:
  -s <host/ip>    Upstream AnyTLS server address or domain
  -p <port>       Upstream AnyTLS server port (e.g. 443)
  -k <password>   AnyTLS authentication password or UUID
  -h <sni>        TLS Server Name Indication (SNI, e.g. www.apple.com)

Optional:
  -l <port>       Local SOCKS5 proxy port (default: 1080)
  -r <port>       Transparent redirect port (SO_ORIGINAL_DST, default: 1100)
  -u <port>       DNS-over-TCP UDP listening port (default: 5353)
  -d              Run as background daemon
```

**Example:**
```bash
./anytls-tiny -s your-server.com -p 443 -k your-uuid -h www.microsoft.com -d
```

---

## 🌐 OpenWrt Deployment Guide

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
```

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

#### 2. nftables / firewall4 Redirection
Generate `/etc/nftables.d/20-anytls.nft` using the included script and your domestic IP CIDR list (`chnroute.txt`):
```bash
python3 openwrt/scripts/gen-nft-chnroute.py chnroute.txt /etc/nftables.d/20-anytls.nft <your_server_ip>
fw4 reload
```

Now, all non-domestic TCP traffic from Wi-Fi and LAN clients will transparently route through `anytls-tiny`!

---

## 📄 License
Released under the [MIT License](LICENSE).
