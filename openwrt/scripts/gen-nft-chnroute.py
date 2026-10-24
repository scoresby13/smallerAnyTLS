#!/usr/bin/env python3
"""
Generate OpenWrt firewall4 (nftables) chnroute ruleset from a CIDR list.

Usage:
  python3 gen-nft-chnroute.py [input_chnroute.txt] [output_20-anytls.nft] [server_ip]
"""

import sys

def main():
    in_file = sys.argv[1] if len(sys.argv) > 1 else "chnroute.txt"
    out_file = sys.argv[2] if len(sys.argv) > 2 else "20-anytls.nft"
    server_ip = sys.argv[3] if len(sys.argv) > 3 else ""

    try:
        with open(in_file, "r", encoding="utf-8") as f:
            cidrs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"Error: {in_file} not found.", file=sys.stderr)
        sys.exit(1)

    with open(out_file, "w", newline="\n", encoding="utf-8") as out:
        out.write("# Auto-generated firewall4 (nftables) configuration for smallerAnyTLS\n\n")
        out.write("set chnroute {\n")
        out.write("    type ipv4_addr\n")
        out.write("    flags interval\n")
        out.write("    elements = {\n")
        for cidr in cidrs:
            out.write(f"        {cidr},\n")
        out.write("    }\n")
        out.write("}\n\n")

        bypass_ips = "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
        if server_ip:
            bypass_ips += f", {server_ip}"

        out.write("chain dstnat_anytls {\n")
        out.write("    type nat hook prerouting priority dstnat - 1; policy accept;\n")
        out.write("    iifname != \"br-lan\" return\n")
        out.write("    ip daddr @chnroute return\n")
        out.write(f"    ip daddr {{ {bypass_ips} }} return\n")
        out.write("    meta l4proto tcp redirect to :1100\n")
        out.write("}\n")

    print(f"Successfully generated {out_file} with {len(cidrs)} CIDR blocks.")

if __name__ == "__main__":
    main()
