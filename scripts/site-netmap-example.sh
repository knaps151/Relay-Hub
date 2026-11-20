#!/usr/bin/env bash
# Example site-side 1:1 NETMAP + Tailscale route advertisement.
# Run on the site edge router/host that can reach the local LAN.
#
# Usage:
#   sudo ./site-netmap-example.sh 10.101.0.0/24 192.168.1.0/24
#
# Then (Tailscale sites):
#   sudo tailscale set --advertise-routes=10.101.0.0/24
# And approve the route in Headscale / Relay UI workflow.

set -euo pipefail

VIRTUAL_CIDR="${1:-10.101.0.0/24}"
LOCAL_CIDR="${2:-192.168.1.0/24}"
TABLE_NAME="relay_hub_netmap"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (nftables + sysctl)"
  exit 1
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null

nft list table ip "$TABLE_NAME" >/dev/null 2>&1 && nft delete table ip "$TABLE_NAME"

nft -f - <<EOF
table ip ${TABLE_NAME} {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    ip daddr ${VIRTUAL_CIDR} dnat ip prefix to ip daddr map { ${VIRTUAL_CIDR} : ${LOCAL_CIDR} }
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr ${LOCAL_CIDR} snat ip prefix to ip saddr map { ${LOCAL_CIDR} : ${VIRTUAL_CIDR} }
  }
}
EOF

echo "Installed 1:1 NETMAP ${VIRTUAL_CIDR} <-> ${LOCAL_CIDR} in table ${TABLE_NAME}"
echo "Advertise ${VIRTUAL_CIDR} into the overlay (Tailscale: tailscale set --advertise-routes=${VIRTUAL_CIDR})"
