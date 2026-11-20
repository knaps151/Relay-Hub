"""Teltonika RutOS UCI config generator for WireGuard sites."""

from __future__ import annotations


def render_teltonika_uci(
    *,
    site_private_key: str,
    site_tunnel_ip: str,
    hub_public_key: str,
    hub_endpoint: str,
    virtual_subnet: str,
    local_subnet: str,
) -> str:
    """
    Generate a Teltonika RutOS UCI script for WireGuard site setup.

    This script configures:
    - WireGuard interface (wg_gw1) with the site's private key
    - Peer connection to the hub
    - Firewall zone with masquerading
    - 1:1 NETMAP from virtual subnet to local subnet
    """
    # Parse endpoint host:port
    if ":" in hub_endpoint:
        endpoint_host, endpoint_port = hub_endpoint.rsplit(":", 1)
    else:
        endpoint_host = hub_endpoint
        endpoint_port = "51820"

    # Extract tunnel IP without CIDR
    tunnel_ip = site_tunnel_ip.split("/")[0]

    # Extract virtual subnet base (e.g., 10.101.5.0 from 10.101.5.0/24)
    virtual_base = virtual_subnet.split("/")[0]

    # Extract local subnet base (e.g., 192.168.1.0 from 192.168.1.0/24)
    local_base = local_subnet.split("/")[0]

    script = f'''#!/bin/sh
# Teltonika RutOS WireGuard Configuration Script
# Site tunnel IP: {site_tunnel_ip}
# Virtual subnet: {virtual_subnet} -> Local subnet: {local_subnet}
#
# Run this script via SSH on your Teltonika RUT/RUTX router.
# After running, the tunnel should come up and reach the hub at {hub_endpoint}.

set -e

echo "Configuring WireGuard interface wg_gw1..."

# Remove existing WireGuard config if present
uci -q delete network.wg_gw1 2>/dev/null || true
uci -q delete network.wg_peer1 2>/dev/null || true

# Create WireGuard interface
uci set network.wg_gw1=interface
uci set network.wg_gw1.proto='wireguard'
uci set network.wg_gw1.private_key='{site_private_key}'
uci add_list network.wg_gw1.addresses='{tunnel_ip}/32'
uci set network.wg_gw1.listen_port='51820'
uci set network.wg_gw1.mtu='1420'

# Create peer (hub)
uci set network.wg_peer1=wireguard_wg_gw1
uci set network.wg_peer1.public_key='{hub_public_key}'
uci set network.wg_peer1.endpoint_host='{endpoint_host}'
uci set network.wg_peer1.endpoint_port='{endpoint_port}'
uci set network.wg_peer1.persistent_keepalive='25'
uci set network.wg_peer1.route_allowed_ips='1'
uci add_list network.wg_peer1.allowed_ips='10.100.0.0/22'

echo "Configuring firewall zone wg..."

# Remove existing wg zone if present
uci -q delete firewall.wg_zone 2>/dev/null || true
uci -q delete firewall.wg_to_lan 2>/dev/null || true
uci -q delete firewall.lan_to_wg 2>/dev/null || true

# Create firewall zone for WireGuard
uci set firewall.wg_zone=zone
uci set firewall.wg_zone.name='wg'
uci set firewall.wg_zone.network='wg_gw1'
uci set firewall.wg_zone.input='ACCEPT'
uci set firewall.wg_zone.output='ACCEPT'
uci set firewall.wg_zone.forward='ACCEPT'
uci set firewall.wg_zone.masq='1'

# Create forwarding rules
uci set firewall.wg_to_lan=forwarding
uci set firewall.wg_to_lan.src='wg'
uci set firewall.wg_to_lan.dest='lan'

uci set firewall.lan_to_wg=forwarding
uci set firewall.lan_to_wg.src='lan'
uci set firewall.lan_to_wg.dest='wg'

echo "Configuring 1:1 NETMAP ({virtual_subnet} <-> {local_subnet})..."

# Remove existing netmap rules if present
uci -q delete firewall.relay_hub_dnat 2>/dev/null || true
uci -q delete firewall.relay_hub_snat 2>/dev/null || true

# DNAT: incoming to virtual subnet -> local subnet
uci set firewall.relay_hub_dnat=redirect
uci set firewall.relay_hub_dnat.name='Relay Hub DNAT'
uci set firewall.relay_hub_dnat.src='wg'
uci set firewall.relay_hub_dnat.src_dip='{virtual_base}/24'
uci set firewall.relay_hub_dnat.dest='lan'
uci set firewall.relay_hub_dnat.dest_ip='{local_base}/24'
uci set firewall.relay_hub_dnat.target='DNAT'

# SNAT: outgoing from local subnet -> virtual subnet
uci set firewall.relay_hub_snat=nat
uci set firewall.relay_hub_snat.name='Relay Hub SNAT'
uci set firewall.relay_hub_snat.src='lan'
uci set firewall.relay_hub_snat.src_ip='{local_base}/24'
uci set firewall.relay_hub_snat.dest='wg'
uci set firewall.relay_hub_snat.snat_ip='{virtual_base}'
uci set firewall.relay_hub_snat.target='SNAT'

# Alternative nftables-based NETMAP (for advanced setups)
# Uncomment below and comment out the UCI redirect/nat rules above if UCI NAT doesn't work
#
# cat >> /etc/firewall.user << 'NETMAP_EOF'
# # Relay Hub 1:1 NETMAP
# nft add table ip relay_hub_netmap 2>/dev/null || true
# nft flush table ip relay_hub_netmap
# nft -f - << EOF
# table ip relay_hub_netmap {{
#   chain prerouting {{
#     type nat hook prerouting priority dstnat; policy accept;
#     ip daddr {virtual_subnet} dnat ip prefix to ip daddr map {{ {virtual_subnet} : {local_subnet} }}
#   }}
#   chain postrouting {{
#     type nat hook postrouting priority srcnat; policy accept;
#     ip saddr {local_subnet} snat ip prefix to ip saddr map {{ {local_subnet} : {virtual_subnet} }}
#   }}
# }}
# EOF
# NETMAP_EOF

echo "Committing configuration..."
uci commit network
uci commit firewall

echo "Restarting services..."
/etc/init.d/network restart
/etc/init.d/firewall restart

echo ""
echo "Configuration complete!"
echo "Tunnel IP: {tunnel_ip}"
echo "Virtual subnet: {virtual_subnet}"
echo "Local subnet: {local_subnet}"
echo ""
echo "Test connectivity:"
echo "  From hub: ping {tunnel_ip}"
echo "  Device at {local_base.rsplit('.', 1)[0]}.100 reachable as {virtual_base.rsplit('.', 1)[0]}.100"
'''
    return script
