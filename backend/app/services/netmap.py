"""Hub-side 1:1 NETMAP: virtual Relay Hub subnets ↔ site LAN prefixes.

Engineers address devices as 10.101.X.Y. The hub DNATs to the site's real
LAN (e.g. 10.0.0.Y) before the packet enters the site WireGuard peer, so
UniFi / simple WG clients do not need site-side NETMAP. Conntrack reverses
the mapping on replies.
"""

from __future__ import annotations

import logging
import subprocess

from app.config import get_settings

logger = logging.getLogger(__name__)

TABLE = "relay_hub_netmap"


def _run(cmd: list[str], dry_run: bool) -> None:
    if dry_run:
        logger.info("DRY_RUN: %s", " ".join(cmd))
        return
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        logger.warning(
            "command failed (%s): %s — %s",
            result.returncode,
            " ".join(cmd),
            (result.stderr or "").strip(),
        )


def _nft(script: str, dry_run: bool) -> None:
    if dry_run:
        logger.info("DRY_RUN nft:\n%s", script)
        return
    result = subprocess.run(
        ["nft", "-f", "-"],
        input=script,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.warning("nft failed: %s", (result.stderr or "").strip())


def apply_site_netmap(virtual_subnet: str, local_subnet: str) -> None:
    """Install/refresh hub DNAT virtual → local for one site (idempotent enough)."""
    settings = get_settings()
    dry = settings.nft_dry_run

    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"], dry_run=dry)

    if dry:
        logger.info("DRY_RUN NETMAP %s <-> %s", virtual_subnet, local_subnet)
        return

    # Ensure table exists
    _nft(
        f"""
table ip {TABLE} {{
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
  }}
  chain output {{
    type nat hook output priority -100; policy accept;
  }}
}}
""",
        dry_run=False,
    )

    _purge_prefix_rules(virtual_subnet)

    dnat_expr = (
        f"ip daddr {virtual_subnet} dnat ip prefix to "
        f"ip daddr map {{ {virtual_subnet} : {local_subnet} }}"
    )
    _nft(f"add rule ip {TABLE} prerouting {dnat_expr}\n", dry_run=False)
    _nft(f"add rule ip {TABLE} output {dnat_expr}\n", dry_run=False)
    logger.info("NETMAP active %s -> %s", virtual_subnet, local_subnet)


def _purge_prefix_rules(virtual_subnet: str) -> None:
    for chain in ("prerouting", "output"):
        listed = subprocess.run(
            ["nft", "-a", "list", "chain", "ip", TABLE, chain],
            check=False,
            capture_output=True,
            text=True,
        )
        if listed.returncode != 0:
            continue
        for line in listed.stdout.splitlines():
            if virtual_subnet not in line or "handle" not in line:
                continue
            handle = line.rsplit("handle", 1)[-1].strip().split()[0]
            subprocess.run(
                ["nft", "delete", "rule", "ip", TABLE, chain, "handle", handle],
                check=False,
                capture_output=True,
            )


def sync_routes_for_wireguard(cidr: str, iface: str) -> None:
    """Install a route for cidr via the WireGuard interface."""
    settings = get_settings()
    _run(["ip", "route", "replace", cidr, "dev", iface], dry_run=settings.nft_dry_run)


def gateway_peer_allowed_ips(local_subnet: str, tunnel_ip: str) -> str:
    """AllowedIPs when hub NETMAPs: real LAN + tunnel address."""
    tun = tunnel_ip.split("/")[0]
    return f"{local_subnet},{tun}/32"
