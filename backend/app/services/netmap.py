from __future__ import annotations

import logging
import subprocess

from app.config import get_settings

logger = logging.getLogger(__name__)

TABLE = "parktech_relay"


def _run(cmd: list[str], dry_run: bool) -> None:
    if dry_run:
        logger.info("DRY_RUN: %s", " ".join(cmd))
        return
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        logger.warning("command failed (%s): %s", result.returncode, result.stderr)


def apply_site_netmap(virtual_subnet: str, local_subnet: str) -> None:
    """
    Hub-side helper: ensure packets for virtual_subnet can be forwarded toward the tunnel.
    Full 1:1 LAN NETMAP typically runs on the site edge (see scripts/site-netmap-example.sh).
    On the hub we install a named nftables set marker / route note for observability.
    """
    settings = get_settings()
    dry = settings.nft_dry_run

    # Ensure forwarding is on
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"], dry_run=dry)

    # Lightweight nftables table so operators can see managed prefixes
    script = f"""
table inet {TABLE} {{
  set virtual_prefixes {{
    type ipv4_addr
    flags interval
  }}
}}
"""
    if dry:
        logger.info("DRY_RUN nftables ensure table for %s -> %s", virtual_subnet, local_subnet)
        return

    # Create table/set if missing, then add prefix
    subprocess.run(["nft", "list", "table", "inet", TABLE], check=False, capture_output=True)
    add_table = subprocess.run(["nft", "-f", "-"], input=script, check=False, capture_output=True, text=True)
    if add_table.returncode != 0:
        logger.debug("nft table ensure: %s", add_table.stderr)
    add = subprocess.run(
        ["nft", "add", "element", "inet", TABLE, "virtual_prefixes", "{", virtual_subnet, "}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if add.returncode != 0:
        logger.debug("nft add element: %s", add.stderr)


def sync_routes_for_wireguard(virtual_subnet: str, iface: str) -> None:
    settings = get_settings()
    _run(["ip", "route", "replace", virtual_subnet, "dev", iface], dry_run=settings.nft_dry_run)
