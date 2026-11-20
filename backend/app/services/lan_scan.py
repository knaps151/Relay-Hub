"""Hub-side LAN discovery via ICMP sweep of a site's virtual subnet."""

from __future__ import annotations

import ipaddress
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models import Site, SiteDevice
from app.services.host_enrich import enrich_hosts
from app.services.provision import add_device
from app.services.subnets import local_ip_for_virtual
from app.services.wireguard import handshake_is_online, parse_handshakes

logger = logging.getLogger(__name__)

PING_CONCURRENCY = 32
PING_TIMEOUT_SEC = 1


@dataclass
class ScanResult:
    probed: int = 0
    added: list[SiteDevice] = field(default_factory=list)
    skipped_existing: int = 0
    responsive: int = 0


def _site_wireguard_online(site: Site) -> bool:
    if not site.wg_public_key:
        return False
    handshakes = {p.public_key: p for p in parse_handshakes()}
    peer = handshakes.get(site.wg_public_key)
    if peer and handshake_is_online(peer.latest_handshake):
        return True
    # Fall back to last polled flag (useful in tests / dry-run)
    return bool(site.online)


def _ping_argv(ip: str) -> list[str]:
    # Linux: -W seconds; macOS: -W milliseconds
    import platform

    if platform.system() == "Darwin":
        return ["ping", "-c", "1", "-W", str(PING_TIMEOUT_SEC * 1000), ip]
    return ["ping", "-c", "1", "-W", str(PING_TIMEOUT_SEC), ip]


def _ping_host(ip: str) -> bool:
    result = subprocess.run(
        _ping_argv(ip),
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _hosts_in_subnet(cidr: str) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.prefixlen != 24:
        raise ValueError("LAN scan only supports /24 virtual subnets in POC")
    # usable hosts; for /24 this is .1-.254
    return [str(ip) for ip in net.hosts()]


def scan_and_add_devices(db: Session, site: Site) -> ScanResult:
    """
    Ping-sweep site.virtual_subnet from the hub and auto-add new responsive hosts.
    Enrichment (reverse DNS + light TCP ports) shapes label / type / admin_port.
    Additive only — never deletes devices that did not reply.
    """
    if site.vpn_type != "wireguard":
        raise ValueError("LAN scan is only available for WireGuard gateway sites")
    if getattr(site, "access_mode", "gateway") != "gateway":
        raise ValueError("LAN scan is only available for gateway sites (not direct devices)")
    if not _site_wireguard_online(site):
        raise ValueError("Site tunnel is offline — connect the site router before scanning")

    loaded = db.scalar(
        select(Site).options(selectinload(Site.devices)).where(Site.id == site.id)
    )
    if loaded:
        site = loaded

    existing_vips = {d.virtual_ip for d in site.devices}
    hosts = _hosts_in_subnet(site.virtual_subnet)
    result = ScanResult(probed=len(hosts))

    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=PING_CONCURRENCY) as pool:
        futures = {pool.submit(_ping_host, ip): ip for ip in hosts}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    alive.append(ip)
            except Exception as exc:
                logger.debug("ping %s failed: %s", ip, exc)

    result.responsive = len(alive)

    to_add: list[tuple[str, str]] = []  # (vip, local_ip)
    for vip in sorted(alive, key=lambda s: tuple(int(x) for x in s.split("."))):
        if vip in existing_vips:
            result.skipped_existing += 1
            continue
        try:
            local_ip = local_ip_for_virtual(site.virtual_subnet, vip, site.local_subnet)
        except ValueError as exc:
            logger.warning("skip %s: %s", vip, exc)
            continue
        to_add.append((vip, local_ip))

    if not to_add:
        return result

    enriched = enrich_hosts(to_add)

    for vip, local_ip in to_add:
        info = enriched.get(vip)
        label = info.label if info else f"Discovered host {local_ip}"
        device_type = info.device_type if info else "generic"
        admin_port = info.admin_port if info else None
        device = add_device(
            db,
            site,
            label=label,
            device_type=device_type,
            local_ip=local_ip,
            admin_port=admin_port,
        )
        result.added.append(device)
        existing_vips.add(vip)

    return result
