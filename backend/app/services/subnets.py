from __future__ import annotations

import ipaddress

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Site


def parse_base_cidr(base_cidr: str) -> ipaddress.IPv4Network:
    network = ipaddress.ip_network(base_cidr, strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("base_cidr must be IPv4")
    if network.prefixlen > 16:
        raise ValueError("base_cidr should be /16 or larger block for site /24 allocation")
    return network


MAX_SITE_INDEX = 254  # 10.101.255.0/24 is reserved


def next_site_index(db: Session) -> int:
    """Return the lowest unused site index (0-254). Index 255 is reserved."""
    rows = set(db.scalars(select(Site.site_index)).all())
    if not rows:
        return 0
    # Find lowest unused index
    for i in range(MAX_SITE_INDEX + 1):
        if i not in rows:
            return i
    raise ValueError(
        f"No free site indices available (max {MAX_SITE_INDEX}). "
        "Delete unused sites to free indices. 10.101.255.0/24 is reserved."
    )


def allocate_virtual_subnet(db: Session, base_cidr: str) -> tuple[int, str]:
    """Return (site_index, virtual_subnet) e.g. (0, '10.101.0.0/24')."""
    base = parse_base_cidr(base_cidr)
    site_index = next_site_index(db)
    # Carve sequential /24s from the base /16
    site_net = ipaddress.ip_network(f"{base.network_address + (site_index * 256)}/24", strict=False)
    if site_net.network_address not in base:
        raise ValueError("No free /24 left in base_cidr")
    return site_index, str(site_net)


def virtual_ip_for_local(virtual_subnet: str, local_ip: str, local_subnet: str) -> str:
    """Map host part of local_ip within local_subnet onto virtual_subnet (1:1)."""
    vnet = ipaddress.ip_network(virtual_subnet, strict=False)
    lnet = ipaddress.ip_network(local_subnet, strict=False)
    lip = ipaddress.ip_address(local_ip)
    if lip not in lnet:
        # Still allow mapping by host octet for POC convenience
        host = int(lip) & 0xFF
    else:
        host = int(lip) - int(lnet.network_address)
    vip = vnet.network_address + host
    if vip not in vnet:
        raise ValueError("Host offset out of range for virtual subnet")
    return str(vip)


def local_ip_for_virtual(virtual_subnet: str, virtual_ip: str, local_subnet: str) -> str:
    """Inverse of virtual_ip_for_local: map virtual host onto local_subnet (1:1)."""
    vnet = ipaddress.ip_network(virtual_subnet, strict=False)
    lnet = ipaddress.ip_network(local_subnet, strict=False)
    vip = ipaddress.ip_address(virtual_ip)
    if vip not in vnet:
        raise ValueError("Virtual IP is not in virtual_subnet")
    host = int(vip) - int(vnet.network_address)
    lip = lnet.network_address + host
    if lip not in lnet:
        raise ValueError("Host offset out of range for local subnet")
    return str(lip)


def default_gateway_virtual_ip(virtual_subnet: str) -> str:
    vnet = ipaddress.ip_network(virtual_subnet, strict=False)
    return str(vnet.network_address + 1)
