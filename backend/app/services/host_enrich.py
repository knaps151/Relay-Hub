"""Light host enrichment for LAN discovery (DNS + TCP ports).

MAC/ARP is not used on the hub path: through WireGuard/NETMAP the neighbour
table shows the tunnel next-hop, not the site device.
"""

from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

ENRICH_CONCURRENCY = 16
DEFAULT_PORTS = (22, 80, 443, 554, 8080, 8443, 9100)

# Prefer these as SiteDevice.admin_port when open
ADMIN_PORT_PREFERENCE = (80, 8080, 8443, 443, 22)


@dataclass
class HostEnrichment:
    ip: str
    hostname: str = ""
    open_ports: list[int] = field(default_factory=list)
    device_type: str = "generic"
    admin_port: int | None = None
    label: str = ""


def reverse_hostname(ip: str, timeout: float = 0.4) -> str:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.rstrip(".")
    except (socket.herror, socket.gaierror, TimeoutError, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(old)


def probe_ports(ip: str, ports: tuple[int, ...] = DEFAULT_PORTS, timeout: float = 0.35) -> list[int]:
    open_ports: list[int] = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            continue
    return open_ports


def infer_device_type(hostname: str, ports: list[int]) -> str:
    h = (hostname or "").lower()
    if 554 in ports or "cam" in h or "nvr" in h or "anpr" in h or "hikvision" in h:
        if "anpr" in h:
            return "anpr"
        return "camera"
    if "charge" in h or "ocpp" in h or ("ev" in h and 8080 in ports):
        return "ev_charger"
    if "router" in h or "gateway" in h or "udm" in h or "unifi" in h or "mikrotik" in h:
        return "router"
    if 9100 in ports or "print" in h:
        return "printer"
    return "generic"


def pick_admin_port(ports: list[int], device_type: str) -> int | None:
    if device_type == "ev_charger" and 8080 in ports:
        return 8080
    if device_type in {"camera", "anpr"} and 80 in ports:
        return 80
    for p in ADMIN_PORT_PREFERENCE:
        if p in ports:
            return p
    return None


def suggested_label(hostname: str, local_ip: str, device_type: str) -> str:
    if hostname:
        short = hostname.split(".")[0]
        if short and short.replace("-", "").replace("_", "").isalnum():
            return short
    if device_type == "camera":
        return f"Camera {local_ip}"
    if device_type == "anpr":
        return f"ANPR {local_ip}"
    if device_type == "ev_charger":
        return f"EV charger {local_ip}"
    if device_type == "router":
        return f"Router {local_ip}"
    if device_type == "printer":
        return f"Printer {local_ip}"
    return f"Discovered host {local_ip}"


def enrich_host(ip: str, *, local_ip: str, ports: tuple[int, ...] = DEFAULT_PORTS) -> HostEnrichment:
    hostname = reverse_hostname(ip)
    open_ports = probe_ports(ip, ports)
    device_type = infer_device_type(hostname, open_ports)
    admin_port = pick_admin_port(open_ports, device_type)
    label = suggested_label(hostname, local_ip, device_type)
    return HostEnrichment(
        ip=ip,
        hostname=hostname,
        open_ports=open_ports,
        device_type=device_type,
        admin_port=admin_port,
        label=label,
    )


def enrich_hosts(
    items: list[tuple[str, str]],
    *,
    ports: tuple[int, ...] = DEFAULT_PORTS,
    concurrency: int = ENRICH_CONCURRENCY,
) -> dict[str, HostEnrichment]:
    """
    Enrich virtual IPs in parallel.
    items: list of (virtual_ip, local_ip)
    """
    out: dict[str, HostEnrichment] = {}

    def one(vip: str, local_ip: str) -> HostEnrichment:
        try:
            return enrich_host(vip, local_ip=local_ip, ports=ports)
        except Exception as exc:
            logger.debug("enrich %s failed: %s", vip, exc)
            return HostEnrichment(
                ip=vip,
                label=f"Discovered host {local_ip}",
                device_type="generic",
            )

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(one, vip, local): vip for vip, local in items}
        for fut in as_completed(futures):
            vip = futures[fut]
            out[vip] = fut.result()
    return out
