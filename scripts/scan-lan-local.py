#!/usr/bin/env python3
"""
Standalone LAN ping-sweep with light enrichment (hostname, MAC, open ports).

No FastAPI/DB required.

Examples:
  python3 scripts/scan-lan-local.py --cidr 10.0.0.0/24 --local-subnet 10.0.0.0/24
  python3 scripts/scan-lan-local.py --cidr 10.0.0.0/24 --max-host 30 --no-ports
  python3 scripts/scan-lan-local.py --cidr 10.101.5.0/24 --local-subnet 192.168.1.0/24 \\
      --fake 10.101.5.50,10.101.5.60
"""

from __future__ import annotations

import argparse
import ipaddress
import platform
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

PING_CONCURRENCY = 32
ENRICH_CONCURRENCY = 16

# Common admin / IoT ports for a light fingerprint (not a full nmap)
DEFAULT_PORTS = (22, 80, 443, 554, 8080, 8443, 9100)


@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor_hint: str = ""
    open_ports: list[int] = field(default_factory=list)
    type_hint: str = "generic"


def ping_cmd(ip: str, timeout_sec: int = 1) -> list[str]:
    if platform.system() == "Darwin":
        return ["ping", "-c", "1", "-W", str(timeout_sec * 1000), ip]
    return ["ping", "-c", "1", "-W", str(timeout_sec), ip]


def ping_host(ip: str, timeout_sec: int = 1) -> bool:
    result = subprocess.run(
        ping_cmd(ip, timeout_sec),
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def hosts_in_subnet(cidr: str, max_host: int | None = None) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.prefixlen != 24:
        raise SystemExit("Only /24 subnets are supported (matches hub POC)")
    hosts = [str(ip) for ip in net.hosts()]
    if max_host is not None:
        hosts = [h for h in hosts if int(h.rsplit(".", 1)[1]) <= max_host]
    return hosts


def local_ip_for_virtual(virtual_subnet: str, virtual_ip: str, local_subnet: str) -> str:
    vnet = ipaddress.ip_network(virtual_subnet, strict=False)
    lnet = ipaddress.ip_network(local_subnet, strict=False)
    vip = ipaddress.ip_address(virtual_ip)
    if vip not in vnet:
        raise ValueError(f"{virtual_ip} not in {virtual_subnet}")
    host = int(vip) - int(vnet.network_address)
    lip = lnet.network_address + host
    if lip not in lnet:
        raise ValueError("host offset out of range for local subnet")
    return str(lip)


def load_arp_table() -> dict[str, str]:
    """Return {ip: mac} from the local ARP/neighbour table."""
    table: dict[str, str] = {}
    try:
        out = subprocess.run(
            ["arp", "-an"],
            check=False,
            capture_output=True,
            text=True,
        ).stdout
    except FileNotFoundError:
        return table

    # macOS: ? (10.0.0.1) at aa:bb:... on en0 ifscope [ethernet]
    # Linux: ? (10.0.0.1) at aa:bb:... [ether] on eth0
    for line in out.splitlines():
        m = re.search(
            r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{11,17}|[0-9a-fA-F-]{11,17})",
            line,
        )
        if not m:
            continue
        ip, mac = m.group(1), m.group(2).lower().replace("-", ":")
        if "incomplete" in line.lower() or mac in {"(incomplete)", "incomplete"}:
            continue
        table[ip] = mac
    return table


# Tiny OUI hints for common kit (not a full vendor DB)
OUI_HINTS = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1c:42": "Parallels",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "28:cd:c1": "Raspberry Pi",
    "d8:3a:dd": "Raspberry Pi",
    "00:1a:2b": "Ayeza / ANPR-ish",
    "00:04:f2": "Polycom",
    "00:90:fb": "Cisco Meraki",
    "f0:9f:c2": "Ubiquiti",
    "18:e8:29": "Ubiquiti",
    "24:5a:4c": "Ubiquiti",
    "78:8a:20": "Ubiquiti",
    "00:17:88": "Philips Hue",
    "b0:be:76": "TP-Link",
    "50:c7:bf": "TP-Link",
    "3c:84:6a": "TP-Link",
    "a4:cf:99": "Apple",
    "f0:18:98": "Apple",
    "ac:bc:32": "Apple",
    "f4:5c:89": "Apple",
    "00:1e:06": "Wyse / thin client",
}


def vendor_from_mac(mac: str) -> str:
    if not mac or len(mac) < 8:
        return ""
    oui = mac[:8].lower()
    return OUI_HINTS.get(oui, "")


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


def probe_ports(ip: str, ports: tuple[int, ...], timeout: float = 0.35) -> list[int]:
    open_ports: list[int] = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            continue
    return open_ports


def type_hint_from(hostname: str, ports: list[int], vendor: str) -> str:
    h = hostname.lower()
    v = vendor.lower()
    if 554 in ports or "cam" in h or "nvr" in h or "anpr" in h:
        return "camera"
    if "charge" in h or "ocpp" in h or 8080 in ports and "ev" in h:
        return "ev_charger"
    if "router" in h or "gateway" in h or "udm" in h or "unifi" in h:
        return "router"
    if "pi" in h or "raspberry" in v:
        return "generic"
    if 9100 in ports:
        return "printer"
    if ports == [22]:
        return "generic"
    if 80 in ports or 443 in ports or 8080 in ports or 8443 in ports:
        return "generic"
    return "generic"


def suggested_label(info: HostInfo, local_ip: str) -> str:
    if info.hostname:
        short = info.hostname.split(".")[0]
        return short
    if info.vendor_hint:
        return f"{info.vendor_hint} {local_ip}"
    return f"Discovered host {local_ip}"


def sweep(hosts: list[str], concurrency: int, timeout_sec: int) -> list[str]:
    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(ping_host, ip, timeout_sec): ip for ip in hosts}
        done = 0
        for fut in as_completed(futures):
            done += 1
            ip = futures[fut]
            if done % 50 == 0 or done == len(hosts):
                print(f"  … {done}/{len(hosts)} probed", file=sys.stderr)
            try:
                if fut.result():
                    alive.append(ip)
                    print(f"  UP  {ip}")
            except Exception as exc:
                print(f"  ERR {ip}: {exc}", file=sys.stderr)
    return sorted(alive, key=lambda s: tuple(int(x) for x in s.split(".")))


def enrich_hosts(
    ips: list[str],
    *,
    do_ports: bool,
    ports: tuple[int, ...],
    concurrency: int,
) -> list[HostInfo]:
    # Refresh ARP after the ping sweep so MAC entries exist for responders
    arp = load_arp_table()
    results: list[HostInfo] = []

    def one(ip: str) -> HostInfo:
        info = HostInfo(ip=ip, mac=arp.get(ip, ""), hostname=reverse_hostname(ip))
        info.vendor_hint = vendor_from_mac(info.mac)
        if do_ports:
            info.open_ports = probe_ports(ip, ports)
        info.type_hint = type_hint_from(info.hostname, info.open_ports, info.vendor_hint)
        return info

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(one, ip) for ip in ips]
        for fut in as_completed(futures):
            results.append(fut.result())

    return sorted(results, key=lambda h: tuple(int(x) for x in h.ip.split(".")))


def main() -> int:
    parser = argparse.ArgumentParser(description="Standalone LAN sweep + enrichment")
    parser.add_argument("--cidr", required=True, help="Virtual (or local) /24 to sweep")
    parser.add_argument(
        "--local-subnet",
        default="192.168.1.0/24",
        help="Customer LAN used for reverse IP map",
    )
    parser.add_argument("--fake", default="", help="Comma-separated IPs (skip ICMP)")
    parser.add_argument("--max-host", type=int, default=None, help="Only probe .1 .. .N")
    parser.add_argument("--concurrency", type=int, default=PING_CONCURRENCY)
    parser.add_argument("--timeout", type=int, default=1, help="Ping timeout (seconds)")
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help=f"TCP ports to probe (default: {','.join(str(p) for p in DEFAULT_PORTS)})",
    )
    parser.add_argument("--no-ports", action="store_true", help="Skip TCP port probes")
    parser.add_argument("--no-enrich", action="store_true", help="Ping only (old output)")
    args = parser.parse_args()

    hosts = hosts_in_subnet(args.cidr, args.max_host)
    print(f"Target {args.cidr}  hosts={len(hosts)}  os={platform.system()}")

    t0 = time.time()
    if args.fake.strip():
        fake_set = {ip.strip() for ip in args.fake.split(",") if ip.strip()}
        alive = sorted(
            (h for h in hosts if h in fake_set),
            key=lambda s: tuple(int(x) for x in s.split(".")),
        )
        print(f"Fake mode — treating {len(alive)} host(s) as up (no ICMP)")
        for ip in alive:
            print(f"  UP  {ip}")
    else:
        print("Sweeping (ICMP)…")
        alive = sweep(hosts, args.concurrency, args.timeout)

    ping_elapsed = time.time() - t0
    print(f"\nResponsive: {len(alive)} / {len(hosts)}  ({ping_elapsed:.1f}s)")

    if not alive:
        print("  (none)")
        return 0

    port_tuple = tuple(
        int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()
    )

    if args.no_enrich:
        print("Would auto-add:")
        for vip in alive:
            try:
                local = local_ip_for_virtual(args.cidr, vip, args.local_subnet)
            except ValueError:
                local = vip
            print(f"  {vip}  →  local {local}  label='Discovered host {local}'")
        return 0

    print("Enriching (DNS / ARP / ports)…")
    t1 = time.time()
    infos = enrich_hosts(
        alive,
        do_ports=not args.no_ports,
        ports=port_tuple or DEFAULT_PORTS,
        concurrency=ENRICH_CONCURRENCY,
    )
    enrich_elapsed = time.time() - t1

    # Table header
    print(
        f"\n{'IP':<15} {'Hostname':<28} {'MAC':<18} {'Vendor':<14} "
        f"{'Ports':<18} {'Type':<10} Label"
    )
    print("-" * 120)
    for info in infos:
        try:
            local = local_ip_for_virtual(args.cidr, info.ip, args.local_subnet)
        except ValueError:
            local = info.ip
        label = suggested_label(info, local)
        ports = ",".join(str(p) for p in info.open_ports) if info.open_ports else "-"
        print(
            f"{info.ip:<15} {(info.hostname or '-'):<28} {(info.mac or '-'):<18} "
            f"{(info.vendor_hint or '-'):<14} {ports:<18} {info.type_hint:<10} {label}"
        )

    print(f"\nEnrichment {enrich_elapsed:.1f}s  ·  total {time.time() - t0:.1f}s")
    print(
        "Hostname = reverse DNS; MAC = ARP after ping; "
        "ports = quick TCP connect; type = light heuristic."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
