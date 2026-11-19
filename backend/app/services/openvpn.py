from __future__ import annotations

import logging
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from app.config import get_settings

logger = logging.getLogger(__name__)


def _pki() -> Path:
    return Path(get_settings().openvpn_pki_dir)


def _ccd() -> Path:
    return Path(get_settings().openvpn_ccd_dir)


def _clients() -> Path:
    path = Path(get_settings().openvpn_clients_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def pki_ready() -> bool:
    pki = _pki()
    return (pki / "ca.crt").exists() and (pki / "ta.key").exists()


def _run_easyrsa(args: list[str]) -> subprocess.CompletedProcess[str]:
    env = {
        "EASYRSA_BATCH": "1",
        "EASYRSA_PKI": str(_pki()),
    }
    # Prefer system easy-rsa if present
    easyrsa = Path("/usr/share/easy-rsa/easyrsa")
    if not easyrsa.exists():
        easyrsa = Path("/usr/share/easy-rsa/3/easyrsa")
    cmd = [str(easyrsa), *args]
    return subprocess.run(cmd, check=False, capture_output=True, text=True, env={**dict(**__import__("os").environ), **env})


def issue_client(common_name: str, client_ip: str, virtual_subnet: str) -> Path:
    """Create client cert/key if needed and write .ovpn + CCD iroute."""
    settings = get_settings()
    pki = _pki()
    ccd = _ccd()
    ccd.mkdir(parents=True, exist_ok=True)
    clients = _clients()

    issued = pki / "issued" / f"{common_name}.crt"
    private = pki / "private" / f"{common_name}.key"

    # Flat layout fallback used by openvpn entrypoint
    flat_crt = pki / f"{common_name}.crt"
    flat_key = pki / f"{common_name}.key"

    if not issued.exists() and not flat_crt.exists():
        _openssl_client_cert(common_name)

    crt_path = issued if issued.exists() else flat_crt
    key_path = private if private.exists() else flat_key
    if not crt_path.exists() or not key_path.exists():
        _openssl_client_cert(common_name)
        crt_path = flat_crt
        key_path = flat_key

    # CCD: assign tunnel IP and iroute the virtual subnet toward this client
    (ccd / common_name).write_text(
        f"ifconfig-push {client_ip} 255.255.255.0\niroute {virtual_subnet}\n",
        encoding="utf-8",
    )

    ca = (pki / "ca.crt").read_text(encoding="utf-8")
    cert = crt_path.read_text(encoding="utf-8")
    key = key_path.read_text(encoding="utf-8")
    ta = (pki / "ta.key").read_text(encoding="utf-8")

    host, _, port = settings.openvpn_endpoint.partition(":")
    port = port or "1194"
    ovpn = f"""client
dev tun
proto tcp
remote {host} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
verb 3
key-direction 1

<ca>
{ca.strip()}
</ca>
<cert>
{cert.strip()}
</cert>
<key>
{key.strip()}
</key>
<tls-auth>
{ta.strip()}
</tls-auth>
"""
    out = clients / f"{common_name}.ovpn"
    out.write_text(ovpn, encoding="utf-8")
    return out


def _openssl_client_cert(common_name: str) -> None:
    pki = _pki()
    pki.mkdir(parents=True, exist_ok=True)
    key = pki / f"{common_name}.key"
    csr = pki / f"{common_name}.csr"
    crt = pki / f"{common_name}.crt"
    ca_crt = pki / "ca.crt"
    ca_key = pki / "ca.key"

    if not ca_crt.exists() or not ca_key.exists():
        raise RuntimeError("OpenVPN CA not ready yet — wait for openvpn container init")

    subprocess.run(
        ["openssl", "req", "-new", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={common_name}"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_crt),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(crt),
            "-days",
            "3650",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def read_client_ovpn(common_name: str) -> str:
    path = _clients() / f"{common_name}.ovpn"
    if not path.exists():
        raise FileNotFoundError(f"No ovpn for {common_name}")
    return path.read_text(encoding="utf-8")


def connected_clients() -> dict[str, datetime]:
    """Parse openvpn-status.log → {common_name: last_seen}."""
    settings = get_settings()
    path = Path(settings.openvpn_status_file)
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8", errors="ignore")
    clients: dict[str, datetime] = {}
    in_client_list = False
    for line in text.splitlines():
        if line.startswith("HEADER,CLIENT_LIST") or line.startswith("OpenVPN CLIENT LIST"):
            in_client_list = True
            continue
        if line.startswith("HEADER,ROUTING_TABLE") or line.startswith("ROUTING TABLE") or line.startswith("GLOBAL STATS"):
            in_client_list = False
            continue
        if not in_client_list:
            # status-version 2: CLIENT_LIST,name,...
            if line.startswith("CLIENT_LIST,"):
                parts = line.split(",")
                if len(parts) >= 8:
                    name = parts[1]
                    # connected since field varies; use now as online marker
                    clients[name] = datetime.utcnow()
            continue
        # Human-readable format: Common Name,Real Address,...
        if "," in line and not line.startswith("Updated"):
            parts = [p.strip() for p in line.split(",")]
            if parts and parts[0] not in {"Common Name", "CN"}:
                clients[parts[0]] = datetime.utcnow()
    return clients


def next_client_ip(site_index: int) -> str:
    # 10.100.1.0/24 server pool; assign .10+site_index for POC
    host = 10 + site_index
    if host > 250:
        raise ValueError("Too many OpenVPN clients for POC pool")
    return f"10.100.1.{host}"
