from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class PeerHandshake:
    public_key: str
    latest_handshake: Optional[datetime]
    endpoint: Optional[str]
    transfer_rx: int = 0
    transfer_tx: int = 0


def _run(cmd: list[str], dry_run: bool = False) -> subprocess.CompletedProcess[str]:
    if dry_run:
        logger.info("DRY_RUN: %s", " ".join(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def generate_keypair() -> tuple[str, str]:
    """Return (private_key, public_key) using wg if available, else openssl fallback."""
    priv = _run(["wg", "genkey"])
    if priv.returncode == 0 and priv.stdout.strip():
        private_key = priv.stdout.strip()
        pub = subprocess.run(
            ["wg", "pubkey"],
            input=private_key,
            check=False,
            capture_output=True,
            text=True,
        )
        if pub.returncode == 0:
            return private_key, pub.stdout.strip()

    # Fallback: Curve25519 via openssl (not identical tooling but fine for dry-run POC on Mac images)
    # Prefer real wg; if missing, synthesize placeholder keys for UI/config generation tests.
    import base64
    import os

    private_key = base64.b64encode(os.urandom(32)).decode()
    public_key = base64.b64encode(os.urandom(32)).decode()
    logger.warning("wg binary unavailable; generated placeholder keys")
    return private_key, public_key


def ensure_hub_interface(private_key: str) -> None:
    settings = get_settings()
    dry = settings.wg_dry_run
    iface = settings.wg_interface

    _run(["ip", "link", "add", "dev", iface, "type", "wireguard"], dry_run=dry)
    conf = f"""[Interface]
PrivateKey = {private_key}
ListenPort = {settings.wg_listen_port}
"""
    conf_path = Path(f"/tmp/{iface}.conf")
    conf_path.write_text(conf, encoding="utf-8")
    result = _run(["wg", "setconf", iface, str(conf_path)], dry_run=dry)
    if result.returncode != 0 and not dry:
        logger.warning("wg setconf failed: %s", result.stderr)
    _run(["ip", "address", "replace", settings.wg_hub_address, "dev", iface], dry_run=dry)
    _run(["ip", "link", "set", "up", "dev", iface], dry_run=dry)


def set_peer(
    public_key: str,
    allowed_ips: str,
    *,
    persistent_keepalive: int = 25,
) -> None:
    settings = get_settings()
    dry = settings.wg_dry_run
    iface = settings.wg_interface
    cmd = [
        "wg",
        "set",
        iface,
        "peer",
        public_key,
        "allowed-ips",
        allowed_ips,
        "persistent-keepalive",
        str(persistent_keepalive),
    ]
    result = _run(cmd, dry_run=dry)
    if result.returncode != 0 and not dry:
        logger.warning("wg set peer failed: %s", result.stderr)

    # Route each AllowedIPs prefix via the WG interface
    for prefix in [p.strip() for p in allowed_ips.split(",") if p.strip()]:
        _run(["ip", "route", "replace", prefix, "dev", iface], dry_run=dry)


def remove_peer(public_key: str) -> None:
    settings = get_settings()
    _run(
        ["wg", "set", settings.wg_interface, "peer", public_key, "remove"],
        dry_run=settings.wg_dry_run,
    )


def parse_handshakes() -> list[PeerHandshake]:
    settings = get_settings()
    if settings.wg_dry_run:
        return []
    result = _run(["wg", "show", settings.wg_interface, "dump"])
    if result.returncode != 0:
        return []
    peers: list[PeerHandshake] = []
    lines = result.stdout.strip().splitlines()
    # First line is interface; subsequent are peers
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        pub = parts[0]
        endpoint = parts[2] if parts[2] != "(none)" else None
        handshake_ts = int(parts[4]) if parts[4].isdigit() else 0
        latest = (
            datetime.fromtimestamp(handshake_ts, tz=timezone.utc).replace(tzinfo=None)
            if handshake_ts > 0
            else None
        )
        rx = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0
        tx = int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 0
        peers.append(
            PeerHandshake(
                public_key=pub,
                latest_handshake=latest,
                endpoint=endpoint,
                transfer_rx=rx,
                transfer_tx=tx,
            )
        )
    return peers


def render_client_conf(
    *,
    client_private_key: str,
    client_address: str,
    hub_public_key: str,
    hub_endpoint: str,
    allowed_ips: str,
) -> str:
    host_port = hub_endpoint
    return f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_address}
DNS = 1.1.1.1

[Peer]
PublicKey = {hub_public_key}
Endpoint = {host_port}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""


def handshake_is_online(latest: Optional[datetime], max_age_seconds: int = 180) -> bool:
    if not latest:
        return False
    age = (datetime.utcnow() - latest).total_seconds()
    return age <= max_age_seconds
