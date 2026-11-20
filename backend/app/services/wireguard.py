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
    try:
        return subprocess.run(cmd, check=False, capture_output=True, text=True)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, stdout="", stderr=f"{cmd[0]}: command not found")


def generate_keypair() -> tuple[str, str]:
    """Return (private_key, public_key) using wg if available, else cryptography X25519 fallback."""
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

    # Fallback: proper X25519 keypair via cryptography library
    # WireGuard keys are Curve25519: private key is 32 random bytes (clamped by X25519),
    # public key is derived via scalar multiplication.
    import base64

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    private_key_obj = X25519PrivateKey.generate()
    # Raw format gives us the 32-byte key that WireGuard expects
    private_bytes = private_key_obj.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_bytes = private_key_obj.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    private_key = base64.b64encode(private_bytes).decode()
    public_key = base64.b64encode(public_bytes).decode()
    logger.info("wg binary unavailable; generated X25519 keypair via cryptography")
    return private_key, public_key


def public_key_from_private(private_key_b64: str) -> str:
    """Derive the WireGuard public key from a base64-encoded private key."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    private_bytes = base64.b64decode(private_key_b64)
    private_key_obj = X25519PrivateKey.from_private_bytes(private_bytes)
    public_bytes = private_key_obj.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return base64.b64encode(public_bytes).decode()


def ensure_hub_interface(private_key: str) -> None:
    """Bring up wg0 without wiping peers.

    Important: do NOT use `wg setconf` with an interface-only file here — that
    removes every peer on each poll (~15s) and clears live handshakes.
    """
    settings = get_settings()
    dry = settings.wg_dry_run
    iface = settings.wg_interface

    _run(["ip", "link", "add", "dev", iface, "type", "wireguard"], dry_run=dry)
    key_path = Path(f"/tmp/{iface}.priv")
    if not dry:
        key_path.write_text(private_key + "\n", encoding="utf-8")
        key_path.chmod(0o600)
    result = _run(
        [
            "wg",
            "set",
            iface,
            "private-key",
            str(key_path),
            "listen-port",
            str(settings.wg_listen_port),
        ],
        dry_run=dry,
    )
    if result.returncode != 0 and not dry:
        logger.warning("wg set listen-port/private-key failed: %s", result.stderr)
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
