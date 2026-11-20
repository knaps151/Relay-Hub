"""Engineer management service for WireGuard access."""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Engineer, HubState
from app.services import wireguard
from app.services.provision import ensure_hub_wireguard_keys, get_or_create_settings

logger = logging.getLogger(__name__)

ENGINEER_SUBNET = "10.100.2.0/24"
ENGINEER_START_IP = 10  # Engineers start at .10, leaving .1-.9 reserved


def next_engineer_ip(db: Session) -> str:
    """Find the next available engineer IP address (10.100.2.10 and up)."""
    engineers = db.scalars(select(Engineer)).all()
    used_ips = set()
    for eng in engineers:
        # Extract host number from IP
        ip = eng.assigned_ip.split("/")[0]
        host = int(ip.split(".")[-1])
        used_ips.add(host)

    # Find lowest unused host number starting at ENGINEER_START_IP
    for host in range(ENGINEER_START_IP, 255):
        if host not in used_ips:
            return f"10.100.2.{host}"

    raise ValueError("No free engineer IPs available (max 244 engineers)")


def create_engineer(db: Session, *, name: str) -> Engineer:
    """Create a new engineer with WireGuard keys and add hub peer."""
    # Ensure hub keys exist
    ensure_hub_wireguard_keys(db)

    # Generate keypair
    private_key, public_key = wireguard.generate_keypair()

    # Allocate IP
    ip = next_engineer_ip(db)

    engineer = Engineer(
        name=name.strip(),
        wg_private_key=private_key,
        wg_public_key=public_key,
        assigned_ip=f"{ip}/32",
        enabled=True,
    )
    db.add(engineer)
    db.commit()
    db.refresh(engineer)

    # Add WireGuard peer
    _sync_engineer_peer(engineer)

    return engineer


def enable_engineer(db: Session, engineer: Engineer) -> None:
    """Enable an engineer and add their WireGuard peer."""
    engineer.enabled = True
    db.commit()
    _sync_engineer_peer(engineer)


def disable_engineer(db: Session, engineer: Engineer) -> None:
    """Disable an engineer and remove their WireGuard peer."""
    engineer.enabled = False
    db.commit()
    _remove_engineer_peer(engineer)


def delete_engineer(db: Session, engineer: Engineer) -> None:
    """Delete an engineer and remove their WireGuard peer."""
    _remove_engineer_peer(engineer)
    db.delete(engineer)
    db.commit()


def _sync_engineer_peer(engineer: Engineer) -> None:
    """Add or update the engineer's WireGuard peer on the hub."""
    if not engineer.enabled:
        return
    ip = engineer.assigned_ip.split("/")[0]
    try:
        wireguard.set_peer(
            engineer.wg_public_key,
            f"{ip}/32",
            persistent_keepalive=25,
        )
    except Exception as exc:
        logger.warning("Failed to add engineer peer %s: %s", engineer.name, exc)


def _remove_engineer_peer(engineer: Engineer) -> None:
    """Remove the engineer's WireGuard peer from the hub."""
    try:
        wireguard.remove_peer(engineer.wg_public_key)
    except Exception as exc:
        logger.warning("Failed to remove engineer peer %s: %s", engineer.name, exc)


def reconcile_engineer_peers(db: Session) -> None:
    """Ensure all enabled engineers have hub peers."""
    engineers = db.scalars(select(Engineer).where(Engineer.enabled == True)).all()
    for eng in engineers:
        _sync_engineer_peer(eng)


def render_engineer_conf(db: Session, engineer: Engineer) -> str:
    """Generate WireGuard config file for an engineer."""
    settings = get_or_create_settings(db)
    hub = db.get(HubState, 1)
    if not hub or not hub.wg_public_key:
        raise ValueError("Hub WireGuard keys not configured")

    ip = engineer.assigned_ip.split("/")[0]
    return wireguard.render_client_conf(
        client_private_key=engineer.wg_private_key,
        client_address=f"{ip}/32",
        hub_public_key=hub.wg_public_key,
        hub_endpoint=settings.wg_endpoint,
        allowed_ips="10.101.0.0/16,10.100.0.0/22",
        include_dns=False,
    )
