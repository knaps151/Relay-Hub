"""Live session tracking for engineers and sites."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Engineer, Site
from app.services import openvpn, wireguard
from app.services.headscale import HeadscaleClient

logger = logging.getLogger(__name__)

# In-memory state for tracking connection transitions
_last_online_state: dict[str, bool] = {}  # key -> was_online


@dataclass
class LiveSession:
    """A currently connected session."""
    actor_type: str  # engineer | site
    actor_id: int
    actor_name: str
    vpn_type: str  # wireguard | openvpn | tailscale
    endpoint: Optional[str]
    last_handshake: Optional[datetime]
    transfer_rx: int = 0
    transfer_tx: int = 0
    site_id: Optional[int] = None
    access_mode: str = "gateway"  # gateway | direct (sites only)


def get_live_sessions(db: Session) -> list[LiveSession]:
    """Get all currently connected sessions (engineers and sites)."""
    sessions: list[LiveSession] = []
    cfg = get_settings()

    # Get WireGuard handshakes
    handshakes = {p.public_key: p for p in wireguard.parse_handshakes()}

    # Engineer sessions (WireGuard)
    engineers = db.scalars(select(Engineer).where(Engineer.enabled == True)).all()
    for eng in engineers:
        peer = handshakes.get(eng.wg_public_key)
        if peer and wireguard.handshake_is_online(peer.latest_handshake):
            sessions.append(LiveSession(
                actor_type="engineer",
                actor_id=eng.id,
                actor_name=eng.name,
                vpn_type="wireguard",
                endpoint=peer.endpoint,
                last_handshake=peer.latest_handshake,
                transfer_rx=peer.transfer_rx,
                transfer_tx=peer.transfer_tx,
            ))

    # Site sessions
    sites = db.scalars(select(Site)).all()

    for site in sites:
        if site.vpn_type == "wireguard":
            peer = handshakes.get(site.wg_public_key)
            if peer and wireguard.handshake_is_online(peer.latest_handshake):
                sessions.append(LiveSession(
                    actor_type="site",
                    actor_id=site.id,
                    actor_name=site.name,
                    vpn_type="wireguard",
                    endpoint=peer.endpoint,
                    last_handshake=peer.latest_handshake,
                    transfer_rx=peer.transfer_rx,
                    transfer_tx=peer.transfer_tx,
                    site_id=site.id,
                    access_mode=getattr(site, "access_mode", "gateway") or "gateway",
                ))
        elif site.vpn_type == "openvpn":
            connected = openvpn.connected_clients()
            if site.ovpn_common_name and site.ovpn_common_name in connected:
                sessions.append(LiveSession(
                    actor_type="site",
                    actor_id=site.id,
                    actor_name=site.name,
                    vpn_type="openvpn",
                    endpoint=None,
                    last_handshake=connected[site.ovpn_common_name],
                    site_id=site.id,
                    access_mode=getattr(site, "access_mode", "gateway") or "gateway",
                ))
        elif site.vpn_type == "tailscale":
            if site.online:
                sessions.append(LiveSession(
                    actor_type="site",
                    actor_id=site.id,
                    actor_name=site.name,
                    vpn_type="tailscale",
                    endpoint=None,
                    last_handshake=site.last_seen,
                    site_id=site.id,
                    access_mode=getattr(site, "access_mode", "gateway") or "gateway",
                ))

    return sessions


def poll_connection_transitions(db: Session) -> None:
    """
    Check for connection state transitions and log them.
    Called from the background loop.
    """
    from app.services.audit import (
        record_engineer_connect,
        record_engineer_disconnect,
        record_site_connect,
        record_site_disconnect,
    )

    cfg = get_settings()

    # Get current WireGuard handshakes
    handshakes = {p.public_key: p for p in wireguard.parse_handshakes()}

    # Check engineer connections
    engineers = db.scalars(select(Engineer).where(Engineer.enabled == True)).all()
    for eng in engineers:
        key = f"engineer:{eng.id}"
        peer = handshakes.get(eng.wg_public_key)
        is_online = peer is not None and wireguard.handshake_is_online(peer.latest_handshake)
        was_online = _last_online_state.get(key, False)

        if is_online and not was_online:
            # New connection
            record_engineer_connect(
                db,
                engineer=eng,
                source_ip=peer.endpoint.split(":")[0] if peer and peer.endpoint else None,
                transfer_rx=peer.transfer_rx if peer else 0,
                transfer_tx=peer.transfer_tx if peer else 0,
            )
            logger.info("Engineer %s connected", eng.name)
        elif was_online and not is_online:
            # Disconnection
            record_engineer_disconnect(db, engineer=eng)
            logger.info("Engineer %s disconnected", eng.name)

        _last_online_state[key] = is_online

    # Check site connections
    sites = db.scalars(select(Site)).all()

    # OpenVPN connected clients
    ovpn_connected = openvpn.connected_clients()

    for site in sites:
        key = f"site:{site.id}"

        if site.vpn_type == "wireguard":
            peer = handshakes.get(site.wg_public_key)
            is_online = peer is not None and wireguard.handshake_is_online(peer.latest_handshake)
            source_ip = peer.endpoint.split(":")[0] if peer and peer.endpoint else None
        elif site.vpn_type == "openvpn":
            is_online = site.ovpn_common_name in ovpn_connected if site.ovpn_common_name else False
            source_ip = None
        elif site.vpn_type == "tailscale":
            is_online = site.online
            source_ip = None
        else:
            is_online = False
            source_ip = None

        was_online = _last_online_state.get(key, False)

        if is_online and not was_online:
            record_site_connect(db, site=site, vpn_type=site.vpn_type, source_ip=source_ip)
            logger.info("Site %s (%s) connected", site.name, site.vpn_type)
        elif was_online and not is_online:
            record_site_disconnect(db, site=site, vpn_type=site.vpn_type)
            logger.info("Site %s (%s) disconnected", site.name, site.vpn_type)

        _last_online_state[key] = is_online


def clear_state_cache() -> None:
    """Clear the in-memory state cache. Useful for testing."""
    _last_online_state.clear()
