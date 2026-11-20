"""Live session tracking for engineers and sites."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.config import get_settings
from app.models import Engineer, EngineerDevice, Site
from app.services import openvpn, wireguard

logger = logging.getLogger(__name__)

_last_online_state: dict[str, bool] = {}


@dataclass
class LiveSession:
    actor_type: str  # engineer | site
    actor_id: int
    actor_name: str
    vpn_type: str
    endpoint: Optional[str]
    last_handshake: Optional[datetime]
    transfer_rx: int = 0
    transfer_tx: int = 0
    site_id: Optional[int] = None
    access_mode: str = "gateway"
    device_label: Optional[str] = None
    device_type_name: Optional[str] = None
    engineer_device_id: Optional[int] = None


def get_live_sessions(db: Session) -> list[LiveSession]:
    sessions: list[LiveSession] = []
    handshakes = {p.public_key: p for p in wireguard.parse_handshakes()}

    devices = db.scalars(
        select(EngineerDevice)
        .options(
            selectinload(EngineerDevice.engineer),
            selectinload(EngineerDevice.tech_device_type),
        )
        .join(Engineer)
        .where(Engineer.enabled == True, EngineerDevice.enabled == True)  # noqa: E712
    ).all()

    for device in devices:
        peer = handshakes.get(device.wg_public_key)
        if peer and wireguard.handshake_is_online(peer.latest_handshake):
            eng = device.engineer
            type_name = device.tech_device_type.name if device.tech_device_type else None
            display = f"{eng.name} · {device.label}" if eng else device.label
            sessions.append(
                LiveSession(
                    actor_type="engineer",
                    actor_id=eng.id if eng else device.id,
                    actor_name=display,
                    vpn_type="wireguard",
                    endpoint=peer.endpoint,
                    last_handshake=peer.latest_handshake,
                    transfer_rx=peer.transfer_rx,
                    transfer_tx=peer.transfer_tx,
                    device_label=device.label,
                    device_type_name=type_name,
                    engineer_device_id=device.id,
                )
            )

    # Legacy engineer peers (pre-migration) still on hub
    for eng in db.scalars(select(Engineer).where(Engineer.enabled == True)).all():  # noqa: E712
        if not eng.wg_public_key:
            continue
        if any(d.wg_public_key == eng.wg_public_key for d in eng.devices):
            continue
        peer = handshakes.get(eng.wg_public_key)
        if peer and wireguard.handshake_is_online(peer.latest_handshake):
            sessions.append(
                LiveSession(
                    actor_type="engineer",
                    actor_id=eng.id,
                    actor_name=eng.name,
                    vpn_type="wireguard",
                    endpoint=peer.endpoint,
                    last_handshake=peer.latest_handshake,
                    transfer_rx=peer.transfer_rx,
                    transfer_tx=peer.transfer_tx,
                )
            )

    for site in db.scalars(select(Site)).all():
        if site.vpn_type == "wireguard":
            peer = handshakes.get(site.wg_public_key or "")
            if peer and wireguard.handshake_is_online(peer.latest_handshake):
                sessions.append(
                    LiveSession(
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
                    )
                )
        elif site.vpn_type == "openvpn":
            connected = openvpn.connected_clients()
            if site.ovpn_common_name and site.ovpn_common_name in connected:
                sessions.append(
                    LiveSession(
                        actor_type="site",
                        actor_id=site.id,
                        actor_name=site.name,
                        vpn_type="openvpn",
                        endpoint=None,
                        last_handshake=connected[site.ovpn_common_name],
                        site_id=site.id,
                        access_mode=getattr(site, "access_mode", "gateway") or "gateway",
                    )
                )
        elif site.vpn_type == "tailscale":
            if site.online:
                sessions.append(
                    LiveSession(
                        actor_type="site",
                        actor_id=site.id,
                        actor_name=site.name,
                        vpn_type="tailscale",
                        endpoint=None,
                        last_handshake=site.last_seen,
                        site_id=site.id,
                        access_mode=getattr(site, "access_mode", "gateway") or "gateway",
                    )
                )

    return sessions


def poll_connection_transitions(db: Session) -> None:
    from app.services.audit import (
        record_engineer_connect,
        record_engineer_disconnect,
        record_site_connect,
        record_site_disconnect,
    )

    handshakes = {p.public_key: p for p in wireguard.parse_handshakes()}

    devices = db.scalars(
        select(EngineerDevice)
        .options(selectinload(EngineerDevice.engineer))
        .join(Engineer)
        .where(Engineer.enabled == True, EngineerDevice.enabled == True)  # noqa: E712
    ).all()

    for device in devices:
        key = f"engineer_device:{device.id}"
        peer = handshakes.get(device.wg_public_key)
        is_online = peer is not None and wireguard.handshake_is_online(peer.latest_handshake)
        was_online = _last_online_state.get(key, False)
        eng = device.engineer
        if is_online and not was_online and eng:
            record_engineer_connect(
                db,
                engineer=eng,
                source_ip=peer.endpoint.split(":")[0] if peer and peer.endpoint else None,
                transfer_rx=peer.transfer_rx if peer else 0,
                transfer_tx=peer.transfer_tx if peer else 0,
            )
            logger.info("Engineer device %s (%s) connected", eng.name, device.label)
        elif was_online and not is_online and eng:
            record_engineer_disconnect(db, engineer=eng)
            logger.info("Engineer device %s (%s) disconnected", eng.name, device.label)
        _last_online_state[key] = is_online

    ovpn_connected = openvpn.connected_clients()
    for site in db.scalars(select(Site)).all():
        key = f"site:{site.id}"
        if site.vpn_type == "wireguard":
            peer = handshakes.get(site.wg_public_key or "")
            is_online = peer is not None and wireguard.handshake_is_online(peer.latest_handshake)
            source_ip = peer.endpoint.split(":")[0] if peer and peer.endpoint else None
        elif site.vpn_type == "openvpn":
            is_online = site.ovpn_common_name in ovpn_connected if site.ovpn_common_name else False
            source_ip = None
        else:
            is_online = bool(site.online)
            source_ip = None

        was_online = _last_online_state.get(key, False)
        if is_online and not was_online:
            record_site_connect(db, site=site, vpn_type=site.vpn_type, source_ip=source_ip)
            logger.info("Site %s (%s) connected", site.name, site.vpn_type)
        elif was_online and not is_online:
            record_site_disconnect(db, site=site, vpn_type=site.vpn_type)
            logger.info("Site %s (%s) disconnected", site.name, site.vpn_type)
        _last_online_state[key] = is_online
