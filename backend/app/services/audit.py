"""Access logging and audit service."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import AccessEvent, Engineer, Site

logger = logging.getLogger(__name__)


def record(
    db: Session,
    *,
    kind: str,
    actor_type: str = "admin",
    actor_id: Optional[int] = None,
    actor_name: str = "Admin",
    site_id: Optional[int] = None,
    device_id: Optional[int] = None,
    source_ip: Optional[str] = None,
    detail: Optional[str] = None,
) -> AccessEvent:
    """
    Record an access event.
    
    Kinds:
    - wg_handshake: WireGuard peer handshake detected
    - ovpn_connect: OpenVPN client connected
    - ts_connect: Tailscale node connected
    - wg_disconnect: WireGuard peer disconnected (no handshake for >3 min)
    - ovpn_disconnect: OpenVPN client disconnected
    - ts_disconnect: Tailscale node disconnected
    - config_download: Config file downloaded (.conf, .ovpn, teltonika.txt)
    - login: Admin login
    """
    event = AccessEvent(
        timestamp=datetime.utcnow(),
        actor_type=actor_type,
        actor_id=actor_id,
        actor_name=actor_name,
        site_id=site_id,
        device_id=device_id,
        kind=kind,
        source_ip=source_ip,
        detail=detail,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    logger.debug("Access event: %s by %s (%s)", kind, actor_name, source_ip)
    return event


def record_login(db: Session, *, source_ip: Optional[str] = None) -> AccessEvent:
    """Record an admin login event."""
    return record(
        db,
        kind="login",
        actor_type="admin",
        actor_name="Admin",
        source_ip=source_ip,
        detail="Admin login",
    )


def record_config_download(
    db: Session,
    *,
    site: Site,
    config_type: str,
    source_ip: Optional[str] = None,
) -> AccessEvent:
    """Record a config file download."""
    return record(
        db,
        kind="config_download",
        actor_type="admin",
        actor_name="Admin",
        site_id=site.id,
        source_ip=source_ip,
        detail=f"Downloaded {config_type} for {site.name}",
    )


def record_engineer_config_download(
    db: Session,
    *,
    engineer: Engineer,
    source_ip: Optional[str] = None,
) -> AccessEvent:
    """Record an engineer config download."""
    return record(
        db,
        kind="config_download",
        actor_type="admin",
        actor_name="Admin",
        source_ip=source_ip,
        detail=f"Downloaded config for engineer {engineer.name}",
    )


def record_engineer_connect(
    db: Session,
    *,
    engineer: Engineer,
    source_ip: Optional[str] = None,
    transfer_rx: int = 0,
    transfer_tx: int = 0,
) -> AccessEvent:
    """Record an engineer WireGuard connection (handshake)."""
    return record(
        db,
        kind="wg_handshake",
        actor_type="engineer",
        actor_id=engineer.id,
        actor_name=engineer.name,
        source_ip=source_ip,
        detail=f"WireGuard handshake (rx={transfer_rx}, tx={transfer_tx})",
    )


def record_engineer_disconnect(
    db: Session,
    *,
    engineer: Engineer,
) -> AccessEvent:
    """Record an engineer WireGuard disconnection."""
    return record(
        db,
        kind="wg_disconnect",
        actor_type="engineer",
        actor_id=engineer.id,
        actor_name=engineer.name,
        detail="WireGuard peer disconnected (no recent handshake)",
    )


def record_site_connect(
    db: Session,
    *,
    site: Site,
    vpn_type: str,
    source_ip: Optional[str] = None,
) -> AccessEvent:
    """Record a site VPN connection."""
    kind_map = {
        "wireguard": "wg_handshake",
        "openvpn": "ovpn_connect",
        "tailscale": "ts_connect",
    }
    kind = kind_map.get(vpn_type, "wg_handshake")
    return record(
        db,
        kind=kind,
        actor_type="admin",
        actor_name=f"Site: {site.name}",
        site_id=site.id,
        source_ip=source_ip,
        detail=f"{vpn_type.title()} site connected",
    )


def record_site_disconnect(
    db: Session,
    *,
    site: Site,
    vpn_type: str,
) -> AccessEvent:
    """Record a site VPN disconnection."""
    kind_map = {
        "wireguard": "wg_disconnect",
        "openvpn": "ovpn_disconnect",
        "tailscale": "ts_disconnect",
    }
    kind = kind_map.get(vpn_type, "wg_disconnect")
    return record(
        db,
        kind=kind,
        actor_type="admin",
        actor_name=f"Site: {site.name}",
        site_id=site.id,
        detail=f"{vpn_type.title()} site disconnected",
    )


def prune_old_events(db: Session, retention_days: Optional[int] = None) -> int:
    """
    Delete access events older than retention period.
    Returns number of deleted events.
    """
    if retention_days is None:
        retention_days = get_settings().access_log_retention_days

    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    result = db.execute(
        delete(AccessEvent).where(AccessEvent.timestamp < cutoff)
    )
    db.commit()
    deleted = result.rowcount
    if deleted > 0:
        logger.info("Pruned %d access events older than %d days", deleted, retention_days)
    return deleted


def get_recent_events(
    db: Session,
    *,
    site_id: Optional[int] = None,
    engineer_id: Optional[int] = None,
    kind: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = 100,
) -> list[AccessEvent]:
    """Get recent access events with optional filters."""
    q = select(AccessEvent).order_by(AccessEvent.timestamp.desc())

    if site_id is not None:
        q = q.where(AccessEvent.site_id == site_id)
    if engineer_id is not None:
        q = q.where(AccessEvent.actor_type == "engineer")
        q = q.where(AccessEvent.actor_id == engineer_id)
    if kind is not None:
        q = q.where(AccessEvent.kind == kind)
    if since is not None:
        q = q.where(AccessEvent.timestamp >= since)
    if until is not None:
        q = q.where(AccessEvent.timestamp <= until)

    q = q.limit(limit)
    return list(db.scalars(q).all())


def get_site_recent_events(db: Session, site_id: int, limit: int = 20) -> list[AccessEvent]:
    """Get recent access events for a specific site."""
    return get_recent_events(db, site_id=site_id, limit=limit)
