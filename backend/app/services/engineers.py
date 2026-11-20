"""Engineer + engineer-device WireGuard access."""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models import (
    CatalogueTechDeviceType,
    Engineer,
    EngineerDevice,
    HubState,
)
from app.services import wireguard
from app.services.provision import ensure_hub_wireguard_keys, get_or_create_settings

logger = logging.getLogger(__name__)

ENGINEER_SUBNET = "10.100.2.0/24"
ENGINEER_START_IP = 10


def next_engineer_ip(db: Session) -> str:
    """Next free host in 10.100.2.0/24 from engineer devices (+ legacy engineer rows)."""
    used_ips: set[int] = set()

    for eng in db.scalars(select(Engineer)).all():
        if eng.assigned_ip:
            host = int(eng.assigned_ip.split("/")[0].split(".")[-1])
            used_ips.add(host)

    for dev in db.scalars(select(EngineerDevice)).all():
        host = int(dev.assigned_ip.split("/")[0].split(".")[-1])
        used_ips.add(host)

    for host in range(ENGINEER_START_IP, 255):
        if host not in used_ips:
            return f"10.100.2.{host}"

    raise ValueError("No free engineer IPs available (max 244)")


def migrate_legacy_engineer_devices(db: Session) -> None:
    """Move legacy engineer WG identity onto an EngineerDevice row (idempotent)."""
    laptop = db.scalar(
        select(CatalogueTechDeviceType).where(CatalogueTechDeviceType.slug == "laptop")
    )
    engineers = db.scalars(select(Engineer).options(selectinload(Engineer.devices))).all()
    changed = False
    for eng in engineers:
        if eng.devices:
            continue
        if not (eng.wg_public_key and eng.wg_private_key and eng.assigned_ip):
            continue
        db.add(
            EngineerDevice(
                engineer_id=eng.id,
                tech_device_type_id=laptop.id if laptop else None,
                label="Laptop",
                wg_private_key=eng.wg_private_key,
                wg_public_key=eng.wg_public_key,
                assigned_ip=eng.assigned_ip if "/" in eng.assigned_ip else f"{eng.assigned_ip}/32",
                enabled=eng.enabled,
            )
        )
        changed = True
    if changed:
        db.commit()


def create_engineer(db: Session, *, name: str) -> Engineer:
    """Create engineer person (no WG peer until a device is added)."""
    # Empty strings keep compatibility with older SQLite NOT NULL engineer columns.
    engineer = Engineer(
        name=name.strip(),
        wg_private_key="",
        wg_public_key="",
        assigned_ip="",
        enabled=True,
    )
    db.add(engineer)
    db.commit()
    db.refresh(engineer)
    return engineer


def create_engineer_device(
    db: Session,
    engineer: Engineer,
    *,
    label: str,
    tech_device_type_id: int | None,
) -> EngineerDevice:
    ensure_hub_wireguard_keys(db)
    private_key, public_key = wireguard.generate_keypair()
    ip = next_engineer_ip(db)

    type_name = None
    if tech_device_type_id:
        t = db.get(CatalogueTechDeviceType, tech_device_type_id)
        if t:
            type_name = t.name

    device = EngineerDevice(
        engineer_id=engineer.id,
        tech_device_type_id=tech_device_type_id,
        label=(label.strip() or type_name or "Device"),
        wg_private_key=private_key,
        wg_public_key=public_key,
        assigned_ip=f"{ip}/32",
        enabled=True,
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    if engineer.enabled and device.enabled:
        _sync_device_peer(device)
    return device


def enable_engineer(db: Session, engineer: Engineer) -> None:
    engineer.enabled = True
    db.commit()
    for device in engineer.devices:
        if device.enabled:
            _sync_device_peer(device)


def disable_engineer(db: Session, engineer: Engineer) -> None:
    engineer.enabled = False
    db.commit()
    for device in engineer.devices:
        _remove_device_peer(device)


def delete_engineer(db: Session, engineer: Engineer) -> None:
    for device in list(engineer.devices):
        _remove_device_peer(device)
    db.delete(engineer)
    db.commit()


def enable_engineer_device(db: Session, device: EngineerDevice) -> None:
    device.enabled = True
    db.commit()
    if device.engineer and device.engineer.enabled:
        _sync_device_peer(device)


def disable_engineer_device(db: Session, device: EngineerDevice) -> None:
    device.enabled = False
    db.commit()
    _remove_device_peer(device)


def delete_engineer_device(db: Session, device: EngineerDevice) -> None:
    _remove_device_peer(device)
    db.delete(device)
    db.commit()


def _sync_device_peer(device: EngineerDevice) -> None:
    if not device.enabled:
        return
    ip = device.assigned_ip.split("/")[0]
    try:
        wireguard.set_peer(device.wg_public_key, f"{ip}/32", persistent_keepalive=25)
    except Exception as exc:
        logger.warning("Failed to add engineer device peer %s: %s", device.label, exc)


def _remove_device_peer(device: EngineerDevice) -> None:
    try:
        wireguard.remove_peer(device.wg_public_key)
    except Exception as exc:
        logger.warning("Failed to remove engineer device peer %s: %s", device.label, exc)


def reconcile_engineer_peers(db: Session) -> None:
    devices = db.scalars(
        select(EngineerDevice)
        .join(Engineer)
        .where(Engineer.enabled == True, EngineerDevice.enabled == True)  # noqa: E712
    ).all()
    for device in devices:
        _sync_device_peer(device)


def render_engineer_device_conf(db: Session, device: EngineerDevice) -> str:
    settings = get_or_create_settings(db)
    hub = db.get(HubState, 1)
    if not hub or not hub.wg_public_key:
        raise ValueError("Hub WireGuard keys not configured")

    ip = device.assigned_ip.split("/")[0]
    return wireguard.render_client_conf(
        client_private_key=device.wg_private_key,
        client_address=f"{ip}/32",
        hub_public_key=hub.wg_public_key,
        hub_endpoint=settings.wg_endpoint,
        allowed_ips="10.101.0.0/16,10.100.0.0/22",
        include_dns=False,
    )


# Back-compat wrappers used by older routes/tests
def render_engineer_conf(db: Session, engineer: Engineer) -> str:
    """Prefer first enabled device; fall back to legacy engineer keys."""
    devices = sorted(engineer.devices, key=lambda d: d.id)
    for device in devices:
        if device.enabled:
            return render_engineer_device_conf(db, device)
    if devices:
        return render_engineer_device_conf(db, devices[0])
    if engineer.wg_private_key and engineer.wg_public_key and engineer.assigned_ip:
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
    raise ValueError("Engineer has no devices yet — add a phone/laptop first")


def _sync_engineer_peer(engineer: Engineer) -> None:
    for device in engineer.devices:
        if engineer.enabled and device.enabled:
            _sync_device_peer(device)
        else:
            _remove_device_peer(device)
