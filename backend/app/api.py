"""JSON API endpoints for ParkTech Relay."""

from __future__ import annotations

import secrets
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.config import get_settings
from app.db import get_db
from app.models import Engineer, Site, SiteDevice
from app.services.engineers import (
    create_engineer,
    delete_engineer,
    disable_engineer,
    enable_engineer,
    render_engineer_conf,
)
from app.services.provision import add_device, create_site, get_or_create_settings
from app.services.subnets import virtual_ip_for_local

router = APIRouter(prefix="/api", tags=["api"])


def _authed_session(request: Request) -> bool:
    """Check if request has valid admin session cookie."""
    return request.cookies.get("relay_session") == "ok"


def _authed_token(authorization: str | None) -> bool:
    """Check if request has valid API bearer token."""
    cfg = get_settings()
    if not cfg.api_token:
        return False
    if not authorization:
        return False
    if not authorization.startswith("Bearer "):
        return False
    token = authorization[7:]
    return secrets.compare_digest(token, cfg.api_token)


def require_api_auth(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> None:
    """Require either session cookie or API bearer token."""
    if _authed_session(request):
        return
    if _authed_token(authorization):
        return
    raise HTTPException(
        status_code=401,
        detail="Authentication required. Use session cookie or Bearer token.",
        headers={"WWW-Authenticate": "Bearer"},
    )


# --- Pydantic Models ---


class SiteCreate(BaseModel):
    name: str
    vpn_type: str  # tailscale | wireguard | openvpn
    local_subnet: str = "192.168.1.0/24"
    site_code: Optional[str] = None


class DeviceCreate(BaseModel):
    label: str
    device_type: str = "generic"
    local_ip: str
    admin_port: Optional[int] = None


class EngineerCreate(BaseModel):
    name: str


class VirtualIPPreview(BaseModel):
    local_ip: str
    local_subnet: str
    virtual_subnet: str


class SiteResponse(BaseModel):
    id: int
    name: str
    site_code: str
    vpn_type: str
    site_index: int
    virtual_subnet: str
    local_subnet: str
    online: bool


class DeviceResponse(BaseModel):
    id: int
    label: str
    device_type: str
    local_ip: str
    virtual_ip: str
    admin_port: Optional[int]


class EngineerResponse(BaseModel):
    id: int
    name: str
    assigned_ip: str
    enabled: bool


# --- Site Endpoints ---


@router.get("/sites", response_model=list[SiteResponse])
def api_list_sites(
    request: Request,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """List all sites."""
    sites = db.scalars(select(Site).order_by(Site.site_index)).all()
    return [
        SiteResponse(
            id=s.id,
            name=s.name,
            site_code=s.site_code,
            vpn_type=s.vpn_type,
            site_index=s.site_index,
            virtual_subnet=s.virtual_subnet,
            local_subnet=s.local_subnet,
            online=s.online,
        )
        for s in sites
    ]


@router.post("/sites", response_model=SiteResponse, status_code=201)
def api_create_site(
    request: Request,
    site_data: SiteCreate,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """Create a new site."""
    try:
        site = create_site(
            db,
            name=site_data.name,
            vpn_type=site_data.vpn_type,
            local_subnet=site_data.local_subnet,
            site_code=site_data.site_code,
        )
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc

    return SiteResponse(
        id=site.id,
        name=site.name,
        site_code=site.site_code,
        vpn_type=site.vpn_type,
        site_index=site.site_index,
        virtual_subnet=site.virtual_subnet,
        local_subnet=site.local_subnet,
        online=site.online,
    )


@router.get("/sites/{site_id}", response_model=SiteResponse)
def api_get_site(
    request: Request,
    site_id: int,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """Get a single site."""
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Site not found")
    return SiteResponse(
        id=site.id,
        name=site.name,
        site_code=site.site_code,
        vpn_type=site.vpn_type,
        site_index=site.site_index,
        virtual_subnet=site.virtual_subnet,
        local_subnet=site.local_subnet,
        online=site.online,
    )


@router.delete("/sites/{site_id}", status_code=204)
def api_delete_site(
    request: Request,
    site_id: int,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """Delete a site."""
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Site not found")
    db.delete(site)
    db.commit()
    return None


# --- Device Endpoints ---


@router.get("/sites/{site_id}/devices", response_model=list[DeviceResponse])
def api_list_devices(
    request: Request,
    site_id: int,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """List all devices for a site."""
    site = db.scalar(
        select(Site).options(selectinload(Site.devices)).where(Site.id == site_id)
    )
    if not site:
        raise HTTPException(404, "Site not found")
    return [
        DeviceResponse(
            id=d.id,
            label=d.label,
            device_type=d.device_type,
            local_ip=d.local_ip,
            virtual_ip=d.virtual_ip,
            admin_port=d.admin_port,
        )
        for d in site.devices
    ]


@router.post("/sites/{site_id}/devices", response_model=DeviceResponse, status_code=201)
def api_create_device(
    request: Request,
    site_id: int,
    device_data: DeviceCreate,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """Add a device to a site."""
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404, "Site not found")
    try:
        device = add_device(
            db,
            site,
            label=device_data.label,
            device_type=device_data.device_type,
            local_ip=device_data.local_ip,
            admin_port=device_data.admin_port,
        )
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc

    return DeviceResponse(
        id=device.id,
        label=device.label,
        device_type=device.device_type,
        local_ip=device.local_ip,
        virtual_ip=device.virtual_ip,
        admin_port=device.admin_port,
    )


@router.delete("/sites/{site_id}/devices/{device_id}", status_code=204)
def api_delete_device(
    request: Request,
    site_id: int,
    device_id: int,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """Delete a device from a site."""
    device = db.get(SiteDevice, device_id)
    if not device or device.site_id != site_id:
        raise HTTPException(404, "Device not found")
    db.delete(device)
    db.commit()
    return None


# --- Engineer Endpoints ---


@router.get("/engineers", response_model=list[EngineerResponse])
def api_list_engineers(
    request: Request,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """List all engineers."""
    engineers = db.scalars(select(Engineer).order_by(Engineer.created_at)).all()
    return [
        EngineerResponse(
            id=e.id,
            name=e.name,
            assigned_ip=e.assigned_ip,
            enabled=e.enabled,
        )
        for e in engineers
    ]


@router.post("/engineers", response_model=EngineerResponse, status_code=201)
def api_create_engineer(
    request: Request,
    engineer_data: EngineerCreate,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """Create a new engineer."""
    try:
        engineer = create_engineer(db, name=engineer_data.name)
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc

    return EngineerResponse(
        id=engineer.id,
        name=engineer.name,
        assigned_ip=engineer.assigned_ip,
        enabled=engineer.enabled,
    )


@router.get("/engineers/{engineer_id}", response_model=EngineerResponse)
def api_get_engineer(
    request: Request,
    engineer_id: int,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """Get a single engineer."""
    engineer = db.get(Engineer, engineer_id)
    if not engineer:
        raise HTTPException(404, "Engineer not found")
    return EngineerResponse(
        id=engineer.id,
        name=engineer.name,
        assigned_ip=engineer.assigned_ip,
        enabled=engineer.enabled,
    )


@router.post("/engineers/{engineer_id}/enable", response_model=EngineerResponse)
def api_enable_engineer(
    request: Request,
    engineer_id: int,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """Enable an engineer's access."""
    engineer = db.get(Engineer, engineer_id)
    if not engineer:
        raise HTTPException(404, "Engineer not found")
    enable_engineer(db, engineer)
    return EngineerResponse(
        id=engineer.id,
        name=engineer.name,
        assigned_ip=engineer.assigned_ip,
        enabled=engineer.enabled,
    )


@router.post("/engineers/{engineer_id}/disable", response_model=EngineerResponse)
def api_disable_engineer(
    request: Request,
    engineer_id: int,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """Disable an engineer's access."""
    engineer = db.get(Engineer, engineer_id)
    if not engineer:
        raise HTTPException(404, "Engineer not found")
    disable_engineer(db, engineer)
    return EngineerResponse(
        id=engineer.id,
        name=engineer.name,
        assigned_ip=engineer.assigned_ip,
        enabled=engineer.enabled,
    )


@router.delete("/engineers/{engineer_id}", status_code=204)
def api_delete_engineer(
    request: Request,
    engineer_id: int,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """Delete an engineer."""
    engineer = db.get(Engineer, engineer_id)
    if not engineer:
        raise HTTPException(404, "Engineer not found")
    delete_engineer(db, engineer)
    return None


# --- Access Events & Sessions Endpoints ---


class AccessEventResponse(BaseModel):
    id: int
    timestamp: str
    actor_type: str
    actor_name: str
    site_id: Optional[int]
    device_id: Optional[int]
    kind: str
    source_ip: Optional[str]
    detail: Optional[str]


class LiveSessionResponse(BaseModel):
    actor_type: str
    actor_id: int
    actor_name: str
    vpn_type: str
    endpoint: Optional[str]
    last_handshake: Optional[str]
    transfer_rx: int
    transfer_tx: int
    site_id: Optional[int]


@router.get("/access-events", response_model=list[AccessEventResponse])
def api_list_access_events(
    request: Request,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
    site_id: Optional[int] = None,
    engineer_id: Optional[int] = None,
    kind: Optional[str] = None,
    days: int = 7,
    limit: int = 500,
):
    """List recent access events."""
    from datetime import datetime, timedelta

    from app.services.audit import get_recent_events

    since = datetime.utcnow() - timedelta(days=days)
    events = get_recent_events(
        db,
        site_id=site_id,
        engineer_id=engineer_id,
        kind=kind,
        since=since,
        limit=min(limit, 1000),
    )
    return [
        AccessEventResponse(
            id=e.id,
            timestamp=e.timestamp.isoformat() if e.timestamp else "",
            actor_type=e.actor_type,
            actor_name=e.actor_name,
            site_id=e.site_id,
            device_id=e.device_id,
            kind=e.kind,
            source_ip=e.source_ip,
            detail=e.detail,
        )
        for e in events
    ]


@router.get("/sessions", response_model=list[LiveSessionResponse])
def api_list_sessions(
    request: Request,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_auth),
):
    """List currently connected sessions (engineers and sites)."""
    from app.services.sessions import get_live_sessions

    sessions = get_live_sessions(db)
    return [
        LiveSessionResponse(
            actor_type=s.actor_type,
            actor_id=s.actor_id,
            actor_name=s.actor_name,
            vpn_type=s.vpn_type,
            endpoint=s.endpoint,
            last_handshake=s.last_handshake.isoformat() if s.last_handshake else None,
            transfer_rx=s.transfer_rx,
            transfer_tx=s.transfer_tx,
            site_id=s.site_id,
        )
        for s in sessions
    ]


# --- Utility Endpoints ---


@router.post("/preview-virtual-ip")
def api_preview_virtual_ip(
    request: Request,
    data: VirtualIPPreview,
    _auth: None = Depends(require_api_auth),
):
    """Preview the virtual IP translation for a local IP."""
    try:
        virtual_ip = virtual_ip_for_local(
            data.virtual_subnet,
            data.local_ip,
            data.local_subnet,
        )
        return {"virtual_ip": virtual_ip}
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
