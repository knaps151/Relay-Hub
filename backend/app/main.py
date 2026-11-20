from __future__ import annotations

import asyncio
import logging
import secrets
import subprocess
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.config import get_settings
from app.db import SessionLocal, get_db, init_db
from app.device_presets import DEVICE_PRESETS
from app.migrate import ensure_schema
from app.models import Site, SiteDevice
from app.services import openvpn
from app.services.headscale import HeadscaleClient
from app.services.provision import (
    add_device,
    create_site,
    get_or_create_settings,
    openvpn_client_conf,
    poll_site_status,
    reconcile_wireguard_peers,
    tailscale_join_cmd,
    wireguard_client_conf,
)
from app.services.subnets import virtual_ip_for_local

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("parktech.relay")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def _timeago(value: Optional[datetime]) -> str:
    if not value:
        return ""
    seconds = int((datetime.utcnow() - value).total_seconds())
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


templates.env.filters["timeago"] = _timeago
templates.env.filters["urlencode"] = lambda v: urlencode({"": v})[1:] if v is not None else ""


async def _background_loops() -> None:
    cfg = get_settings()
    while True:
        db = SessionLocal()
        try:
            reconcile_wireguard_peers(db)
            poll_site_status(db)
        except Exception:
            logger.exception("background sync failed")
        finally:
            db.close()
        await asyncio.sleep(cfg.poll_interval_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    ensure_schema()
    try:
        from app.bootstrap_headscale import bootstrap_headscale

        await asyncio.to_thread(bootstrap_headscale)
    except Exception:
        logger.exception("Headscale bootstrap failed")
    db = SessionLocal()
    try:
        get_or_create_settings(db)
    finally:
        db.close()
    task = asyncio.create_task(_background_loops())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="ParkTech Relay", lifespan=lifespan)
static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


def _authed(request: Request) -> bool:
    return request.cookies.get("relay_session") == "ok"


def _headscale_ready() -> bool:
    try:
        return HeadscaleClient().ready()
    except Exception:
        return False


def _all_regions(db: Session) -> list[str]:
    rows = db.scalars(select(Site.region).where(Site.region != "").distinct()).all()
    return sorted({(r or "").strip() for r in rows if (r or "").strip()})


def _filter_sites(
    db: Session,
    *,
    q: str = "",
    vpn_type: str = "",
    region: str = "",
) -> list[Site]:
    stmt = select(Site).options(selectinload(Site.devices))
    sites = list(db.scalars(stmt).all())
    qn = q.strip().lower()
    if qn:
        sites = [
            s
            for s in sites
            if qn in s.name.lower()
            or qn in s.site_code.lower()
            or qn in (s.region or "").lower()
        ]
    if vpn_type in {"tailscale", "wireguard", "openvpn"}:
        sites = [s for s in sites if s.vpn_type == vpn_type]
    if region.strip():
        sites = [s for s in sites if (s.region or "") == region.strip()]
    sites.sort(key=lambda s: (s.online, s.name.lower()))
    return sites


def _counts(sites: list[Site]) -> dict[str, int]:
    online = sum(1 for s in sites if s.online)
    return {"total": len(sites), "online": online, "offline": len(sites) - online}


def _checklist(db: Session, hs_ready: bool, ovpn_ready: bool) -> dict[str, bool]:
    sites = list(db.scalars(select(Site)).all())
    return {
        "headscale": hs_ready,
        "openvpn": ovpn_ready,
        "has_site": len(sites) > 0,
        "has_online": any(s.online for s in sites),
    }


def _toast(response: Response, message: str, ok: bool = True) -> Response:
    response.headers["X-Toast"] = message
    response.headers["X-Toast-Ok"] = "1" if ok else "0"
    return response


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if _authed(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None, "settings": None})


@app.post("/login")
def login(request: Request, password: str = Form(...)):
    cfg = get_settings()
    if not secrets.compare_digest(password, cfg.admin_password):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid password", "settings": None},
            status_code=401,
        )
    redirect = RedirectResponse("/", status_code=303)
    redirect.set_cookie("relay_session", "ok", httponly=True, samesite="lax")
    return redirect


@app.post("/logout")
def logout():
    redirect = RedirectResponse("/login", status_code=303)
    redirect.delete_cookie("relay_session")
    return redirect


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    q: str = Query(""),
    vpn_type: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    settings = get_or_create_settings(db)
    if not settings.setup_completed:
        return RedirectResponse("/setup", status_code=303)

    vpn_filter = vpn_type or ""
    region_filter = region or ""
    all_sites = _filter_sites(db, q="", vpn_type="", region="")
    sites = _filter_sites(db, q=q, vpn_type=vpn_filter, region=region_filter)
    hs_ready = _headscale_ready()
    ovpn_ready = openvpn.pki_ready()

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "settings": settings,
            "sites": sites,
            "q": q,
            "vpn_filter": vpn_filter,
            "region_filter": region_filter,
            "regions": _all_regions(db),
            "counts": _counts(all_sites),
            "checklist": _checklist(db, hs_ready, ovpn_ready),
            "headscale_ready": hs_ready,
            "openvpn_ready": ovpn_ready,
            "cfg": get_settings(),
        },
    )


@app.get("/partials/fleet", response_class=HTMLResponse)
def fleet_partial(
    request: Request,
    db: Session = Depends(get_db),
    q: str = Query(""),
    vpn_type: str = Query(""),
    region: str = Query(""),
):
    if not _authed(request):
        raise HTTPException(401)
    settings = get_or_create_settings(db)
    sites = _filter_sites(db, q=q, vpn_type=vpn_type, region=region)
    return templates.TemplateResponse(
        request,
        "partials/fleet_table.html",
        {
            "settings": settings,
            "sites": sites,
            "q": q,
            "vpn_filter": vpn_type,
            "region_filter": region,
        },
    )


@app.get("/setup", response_class=HTMLResponse)
def setup_form(request: Request, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    settings = get_or_create_settings(db)
    return templates.TemplateResponse(
        request,
        "setup.html",
        {
            "settings": settings,
            "headscale_ready": _headscale_ready(),
            "openvpn_ready": openvpn.pki_ready(),
            "cfg": get_settings(),
        },
    )


@app.post("/setup")
def setup_save(
    request: Request,
    db: Session = Depends(get_db),
    operator_name: str = Form(...),
    public_ui_url: str = Form(...),
    headscale_url: str = Form(...),
    wg_endpoint: str = Form(...),
    openvpn_endpoint: str = Form(...),
    base_cidr: str = Form("10.101.0.0/16"),
    domain: str = Form(""),
):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    settings = get_or_create_settings(db)
    settings.operator_name = operator_name.strip()
    settings.public_ui_url = public_ui_url.strip().rstrip("/")
    settings.headscale_url = headscale_url.strip().rstrip("/")
    settings.wg_endpoint = wg_endpoint.strip()
    settings.openvpn_endpoint = openvpn_endpoint.strip()
    settings.base_cidr = base_cidr.strip()
    settings.domain = domain.strip() or None
    settings.setup_completed = True
    db.commit()
    return RedirectResponse("/", status_code=303)


@app.get("/sites/new", response_class=HTMLResponse)
def site_new_form(request: Request, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    settings = get_or_create_settings(db)
    return templates.TemplateResponse(
        request,
        "site_new.html",
        {"settings": settings, "error": None, "regions": _all_regions(db)},
    )


@app.post("/sites/new")
def site_new(
    request: Request,
    db: Session = Depends(get_db),
    name: str = Form(...),
    vpn_type: str = Form(...),
    local_subnet: str = Form("192.168.1.0/24"),
    site_code: str = Form(""),
    region: str = Form(""),
):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    try:
        site = create_site(
            db,
            name=name,
            vpn_type=vpn_type,
            local_subnet=local_subnet or None,
            site_code=site_code or None,
            region=region or None,
        )
    except Exception as exc:
        settings = get_or_create_settings(db)
        return templates.TemplateResponse(
            request,
            "site_new.html",
            {"settings": settings, "error": str(exc), "regions": _all_regions(db)},
            status_code=400,
        )
    return RedirectResponse(f"/sites/{site.id}", status_code=303)


@app.get("/sites/{site_id}", response_class=HTMLResponse)
def site_detail(request: Request, site_id: int, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    site = db.scalar(
        select(Site).options(selectinload(Site.devices)).where(Site.id == site_id)
    )
    if not site:
        raise HTTPException(404, "Site not found")
    settings = get_or_create_settings(db)
    join_cmd = None
    if site.vpn_type == "tailscale":
        join_cmd = tailscale_join_cmd(db, site)
    return templates.TemplateResponse(
        request,
        "site_detail.html",
        {
            "settings": settings,
            "site": site,
            "join_cmd": join_cmd,
            "cfg": get_settings(),
            "presets": DEVICE_PRESETS,
        },
    )


@app.post("/sites/{site_id}/devices")
def site_add_device(
    request: Request,
    site_id: int,
    db: Session = Depends(get_db),
    label: str = Form(...),
    device_type: str = Form("generic"),
    local_ip: str = Form(...),
    admin_port: str = Form(""),
):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    site = db.get(Site, site_id)
    if not site:
        raise HTTPException(404)
    port = int(admin_port) if admin_port.strip().isdigit() else None
    add_device(db, site, label=label, device_type=device_type, local_ip=local_ip, admin_port=port)
    return RedirectResponse(f"/sites/{site_id}#cheat-sheet", status_code=303)


@app.post("/sites/{site_id}/devices/{device_id}/edit")
def site_edit_device(
    request: Request,
    site_id: int,
    device_id: int,
    db: Session = Depends(get_db),
    label: str = Form(...),
    device_type: str = Form(...),
    local_ip: str = Form(...),
    admin_port: str = Form(""),
):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    site = db.get(Site, site_id)
    device = db.get(SiteDevice, device_id)
    if not site or not device or device.site_id != site.id:
        raise HTTPException(404)
    device.label = label.strip()
    device.device_type = device_type.strip() or "generic"
    device.local_ip = local_ip.strip()
    device.admin_port = int(admin_port) if admin_port.strip().isdigit() else None
    device.virtual_ip = virtual_ip_for_local(site.virtual_subnet, device.local_ip, site.local_subnet)
    db.commit()
    return RedirectResponse(f"/sites/{site_id}#cheat-sheet", status_code=303)


@app.post("/sites/{site_id}/devices/{device_id}/delete")
def site_delete_device(
    request: Request,
    site_id: int,
    device_id: int,
    db: Session = Depends(get_db),
):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    site = db.get(Site, site_id)
    device = db.get(SiteDevice, device_id)
    if site and device and device.site_id == site.id:
        db.delete(device)
        db.commit()
    return RedirectResponse(f"/sites/{site_id}#cheat-sheet", status_code=303)


@app.post("/sites/{site_id}/devices/{device_id}/ping")
def site_ping_device(
    request: Request,
    site_id: int,
    device_id: int,
    db: Session = Depends(get_db),
):
    if not _authed(request):
        raise HTTPException(401)
    site = db.get(Site, site_id)
    device = db.get(SiteDevice, device_id)
    if not site or not device or device.site_id != site.id:
        raise HTTPException(404)

    target = device.virtual_ip
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", target],
        check=False,
        capture_output=True,
        text=True,
    )
    response = Response(status_code=204)
    if result.returncode == 0:
        return _toast(response, f"Ping OK - {target}", ok=True)
    return _toast(response, f"Ping failed - {target}", ok=False)


@app.post("/sites/{site_id}/delete")
def site_delete(request: Request, site_id: int, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    site = db.get(Site, site_id)
    if site:
        db.delete(site)
        db.commit()
    return RedirectResponse("/", status_code=303)


@app.get("/sites/{site_id}/wireguard.conf")
def download_wg(request: Request, site_id: int, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    site = db.get(Site, site_id)
    if not site or site.vpn_type != "wireguard":
        raise HTTPException(404)
    conf = wireguard_client_conf(db, site)
    return PlainTextResponse(
        conf,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{site.site_code}.conf"'},
    )


@app.get("/sites/{site_id}/client.ovpn")
def download_ovpn(request: Request, site_id: int, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    site = db.get(Site, site_id)
    if not site or site.vpn_type != "openvpn":
        raise HTTPException(404)
    try:
        conf = openvpn_client_conf(site)
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
    return PlainTextResponse(
        conf,
        media_type="application/x-openvpn-profile",
        headers={"Content-Disposition": f'attachment; filename="{site.site_code}.ovpn"'},
    )


@app.post("/sites/{site_id}/tailscale/refresh-key")
def refresh_ts_key(request: Request, site_id: int, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    site = db.get(Site, site_id)
    if not site or site.vpn_type != "tailscale":
        raise HTTPException(404)
    client = HeadscaleClient()
    site.ts_preauth_key = client.create_preauth_key(
        get_settings().headscale_user, reusable=False, expiration_days=365
    )
    site.notes = None
    db.commit()
    return RedirectResponse(f"/sites/{site_id}", status_code=303)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    settings = get_or_create_settings(db)
    return templates.TemplateResponse(
        request,
        "setup.html",
        {
            "settings": settings,
            "headscale_ready": _headscale_ready(),
            "openvpn_ready": openvpn.pki_ready(),
            "cfg": get_settings(),
        },
    )
