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
from app.models import Engineer, Site, SiteDevice
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
    teltonika_uci_script,
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


def _is_insecure_config() -> bool:
    """Check if the app is running with an insecure configuration."""
    cfg = get_settings()
    # Insecure if using default password AND not in HTTP_ONLY mode (i.e., production)
    return cfg.admin_password == "parktech" and not cfg.http_only


def _security_warning() -> str | None:
    """Return a security warning message if applicable."""
    if _is_insecure_config():
        return (
            "SECURITY WARNING: You are using the default password 'parktech' "
            "in production mode (HTTP_ONLY=0). Change ADMIN_PASSWORD in .env immediately!"
        )
    return None


_last_prune_date: str = ""


async def _background_loops() -> None:
    global _last_prune_date
    cfg = get_settings()
    while True:
        db = SessionLocal()
        try:
            reconcile_wireguard_peers(db)
            poll_site_status(db)
            from app.services.engineers import reconcile_engineer_peers

            reconcile_engineer_peers(db)
            from app.services.sessions import poll_connection_transitions

            poll_connection_transitions(db)
            from datetime import date

            today = date.today().isoformat()
            if today != _last_prune_date:
                from app.services.audit import prune_old_events

                prune_old_events(db)
                _last_prune_date = today
        except Exception:
            logger.exception("background sync failed")
        finally:
            db.close()
        await asyncio.sleep(cfg.poll_interval_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
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

from app.api import router as api_router  # noqa: E402

app.include_router(api_router)


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



def _authed(request: Request) -> bool:
    return request.cookies.get("relay_session") == "ok"


def require_auth(request: Request) -> None:
    cfg = get_settings()
    # Allow health without auth; UI routes check cookie
    if request.url.path in {"/healthz", "/login"}:
        return
    if request.method == "POST" and request.url.path == "/login":
        return
    if not _authed(request) and not request.url.path.startswith("/static"):
        # API-ish downloads still need auth
        pass


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if _authed(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": None},
    )


@app.post("/login")
def login(request: Request, password: str = Form(...)):
    cfg = get_settings()
    if not secrets.compare_digest(password, cfg.admin_password):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid password"},
            status_code=401,
        )
    # Record login event (best-effort, don't block login on audit failure)
    try:
        db = SessionLocal()
        try:
            from app.services.audit import record_login
            source_ip = request.client.host if request.client else None
            record_login(db, source_ip=source_ip)
        finally:
            db.close()
    except Exception:
        pass  # Audit failure shouldn't block login

    redirect = RedirectResponse("/", status_code=303)
    redirect.set_cookie("relay_session", "ok", httponly=True, samesite="lax")
    return redirect


@app.post("/logout")
def logout():
    redirect = RedirectResponse("/login", status_code=303)
    redirect.delete_cookie("relay_session")
    return redirect


def _guard(request: Request):
    if not _authed(request):
        raise HTTPException(status_code=303, headers={"Location": "/login"})


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
    all_sites = _filter_sites(db)
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
            "security_warning": _security_warning(),
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
            "security_warning": _security_warning(),
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
            "security_warning": _security_warning(),
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
        {
            "settings": settings,
            "error": None,
            "regions": _all_regions(db),
            "security_warning": _security_warning(),
        },
    )


@app.post("/sites/new")
def site_new(
    request: Request,
    db: Session = Depends(get_db),
    name: str = Form(...),
    vpn_type: str = Form("wireguard"),
    local_subnet: str = Form("192.168.1.0/24"),
    site_code: str = Form(""),
    region: str = Form(""),
    access_mode: str = Form("gateway"),
    device_label: str = Form(""),
    device_admin_port: str = Form(""),
):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    port: int | None = None
    if device_admin_port.strip():
        try:
            port = int(device_admin_port.strip())
        except ValueError as exc:
            settings = get_or_create_settings(db)
            return templates.TemplateResponse(
                request,
                "site_new.html",
                {
                    "settings": settings,
                    "error": f"Invalid admin port: {exc}",
                    "regions": _all_regions(db),
                    "security_warning": _security_warning(),
                },
                status_code=400,
            )
    try:
        site = create_site(
            db,
            name=name,
            vpn_type=vpn_type,
            local_subnet=local_subnet or None,
            site_code=site_code or None,
            region=region or None,
            access_mode=access_mode or "gateway",
            device_label=device_label or None,
            device_admin_port=port,
        )
    except Exception as exc:
        settings = get_or_create_settings(db)
        return templates.TemplateResponse(
            request,
            "site_new.html",
            {
                "settings": settings,
                "error": str(exc),
                "regions": _all_regions(db),
                "security_warning": _security_warning(),
            },
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
    # Get recent access events for this site
    from app.services.audit import get_site_recent_events
    recent_events = get_site_recent_events(db, site_id=site.id, limit=10)
    return templates.TemplateResponse(
        request,
        "site_detail.html",
        {
            "settings": settings,
            "site": site,
            "join_cmd": join_cmd,
            "cfg": get_settings(),
            "security_warning": _security_warning(),
            "recent_events": recent_events,
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
    # Record config download
    from app.services.audit import record_config_download
    source_ip = request.client.host if request.client else None
    record_config_download(db, site=site, config_type="wireguard.conf", source_ip=source_ip)
    return PlainTextResponse(
        conf,
        media_type="application/x-wireguard-profile",
        headers={
            "Content-Disposition": f'attachment; filename="{site.site_code}.conf"',
            "Content-Type": "application/x-wireguard-profile; charset=utf-8",
        },
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
    # Record config download
    from app.services.audit import record_config_download
    source_ip = request.client.host if request.client else None
    record_config_download(db, site=site, config_type="client.ovpn", source_ip=source_ip)
    return PlainTextResponse(
        conf,
        media_type="application/x-openvpn-profile",
        headers={"Content-Disposition": f'attachment; filename="{site.site_code}.ovpn"'},
    )


@app.get("/sites/{site_id}/teltonika.txt")
def download_teltonika(request: Request, site_id: int, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    site = db.get(Site, site_id)
    if not site or site.vpn_type != "wireguard":
        raise HTTPException(404, "Teltonika config only available for WireGuard sites")
    try:
        script = teltonika_uci_script(db, site)
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
    # Record config download
    from app.services.audit import record_config_download
    source_ip = request.client.host if request.client else None
    record_config_download(db, site=site, config_type="teltonika.txt", source_ip=source_ip)
    return PlainTextResponse(
        script,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{site.site_code}-teltonika.txt"'},
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
            "security_warning": _security_warning(),
            "headscale_ready": _headscale_ready(),
            "openvpn_ready": openvpn.pki_ready(),
            "cfg": get_settings(),
        },
    )


# --- Engineers ---

@app.get("/engineers", response_class=HTMLResponse)
def engineers_list(request: Request, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    settings = get_or_create_settings(db)
    engineers = db.scalars(select(Engineer).order_by(Engineer.created_at)).all()
    return templates.TemplateResponse(
        request,
        "engineers.html",
        {
            "settings": settings,
            "engineers": engineers,
            "security_warning": _security_warning(),
        },
    )


@app.get("/engineers/new", response_class=HTMLResponse)
def engineer_new_form(request: Request, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    settings = get_or_create_settings(db)
    return templates.TemplateResponse(
        request,
        "engineer_new.html",
        {"settings": settings, "error": None, "security_warning": _security_warning()},
    )


@app.post("/engineers/new")
def engineer_new(
    request: Request,
    db: Session = Depends(get_db),
    name: str = Form(...),
):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)

    from app.services.engineers import create_engineer

    try:
        engineer = create_engineer(db, name=name)
    except Exception as exc:
        settings = get_or_create_settings(db)
        return templates.TemplateResponse(
            request,
            "engineer_new.html",
            {"settings": settings, "error": str(exc), "security_warning": _security_warning()},
            status_code=400,
        )
    return RedirectResponse(f"/engineers/{engineer.id}", status_code=303)


@app.get("/engineers/{engineer_id}", response_class=HTMLResponse)
def engineer_detail(request: Request, engineer_id: int, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    engineer = db.get(Engineer, engineer_id)
    if not engineer:
        raise HTTPException(404, "Engineer not found")
    settings = get_or_create_settings(db)
    return templates.TemplateResponse(
        request,
        "engineer_detail.html",
        {
            "settings": settings,
            "engineer": engineer,
            "security_warning": _security_warning(),
        },
    )


@app.post("/engineers/{engineer_id}/enable")
def engineer_enable(request: Request, engineer_id: int, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    engineer = db.get(Engineer, engineer_id)
    if not engineer:
        raise HTTPException(404)

    from app.services.engineers import enable_engineer

    enable_engineer(db, engineer)
    return RedirectResponse(f"/engineers/{engineer_id}", status_code=303)


@app.post("/engineers/{engineer_id}/disable")
def engineer_disable(request: Request, engineer_id: int, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    engineer = db.get(Engineer, engineer_id)
    if not engineer:
        raise HTTPException(404)

    from app.services.engineers import disable_engineer

    disable_engineer(db, engineer)
    return RedirectResponse(f"/engineers/{engineer_id}", status_code=303)


@app.post("/engineers/{engineer_id}/delete")
def engineer_delete(request: Request, engineer_id: int, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    engineer = db.get(Engineer, engineer_id)
    if not engineer:
        raise HTTPException(404)

    from app.services.engineers import delete_engineer

    delete_engineer(db, engineer)
    return RedirectResponse("/engineers", status_code=303)


@app.get("/engineers/{engineer_id}/wireguard.conf")
def download_engineer_conf(request: Request, engineer_id: int, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    engineer = db.get(Engineer, engineer_id)
    if not engineer:
        raise HTTPException(404)

    from app.services.engineers import render_engineer_conf

    conf = render_engineer_conf(db, engineer)
    # Record config download
    from app.services.audit import record_engineer_config_download
    source_ip = request.client.host if request.client else None
    record_engineer_config_download(db, engineer=engineer, source_ip=source_ip)
    filename = engineer.name.lower().replace(" ", "-")[:20] or "engineer"
    return PlainTextResponse(
        conf,
        media_type="application/x-wireguard-profile",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}.conf"',
            "Content-Type": "application/x-wireguard-profile; charset=utf-8",
        },
    )


# --- Connected / Access Log ---

@app.get("/connected", response_class=HTMLResponse)
def connected_page(request: Request, db: Session = Depends(get_db)):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    settings = get_or_create_settings(db)

    from app.services.sessions import get_live_sessions

    sessions = get_live_sessions(db)
    tech_sessions = [s for s in sessions if s.actor_type == "engineer"]
    site_sessions = [s for s in sessions if s.actor_type == "site"]
    return templates.TemplateResponse(
        request,
        "connected.html",
        {
            "settings": settings,
            "sessions": sessions,
            "tech_sessions": tech_sessions,
            "site_sessions": site_sessions,
            "tech_count": len(tech_sessions),
            "site_count": len(site_sessions),
            "security_warning": _security_warning(),
        },
    )


@app.get("/access-log", response_class=HTMLResponse)
def access_log_page(
    request: Request,
    db: Session = Depends(get_db),
    site_id: Optional[int] = Query(None),
    engineer_id: Optional[int] = Query(None),
    kind: Optional[str] = Query(None),
    days: int = Query(7),
):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    settings = get_or_create_settings(db)

    from datetime import datetime, timedelta

    from app.services.audit import get_recent_events

    since = datetime.utcnow() - timedelta(days=days)
    events = get_recent_events(
        db,
        site_id=site_id,
        engineer_id=engineer_id,
        kind=kind,
        since=since,
        limit=500,
    )

    # Get sites and engineers for filter dropdowns
    sites = db.scalars(select(Site).order_by(Site.name)).all()
    engineers = db.scalars(select(Engineer).order_by(Engineer.name)).all()

    return templates.TemplateResponse(
        request,
        "access_log.html",
        {
            "settings": settings,
            "events": events,
            "sites": sites,
            "engineers": engineers,
            "filter_site_id": site_id,
            "filter_engineer_id": engineer_id,
            "filter_kind": kind,
            "filter_days": days,
            "security_warning": _security_warning(),
        },
    )


@app.get("/access-log/export.csv")
def access_log_export(
    request: Request,
    db: Session = Depends(get_db),
    site_id: Optional[int] = Query(None),
    engineer_id: Optional[int] = Query(None),
    kind: Optional[str] = Query(None),
    days: int = Query(90),
):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)

    from datetime import datetime, timedelta
    import csv
    import io

    from app.services.audit import get_recent_events

    since = datetime.utcnow() - timedelta(days=days)
    events = get_recent_events(
        db,
        site_id=site_id,
        engineer_id=engineer_id,
        kind=kind,
        since=since,
        limit=10000,
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Kind", "Actor Type", "Actor Name", "Site ID", "Device ID", "Source IP", "Detail"])
    for e in events:
        writer.writerow([
            e.timestamp.isoformat() if e.timestamp else "",
            e.kind,
            e.actor_type,
            e.actor_name,
            e.site_id or "",
            e.device_id or "",
            e.source_ip or "",
            e.detail or "",
        ])

    csv_content = output.getvalue()
    return PlainTextResponse(
        csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="access-log-{datetime.utcnow().strftime("%Y%m%d")}.csv"'},
    )
