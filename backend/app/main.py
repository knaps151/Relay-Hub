from __future__ import annotations

import asyncio
import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.config import get_settings
from app.db import SessionLocal, get_db, init_db
from app.models import Site
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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("parktech.relay")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


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
    vpn_type: Optional[str] = Query(None),
):
    if not _authed(request):
        return RedirectResponse("/login", status_code=303)
    settings = get_or_create_settings(db)
    if not settings.setup_completed:
        return RedirectResponse("/setup", status_code=303)

    q = select(Site).options(selectinload(Site.devices)).order_by(Site.site_index)
    if vpn_type in {"tailscale", "wireguard", "openvpn"}:
        q = q.where(Site.vpn_type == vpn_type)
    sites = db.scalars(q).all()
    hs_ready = False
    try:
        hs_ready = HeadscaleClient().ready()
    except Exception:
        hs_ready = False

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "settings": settings,
            "sites": sites,
            "vpn_filter": vpn_type or "",
            "headscale_ready": hs_ready,
            "openvpn_ready": openvpn.pki_ready(),
            "cfg": get_settings(),
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
        {"settings": settings, "security_warning": _security_warning()},
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
        {"settings": settings, "error": None, "security_warning": _security_warning()},
    )


@app.post("/sites/new")
def site_new(
    request: Request,
    db: Session = Depends(get_db),
    name: str = Form(...),
    vpn_type: str = Form(...),
    local_subnet: str = Form("192.168.1.0/24"),
    site_code: str = Form(""),
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
        )
    except Exception as exc:
        settings = get_or_create_settings(db)
        return templates.TemplateResponse(
            request,
            "site_new.html",
            {"settings": settings, "error": str(exc), "security_warning": _security_warning()},
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
            "security_warning": _security_warning(),
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
    return RedirectResponse(f"/sites/{site_id}", status_code=303)


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
        request, "setup.html", {"settings": settings, "security_warning": _security_warning()}
    )
