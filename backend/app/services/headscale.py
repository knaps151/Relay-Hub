from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class HeadscaleError(RuntimeError):
    pass


class HeadscaleClient:
    def __init__(self) -> None:
        self.settings = get_settings()

    def _api_key(self) -> str:
        path = Path(self.settings.headscale_api_key_file)
        if path.exists():
            key = path.read_text(encoding="utf-8").strip()
            if key:
                return key
        raise HeadscaleError(
            f"Headscale API key not found at {path}. Wait for bootstrap or create one."
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key()}",
            "Accept": "application/json",
        }

    def _url(self, path: str) -> str:
        return f"{self.settings.headscale_api_url.rstrip('/')}/{path.lstrip('/')}"

    def ready(self) -> bool:
        try:
            self._api_key()
            with httpx.Client(timeout=5.0) as client:
                r = client.get(self._url("/api/v1/user"), headers=self._headers())
                return r.status_code < 500
        except Exception:
            return False

    def list_users(self) -> list[dict[str, Any]]:
        with httpx.Client(timeout=10.0) as client:
            r = client.get(self._url("/api/v1/user"), headers=self._headers())
            if r.status_code >= 400:
                raise HeadscaleError(f"list users failed: {r.status_code} {r.text}")
            data = r.json()
            return data.get("users") or data.get("Users") or []

    def ensure_user(self, name: str) -> dict[str, Any]:
        users = self.list_users()
        for u in users:
            if u.get("name") == name:
                return u
        with httpx.Client(timeout=10.0) as client:
            r = client.post(
                self._url("/api/v1/user"),
                headers=self._headers(),
                json={"name": name},
            )
            if r.status_code >= 400:
                # race: already exists
                users = self.list_users()
                for u in users:
                    if u.get("name") == name:
                        return u
                raise HeadscaleError(f"create user failed: {r.status_code} {r.text}")
            data = r.json()
            return data.get("user") or data.get("User") or data

    def create_preauth_key(
        self,
        user: str,
        *,
        reusable: bool = False,
        ephemeral: bool = False,
        expiration_days: int = 365,
    ) -> str:
        self.ensure_user(user)
        expiry = datetime.now(timezone.utc) + timedelta(days=expiration_days)
        payload = {
            "user": user,
            "reusable": reusable,
            "ephemeral": ephemeral,
            "expiration": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        with httpx.Client(timeout=10.0) as client:
            r = client.post(
                self._url("/api/v1/preauthkey"),
                headers=self._headers(),
                json=payload,
            )
            if r.status_code >= 400:
                raise HeadscaleError(f"create preauth key failed: {r.status_code} {r.text}")
            data = r.json()
            key_obj = data.get("preAuthKey") or data.get("preauthkey") or data.get("preAuthKeys") or data
            if isinstance(key_obj, list):
                key_obj = key_obj[0]
            key = key_obj.get("key") if isinstance(key_obj, dict) else None
            if not key:
                raise HeadscaleError(f"unexpected preauth response: {data}")
            return key

    def list_nodes(self, user: Optional[str] = None) -> list[dict[str, Any]]:
        params = {}
        if user:
            params["user"] = user
        with httpx.Client(timeout=10.0) as client:
            r = client.get(
                self._url("/api/v1/node"),
                headers=self._headers(),
                params=params,
            )
            if r.status_code >= 400:
                raise HeadscaleError(f"list nodes failed: {r.status_code} {r.text}")
            data = r.json()
            return data.get("nodes") or data.get("Nodes") or []

    def find_node_for_site(self, site_code: str, user: Optional[str] = None) -> Optional[dict[str, Any]]:
        nodes = self.list_nodes(user=user)
        needle = site_code.lower().replace("_", "-")
        for node in nodes:
            name = (node.get("name") or node.get("givenName") or node.get("hostname") or "").lower()
            if needle in name or name == needle:
                return node
            tags = node.get("validTags") or node.get("forcedTags") or []
            if any(site_code in str(t) for t in tags):
                return node
        return None

    def node_online(self, node: dict[str, Any]) -> bool:
        # Headscale exposes online boolean in recent versions; fall back to lastSeen heuristics
        if "online" in node:
            return bool(node["online"])
        if "Online" in node:
            return bool(node["Online"])
        return bool(node.get("online") or node.get("Online"))


def join_command(headscale_url: str, auth_key: str, advertise_routes: str) -> str:
    return (
        f"tailscale up --login-server={headscale_url} "
        f"--authkey={auth_key} "
        f"--advertise-routes={advertise_routes} "
        f"--accept-routes --accept-dns=false"
    )
