from __future__ import annotations

import logging
import os
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def bootstrap_headscale() -> None:
    """Create Headscale user + API key via CLI over the unix socket."""
    api_key_file = Path(os.environ.get("HEADSCALE_API_KEY_FILE", "/data/headscale-api.key"))
    sock = Path(os.environ.get("HEADSCALE_SOCKET", "/var/run/headscale/headscale.sock"))
    user = os.environ.get("HEADSCALE_USER", "parktech")

    logger.info("Waiting for Headscale socket at %s", sock)
    for _ in range(90):
        if sock.exists():
            break
        time.sleep(1)
    else:
        logger.error("Headscale socket not available; Tailscale provisioning will fail until fixed")
        return

    time.sleep(2)

    def run(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["headscale", *args],
            check=False,
            capture_output=True,
            text=True,
        )

    create_user = run(["users", "create", user])
    if create_user.returncode != 0 and "already" not in (create_user.stderr + create_user.stdout).lower():
        # older/newer CLI variants
        create_user = run(["user", "create", user])
        if create_user.returncode != 0:
            logger.warning("create user: %s %s", create_user.stdout, create_user.stderr)

    if api_key_file.exists() and api_key_file.read_text(encoding="utf-8").strip():
        logger.info("Headscale API key already present")
        return

    key_result = run(["apikeys", "create", "--expiration", "999d"])
    if key_result.returncode != 0:
        key_result = run(["api-keys", "create", "--expiration", "999d"])
    if key_result.returncode != 0:
        key_result = run(["apikey", "create", "--expiration", "999d"])

    if key_result.returncode != 0:
        logger.error("Failed to create API key: %s %s", key_result.stdout, key_result.stderr)
        return

    # Prefer last non-empty line; headscale often prints the raw key
    lines = [ln.strip() for ln in key_result.stdout.splitlines() if ln.strip()]
    key = lines[-1] if lines else ""
    # Sometimes key is prefixed
    for ln in reversed(lines):
        if len(ln) > 20 and " " not in ln:
            key = ln
            break
    if not key:
        logger.error("Could not parse API key from: %r", key_result.stdout)
        return

    api_key_file.parent.mkdir(parents=True, exist_ok=True)
    api_key_file.write_text(key, encoding="utf-8")
    api_key_file.chmod(0o644)
    logger.info("Wrote Headscale API key to %s", api_key_file)
