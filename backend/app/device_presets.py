from __future__ import annotations

from typing import Any

DEVICE_PRESETS: list[dict[str, Any]] = [
    {"id": "router", "label": "Router", "device_type": "router", "admin_port": 80},
    {"id": "anpr", "label": "ANPR Camera", "device_type": "anpr", "admin_port": 80},
    {"id": "camera", "label": "Camera", "device_type": "camera", "admin_port": 80},
    {"id": "pay_display", "label": "Pay & Display", "device_type": "pay_display", "admin_port": 80},
    {"id": "ev_charger", "label": "EV Charger", "device_type": "ev_charger", "admin_port": 8080},
    {"id": "generic", "label": "Generic", "device_type": "generic", "admin_port": None},
]


def rtsp_url(virtual_ip: str) -> str:
    return f"rtsp://{virtual_ip}:554/stream"
