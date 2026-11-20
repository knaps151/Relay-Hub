"""Server-side QR codes for WireGuard mobile import (no CDN / browser JS)."""

from __future__ import annotations


def svg_data_uri(payload: str, *, scale: int = 4) -> str:
    """Return a data: URI SVG QR encoding ``payload`` (WireGuard conf text)."""
    import segno

    qr = segno.make(payload, error="m")
    return qr.svg_data_uri(scale=scale, border=2)
