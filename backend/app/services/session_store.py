"""Server-side session management with CSRF protection."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional


@dataclass
class SessionData:
    """Server-side session data."""
    created_at: datetime = field(default_factory=datetime.utcnow)
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    source_ip: Optional[str] = None


SESSION_TTL = timedelta(hours=24)
_sessions: dict[str, SessionData] = {}
_lock = threading.Lock()


def create_session(source_ip: Optional[str] = None) -> tuple[str, SessionData]:
    """Create a new session and return (session_id, session_data)."""
    session_id = secrets.token_urlsafe(32)
    data = SessionData(source_ip=source_ip)
    with _lock:
        _sessions[session_id] = data
    return session_id, data


def get_session(session_id: str) -> Optional[SessionData]:
    """Get session data if valid and not expired."""
    with _lock:
        data = _sessions.get(session_id)
        if not data:
            return None
        if datetime.utcnow() - data.created_at > SESSION_TTL:
            del _sessions[session_id]
            return None
        return data


def delete_session(session_id: str) -> None:
    """Delete a session."""
    with _lock:
        _sessions.pop(session_id, None)


def validate_csrf(session_id: str, csrf_token: str) -> bool:
    """Validate a CSRF token for a session."""
    data = get_session(session_id)
    if not data:
        return False
    return hmac.compare_digest(data.csrf_token, csrf_token)


def cleanup_expired() -> int:
    """Remove expired sessions. Returns count of removed sessions."""
    now = datetime.utcnow()
    removed = 0
    with _lock:
        expired_ids = [
            sid for sid, data in _sessions.items()
            if now - data.created_at > SESSION_TTL
        ]
        for sid in expired_ids:
            del _sessions[sid]
            removed += 1
    return removed


def clear_all_sessions() -> None:
    """Clear all sessions (for testing)."""
    with _lock:
        _sessions.clear()
