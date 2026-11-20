from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class SettingsRow(Base):
    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    operator_name: Mapped[str] = mapped_column(String(200), default="ParkTech Operator")
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    public_ui_url: Mapped[str] = mapped_column(String(500), default="http://127.0.0.1:8000")
    headscale_url: Mapped[str] = mapped_column(String(500), default="http://127.0.0.1:8080")
    wg_endpoint: Mapped[str] = mapped_column(String(255), default="127.0.0.1:51820")
    openvpn_endpoint: Mapped[str] = mapped_column(String(255), default="127.0.0.1:1194")
    base_cidr: Mapped[str] = mapped_column(String(64), default="10.101.0.0/16")
    setup_completed: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Site(Base):
    __tablename__ = "sites"
    __table_args__ = (UniqueConstraint("site_code", name="uq_site_code"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200))
    site_code: Mapped[str] = mapped_column(String(64))
    vpn_type: Mapped[str] = mapped_column(String(32))  # tailscale | wireguard | openvpn
    region: Mapped[str] = mapped_column(String(120), default="")
    site_index: Mapped[int] = mapped_column(Integer)
    virtual_subnet: Mapped[str] = mapped_column(String(64))
    local_subnet: Mapped[str] = mapped_column(String(64), default="192.168.1.0/24")

    # Tailscale / Headscale
    ts_preauth_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ts_user: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ts_node_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ts_node_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # WireGuard
    wg_private_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    wg_public_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    wg_hub_public_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    wg_tunnel_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # OpenVPN
    ovpn_common_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ovpn_client_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    online: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_handshake: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    devices: Mapped[list[SiteDevice]] = relationship(
        "SiteDevice", back_populates="site", cascade="all, delete-orphan"
    )


class SiteDevice(Base):
    __tablename__ = "site_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    label: Mapped[str] = mapped_column(String(200))
    device_type: Mapped[str] = mapped_column(String(64), default="generic")
    local_ip: Mapped[str] = mapped_column(String(64))
    virtual_ip: Mapped[str] = mapped_column(String(64))
    admin_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    site: Mapped[Site] = relationship("Site", back_populates="devices")


class HubState(Base):
    __tablename__ = "hub_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    wg_private_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    wg_public_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
