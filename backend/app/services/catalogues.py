"""Admin catalogues: regions, tech device types, site equipment types."""

from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    CatalogueEquipmentType,
    CatalogueRegion,
    CatalogueTechDeviceType,
    Site,
)


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")[:80] or "item"


def seed_catalogues(db: Session) -> None:
    """Idempotent seed of default catalogue rows + import existing site regions."""
    _seed_regions(db)
    db.flush()
    _seed_tech_types(db)
    db.flush()
    _seed_equipment_types(db)
    db.flush()
    _import_site_regions(db)
    db.commit()


def _ensure_row(db: Session, model, *, name: str, slug: str, sort_order: int, **extra) -> None:
    existing = db.scalar(select(model).where(model.slug == slug))
    if existing:
        return
    # Also skip pending same-slug objects in this session
    for obj in db.new:
        if isinstance(obj, model) and getattr(obj, "slug", None) == slug:
            return
    db.add(model(name=name, slug=slug, sort_order=sort_order, active=True, **extra))


def _seed_regions(db: Session) -> None:
    defaults = [
        ("London", "london", 10),
        ("Midlands", "midlands", 20),
        ("North", "north", 30),
        ("South", "south", 40),
        ("Scotland", "scotland", 50),
        ("Wales", "wales", 60),
    ]
    for name, slug, order in defaults:
        _ensure_row(db, CatalogueRegion, name=name, slug=slug, sort_order=order)


def _seed_tech_types(db: Session) -> None:
    defaults = [
        ("Phone", "phone", 10),
        ("Laptop", "laptop", 20),
        ("Tablet", "tablet", 30),
    ]
    for name, slug, order in defaults:
        _ensure_row(db, CatalogueTechDeviceType, name=name, slug=slug, sort_order=order)


def _seed_equipment_types(db: Session) -> None:
    defaults = [
        ("Router", "router", 10, 80),
        ("ANPR Camera", "anpr", 20, 80),
        ("Camera", "camera", 30, 80),
        ("Pay & Display", "pay_display", 40, 80),
        ("EV Charger", "ev_charger", 50, 8080),
        ("Generic", "generic", 90, None),
    ]
    for name, slug, order, port in defaults:
        _ensure_row(
            db,
            CatalogueEquipmentType,
            name=name,
            slug=slug,
            sort_order=order,
            default_admin_port=port,
        )


def _import_site_regions(db: Session) -> None:
    rows = db.scalars(select(Site.region).where(Site.region != "").distinct()).all()
    for name in rows:
        name = (name or "").strip()
        if not name:
            continue
        slug = slugify(name)
        existing = db.scalar(select(CatalogueRegion).where(CatalogueRegion.slug == slug))
        if existing:
            continue
        pending = any(
            isinstance(obj, CatalogueRegion) and obj.slug == slug for obj in db.new
        )
        if pending:
            continue
        db.add(
            CatalogueRegion(
                name=name,
                slug=slug,
                active=True,
                sort_order=100,
            )
        )


def list_regions(db: Session, *, active_only: bool = True) -> list[CatalogueRegion]:
    q = select(CatalogueRegion).order_by(CatalogueRegion.sort_order, CatalogueRegion.name)
    if active_only:
        q = q.where(CatalogueRegion.active == True)  # noqa: E712
    return list(db.scalars(q).all())


def list_tech_device_types(db: Session, *, active_only: bool = True) -> list[CatalogueTechDeviceType]:
    q = select(CatalogueTechDeviceType).order_by(
        CatalogueTechDeviceType.sort_order, CatalogueTechDeviceType.name
    )
    if active_only:
        q = q.where(CatalogueTechDeviceType.active == True)  # noqa: E712
    return list(db.scalars(q).all())


def list_equipment_types(db: Session, *, active_only: bool = True) -> list[CatalogueEquipmentType]:
    q = select(CatalogueEquipmentType).order_by(
        CatalogueEquipmentType.sort_order, CatalogueEquipmentType.name
    )
    if active_only:
        q = q.where(CatalogueEquipmentType.active == True)  # noqa: E712
    return list(db.scalars(q).all())


def add_region(db: Session, *, name: str) -> CatalogueRegion:
    name = name.strip()
    if not name:
        raise ValueError("Region name is required")
    slug = slugify(name)
    if db.scalar(select(CatalogueRegion).where(CatalogueRegion.slug == slug)):
        raise ValueError("A region with that name already exists")
    row = CatalogueRegion(name=name, slug=slug, active=True, sort_order=100)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def add_tech_device_type(db: Session, *, name: str) -> CatalogueTechDeviceType:
    name = name.strip()
    if not name:
        raise ValueError("Type name is required")
    slug = slugify(name)
    if db.scalar(select(CatalogueTechDeviceType).where(CatalogueTechDeviceType.slug == slug)):
        raise ValueError("A tech device type with that name already exists")
    row = CatalogueTechDeviceType(name=name, slug=slug, active=True, sort_order=100)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def add_equipment_type(
    db: Session,
    *,
    name: str,
    default_admin_port: int | None = None,
) -> CatalogueEquipmentType:
    name = name.strip()
    if not name:
        raise ValueError("Type name is required")
    slug = slugify(name)
    if db.scalar(select(CatalogueEquipmentType).where(CatalogueEquipmentType.slug == slug)):
        raise ValueError("An equipment type with that name already exists")
    row = CatalogueEquipmentType(
        name=name,
        slug=slug,
        default_admin_port=default_admin_port,
        active=True,
        sort_order=100,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def set_active(db: Session, model, row_id: int, active: bool) -> None:
    row = db.get(model, row_id)
    if not row:
        raise ValueError("Item not found")
    row.active = active
    db.commit()
