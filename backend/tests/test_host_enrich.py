"""Unit tests for host enrichment helpers."""

from app.services.host_enrich import (
    HostEnrichment,
    infer_device_type,
    pick_admin_port,
    suggested_label,
)


def test_infer_camera_from_rtsp_port():
    assert infer_device_type("", [80, 554]) == "camera"


def test_infer_anpr_from_hostname():
    assert infer_device_type("anpr-gate.local", [80]) == "anpr"


def test_infer_ev_charger():
    assert infer_device_type("ev-charge-01", [8080]) == "ev_charger"


def test_pick_admin_port_prefers_http():
    assert pick_admin_port([22, 443, 80], "generic") == 80


def test_pick_admin_port_ev():
    assert pick_admin_port([80, 8080], "ev_charger") == 8080


def test_suggested_label_from_hostname():
    assert suggested_label("piserver.localdomain", "10.0.0.1", "generic") == "piserver"


def test_suggested_label_fallback_typed():
    assert suggested_label("", "192.168.1.50", "camera") == "Camera 192.168.1.50"


def test_suggested_label_generic_fallback():
    assert suggested_label("", "192.168.1.60", "generic") == "Discovered host 192.168.1.60"


def test_enrichment_dataclass_defaults():
    e = HostEnrichment(ip="10.101.0.5")
    assert e.device_type == "generic"
    assert e.open_ports == []
