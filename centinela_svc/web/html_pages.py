"""Static HTML pages, read once at import."""
from __future__ import annotations

from pathlib import Path

_DIR = Path(__file__).resolve().parent / "templates"


def _read(name: str) -> str:
    return (_DIR / name).read_text(encoding="utf-8")


PANEL = _read("panel.html")
LEGACY_PANEL = _read("panel_legacy.html") if (_DIR / "panel_legacy.html").exists() else PANEL
PORTAL = _read("portal.html")
DASHBOARD = _read("dashboard.html")
LOGIN = _read("login.html")
NO_ACCESS = _read("noaccess.html")
