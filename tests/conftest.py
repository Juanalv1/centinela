"""Shared test setup: both services use flat imports and each has an `app.py`,
so they are loaded by path under unique module names."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SVC = ROOT / "centinela_svc"
VICTIM = ROOT / "victim"

sys.path.insert(0, str(SVC))
sys.path.insert(1, str(VICTIM))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
