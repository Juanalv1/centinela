"""Append-only, hash-chained JSONL audit log."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str, keep: int = 500) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.keep = keep
        self.entries: list[dict] = []
        self._lock = threading.Lock()
        self._prev = GENESIS
        self._seq = 0

    def append(self, kind: str, data: dict) -> dict:
        with self._lock:
            self._seq += 1
            entry = {"seq": self._seq, "ts": time.time(), "kind": kind,
                     "prev_sha256": self._prev, "data": data}
            line = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self._prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
            self.entries.append(entry)
            del self.entries[:-self.keep]
            return entry
