"""Normalized access events: the one format every source is mapped to before the per-key baseline.

Metadata only: which credential (its id and label, never its value), from which
ip, when, which path and how much came back. Query strings and bodies are never
kept; the pagination parameter is the only part of a query that is read, as a
value. Fields outside the format are ignored, never stored. No I/O here.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from urllib.parse import parse_qs

VICTIM_SOURCE = "victim"
SOURCE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_ID_LEN = 128
MAX_PATH_LEN = 512
MAX_LABEL_LEN = 128


class InvalidEvent(ValueError):
    pass


@dataclass(frozen=True)
class AccessEvent:
    source: str
    event_id: str | int  # unique per source; (source, event_id) is what dedupe compares
    ts: float  # epoch seconds
    key_id: int
    client_ip: str
    path: str
    status: int
    bytes: int = 0
    method: str | None = None
    key_label: str | None = None
    page: str | None = None

    def entry(self) -> dict:
        """The row shape the per-key baseline reads."""
        return {"source": self.source, "id": self.event_id, "ts": self.ts, "api_key_id": self.key_id,
                "ip": self.client_ip, "method": self.method, "path": self.path, "page": self.page,
                "status": self.status, "bytes": self.bytes}


def page_of(query: str | None) -> str | None:
    """The pagination value of a query string; nothing else of the query is read."""
    return next(iter(parse_qs(query or "").get("page", [])), None)


def _int(raw: dict, field: str, lo: int, hi: int | None = None, default: int | None = None) -> int:
    value = raw.get(field, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < lo or (hi is not None and value > hi):
        raise InvalidEvent(f"{field}: expected an integer >= {lo}" + (f" and <= {hi}" if hi else ""))
    return value


def _text(raw: dict, field: str, max_len: int, required: bool = True) -> str | None:
    value = raw.get(field)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise InvalidEvent(f"{field}: expected a non-empty string of at most {max_len} characters")
    return value


def parse_event(raw: dict, source: str) -> AccessEvent:
    """A pushed event, validated. Raises InvalidEvent naming the first bad field."""
    if not isinstance(raw, dict):
        raise InvalidEvent("event: expected an object")
    if not SOURCE_RE.match(source or ""):
        raise InvalidEvent("source: letters, digits, '.', '_' or '-', at most 64")
    event_id = raw.get("id")
    if isinstance(event_id, bool) or not isinstance(event_id, int):
        event_id = _text(raw, "id", MAX_ID_LEN)
    ts = raw.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts) or ts <= 0:
        raise InvalidEvent("ts: expected epoch seconds")
    path, _, query = _text(raw, "path", MAX_PATH_LEN).partition("?")
    if not path.startswith("/"):
        raise InvalidEvent("path: expected an absolute path")
    page = raw.get("page")
    if isinstance(page, bool) or not isinstance(page, (str, int, type(None))):
        raise InvalidEvent("page: expected a string or an integer")
    page = str(page)[:32] if page is not None else page_of(query)
    method = _text(raw, "method", 16, required=False)
    return AccessEvent(source, event_id, float(ts), _int(raw, "key_id", 0), _text(raw, "ip", 64), path,
                       _int(raw, "status", 100, 599), _int(raw, "bytes", 0, default=0),
                       method.upper() if method else None, _text(raw, "key_label", MAX_LABEL_LEN, required=False),
                       page)
