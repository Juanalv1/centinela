"""Reference forwarder: nginx JSON access log -> Centinela's POST /api/ingest/access.

Standard library only. Reads the log written by the `centinela` log_format in
docs/INTEGRACION.md, keeps metadata only (no query string beyond the page
value, never bodies or key values) and posts batches. Lines without a key id
(anonymous or session traffic) are skipped. It remembers the byte offset it
delivered up to in --state, so a restart resumes there; a replay is harmless
anyway, the endpoint is idempotent by (source, event id).

    CENTINELA_INGEST_TOKEN=... python forward_nginx.py --log /var/log/nginx/centinela.json \\
        --url https://centinela.example.com --source nginx-edge --state /var/lib/centinela/offset --follow

The token is read from the environment, never from the command line (visible in `ps`).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs


class DeliveryFailed(Exception):
    def __init__(self, offset: int, cause: Exception) -> None:
        super().__init__(f"delivery failed at byte {offset}: {cause}")
        self.offset = offset


def parse_line(line: str) -> dict | None:
    """One log line as an ingest event, or None when it is malformed or not made with a key."""
    try:
        rec = json.loads(line)
        key = str(rec.get("key_id", ""))
        if not key.isdigit():
            return None  # empty, "-", or anything that is not an id
        path, _, query = rec["request_uri"].partition("?")
        event = {"id": rec["request_id"], "ts": float(rec["msec"]), "key_id": int(key),
                 "ip": rec["remote_addr"], "method": rec.get("request_method") or None, "path": path,
                 "status": int(rec["status"]), "bytes": int(rec.get("body_bytes_sent") or 0)}
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    page = next(iter(parse_qs(query).get("page", [])), None)
    if page is not None:
        event["page"] = page
    if rec.get("key_label") not in (None, "", "-"):
        event["key_label"] = rec["key_label"]
    return event


def forward(log: Path, offset: int, post, batch: int = 500) -> int:
    """Post every complete line after `offset` in batches; return the offset delivered up to.
    Raises DeliveryFailed (carrying the last delivered offset) when a post fails."""
    if log.stat().st_size < offset:
        offset = 0  # the log was rotated or truncated
    events: list[dict] = []
    delivered = end = offset
    with log.open("rb") as fh:
        fh.seek(offset)
        for raw in fh:
            if not raw.endswith(b"\n"):
                break  # nginx is still writing this line
            end += len(raw)
            event = parse_line(raw.decode("utf-8", errors="replace"))
            if event is not None:
                events.append(event)
            if len(events) >= batch:
                delivered = _deliver(post, events, delivered, end)
                events = []
    if events:
        _deliver(post, events, delivered, end)
    return end


def _deliver(post, events: list[dict], delivered: int, end: int) -> int:
    try:
        post(events)
    except Exception as exc:
        raise DeliveryFailed(delivered, exc) from exc
    return end


def post_batch(url: str, token: str, source: str, events: list[dict], opener=urllib.request.urlopen) -> dict:
    req = urllib.request.Request(
        url.rstrip("/") + "/api/ingest/access", method="POST",
        data=json.dumps({"source": source, "events": events}).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with opener(req, timeout=15) as resp:
        return json.loads(resp.read())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", type=Path, required=True, help="nginx access log in the centinela JSON format")
    ap.add_argument("--url", required=True, help="Centinela base URL")
    ap.add_argument("--source", default="nginx", help="name of this log for Centinela (not 'victim')")
    ap.add_argument("--state", type=Path, help="file that keeps the delivered byte offset across restarts")
    ap.add_argument("--batch", type=int, default=500, help="events per request (Centinela accepts up to 1000)")
    ap.add_argument("--follow", action="store_true", help="keep reading new lines")
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between reads with --follow")
    args = ap.parse_args(argv)
    token = os.environ.get("CENTINELA_INGEST_TOKEN")
    if not token:
        print("CENTINELA_INGEST_TOKEN is not set", file=sys.stderr)
        return 2
    offset = int(args.state.read_text()) if args.state and args.state.exists() else 0

    def post(events: list[dict]) -> None:
        out = post_batch(args.url, token, args.source, events)
        print(f"sent {out.get('received')} events, {out.get('new')} new", file=sys.stderr)

    while True:
        try:
            offset = forward(args.log, offset, post, args.batch)
        except DeliveryFailed as exc:
            offset = exc.offset
            print(exc, file=sys.stderr)
            if not args.follow:
                return 1
        finally:
            if args.state:
                args.state.write_text(str(offset))
        if not args.follow:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
