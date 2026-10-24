"""Harmless "sync" job: a CPU loop that keeps one outbound connection open.

Behaves like a disguised miner without any telling string: busy CPU, a
persistent keep-alive connection to SYNC_ENDPOINT (an HTTP(S) URL we control,
checked in every --interval seconds) and no disk output. It sends nothing but
GET requests, touches no files and stops by itself after --max-seconds.
Without SYNC_ENDPOINT it only burns CPU.
"""
import argparse
import http.client
import os
import time
from urllib.parse import urlsplit


def check_in(conn, path: str):
    try:
        conn.request("GET", path, headers={"Connection": "keep-alive"})
        resp = conn.getresponse()
        resp.read()
        if resp.will_close:  # the server ends each exchange: reopen so the channel stays up
            conn.close()
            conn.connect()
    except (OSError, http.client.HTTPException):
        conn.close()  # reconnects on the next request


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=float, default=15.0)
    parser.add_argument("--max-seconds", type=float, default=600.0)
    args = parser.parse_args()

    url = urlsplit(os.environ.get("SYNC_ENDPOINT", ""))
    conn = None
    if url.hostname:
        cls = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
        conn = cls(url.hostname, url.port, timeout=10)
    path = url.path or "/"

    deadline = time.monotonic() + min(args.max_seconds, 600.0)
    next_check = time.monotonic()
    x = 0
    while time.monotonic() < deadline:
        if conn is not None and time.monotonic() >= next_check:
            check_in(conn, path)
            next_check = time.monotonic() + args.interval
        for i in range(100_000):
            x = (x * 31 + i) % 1_000_003


if __name__ == "__main__":
    main()
