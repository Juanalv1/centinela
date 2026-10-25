"""Legitimate heavy "backup" job: compresses data and writes real archive files.

CPU-heavy like the other jobs, but its work shows up as steady disk writes
(at most ~2 MB/s, three rotating 8 MB files under --dest). It opens no sockets
and stops by itself after --max-seconds.
"""
import argparse
import os
import time
import zlib
from pathlib import Path

FILE_BYTES = 8 * 1024 * 1024
KEEP_FILES = 3
MAX_BPS = 2 * 1024 * 1024


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest", default="/tmp/backups")
    parser.add_argument("--max-seconds", type=float, default=600.0)
    args = parser.parse_args()

    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + min(args.max_seconds, 600.0)
    index, written, window_start, window_bytes = 0, 0, time.monotonic(), 0
    out = (dest / f"archive-{index}.z").open("wb")
    while time.monotonic() < deadline:
        block = zlib.compress(os.urandom(16 * 1024) * 16, 9)  # the CPU cost of a real backup
        if time.monotonic() - window_start >= 1.0:
            window_start, window_bytes = time.monotonic(), 0
        if window_bytes >= MAX_BPS:
            continue  # keep compressing, but cap the disk rate
        out.write(block)
        out.flush()
        os.fsync(out.fileno())
        written += len(block)
        window_bytes += len(block)
        if written >= FILE_BYTES:
            out.close()
            index += 1
            (dest / f"archive-{index - KEEP_FILES}.z").unlink(missing_ok=True)
            out = (dest / f"archive-{index}.z").open("wb")
            written = 0
    out.close()


if __name__ == "__main__":
    main()
