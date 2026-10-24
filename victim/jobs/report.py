"""Harmless "report" job: a pure-arithmetic CPU loop.

It accepts (and ignores) `--pool` / `--threads` arguments so its command line
looks like a cryptominer to an observer. It opens no sockets, touches no files
and stops by itself after --max-seconds (default 600).
"""
import argparse
import time


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pool", default="")  # cosmetic only, never used
    parser.add_argument("--threads", type=int, default=1)  # cosmetic only
    parser.add_argument("--max-seconds", type=float, default=600.0)
    args = parser.parse_args()

    deadline = time.monotonic() + min(args.max_seconds, 600.0)
    x = 0
    while time.monotonic() < deadline:
        for i in range(100_000):
            x = (x * 31 + i) % 1_000_003


if __name__ == "__main__":
    main()
