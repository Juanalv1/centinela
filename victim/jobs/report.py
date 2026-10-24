"""Harmless "report" job: a pure-arithmetic CPU loop.

It accepts (and ignores) `--pool` / `--threads` arguments so its command line
looks like a cryptominer to an observer. It opens no sockets, touches no files
and stops by itself after --max-seconds (default 600).
"""
import argparse
import threading
import time


def _burn(deadline: float) -> None:
    x = 0
    while time.monotonic() < deadline:
        for i in range(100_000):
            x = (x * 31 + i) % 1_000_003


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pool", default="")  # cosmetic only, never used
    parser.add_argument("--threads", type=int, default=1)  # real: CPU-burning threads
    parser.add_argument("--max-seconds", type=float, default=600.0)
    args = parser.parse_args()

    deadline = time.monotonic() + min(args.max_seconds, 600.0)
    # Several threads saturate the container's CPU quota so the attack is
    # unmistakable on the panel; the loop still opens no sockets and no files.
    workers = [threading.Thread(target=_burn, args=(deadline,), daemon=True)
               for _ in range(max(1, args.threads))]
    for w in workers:
        w.start()
    for w in workers:
        w.join()


if __name__ == "__main__":
    main()
