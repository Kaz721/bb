#!/usr/bin/env python3
import argparse
import sys
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def ping_once(url: str, timeout: float) -> bool:
    started = time.perf_counter()
    try:
        request = Request(url, method="GET")
        with urlopen(request, timeout=timeout) as response:
            status = response.getcode()
        elapsed_ms = (time.perf_counter() - started) * 1000
        now = datetime.now(timezone.utc).isoformat()
        print(f"[{now}] OK status={status} latency_ms={elapsed_ms:.2f}")
        return True
    except HTTPError as error:
        elapsed_ms = (time.perf_counter() - started) * 1000
        now = datetime.now(timezone.utc).isoformat()
        print(f"[{now}] FAIL status={error.code} latency_ms={elapsed_ms:.2f}", file=sys.stderr)
        return False
    except URLError as error:
        now = datetime.now(timezone.utc).isoformat()
        print(f"[{now}] FAIL error={error.reason}", file=sys.stderr)
        return False
    except Exception as error:  # pragma: no cover
        now = datetime.now(timezone.utc).isoformat()
        print(f"[{now}] FAIL error={error}", file=sys.stderr)
        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HTTP ping monitor")
    parser.add_argument(
        "--url",
        default="http://162.243.172.250",
        help="Target URL to ping (default: http://162.243.172.250)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Seconds to wait between pings (default: 5)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Request timeout in seconds (default: 3)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of requests to send (0 means run forever)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sent = 0
    failures = 0

    while args.count == 0 or sent < args.count:
        ok = ping_once(args.url, args.timeout)
        failures += 0 if ok else 1
        sent += 1
        if args.count == 0 or sent < args.count:
            time.sleep(max(0.0, args.interval))

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
