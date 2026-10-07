#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""One-off runner DNS diagnostic: sample github.com for five minutes.

Temporarily run by the VMSS Virtual C PR job. On the first failed lookup, print
direct configured-server DNS responses and exit nonzero. No GitHub HTTP calls
are made.
"""

import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

DURATION_SECONDS = 300
LOOKUP_CODE = """
import socket
import sys

try:
    addresses = socket.getaddrinfo("github.com", 443, type=socket.SOCK_STREAM)
    print(sorted({address[4][0] for address in addresses}))
except socket.gaierror as error:
    print(f"getaddrinfo errno={error.errno}: {error}", file=sys.stderr)
    sys.exit(1)
"""


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def resolver_context() -> list[str]:
    servers = []
    for name in ("/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/hosts"):
        print(f"--- {name} ---", flush=True)
        contents = Path(name).read_text(encoding="utf-8")
        print(contents, flush=True)
        if name == "/etc/resolv.conf":
            for line in contents.splitlines():
                fields = line.split("#", 1)[0].split()
                if len(fields) >= 2 and fields[0] == "nameserver":
                    servers.append(fields[1])
    return list(dict.fromkeys(servers))


def diagnose(servers: list[str]) -> None:
    for server in servers:
        for query_type in ("A", "AAAA"):
            for transport in ("+notcp", "+tcp"):
                command = [
                    "dig",
                    f"@{server}",
                    "github.com",
                    query_type,
                    transport,
                    "+time=2",
                    "+tries=1",
                    "+ignore",
                ]
                print(f"{timestamp()} {' '.join(command)}", flush=True)
                try:
                    result = subprocess.run(command, check=False, timeout=5)
                    print(f"dig exit status: {result.returncode}", flush=True)
                except subprocess.TimeoutExpired:
                    print("dig exceeded the 5-second deadline", flush=True)


def main() -> int:
    servers = resolver_context()
    if not servers or shutil.which("dig") is None:
        print("Configured nameservers and dig are required", file=sys.stderr)
        return 2

    deadline = time.monotonic() + DURATION_SECONDS
    lookups = 0
    while time.monotonic() < deadline:
        started = time.monotonic()
        lookups += 1
        print(f"{timestamp()} lookup {lookups}", flush=True)
        try:
            result = subprocess.run(
                [sys.executable, "-c", LOOKUP_CODE],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            print(result.stdout, end="", flush=True)
            print(result.stderr, end="", file=sys.stderr, flush=True)
            print(
                f"exit={result.returncode}, elapsed={time.monotonic() - started:.3f}s",
                flush=True,
            )
            failed = result.returncode != 0
        except subprocess.TimeoutExpired as error:
            print("Lookup exceeded the 10-second deadline", flush=True)
            print(
                f"Partial stdout: {error.stdout!r}; stderr: {error.stderr!r}",
                flush=True,
            )
            failed = True
        if failed:
            diagnose(servers)
            return 1
        time.sleep(max(0, min(1, deadline - time.monotonic())))

    print(
        f"{lookups} successful lookups; no failure observed in this window. "
        "This does not rule out intermittent DNS failures.",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
