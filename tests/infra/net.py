# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import re
import socket
from random import randrange as rr
from subprocess import check_output
from os import getenv


def ephemeral_range():
    # Linux
    try:
        with open(
            "/proc/sys/net/ipv4/ip_local_port_range", encoding="utf-8"
        ) as port_range:
            return tuple(int(port) for port in port_range.read().split())
    except IOError:
        pass

    # WSL
    try:
        output = check_output(
            [
                "/mnt/c/Windows/System32/netsh.exe",
                "int",
                "ipv4",
                "show",
                "dynamicport",
                "tcp",
            ]
        )
        match = re.compile(r"Start Port\s+: (?P<port>\d+)", re.MULTILINE).search(
            str(output)
        )
        if not match:
            raise ValueError("Failed to match start port in {}".format(output))
        return (int(match.group("port")), 65535)
    except (OSError, ValueError, IndexError):
        pass

    # Take a guess and use the IANA recommendation
    return (49152, 65535)


EPHEMERAL_RANGE = ephemeral_range()


def probably_free_local_port(host):
    tries = 1000
    for _ in range(tries):
        port = rr(*EPHEMERAL_RANGE)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((host, port))
            s.close()
            return port
        except socket.error:
            pass
    raise RuntimeError("Couldn't get a free port after {} tries!".format(tries))


def probably_free_remote_port(host):
    tries = 1000
    for _ in range(tries):
        port = rr(*EPHEMERAL_RANGE)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((host, port))
            s.close()
        except socket.error:
            return port
    raise RuntimeError("Couldn't get a free port after {} tries!".format(tries))


def two_different(finder, *args, **kwargs):
    one, two = finder(*args, **kwargs), finder(*args, **kwargs)
    while two == one:
        two = finder(*args, **kwargs)
    return (one, two)


def expand_localhost():
    ipv4 = ".".join((str(b) for b in (127, rr(1, 255), rr(1, 255), rr(2, 255))))
    if getenv("CCF_IPV6"):
        return f"::ffff:{ipv4}"
    else:
        return ipv4
