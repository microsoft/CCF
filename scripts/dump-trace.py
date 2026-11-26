#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Dump a MessagePack trace on standard input as NDJSON on standard output:
the inverse of pack-trace.py."""

import json
import struct
import sys

import msgpack

# Log messages need not be valid UTF-8.
messages = msgpack.Unpacker(sys.stdin.buffer, raw=False, unicode_errors="replace")
for tag, time, record in messages:
    event = {"tag": tag}
    if time is not None:
        seconds, nanoseconds = struct.unpack(">II", time.data)
        event["ts"] = seconds * 10**9 + nanoseconds
    print(json.dumps({**event, **record}))
