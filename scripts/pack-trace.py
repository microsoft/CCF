#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Pack an NDJSON trace on standard input as the Fluentd Forward MessagePack
which nodes emit, on standard output. A line is a `{pid, m_ts, msg}` record,
with its `tag`, by default `ccf.cft`, and its `ts` in nanoseconds, if any."""

import json
import struct
import sys

import msgpack

for line in sys.stdin:
    record = json.loads(line)
    tag = record.pop("tag", "ccf.cft")
    time = record.pop("ts", None)
    if time is not None:
        time = msgpack.ExtType(0, struct.pack(">II", *divmod(time, 10**9)))
    sys.stdout.buffer.write(msgpack.packb([tag, time, record]))
