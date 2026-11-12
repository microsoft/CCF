# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Check consensus protocol traces against the lean/consistency model.

Nodes export their ccf.cft trace events to a local collector. Tests add only
what nodes cannot observe: transaction statuses reported to clients. The joint
trace is replayed by consistency-replay.
"""

import contextlib
import json
import os
import struct
import subprocess
import threading
import time

from loguru import logger as LOG

import infra.fluentd

# The consensus events that the consistency replayer uses.
FUNCTIONS = ("become_leader", "send_request_vote", "replicate", "commit")

# Upper bound on the nodes started by one test.
MAX_NODES = 64

# The trace recorded by the current thread, if any: record key to
# (nanoseconds since the epoch, per-process sequence number, record).
_recording = threading.local()


def tx_status(r):
    """Record the transaction status that r, a /node/tx response, gave a client."""
    events = getattr(_recording, "events", None)
    if events is not None:
        body = r.body.json()
        view, seqno = body["transaction_id"].split(".")
        msg = {
            "function": "tx_status",
            "view": int(view),
            "seqno": int(seqno),
            "status": body["status"],
        }
        events[("client", len(events))] = (time.time_ns(), 0, {"msg": msg})


@contextlib.contextmanager
def recording(args):
    """Trace the nodes started with args, then replay the trace.

    Does nothing unless CCF_LEAN_CONSISTENCY_REPLAYER names the replayer. The
    body must stop its nodes. The trace is not replayed if the body raises.
    """
    replayer = os.getenv("CCF_LEAN_CONSISTENCY_REPLAYER")
    if not replayer:
        yield
        return
    events = {}

    def node_event(tag, timestamp, record):
        if tag == "ccf.cft" and record["msg"]["function"] in FUNCTIONS:
            seconds, nanos = struct.unpack(">II", timestamp.data)
            # Keyed by origin, as delivery retries can duplicate records.
            events[(record["process_id"], record["h_ts"])] = (
                seconds * 10**9 + nanos,
                record["h_ts"],
                record,
            )

    path = os.path.join(args.workspace, f"{args.label}_consistency_trace.ndjson")
    try:
        with infra.fluentd.Collector(MAX_NODES, node_event) as collector:
            endpoint = {**collector.endpoint, "tag-prefix-allow-list": ["ccf.cft"]}
            args.observability = {"fluentd": [endpoint]}
            _recording.events = events
            yield
    finally:
        _recording.events = None
        with open(path, "w", encoding="ascii") as f:
            for ts, _, record in sorted(events.values(), key=lambda e: e[:2]):
                f.write(json.dumps({"ts": ts, **record}) + "\n")
    result = subprocess.run(
        [replayer, path], capture_output=True, text=True, check=False
    )
    assert (
        result.returncode == 0
    ), f"Lean consistency replay failed:\n{result.stdout}{result.stderr}"
    LOG.info(result.stdout.strip())
