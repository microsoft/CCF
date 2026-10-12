# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import subprocess

from loguru import logger as LOG


def validate_recovery_trace_if_enabled(network, label):
    """Replay the started nodes' recovery-decision-protocol traces through the Lean model."""
    replayer = os.getenv("CCF_LEAN_TRACE_REPLAYER")
    if not replayer:
        return
    logs = [node.get_logs()[0] for node in network.nodes if node.remote is not None]
    result = subprocess.run(
        [
            replayer,
            "--participants",
            str(len(logs)),
            *logs,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert (
        result.returncode == 0
    ), f"Lean trace replay failed for {label}:\n{result.stdout}{result.stderr}"
    LOG.info(result.stdout.strip())
