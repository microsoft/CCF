# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import logging
import os
import pathlib
import subprocess

TRACE_VALIDATOR_ENV = "CCF_LEAN_TRACE_VALIDATOR"
LOG = logging.getLogger(__name__)


def _validator_path():
    configured = os.getenv(TRACE_VALIDATOR_ENV)
    if configured:
        return pathlib.Path(configured)
    repository = pathlib.Path(__file__).resolve().parents[2]
    return (
        repository
        / "lean"
        / "disaster-recovery-trace"
        / ".lake"
        / "build"
        / "bin"
        / "trace-validator"
    )


def validate_recovery_trace(network, label, expected_open_kind, timeout=20):
    nodes = [node for node in network.nodes if node.remote is not None]
    log_paths = []
    for node in nodes:
        out_path, _ = node.get_logs()
        if out_path is None:
            raise FileNotFoundError(f"missing recovery trace log for {label}")
        log_paths.append(out_path)

    validator = _validator_path()
    if not validator.is_file():
        raise FileNotFoundError(
            f"Lean trace validator not found at {validator}; set {TRACE_VALIDATOR_ENV}"
        )
    result = subprocess.run(
        [
            validator,
            "--logs",
            str(len(nodes)),
            expected_open_kind,
            str(round(timeout * 1000)),
            *log_paths,
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout + 5,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Lean recovery trace validation failed for {label} ({log_paths}):\n"
            f"{result.stdout}{result.stderr}"
        )
    LOG.info(result.stdout.strip())


def validate_recovery_trace_if_enabled(network, label, expected_open_kind, timeout=20):
    if not os.getenv(TRACE_VALIDATOR_ENV):
        return None
    return validate_recovery_trace(
        network,
        label,
        expected_open_kind=expected_open_kind,
        timeout=timeout,
    )
