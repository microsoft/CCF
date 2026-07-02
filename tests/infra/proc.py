# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from subprocess import run, Popen, PIPE
from pathlib import Path
from typing import Optional, Dict

from loguru import logger as LOG


def get_proc_memory_stats(pid: int) -> Optional[Dict[str, int]]:
    """Read memory statistics for a process from /proc/<pid>/status.

    Returns a dict with keys:
      - current_rss: current resident set size in bytes
      - peak_rss: peak resident set size (VmHWM) in bytes
      - virtual_size: total virtual memory size in bytes
    Returns None if the process info cannot be read.
    """
    try:
        status_path = Path(f"/proc/{pid}/status")
        text = status_path.read_text()
    except (OSError, PermissionError):
        return None

    fields = {"VmRSS": "current_rss", "VmHWM": "peak_rss", "VmSize": "virtual_size"}
    result = {}
    for line in text.splitlines():
        parts = line.split(":", 1)
        if len(parts) == 2 and parts[0].strip() in fields:
            key = fields[parts[0].strip()]
            # Values in /proc/*/status are in kB
            value_str = parts[1].strip().split()[0]
            result[key] = int(value_str) * 1024
    return result if len(result) == len(fields) else None


def ccall(*args, path=None, log_output=True, env=None):
    suffix = f" [cwd: {path}]" if path else ""
    cmd = " ".join(args)
    LOG.info(f"{cmd}{suffix}")
    result = run(args, capture_output=True, cwd=path, check=False, env=env)
    if result.stdout and log_output:
        LOG.debug("stdout: {}".format(result.stdout.decode().strip()))
    if result.stderr and log_output:
        LOG.error("stderr: {}".format(result.stderr.decode().strip()))
    return result


def ccall_with_pipe(procs):
    cur_proc = Popen(procs[0], shell=False, stdout=PIPE)
    for p in procs[1:]:
        cur_proc = Popen(p, shell=False, stdin=cur_proc.stdout, stdout=PIPE)

    return (cur_proc.communicate()[0]).decode().strip()
