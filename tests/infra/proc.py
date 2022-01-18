# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import subprocess
from subprocess import run

from loguru import logger as LOG


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
    cur_proc = subprocess.Popen(procs[0], shell=False, stdout=subprocess.PIPE)
    for p in procs[1:]:
        cur_proc = subprocess.Popen(
            p, shell=False, stdin=cur_proc.stdout, stdout=subprocess.PIPE
        )

    return (cur_proc.communicate()[0]).decode().strip()
