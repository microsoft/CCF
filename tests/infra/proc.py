# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import logging
from subprocess import run

from loguru import logger as LOG


def ccall(*args, log_output=True):
    LOG.info(" ".join(args))
    result = run(args, capture_output=True)
    if result.stdout and log_output:
        LOG.debug("stdout: {}".format(result.stdout.decode().strip()))
    if result.stderr and log_output:
        LOG.error("stderr: {}".format(result.stderr.decode().strip()))
    return result
