# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Pass the task-local queue probe's output path to the node."""

import os
import runpy
import sys

import infra.remote

original_start = infra.remote.LocalRemote.start


def start_with_queue_probe(self):
    self.env = {
        **self.env,
        "CCF_QUEUE_PROBE_OUT": os.environ["CCF_QUEUE_PROBE_OUT"],
    }
    return original_start(self)


infra.remote.LocalRemote.start = start_with_queue_probe
driver = os.environ["CCF_QUEUE_ORIGINAL_DRIVER"]
sys.argv[0] = driver
runpy.run_path(driver, run_name="__main__")
