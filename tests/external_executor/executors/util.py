# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import threading
from contextlib import contextmanager

from loguru import logger as LOG


class ExecutorThread:
    def __init__(self, executor):
        self.executor = executor
        self.thread = None
        self.terminate_event = None

    def start(self):
        assert self.thread == None, "Already started"
        LOG.info("Starting executor")
        self.terminate_event = threading.Event()
        self.thread = threading.Thread(
            target=self.executor.run_loop,
        )
        self.thread.start()

    def terminate(self):
        assert self.thread != None, "Already terminated"
        LOG.info("Terminating executor")
        self.executor.terminate()
        self.thread.join()
        self.thread = None


@contextmanager
def executor_thread(executor):
    et = ExecutorThread(executor)
    et.start()
    yield executor
    et.terminate()
