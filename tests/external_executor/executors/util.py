# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import threading
import time
from contextlib import contextmanager

from loguru import logger as LOG


class ExecutorThread:
    def __init__(self, executor):
        self.executor = executor
        self.thread = None
        self.activated_event = None

    def start(self):
        assert self.thread == None, "Already started"
        LOG.info("Starting executor")
        self.activated_event = threading.Event()
        self.thread = threading.Thread(
            target=self.executor.run_loop, args=(self.activated_event,)
        )
        self.thread.start()
        assert self.activated_event.wait(timeout=3), "Executor failed to activate after 3 seconds"

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
