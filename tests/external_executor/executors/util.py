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
    # Sleep briefly to give executor time to actually start (registered +
    # activated + ready for requests).
    # Doing this deterministically is hard because we're generally waiting for
    # the executor to enter a blocking loop. Any indication that its about to
    # enter the loop may have a delay until it actually enters, so anything
    # checking it may race with the executor being ready.
    time.sleep(0.2)
    yield executor
    et.terminate()
