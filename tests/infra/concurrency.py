# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import threading
from contextvars import copy_context

from infra.test_reporting import CURRENT_TEST


class Thread(threading.Thread):
    """Carry the owning test identity into child threads, including failures."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.test_context = CURRENT_TEST.get()
        self._context = copy_context()

    def run(self):
        self._context.run(super().run)


class StoppableThread(Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.daemon = True
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()
