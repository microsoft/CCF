# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import threading
from contextvars import copy_context

from infra.test_reporting import CURRENT_TEST, record_failure


class Thread(threading.Thread):
    """Carry test identity into child threads; subclasses override _run, not run."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.test_context = CURRENT_TEST.get()
        self._ccf_context = copy_context()

    def run(self):
        try:
            self._ccf_context.run(self._run)
        except Exception as exc:
            record_failure(exc, context=self.test_context, thread=self.name)
            raise

    def _run(self):
        super().run()


class StoppableThread(Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.daemon = True
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def is_stopped(self):
        return self._stop_event.is_set()
