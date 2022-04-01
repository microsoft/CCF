# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import threading

from loguru import logger as LOG


class StoppableThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.daemon = True
        self._stop_event = threading.Event()

    def stop(self):
        LOG.success("stop")
        self._stop_event.set()

    def is_stopped(self):
        LOG.error(f"is stopped?")
        return self._stop_event.is_set()
