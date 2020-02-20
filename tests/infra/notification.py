# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import threading
import http.server
import queue
import json
from contextlib import contextmanager

from loguru import logger as LOG


class PostQueueRequestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        self.queue = server.queue
        self.error_queue = server.error_queue
        self.checker = server.checker
        super(PostQueueRequestHandler, self).__init__(request, client_address, server)

    def do_POST(self):
        self.send_response(201)
        self.end_headers()
        content_length = int(self.headers["Content-Length"])
        body = self.rfile.read(content_length)
        if callable(self.checker) and not self.checker(body):
            LOG.error(f"Notification is not in expected format: {body}")
            self.error_queue.put(body)
        else:
            self.queue.put(body)

    def log_message(self, format, *args):
        pass


class PostQueueServer(http.server.HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, checker=None):
        assert (
            RequestHandlerClass is PostQueueRequestHandler
        ), "Should be initialised with PostQueueRequestHandler"
        self.queue = queue.Queue()
        self.error_queue = queue.Queue()
        self.checker = checker
        super(PostQueueServer, self).__init__(server_address, PostQueueRequestHandler)

    def get_queue(self):
        return self.queue

    def check_errors(self):
        return self.error_queue.empty()


@contextmanager
def notification_server(server_info, checker=None):
    host = None
    port = []
    if server_info is not None:
        host, *port = server_info.split(":")
        if not host or not (port and port[0]):
            raise ValueError("Notification server host:port configuration is invalid")
    else:
        raise ValueError("Notification server host:port configuration is invalid")

    with PostQueueServer(
        (host, int(port[0])), PostQueueRequestHandler, checker
    ) as server:
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        LOG.success("Notification server started")

        try:
            yield server
        finally:
            assert (
                server.check_errors() is True
            ), "Notification server caught malformed notifications"
            server.shutdown()
            server.server_close()
