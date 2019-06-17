# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import threading
import socketserver
import queue
import json
from contextlib import contextmanager

from loguru import logger as LOG


class NotificationServer(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.queue = server.queue
        self.error_queue = server.error_queue
        self.checker = server.checker
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        data = self.request.recv(1024).strip()
        if data:
            if callable(self.checker):
                if not self.checker(data):
                    LOG.error("Notification is not in expect format: {}".format(data))
                    self.error_queue.put(data)
            self.queue.put(data)
        else:
            LOG.info("Notification client disconnected")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(
        self, server_address, RequestHandlerClass, bind_and_activate=True, checker=None
    ):
        self.queue = queue.Queue()
        self.error_queue = queue.Queue()
        self.checker = checker
        socketserver.TCPServer.__init__(
            self,
            server_address,
            RequestHandlerClass,
            bind_and_activate=bind_and_activate,
        )

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

    ThreadedTCPServer.allow_reuse_address = True
    with ThreadedTCPServer(
        (host, int(port[0])), NotificationServer, True, checker
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
