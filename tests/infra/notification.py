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
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        data = self.request.recv(1024).strip()
        if data:
            self.queue.put(data)
            LOG.trace("queue:{}".format(list(self.queue.queue)))
        else:
            LOG.info("Notification client disconnected")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        self.queue = queue.Queue()
        socketserver.TCPServer.__init__(
            self,
            server_address,
            RequestHandlerClass,
            bind_and_activate=bind_and_activate,
        )

    def get_queue(self):
        return self.queue


@contextmanager
def notification_server(server_info):

    host = None
    port = []
    if server_info is not None:
        host, *port = server_info.split(":")

        if not host or not (port and port[0]):
            raise ValueError("Notification server host:port configuration is invalid")
    else:
        raise ValueError("Notification server host:port configuration is invalid")

    ThreadedTCPServer.allow_reuse_address = True
    with ThreadedTCPServer((host, int(port[0])), NotificationServer, True) as server:

        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        LOG.info("Notification server started")

        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()
