# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import requests
import threading
import grpc
import time

from loguru import logger as LOG


# pylint: disable=import-error
import kv_pb2 as KV

# pylint: disable=import-error
import http_pb2 as HTTP

# pylint: disable=import-error
import kv_pb2_grpc as Service

# pylint: disable=no-name-in-module
from google.protobuf.empty_pb2 import Empty as Empty


class WikiCacherExecutor:
    API_VERSION = "v1"
    PROJECT = "wikipedia"
    LANGUAGE = "en"

    CACHE_TABLE = "wiki_descriptions"

    def __init__(self, base_url="https://api.wikimedia.org"):
        self.base_url = base_url
        self.thread = None
        self.terminate_event = None

    def _api_base(self):
        return "/".join(
            (
                self.base_url,
                "core",
                self.API_VERSION,
                self.PROJECT,
                self.LANGUAGE,
            )
        )

    def _get_description(self, title):
        url = "/".join((self._api_base(), "page", title, "description"))
        LOG.debug(f"Requesting {url}")
        r = requests.get(url)
        if r.status_code == 200:
            return r.json()["description"]
        LOG.error(r)

    def _execute_update_cache(self, kv_stub, request, response):
        # TODO: Should parse with a regex
        prefix = "/update_cache/"
        title = request.uri[len(prefix) :]
        description = self._get_description(title)
        if description == None:
            response.status_code = HTTP.HttpStatusCode.NOT_FOUND
            response.body = f"Error when fetching article with title '{title}'".encode(
                "utf-8"
            )

        kv_stub.Put(
            KV.KVKeyValue(
                table=self.CACHE_TABLE,
                key=title.encode("utf-8"),
                value=description.encode("utf-8"),
            )
        )
        response.status_code = HTTP.HttpStatusCode.OK
        response.body = (
            f"Successfully updated cache with description of '{title}'".encode("utf-8")
        )

    def _execute_get_description(self, kv_stub, request, response):
        # TODO: Should parse with a regex
        prefix = "/article_description/"
        title = request.uri[len(prefix) :]
        result = kv_stub.Get(
            KV.KVKey(table=self.CACHE_TABLE, key=title.encode("utf-8"))
        )

        if not result.HasField("optional"):
            response.status_code = HTTP.HttpStatusCode.NOT_FOUND
            response.body = f"No description for '{title}' in cache"

        response.status_code = HTTP.HttpStatusCode.OK
        response.body = result.optional.value

    def _run_loop(self, ccf_node, credentials):
        LOG.info("Beginning executor loop")

        with grpc.secure_channel(
            target=f"{ccf_node.get_public_rpc_host()}:{ccf_node.get_public_rpc_port()}",
            credentials=credentials,
        ) as channel:
            stub = Service.KVStub(channel)

            while not (self.terminate_event.is_set()):
                request_description_opt = stub.StartTx(Empty())
                if not request_description_opt.HasField("optional"):
                    LOG.trace("No request pending")
                    stub.EndTx(KV.ResponseDescription())
                    time.sleep(0.1)
                    continue

                request = request_description_opt.optional
                response = KV.ResponseDescription(
                    status_code=HTTP.HttpStatusCode.NOT_FOUND
                )

                if request.method == "POST" and request.uri.startswith(
                    "/update_cache/"
                ):
                    LOG.info(f"Updating article in cache: {request.uri}")
                    self._execute_update_cache(stub, request, response)

                elif request.method == "GET" and request.uri.startswith(
                    "/article_description/"
                ):
                    LOG.info(f"Retrieving description from cache: {request.uri}")
                    self._execute_get_description(stub, request, response)

                else:
                    LOG.error(f"Unhandled request: {request.method} {request.uri}")
                    # TODO: Build a precise 404 response

                stub.EndTx(response)

        LOG.info("Ended executor loop")

    def start(self, ccf_node, credentials):
        assert self.thread == None, "Already started"
        LOG.info("Starting executor")
        self.terminate_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run_loop, args=(ccf_node, credentials)
        )
        self.thread.start()

    def terminate(self):
        assert self.thread != None, "Already terminated"
        LOG.info("Terminating executor")
        self.terminate_event.set()
        self.thread.join()
