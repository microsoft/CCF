# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import requests
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
    supported_endpoints = None
    credentials = None

    def __init__(self, ccf_node, base_url="https://api.wikimedia.org", label=None):
        self.ccf_node = ccf_node
        self.base_url = base_url
        if label is not None:
            self.prefix = f"[{label}] "
        else:
            self.prefix = ""

        self.handled_requests_count = 0

    def get_supported_endpoints(self, topics):
        endpoints = []
        for topic in topics:
            endpoints.append(("POST", "/update_cache/" + topic))
            endpoints.append(("GET", "/article_description/" + topic))
        return endpoints

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
        LOG.debug(f"{self.prefix}Requesting {url}")
        r = requests.get(url, timeout=3)
        if r.status_code == 200:
            return r.json()["description"]
        LOG.error(f"{self.prefix}{r}")

    def _execute_update_cache(self, kv_stub, request, response):
        prefix = "/update_cache/"
        title = request.uri[len(prefix) :]
        description = self._get_description(title)
        if description == None:
            response.status_code = HTTP.HttpStatusCode.BAD_GATEWAY
            response.body = f"Error when fetching article with title '{title}'".encode(
                "utf-8"
            )
        else:
            kv_stub.Put(
                KV.KVKeyValue(
                    table=self.CACHE_TABLE,
                    key=title.encode("utf-8"),
                    value=description.encode("utf-8"),
                )
            )
            response.status_code = HTTP.HttpStatusCode.OK
            response.body = f"Successfully updated cache with description of '{title}':\n\n{description}".encode(
                "utf-8"
            )

    def _execute_get_description(self, kv_stub, request, response):
        prefix = "/article_description/"
        title = request.uri[len(prefix) :]
        result = kv_stub.Get(
            KV.KVKey(table=self.CACHE_TABLE, key=title.encode("utf-8"))
        )

        if not result.HasField("optional"):
            response.status_code = HTTP.HttpStatusCode.NOT_FOUND
            response.body = f"No description for '{title}' in cache".encode("utf-8")
        else:
            response.status_code = HTTP.HttpStatusCode.OK
            response.body = result.optional.value

    def run_loop(self, terminate_event):
        LOG.info(f"{self.prefix}Beginning executor loop")

        target_uri = self.ccf_node.get_public_rpc_address()
        with grpc.secure_channel(
            target=target_uri,
            credentials=self.credentials,
        ) as channel:
            stub = Service.KVStub(channel)

            while not (terminate_event.is_set()):
                for request in stub.StartTx(Empty()):
                    self.handled_requests_count += 1
                    
                    response = KV.ResponseDescription(
                        status_code=HTTP.HttpStatusCode.NOT_FOUND
                    )

                    if request.method == "POST" and request.uri.startswith(
                        "/update_cache/"
                    ):
                        LOG.info(f"{self.prefix}Updating article in cache: {request.uri}")
                        self._execute_update_cache(stub, request, response)

                    elif request.method == "GET" and request.uri.startswith(
                        "/article_description/"
                    ):
                        LOG.info(
                            f"{self.prefix}Retrieving description from cache: {request.uri}"
                        )
                        self._execute_get_description(stub, request, response)

                    else:
                        LOG.error(
                            f"{self.prefix}Unhandled request: {request.method} {request.uri}"
                        )
                        response.status_code = HTTP.HttpStatusCode.NOT_FOUND
                        response.body = (
                            f"No resource found at {request.method} {request.uri}".encode(
                                "utf-8"
                            )
                        )

                    stub.EndTx(response)

        LOG.info(f"{self.prefix}Ended executor loop")
