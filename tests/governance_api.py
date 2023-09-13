# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
from loguru import logger as LOG
import suite.test_requirements as reqs
import json
import os
import openapi_core as oac

class CcfGovRequest:
    def __init__(self, node, path, method, operation):
        self._host_url = f"https://127.0.0.1:8000"
        self._path = path
        self._method = method
        self.parameters = oac.protocols.RequestParameters()
    @property
    def host_url(self):
        return self._host_url
    @property
    def path(self):
        return self._path
    @property
    def method(self):
        return self._method
    @property
    def body(self):
        return None
    @property
    def mimetype(self):
        return "application/json"

class CcfGovResponse:
    def __init__(self, result):
        self.data = None
        self.status_code = result.status_code
        self.headers = result.headers
        self.mimetype = "text/javascript"

def test_response_schema_single(primary, openapi_path):
    raw_spec = json.load(open(openapi_path))
    spec = oac.Spec.from_file_path(openapi_path)

    api_version = raw_spec["info"]["version"]

    with primary.client() as c:
        for path, operations in raw_spec["paths"].items():
            for method, operation in operations.items():
                # TODO: Variable substitution
                # TODO: Signed requests
                request = CcfGovRequest(primary, path, method, operation)
                oac.validate_request(request, spec)

                result = c.call(f"{path}?api-version={api_version}", http_verb=method)
                if result.status_code == 200:
                    response = CcfGovResponse(result)
                    oac.validate_response(request, response, spec);




@reqs.description(
    "Check that schema's endpoints are available, and return responses of the declared schema"
)
def test_response_schema(network, args):
    primary, _ = network.find_primary()

    openapi_dir = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "gov-api",
        "openapi",
    )
    for dirpath, dirnames, filenames in os.walk(openapi_dir):
        for file in filenames:
            openapi_path = os.path.join(dirpath, file)
            test_response_schema_single(primary, openapi_path)

    return network


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)

        network = test_response_schema(network, args)
