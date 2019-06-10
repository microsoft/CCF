# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
import getpass
import json
import time
import logging
import multiprocessing
import shutil
import random
import infra.ccf
import infra.proc
import infra.jsonrpc
import e2e_args

from loguru import logger as LOG


def run(args):
    hosts = ["localhost", "localhost"]
    os.makedirs(args.schema_dir, exist_ok=True)

    changed_files = []

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes
    ) as network:
        primary, followers = network.start_and_join(args)

        check = infra.ccf.Checker()

        with primary.user_client(format="json") as uc:
            list_response = uc.rpc("listMethods", {})
            check(list_response)
            methods = list_response.result["methods"]

            for method in methods:
                schema_response = uc.rpc("getSchema", {"method": method})
                check(schema_response)

                if schema_response.result is not None:
                    for schema_type in ["params", "result"]:
                        element_name = "{}_schema".format(schema_type)
                        element = schema_response.result[element_name]
                        if element is not None and len(element) != 0:
                            formatted_schema = json.dumps(element, indent=2)
                            target_file = os.path.join(
                                args.schema_dir,
                                "{}_{}.json".format(method, schema_type),
                            )
                            with open(target_file, "a+") as f:
                                f.seek(0)
                                previous = f.read()
                                if previous != formatted_schema:
                                    LOG.debug(
                                        "Writing schema to {}".format(target_file)
                                    )
                                    f.truncate(0)
                                    f.seek(0)
                                    f.write(formatted_schema)
                                    changed_files.append(target_file)
                                else:
                                    LOG.debug(
                                        "Schema matches in {}".format(target_file)
                                    )

    if len(changed_files) > 0:
        LOG.error("Made changes to the following schema files:")
        for f in changed_files:
            LOG.error(" " + f)
        sys.exit(1)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., libloggingenc)",
            required=True,
        )
        parser.add_argument(
            "--schema-dir",
            help="Path to directory where retrieved schema should be saved",
            required=True,
        )

    args = e2e_args.cli_args(add=add)
    run(args)
