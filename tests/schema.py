# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
import json
import http
import infra.network
import infra.proc
import infra.e2e_args
import infra.checker

from loguru import logger as LOG


def build_schema_file_path(root, verb, method, schema_type):
    return os.path.join(root, "{}_{}_{}.json".format(method, verb.upper(), schema_type))


def run(args):
    hosts = ["localhost"] * (4 if args.consensus == "pbft" or args.consensus == "aft" else 2)
    os.makedirs(args.schema_dir, exist_ok=True)

    changed_files = []
    methods_with_schema = set()
    methods_without_schema = set()
    old_schema = set(
        os.path.join(dir_path, filename)
        for dir_path, _, filenames in os.walk(args.schema_dir)
        for filename in filenames
    )

    all_methods = []

    def fetch_schema(client, prefix):
        list_response = client.get(f"/{prefix}/api")
        check(
            list_response, error=lambda status, msg: status == http.HTTPStatus.OK.value
        )
        methods = list_response.body["endpoints"]
        all_methods.extend([m["path"] for m in methods])

        for method in [m["path"] for m in methods]:
            schema_found = False
            schema_response = client.get(f'/{prefix}/api/schema?method="{method}"')
            check(
                schema_response,
                error=lambda status, msg: status == http.HTTPStatus.OK.value,
            )

            if schema_response.body is not None:
                for verb, schema_element in schema_response.body.items():
                    for schema_type in ["params", "result"]:
                        element_name = "{}_schema".format(schema_type)
                        element = schema_element[element_name]
                        target_file = build_schema_file_path(
                            args.schema_dir, verb, method, schema_type
                        )
                        if element is not None and len(element) != 0:
                            try:
                                old_schema.remove(target_file)
                            except KeyError:
                                pass
                            schema_found = True
                            formatted_schema = json.dumps(element, indent=2)
                            os.makedirs(os.path.dirname(target_file), exist_ok=True)
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

            if schema_found:
                methods_with_schema.add(method)
            else:
                methods_without_schema.add(method)

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes
    ) as network:
        network.start_and_join(args)
        primary, _ = network.find_primary()

        check = infra.checker.Checker()

        with primary.client("user0") as user_client:
            LOG.info("user frontend")
            fetch_schema(user_client, "app")

        with primary.client() as node_client:
            LOG.info("node frontend")
            fetch_schema(node_client, "node")

        with primary.client("member0") as member_client:
            LOG.info("member frontend")
            fetch_schema(member_client, "gov")

    if len(methods_without_schema) > 0:
        LOG.info("The following methods have no schema:")
        for m in sorted(methods_without_schema):
            LOG.info(" " + m)

    made_changes = False

    if len(old_schema) > 0:
        LOG.error("Removing old files which are no longer reported by the service:")
        for f in old_schema:
            LOG.error(" " + f)
            os.remove(f)
            f_dir = os.path.dirname(f)
            # Remove empty directories too
            while not os.listdir(f_dir):
                os.rmdir(f_dir)
                f_dir = os.path.dirname(f_dir)
        made_changes = True

    if len(changed_files) > 0:
        LOG.error("Made changes to the following schema files:")
        for f in changed_files:
            LOG.error(" " + f)
        made_changes = True

    if args.list_all:
        LOG.info("Discovered methods:")
        for method in sorted(set(all_methods)):
            LOG.info(f"  {method}")

    if made_changes:
        sys.exit(1)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., liblogging)",
            required=True,
        )
        parser.add_argument(
            "--schema-dir",
            help="Path to directory where retrieved schema should be saved",
            required=True,
        )
        parser.add_argument(
            "--list-all",
            help="List all discovered methods at the end of the run",
            action="store_true",
        )

    args = infra.e2e_args.cli_args(add=add)
    run(args)
