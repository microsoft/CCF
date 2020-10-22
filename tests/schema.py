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
import openapi_spec_validator

from loguru import logger as LOG


def run(args):
    os.makedirs(args.schema_dir, exist_ok=True)

    changed_files = []
    old_schema = set(
        os.path.join(dir_path, filename)
        for dir_path, _, filenames in os.walk(args.schema_dir)
        for filename in filenames
    )

    documents_valid = True
    all_methods = []

    def fetch_schema(client, prefix):
        api_response = client.get(f"/{prefix}/api")
        check(
            api_response, error=lambda status, msg: status == http.HTTPStatus.OK.value
        )

        response_body = api_response.body.json()
        paths = response_body["paths"]
        all_methods.extend(paths.keys())

        formatted_schema = json.dumps(response_body, indent=2)
        openapi_target_file = os.path.join(args.schema_dir, f"{prefix}_openapi.json")

        try:
            old_schema.remove(openapi_target_file)
        except KeyError:
            pass

        with open(openapi_target_file, "a+") as f:
            f.seek(0)
            previous = f.read()
            if previous != formatted_schema:
                LOG.debug("Writing schema to {}".format(openapi_target_file))
                f.truncate(0)
                f.seek(0)
                f.write(formatted_schema)
                changed_files.append(openapi_target_file)
            else:
                LOG.debug("Schema matches in {}".format(openapi_target_file))

        try:
            openapi_spec_validator.validate_spec(response_body)
        except Exception as e:
            LOG.error(f"Validation of {prefix} schema failed")
            LOG.error(e)
            return False

        return True

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes
    ) as network:
        network.start_and_join(args)
        primary, _ = network.find_primary()

        check = infra.checker.Checker()

        with primary.client("user0") as user_client:
            LOG.info("user frontend")
            if not fetch_schema(user_client, "app"):
                documents_valid = False

        with primary.client() as node_client:
            LOG.info("node frontend")
            if not fetch_schema(node_client, "node"):
                documents_valid = False

        with primary.client("member0") as member_client:
            LOG.info("member frontend")
            if not fetch_schema(member_client, "gov"):
                documents_valid = False

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

    if made_changes or not documents_valid:
        sys.exit(1)


if __name__ == "__main__":

    def add(parser):
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
    args.nodes = ["local://localhost"]
    run(args)
