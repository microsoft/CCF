# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import json
import http
import infra.network
import infra.proc
import infra.e2e_args
import infra.checker
import openapi_spec_validator
from packaging import version
from infra.runner import ConcurrentRunner
import nobuiltins
import packaging.version
import e2e_tutorial
import e2e_operations

from loguru import logger as LOG


def run(args):
    os.makedirs(args.schema_dir, exist_ok=True)

    changed_files = []
    old_schema = set(
        dir_entry.path
        for dir_entry in os.scandir(args.schema_dir)
        if dir_entry.is_file()
    )

    documents_valid = True
    all_methods = []

    def fetch_schema(api_response, target_file_path):
        check(
            api_response, error=lambda status, msg: status == http.HTTPStatus.OK.value
        )

        response_body = api_response.body.json()
        paths = response_body["paths"]
        all_methods.extend(paths.keys())
        fetched_version = response_body["info"]["version"]

        formatted_schema = json.dumps(response_body, indent=2)
        openapi_target_file = os.path.join(args.schema_dir, target_file_path)

        try:
            old_schema.remove(openapi_target_file)
        except KeyError:
            pass

        with open(openapi_target_file, "a+", encoding="utf-8") as f:
            prefix, ext = os.path.splitext(openapi_target_file)
            f.seek(0)
            previous = f.read().strip()
            if previous != formatted_schema:
                file_version = "0.0.0"
                try:
                    from_file = json.loads(previous)
                    file_version = from_file["info"]["version"]
                    file_version = version.parse(file_version)
                except (
                    json.JSONDecodeError,
                    KeyError,
                    packaging.version.InvalidVersion,
                ):
                    pass

                try:
                    fetched_version = version.parse(fetched_version)
                except packaging.version.InvalidVersion:
                    pass

                if fetched_version > file_version:
                    LOG.debug(
                        f"Writing schema to {openapi_target_file} - overwriting {file_version} with {fetched_version}"
                    )
                    f.truncate(0)
                    f.seek(0)
                    f.write(formatted_schema)
                else:
                    LOG.error(
                        f"Found differences in {openapi_target_file}, but not overwriting as retrieved version is not newer ({fetched_version} <= {file_version})"
                    )
                    alt_file = f"{prefix}_{fetched_version}{ext}"
                    LOG.error(f"Writing to {alt_file} for comparison")
                    with open(alt_file, "w", encoding="utf-8") as f2:
                        f2.write(formatted_schema)
                    try:
                        old_schema.remove(alt_file)
                    except KeyError:
                        pass
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
        network.start_and_open(args)
        primary, _ = network.find_primary()

        check = infra.checker.Checker()

        with primary.client() as client:
            LOG.info("user frontend")
            if not fetch_schema(client.get("/app/api"), "app_openapi.json"):
                documents_valid = False

            LOG.info("node frontend")
            if not fetch_schema(client.get("/node/api"), "node_openapi.json"):
                documents_valid = False

            LOG.info("member frontend")
            if not fetch_schema(client.get("/gov/api"), "gov_openapi.json"):
                documents_valid = False

        with primary.api_versioned_client(
            api_version=infra.clients.API_VERSION_PREVIEW_01
        ) as client:
            LOG.info("gov API - preview v1")
            if not fetch_schema(
                client.get("/gov/api"), "gov/2023-06-01-preview/gov.json"
            ):
                documents_valid = False

        with primary.api_versioned_client(
            api_version=infra.clients.API_VERSION_01
        ) as client:
            LOG.info("gov API - v1")
            if not fetch_schema(client.get("/gov/api"), "gov/2024-07-01/gov.json"):
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
        LOG.error("Found problems with the following schema files:")
        for f in changed_files:
            LOG.error(" " + f)
        made_changes = True

    if args.list_all:
        LOG.info("Discovered methods:")
        for method in sorted(set(all_methods)):
            LOG.info(f"  {method}")

    assert not (made_changes or not documents_valid)


def run_nobuiltins(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        nobuiltins.test_nobuiltins_endpoints(network, args)


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
        parser.add_argument(
            "--ledger-tutorial",
            help="Path to ledger tutorial file",
            type=str,
        )
        parser.add_argument(
            "--config-samples-dir",
            help="Configuration samples directory",
            type=str,
            default=None,
        )
        parser.add_argument(
            "--historical-testdata",
            help="Historical ledger test data directory",
            type=str,
        )

    cr = ConcurrentRunner(add)

    # cr.add(
    #     "schema",
    #     run,
    #     package="samples/apps/logging/liblogging",
    #     nodes=infra.e2e_args.nodes(cr.args, 1),
    # )

    # cr.add(
    #     "nobuiltins",
    #     run_nobuiltins,
    #     package="samples/apps/nobuiltins/libnobuiltins",
    #     nodes=infra.e2e_args.min_nodes(cr.args, f=1),
    # )

    # cr.add(
    #     "tutorial",
    #     e2e_tutorial.run,
    #     package="samples/apps/logging/liblogging",
    #     nodes=["local://127.0.0.1:8000"],
    #     initial_member_count=1,
    # )

    cr.add(
        "operations",
        e2e_operations.run,
        package="samples/apps/logging/liblogging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        initial_user_count=1,
        ledger_chunk_bytes="1MB",
    )

    cr.run()
