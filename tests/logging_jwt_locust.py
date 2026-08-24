# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Blocking-on-commit logging benchmark authenticated with bearer JWTs."""

import argparse

import infra.e2e_args
import infra.jwt_issuer
import infra.locust_benchmark
from loguru import logger as LOG

LOCUST_FILE_NAME = "logging_jwt_locustfile.py"
DEFAULT_KEY_SPACE_SIZE = 1000


def prepare_workload(args, network, _primary) -> infra.locust_benchmark.Workload:
    jwt_issuer = infra.jwt_issuer.JwtIssuer("https://example.issuer")
    jwt_issuer.register(network)
    jwt = jwt_issuer.issue_jwt()
    return infra.locust_benchmark.Workload(
        locust_file_name=LOCUST_FILE_NAME,
        arguments=("--key-space-size", str(args.key_space_size)),
        # The token is inherited by Locust workers but never appears in the
        # process command line or the logged command.
        environment={infra.locust_benchmark.JWT_ENVIRONMENT_VARIABLE: jwt},
    )


def cli_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    infra.locust_benchmark.add_cli_arguments(parser)
    parser.add_argument(
        "--key-space-size",
        help="Number of distinct logging records written to",
        type=int,
        default=DEFAULT_KEY_SPACE_SIZE,
    )
    return infra.e2e_args.cli_args(
        parser=parser, accept_unknown=False, ledger_chunk_bytes_override="5MB"
    )


if __name__ == "__main__":
    args = cli_args()
    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    LOG.info("Running Logging JWT Blocking Locust benchmark")
    infra.locust_benchmark.run(args, prepare_workload)
