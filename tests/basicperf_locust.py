# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
"Basic Blocking Locust" benchmark.

Measures the throughput of blocking writes (PUT /records/blocking/{key}), which
only return once the transaction has committed. This covers the same ground as
the piccolo-driven "Basic Blocking" benchmark, but drives load with locust
instead, so that the client count can be ramped up and the workload described
in Python rather than in a pre-generated parquet file.

The load itself is defined in infra/basicperf_locustfile.py. Shared Locust
orchestration and statistics handling live in infra/locust_benchmark.py.
"""

import argparse

import infra.e2e_args
import infra.key_space
import infra.locust_benchmark

LOCUST_FILE_NAME = "basicperf_locustfile.py"


def prepare_workload(args, _network, primary) -> infra.locust_benchmark.Workload:
    infra.key_space.create_and_fill_key_space(args.key_space_size, primary)
    session_auth = primary.session_auth("user0")["session_auth"]
    return infra.locust_benchmark.Workload(
        locust_file_name=LOCUST_FILE_NAME,
        arguments=(
            "--cert",
            session_auth.cert,
            "--key",
            session_auth.key,
            "--key-space-size",
            str(args.key_space_size),
        ),
    )


def cli_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    infra.locust_benchmark.add_cli_arguments(parser)
    parser.add_argument(
        "--key-space-size",
        help="Size of the key space which is pre-populated and written to",
        type=int,
        default=1000,
    )
    return infra.e2e_args.cli_args(
        parser=parser, accept_unknown=False, ledger_chunk_bytes_override="5MB"
    )


if __name__ == "__main__":
    args = cli_args()
    # A single node is enough: the benchmark measures the time taken to commit
    # on the primary, and additional nodes only add replication cost.
    args.nodes = infra.e2e_args.min_nodes(args, f=0)

    infra.locust_benchmark.run(args, prepare_workload)
