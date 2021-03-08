# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.perfclient
import sys
import os

if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-w", "--warehouses", help="Number of warehouses", default=10, type=int
        )

    args, unknown_args = infra.perfclient.cli_args(add=add, accept_unknown=True)

    unknown_args = [term for arg in unknown_args for term in arg.split(" ")]

    def get_command(*common_args):
        return [*common_args, "--warehouses", str(args.accounts)] + unknown_args

    args.package = "libtpcc"
    infra.perfclient.run(get_command, args)
