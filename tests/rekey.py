# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.ccf
import infra.jsonrpc
import infra.notification
import suite.test_requirements as reqs
import e2e_args
import time

from loguru import logger as LOG


@reqs.supports_methods("mkSign", "LOG_record", "LOG_get")
@reqs.at_least_n_nodes(2)
def test(network, args):
    LOG.info("Rekey ledger after running some transactions")
    primary, backup = network.find_primary()

    with primary.node_client(format="json") as mc:
        check_commit = infra.checker.Checker(mc)
        check = infra.checker.Checker()

        msg = "Hello world"

        LOG.info("Record transactions on primary on primary")
        with primary.user_client(format="json") as c:
            for i in range(1, 1):
                check_commit(
                    c.rpc("LOG_record", {"id": i, "msg": f"{msg} #{i}"}), result=True
                )

        network.consortium.rekey_ledger(member_id=1, remote_node=primary)

        with primary.user_client(format="json") as c:
            for i in range(1, 1):
                check_commit(
                    c.rpc("LOG_record", {"id": i, "msg": f"{msg} #{i}"}), result=True
                )

    return network


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb,
    ) as network:
        network.start_and_join(args)
        test(network, args)


if __name__ == "__main__":

    args = e2e_args.cli_args()
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"
    run(args)
