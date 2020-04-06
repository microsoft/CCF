# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.ccf
import infra.notification
import suite.test_requirements as reqs
import infra.e2e_args
import time

from loguru import logger as LOG


@reqs.description("Rekey the ledger once")
@reqs.supports_methods("mkSign")
@reqs.at_least_n_nodes(1)
def test(network, args):
    primary, _ = network.find_primary()

    # Retrieve current index version to check for sealed secrets later
    with primary.node_client() as nc:
        check_commit = infra.checker.Checker(nc)
        res = nc.rpc("mkSign")
        check_commit(res, result=True)
        version_before_rekey = res.commit

    network.consortium.rekey_ledger(primary)
    network.wait_for_sealed_secrets_at_version(version_before_rekey)

    return network


# Run some write transactions against the logging app
def record_transactions(primary, txs_count=1):
    with primary.node_client() as nc:
        check_commit = infra.checker.Checker(nc)

        with primary.user_client() as c:
            for i in range(1, txs_count):
                check_commit(
                    c.rpc("LOG_record", {"id": i, "msg": f"entry #{i}"}), result=True
                )


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb,
    ) as network:
        network.start_and_join(args)
        primary, _ = network.find_primary()

        record_transactions(primary)
        test(network, args)
        record_transactions(primary)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = args.app_script and "liblua_generic" or "liblogging"
    run(args)
