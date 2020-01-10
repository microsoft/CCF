# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.ccf
import infra.jsonrpc
import infra.notification
import suite.test_requirements as reqs
import e2e_args

from loguru import logger as LOG

@reqs.at_least_n_nodes(2)
def test(network, args, notifications_queue=None):
    LOG.info("Running transactions against logging app")
    primary, backup = network.find_primary_and_any_backup()

    with primary.node_client(format="json") as mc:
        check_commit = infra.checker.Checker(mc, notifications_queue)
        check = infra.checker.Checker()

        msg = "Hello world"
        msg2 = "Hello there"
        backup_msg = "Msg sent to a backup"

        LOG.info("Write/Read on primary")
        with primary.user_client(format="json") as c:
            check_commit(c.rpc("LOG_record", {"id": 42, "msg": msg}), result=True)
            check_commit(c.rpc("LOG_record", {"id": 43, "msg": msg2}), result=True)
            check(c.rpc("LOG_get", {"id": 42}), result={"msg": msg})
            check(c.rpc("LOG_get", {"id": 43}), result={"msg": msg2})

        LOG.info("Write on all backup frontends")
        with backup.node_client(format="json") as c:
            check_commit(c.do("mkSign", params={}), result=True)
        with backup.member_client(format="json") as c:
            check_commit(c.do("mkSign", params={}), result=True)

        LOG.info("Write/Read on backup")

        with backup.user_client(format="json") as c:
            check_commit(
                c.rpc("LOG_record", {"id": 100, "msg": backup_msg}), result=True
            )
            check(c.rpc("LOG_get", {"id": 100}), result={"msg": backup_msg})
            check(c.rpc("LOG_get", {"id": 42}), result={"msg": msg})

        LOG.info("Write/Read large messages on primary")
        with primary.user_client(format="json") as c:
            id = 44
            for p in range(14, 20):
                long_msg = "X" * (2 ** p)
                check_commit(
                    c.rpc("LOG_record", {"id": id, "msg": long_msg}), result=True,
                )
                check(c.rpc("LOG_get", {"id": id}), result={"msg": long_msg})
                id += 1

    return network


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb,
    ) as network:
        network.start_and_join(args)
        network = test(network, args, None)


if __name__ == "__main__":
    args = e2e_args.cli_args()
    args.package = "libjsgenericenc"
    run(args)
