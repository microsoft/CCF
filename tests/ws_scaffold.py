# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.ccf
import infra.proc
import infra.notification
import infra.net
import suite.test_requirements as reqs
import infra.e2e_args
import time

from loguru import logger as LOG


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("/app/log/private")
@reqs.at_least_n_nodes(2)
def test(network, args, notifications_queue=None):
    primary, other = network.find_primary_and_any_backup()

    msg = "Hello world"
    LOG.info("Write on primary")
    with primary.client("user0", ws=True) as c:
        for i in [1, 50, 500]:
            r = c.rpc("/app/log/private", {"id": 42, "msg": msg * i})
            assert r.result == True, r.result

    # Before we start sending transactions to the secondary,
    # we want to wait for its app frontend to be open, which is
    # when it's aware that the network is open.
    end_time = time.time() + 10
    with other.client() as nc:
        while time.time() < end_time:
            r = nc.get("/node/network")
            if r.result == "OPEN":
                break
            else:
                time.sleep(0.1)
        assert r.result == "OPEN", r

    LOG.info("Write on secondary through forwarding")
    with other.client("user0", ws=True) as c:
        for i in [1, 50, 500]:
            r = c.rpc("/app/log/private", {"id": 42, "msg": msg * i})
            assert r.result == True, r.result

    return network


def run(args):
    hosts = ["localhost"] * (4 if args.consensus == "pbft" else 2)

    with infra.notification.notification_server(args.notify_server) as notifications:
        notifications_queue = (
            notifications.get_queue()
            if (args.package == "liblogging" and args.consensus == "raft")
            else None
        )

        with infra.ccf.network(
            hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
        ) as network:
            network.start_and_join(args)
            test(network, args, notifications_queue)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = args.app_script or "liblogging"

    notify_server_host = "localhost"
    args.notify_server = (
        notify_server_host
        + ":"
        + str(infra.net.probably_free_local_port(notify_server_host))
    )
    run(args)
