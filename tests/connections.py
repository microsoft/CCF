# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import time
import infra.network
import infra.proc
import infra.checker
import contextlib
import resource
import psutil

from loguru import logger as LOG


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        check = infra.checker.Checker()
        network.start_and_join(args)
        primary, _ = network.find_nodes()

        primary_pid = primary.remote.remote.proc.pid

        num_fds = psutil.Process(primary_pid).num_fds()
        max_fds = num_fds + 150
        LOG.success(f"{primary_pid} has {num_fds} open file descriptors")

        resource.prlimit(primary_pid, resource.RLIMIT_NOFILE, (max_fds, max_fds))
        LOG.success(f"set max fds to {max_fds} on {primary_pid}")

        def create_connections_until_exhaustion(target):
            with contextlib.ExitStack() as es:
                clients = []
                LOG.success(f"Creating {target} clients")
                for i in range(target):
                    try:
                        LOG.info(f"Creating client {i}")
                        clients.append(es.enter_context(primary.client("user0", connection_timeout=1)))
                        check(
                            clients[-1].post("/app/log/private", {"id": 42, "msg": "foo"}),
                            result=True,
                        )
                    except Exception as e:
                        LOG.warning(f"Hit exception at client {i}: {e}")
                        break

                num_fds = psutil.Process(primary_pid).num_fds()
                LOG.success(
                    f"{primary_pid} has {num_fds}/{max_fds} open file descriptors"
                )

                clients.pop(-1)

                LOG.info("Continuing to submit on existing connections")
                for _ in range(1):
                    for client in clients:
                        try:
                            client.post("/app/log/private", {"id": 42, "msg": "foo"}, timeout=1)
                        except Exception as e:
                            LOG.error(e)
                            raise e

                time.sleep(1)
                num_fds = psutil.Process(primary_pid).num_fds()
                LOG.success(f"{primary_pid} has {num_fds}/{max_fds} open file descriptors")

                LOG.info("Disconnecting clients")
                clients = []

            time.sleep(1)
            num_fds = psutil.Process(primary_pid).num_fds()
            LOG.success(f"{primary_pid} has {num_fds}/{max_fds} open file descriptors")
            return num_fds

        nb_conn = (max_fds - num_fds) * 2
        num_fds = create_connections_until_exhaustion(nb_conn)

        to_create = max_fds - num_fds + 1
        num_fds = create_connections_until_exhaustion(to_create)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
