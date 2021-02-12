# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import suite.test_requirements as reqs
import reconfiguration
import random
import time
import threading
from ccf.log_capture import flush_info

from loguru import logger as LOG


@reqs.description("Suspend and resume primary")
@reqs.at_least_n_nodes(3)
def test_suspend_primary(network, args):
    primary, _ = network.find_primary()
    primary.suspend()
    new_primary, new_term = network.wait_for_new_primary(primary.node_id)
    LOG.debug(f"New primary is {new_primary.node_id} in term {new_term}")
    reconfiguration.check_can_progress(new_primary)
    primary.resume()
    reconfiguration.check_can_progress(new_primary)
    return network


@reqs.description("Suspend and resume all nodes while submitting constant client load")
@reqs.at_least_n_nodes(3)
def test_rolling_disconnections(network, args):
    def client_action(nodes, shutdown_event):
        node_index = 0
        last_status = None
        while not shutdown_event.is_set():
            node = nodes[node_index]
            with node.client("user0") as uc:
                this_status = None
                try:
                    logs = []
                    r = uc.post(
                        "/app/log/private",
                        {"id": 42, "msg": "Hello world"},
                        timeout=0.5,
                        log_capture=logs,
                    )
                    this_status = r.status_code
                except Exception as e:
                    pass

                # Only log output when status code changes, swallow all contiguous repeats
                if this_status != last_status:
                    last_status = this_status
                    flush_info(logs)
            node_index = (node_index + 1) % len(nodes)

    primary, backups = network.find_nodes()
    nodes = [primary, *backups]

    # Start a second thread which will submit commands round robin to each node
    shutdown_event = threading.Event()
    clients_thread = threading.Thread(
        target=client_action, args=(nodes, shutdown_event)
    )
    clients_thread.start()

    try:
        # Suspend the nodes one-by-one, in a random order
        random.shuffle(nodes)
        for node in nodes:
            node.suspend()
            time.sleep(1)

        # Resume the nodes one-by-one, in a (different!) random order
        random.shuffle(nodes)
        for node in nodes:
            node.resume()
            time.sleep(1)

        new_primary, new_term = network.find_primary(timeout=16)
        LOG.debug(f"New primary is {new_primary.node_id} in term {new_term}")

        reconfiguration.check_can_progress(new_primary)

        shutdown_event.set()
        clients_thread.join()
    except:
        shutdown_event.set()
        clients_thread.join()
        raise


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        # Replace primary repeatedly and check the network still operates
        LOG.info(f"Retiring primary {args.rotation_retirements} times")
        for _ in range(args.rotation_retirements):
            LOG.warning(f"Retirement {i}")
            reconfiguration.test_add_node(network, args)
            reconfiguration.test_retire_primary(network, args)

        reconfiguration.test_add_node(network, args)
        # Suspend primary repeatedly and check the network still operates
        # Suspend all nodes while submitting transactions and check the network recovers
        LOG.info(f"Suspending primary {args.rotation_suspensions} times")
        for i in range(args.rotation_suspensions):
            LOG.warning(f"Suspension {i}")
            test_suspend_primary(network, args)

            LOG.warning(f"Rolling disconnection {i}")
            test_rolling_disconnections(network, args)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--rotation-retirements",
            help="Number of times to retired the primary",
            type=int,
            default=3,
        )
        parser.add_argument(
            "--rotation-suspensions",
            help="Number of times to suspend the primary",
            type=int,
            default=3,
        )

    args = infra.e2e_args.cli_args(add=add)
    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_member_count = 1
    run(args)
