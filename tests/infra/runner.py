# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import copy
import getpass
import logging
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from random import seed
from typing import ClassVar

import better_exceptions
from loguru import logger as LOG

import infra.bencher
import infra.jwt_issuer
import infra.network
import infra.proc
import infra.remote_client

logging.getLogger("matplotlib").setLevel(logging.WARNING)


def minimum_number_of_local_nodes(args):
    if args.send_tx_to == "backups":
        return 2

    return 1


def get_command_args(args, get_command):
    command_args = []
    return get_command(*command_args)


def filter_nodes(primary, backups, filter_type):
    if filter_type == "primary":
        return [primary]
    elif filter_type == "backups":
        assert backups, "--send-tx-to backups but no backup was found"
        return backups
    else:
        return [primary] + backups


def configure_remote_client(args, client_id, client_host, node, command_args):
    client_host = infra.net.expand_localhost()
    try:
        remote_client = infra.remote_client.CCFRemoteClient(
            "client_" + str(client_id),
            client_host,
            args.client,
            node.get_public_rpc_host(),
            node.get_public_rpc_port(),
            args.workspace,
            args.label,
            args.config,
            command_args,
        )
        remote_client.setup()
        return remote_client
    except Exception:
        LOG.exception(f"Failed to start client {client_host}")
        raise


def run(get_command, args):
    if args.fixed_seed:
        seed(getpass.getuser())

    hosts = args.nodes
    if not hosts:
        hosts = infra.e2e_args.nodes(args, minimum_number_of_local_nodes(args))

    args.initial_user_count = 3
    args.sig_ms_interval = 1000  # Set to node default value
    args.ledger_chunk_bytes = "5MB"  # Set to node default value

    LOG.info(f"Starting nodes on {hosts}")

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        primary, backups = network.find_nodes()

        command_args = get_command_args(args, get_command)

        if args.use_jwt:
            jwt_issuer = infra.jwt_issuer.JwtIssuer("https://example.issuer")
            jwt_issuer.register(network)
            jwt = jwt_issuer.issue_jwt()
            command_args += ["--bearer-token", jwt]

        nodes_to_send_to = filter_nodes(primary, backups, args.send_tx_to)
        clients = []
        client_hosts = []
        if args.one_client_per_backup:
            assert backups, "--one-client-per-backup was set but no backup was found"
            client_hosts = ["localhost"] * len(backups)
        else:
            if args.client_nodes:
                client_hosts.extend(args.client_nodes)

        if args.num_localhost_clients:
            client_hosts.extend(["localhost"] * int(args.num_localhost_clients))

        if not client_hosts:
            client_hosts = ["localhost"]

        for client_id, client_host in enumerate(client_hosts):
            node = nodes_to_send_to[client_id % len(nodes_to_send_to)]
            remote_client = configure_remote_client(
                args, client_id, client_host, node, command_args
            )
            clients.append(remote_client)

        if args.network_only:
            for remote_client in clients:
                LOG.info(f"Client can be run with: {remote_client.remote.get_cmd()}")
            while True:
                time.sleep(60)
        else:
            for remote_client in clients:
                remote_client.start()

            hard_stop_timeout = 90
            format_width = len(str(hard_stop_timeout)) + 3

            try:
                start_time = time.time()
                while True:
                    stop_waiting = True
                    for i, remote_client in enumerate(clients):
                        done = remote_client.check_done(timeout=0)
                        # all the clients need to be done
                        LOG.info(
                            f"Client {i} has {'completed' if done else 'not completed'} running ({time.time() - start_time:>{format_width}.2f}s / {hard_stop_timeout}s)"
                        )
                        stop_waiting = stop_waiting and done
                    if stop_waiting:
                        break
                    if time.time() > start_time + hard_stop_timeout:
                        raise TimeoutError(
                            f"Client still running after {hard_stop_timeout}s"
                        )

                    time.sleep(5)

                perf_label = args.perf_label

                for remote_client in clients:
                    perf_result = remote_client.get_result()
                    LOG.success(f"{args.label}/{remote_client.name}: {perf_result}")
                    bf = infra.bencher.Bencher()
                    bf.set(
                        perf_label,
                        infra.bencher.Throughput(perf_result),
                    )

                primary, _ = network.find_primary()
                mem = infra.proc.get_proc_memory_stats(primary.remote.remote.proc.pid)
                if mem is not None:
                    bf = infra.bencher.Bencher()
                    bf.set_memory(perf_label, mem)

                for remote_client in clients:
                    remote_client.stop()

            except Exception:
                LOG.error("Stopping clients due to exception")
                for remote_client in clients:
                    remote_client.stop()
                raise


FAILURES = []


def log_exception(args: threading.ExceptHookArgs):
    description = f"Failure in {args.thread.name}: {args.exc_value!r}"
    FAILURES.append(description)
    LOG.error(
        description
        + "\n"
        + "\n".join(
            better_exceptions.format_exception(
                args.exc_type, args.exc_value, args.exc_traceback
            )
        )
    )


threading.excepthook = log_exception


class ConcurrentRunner:
    # Env var to filter sub-tests by exact name match. Value is a
    # '|'-separated list, e.g. CR_FILTER="testname1|testname2". When set,
    # only sub-tests whose name fully matches one of the entries are added.
    _test_filter: ClassVar[list[str] | None] = (
        os.environ["CR_FILTER"].split("|") if os.environ.get("CR_FILTER") else None
    )

    def __init__(self, add_options=None) -> None:
        def add(parser):
            parser.add_argument(
                "-N",
                "--show-only",
                help="List all sub-tests without executing",
                action="store_true",
            )
            parser.add_argument(
                "-R",
                "--regex",
                help="Run sub-tests whose name includes this string",
                metavar="<string>",
            )
            if add_options:
                add_options(parser)

        self.args = infra.e2e_args.cli_args(add=add)
        # Sub-tests to run, as (name, target, args) triples. Per instance, so
        # that two runners in one process do not inherit each other's sub-tests.
        # Threads are created by run(), so the pool decides how many exist.
        self.tests: list[tuple[str, object, object]] = []

    def add(self, prefix, target, **args_overrides):
        if self._test_filter is not None and prefix not in self._test_filter:
            return
        args_ = copy.deepcopy(self.args)
        for k, v in args_overrides.items():
            setattr(args_, k, v)
        args_.label = f"{prefix}_{self.args.label}"
        self.tests.append((prefix, target, args_))

    @staticmethod
    def default_max_concurrent():
        """Concurrent sub-tests a runner may have in flight.

        Each sub-test drives its own CCF network of one to five node processes.
        Nodes spend most of their time waiting on timers and sockets, but a
        network that cannot get CPU promptly sees spurious leadership elections
        and dropped sessions, so this bounds how many run at once.

        One per core: a ceiling on new growth rather than a tightening of what
        already worked, since the largest runner sustains around fifteen
        concurrent nodes on a sixteen-core CI runner without trouble. Tests
        whose sub-tests are unusually sensitive, such as partitions_test, pass
        a lower value to run().
        """
        cores_count = len(os.sched_getaffinity(0))
        return max(2, cores_count)

    def _resolve_max_concurrent(self, max_concurrent):
        limits = [max_concurrent or self.default_max_concurrent()]

        # Instrumented builds process every operation far more slowly, so they
        # sustain fewer concurrent networks before nodes start missing their
        # election timeouts.
        if os.getenv("TSAN_OPTIONS") or os.getenv("CCF_GLIBCXX_DEBUG"):
            cores_count = len(os.sched_getaffinity(0))
            avg_nodes_per_network = 3
            safety_factor = 0.5
            limits.append(
                max(1, int(safety_factor * cores_count / avg_nodes_per_network))
            )

        return max(1, min(limits))

    @staticmethod
    def _run_one(name, target, args):
        # Sub-tests are identified by thread name in the log format, so restore
        # it here: pool workers are reused and carry the previous name.
        threading.current_thread().name = name
        target(args)

    def run(self, max_concurrent=None):
        config = {
            "handlers": [
                {
                    "sink": sys.stdout,
                    "format": lambda record: infra.e2e_args.format_log_record(
                        record, include_thread=True
                    ),
                }
            ]
        }
        LOG.configure(**config)

        tests = self.tests
        if self.args.regex:
            pattern = re.compile(self.args.regex)
            tests = [test for test in tests if pattern.search(test[0])]

        if self.args.show_only:
            for name, _, _ in tests:
                print(name)
            return

        if not tests:
            return

        max_concurrent = self._resolve_max_concurrent(max_concurrent)
        LOG.info(
            f"Running {len(tests)} sub-tests, at most {max_concurrent} concurrently"
        )

        # A bounded pool rather than fixed batches: a sub-test starts as soon as
        # any other finishes, so a single long sub-test does not hold back the
        # ones queued behind it.
        failures = []
        with ThreadPoolExecutor(max_workers=max_concurrent) as pool:
            futures = {
                pool.submit(self._run_one, name, target, args): name
                for name, target, args in tests
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    future.result()
                except Exception as e:
                    description = f"Failure in {name}: {e!r}"
                    failures.append(description)
                    LOG.error(
                        description
                        + "\n"
                        + "".join(better_exceptions.format_exception(*sys.exc_info()))
                    )

        # FAILURES catches exceptions from threads the sub-tests start
        # themselves, which do not surface through the pool's futures.
        failures.extend(FAILURES)
        if failures:
            raise RuntimeError(failures)
