# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.network
import functools

from loguru import logger as LOG
from math import ceil


class TestRequirementsNotMet(Exception):
    pass


def description(desc):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            LOG.success(desc)
            return func(*args, **kwargs)

        return wrapper

    return decorator


def ensure_reqs(check_reqs):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(network, args, *nargs, **kwargs):
            if args.enforce_reqs:
                try:
                    # This should throw TestRequirementsNotMet if any checks fail.
                    # Return code is ignored
                    check_reqs(network, args, *nargs, **kwargs)
                except TestRequirementsNotMet:
                    raise
                except Exception as e:
                    raise TestRequirementsNotMet(
                        f"Could not check if test requirements were met: {e}"
                    ) from e

            return func(network, args, *nargs, **kwargs)

        return wrapper

    return decorator


def supports_methods(*methods):
    def remove_prefix(s, prefix):
        if s.startswith(prefix):
            return s[len(prefix) :]
        return s

    def check(network, args, *nargs, **kwargs):
        primary, _ = network.find_primary()
        with primary.client("user0") as c:
            response = c.get("/app/api")
            supported_methods = response.body.json()["paths"]
            LOG.warning(f"Supported methods are: {supported_methods.keys()}")
            missing = {*methods}.difference(
                [remove_prefix(key, "/") for key in supported_methods.keys()]
            )
            if missing:
                concat = ", ".join(missing)
                raise TestRequirementsNotMet(f"Missing required methods: {concat}")

    return ensure_reqs(check)


def at_least_n_nodes(n):
    def check(network, args, *nargs, **kwargs):
        running_nodes = len(network.get_joined_nodes())
        if running_nodes < n:
            raise TestRequirementsNotMet(
                f"Too few nodes. Only have {running_nodes}, requires at least {n}"
            )

    return ensure_reqs(check)


def sufficient_recovery_member_count():
    def check(network, args, *nargs, **kwargs):
        if (
            len(network.consortium.get_active_recovery_members())
            <= network.consortium.recovery_threshold
        ):
            raise TestRequirementsNotMet(
                "Cannot retire recovery member since number of active recovery members"
                f" ({len(network.consortium.get_active_members()) - 1}) would be less than"
                f" the recovery threshold ({network.consortium.recovery_threshold})"
            )

    return ensure_reqs(check)


def can_kill_n_nodes(nodes_to_kill_count):
    def check(network, args, *nargs, **kwargs):
        primary, _ = network.find_primary()
        with primary.client(
            f"member{network.consortium.get_any_active_member().member_id}"
        ) as c:
            r = c.post(
                "/gov/query",
                {
                    "text": """tables = ...
                        trusted_nodes_count = 0
                        tables["public:ccf.gov.nodes.info"]:foreach(function(node_id, details)
                            if details["status"] == "TRUSTED" then
                                trusted_nodes_count = trusted_nodes_count + 1
                            end
                        end)
                        return trusted_nodes_count
                        """
                },
            )

            trusted_nodes_count = r.body.json()
            running_nodes_count = len(network.get_joined_nodes())
            would_leave_nodes_count = running_nodes_count - nodes_to_kill_count
            minimum_nodes_to_run_count = ceil((trusted_nodes_count + 1) / 2)
            if args.consensus == "cft" and (
                would_leave_nodes_count < minimum_nodes_to_run_count
            ):
                raise TestRequirementsNotMet(
                    f"Cannot kill {nodes_to_kill_count} node(s) as the network would not be able to make progress"
                    f" (would leave {would_leave_nodes_count} nodes but requires {minimum_nodes_to_run_count} nodes to make progress) "
                )

    return ensure_reqs(check)


def installed_package(p):
    def check(network, args, *nargs, **kwargs):
        if args.package != p:
            raise TestRequirementsNotMet(
                f"Incorrect app. Requires '{p}', not '{args.package}'"
            )

    return ensure_reqs(check)


def recover(number_txs=5):
    # Runs some transactions before recovering the network and guarantees that all
    # transactions are successfully recovered
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            network = args[0]
            infra.e2e_args = vars(args[1])
            network.txs.issue(
                network=network,
                number_txs=infra.e2e_args.get("msgs_per_recovery") or number_txs,
            )
            new_network = func(*args, **kwargs)
            new_network.txs.verify(
                network=new_network,
                timeout=infra.e2e_args.get("ledger_recovery_timeout"),
            )
            return new_network

        return wrapper

    return decorator


def add_from_snapshot():
    # Before adding the node from a snapshot, override at least one app entry
    # and wait for a snapshot covering that entry. After the test, verify
    # that all entries (including historical ones) can be read.
    def issue_historical_queries_with_snapshot(network, snapshot_tx_interval):
        network.txs.issue(network, number_txs=1)
        for _ in range(1, snapshot_tx_interval):
            network.txs.issue(network, number_txs=1, repeat=True)
            last_tx = network.txs.get_last_tx(priv=True)
            if network.wait_for_snapshot_committed_for(seqno=last_tx[1]["seqno"]):
                break

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            network = args[0]
            infra.e2e_args = vars(args[1])
            snapshot_tx_interval = infra.e2e_args.get("snapshot_tx_interval")
            if snapshot_tx_interval is not None:
                issue_historical_queries_with_snapshot(
                    network, int(snapshot_tx_interval)
                )
            network = func(*args, **kwargs)
            # Only verify entries on node just added
            network.txs.verify(node=network.get_joined_nodes()[-1])

            return network

        return wrapper

    return decorator
