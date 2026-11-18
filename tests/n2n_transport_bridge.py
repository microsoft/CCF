# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Legacy interoperability coverage intended for removal with the N2N bridge."""

import infra.e2e_args
import infra.interfaces
from infra.runner import ConcurrentRunner
from n2n_tls import run

if __name__ == "__main__":
    runner = ConcurrentRunner()
    runner.args.package = "samples/apps/logging/logging"
    for name, enabled in (
        ("legacy", (False, False, False)),
        ("mixed", (True, True, False, False)),
    ):
        hosts = infra.e2e_args.nodes(runner.args, len(enabled))
        for host, tls in zip(hosts, enabled):
            host.node_to_node_tls_interface = (
                infra.interfaces.Interface(host=host.get_primary_interface().host)
                if tls
                else None
            )
        runner.add(
            name,
            run,
            nodes=hosts,
            snapshot_tx_interval=100,
        )
    runner.run()
