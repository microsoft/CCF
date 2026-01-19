# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
from infra.runner import ConcurrentRunner
import e2e_operations

if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "platform",
        e2e_operations.run_snp_tests,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
        initial_user_count=1,
        ledger_chunk_bytes="1B",  # Chunk ledger at every signature transaction
    )

    cr.run()
