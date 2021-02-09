# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
from loguru import logger as LOG

# Note: It is safer to run the ledger tutorial when the service has stopped
# as all ledger files will have been written to.

# Change default log format
LOG.remove()
LOG.add(
    sys.stdout,
    format="<green>[{time:HH:mm:ss.SSS}]</green> {message}",
)

if len(sys.argv) < 2:
    print("Error: Ledger directory should be specified as first argument")
    sys.exit(1)

ledger_dir = sys.argv[1]

# SNIPPET: import_ledger
import ccf.ledger

# SNIPPET: create_ledger
ledger = ccf.ledger.Ledger(ledger_dir)

# SNIPPET: target_table
target_table = "public:ccf.gov.nodes.info"

# SNIPPET_START: iterate_over_ledger
target_table_changes = 0  # Simple counter

for chunk in ledger:
    for transaction in chunk:
        # Retrieve all public tables changed in transaction
        public_tables = transaction.get_public_domain().get_tables()

        # If target_table was changed, count the number of keys changed
        if target_table in public_tables:
            for key, value in public_tables[target_table].items():
                target_table_changes += 1  # A key was changed
# SNIPPET_END: iterate_over_ledger
