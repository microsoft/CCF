# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
from loguru import logger as LOG
import json

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
for chunk in ledger:
    for transaction in chunk:
        # Retrieve all public tables changed in transaction
        public_tables = transaction.get_public_domain().get_tables()

        if target_table in public_tables:
            # Ledger verification is happening implicitly in ccf.ledger.Ledger()
            for key, value in public_tables[target_table].items():
                # Note: `key` and `value` are raw bytes here.
                # This code needs to have knowledge of the serialisation format for each table.
                # In this case, the target table 'public:ccf.gov.nodes.info' is raw bytes to JSON.
                LOG.info(f"{key.decode()} : {json.loads(value)}")
# SNIPPET_END: iterate_over_ledger
