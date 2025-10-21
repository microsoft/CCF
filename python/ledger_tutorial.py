# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import sys
import json
import random
import ccf.ledger

if len(sys.argv) < 2:
    print("Error: Ledger directory should be specified as first argument")
    sys.exit(1)

ledger_dirs = sys.argv[1:]

# Because all ledger files are closed and are no longer being
# written to, it is safe to read all of them, even those that may
# contain uncommitted transactions.
# SNIPPET_START: create_ledger

ledger = ccf.ledger.Ledger(ledger_dirs, committed_only=False)
# SNIPPET_END: create_ledger

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
                print(f"{key.decode()} : {json.loads(value)}")
# SNIPPET_END: iterate_over_ledger

# Read state of ledger
latest_state, latest_seqno = ledger.get_latest_public_state()

seqnos = [1, 2, 3, latest_seqno // 2, latest_seqno]
random.shuffle(seqnos)
for seqno in seqnos:
    transaction = ledger.get_transaction(seqno)

# Confirm latest state can still be accessed, and is unchanged
latest_state1, latest_seqno1 = ledger.get_latest_public_state()
assert latest_seqno == latest_seqno1
assert latest_state == latest_state1
