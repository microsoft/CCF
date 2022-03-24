Receipts
========

In combination with a copy of the ledger, receipts are also useful for audit purposes.

Check for transaction inclusion
-------------------------------

A user having executed a transaction, fetched a receipt for it, can check for its inclusion in the ledger.
All they need to do is scan to the corresponding :term:`Transaction ID`, digest the transaction, and compare it with `write_set_digest` in their receipt.

Denounce an invalid recovery
----------------------------

A user having executed a number of transactions, and fetched receipts for them, can denounce a recovery that removes one or more of these transactions.
This may occur if the consortium approves a catastrophic recovery from a truncated ledger.

This user can either:

1. Query the new service for receipts at the same :term:`Transaction ID` values.  If those transactions come back as `INVALID`, because they were truncated, the signature over the old receipts is proof of truncation. If they come back as `COMMITTED` with a different root, the existence of two signatures over different roots at the same TxID is proof that a fork happened.
2. Scan the ledger, for example using the :doc:`/audit/python_library`, and find the transactions for which they have receipts. The `write_set_digest` in the receipt should match the digest of the transactions on disk. If it doesn't, the signature over the receipt is proof of a fork.