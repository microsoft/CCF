Receipts
========

CCF implements `write` receipts, which are signed proofs associated with a transaction. They serve two main purposes:

1. :ref:`Endorse <use_apps/verify_tx:Application Claims>` claims made by the application logic, ie. a signed statement of fact, verifiable offline and by third parties, equivalent to "this transaction produced this outcome at this position in the ledger".
2. Together with a copy of the ledger, or other receipts, they can be used to :ref:`audit <audit/receipts:Receipts>` the service and hold the consortium to account.

Internally, receipts are also used to establish the validity of ledger snapshots.