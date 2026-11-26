A node running the recovery decision protocol now requests its restart to join another node only once the transaction recording that decision has committed, so a node that opens the service while an `IAmOpen` message is being handled is no longer restarted.
See [Recovery Decision Protocol](doc/operations/recovery.rst#recovery-decision-protocol).
