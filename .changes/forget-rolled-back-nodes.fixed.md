A node which rolls back an uncommitted reconfiguration transaction now stops tracking the nodes which only that transaction added, where a primary previously continued to send them `AppendEntries` and to list them in `GET /node/consensus`.
See [Reconfiguration](doc/architecture/consensus/index.rst#reconfiguration).
