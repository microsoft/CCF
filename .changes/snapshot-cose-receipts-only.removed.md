Nodes and `ccf.ledger.Snapshot` accept only COSE snapshot receipts, so snapshots written by releases before 7.0 are rejected when joining or recovering, and a node which rejects the snapshot fetched from its join target then joins from the sequence number that target started from.
See [Snapshot Receipts](doc/build_apps/migration_7_x_to_8_x.rst#snapshot-receipts).
