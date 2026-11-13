Joining and backup nodes now allocate the buffer for a snapshot fetched from a peer once, at the snapshot's full size, instead of growing it as byte ranges arrive, so a fetch needs about the snapshot's size in memory rather than two or more times it.
See [Backup Snapshot Fetching](doc/operations/ledger_snapshot.rst#backup-snapshot-fetching).
