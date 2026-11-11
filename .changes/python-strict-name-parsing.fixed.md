`ccf.ledger.range_from_filename`, `ccf.ledger.snapshot_index_from_filename` and `ccf.tx_id.TxID.parse` now reject names and transaction IDs containing signs, whitespace, underscores, non-ASCII digits or unexpected prefixes.
`range_from_filename` also rejects ordinary ledger chunk names whose end seqno precedes their start seqno.
