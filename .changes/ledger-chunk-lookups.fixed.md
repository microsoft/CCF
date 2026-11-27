`GET` and `HEAD` requests to `/node/ledger_chunk?since=<seqno>` no longer wait for the ledger writer's lock to locate a committed chunk, for example while another chunk is being flushed to disk.
If no committed chunk contains the requested sequence number, the optional [`include_committed_prefix=true` fallback](doc/operations/ledger_snapshot.rst#download-endpoints) can still wait for the writer.
