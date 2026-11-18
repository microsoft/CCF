# Replay failure fixtures

The [Lean workflow](../../../../.github/workflows/lean.yml) runs the synthetic fixtures through the real replay executable.
Replication failures follow a two-node history with a committed signature, membership expansion, a further signature, a joiner initializing from a snapshot at the committed signature, a heartbeat and log replication.
The [valid control](valid/replication.ndjson) continues through follower catch-up, acknowledgement and commit.
Its snapshot installation hooks directly follow the leader's `replicate` batch and include a bare tick, both of which replay must accept.
The [rejected replicate](valid/rejected-replicate.ndjson) control is a `replicate` call that CCF rejected at its first entry, so it traces no `replicate_entry` and appends nothing.
The [bootstrap](valid/bootstrap.ndjson) control starts like a real node: bare ticks before genesis, then a flush of the genesis entry.

| Fixture                                                                 | Expected failure                                        |
| ----------------------------------------------------------------------- | ------------------------------------------------------- |
| [Snapshot mismatch](invalid/snapshot-mismatch.ndjson)                   | Observed view differs from the model                    |
| [Unsupported snapshot field](invalid/unsupported-snapshot-field.ndjson) | Unsupported observation field                           |
| [Malformed append](invalid/malformed-append.ndjson)                     | Boolean append argument expected                        |
| [Ungrouped event](invalid/ungrouped-event.ndjson)                       | No reduction rule consumes the event                    |
| [Disabled append](invalid/disabled-append.ndjson)                       | Append attempted by a non-leader                        |
| [Missing packet](invalid/missing-packet.ndjson)                         | No queued model packet to receive                       |
| [Packet mismatch](invalid/packet-mismatch.ndjson)                       | Received index differs from the queued model payload    |
| [Retirement on signature](invalid/retirement-signature.ndjson)          | Retirement follows a signature `replicate_entry`        |
| [Retirement seqno mismatch](invalid/retirement-seqno-mismatch.ndjson)   | Retirement seqno differs from its `replicate_entry`     |
| [Retirement node mismatch](invalid/retirement-node-mismatch.ndjson)     | Retirement follows another node's `replicate_entry`     |
| [Retirement non-adjacent](invalid/retirement-nonadjacent.ndjson)        | An event separates `replicate_entry` and its retirement |
| [Orphan retirement](invalid/retirement-orphan.ndjson)                   | Retirement without a `replicate_entry`                  |
| [Uncommitted snapshot](invalid/uncommitted-snapshot.ndjson)             | Joiner initializes at an uncommitted signature          |
| [Bootstrap event](invalid/bootstrap-event.ndjson)                       | Non-tick event before genesis                           |
| [Bootstrap flush send](invalid/bootstrap-flush-send.ndjson)             | Send from the genesis flush, which must send nothing    |

From `lean/consensus`, inspect a failure directly (exit status 1 is expected):

```sh
lake exe consensus-replay replay/fixtures/invalid/snapshot-mismatch.ndjson
```
