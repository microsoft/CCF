# Replay failure fixtures

The [Lean workflow](../../../../.github/workflows/lean.yml) runs the synthetic fixtures through the real replay executable.
Replication failures follow a two-node history with a committed signature, membership expansion, a further signature, a joiner initializing from a snapshot at the committed signature, a heartbeat and log replication.
The [valid control](valid/replication.ndjson) continues through follower catch-up, acknowledgement and commit.
Its snapshot installation hooks directly follow the leader's `replicate` and include a bare tick, both of which replay must accept.

| Fixture                                                                 | Expected failure                                     |
| ----------------------------------------------------------------------- | ---------------------------------------------------- |
| [Snapshot mismatch](invalid/snapshot-mismatch.ndjson)                   | Observed view differs from the model                 |
| [Unsupported snapshot field](invalid/unsupported-snapshot-field.ndjson) | Unsupported observation field                        |
| [Malformed append](invalid/malformed-append.ndjson)                     | Boolean append argument expected                     |
| [Ungrouped event](invalid/ungrouped-event.ndjson)                       | No reduction rule consumes the event                 |
| [Disabled append](invalid/disabled-append.ndjson)                       | Append attempted by a non-leader                     |
| [Missing packet](invalid/missing-packet.ndjson)                         | No queued model packet to receive                    |
| [Packet mismatch](invalid/packet-mismatch.ndjson)                       | Received index differs from the queued model payload |
| [Retirement on signature](invalid/retirement-signature.ndjson)          | Retirement follows a signature `replicate`           |
| [Retirement seqno mismatch](invalid/retirement-seqno-mismatch.ndjson)   | Retirement seqno differs from its `replicate`        |
| [Retirement node mismatch](invalid/retirement-node-mismatch.ndjson)     | Retirement follows another node's `replicate`        |
| [Retirement non-adjacent](invalid/retirement-nonadjacent.ndjson)        | An event separates `replicate` and its retirement    |
| [Orphan retirement](invalid/retirement-orphan.ndjson)                   | Retirement without a `replicate`                     |
| [Uncommitted snapshot](invalid/uncommitted-snapshot.ndjson)             | Joiner initializes at an uncommitted signature       |

From `lean/consensus`, inspect a failure directly (exit status 1 is expected):

```sh
lake exe consensus-replay replay/fixtures/invalid/snapshot-mismatch.ndjson
```
