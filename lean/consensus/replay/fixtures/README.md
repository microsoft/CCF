# Replay failure fixtures

The [Lean workflow](../../../../.github/workflows/lean.yml) runs the synthetic fixtures through the real replay executable.
Replication failures follow a two-node history with a committed signature, membership expansion, a rejected heartbeat and log retransmission.
The [valid control](valid/replication.ndjson) continues through follower catch-up, commit and acknowledgement.
Singleton retirement fixtures check that unmatched writes are discarded while a matching write cannot attach to a signature.

| Fixture                                                                 | Expected failure                                     |
| ----------------------------------------------------------------------- | ---------------------------------------------------- |
| [Snapshot mismatch](invalid/snapshot-mismatch.ndjson)                   | Observed view differs from the model                 |
| [Unsupported snapshot field](invalid/unsupported-snapshot-field.ndjson) | Unsupported observation field                        |
| [Malformed append](invalid/malformed-append.ndjson)                     | Boolean append argument expected                     |
| [Ungrouped event](invalid/ungrouped-event.ndjson)                       | No reduction rule consumes the event                 |
| [Disabled append](invalid/disabled-append.ndjson)                       | Append attempted by a non-leader                     |
| [Missing packet](invalid/missing-packet.ndjson)                         | No queued model packet to receive                    |
| [Packet mismatch](invalid/packet-mismatch.ndjson)                       | Received index differs from the queued model payload |
| [Retirement on signature](invalid/retirement-signature.ndjson)          | Matching retirement write is followed by a signature |

Valid controls cover unmatched retirement writes followed by a [different seqno](valid/retirement-seqno-mismatch.ndjson), a [different node](valid/retirement-node-mismatch.ndjson), an [unrelated event](valid/retirement-nonadjacent.ndjson), or [end of input](valid/retirement-orphan.ndjson).

From `lean/consensus`, inspect a failure directly (exit status 1 is expected):

```sh
lake exe consensus-replay replay/fixtures/invalid/snapshot-mismatch.ndjson
```
