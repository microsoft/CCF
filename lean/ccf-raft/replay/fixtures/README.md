# Replay failure fixtures

The [Lean workflow](../../../../.github/workflows/lean.yml) runs the synthetic fixtures through the real replay executable.
Each failure follows a two-node history with a committed signature, membership expansion, a rejected heartbeat and log retransmission.
The [valid control](valid/replication.ndjson) continues through follower catch-up, commit and acknowledgement.

| Fixture                                                                 | Expected failure                                     |
| ----------------------------------------------------------------------- | ---------------------------------------------------- |
| [Snapshot mismatch](invalid/snapshot-mismatch.ndjson)                   | Observed view differs from the model                 |
| [Unsupported snapshot field](invalid/unsupported-snapshot-field.ndjson) | Unsupported observation field                        |
| [Malformed append](invalid/malformed-append.ndjson)                     | Boolean append argument expected                     |
| [Ungrouped event](invalid/ungrouped-event.ndjson)                       | No reduction rule consumes the event                 |
| [Disabled append](invalid/disabled-append.ndjson)                       | Append attempted by a non-leader                     |
| [Missing packet](invalid/missing-packet.ndjson)                         | No queued model packet to receive                    |
| [Packet mismatch](invalid/packet-mismatch.ndjson)                       | Received index differs from the queued model payload |

From `lean/ccf-raft`, inspect a failure directly (exit status 1 is expected):

```sh
lake exe ccfraft-replay replay/fixtures/invalid/snapshot-mismatch.ndjson
```
