# Replay failure fixtures

The [Lean workflow](../../../../.github/workflows/lean.yml) runs the synthetic fixtures through the real replay executable.
Each invalid fixture must exit with status 1, print no success output, and match its adjacent `.stderr` file exactly, with absolute paths replaced by the fixture name.
Each failure follows a two-node history with a committed signature, membership expansion, a rejected heartbeat and log retransmission.
The [valid control](valid/replication.ndjson) continues through follower catch-up, commit and acknowledgement.

| Fixture                                                              | Expected diagnostic                                                                    |
| -------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| [Snapshot mismatch](invalid/snapshot-mismatch.ndjson)                  | [Observed view differs from the model](invalid/snapshot-mismatch.stderr)                |
| [Unsupported snapshot field](invalid/unsupported-snapshot-field.ndjson) | [Unsupported observation field](invalid/unsupported-snapshot-field.stderr)              |
| [Malformed append](invalid/malformed-append.ndjson)                    | [Boolean append argument expected](invalid/malformed-append.stderr)                     |
| [Ungrouped event](invalid/ungrouped-event.ndjson)                      | [No reduction rule consumes the event](invalid/ungrouped-event.stderr)                  |
| [Disabled append](invalid/disabled-append.ndjson)                      | [Append attempted by a non-leader](invalid/disabled-append.stderr)                       |
| [Missing packet](invalid/missing-packet.ndjson)                        | [No queued model packet to receive](invalid/missing-packet.stderr)                      |
| [Packet mismatch](invalid/packet-mismatch.ndjson)                       | [Received index differs from the queued model payload](invalid/packet-mismatch.stderr) |

From `lean/ccf-raft`, inspect a failure directly (exit status 1 is expected):

```sh
lake exe ccfraft-replay replay/fixtures/invalid/snapshot-mismatch.ndjson
```
