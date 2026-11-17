# Trace validation fixtures

The [Lean workflow](../../../../.github/workflows/lean-package.yml) runs these fixtures through the `consensus-replay` executable.
The valid fixtures are unmodified `cft_driver` captures: [two-node startup](valid/startup_2nodes.ndjson), [append](valid/append.ndjson) and [reconfiguration](valid/reconfig_0_1.ndjson).
Each invalid fixture is the two-node startup capture with one change, and must be rejected with exit status 1.

| Fixture                                                         | Change                                                    | Expected failure                                           |
| --------------------------------------------------------------- | --------------------------------------------------------- | ---------------------------------------------------------- |
| [State mismatch](invalid/state-mismatch.ndjson)                 | A `replicate_entry` snapshot's `last_idx` is one too high | `state.last_idx` differs from the model                    |
| [Commit mismatch](invalid/commit-mismatch.ndjson)               | A `commit` event's `idx` is lowered                       | `idx` differs from the model                               |
| [Match index mismatch](invalid/match-idx-mismatch.ndjson)       | A response's `match_idx` is raised                        | `match_idx` differs from the model                         |
| [Packet mismatch](invalid/packet-mismatch.ndjson)               | A received AppendEntries has a different `prev_idx`       | No node can step: the receive matches no published message |
| [Missing send](invalid/missing-send.ndjson)                     | A `send_append_entries_response` is deleted               | The lock is released before the expected trace point       |
| [Missing commit](invalid/missing-commit.ndjson)                 | A `commit` event is deleted                               | The lock is released before the expected trace point       |
| [Unknown trace point](invalid/unknown-trace-point.ndjson)       | `execute_append_entries_sync` is renamed                  | The model expects a different trace point                  |
| [Reordered events](invalid/reordered-events.ndjson)             | Two events of one node are swapped                        | The model expects a different trace point                  |
| [Configuration mismatch](invalid/configuration-mismatch.ndjson) | An `add_configuration` hook omits a node                  | A later send is not explained by the open lock hold        |
| [Missing field](invalid/missing-field.ndjson)                   | `become_leader` lacks its `votes_for_me` field            | `votes_for_me` is absent                                   |
| [Missing sequence number](invalid/missing-seqno.ndjson)         | A `replicate_entry` lacks its `seqno` field               | `seqno` is absent                                          |
| [Missing match index](invalid/missing-match-idx.ndjson)         | A `send_append_entries` lacks its `match_idx` field       | `match_idx` is absent                                      |

From `lean/consensus`, inspect a failure directly (exit status 1 is expected):

```sh
lake exe consensus-replay replay/fixtures/invalid/state-mismatch.ndjson
```
