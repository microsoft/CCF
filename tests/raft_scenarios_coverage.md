# Raft scenario coverage report

## Method

Coverage was measured from a Debug build configured with `-DCOVERAGE=ON`.
The baseline ran the 42 scenario files on the base commit, before the eight
files added by this PR. Each new scenario profile was then merged cumulatively
in the order shown below.
`llvm-profdata-18` and `llvm-cov-18 report` produced the line and branch totals.
Raft tracing was disabled for the coverage build, matching `coverage.yml`.

The overall figures include every instrumented source file linked into
`raft_driver`. The focused figures cover `raft.h`, `driver.cpp`, `driver.h`, and
`logging_stub.h`.

## Results

| Scope                      |       Baseline lines |          Final lines |  Baseline branches |     Final branches |
| -------------------------- | -------------------: | -------------------: | -----------------: | -----------------: |
| Whole `raft_driver` binary | 3,243/6,604 (49.11%) | 3,361/6,604 (50.89%) | 940/1,522 (61.76%) | 982/1,522 (64.52%) |
| Raft driver and AFT core   | 2,692/3,520 (76.48%) | 2,807/3,520 (79.74%) | 853/1,312 (65.02%) | 893/1,312 (68.06%) |

Together, the eight scenarios added by this PR add 118 covered lines and 42
covered branch outcomes. This raises whole-binary line coverage by 1.79
percentage points and branch coverage by 2.76 percentage points.

| Scenario                         | Summary                                                                                                                                                                        | New lines | New branches | Cumulative line / branch coverage |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------: | -----------: | --------------------------------: |
| `leadership_race`                | Isolates a leader until CheckQuorum makes it step down, attempts a client write and leadership transfer while leaderless, then elects a replacement from the surviving quorum. |        25 |            7 |                   49.49% / 62.22% |
| `delayed_vote_requests`          | Starts simultaneous election attempts, rejects a delayed same-term vote request after learning the winner, and ignores the delayed rejection during a later pre-vote round.    |        19 |            6 |                   49.77% / 62.61% |
| `retirement_rollback`            | Delivers an unsigned retirement to the retiring node, then elects it with quorums from both active configurations so leadership rolls back the abandoned reconfiguration.      |        16 |            6 |                   50.02% / 63.01% |
| `retired_node_delayed_responses` | Retains vote and append responses across retirement cleanup and verifies that responses from the removed peer are safely ignored.                                              |        12 |            6 |                   50.20% / 63.40% |
| `large_entry_batching`           | Replicates a burst whose encoded size crosses the AppendEntries target, forcing batch-size recalculation and proactive sends before normal commit.                             |        10 |            5 |                   50.35% / 63.73% |
| `message_type_summaries`         | Queues the messages produced by replication, elections, and nomination, then renders their compact diagnostic labels, including a successful append response.                  |        25 |            8 |                   50.73% / 64.26% |
| `replicate_on_latest_leader`     | Keeps primaries alive in two terms and verifies that `replicate,latest` selects the higher-term leader.                                                                        |         4 |            1 |                   50.79% / 64.32% |
| `swap_single_node`               | Atomically replaces one backup through the singular `swap_node` command and converges the replacement on the committed configuration.                                          |         7 |            3 |                   50.89% / 64.52% |

### Incrementally covered source

- `leadership_race`
  - `raft.h:2772-2778`: the non-leader `nominate_successor()` path.
  - `driver.h:136-143,950-963`: `latest` replication when there is no primary.
  - `driver.cpp:184-188`: the `state_one` scenario command.
- `delayed_vote_requests`
  - `raft.h:1772-1783`: deny a regular vote after a leader is known.
  - `raft.h:1988-1999`: discard a delayed regular-vote response after the node
    has moved into `PreVoteCandidate`.
- `retirement_rollback`
  - `raft.h:2728-2745`: restore `Retired/Ordered` membership to `Active` while
    rolling back an uncommitted retirement.
- `retired_node_delayed_responses`
  - `raft.h:1572-1580`: ignore an append response from a removed peer.
  - `raft.h:1943-1948`: ignore vote responses from a removed peer.
- `large_entry_batching`
  - `raft.h:716-726`: cross the AppendEntries size target, update batching, and
    proactively send the pending entries to followers.
- `message_type_summaries`
  - `driver.h:669-711`: render request-vote, append-entries, proposal, and
    pre-vote request/response diagnostics, including the append ACK branch.
- `replicate_on_latest_leader`
  - `driver.h:952-956`: select the highest-term primary for a `latest`
    replication request when multiple primaries exist.
- `swap_single_node`
  - `driver.cpp:125-128`: parse and execute the singular node-swap command.
  - `kv_types.h:69-71`: compare reconfiguration IDs while applying the atomic
    replacement.

## Remaining gaps

After these scenarios, the focused files still report the following misses:

| File                                    | Missed lines | Missed branch outcomes |
| --------------------------------------- | -----------: | ---------------------: |
| `src/consensus/aft/raft.h`              |          315 |                    355 |
| `src/consensus/aft/test/driver.cpp`     |           49 |                     12 |
| `src/consensus/aft/test/driver.h`       |          244 |                     47 |
| `src/consensus/aft/test/logging_stub.h` |          105 |                      5 |

The remaining gaps fall into these groups:

- **APIs not exposed by the scenario language.** Capacity and signature queries,
  recovery initialisation, commit callbacks, and channel creation live around
  `raft.h:242-304,395-502,582-596,2615-2619,2662-2678,2818-2827`. The driver
  either never calls these APIs or deliberately constructs null/always-ready
  stubs. They need focused C++ unit or node tests rather than scenario files.
- **Negative and malformed input.** Parser errors and failed assertions in
  `driver.cpp:26-50,96-102,158-163,324-326` and
  `driver.h:158-163,211-214,251-254,269-293,1179-1185,1249-1255,1305-1478`
  require the scenario process to fail. Similarly, authentication, malformed
  serialisation, failed sends, and unsupported apply results in
  `raft.h:628-664,809-832,1094-1098,1323-1345,1377-1463` cannot be produced by
  the well-formed channel and store stubs.
- **Defensive protocol states.** `raft.h:1228-1238` is explicitly documented as
  redundant, `raft.h:1289-1304` is a same-term conflict canary, and
  `raft.h:2000-2018` describes an impossible pre-vote response. Empty-config
  election paths and illegal update/commit paths around
  `raft.h:2139-2148,2395-2401,2446-2451,2461-2465,2502-2506,2568-2581,2684-2692`
  likewise violate normal scenario setup or Raft invariants.
- **Ordering not deterministically expressible.** The stale successful ACK path
  at `raft.h:1641-1654` needs two responses from one peer to be delivered out of
  FIFO order. The DSL only offers random shuffling, which would make coverage
  flaky. The missing-payload path at `driver.h:805-823` is a driver artifact;
  its source comment explains that real hosts order AppendEntries before ledger
  truncation, so it is not a plausible CCF network fault.
- **Trace-model limitations.** A stale `ProposeRequestVote` can reach
  `raft.h:2066-2075`, but `ccfraft.tla:1311-1317` only models a proposal whose
  term equals the receiver's current term. A signed-retirement rollback can
  reach `raft.h:2719-2723`, but `Traceccfraft.tla:395-406` treats
  `execute_append_entries_sync` as leaving model variables unchanged. Scenarios
  for both implementation paths ran successfully but failed trace validation,
  so the trace model must be extended before those cases can join this suite.
- **Deprecated, random, or failure-only driver commands.** The old `nodes`,
  `create_new_node`, and `replicate_new_configuration` setup paths are
  intentionally avoided. The `shuffle_one` and `shuffle_all` commands are
  nondeterministic, while invalid-command and failed-assertion branches cannot
  belong to a passing scenario suite.
- **Coverage instrumentation artifacts.** Many residual branch outcomes occur
  inside logging macro expansions rather than distinct Raft decisions. Also,
  2,533 missed lines and 123 missed branch outcomes belong to linked crypto,
  task, formatting, and support sources outside the four focused files. Those
  require their own unit tests and are not addressable through Raft scenarios.
