# Trace replay

The production path is entirely Lean, following [DisasterRecovery's records, reduction and direct replay](../../disaster-recovery/replayer/README.md):

```text
raft_driver stdout -(CCFRaft/Replay/Records.lean)-> validated records
                   -(CCFRaft/Replay/Reduction.lean)-> actions and observations
                   -(CCFRaft/Replay.lean)-> model execution or discrepancy
```

`CCFRaft/Replay/Suite.lean` captures and checks the inventory; `ReplayMain.lean` is the command-line entry point.
Unlike DisasterRecovery's independent node logs, the single-threaded driver already records one global order, so there is no commit-order reconstruction, delivery search, or wait for growing logs.
Instructions are Lean values, not a second JSON schema.
The old Python reducer, harness and JSON replay input are retired.

## Commands

Run from `lean/ccf-raft`:

```sh
lake build --wfail ccfraft-replay replay-checks canonical-checks
lake exe ccfraft-replay capture.stdout
lake exe ccfraft-replay events.ndjson
lake exe ccfraft-replay suite --driver ../../build/raft_driver --output ../../build/raft-replay
lake exe replay-checks
lake exe canonical-checks
```

Build the driver with `CCF_RAFT_TRACING=ON`, as described in the [package README](../README.md#trace-validation).
`suite` selects every regular file under `../../tests/raft_scenarios`, recursively and sorted, matching `tests/raft_scenarios_runner.py`.
Use `--scenarios DIR` to select another inventory and `--timeout-ms N` to change the positive per-capture timeout from 120000 milliseconds.
A capture failure, nonempty driver stderr, malformed or unsupported event, disabled action, impossible delivery or observation mismatch fails that scenario.
The runner attempts every scenario, writes raw `<scenario>.stdout` and `.stderr` unchanged plus `.result.json` and `summary.json`, and exits nonzero if any scenario failed.
It removes the previous summary before validating the inventory, so an empty inventory or interruption cannot leave a stale success.
The output directory must be outside the scenario inventory.

`--raw-directory DIR` instead of `--driver PATH` checks existing `<scenario>.stdout` captures.
Missing captures and invalid UTF-8 are per-scenario failures, not skips or reasons to stop checking the rest.
Reusing captures does not validate a changed implementation.
Single-trace success prints JSON counts of every consumed instruction, action and observation; failure reports the original input line, C++ function and location when supplied, command, and reduction rule.

## Records and rules

NDJSON contains only command and Raft event objects.
Captured `.stdout` additionally allows `<RaftDriver>` diagram lines and well-formed ordinary logger records.
Blank, malformed and unknown output lines fail rather than being filtered.
JSON duplicate keys, including escaped equivalent spellings, fail before object construction can erase them.
Event names, fields, state fields, packet families and coordinates are checked in `Records.lean`; unsupported extensions cannot silently disappear from observations.
Timestamps do not influence order.
Creation commands declare fixed pre-vote modes even for future nodes that have not emitted any Raft event.

The named branches of `reduce` in `Reduction.lean` consume every event:

| Source event                                                      | Model action and checks                                                                                                         |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Exact five-event bootstrap                                        | Audit the preloaded singleton configuration, append the bootstrap signature, observe its internal commit                        |
| `replicate`                                                       | One nonempty `append`, with its configuration hooks, new-peer heartbeats and internal commit                                    |
| `send_append_entries` outside a callback group                    | `sendEntries(destination, endIndex)`; check the recorded `sent_idx` against `prev_idx`                                          |
| `recv_*`                                                          | Observation-selected delivery, with term adoption, synchronous promotions, commits and response observations in the same action |
| `become_candidate`, `become_pre_vote_candidate` outside a receive | Election timeout with nested self-quorum promotions, complete ordered request loop and leadership heartbeats                    |
| `become_follower` outside a receive                               | Check-quorum timeout                                                                                                            |
| `step_down_and_nominate_successor` outside a commit               | Nullary `nominateSuccessor`, only under a `nominate_successor` command; observe the model-chosen destination                    |
| `drop_pending_to`                                                 | Check and exclude one FIFO queue-head occurrence without stepping the model                                                     |

Commands alone do not invent protocol actions.
Shuffled queues (`shuffle_one`, `shuffle_all`), ungrouped callbacks, missing required group members and invalid group order are rejected.
Each transaction carries at most one configuration in its `TransactionMetadata`.
Multiple configuration callbacks for one append and duplicate configuration-cache indices are rejected, not collapsed into one configuration or split into invented model actions.
The model and its guards are unchanged.

## Atomic boundaries and observations

`RaftDriver::_replicate` in `src/consensus/aft/test/driver.h` passes a singleton `BatchVector`, so each `replicate` event is one append action.
A globally committable entry is a signature; another entry is a transaction identified by its source `file:line`.
Configuration callbacks supply the optional configuration metadata, and `cleanup_nodes` supplies its retired-committed node set.
The preloaded bootstrap configuration has the empty transaction identifier.
Adjacent callbacks do not establish a general multi-entry production batch boundary; replaying such calls needs additional trace evidence.

`raft.h` traces `replicate`, `add_configuration`, `execute_append_entries_sync`, `commit` and sends before their mutations, whereas role-change events trace after changing role.
The reducer checks stable fields and log-entry evidence across an atomic action, not intermediate callback snapshots as if they were separate model states.
Every intentional omitted transient field retains its raw value and a reason in the instruction's origin; every other supplied property is observed by default.
Committable indices are a partial cache: each recorded index must point to a signature, but an absent index asserts nothing.
Configuration caches within a receive are checked against log-entry configurations, and a positive callback commit frontier must already point to a committed signature.
Present retirement indices remain checked even when later callbacks may set an index that was absent.
Follower delivery commits at each newly applied signature and once at the end, preserving the first frontier covering its retirement record while allowing a later final commit index.
Replay still executes this as one model delivery and checks callback evidence against the resulting log and state; it does not insert intermediate commit actions.
The model's `noRetirementObserved` membership phase maps to the trace's `active` label, including declared nodes that have not yet joined.

New-peer configuration heartbeats belong to the append and use the constructor's next-index sentinel, one past the model's sent frontier.
Ordinary sends do not use this adjustment.
Vote and pre-vote responses share `send_request_vote_response`; `packet.msg` distinguishes them, and each supplied response snapshot and packet is checked after its receive.
A `become_follower` inside a receive checks only role and term after the atomic receive; other fields can change later in that same operation.
Lower-term NACK hints remain log terms, not new election terms.
A higher-term nomination is consumed without adopting its term or forcing an election.

Commits and promotions are never standalone model actions.
`become_leader` may commit and heartbeat synchronously.
Terminal retirement nominates inside its committing action, using the precommit eligible peers and configurations before pruning and clearing leadership.
The reducer audits the raw leader/completed-retirement snapshot and observes the proposal rather than substituting its destination into the action.
The model selects the maximum acknowledged index, latest containing active configuration index, then lexical node ID; `"2"` ranks above `"10"`.

## Packet accounting

The model's network is an unordered multiset, and remains so.
The replayer preserves recorded event order, but does not impose send order on receives.
A receive selects a live model envelope with the recorded source, destination and packet fields, even if an earlier envelope remains pending on that pair.
The receive observation and action use the same selector; unavailable or mismatching packets fail explicitly before delivery, without searching for a different execution or discarding earlier packets.
A drop excludes exactly one occurrence from future observations and deliveries, but leaves it undelivered in the model network.
Equal envelopes retain their multiplicity.
Explicit driver drops still check and exclude the queue head for that directed pair.

Equal full model envelopes are interchangeable occurrences.
If different full model envelopes match the same recorded fields, replay fails with an ambiguous-packet diagnostic rather than guessing unobserved payload contents.
This conservative rejection can exclude otherwise admissible traces; replay does not backtrack over alternative payloads.
Packet headers do not encode physical nonces or channel epochs, and reconnect commands do not reset replay queues or invent drops.
Native authentication losses and channel-buffer replacement are not reconstructed; an unreceived envelope may simply remain pending.

Send telemetry is deliberately **not** required to enumerate every model emission exactly once.
A send observation checks compatibility with the latest pending packet for its endpoints; it neither creates nor consumes a packet.
Repeated observations may check the same occurrence, unobserved emissions may remain pending between actions or at EOF, and omitted optional response-send telemetry does not itself fail replay.
Actual delivery still requires a live compatible model packet and an enabled transition.
This relaxation checks observations and delivery feasibility, not completeness or exactly-once correspondence of implementation sends.
It does not relax record parsing, source callback ordering, action guards or state observations.

## Regression coverage

`replay/tests/Main.lean` replaces the old Python regression suite.
It runs the retained bootstrap, startup, vote-response, missing-prefix, configuration, drop/resend and retirement fixtures, checks instruction consumption, mutates every projected observation field, and exercises raw callback/packet mutations, malformed and unsupported records, disabled actions, missing packets, wrong drop heads and repeated/drop message occurrences.
Receive regressions deliver a later heartbeat before an earlier data packet, require the NACK and retention of the earlier packet, reject unavailable and ambiguous selectors, and preserve equal-copy multiplicity.
Focused cases cover the relaxed send-telemetry semantics, transaction metadata, undeclared metadata members, and rejected duplicate configuration callbacks and cache indices.
The test executable doubles as a deterministic fake driver for capture byte preservation, timeout/nonzero-exit/stderr failures, recursive inventory, invalid encoding, missing captures and stale-summary removal.
Neither it nor the replayer imports proof modules.
The combined package still includes every model/proof import and required proof checks; replay-only builds do not replace the full proof build and kernel checks.
