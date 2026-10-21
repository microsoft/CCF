# Trace replay

Protocol validation is entirely Lean, following [DisasterRecovery's records, reduction and direct replay](../../disaster-recovery/replayer/README.md):

```text
raft_driver records -(CCFRaft/Replay/Records.lean)-> validated records
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
lake build --wfail ccfraft-replay replay-checks
lake exe ccfraft-replay capture.stdout
lake exe ccfraft-replay events.ndjson
cmake -S ../.. -B /tmp/ccf-raft-build -GNinja
cmake --build /tmp/ccf-raft-build --target raft_driver
python3 ../../tests/raft_trace_capture.py /tmp/ccf-raft-build/raft_driver ../../tests/raft_scenarios /tmp/ccf-raft-captures
lake exe ccfraft-replay suite --raw-directory /tmp/ccf-raft-captures --output /tmp/ccf-raft-results
lake exe replay-checks --no-cleanup
lake exe replay-checks
```

The collector needs the `msgpack` dependency from `tests/requirements.txt` in the active Python environment.
The removed `CCF_RAFT_TRACING` switch no longer enables stdout tracing.
The current collector connects the driver's Fluentd endpoint on loopback and writes the original `process_id`, `h_ts` and `msg` records as NDJSON, retaining native stdout/stderr bytes in `.driver.stdout` and `.driver.stderr` files even when they contain invalid UTF-8.
This includes every native `operation_boundary` record, without synthesizing either endpoint.
It uses the existing MessagePack transport helper, not a Python protocol reducer; it never sorts or edits events to make a replay succeed.
Subprocess, transport, decoding and sequence failures preserve received records under `.partial`, never as successful replay inputs.
Unsupported values that cannot be encoded as JSON also retain the decoded records unchanged in `.driver.records.msgpack`; they are rejected, not converted into supported protocol data.
The shared `run_driver` helper still returns text stdout/stderr on success; its `CaptureError` carries binary stdout/stderr and received records on failure.
The legacy `suite --driver PATH` option remains for executables that already emit trace NDJSON on stdout, including the regression fake driver; it is not the current native driver's interface.
`suite` selects every regular file under `../../tests/raft_scenarios`, recursively and sorted, matching `tests/raft_scenarios_runner.py`.
Use `--scenarios DIR` to select another inventory and `--timeout-ms N` to change the positive per-capture timeout from 120000 milliseconds.
For legacy `--driver` capture, this single deadline includes process exit and draining both pipes, even when descendants retain them.
Each capture owns a new process group and terminates that group on timeout before joining its readers.
A capture failure, nonempty driver stderr, malformed or unsupported event, disabled action, impossible delivery or observation mismatch fails that scenario.
The runner attempts every scenario, writes raw `<scenario>.stdout` and `.stderr` unchanged plus `.result.json` and `summary.json`, and exits nonzero if any scenario failed.
It resolves and validates that the output and scenario inventory trees are disjoint before creating directories or removing any previous summary.
Neither directory may contain the other, since mirrored output paths could otherwise overwrite scenarios.
Missing output directories are created automatically after this check; dangling symlinks, inaccessible paths and unresolved parent traversals fail without cleanup.
Only after validating this separation does it remove the previous summary, so an empty inventory or interruption cannot leave a stale success at a safe output location.
`replay-checks --no-cleanup` runs the parser, reduction, boundary, direct-model, identity and transport regressions without the temporary capture/suite tests or their filesystem cleanup.

The separate legacy TLA adapter, `tests/raft_trace.py::as_log_lines`, omits only `operation_boundary` records because they are observations, not TLA protocol steps.
The Lean collector does not use that adapter.

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
Current `ccf.raft_trace` envelopes must have one process identity and contiguous sequence numbers starting at zero; mixed legacy/current records, missing, repeated or reordered sequences fail.
Lean converts only the current structural layout (`commit.idx` and flat `add_configuration` fields) to the named reducer's fields; their values and raw source records are retained unchanged.

The named branches of `reduce` in `Reduction.lean` consume every event:

| Source event                                                      | Model action and checks                                                                                                            |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Native bootstrap operation and first signature                    | Audit constructor/genesis alignment and the existing five callbacks; check the genuine genesis POST before appending the signature |
| `replicate`                                                       | One nonempty `append`, with its configuration hooks, new-peer heartbeats and internal commit                                       |
| `send_append_entries` outside a callback group                    | `sendEntries(destination, endIndex)`; check the recorded `sent_idx` against `prev_idx`                                             |
| `recv_*`                                                          | Observation-selected delivery, with term adoption, synchronous promotions, commits and response observations in the same action    |
| `become_candidate`, `become_pre_vote_candidate` outside a receive | Election timeout with nested self-quorum promotions, complete ordered request loop and leadership heartbeats                       |
| `become_follower` outside a receive                               | Check-quorum timeout                                                                                                               |
| `step_down_and_nominate_successor` outside a commit               | Nullary `nominateSuccessor`, only under a `nominate_successor` command; observe the model-chosen destination                       |
| `drop_pending_to`                                                 | Check and exclude one FIFO queue-head occurrence without stepping the model                                                        |

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
Model node IDs are lexical ordinals in the distinct sorted declared-name list, never numeric interpretations of textual names.
The initial membership contains the bootstrap node's ordinal; its minimum starts as primary even when earlier lexical nodes exist elsewhere in the population.
Request ID zero is reserved for genesis; other IDs map injectively to transaction source locations, which remain available in entry observations.
Adjacent callbacks do not establish a general multi-entry production batch boundary; replaying such calls needs additional trace evidence.

`raft.h` traces `replicate`, `add_configuration`, `execute_append_entries_sync`, `commit` and sends before their mutations, whereas role-change events trace after changing role.
Every post-initialization chunk requires an observed native PRE equal to the model's pre-state projection, the existing reduced actions executed through unchanged `Model.transitionSystem.step`, and an observed native POST equal to the model's resulting projection.
Neither side is optional.
The reduction is not a one-to-one callback history: one native periodic call can reduce to several sends and a check-quorum timeout, and one append can include proactive sends.
A call with no protocol callbacks still has both snapshots and checks a projected stutter.

[`RaftDriver`](../../../src/consensus/aft/test/driver.h) emits `operation_boundary` records with `operation_id`, `operation`, `phase`, `state`, `configurations` and `peers`.
Snapshots read actual native state, configurations and peer indices under the consensus lock.
The globally increasing operation ID starts at zero; PRE precedes the callbacks and its matching POST follows them.
Lean requires a nonnested pair with the same ID, operation, node and command context, and requires every protocol event to lie inside a pair.
Missing, duplicate, misassociated or reordered boundaries fail explicitly, independently of the transport sequence check.
Old captures without these records are unsupported, not successful under a weaker equivalence contract.

| Native operation | Recorded boundary                                                                                                                             |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `bootstrap`      | After constructing the start node and before forcing leadership, then after replicating the genesis configuration                             |
| `replicate`      | Immediately before the singleton native `replicate` call, then after its hooks, append, optional sends, commit, retirement and pruning finish |
| `receive`        | Before and after the dispatched `recv_message`, including ignored messages and receives with no terminal response callback                    |
| `periodic`       | Before and after `periodic`, including pre-timeout role, post-send peer progress and check-quorum changes                                     |
| `nominate`       | Before and after the explicit nomination call, including calls without a successor                                                            |
| `drop`           | Before and after recording one explicitly dropped packet; only node state, not native queue enumeration, is projected                         |

The boundary projection is fixed, with no value-dependent exemptions:

| Native evidence                                                           | Model projection checked on both sides                                                                                                              |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Leadership, term, last index, commit index                                | Role, current term, log length and commit index                                                                                                     |
| Membership/retirement phase and all three optional retirement coordinates | Ledger-derived membership phase, removal index, first covering signature index and committed confirmation transaction index; absence is checked too |
| Fixed `pre_vote_enabled`                                                  | The node's creation-time declaration                                                                                                                |
| Complete `committable_indices`                                            | Exactly all signature positions above the model commit frontier, not just a positive subset or the cache's extrema                                  |
| Complete configuration cache                                              | Exactly the last committed configuration and pending configurations, with lexical member names and transaction indices                              |
| Complete raw peer table                                                   | The named `leaderActivePeerProgress` quotient below                                                                                                 |

`leaderActivePeerProgress` contains every other member of the active configuration union while the node is leader, with exact `sentIndex` and `matchIndex`.
The raw peer table must be sorted, unique and cover every active peer; a missing peer is not silently omitted.
Both native and model projections discard unused nonleader progress and progress for retained peers outside the active configuration union.
This fixed quotient accommodates follower constructor sentinels and CCF's retained rollback/retirement peers; it never selects peers by whether their indices match.
Internal new-peer heartbeat observations retain their existing, separately named next-index adjustment.

This is equality of the stated projection, not equality of the entire `NodeState`, ledger contents or network.
Votes, follower flags, clocks, store state and native queue enumeration are not in the boundary projection; existing model guards, entry evidence and packet accounting constrain their relevant effects separately.
No application-content or complete native send-enumeration claim is added.

Initialization is explicit rather than a fabricated model action.
The bootstrap PRE is audited against the native constructor's empty log/cache, no role, term zero, absent retirement coordinates and fixed pre-vote declaration.
The existing forced-leader/genesis/signature/commit prelude and singleton genesis argument are still audited.
The genuine genesis POST must match `Model.initialNodeState` before the first signature action; the signature itself then has both required external checks.
No model output or commit target supplies an observed POST.

Existing internal phase checks are supplemental, never substitutes for these external boundaries.
For a timeout's first pre-vote callback, the role is already assigned while the other fields still describe the pre-state.
Earlier nested candidate and term-adoption snapshots are internal, not additional model states.
Their unused values may differ without invalidating matching external endpoints; schema checks, fixed pre-vote declarations and facts used by the existing action/group recognizer still apply.
Each internal field exclusion retains its raw value and fixed phase reason in its instruction origin.

Internal committable-index evidence remains a positive signature check because callbacks can precede cache insertion or pruning.
External boundary caches, by contrast, are compared completely.
Configuration caches within a receive are checked against log-entry configurations, and a positive callback commit frontier must already point to a committed signature.
Present retirement indices remain checked even when later callbacks may set an index that was absent.
Follower delivery commits at each newly applied signature and once at the end, preserving the first frontier covering its retirement record while allowing a later final commit index.
Replay still executes this as one model delivery and checks callback evidence against the resulting log and state; it does not insert intermediate commit actions.
The model's `noRetirementObserved` membership phase maps to the trace's `active` label, including declared nodes that have not yet joined.

New-peer configuration heartbeats belong to the append and use the constructor's next-index sentinel, one past the model's sent frontier.
Ordinary sends do not use this adjustment.
Vote and pre-vote responses share `send_request_vote_response`; `packet.msg` distinguishes them, and each supplied response snapshot and packet is checked after its receive.
A `become_follower` that ends a receive checks its full snapshot after the action, including unchanged log, cache and retirement facts.
When later response or promotion callbacks follow it, that adoption snapshot is internal and is not compared to either endpoint.
Lower-term NACK hints remain log terms, not new election terms.
A higher-term nomination is consumed without adopting its term or forcing an election.

Commits and promotions are never standalone model actions.
`become_leader` may commit and heartbeat synchronously.
Terminal retirement nominates inside its committing action, using the precommit eligible peers and configurations before pruning and clearing leadership.
The reducer audits the raw leader/completed-retirement snapshot and observes the proposal rather than substituting its destination into the action.
Its configuration cache must equal the checked pre-pruning commit cache.
The model selects the maximum acknowledged index, latest containing active configuration index, then lexical node ID; `"2"` ranks above `"10"`.

The leader commit snapshot records the old frontier, not the post-commit state.
Before the action, replay checks its old `commitIndex` against the enclosing pre-state and observes its old confirmation index.
After the action, `stateBeforeCommit` compares the recorded post-append log and its retirement/configuration projections at that independently checked old frontier.
This read-only view uses the final log, the old frontier, and confirmation transactions in that committed prefix; it does not execute an intermediate action or modify model state.
The role is checked at its named leader phase rather than compared to a potentially cleared final role.
The commit target must advance the old frontier and equal the model effect, but is not presented as a native post-state observation.
The separate required operation POST observes the actual advanced frontier, final role and retirement phase, pruned cache and peer progress.

`preVoteEnabled` checks the fixed driver configuration, not a mutable model field.
Timeout elections with pre-vote disabled are explicitly unsupported; same-term nominations retain their direct-election behavior.
No synthetic nominations or mode toggle are inserted into the model.

The model's `retiredCommittedIndex` is the confirmation transaction's index, not the covering signature's index.
The native test stub's [`LoggingStubStoreConfig::compact`](../../../src/consensus/aft/test/logging_stub.h) passes the stored transaction version, matching production [`on_nodes_global_commit`](../../../src/node/node_state.h), and consumes every processed hook entry, including one exactly at the compact frontier.
For a confirmation transaction at index 5 covered by a signature at index 6, the hook reports 5, not 6.
The retained `terminal_retirement.stdout` records the old stub's incorrect compact-frontier index and lacks the new boundaries.
It remains unmodified historical negative evidence and is rejected as unsupported, not repaired with invented endpoints.
Fresh native retirement fixtures record transaction index 5, and an independent raw POST mutation to 6 must fail the boundary comparison.

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
It runs freshly captured bootstrap, startup, vote-response, missing-prefix, configuration, drop/resend, nomination and follower-retirement fixtures, checks instruction consumption, mutates every projected observation field, and exercises raw callback/packet mutations, malformed and unsupported records, disabled actions, missing packets, wrong drop heads and repeated/drop message occurrences.
Independent typed raw PRE and POST mutations cover scalar state, retirement absence, complete caches and peer progress, with missing/pairing/order negatives and legitimate ignored-internal-detail positives.
[`tests/refresh_fixtures.py`](tests/refresh_fixtures.py) refreshes positive fixtures from actual native captures and complete operation prefixes, retaining raw lines and recording origin hashes; it never generates endpoint values or rewrites the historical terminal fixture.
Receive regressions deliver a later heartbeat before an earlier data packet, require the NACK and retention of the earlier packet, reject unavailable and ambiguous selectors, and preserve equal-copy multiplicity.
Focused cases cover the relaxed send-telemetry semantics, transaction metadata, undeclared metadata members, and rejected duplicate configuration callbacks and cache indices.
Independent typed raw boundary mutations cover commit frontiers and stable fields, leadership heartbeats, receive pre/post states, terminal adoption, timeout phases and bootstrap initialization.
Paired positives deliberately change unused internal candidate, follower-adoption and genesis details while keeping the chosen endpoints fixed.
`self_quorum.stdout` is a fresh native `reconfig_0_1` capture from the corrected test stub, including the required endpoints.
The test executable doubles as a deterministic fake driver for capture byte preservation, timeout/nonzero-exit/stderr failures, recursive inventory, invalid encoding, missing captures and stale-summary removal.
Neither it nor the replayer imports proof modules.
Identity/init regressions cover lexical ordinals, a nonzero bootstrap ordinal, population preservation, genesis, undeclared IDs and duplicate request provenance.
Current-envelope regressions cover sequence gaps, reordering, process identity, field-layout decoding and explicit disabled-mode rejection.
The native scenarios use pre-vote for timeout elections, including delayed nomination, partial-prefix overcommit, stale leaders and competing signed suffixes.
`soft_rollback` uses five nodes so a short-log candidate obtains a genuine pre-vote quorum before its higher-term vote request reaches a node with an unsigned suffix.
`retire_backup` checks that a removed node cannot inflate the term or depose the leader, then learns its retirement through ordinary prefix repair.
These migrations retain the disabled-mode rejection boundary; they do not synthesize nominations or introduce a model toggle.
`python3 tests/raft_trace_capture_test.py` from the repository root exercises transport ordering, duplicate keys, unchanged records and stale-success removal.
Replay-only builds do not replace the separately integrated proof build and kernel checks.
Successful replay witnesses a finite model execution compatible with these observations, not universal production inclusion, infinite extension, fairness or liveness.

## Kernel checks

Run `lake check` only in CI, not locally.
The [Lean workflow](../../../.github/workflows/lean.yml) exports/checks `CCFRaft`, `ccfraft-replay` and `replay-checks` separately because the executable roots have distinct `main` declarations.
Local builds and regressions are separate evidence, not a kernel-check pass.
The CI checks allow only `propext`, `Classical.choice` and `Quot.sound`.
They run without build sandboxing, so configuration and build code must be trusted.
