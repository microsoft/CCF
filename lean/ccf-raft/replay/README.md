# Trace replay

Protocol validation is entirely Lean, following [DisasterRecovery's records, reduction and direct replay](../../disaster-recovery/replayer/README.md):

```text
Python capture -> JSON trace
JSON trace -(CCFRaft/Replay/Records.lean)-> Events
           -(CCFRaft/Replay/Reduction.lean)-> actions and observations
           -(CCFRaft/Replay.lean)-> model execution or discrepancy
```

[`tests/raft_trace_capture.py`](../../../tests/raft_trace_capture.py) owns capture, process lifecycle, scenario inventory and suite results, using the existing Python trace transport helper.
Lean starts at a JSON trace; `ReplayMain.lean` accepts exactly one trace path.
`CCFRaft/Replay/Replayer.lean` orchestrates record preparation, reduction and model replay, including node/request identity tables and bootstrap initialization.
Unlike DisasterRecovery's independent node logs, the single-threaded driver already records one global order, so there is no commit-order reconstruction, delivery search, or wait for growing logs.
`Instruction` has only `action` and `observe` constructors, each carrying its trace location and reduction rule.
An observation is a read-only `ReplayState -> Except String Unit` function that captures expected values and stable identities.
The interpreter executes an action through the model, or runs an observation and returns the unchanged state.
Instructions are Lean values, not a second JSON schema or a serialized observation language.
The old Python reducer, harness and JSON replay input are retired.

## Commands

Run from `lean/ccf-raft`:

```sh
lake build --wfail ccfraft-replay replay-checks
lake exe ccfraft-replay capture.stdout
lake exe ccfraft-replay events.ndjson
cmake -S ../.. -B /tmp/ccf-raft-build -GNinja
cmake --build /tmp/ccf-raft-build --target raft_driver
python3 ../../tests/raft_trace_capture.py ../../tests/raft_scenarios /tmp/ccf-raft-captures \
  --driver /tmp/ccf-raft-build/raft_driver --replayer .lake/build/bin/ccfraft-replay
python3 ../../tests/raft_trace_capture.py ../../tests/raft_scenarios /tmp/ccf-raft-results \
  --raw-directory /tmp/ccf-raft-captures --replayer .lake/build/bin/ccfraft-replay
lake exe replay-checks
```

The collector needs the `msgpack` dependency from `tests/requirements.txt` in the active Python environment.
The removed `CCF_RAFT_TRACING` switch no longer enables stdout tracing.
The current collector connects the driver's Fluentd endpoint on loopback and writes the original `process_id`, `h_ts` and `msg` records as NDJSON, retaining native stdout/stderr bytes in `.driver.stdout` and `.driver.stderr` files even when they contain invalid UTF-8.
It uses the existing MessagePack transport helper, not a Python protocol reducer; it never sorts or edits events to make a replay succeed.
Subprocess, transport, decoding and sequence failures preserve received records under `.partial`, never as successful replay inputs.
Unsupported values that cannot be encoded as JSON also retain the decoded records unchanged in `.driver.records.msgpack`; they are rejected, not converted into supported protocol data.
The collector requests binary stdout/stderr from the shared `run_driver` helper, so console encoding does not constrain structured replay records.
Other consumers retain the helper's default text output; its `CaptureError` carries binary stdout/stderr and received records on failure.
The Python runner selects every regular file under its scenario directory, recursively and sorted, matching `tests/raft_scenarios_runner.py`.
Omit `--replayer` with `--driver` for capture only; use `--raw-directory` with `--replayer` to check existing captures without launching a driver.
Use `--timeout N` to change the positive, finite subprocess timeout from 60 seconds.
Capture and replay use the standard Python subprocess infrastructure; there is no Lean process launcher or suite mode.
A capture failure, malformed or unsupported event, disabled action, impossible delivery or observation mismatch fails that scenario.
Successful drivers may write diagnostics to stderr; these are preserved and their location is reported, without treating warnings as protocol failures.
The runner attempts every scenario, retains JSON traces as `<scenario>.stdout`, and writes `.result.json` and `summary.json`, with capture/replay failure stages and a nonzero exit if any scenario failed.
Native console bytes remain in the separate `.driver.stdout` and `.driver.stderr` evidence files.
It resolves and validates that the output and scenario inventory trees are disjoint before creating directories or removing any previous summary.
Neither directory may contain the other, since mirrored output paths could otherwise overwrite scenarios.
Missing output directories are created automatically after this check.
Only after validating this separation does it remove the previous summary, so an empty inventory or interruption cannot leave a stale success at a safe output location.
`replay-checks` runs parser, reduction, observation, direct-model, identity and transport regressions; capture and suite tests live in Python.

The separate legacy TLA adapter, `tests/raft_trace.py::as_log_lines`, changes the record layout while preserving event order.
It supplies the TLA consumer's `pre_vote_enabled: true` field in copied snapshots, reflecting the native implementation's unconditional pre-vote without modifying captured records.
The Lean collector does not use that adapter.

`--raw-directory DIR` instead of `--driver PATH` checks existing `<scenario>.stdout` captures.
Missing captures and invalid UTF-8 are per-scenario failures, not skips or reasons to stop checking the rest.
Reusing captures does not validate a changed implementation.
Single-trace success prints JSON counts of every consumed instruction, action and observation.
An observation failure reports the instruction position, original trace file and line, reduction rule, and expected/actual discrepancy.
Additional native function, command and implementation metadata remains in the original trace rather than being copied into each instruction.

## Records and rules

NDJSON contains only current Fluentd `ccf.raft_trace` envelopes, each retaining `process_id`, `h_ts` and `msg`.
Commands use `msg.cmd`; events use `msg.function`, with flat `msg.idx` for commits and flat `msg.idx`, `msg.rid`, `msg.nodes` and `msg.configurations` for configuration events.
Legacy `raft_trace` records and their nested `args` layout are unsupported.
Every input is NDJSON regardless of its filename extension; `.stdout` is the collector's existing JSON trace naming convention, not mixed console output.
Blank, malformed JSON and non-JSON output lines fail rather than being filtered.
Records use ordinary Lean JSON parsing, including its duplicate-key coalescing; there is no separate schema validator or lexical duplicate-key scan.
Projection, reduction and replay read the fields they use with fallible accessors and preserve source locations on failure.
Unrelated envelope, event, state and configuration metadata is ignored.
Configuration membership uses node names, not address metadata or the unused `rid` field.
Packet fields passed to replay remain observations and are checked against model-generated packets, rather than a separate packet schema.
Records are never sorted by timestamp.
Creation commands declare node identities even for future nodes that have not emitted any Raft event.
Other command names are provenance, not a whitelist or independent model actions; an unrecognized Event still fails reduction.
Timeout elections always use pre-vote in both native Raft and the model; there is no per-node mode flag or driver toggle.
Envelopes must have one process identity and contiguous sequence numbers starting at zero; missing, repeated or reordered sequences fail.
The reducer reads native message fields directly, without manufacturing a compatibility representation.
Event projection retains the original command and event envelopes for provenance.

`Reduction.lean` parses the ordered native event stream with [`CCF.Parsec`](../../common/README.md#event-parsing), the common package's generic event-array adapter and stateful combinators over Lean's `Std.Internal.Parsec`.
Its rules live in `CCFRaft.Replay.Reducer`; `Reducer.reduce` accepts prepared Events and identity tables and returns the bootstrap leader and emitted instructions.
It does not normalize records, discover identities, construct the replay header or execute the model.
`CCF.Parsec.ParserT Event ReductionState` keeps parser position separate from the header and accumulated instructions without requiring equality on JSON events.
Named reduction alternatives use `attempt`: a failed constrained pattern restores both input position and accumulated instructions before another alternative is tried.
Optional and repeated subrules also use transactional attempts.
Events must match the expected node and protocol fields; grouping does not depend on driver-command context.
An unmatched or malformed Event still rejects the complete trace through the leftover-Event check rather than disappearing.
When a speculative pattern consumed Events before failing, its farthest diagnostic survives rollback and is reported if no successful interpretation reaches that position.
Each grammar names its local recognizers with `let subrule := event "event_name" fun e => ...`, auditing only that event with `checked` and `read`.
`checked` establishes grouping, supported native phases or action-construction constraints; model compatibility belongs in observations emitted by the rule.
Its consumption phase binds ordinary values in trace order; its emission phase explicitly produces actions and observations from that evidence.
Larger content-preparation and subgrammar blocks are defined locally in the rule header, keeping the consumption section focused on sequencing.
Shared commit, promotion and election evidence has parse-only grammars and separate emission helpers, so optional or repeated recognizers never emit instructions while matching.
The top-level grammar is bootstrap followed by `many_ reductionRules`, then a single leftover-event check that requires the input to be exhausted.
Each rule explicitly emits its head Event's pre-action observation with a rule-specific tag before emitting its action.
There is no trailing observation or invented snapshot at end of input.
The state-threading `many` bridge attempts each repeated pattern and accumulates instructions directly, without reparsing individual chunks or flattening separately initialized output batches.
The same common combinators handle optional rules and repetitions; each repeated grammar must consume an event before succeeding.
Leadership-heartbeat recognition checks empty-packet coordinates and consumes at most one send per distinct destination, without requiring coverage of every active peer.
State and packet observations check the term and destination during replay.
Retired peers can also receive promotion heartbeats even though they are absent from active configurations.
A subsequent send to an already observed destination remains available as an ordinary send action.
The declared population bounds the loop; no driver-command fence is used.
Append, receive, tick, send, nomination and drop are named alternatives.
The receive grammar is an explicit choice between independently defined message families:

```lean
ruleRecvAppendEntries
<|> ruleRecvProposeRequestVote
<|> ruleRecvRequestVote
<|> ruleRecvRequestVoteResponse
<|> ruleRecvAppendEntriesResponse
```

Each family consumes its head and synchronous events, then explicitly calls `emitAction` for its receive before emitting any event's `emitObserve`, `emitObserveEntry` or `emitObservePacket`.
The parser produces instructions; it does not execute the model while parsing.
Parsed evidence is local to its grammar, not a later whole-trace observation pass or a list of future events used to choose which state fields to compare.
The receive action retains the head's origin; each event's observations retain that event's origin.
Every instruction carries exactly one origin, enforced by its type rather than a runtime check on an origin list.
The packet is a value carried from the parsed head, not a separate binding instruction.
Candidate/leader promotion, commit/retirement nomination, configuration hooks and new-peer heartbeats are separate composable rules rather than mutations of a dispatcher accumulator.
AppendEntries composes repeated execution/configuration/commit events followed by an optional response; it permits zero execution events for empty heartbeats and NACKs rather than requiring `many1` unconditionally.
The central leftover-event check rejects unconsumed events with their source location and name.
Commands with no events do not invent actions or observations.
Bootstrap consumes only the forced-leader and singleton genesis events, so the signature is still replayed normally.
Optional Events match their name, source node and rule-specific protocol constraints; a failed match leaves them for the next reduction rule.
Follower-transition recognition checks whether the received packet's family, term and receiver's pre-state permit adoption, including same-term AppendEntries demotion of candidates.
An ignored same-term vote response therefore cannot absorb a later check-quorum transition.
Recognized follower Events contribute a term observation after the receive action; response-peer eligibility remains enforced by the unchanged model rather than inferred from an incomplete native peer snapshot.

The named operation rules consume every event:

| Source event                                                      | Model action and checks                                                                                         |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Forced-leader and genesis events                                  | Audit initial leadership and singleton genesis arguments against the preloaded model initialization             |
| `replicate`                                                       | One nonempty `append`, with its configuration hooks, new-peer heartbeats and internal commit                    |
| `send_append_entries` outside a event group                       | `sendEntries(destination, endIndex)`; check the recorded `sent_idx` against `prev_idx`                          |
| `recv_*`                                                          | FIFO delivery, with term adoption, synchronous promotions, commits and response observations in the same action |
| `become_candidate`, `become_pre_vote_candidate` outside a receive | Election timeout with nested self-quorum promotions, request observations and leadership heartbeats             |
| `become_follower` outside a receive                               | Check-quorum timeout                                                                                            |
| `step_down_and_nominate_successor` outside a commit               | Nullary `nominateSuccessor`, only under a `nominate_successor` command; observe the model-chosen destination    |
| `drop_pending_to`                                                 | Check and exclude one FIFO queue-head occurrence without stepping the model                                     |

Commands alone do not invent protocol actions.
Out-of-order deliveries, ungrouped events, missing required group members and invalid group order are rejected.
Shuffle commands do not themselves create model actions; a subsequent delivery must still obey the strict FIFO replay policy.
Each transaction carries at most one configuration in its `TransactionMetadata`.
Multiple configuration events for one append are rejected, not collapsed into one configuration or split into invented model actions.
Configuration-cache lists retain their recorded order and entries; cache observations compare them to the model rather than prevalidating the list.
Extra configuration Events have no standalone rule and are rejected by the central leftover-event check rather than a special duplicate lookahead.
The model and its guards are unchanged.

## Atomic boundaries and observations

`RaftDriver::_replicate` in `src/consensus/aft/test/driver.h` passes a singleton `BatchVector`, so each `replicate` event is one append action.
A globally committable entry is a signature; another entry is a transaction identified by its source `file:line`.
Configuration events supply the optional configuration metadata, and `cleanup_nodes` supplies its retired-committed node set.
Configuration/write pairing checks the index and transaction kind; the configuration snapshot is observed before the append, rather than compared to another raw snapshot during reduction.
The append's recorded `seqno` and `view` are observed as the resulting model log length and term.
Retirement-confirmation names resolve to a model set, so duplicates and an empty set need no separate input restriction.
The preloaded bootstrap configuration has the empty transaction identifier.
Model node IDs are lexical ordinals in the distinct sorted declared-name list, never numeric interpretations of textual names.
The initial membership contains the bootstrap node's ordinal; its minimum starts as primary even when earlier lexical nodes exist elsewhere in the population.
Request ID zero is reserved for genesis; other IDs map injectively to transaction source locations, which remain available in entry observations.
Adjacent events do not establish a general multi-entry production batch boundary; replaying such calls needs additional trace evidence.

A native byte-threshold flush can send a newly appended signature to a retired peer before a leader that is the sole active member commits it in the same call.
The model commits that signature atomically with its append, so replay rejects the intermediate packet carrying the new entry with the old commit frontier rather than inventing an intermediate model state.

`raft.h` traces `replicate`, `add_configuration`, `execute_append_entries_sync`, `commit` and sends before their mutations, whereas role-change events trace after changing role.
Each rule emits actions executed through unchanged `Model.transitionSystem.step` and observations checked against that execution.
One periodic driver call can produce several independently observed send or timeout rules.
The driver does not emit separate operation snapshots, IDs, or complete peer/cache dumps.
Observations use only existing event snapshots: role, term, log length, commit frontier, membership/retirement fields, available configuration caches and packet-specific peer progress.
Role-change Events already contain the assigned role; the timeout rules exclude that field from their pre-action observations while checking the transition.
This does not claim complete driver-entry/exit equality, exact signature-cache enumeration, complete peer-table equality, or a final snapshot when no event supplies one.
Votes, clocks, store contents and native queue enumeration are not observed directly.

Initialization is explicit rather than a fabricated model action.
The forced-leader/genesis prelude and singleton genesis argument are audited locally.
The following signature and commit use the ordinary append and leader-commit grammars, not bootstrap lookahead.
Genesis is preloaded by `Model.initialNodeState`; its configuration entry and the initial term are checked without inventing a bootstrap action or a constructor snapshot.

For a timeout's first pre-vote event, the role is already assigned while the other fields still describe the pre-state.
Earlier nested candidate and term-adoption snapshots are internal, not additional model states.
Their unused values may differ; fields used by projections, action recognizers and observations still require appropriate types.
Execution, configuration and follower-commit rules check event context, sender where applicable, the raw follower role, the stable term, signature-kind evidence, configuration-entry evidence and positive committed-prefix evidence.
They do not compare intermediate log length, membership phase or retirement coordinates to the final model state.
Remaining fixed phase exclusions, such as a leader commit snapshot before role clearing, are documented at their emission sites rather than carried in observation metadata; they do not depend on future event inspection.

Internal committable-index evidence remains a positive signature check because events can precede cache insertion or pruning.
Configuration caches within a receive are checked against log-entry configurations, and a positive event commit frontier must already point to a committed signature.
Follower delivery commits at each newly applied signature and once at the end, preserving the first frontier covering its retirement record while allowing a later final commit index.
Replay still executes this as one model delivery and checks event evidence against the resulting log and state; it does not insert intermediate commit actions.
The model's `noRetirementObserved` membership phase maps to the trace's `active` label, including declared nodes that have not yet joined.

New-peer configuration heartbeats belong to the append and use the constructor's next-index sentinel, one past the model's sent frontier.
The rule consumes the constructor heartbeats that are present, without requiring one for every new peer.
Ordinary sends do not use this adjustment.
Vote and pre-vote responses share `send_request_vote_response`; `packet.msg` distinguishes them, and each supplied response snapshot and packet is checked after its receive.
`become_follower` is an optional internal adoption event, not an additional model state or a conditionally selected endpoint.
Its snapshot is not promoted to a full-state observation based on whether another event follows.
Response-send events retain their stable state and packet observations; an absent optional response does not invent a post-state snapshot.
Lower-term NACK hints remain log terms, not new election terms.
A higher-term nomination is consumed without adopting its term or forcing an election.

Commits and promotions are never standalone model actions.
`become_leader` may commit and heartbeat synchronously.
Terminal retirement nominates inside its committing action, using the precommit eligible peers and configurations before pruning and clearing leadership.
The reducer audits the raw leader/completed-retirement snapshot and observes the proposal rather than substituting its destination into the action.
Its configuration cache must equal the checked pre-pruning commit cache.
The model selects the maximum acknowledged index, latest containing active configuration index, then lexical node ID; `"2"` ranks above `"10"`.

The leader commit snapshot records the old frontier, not the post-commit state.
The commit rule takes the old frontier from the already-parsed action head.
Its `observeBeforeCommit` observation checks the recorded frontier, post-append log and retirement/configuration projections after the action, including the old confirmation coordinate.
This read-only view uses the final log, the old frontier, and confirmation transactions in that committed prefix; it does not execute an intermediate action or modify model state.
The role is checked at its named leader phase rather than compared to a potentially cleared final role.
The commit target must advance the old frontier and equal the model effect, but is not presented as a native post-state observation.
Subsequent event snapshots check the advanced state when present.

Timeout elections must start in the pre-vote phase; same-term nominations retain their direct-election behavior.
Legacy `pre_vote_enabled` metadata and command labels are unused; they do not configure the model.
Actual elections that skip the required pre-vote entry still fail reduction.
The fixture refresh script preserves actual new native records rather than rewriting old captures to fit the model.
No synthetic nominations or mode toggle are inserted into the model.

The model's `retiredCommittedIndex` is the confirmation transaction's index, not the covering signature's index.
The native test stub's [`LoggingStubStoreConfig::compact`](../../../src/consensus/aft/test/logging_stub.h) passes the stored transaction version, matching production [`on_nodes_global_commit`](../../../src/node/node_state.h), and consumes every processed hook entry, including one exactly at the compact frontier.
For a confirmation transaction at index 5 covered by a signature at index 6, the hook reports 5, not 6.
The retained `terminal_retirement.stdout` records the old stub's incorrect compact-frontier index.
It remains unmodified historical negative evidence; its legacy mixed-console format is rejected before protocol replay.
Fresh native retirement fixtures record transaction index 5.

## Packet accounting

The model's network is an unordered multiset, and remains so.
The replayer assumes strict FIFO independently for each directed source/destination pair.
A receive selects the oldest live pending envelope for that pair, checks the recorded packet fields against it, and delivers its actual full payload.
It never searches ahead for a matching packet or reconstructs unobserved payload data.
An unavailable or mismatching head fails when replay executes the action; there is no redundant incoming-packet observation.
A drop excludes exactly one occurrence from future observations and deliveries, but leaves it undelivered in the model network.
Equal envelopes retain their multiplicity.
Explicit driver drops still check and exclude the queue head for that directed pair.
Sender consistency is a rule-local observation, not a condition for recognizing a drop event.

If different full model envelopes have identical recorded fields, FIFO determines which actual payload is delivered; no uniqueness or ambiguity check is needed.
Successful replay witnesses a compatible execution under this policy.
A FIFO replay failure does not prove that no execution with a different delivery order could match.
Packet headers do not encode physical nonces or channel epochs, and reconnect commands do not reset replay queues or invent drops.
Native authentication losses and channel-buffer replacement are not reconstructed; an unreceived envelope may simply remain pending.
An unreceived head blocks later receives on that pair unless an explicit drop excludes it.

Send telemetry is deliberately **not** required to enumerate every model emission exactly once.
A send observation checks compatibility with the latest pending packet for its endpoints; it neither creates nor consumes a packet.
Repeated observations may check the same occurrence, unobserved emissions may remain pending between actions or at EOF, and omitted optional response-send telemetry does not itself fail replay.
Election vote/pre-vote requests and new-peer constructor heartbeat observations may be omitted, repeated or reordered; reduction does not compare their destinations to a complete ordered peer list.
Promotion heartbeat coverage is also optional; a repeated destination still ends that group so a later independent send is not swallowed as an observation.
Each observed send must still match a model-generated packet during replay.
Actual delivery still requires a live compatible model packet and an enabled transition.
This relaxation checks observations and delivery feasibility, not completeness or exactly-once correspondence of implementation sends.
It does not relax record parsing, source event ordering, action guards or state observations.

## Regression coverage

`replay/tests/Main.lean` replaces the old Python regression suite.
It runs freshly captured bootstrap, startup, vote-response, missing-prefix, configuration, drop/resend, nomination and follower-retirement fixtures, checks instruction consumption, mutates every projected observation field, and exercises raw event/packet mutations, malformed JSON, missing or mistyped consumed fields, disabled actions, missing packets, wrong drop heads and repeated/drop message occurrences.
Unused metadata and command labels are accepted without changing replay, while unknown Events still fail.
Generic parser tests cover event types without equality, state threading and rollback, committed failures, optional/repeated rules, non-consuming observation ordering, and EOF.
[`tests/refresh_fixtures.py`](tests/refresh_fixtures.py) refreshes positive fixtures from actual native captures and complete event groups, retaining exact bytes and recording origin hashes; it rejects legacy input and never generates snapshot values or rewrites the historical terminal fixture.
Fixture slices retain their native process and sequence coordinates, so the bootstrap, configuration-callback and missing-prefix slices concatenate into their original stream.
Only synthetic protocol splices in the regression tests receive new contiguous sequence numbers; fixture loading and transport-integrity tests use unmodified envelopes.
The historical negative `terminal_retirement.stdout` remains unchanged and explicitly tests unsupported mixed-console input.
Receive regressions reject a later heartbeat while an earlier data packet remains pending, check head selection when distinct payloads have identical headers, and preserve equal-copy multiplicity and explicit drops.
Focused cases cover the relaxed send-telemetry semantics, transaction metadata, undeclared metadata members, rejected duplicate configuration events and preservation of recorded cache evidence.
Corrupted append coordinates, configuration snapshots, commit frontiers, send coordinates and drop senders are accepted by their grammars where grouping remains valid, then rejected by replay observations.
Typed raw event mutations cover observed state and timeout-phase fields.
Positive cases deliberately change unused internal candidate, follower-adoption and execution/configuration/commit details.
Emission tests require receive actions to precede their event observations, retain only their head origin, and omit redundant incoming-packet matching observations.
They retain malformed-field, entry/configuration, packet and event-context rejection.
`self_quorum.stdout` is a fresh native `reconfig_0_1` capture from the corrected test stub.
Python subprocess regressions cover capture byte preservation, timeout/nonzero-exit failures, successful diagnostic stderr, recursive inventory, invalid encoding, missing captures and stale-summary removal.
Neither the Lean regression executable nor the replayer imports proof modules.
Observation regressions exercise each checker against concrete states and corrupted fields, verify stable captured identities, and prove that successful observation execution returns the unchanged replay state.
Identity/init regressions cover lexical ordinals, a nonzero bootstrap ordinal, population preservation, genesis, undeclared IDs and duplicate request provenance.
Current-envelope regressions cover sequence gaps, reordering, process identity, direct flat-field consumption, legacy rejection, ignored unused metadata, command/source provenance and mandatory pre-vote election entry.
`python3 lean/ccf-raft/replay/tests/refresh_fixtures_test.py` from the repository root checks byte-preserving fixture slices, origin hashes and rejection of legacy sources without writing a replacement.
The native scenarios use pre-vote for timeout elections, including delayed nomination, partial-prefix overcommit, stale leaders and competing signed suffixes.
`soft_rollback` uses five nodes so a short-log candidate obtains a genuine pre-vote quorum before its higher-term vote request reaches a node with an unsigned suffix.
`retire_backup` checks that a removed node cannot inflate the term or depose the leader, then learns its retirement through ordinary prefix repair.
These migrations retain genuine pre-vote exchanges; they do not synthesize nominations or introduce a model toggle.
`python3 tests/raft_trace_capture_test.py` from the repository root exercises transport ordering, duplicate keys, unchanged records and stale-success removal.
`python3 tests/raft_trace_replay_test.py` covers the Python capture/replay suite and its failure paths.
Build `ccfraft-replay` first; set `CCF_RAFT_REPLAYER` to its executable when using an external build directory.
Replay-only builds do not replace the separately integrated proof build and kernel checks.
Successful replay witnesses a finite model execution compatible with these observations, not universal production inclusion, infinite extension, fairness or liveness.

## Kernel checks

Run `lake check` only in CI, not locally.
The [Lean workflow](../../../.github/workflows/lean.yml) exports/checks `CCFRaft`, `ccfraft-replay` and `replay-checks` separately because the executable roots have distinct `main` declarations.
Local builds and regressions are separate evidence, not a kernel-check pass.
The CI checks allow only `propext`, `Classical.choice` and `Quot.sound`.
They run without build sandboxing, so configuration and build code must be trusted.
