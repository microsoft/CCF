# Raw trace reduction reference

`capture.py` saves actual `raft_driver` stdout without preprocessing.
`reduction.py` translates those records into `ccfraft-replay/v2` instructions.
`run_scenarios.py` invokes capture, reduction, and the canonical Lean executable
for every file under `tests/raft_scenarios`.

The reducer does not run a solver, search for actions, import the earlier
experimental reducer, or construct a protocol state. It consumes prefixes of the
recorded event list in one loop. It has no packet queue or future-event
correlation. Lean alone executes protocol actions and compares observations.

## Commands and files

Run these commands from `lean/ccf-raft`.

| Command                                                     | Result                                                            |
| ----------------------------------------------------------- | ----------------------------------------------------------------- |
| `python3 replay/capture.py DRIVER SCENARIO OUTPUT.stdout`   | Verbatim stdout and a sibling `OUTPUT.stderr`                     |
| `python3 replay/reduction.py INPUT OUTPUT.json`             | Deterministic, indented replay JSON                               |
| `python3 replay/run_scenarios.py DRIVER --output DIRECTORY` | Every upstream scenario, individual artifacts, and `summary.json` |
| `python3 -m unittest discover -s tests -p 'test_*.py' -v`   | Python and canonical wire regression tests                        |

The suite accepts `--replayer`, `--scenarios`, and `--timeout`.
`--raw-directory DIRECTORY` reuses existing `<scenario>.stdout` captures without
running the driver. In this mode, the driver argument is optional. The inventory
still comes from the scenario directory, so a missing capture is a failure
rather than an omitted scenario. Origins refer to the existing captures.
The default replayer is `.lake/build/bin/ccfraft-replay`.
The default timeout is 120 seconds per external invocation.
The suite does not build the driver or Lean package.
The full test command requires the built canonical executable.
`test_replay.py` checks a valid source bootstrap, falsified observations, disabled
actions, and malformed packets against that executable. It fails explicitly
when the executable is absent. The Python-only subset uses
`python3 -m unittest discover -s tests -p 'test_reduction.py' -v`.

Persistent corpus integration uses `build/raft_driver` and
`build/raft-replay/raw/<scenario>.stdout` under the repository. For existing
captures, `--raw-directory ../../build/raft-replay/raw --output
../../build/raft-replay/replayed` keeps source provenance and results outside
temporary build storage.

The inventory matches the directory expansion used by
[`tests/raft_scenarios_runner.py`](../../../tests/raft_scenarios_runner.py).
Every regular file is selected recursively, including extensionless files and
names such as `suffix_collision.1`. Sorting fixes execution order. No scenario
name, extension, or deprecated syntax is filtered out.

Capture and replay failures and explicit reduction errors remain failed scenarios.
The suite attempts the rest of the inventory and exits nonzero if any scenario fails.
A driver stderr stream also makes capture fail, matching the upstream scenario
runner, even when the driver exits with status zero.
A successful executable exit is insufficient. Its JSON response must report
`status: "ok"` and the exact emitted instruction, action, and observation counts.
The runner removes stale replay artifacts for a scenario before attempting it.
It invalidates an old `summary.json` before validating the new inventory.
Only a completed run writes a summary, so interruption cannot leave an old
successful summary looking like the result of the new run.

## Input and provenance

NDJSON input contains one object per physical line. Empty input, empty records,
duplicate JSON keys, non-finite numbers, non-object records, and malformed JSON
are errors. After extraction, preprocessing assumes driver-shaped records.
Malformed record structures can raise ordinary Python exceptions and abort the run.
The reducer uses file order without sorting or checking timestamps.

A `.stdout` input is a verbatim driver capture. `trace_io.py` recognizes
`<RaftDriver>` diagram lines and structured non-Raft logger records. These
transport records do not describe Raft transitions. Unknown stdout text is an
error, not a line to discard. At least one actual Raft event is required.
The captured file remains unchanged, including CRLF line endings.

Every instruction has a nonempty `origin` array. Entries include the input file,
its original physical line, a rule identifier, the function, and the command
marker with its original line. Recorded C++ file and line information is retained.
File paths are absolute so that diagnostics remain usable when replay runs from
a different working directory.
Coalesced actions list all contributing event origins. A raw NDJSON fixture uses
its own physical line numbers. A captured stdout file never uses renumbered
filtered-NDJSON positions.

Known command markers establish context rather than protocol actions. For
example, `dispatch_all` determines which calls the driver makes, and
`assert_commit_idx` runs a driver assertion. A command with no emitted Raft event
does not cause an invented model step. Unknown command names fail.
Original markers, including a trailing assertion without subsequent events,
remain in the captured stdout.

`shuffle_one` and `shuffle_all` are unsupported and fail during parsing.
The supported driver scenarios preserve source/destination queue order.

`associate()` attaches command context and collects the global per-node pre-vote
map, including nodes that have not emitted an event. It does not reconstruct
protocol state or packet queues. Rules check their own preconditions; state and
packet projection happens when emitting observations, not in a separate preflight.

Node creation commands declare pre-vote compatibility modes. The driver's
initial setting is `true`. `pre_vote_enabled` changes the setting for subsequent
creations, not existing nodes. This follows
[`RaftDriver::add_node`](../../../src/consensus/aft/test/driver.h).
Without a creation command, the first snapshot supplies the node's mode.
Lean checks recorded modes against this map and rejects undeclared configuration
nodes.

## Coordinates and bootstrap

The supported prelude consists of these five events on one leader, with raw term
2 throughout:

| Event               | Required raw state or argument                                    |
| ------------------- | ----------------------------------------------------------------- |
| `become_leader`     | Leader, active, log length 0, commit index 0                      |
| `replicate`         | Noncommittable configuration write at index 1, pre-write length 0 |
| `add_configuration` | Singleton leader configuration at index 1, pre-write length 0     |
| `replicate`         | Committable signature at index 2, pre-write length 1              |
| `commit`            | Target index 2, pre-commit length 2 and commit index 0            |

The committable-index snapshots must be `[]`, `[]`, `[]`, `[]`, and `[2]`.
All five events retain origins and state observations under `bootstrap`.
The paired configuration write and callback become one guarded
`initializeConfiguration` action. Existing `signCommittableMessages` and
`advanceCommitIndex` actions append the signature and commit index 2. This
produces ten instructions, with three actions and seven observations, including
the signature-marker check before commit.
No bootstrap entries are erased.

Every ledger index remains its physical raw value. This includes log lengths,
commit indices, peer progress, retirement indices, and packet coordinates.
Every term remains its raw value, including 0 and 1. State and packet terms,
including term-at-index fields, use this identity mapping.
The model starts bootstrap nodes at `BOOTSTRAP_TERM = 2` and fresh nodes at 0.
Elections increment the current term by one. No recorded term becomes a sentinel.

Each recorded committable index produces a `signature-marker` entry observation.
The marker must point to a signature in the canonical log. The implementation's
cache is not a complete enumeration of signature entries: for example, a batch
can retain markers 5 and 7 while the log also contains signature 6.
An absent marker therefore does not assert an absent signature. This follows
the subset relation in `Traceccfraft.tla` and `CommittableIndices` in
`ccfraft.tla`, rather than equating the implementation cache to the log.
`configurations` contains all recorded configurations as `{index, nodes}`
objects. The canonical observer compares explicit physical configurations,
excluding only its implicit index-zero initialization metadata.
Configuration node names are sorted. Driver address metadata must be the
recorded empty address `":"`, and `rid` must equal `idx`. Neither field has a
separate protocol transition.

This projection is not claimed to cover every initial state. A trace without
this exact prelude fails, even when its scenario is selected by the suite.

## Reduction rules

`reduce_trace` contains the rules in one `while events` loop. `peek(n)` reads
the next function names; `take(n)` consumes that prefix. Compound patterns precede
their single-event alternatives. A matched pattern with invalid evidence fails
rather than falling through to another rule.

Configuration writes consume the recorded new-peer heartbeat prefix. Its length
and destinations come from the configuration arguments and pre-change snapshot.
AppendEntries receives consume a variable-length, same-node, same-command run of
execute, configuration, and commit callbacks, ending at a recorded response when
present. Neither rule carries partial-call state into the next loop iteration.

`Instructions` only builds output. Each rule supplies action parameters explicitly;
the builder does not infer the acting node or choose a protocol step.

| Rule                          | Recorded boundary and emitted result                                                                                                                                                                                         |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bootstrap`                   | Verify the exact prelude above. Coalesce its configuration callback into guarded `initializeConfiguration`, then emit signature and commit actions with every boundary observation.                                          |
| `write-pre`                   | Observe before an accepted `replicate`. Verify successor sequence number and matching term. Emit `clientRequest`, `signCommittableMessages`, or `appendRetiredCommitted` for a `cleanup_nodes` write.                        |
| `configuration-pair`          | An adjacent leader `replicate` and `add_configuration` must share node, command, state, and index. Preserve both pre-state observations and emit one `changeConfiguration` with both origins.                                |
| `configuration-callback-pre`  | Observe log length, term, role, commit index, pending signatures, and pre-vote mode before `changeConfiguration`. The callback runs before ledger append and does not change these fields.                                   |
| `configuration-callback-post` | Observe membership and retirement fields after `changeConfiguration`, including unchanged values. The configuration hook has already applied those side effects at the callback.                                             |
| `configuration-callback-peer` | For a verified newly created peer heartbeat, convert the constructor's `sent_idx = old_length + 1` next-index sentinel to `sentIndex = old_length`. Preserve `match_idx = 0`. This conversion applies only to this callback. |
| `configuration-callback-send` | After `changeConfiguration`, emit the one recorded heartbeat with `batchEnd = old_length`. Its queue snapshot uses the pre-append prefix, not the new configuration entry.                                                   |
| `send-pre`                    | Observe the sender and any recorded `sent_idx` and `match_idx` before sending. Emit the request action for the recorded destination.                                                                                         |
| `atomic-append`               | Emit exactly one `appendEntries`, with projected `batchEnd`, for one recorded packet. Never split an append batch or manufacture intermediate network packets.                                                               |
| `send-post`                   | Compare every packet field against the latest queued packet from that source to that destination.                                                                                                                            |
| `signature-marker`            | Check each recorded committable index with an `entry` observation requiring signature content. Do not assert that unlisted log entries are not signatures.                                                                   |
| `drop`                        | Observe the sender and source/destination queue head, then emit `drop` at occurrence zero. One recorded drop removes one packet.                                                                                             |
| `receive-pre`                 | Compare receiver state, recorded peer progress, and the selected source-relative queue head before processing it.                                                                                                            |
| `receive-term`                | A following same-node `become_follower` at the packet's higher term witnesses `updateTerm`. Observe its post-state before the consuming receive.                                                                             |
| `receive-fallback`            | Same-term AppendEntries fallback uses the canonical non-consuming fallback receive, observes the follower boundary, and then consumes the packet.                                                                            |
| `receive-follower-post`       | Observe the complete `become_follower` snapshot after term update or same-term fallback, before rollback and entry application.                                                                                              |
| `atomic-receive`              | Group adjacent same-node AppendEntries callbacks through `send_append_entries_response`. Execute one consuming receive. A nomination's adjacent `become_candidate` is part of that receive, not a second election.           |
| `tla-callback-stutter`        | Emit all callback properties except explicit, reasoned exclusions. Retain excluded values and reasons in provenance.                                                                                                         |
| `callback-entry`              | Compare a follower configuration callback's physical entry index and node set against the final canonical log. Compare a commit callback's target against a committed signature entry.                                       |
| `callback-configuration`      | Compare each configuration-cache entry against its physical log entry, even when later commit compacts the active cache.                                                                                                     |
| `callback-committed-prefix`   | Check that an intermediate nonzero commit frontier points to a committed signature, without equating it to the final frontier.                                                                                               |
| `receive-post`                | Observe the complete terminal response or candidate state after the action, including unchanged values.                                                                                                                      |
| `response-post`               | Compare the recorded AppendEntries response against the latest queued response after the receive.                                                                                                                            |
| `commit-pre`                  | Observe a standalone leader `commit` callback before `advanceCommitIndex`. An ungrouped follower commit is an error.                                                                                                         |
| `commit-post`                 | Compare the resulting commit index to the recorded `args.idx`.                                                                                                                                                               |
| `terminal-commit`             | Coalesce a commit with its immediate same-node, same-command retirement nomination. Emit one `advanceCommitIndexAndProposeVote` using the nomination's recorded destination.                                                 |
| `terminal-nomination-pre`     | Check the unchanged log, term, configuration cache, and retirement ordering indices before the combined action. The configuration cache has not yet been compacted at this callback.                                         |
| `terminal-nomination-post`    | Observe the new commit and retired-committed frontier after the combined action. The callback's old leader role and completed retirement phase are checked as raw call-site facts, not compared to the final terminal state. |
| `role-post`                   | Emit the corresponding election, promotion, or quorum-step-down action, then observe the recorded state. Disabled canonical actions are failures.                                                                            |
| `nomination`                  | Emit `proposeVote` using the destination recorded in `to_node_id`. No later receive or drop is needed to determine the action.                                                                                               |

Ordinary writes use `input-file:original-line` as an opaque transaction identity.
The reducer does not guess transaction contents or equate different accepted
writes by equal log coordinates.

Boundary selection depends on source callback ordering, not on observed scalar
values matching either endpoint. Mutating a callback field cannot move its
observation across an action.

`emit_observations(event, rule, properties, exclusions={field: reason})` checks
every supplied property by default. Without `properties`, it uses
`state_facts(event)`. Exclusions must name supplied properties and give nonempty
reasons. A new property is observed unless a rule explicitly excludes it.
An empty state observation is an error. Callers cannot override its provenance.
Committable-cache properties produce signature-entry observations rather than
cache equality, as described above.

Receive helpers remain after the consuming atomic receive, but their checks
are stronger than the original masks from
[`Traceccfraft.tla`](../../../tla/consensus/Traceccfraft.tla):

| Callback property               | Observation or exclusion                                                                                                                                                                  |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `become_follower` snapshot      | All properties. Term assignment precedes the trace; rollback and entry application follow it.                                                                                             |
| `currentTerm`, `preVoteEnabled` | Exact equality throughout the execute loop, configuration hooks, and commit callbacks.                                                                                                    |
| `logLength`                     | Exact equality after the last execute callback. Earlier callbacks precede entry application, so their partial lengths are excluded.                                                       |
| `commitIndex`                   | Exact equality after the last commit callback. Earlier nonzero frontiers instead produce committed-signature entry observations.                                                          |
| `role`                          | Checked as follower at the raw call site. Also compared to the final role unless a pending commit could trigger terminal retirement.                                                      |
| `membershipState`               | Excluded because configuration, signature, and commit callbacks can each advance retirement within one packet.                                                                            |
| Retirement indices              | Present indices are compared exactly. An absent index is excluded only while its writer remains: configuration for ordering, entry execution for signing, commit for terminal retirement. |
| `committableIndices`            | Each recorded marker must identify a signature in the final log. Later commits may remove markers from the cache, not the log.                                                            |
| `configurations`                | Each recorded configuration is checked as a log entry. Cache equality is excluded because later hooks insert configurations and commit discards older ones.                               |

The receive rule states each exclusion beside its source-based reason.
Its `pending` set includes the current callback because execute and commit trace
before their mutations. This is a set of recorded function names, not model state.
`origin.omittedTransientFields` preserves the excluded values and
`origin.omissionReasons` preserves those reasons, including reasons for replacing
an exact state comparison with an entry observation. `origin.rawRecord` retains
the complete callback. The terminal response snapshot is still observed in full,
and its packet is compared separately.

Configuration callback arguments produce an `entry` observation with
`fields: {kind: "configuration", configuration: [...]}` at the recorded index.
Commit callback arguments produce
`fields: {kind: "signature", committed: true}` at the recorded target.
Lean checks these against the final physical log and commit frontier, without
pretending that an intermediate commit index is the final index.

All stable state observations include recorded role, term, log length, commit
index, pre-vote flag, membership phase, optional retirement indices, pending
signatures, configurations, and peer progress where available. The reducer does
not replace `none` with `follower` or patch state to make a replay pass.

`contains_new_view` remains in packet observations. Lean checks its fixed false
compatibility value. The reducer never treats an unexpected true value as an
unused bit to discard.

## Head-of-queue packets

Each receive or drop observes the canonical queue head for its source and
destination before consuming it. A missing packet or mismatched field fails in
Lean. The reducer never searches for a later matching packet. Repeated packets
remain separate occurrences; each drop removes exactly one.

`RaftDriver::drop_pending_to` drains the selected source/destination queue and
records one drop per packet. Each event therefore selects occurrence zero.
Explicit queue-shuffling commands are rejected rather than modeled.

C++ does not trace RequestVote response sends. The canonical receive action
already generates those responses. Subsequent receive or drop observations
check their recorded fields, including `vote_granted`, against the canonical
queue. No Python reconstruction of unlogged sends is needed.

A higher-term nomination does not imply `updateTerm` or a new election.
`recv_propose_request_vote` acts only for a same-term nomination. An ignored
nomination still emits a consuming canonical `receive`.

The originating `step_down_and_nominate_successor` trace records the selected
successor as `to_node_id`. Older captures without that field must be recaptured
with the updated driver. The reducer rejects them instead of recovering a
destination from future events.

## Terminal retirement

`become_retired(RetiredCommitted)` calls `nominate_successor` before assigning
the final retirement phase and clearing the leadership role. The nomination
record consequently still says leader and completed, even though compaction has
already advanced the commit index. These are checked raw call-site facts.
They are not observations of the final canonical state.

For an immediate same-command commit and retirement nomination, the reducer
emits the existing combined commit-and-propose action exactly once. The callback's
unchanged fields are observed before that action. Its new commit frontier and
retired-committed frontier are observed after it. Configuration-cache observations
remain before the action because C++ discards old configurations after returning
from its commit callbacks. A separate user-requested nomination still emits
`proposeVote` and does not imply retirement.

## Regression fixtures

The rejected v1 scheme erased the bootstrap prefix. It conflated a fresh
follower's length 0 with a heartbeat's previous index 2, turning a required NACK
into an ACK. It also made a legal subsequent signature appear to operate on an
empty log. V2 retains physical indices and initializes the real entries through
canonical actions. V1 documents are rejected rather than interpreted as V2.

`tests/fixtures/configuration_callback.ndjson` retains the callback-ordering
regression. Historical lines 13 and 14 accept configuration entry 3. Line 15
sends a heartbeat with physical log length 2 and constructor `sent_idx` 3.
The callback rules preserve the pre-append log observation, check the peer's
post-construction frontier 2, and emit exactly the recorded heartbeat.

The fixtures are verbatim excerpts of the historical captured `bad_network`
trace. `bootstrap.ndjson` contains original lines 1 through 9.
`configuration_callback.ndjson` contains original lines 10 through 17.
`missing_prefix_response.ndjson` contains original lines 18 through 22.
Together, these three excerpts replay the initial configuration callback and
the fresh follower's required NACK against the canonical executable.
Their local file/line provenance is intentional. Production capture retains
the complete original stdout and therefore its original line numbering.

`startup.ndjson` contains every Raft record from the freshly built driver's
`startup` scenario. Its end-to-end regression checks physical log length 2 and
commit index 2 before the first post-bootstrap signature, then rejects a mutation
that changes that observed length to 0.

`drop_resend.ndjson` isolates the same-sender packet events at original lines
137, 140, 155, 163, and 164, together with their command markers. Its test checks
packet reduction and occurrence accounting only. It is not a complete scenario
and does not claim canonical replay from bootstrap.

`terminal_retirement.stdout` is a complete fresh `reconfig_0_1` driver capture.
It covers committing a retirement marker, the before-demotion nomination
callback, successor election, and subsequent traffic involving the retired node.

`retire_follower.stdout` is a complete `retire_one` driver capture. It covers
retirement indices already set in interior follower callbacks. Mutation tests
change those raw indices and require canonical replay to reject them.
