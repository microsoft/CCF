# Raw trace reduction reference

`capture.py` saves actual `raft_driver` stdout without preprocessing.
`reduction.py` translates those records into `ccfraft-replay/v2` instructions.
`run_scenarios.py` invokes capture, reduction, and the canonical Lean executable
for every file under `tests/raft_scenarios`.

The reducer does not run a solver, search for actions, import the earlier
experimental reducer, or construct a protocol state. It keeps a packet-occurrence
ledger to correlate recorded sends, receives, and drops. Lean alone executes
protocol actions and compares observations.

## Commands and files

| Command                                                   | Result                                                            |
| --------------------------------------------------------- | ----------------------------------------------------------------- |
| `python3 capture.py DRIVER SCENARIO OUTPUT.stdout`        | Verbatim stdout and a sibling `OUTPUT.stderr`                     |
| `python3 reduction.py INPUT OUTPUT.json`                  | Deterministic, indented replay JSON                               |
| `python3 run_scenarios.py DRIVER --output DIRECTORY`      | Every upstream scenario, individual artifacts, and `summary.json` |
| `python3 -m unittest discover -s tests -p 'test_*.py' -v` | Python and canonical wire regression tests                        |

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
[`tests/raft_scenarios_runner.py`](../../tests/raft_scenarios_runner.py).
Every regular file is selected recursively, including extensionless files and
names such as `suffix_collision.1`. Sorting fixes execution order. No scenario
name, extension, or deprecated syntax is filtered out.

Each failed capture, reduction, or replay remains a failed scenario. The suite
attempts the rest of the inventory and exits nonzero if any scenario fails.
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
are errors. Event timestamps must increase strictly in input order. The reducer
never sorts records.

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

Node creation commands also declare pre-vote compatibility modes. The driver's
initial setting is `true`. `pre_vote_enabled` changes the setting for subsequent
creations, not existing nodes. This follows
[`RaftDriver::add_node`](../../src/consensus/aft/test/driver.h).
Recorded node-state modes must agree with their creation setting. A configuration
node without either a recorded creation or an observed mode is an error.

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
Raw term 0 remains 0. Raw terms at least 2 use `raw - 1`.
Raw term 1 is rejected under this prelude. Term-at-index fields use the same
term mapping, without changing a recorded nonzero term to a sentinel.

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
| `drop`                        | Observe the sender and exact pending packet, then emit `drop` with its sender-relative occurrence. One recorded drop removes one occurrence.                                                                                 |
| `receive-pre`                 | Compare receiver state, recorded peer progress, and the selected source-relative queue head before processing it.                                                                                                            |
| `receive-term`                | A following same-node `become_follower` at the packet's higher term witnesses `updateTerm`. Observe its post-state before the consuming receive.                                                                             |
| `receive-fallback`            | Same-term AppendEntries fallback uses the canonical non-consuming fallback receive, observes the follower boundary, and then consumes the packet.                                                                            |
| `atomic-receive`              | Group adjacent same-node AppendEntries callbacks through `send_append_entries_response`. Execute one consuming receive. A nomination's adjacent `become_candidate` is part of that receive, not a second election.           |
| `tla-callback-stutter`        | Apply the fixed callback masks below at source-defined stable boundaries. Retain the complete raw callback and every omitted transient field in provenance.                                                                  |
| `callback-entry`              | Compare a follower configuration callback's physical entry index and node set against the final canonical log. Compare a commit callback's target against a committed signature entry.                                       |
| `receive-post`                | Observe the complete terminal response or candidate state after the action, including unchanged values.                                                                                                                      |
| `response-post`               | Compare the recorded AppendEntries response against the latest queued response after the receive.                                                                                                                            |
| `commit-pre`                  | Observe a standalone leader `commit` callback before `advanceCommitIndex`. An ungrouped follower commit is an error.                                                                                                         |
| `commit-post`                 | Compare the resulting commit index to the recorded `args.idx`.                                                                                                                                                               |
| `terminal-commit`             | Coalesce a commit with its immediate same-node, same-command retirement nomination. Emit one `advanceCommitIndexAndProposeVote` with the destination determined from the recorded packet receive or drop.                    |
| `terminal-nomination-pre`     | Check the unchanged log, term, configuration cache, and retirement ordering indices before the combined action. The configuration cache has not yet been compacted at this callback.                                         |
| `terminal-nomination-post`    | Observe the new commit and retired-committed frontier after the combined action. The callback's old leader role and completed retirement phase are checked as raw call-site facts, not compared to the final terminal state. |
| `role-post`                   | Emit the corresponding election, promotion, or quorum-step-down action, then observe the recorded state. Disabled canonical actions are failures.                                                                            |
| `nomination`                  | Correlate a nomination with its unique subsequent same-source, same-term recorded receive or drop. Emit `proposeVote` with both origins. Missing or ambiguous destinations are errors.                                       |

Ordinary writes use `input-file:original-line` as an opaque transaction identity.
The reducer does not guess transaction contents or equate different accepted
writes by equal log coordinates.

Boundary selection depends on source callback ordering, not on observed scalar
values matching either endpoint. Mutating a callback field cannot move its
observation across an action.

The fixed masks use the atomic receive boundary from
[`Traceccfraft.tla`](../../tla/consensus/Traceccfraft.tla). Interior follower roles
are checked directly against their C++ call sites rather than against a final
state that may already have completed retirement:

| Raw callback                         | Observed fields                                            | TLA source                                          |
| ------------------------------------ | ---------------------------------------------------------- | --------------------------------------------------- |
| `execute_append_entries_sync`        | `currentTerm`, `preVoteEnabled`; raw role must be follower | `IsExecuteAppendEntries`, line 396                  |
| Follower `add_configuration`         | `preVoteEnabled`; raw role must be follower                | `IsAddConfiguration`, line 283                      |
| Follower `commit`                    | `preVoteEnabled`; raw role must be follower                | `IsAdvanceCommitIndex`, follower branch at line 321 |
| Receive-associated `become_follower` | `role`, `membershipState`, `preVoteEnabled`                | `IsBecomeFollower`, line 430                        |

Receive helpers stutter after the one consuming atomic receive. An associated
`become_follower` follows the explicit term-update or same-term fallback action.
These diagnostic callbacks can occur partway through a packet. Their transient
log length, commit index, pending signatures, configuration list, and retirement
fields are not stable canonical observations at that point. In particular, a
single batch can add or remove the receiving node and advance its retirement
phase between callbacks. The TLA preprocessing removes an execute record before
a configuration callback. This reducer retains it, but does not equate any
interior membership phase to the packet's final membership phase.
Fields outside both the canonical mask and the raw call-site checks are recorded under
`origin.omittedTransientFields`, with values. `origin.rawRecord` retains the
complete original callback, including arguments and implementation location.
`origin.checkedRawFields` records the call-site predicates checked by Python.
The full `send_append_entries_response` state is still observed after the atomic
receive, and its packet is compared separately. No raw callback disappears.

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

## Packet occurrence rules

The occurrence ledger retains each explicit packet send. Receives consume the
first matching packet from that sender. A receive that would reorder packets
from one sender fails because the canonical receive action selects that sender's
first pending packet.

A drop can select a later matching occurrence. Equal fully recorded packets use
the earliest identical occurrence, preserving multiplicity. A resend creates a
new occurrence and has its own source line.

C++ does not trace RequestVote response sends. Its
`recv_request_vote_unsafe` sends exactly one response, including for stale terms.
The occurrence ledger records only the response family and the term established
by that call. It does not invent `vote_granted`. A later recorded receive or drop
supplies that field for Lean to check. If a drop matches multiple such incomplete
response occurrences, reduction fails rather than guessing.

A higher-term nomination does not imply `updateTerm` or a new election.
`recv_propose_request_vote` acts only for a same-term nomination. An ignored
nomination still emits a consuming canonical `receive`.

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
