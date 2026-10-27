# CCF-Raft trace replay

The replayer checks finite `raft_driver` captures against the existing Lean model.
Python captures the native driver and runs scenario suites; Lean validates the recorded protocol behavior.
A pass witnesses a compatible finite execution under the [replay policy](#replay-contract), not a proof of C++ correctness.
A failure may indicate malformed input, unsupported evidence, a FIFO-policy mismatch or a model discrepancy; it is not automatically a native consensus bug.

```text
Fluentd records -> prepareEvents (Input.lean) -> named reduction rules
                -> model actions + read-only observations -> Interpreter
```

## Run replay

Use the [supported CCF development environment](../../../doc/contribute/build_setup.rst) and [native build prerequisites](../../../doc/contribute/build_ccf.rst).
Install the package's Lean toolchain and dependencies as described in [model validation](../README.md#validation).
The Python collector also requires `msgpack` from [`tests/requirements.txt`](../../../tests/requirements.txt) in the active environment.

### Capture and replay current scenarios

Run from `lean/ccf-raft`:

```sh
lake build --wfail ccfraft-replay replay-checks
cmake -S ../.. -B /tmp/ccf-raft-build -GNinja
cmake --build /tmp/ccf-raft-build --target raft_driver
python3 ../../tests/raft_trace_capture.py ../../tests/raft_scenarios /tmp/ccf-raft-captures \
  --driver /tmp/ccf-raft-build/raft_driver --replayer .lake/build/bin/ccfraft-replay
```

The runner recursively selects every scenario file, attempts each one and reports per-scenario results.
Omit `--replayer` for capture only.
Use `--timeout N` to change the positive, finite per-scenario timeout from 60 seconds.
The output directory and scenario inventory must be disjoint: neither may contain the other.
Inventories whose generated artifact paths collide, such as `one` and `one.result.json/next`, are rejected before modifying output.

### Replay existing captures

For one trace produced by the preceding command, from `lean/ccf-raft`:

```sh
lake exe ccfraft-replay /tmp/ccf-raft-captures/retire_backup.stdout
```

For the same scenario inventory using saved captures, without starting a driver:

```sh
python3 ../../tests/raft_trace_capture.py ../../tests/raft_scenarios /tmp/ccf-raft-results \
  --raw-directory /tmp/ccf-raft-captures --replayer .lake/build/bin/ccfraft-replay
```

Reusing captures checks the selected replayer, not a changed native implementation.
Missing captures and invalid encoding are failures, not skipped scenarios.
If the replay executable is built elsewhere, pass its actual path to `--replayer`.

### Results and failures

| Artifact                           | Meaning                                                                                                                         |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `<scenario>.stdout`                | Original Fluentd records serialized as NDJSON; despite the extension, this is not console output                                |
| `.driver.stdout`, `.driver.stderr` | Native console bytes, retained separately; diagnostic stderr alone does not imply failure                                       |
| `.result.json`, `summary.json`     | Per-scenario and suite results, including the failed stage; inspect the stage because capture-only success is not a replay pass |
| `.partial`                         | Received records retained after capture, transport or decoding failure, not a successful trace                                  |
| `.driver.records.msgpack`          | Original records retained when a value cannot be represented in JSON                                                            |

The suite exits nonzero if any scenario fails.
Single-trace replay prints JSON counts for instructions, actions and observations on success.
Observation failures include the instruction position, trace file/line, reduction rule and discrepancy.
Capture failures should be diagnosed from the native/transport artifacts; an `ungrouped event` points to input interpretation or reduction; an instruction failure points to execution or an observation.

The collector uses the driver's loopback Fluentd endpoint, not redirected stdout or the removed `CCF_RAFT_TRACING` switch.
It preserves capture order and original `process_id`, `h_ts` and `msg` values; it never sorts or repairs events to make replay succeed.

## Replay contract

### Input and reduction

Input must be current Fluentd `ccf.raft_trace` NDJSON, regardless of filename extension.
Mixed console logs, legacy `raft_trace` layouts, blank/malformed records, mixed process identities and noncontiguous sequence numbers are rejected.
Ordinary Lean JSON parsing coalesces duplicate object keys; there is no separate duplicate-key scan.
Consumed fields use fallible accessors; unrelated metadata is ignored.

Commands declare identities and retain provenance, but do not independently create model actions.
Some rules also use command meaning: bootstrap requires `start_node`, standalone nomination requires `nominate_successor`, and `cleanup_nodes` supplies retirement-confirmation metadata.
Node identities are distinct names sorted lexically, not numeric interpretations of strings.
Request identifiers refer to transaction source locations; zero is reserved for genesis.

Every event must belong to a named rule, and all input must be consumed.
Each rule first consumes its evidence, then emits instructions.
Protocol-action rules emit the head's pre-action observation, the action, and comparable synchronous-event/post-action observations.
Bootstrap emits only initialization observations; a drop checks its snapshot and packet before excluding the envelope, with no post-observation.
Replay executes those instructions later; parsing does not execute the model.
Actions retain the head's origin, and observations retain the source event's origin.
There is no required terminal observation or invented snapshot at EOF: a finite prefix can end in an action or leave packets pending.

| Source event                                  | Model action or evidence                                                                  |
| --------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Forced leader and singleton genesis           | Check initialization against the preloaded model state                                    |
| `replicate`                                   | One append, including configuration hooks, constructor heartbeats and synchronous commit  |
| Independent `send_append_entries`             | Send entries to the recorded peer/end index                                               |
| `recv_*`                                      | Deliver the FIFO head; check adoption, execution, promotion, commit and response evidence |
| `become_pre_vote_candidate` outside a receive | Election timeout, including self-quorum promotion when applicable                         |
| `become_follower` outside a receive           | Check-quorum timeout                                                                      |
| Standalone `step_down_and_nominate_successor` | Nominate using the model's successor selection                                            |
| `drop_pending_to`                             | Exclude one pending FIFO-head occurrence                                                  |

Timeout elections require pre-vote; same-term nominations retain their direct-election behavior.
Commits and promotions are synchronous evidence, not extra model actions.
The model and its guards are unchanged.

### Observations and native phases

There are three basic observation kinds:

| Kind   | Purpose                                                                                                                                                                        |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| State  | `emitObserveSnapshot` checks a supported node snapshot minus explicit exclusions; `emitObserveState` checks explicit output coordinates such as a write index or commit target |
| Entry  | Check a model log entry's term, kind, configuration, transaction identity or committed status                                                                                  |
| Packet | Check recorded fields against a queued model packet; nomination uses a constructed proposal header                                                                             |

A snapshot includes supported recorded role, term, log length, commit index, retirement fields, available signature/configuration caches and compatible recorded peer progress.
It does not mean the entire model state, every peer, full log contents, votes, clocks, KV contents or network enumeration.
At stable boundaries, `committable_indices` must exactly match the native cache projection: empty, the sole uncommitted signature index, or the first and last such indices in order.
This checks the recorded extrema, not unrecorded interior cache entries; extra, missing, reordered or duplicate markers are rejected.
Entry and packet checks supplement snapshots rather than replace them.

Native callbacks often occur before a mutation, while the model performs several effects atomically.
The emitters document exclusions at the point where they are needed:

| Native phase                                   | Comparison                                                                                                                                                                        |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Role change                                    | The callback already contains the new role; exclude that role before the action and check it afterwards where comparable                                                          |
| Candidate followed by promotion                | Exclude fields affected by role change and unsigned-suffix rollback                                                                                                               |
| Leader commit or an empty AppendEntries commit | Use `observeBeforeCommit` with the checked action head's old commit index; exclude a role that committing may clear, and check the commit target separately                       |
| AppendEntries callbacks                        | Retain log-derived fields when the packet is empty, and commit-derived fields when its limit cannot advance the checked pre-state; otherwise exclude fields that can still change |
| New-peer constructor heartbeat                 | Observe the applied configuration but exclude the pre-append log length; translate its next-index sentinel to the model's sent index                                              |
| Ordinary send or standalone nomination         | Recheck unchanged recorded fields after the action; sending excludes the updated `sent_idx`                                                                                       |

Committing does not change the log, so `observeBeforeCommit` reads the final log at an independently checked old commit index and derives retirement confirmation from that prefix.
It checks a read-only view, never executes an intermediate action or changes replay state.
Post-action checks of unchanged fields reuse existing evidence; they do not claim a new native post-action snapshot.
The driver supplies no separate operation-boundary snapshots or operation IDs.

For AppendEntries, caches and retirement phase depend on both log and commit progress.
If neither can change, internal snapshots are checked fully; empty-request commits use the pre-commit view.
Other intermediate callbacks retain positive signature/configuration-entry and committed-prefix evidence where exact cache comparison is not justified.
Missing optional packet coordinates keep the conservative exclusions; malformed supplied coordinates fail the preceding model-packet check.
These decisions use the packet and checked pre-state, not absence of later telemetry.

### Packets, drops and delivery order

The model network is an unordered multiset; replay imposes strict FIFO independently for each directed source/destination pair.
A receive selects the oldest live envelope for that pair, checks the recorded fields and delivers its actual full model payload.
It never searches ahead for a match or reconstructs unobserved payload data.
If distinct payloads share the same recorded headers, FIFO selects the occurrence; there is no uniqueness/ambiguity check.
A drop excludes one occurrence from future observations/deliveries but leaves it undelivered in the model network.
Equal envelopes preserve multiplicity.

Send observations check the latest pending packet for their endpoints without creating or consuming it.
They need not enumerate every emission exactly once: repeated observations may inspect the same occurrence, and unobserved emissions may remain pending.
Optional vote/pre-vote requests, constructor heartbeats and response-send telemetry need not cover every peer.
Promotion-heartbeat coverage is also optional, but a repeated destination ends that group so a later independent send is not swallowed.
Every observed send still needs a compatible model packet; every delivery needs an enabled model transition.

Reconnect commands do not reset queues or invent drops.
Native authentication losses and channel-buffer replacement are not reconstructed.
An unreceived head blocks later receives on that pair unless explicitly dropped.
A FIFO failure does not prove that no execution under another delivery order could match.

### Limits

Successful replay establishes finite compatibility under this policy, not universal C++ refinement, complete native entry-byte/KV equality, complete send accounting, infinite extension, fairness or liveness.
Replay is independent of the model's safety proofs.

The native driver supplies singleton append batches.
Adjacent events do not establish an arbitrary multi-entry production batch boundary.
A native byte-threshold flush can also send a new signature with the old commit index before a sole active leader commits it; replay rejects this intermediate packet because the model append commits atomically.
Neither limitation is handled by inventing intermediate model states.

## Maintaining the replayer

| File                                                                  | Ownership                                                                                                   |
| --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [`ReplayMain.lean`](ReplayMain.lean)                                  | CLI/files/results; calls `prepareEvents`, `reduce` and `replay`                                             |
| [`Input.lean`](../CCFRaft/Replay/Input.lean)                          | JSON access, records, transport validation, command association and node discovery                          |
| [`Reduction.lean`](../CCFRaft/Replay/Reduction.lean)                  | `CCFRaft.Replay.reduce` prepares identities/header; `Reducer.reduce` consumes events and emits instructions |
| [`Interpreter.lean`](../CCFRaft/Replay/Interpreter.lean)              | Actions, read-only state/entry/packet checks and direct model execution                                     |
| [`tests/raft_trace_capture.py`](../../../tests/raft_trace_capture.py) | Native capture, scenario inventory, subprocess lifecycle and suite results                                  |

After reduction identifies the forced leader, outer `reduce` finalizes the header's singleton genesis membership; `replay` initializes that state before executing instructions.

Rules use [`CCF.Parsec`](../../common/README.md#event-parsing), which threads emitted instructions transactionally while parsing an event array.
Keep local recognizers and consumption before emission; speculative matching must not leave instructions behind.
Wrap alternatives and repeated/optional speculative subrules in `attempt`; a failed match restores both cursor and application state.
Repeated rules must consume input, and the final leftover-event check rejects unmatched events.
The farthest failed consumed pattern supplies the diagnostic when parsing ultimately fails before that position.

To add a rule, register it in `reductionRules`, establish grouping/phase/action-construction constraints with `checked` and `read`, then emit model actions and observations.
Model consistency belongs in observations, not in new parser guards that compare snapshots.
Keep partial observations explicit, explain exclusions, and do not repair model state.
For an `ungrouped event`, inspect the recognizer and neighboring native records; for an instruction failure, locate its emission tag and checker before changing the model.
See [DisasterRecovery replay](../../disaster-recovery/replayer/README.md) for the same records/reduction/direct-execution separation.

## Regression and CI checks

The [Virtual C CI job](../../../.github/workflows/ci.yml) captures and replays every `tests/raft_scenarios` scenario with the current native driver and Lean executable.
There is no checked-in capture corpus or separate fixture-refresh pipeline.

The retained tests cover gaps that successful native scenarios cannot exercise:

| Checks                                                                              | Coverage beyond successful scenarios                                                                                                                      |
| ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`tests/Main.lean`](tests/Main.lean)                                                | Malformed input, speculative parser rollback, wrong state/entry/packet observations, read-only checks, FIFO ambiguity/multiplicity and invalid identities |
| [`raft_trace_capture_test.py`](../../../tests/raft_trace_capture_test.py)           | Invalid transport/encoding, binary diagnostics, timeout/spawn failures, partial evidence and stale-success removal                                        |
| [`raft_trace_replay_test.py`](../../../tests/raft_trace_replay_test.py)             | Failed scenarios, invalid inventories/output overlap, subprocess failures and malformed CLI input                                                         |
| Retirement-hook unit test in [`main.cpp`](../../../src/consensus/aft/test/main.cpp) | Multiple hooks crossed by one compaction, repeated compaction and rollback of pending hooks                                                               |

From `lean/ccf-raft`, run the standalone checks without scenario captures:

```sh
lake exe replay-checks
```

From the repository root:

```sh
python3 tests/raft_trace_capture_test.py
python3 tests/raft_trace_replay_test.py
```

Build `ccfraft-replay` first; set `CCF_RAFT_REPLAYER` to its actual executable when using an external build directory.

### Kernel checks

Run `lake check` only in CI, not locally.
The [Lean workflow](../../../.github/workflows/lean.yml) checks `CCFRaft`, `ccfraft-replay` and `replay-checks` separately because the executable roots have distinct `main` declarations.
The allowed axioms are `propext`, `Classical.choice` and `Quot.sound`.
Checks run without build sandboxing, so configuration/build code must be trusted.
Local builds and regressions are not a CI kernel-check pass; replay-only builds do not replace the [model/proof validation](../README.md#validation).
