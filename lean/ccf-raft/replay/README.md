# CCF-Raft trace replay

Replay native `raft_driver` captures against the Lean Raft model.
Python collects traces and runs suites; Lean checks action-boundary snapshots and replays the corresponding model actions.

## Run replay

Install the [native build prerequisites](../../../doc/contribute/build_ccf.rst), [Lean](https://lean-lang.org/install/) and Python `msgpack`.
The Lean version is [pinned](../../lean-toolchain).
From `lean/ccf-raft`:

```sh
lake exe cache get
lake build --wfail ccfraft-replay
cmake -S ../.. -B /tmp/ccf-raft-build -GNinja
cmake --build /tmp/ccf-raft-build --target raft_driver
python3 ../../tests/raft_trace_capture.py ../../tests/raft_scenarios /tmp/ccf-raft-captures \
  --driver /tmp/ccf-raft-build/raft_driver --replayer .lake/build/bin/ccfraft-replay
```

The suite recursively attempts every scenario and exits nonzero if any fails.
Keep output outside the scenario inventory.
Omit `--replayer` for capture only; use `--timeout N` to override the 60-second per-scenario timeout.
For existing builds, substitute the actual driver/replayer executable paths.

### Rerun saved captures

From the same directory, replay one generated trace:

```sh
lake exe ccfraft-replay /tmp/ccf-raft-captures/retire_backup.stdout
```

This prints JSON counts on success or a diagnostic on failure; it does not update suite result files.
To replay the whole saved suite without starting the driver:

```sh
python3 ../../tests/raft_trace_capture.py ../../tests/raft_scenarios /tmp/ccf-raft-results \
  --raw-directory /tmp/ccf-raft-captures --replayer .lake/build/bin/ccfraft-replay
```

Saved captures test the replayer, not changed native code: rebuild the driver and capture again to test a native fix.
Captures must include the current boundary markers; regenerate older captures rather than guessing their grouping.

### Diagnose failures

Start with `summary.json` and `<scenario>.result.json`; the `stage` distinguishes capture from replay.
**Capture-only success is not a replay pass.**
`<scenario>.stdout` is structured `ccf.raft_trace` NDJSON, not console output.
Capture failures preserve console bytes in `.stdout.driver.stdout` / `.stdout.driver.stderr` and incomplete records in `.partial` (or `.stdout.driver.records.msgpack` when JSON cannot represent them).

For `ungrouped event`, inspect the named reduction rules and neighboring records.
For an instruction failure, follow its trace location, rule tag and diagnostic to the emitting rule and interpreter below.
A failure can reflect unsupported evidence or replay policy, not necessarily a native consensus bug.

## Replay contract

Every event must match a named rule; protocol rules emit one action, while bootstrap selects the initial singleton membership.
Rules peek action inputs before consuming events, and only top-level alternatives backtrack.
`election_timeout` and `check_quorum` identify timeout entry points; `become_pre_vote_candidate_end`, `become_leader_end`, `add_configuration_end` and `commit_end` delimit callbacks.
Within an append, `batch_flush` identifies the subsequent send records as flush choices rather than configuration-created heartbeats.
Their destinations and packet end indexes become arguments of the same model append action, which flushes before committing.
Actions must be enabled by the model; replay never repairs model state to fit a trace.

The dispatcher emits one read-only observation before each action, comparing the recorded node snapshot with the current model state.
Snapshot checks accept partial objects but reject empty objects and unknown fields.
Individual rules emit no observations; intermediate callbacks and emitted packet contents are not checked.
There is no final post-action snapshot check: an action's effects are checked only where a later action-boundary snapshot exposes them.

Delivery is strict FIFO per directed node pair, preserving multiplicity and delivering the queued **model payload**, not reconstructing unrecorded native bytes.
Received packet fields must match that queued payload; an explicit drop excludes one queued occurrence from later delivery.
Not every modeled emission needs a matching native send event, and traces may end with packets pending.
A FIFO failure does not rule out a compatible execution under another delivery order.

A pass establishes an enabled model-action sequence with matching action-boundary snapshots and receive packets, not universal C++ refinement, complete log-byte/KV equality, fairness or liveness.
It is independent of the model's safety proofs.
The driver supplies singleton append batches; arbitrary production batches and intermediate packets without an atomic model counterpart are unsupported.

## Source and checks

- [`Input.lean`](../CCFRaft/Replay/Input.lean): decode records, validate transport order, associate commands and discover identities.
- [`Reduction.lean`](../CCFRaft/Replay/Reduction.lean): named rules, explicit boundaries and the dispatcher's snapshot check.
- [`Interpreter.lean`](../CCFRaft/Replay/Interpreter.lean): boundary-state field comparisons, FIFO selection and model execution.
- [`ReplayMain.lean`](ReplayMain.lean) / [`raft_trace_capture.py`](../../../tests/raft_trace_capture.py): single-trace CLI / capture and suite runner.

The [Virtual C job](../../../.github/workflows/ci.yml) captures and replays all native scenarios.
Standalone rejection checks run with `lake exe replay-checks`; the Python suites are `tests/raft_trace_capture_test.py` and `tests/raft_trace_replay_test.py` from the repository root.
For an external build, set `CCF_RAFT_REPLAYER` to the replay executable when running Python tests.

### Kernel checks

`lake check` is **CI-only**, not a local replay command.
The [Lean workflow](../../../.github/workflows/lean.yml) checks the library and executable roots separately, allowing only `propext`, `Classical.choice` and `Quot.sound`.
See [model validation](../README.md#validation) for proof checks; a replay pass does not replace them.
