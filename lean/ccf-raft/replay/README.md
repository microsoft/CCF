# CCF-Raft trace replay

Replay native `raft_driver` captures against the Lean Raft model.
Python collects traces and runs suites; Lean reduces recorded events to model actions and checks their observations.

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

### Diagnose failures

Start with `summary.json` and `<scenario>.result.json`; the `stage` distinguishes capture from replay.
**Capture-only success is not a replay pass.**
`<scenario>.stdout` is structured `ccf.raft_trace` NDJSON, not console output.
Capture failures preserve console bytes in `.stdout.driver.stdout` / `.stdout.driver.stderr` and incomplete records in `.partial` (or `.stdout.driver.records.msgpack` when JSON cannot represent them).

For `ungrouped event`, inspect the named reduction rules and neighboring records.
For an instruction failure, follow its trace location, rule tag and discrepancy to the emitting rule and observation checker below.
A failure can reflect unsupported evidence or replay policy, not necessarily a native consensus bug.

## Replay contract

Every event must match a named rule; protocol rules emit one action plus read-only observations, while bootstrap emits only observations.
Actions must be enabled by the model; replay never repairs model state to fit a trace.

Checks compare supported recorded state fields, log-entry facts and packet fields, with explicit exclusions for native callbacks inside an atomic model step.
Rechecking unchanged fields after an action is not a fresh native snapshot.
Signature-cache checks compare the recorded first/last indices, not unrecorded interior entries.

Delivery is strict FIFO per directed node pair, preserving multiplicity and delivering the queued **model payload**, not reconstructing unrecorded native bytes.
An explicit drop excludes one occurrence from later delivery.
Send observations need not enumerate every emission, and traces may end with packets pending.
A FIFO failure does not rule out a compatible execution under another delivery order.

A pass establishes compatibility of this finite trace under these rules, not universal C++ refinement, complete log-byte/KV equality, fairness or liveness.
It is independent of the model's safety proofs.
The driver supplies singleton append batches; arbitrary production batches and intermediate packets without an atomic model counterpart are unsupported, including a signature flushed before its singleton leader commits.

## Source and checks

- [`Input.lean`](../CCFRaft/Replay/Input.lean): decode records, validate transport order, associate commands and discover identities.
- [`Reduction.lean`](../CCFRaft/Replay/Reduction.lean): named rules, action emission and native-phase exclusions.
- [`Interpreter.lean`](../CCFRaft/Replay/Interpreter.lean): read-only observations, FIFO selection and model execution.
- [`ReplayMain.lean`](ReplayMain.lean) / [`raft_trace_capture.py`](../../../tests/raft_trace_capture.py): single-trace CLI / capture and suite runner.

The [Virtual C job](../../../.github/workflows/ci.yml) captures and replays all native scenarios.
Standalone rejection checks run with `lake exe replay-checks`; the Python suites are `tests/raft_trace_capture_test.py` and `tests/raft_trace_replay_test.py` from the repository root.
For an external build, set `CCF_RAFT_REPLAYER` to the replay executable when running Python tests.

### Kernel checks

`lake check` is **CI-only**, not a local replay command.
The [Lean workflow](../../../.github/workflows/lean.yml) checks the library and executable roots separately, allowing only `propext`, `Classical.choice` and `Quot.sound`.
See [model validation](../README.md#validation) for proof checks; a replay pass does not replace them.
