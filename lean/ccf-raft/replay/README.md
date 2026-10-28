# CCF-Raft trace replay

Replay native `raft_driver` captures against the Lean Raft model.
Python collects traces and runs suites; Lean checks native-entry snapshots and replays the corresponding model actions.

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

## Replay contract

Every event must match a named rule; bootstrap selects the initial singleton membership.
Rules read action inputs from their matching events, and only top-level alternatives backtrack.
Actions must be enabled by the model.
After bootstrap, each rule emits one read-only observation before its model actions, comparing the native group's entry snapshot with the current model state.

Delivery is strict FIFO per directed node pair, preserving multiplicity and delivering the queued **model payload**, not reconstructing unrecorded native bytes.

## Source and checks

- [`Input.lean`](../CCFRaft/Replay/Input.lean): decode events, carry optional command provenance and collect identities.
- [`Reduction.lean`](../CCFRaft/Replay/Reduction.lean): named rules, explicit boundaries and rule-tagged snapshot checks.
- [`Interpreter.lean`](../CCFRaft/Replay/Interpreter.lean): boundary-state field comparisons, FIFO selection and model execution.
- [`ReplayMain.lean`](ReplayMain.lean) / [`raft_trace_capture.py`](../../../tests/raft_trace_capture.py): single-trace CLI / capture and suite runner.

The Python suites are `tests/raft_trace_capture_test.py` and `tests/raft_trace_replay_test.py` from the repository root.
For an external build, set `CCF_RAFT_REPLAYER` to the replay executable when running Python tests.

See [failure fixtures](fixtures/README.md) for examples and expected diagnostics.

### Kernel checks

`lake check` is **CI-only**, not a local replay command.
The [Lean workflow](../../../.github/workflows/lean.yml) checks the library and executable roots separately, allowing only `propext`, `Classical.choice` and `Quot.sound`.
See [model validation](../README.md#validation) for proof checks; a replay pass does not replace them.
