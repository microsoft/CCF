# CCF-Raft trace replay

Replay native `raft_driver` captures against the Lean Raft model.
The existing `raft_scenario_test` collects native traces; `ccfraft-replay` validates one trace per invocation.

## Run replay

Install the [native build prerequisites](../../../doc/contribute/build_ccf.rst), [Lean](https://lean-lang.org/install/) and Python `msgpack`.
The Lean version is [pinned](../../lean-toolchain).
From `lean/ccf-raft`, build the validator and validate a saved trace:

```sh
lake exe cache get
lake build --wfail ccfraft-replay
./.lake/build/bin/ccfraft-replay path/to/trace.ndjson
```

To generate captures, build the native driver and run the existing scenario test.
This needs Python `msgpack` available to CTest:

```bash
set -euo pipefail
cmake -S ../.. -B /tmp/ccf-raft-build -GNinja
cmake --build /tmp/ccf-raft-build --target raft_driver
ctest --test-dir /tmp/ccf-raft-build -VV -R '^raft_scenario_test$' --no-tests=error
for trace in /tmp/ccf-raft-build/consensus/raw/*.ndjson; do
  ./.lake/build/bin/ccfraft-replay "$trace"
done
```

The scenario runner preserves the raw records in `consensus/raw/` alongside the existing TLA-preprocessed captures.

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
- [`ReplayMain.lean`](ReplayMain.lean): single-trace validation CLI.
- [`raft_scenarios_runner.py`](../../../tests/raft_scenarios_runner.py): existing native scenario runner and capture generation.

See [failure fixtures](fixtures/README.md) for examples and expected diagnostics.

### Kernel checks

`lake check` is **CI-only**, not a local replay command.
The [Lean workflow](../../../.github/workflows/lean.yml) checks the library and executable roots separately, allowing only `propext`, `Classical.choice` and `Quot.sound`.
See [model validation](../README.md#validation) for proof checks; a replay pass does not replace them.
