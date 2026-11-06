# CCF consensus protocol trace replay

Replay native `cft_driver` captures against the Lean model of the CCF consensus protocol.
The existing `cft_scenario_test` collects native traces; `consensus-replay` validates one trace per invocation.

## Run replay

Install the [native build prerequisites](../../../doc/contribute/build_ccf.rst), [Lean](https://lean-lang.org/install/) and Python `msgpack`.
The Lean version is [pinned](../../lean-toolchain).
From `lean/consensus`, build the validator and validate a saved trace:

```sh
lake exe cache get
lake build --wfail consensus-replay
./.lake/build/bin/consensus-replay path/to/trace.ndjson
```

To generate captures, build the native driver and run the existing scenario test.
Use a fresh build directory to avoid replaying stale captures from earlier runs.
This needs Python `msgpack` available to CTest:

```bash
set -euo pipefail
cmake -S ../.. -B /tmp/cft-build -GNinja
cmake --build /tmp/cft-build --target cft_driver
ctest --test-dir /tmp/cft-build -VV -R '^cft_scenario_test$' --no-tests=error
for trace in /tmp/cft-build/consensus/raw/*.ndjson; do
  ./.lake/build/bin/consensus-replay "$trace"
done
```

The scenario runner preserves the raw records in `consensus/raw/` alongside the existing TLA-preprocessed captures.
All events use the Fluentd tag `ccf.cft`.
Packet message names are unprefixed, for example `append_entries` and `request_vote`.

## CI captures and replay

The [Lean workflow](../../../.github/workflows/lean.yml) generates native captures and validates every trace.
Separate [package checks](../../../.github/workflows/lean-package.yml) cover the library and executable, imports, formatting, linting, and positive/negative replay fixtures.

## Replay contract

Every protocol event must match a named rule; bootstrap selects the initial singleton membership.
Rules group a head protocol event with its callbacks and read action inputs from those events; only top-level alternatives backtrack.
Actions must be enabled by the model.
After bootstrap, each rule emits one read-only observation before its model actions, comparing the native group's entry snapshot with the current model state.

`retired_committed_tx` records describe nodes-table writes, not global retirement completion.
Input preparation associates earlier metadata with accepted `replicate` events by source node and seqno, filling the model's existing ledger transaction metadata before rule reduction.
Metadata is retained even after a match; unmatched records are not errors and do not change model state.
Matching omits the transaction view, so seqno reuse after rejection or rollback may attach stale metadata or reject a signature with `retirement metadata on signature`.
Use complete raw captures generated with this tracing; older retirement captures need regeneration because cleanup commands no longer supply missing metadata.
Replay does not detect missing metadata, so a pass alone does not establish that retirement writes were captured.

Delivery is strict FIFO per directed node pair, preserving multiplicity and delivering the queued **model payload**, not reconstructing unrecorded native bytes.

## Source and checks

- [`Input.lean`](../Consensus/Replay/Input.lean): decode events, associate retirement metadata, carry optional command provenance and collect identities.
- [`Reduction.lean`](../Consensus/Replay/Reduction.lean): named rules, explicit boundaries and rule-tagged snapshot checks.
- [`Interpreter.lean`](../Consensus/Replay/Interpreter.lean): boundary-state field comparisons, FIFO selection and model execution.
- [`ReplayMain.lean`](ReplayMain.lean): single-trace validation CLI.
- [`cft_scenarios_runner.py`](../../../tests/cft_scenarios_runner.py): existing native scenario runner and capture generation.

See [failure fixtures](fixtures/README.md) for examples and expected diagnostics.

### Kernel checks

`lake check` is **CI-only**, not a local replay command.
The [Lean workflow](../../../.github/workflows/lean.yml) checks the library and executable roots together, allowing only `propext`, `Classical.choice` and `Quot.sound`.
See [model validation](../README.md#validation) for proof checks; a replay pass does not replace them.
