# CCF consensus protocol trace replay

Replay native `cft_driver` captures against the Lean model of the CCF consensus protocol.
The existing `cft_scenario_test` collects native traces; `consensus-replay` validates one trace per invocation.

## Run replay

Install the [native build prerequisites](../../../doc/contribute/build_ccf.rst), [Lean](https://lean-lang.org/install/) and Python `msgpack`.
The Lean version is [pinned](../../lean-toolchain).
From `lean/consensus`, build the validator and validate a saved trace:

```sh
lake build --wfail consensus-replay
./.lake/build/bin/consensus-replay path/to/trace.ndjson
```

To generate captures, build the native driver and run the existing scenario test.
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

The scenario runner writes the raw records to `consensus/raw/`.
The Fluentd tag is `ccf.cft`; packet message names are unprefixed, for example `append_entries` and `request_vote`.

## CI captures and replay

The [Lean workflow](../../../.github/workflows/lean.yml) generates native captures on the existing Azure Linux runner while checking Lean packages independently on Ubuntu 26.04.
Consensus runs in the same package matrix as common, consistency, disaster-recovery, and KV.
Its package check retains separate library and executable kernel checks, import/architecture checking, formatting, linting, and positive/negative replay fixtures.

The independent replay job waits only for native captures, not package validation.
It installs the pinned Lean toolchain, builds `consensus-replay` directly, downloads the captures from the same workflow run, and validates every native trace.
The executable is built and run on the same Ubuntu 26.04 runner; no executable artifact is uploaded or downloaded.
Missing artifacts, empty trace selections, build failures, and replay failures fail the job explicitly.
There is no runner held idle polling capture status.
See [CI package isolation](../../disaster-recovery/README.md#ci-package-isolation) for the aggregate gate and package inventory rules.

## Replay contract

Every event must match a named rule; bootstrap selects the initial singleton membership.
Rules read action inputs from their matching events, and only top-level alternatives backtrack.
Actions must be enabled by the model.
After bootstrap, each rule emits one read-only observation before its model actions, comparing the native group's entry snapshot with the current model state.

Delivery is strict FIFO per directed node pair, preserving multiplicity and delivering the queued **model payload**, not reconstructing unrecorded native bytes.

## Source and checks

- [`Input.lean`](../Consensus/Replay/Input.lean): decode events, carry optional command provenance and collect identities.
- [`Reduction.lean`](../Consensus/Replay/Reduction.lean): named rules, explicit boundaries and rule-tagged snapshot checks.
- [`Interpreter.lean`](../Consensus/Replay/Interpreter.lean): boundary-state field comparisons, FIFO selection and model execution.
- [`ReplayMain.lean`](ReplayMain.lean): single-trace validation CLI.
- [`cft_scenarios_runner.py`](../../../tests/cft_scenarios_runner.py): existing native scenario runner and capture generation.

See [failure fixtures](fixtures/README.md) for examples and expected diagnostics.

### Kernel checks

`lake check` is **CI-only**, not a local replay command.
The [Lean workflow](../../../.github/workflows/lean.yml) checks the library and executable roots together, allowing only `propext`, `Classical.choice` and `Quot.sound`.
See [model validation](../README.md#validation) for proof checks; a replay pass does not replace them.
