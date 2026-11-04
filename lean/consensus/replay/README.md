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
This needs Python `msgpack` available to CTest:

```bash
set -euo pipefail
shopt -s failglob
cmake -S ../.. -B /tmp/cft-build -GNinja
cmake --build /tmp/cft-build --target cft_driver
ctest --test-dir /tmp/cft-build -VV -R '^cft_scenario_test$' --no-tests=error
for trace in /tmp/cft-build/consensus/raw/*.ndjson; do
  ./.lake/build/bin/consensus-replay "$trace"
done
```

The scenario runner preserves the raw records in `consensus/raw/` alongside the existing TLA-preprocessed captures.
The Fluentd tag is `ccf.cft`; packet message names are unprefixed, for example `append_entries` and `request_vote`.

## CI captures and replay

The [Lean workflow](../../../.github/workflows/lean.yml) generates native captures on the existing Azure Linux runner while checking Lean packages independently on Ubuntu 26.04.
Consensus runs in the same package matrix as common, consistency, disaster-recovery, and KV.
Its package check retains separate library and executable kernel checks, import/architecture checking, formatting, linting, and positive/negative replay fixtures.

The independent replay job waits only for native captures, not package validation.
It installs the pinned Lean toolchain, restores Mathlib caches, builds `consensus-replay` directly, downloads the captures from the same workflow run, and validates every native trace.
The executable is built and run on the same Ubuntu 26.04 runner; no executable artifact is uploaded or downloaded.
Missing artifacts, empty trace selections, build failures, and replay failures fail the job explicitly.
There is no runner held idle polling capture status.
See [CI package isolation](../../disaster-recovery/README.md#ci-package-isolation) for the aggregate gate and package inventory rules.

## Replay contract

Every event must match a named rule; bootstrap selects the initial singleton membership.
Rules read action inputs from their matching events, and only top-level alternatives backtrack.
Actions must be enabled by the model.
Consecutive packets to the same peer within a periodic or append-flush boundary reduce to one complete `sendEntries` pass, not independently scheduled batches.
After bootstrap, each rule checks the native group's entry snapshot against model state before executing its protocol action.
Retirement inputs may be enqueued before this check; they only take effect when the protocol action reaches the matching commit.

Delivery is strict FIFO per directed node pair, preserving multiplicity and delivering the queued **model payload**, not reconstructing unrecorded native bytes.

### Global-commit retirement hooks

Native `retired_committed` events supply retirement inputs (`seqno` and ordered `node_ids`) rather than ledger metadata.
The reducer queues these inputs for consumption at the enclosing commit, including intermediate commits within a receive.
Nodes are processed in order, so a retiring primary chooses its successor after earlier peer removals but before later ones and before discarding old configurations.
Invalid or unconsumed inputs reject replay.

### Scope

Replay ignores driver commands and assumes complete, ordered native events, a singleton bootstrap and paired replication/configuration events.
It does not validate application data or the KV's retirement decisions, and does not model rollback-retained peers or `remove_deleted_nodes`.

## Replay checks

CI replays every scenario capture and checks the existing valid and invalid trace fixtures.
The [`retirement_hook_order`](../../../tests/cft_scenarios/retirement_hook_order) scenario removes a more-replicated peer before self-retirement, so reversing that order selects the wrong successor.
The [empty-hook fixture](fixtures/valid/empty-retirement-hook.ndjson) checks consumption of an event with no node IDs.

## Source and checks

- [`Input.lean`](../Consensus/Replay/Input.lean): decode native events, ignore driver commands and collect identities.
- [`Reduction.lean`](../Consensus/Replay/Reduction.lean): named rules, explicit boundaries and rule-tagged snapshot checks.
- [`Interpreter.lean`](../Consensus/Replay/Interpreter.lean): boundary-state field comparisons, FIFO selection and model execution.
- [`ReplayMain.lean`](ReplayMain.lean): single-trace validation CLI.
- [`cft_scenarios_runner.py`](../../../tests/cft_scenarios_runner.py): existing native scenario runner and capture generation.

See [failure fixtures](fixtures/README.md) for examples and expected diagnostics.

### Kernel checks

`lake check` is **CI-only**, not a local replay command.
The [Lean workflow](../../../.github/workflows/lean.yml) checks the library and executable roots together, allowing only `propext`, `Classical.choice` and `Quot.sound`.
See [model validation](../README.md#validation) for proof checks; a replay pass does not replace them.
