# CCF consensus protocol trace replay

Replay native `cft_driver` captures against the Lean model of the CCF consensus protocol.
The existing `cft_scenario_test` collects native traces; `consensus-replay` validates one trace per invocation, or reports the [outcomes](#outcomes) of several.

## Run replay

Install the [native build prerequisites](../../../doc/contribute/build_ccf.rst), [Lean](https://lean-lang.org/install/) and Python `msgpack`.
The Lean version is [pinned](../../lean-toolchain).
From `lean/consensus`, build the validator and validate a saved trace:

```sh
lake build --wfail consensus-replay
./.lake/build/bin/consensus-replay path/to/trace.ndjson
```

To generate captures, build the native driver and run the existing scenario test.
The driver links the [scenarios](../../../tests/cft_scenarios/README.md), which are Lean programs, so CMake must find `lake`.
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

The scenario runner writes the raw records to `consensus/raw/`.
The Fluentd tag is `ccf.cft`; packet message names are unprefixed, for example `append_entries` and `request_vote`.
For one scenario, `/tmp/cft-build/cft_driver <name> <name>.ndjson` writes the same trace, without the scenario test or `msgpack`.

## Outcomes

Replay names what each model action does: the branch which a handler in [`Node.lean`](../Consensus/Model/Node.lean) takes, or an effect which handlers share, such as a commit.
[`Outcomes.lean`](../Consensus/Replay/Outcomes.lean) declares these outcomes in the order of the handlers.
To report how many steps and traces show each outcome, and which outcomes no trace shows, validate the traces together:

```sh
./.lake/build/bin/consensus-replay --outcomes /tmp/cft-build/consensus/raw/*.ndjson
```

An outcome which no trace shows is a missing scenario, a step which the driver or the reduction cannot produce, or behaviour which the model allows and the implementation lacks.
For example, a nomination without a successor traces no `step_down_and_nominate_successor`, so replay runs no model action for it.

To compare with the implementation, configure the scenario build with `-DCOVERAGE=ON` and run the scenario test.
[`coverage.sh`](../../../scripts/coverage.sh) then lists the lines of [`cft.h`](../../../src/consensus/aft/cft.h) which the scenarios do not execute:

```sh
(cd /tmp/cft-build && "$OLDPWD/../../scripts/coverage.sh" --show-uncovered cft_driver)
```

## Replay contract

Every protocol event must match a named rule; bootstrap selects the initial singleton membership.
Rules group related protocol events and read action inputs from those events; only top-level alternatives backtrack.
Actions must be enabled by the model.
After bootstrap, each rule emits one read-only observation before its model actions, comparing the native group's entry snapshot with the current model state.
A native `replicate` event and the entries that follow it, each starting with its `replicate_entry` event, form one group and one model append, so the model checks commit once per batch, as CCF does.
A `replicate` call rejected at its first entry traces no entries and appends nothing.

A receive delivers any queued model envelope from its sender whose rendered packet has exactly the native packet's fields, with equal values.
It delivers the queued **model payload**, not reconstructing unrecorded native bytes; if matching envelopes differ in payload, for example in AppendEntries entries, which packets omit, replay fails with an ambiguous delivery.
An envelope that is never delivered stays queued, which models loss, so `drop_pending_to` emits no observation or action.
After each rule's actions, the envelopes they queued must equal the rule's native sends, as a multiset of target and rendered packet.
Native code does not trace the `propose_request_vote` send that follows `step_down_and_nominate_successor`, so replay counts each `step_down_and_nominate_successor` as that send.

## Source and checks

- [`Input.lean`](../Consensus/Replay/Input.lean): decode events, carry optional command provenance and collect identities.
- [`Reduction.lean`](../Consensus/Replay/Reduction.lean): named rules, explicit boundaries and rule-tagged snapshot checks.
- [`Interpreter.lean`](../Consensus/Replay/Interpreter.lean): boundary-state field comparisons, packet selection, send checks and model execution.
- [`Outcomes.lean`](../Consensus/Replay/Outcomes.lean): the outcomes of model steps, and their report.
- [`ReplayMain.lean`](ReplayMain.lean): CLI which validates one trace, or reports the outcomes of several.
- [`ReplayDelivery.lean`](../Consensus/Tests/ReplayDelivery.lean): delivery selection among equal rendered packets.
- [`ReplayOutcomes.lean`](../Consensus/Tests/ReplayOutcomes.lean): outcomes of chosen steps, and the report of several traces.
- [`cft_scenarios_runner.py`](../../../tests/cft_scenarios_runner.py): existing native scenario runner and capture generation.

See [failure fixtures](fixtures/README.md) for examples and expected diagnostics.
