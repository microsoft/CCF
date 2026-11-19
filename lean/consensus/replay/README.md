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

## Replay contract

A trace is one NDJSON file of `{pid, m_ts, msg}` records from all nodes, in any line order, where `pid` identifies the process that emitted the record.
Replay orders each process's records by `m_ts`, a counter that must not repeat within the process and may have gaps because other tags share it.
It then splits events into one stream per node; a process may trace several nodes, as `cft_driver` does, but each node's records must come from one process.
Native code emits consensus events while holding the node's consensus lock, so a node's `m_ts` order is the order of its lock holds, whichever threads took them.
Every protocol event must match a named rule; the node whose stream starts with bootstrap selects the initial singleton membership.
Bootstrap accepts bare ticks and nominations before genesis, which native code runs asynchronously after the first node becomes leader, and a flush of the genesis entry.
Rules reduce each node's stream independently into groups, one per hold of the consensus lock, and read action inputs from its events; only top-level alternatives backtrack.
A native `replicate` event and the entries that follow it, each starting with its `replicate_entry` event, form one group and one model append, so the model checks commit once per batch, as CCF does.
A `replicate` call rejected at its first entry traces no entries and appends nothing.
Snapshot installation runs its `add_configuration` and `retired_committed_tx` hooks outside the lock, before the node's `init_as_backup`; the hooks form no group, so the initialization's group starts at `init_as_backup` and groups that fall between them, such as ticks of any node, replay as usual.

Replay repeatedly runs the next group of some node, with no other group's actions between its actions.
It runs the enabled group with the earliest `ts`, the wall-clock emission time in nanoseconds that a record may carry; without it `m_ts` stands in, which is the order of execution within a process and otherwise only makes diagnostics reproducible, as counters of different processes are not comparable.
A group whose first action is a receive waits until a matching packet is queued, and one whose first action is `init_as_backup` waits until some node has committed its prefix; other actions must be enabled when their group runs.
Clocks of different hosts therefore only choose among enabled groups, and cannot fail a trace.
If groups remain but none may run, replay fails, listing first the groups that can never run, such as a receive whose packet is never sent.
`--schedule` prints the groups in the order they ran, ending with any that failed.
After bootstrap, each group emits one read-only observation before its model actions, comparing the native group's entry snapshot with the current model state.

A receive delivers any queued model envelope from its sender whose rendered packet has exactly the native packet's fields, with equal values.
It delivers the queued **model payload**, not reconstructing unrecorded native bytes; if matching envelopes differ in payload, for example in AppendEntries entries, which packets omit, replay fails with an ambiguous delivery.
An envelope that is never delivered stays queued, which models loss, so `drop_pending_to` emits no observation or action.
After each rule's actions, the envelopes they queued must equal the rule's native sends, as a multiset of target and rendered packet.

## Source and checks

- [`Input.lean`](../Consensus/Replay/Input.lean): decode events, order and split them into per-node streams and collect identities.
- [`Reduction.lean`](../Consensus/Replay/Reduction.lean): named rules, each reducing one lock hold of a node, explicit boundaries and rule-tagged snapshot checks.
- [`Groups.lean`](../Consensus/Replay/Groups.lean): runs the rules over each node's stream, taking each rule's instructions as a group.
- [`Interpreter.lean`](../Consensus/Replay/Interpreter.lean): boundary-state field comparisons, packet selection, send checks, group scheduling and model execution.
- [`ReplayMain.lean`](ReplayMain.lean): single-trace validation CLI.
- [`ReplayDelivery.lean`](../Consensus/Tests/ReplayDelivery.lean): delivery selection among equal rendered packets.
- [`cft_scenarios_runner.py`](../../../tests/cft_scenarios_runner.py): existing native scenario runner and capture generation.

See [failure fixtures](fixtures/README.md) for examples and expected diagnostics.
