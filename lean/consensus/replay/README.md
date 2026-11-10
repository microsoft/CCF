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

A trace is one NDJSON file of `{process_id, h_ts, msg}` records from all nodes, in any line order.
Replay orders each process's records by `h_ts`, a counter that must not repeat within the process and may have gaps because other tags share it.
It then splits events into one stream per node; a process may trace several nodes, as `cft_driver` does, but each node's records must come from one process.
Every protocol event must match a named rule; the node whose stream starts with bootstrap selects the initial singleton membership.
Bootstrap accepts bare ticks before genesis, which native code runs asynchronously after the first node becomes leader, and a flush of the genesis entry.
Rules reduce each node's stream independently into groups, one per native lock hold or initialization with its snapshot hooks, and read action inputs from its events; only top-level alternatives backtrack.
A native `replicate` event and the entries that follow it, each starting with its `replicate_entry` event, form one group and one model append, so the model checks commit once per batch, as CCF does.
A `replicate` call rejected at its first entry traces no entries and appends nothing.
Replay repeatedly runs the next group of any node whose group is enabled, with no other group's actions between its actions.
Among enabled groups it prefers the earliest `h_ts`, then the lexically first node, only so that diagnostics are reproducible; counters of different processes are not comparable.
A group whose first action is a receive waits until a matching packet is queued, and one whose first action is `init_as_backup` waits until some node has committed its prefix; other actions must be enabled when their group runs.
If groups remain but none is enabled, replay fails, listing each waiting group.
After bootstrap, each group emits one read-only observation before its model actions, comparing the native group's entry snapshot with the current model state.

A receive delivers any queued model envelope from its sender whose rendered packet has exactly the native packet's fields, with equal values.
It delivers the queued **model payload**, not reconstructing unrecorded native bytes; if matching envelopes differ in payload, for example in AppendEntries entries, which packets omit, replay fails with an ambiguous delivery.
An envelope that is never delivered stays queued, which models loss, so `drop_pending_to` emits no observation or action.
After each rule's actions, the envelopes they queued must equal the rule's native sends, as a multiset of target and rendered packet.
Native code does not trace the `propose_request_vote` send that follows `step_down_and_nominate_successor`, so replay counts each `step_down_and_nominate_successor` as that send.

## Source and checks

- [`Input.lean`](../Consensus/Replay/Input.lean): decode events, order and split them into per-node streams, carry optional command provenance and collect identities.
- [`Reduction.lean`](../Consensus/Replay/Reduction.lean): named rules reducing each node's stream into groups, explicit boundaries and rule-tagged snapshot checks.
- [`Interpreter.lean`](../Consensus/Replay/Interpreter.lean): boundary-state field comparisons, packet selection, send checks, group scheduling and model execution.
- [`ReplayMain.lean`](ReplayMain.lean): single-trace validation CLI.
- [`ReplayDelivery.lean`](../Consensus/Tests/ReplayDelivery.lean): delivery selection among equal rendered packets.
- [`ReplayStreams.lean`](../Consensus/Tests/ReplayStreams.lean): rejection of repeated `h_ts` and of a node traced by two processes, waiting receives and atomic groups.
- [`check-order.py`](check-order.py): verdicts unchanged by shuffling records or by moving each node into its own process.
- [`cft_scenarios_runner.py`](../../../tests/cft_scenarios_runner.py): existing native scenario runner and capture generation.

See [failure fixtures](fixtures/README.md) for examples and expected diagnostics.
