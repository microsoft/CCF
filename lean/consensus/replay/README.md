# CCF consensus protocol trace replay

Replay native `cft_driver` captures against the Lean model of the CCF consensus protocol.
The existing `cft_scenario_test` collects native traces; `consensus-replay` validates one trace per invocation.

## Run replay

Install the [native build prerequisites](../../../doc/contribute/build_ccf.rst), [Lean](https://lean-lang.org/install/) and Python `msgpack`.
The Lean version is [pinned](../../lean-toolchain).
From `lean/consensus`, build the validator and validate a saved trace:

```sh
lake build --wfail consensus-replay
./.lake/build/bin/consensus-replay path/to/trace.msgpack
```

To read a trace, [`dump-trace.py`](../../../scripts/dump-trace.py) dumps it as NDJSON, a record per line, which [`pack-trace.py`](../../../scripts/pack-trace.py) packs again:

```sh
../../scripts/dump-trace.py < path/to/trace.msgpack | grep -n ccf.cft
```

Replay names a record as `<trace>:<n>`, by its number among the records of every tag: it is line `n` of the dump, which `grep -n` prefixes.

To generate captures, build the native driver and run the existing scenario test.
The driver links the [scenarios](../../../tests/cft_scenarios/README.md), which are Lean programs, so CMake must find `lake`.
Use a fresh build directory to avoid replaying stale captures from earlier runs.
This needs Python `msgpack` available to CTest:

```bash
set -euo pipefail
cmake -S ../.. -B /tmp/cft-build -GNinja
cmake --build /tmp/cft-build --target cft_driver
ctest --test-dir /tmp/cft-build -VV -R '^cft_scenario_test$' --no-tests=error
for trace in /tmp/cft-build/consensus/raw/*.msgpack; do
  ./.lake/build/bin/consensus-replay "$trace"
done
```

The scenario runner writes the raw MessagePack records to `consensus/raw/`.
The Fluentd tag is `ccf.cft`; packet message names are unprefixed, for example `append_entries` and `request_vote`.

## Replay contract

A trace is a stream of Fluentd Forward MessagePack records `[tag, EventTime|nil, {pid, m_ts, msg}]` from all nodes, in any record order, where `pid` identifies the process that emitted the record.
Replay skips records whose `tag` is not `ccf.cft` without UTF-8 decoding their payloads, so a capture may hold events of other tags such as `ccf.log`.
It reads a `ccf.cft` record into the type of its `function`, as [`cft_trace_msgpack.h`](../../../src/consensus/aft/cft_trace_msgpack.h) writes it: `function` is the first key of `msg`, and `msg` the first key of a `packet`.
Other keys may be in any order; an unknown key is skipped in an event, and rejected in a `state` or a `packet`.
A record which does not read as its type fails the trace, with `--lenient` too.
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
`--lenient` accepts a trace that is incomplete, for example because a node was killed before it sent its last events: a node's groups end before its first event that no rule consumes, and replay ends once no group may run.
The reported `watermark` is then the least fraction of a node's events that replay consumed; a group that the model disagrees with still fails the trace.
After bootstrap, each group emits one read-only observation before its model actions, comparing the native group's entry snapshot with the current model state.
A tick with no action emits no group, so its snapshot is not compared: the node's next group compares the state it starts from.
A trace may so have no group at all.

A receive delivers any queued model envelope from its sender whose rendered packet has exactly the native packet's fields, with equal values.
It delivers the queued **model payload**, not reconstructing unrecorded native bytes; if matching envelopes differ in payload, for example in AppendEntries entries, which packets omit, replay fails with an ambiguous delivery.
An envelope that is never delivered stays queued, which models loss, so `drop_pending_to` emits no observation or action.
After each rule's actions, the envelopes they queued must equal the rule's native sends, as a multiset of target and rendered packet.

## Source and checks

- [`Trace.lean`](../Consensus/Replay/Trace.lean): the types of trace records, each declared with the reader of its MessagePack map.
- [`Input.lean`](../Consensus/Replay/Input.lean): read events, order and split them into per-node streams and collect identities.
- [`Reduction.lean`](../Consensus/Replay/Reduction.lean): named rules, each reducing one lock hold of a node, explicit boundaries and rule-tagged snapshot checks.
- [`Groups.lean`](../Consensus/Replay/Groups.lean): runs the rules over each node's stream, taking each rule's instructions as a group.
- [`Interpreter.lean`](../Consensus/Replay/Interpreter.lean): boundary-state field comparisons, packet selection, send checks, group scheduling and model execution.
- [`ReplayMain.lean`](ReplayMain.lean): single-trace validation CLI.
- [`ReplayDelivery.lean`](../Consensus/Tests/ReplayDelivery.lean): delivery selection among equal rendered packets.
- [`cft_scenarios_runner.py`](../../../tests/cft_scenarios_runner.py): existing native scenario runner and capture generation.

See [failure fixtures](fixtures/README.md) for examples and expected diagnostics.
