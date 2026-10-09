# Trace replay

`disaster-recovery-replay` checks the node logs of one e2e recovery scenario
against the model:

```text
node logs -(DisasterRecovery/TraceValidation/Records.lean)-> records
          -(DisasterRecovery/TraceValidation/Reduction.lean)-> actions and observations, in commit order
          -(DisasterRecovery/TraceValidation.lean)-> success or discrepancy
```

It has its own Lake package in `lean/disaster-recovery/replayer`, which builds
only the replayer and the modules it imports. They import no Mathlib module, so
the package has no dependencies. Run it from there:

```bash
lake exe disaster-recovery-replay --participants N [--wait-ms N] LOG...
```

By default it waits up to 20 seconds for the nodes to log a complete
scenario; `--wait-ms 0` makes any incompleteness fail immediately. It replays
the reduced trace through `Model.transitionSystem`, prints how many actions
and observations it replayed, and checks the scenario. Malformed records,
records that no commit order explains, disabled actions and observation
mismatches fail it immediately. Each instruction names the log line and the
rule it comes from, so a failure points back to both.

The recovery decision protocol scenarios only run in the SNP Genoa CI job,
which sets `CCF_RECOVERY_TRACE=1` for its tests, and `tests/infra/remote.py`
passes it on to the nodes. After the quorum, failover and multiple-timeout
scenarios in `tests/e2e_operations.py`, `tests/infra/recovery_trace.py` runs
the replayer on the nodes' logs.
`.github/workflows/lean.yml` checks the records of committed fixtures of those
three scenarios against the schema, then builds the replayer and runs
`check-fixtures.sh` on them.

## Records

When the `CCF_RECOVERY_TRACE` environment variable is set to a non-empty
value, `src/node/recovery_decision_protocol.cpp` logs `RDP_TRACE` followed by
one JSON object. Every record has `node`, `sequence`, a per-node counter from
0, and `kind`:

| Kind                                                              | Emitted when                                                       |
| ----------------------------------------------------------------- | ------------------------------------------------------------------ |
| `start`                                                           | The global hook sees the protocol start in Gossiping, at `version` |
| `gossip_accepted`, `vote_accepted`, `iamopen_accepted`, `timeout` | The endpoint's locally committed function runs                     |
| `send`                                                            | A retry is about to dispatch one `message` to its `target`         |

`start` also carries the `expected_locations`. Handler records hold the phase
and timeout phase that `advance()` read and wrote (`pre`, `pre_timeout`,
`post`, `post_timeout`), and any `chosen` node, `open_kind` or `restart` it
read, wrote or requested. An IAmOpen's `pre` and `chosen` are its own Joining
writes, which `advance()` then reads. Only executions whose transaction
committed are logged, with the seqno of the TxID that CCF reported as their
`version`: the version the transaction committed at if it wrote, and the
version it read at otherwise. A vote or IAmOpen always writes, and any other
write that the replay can observe changes a phase, so the replayer treats an
execution that changes neither phase as a read.

Receives name their sender in `source`. A send's `message` is `gossip`, `vote`
or `iamopen`. The sends of one retry share a `batch` and the version of the
`sm_state` value the retry read, in `pre_version`. Gossip records and sends
carry the gossiped `txid`, as `"view.seqno"`.

`trace.schema.json` is the JSON Schema of the records: the fields of each kind
and the values that the C++ writes for them, but none of the protocol's rules,
which the replay checks. `check-schema.py LOG...`, which needs the `jsonschema`
Python package, checks the records of node logs against it.

## Rules

The reduction orders each node's records as they committed, and tells logs
that are still growing, which it waits for, from logs that no order explains,
which fail. The replay checks everything else.

| Rule           | Effect                                                                                                             |
| -------------- | ------------------------------------------------------------------------------------------------------------------ |
| `config`       | Every node's `start` record carries the same `expected_locations`                                                  |
| `start`        | Each node starts once, and every execution is at or after its start version                                        |
| `delivery`     | Each receive takes an earlier send of its message from its `source` that no other receive has taken                |
| `commit-order` | A node's executions run in version order; an execution that wrote nothing runs after the write at its version      |
| `retry`        | A retry runs right after the `sm_state` write at the version it read                                               |
| `scenario`     | No more nodes log than the participants, each ends Opening, Open or Joining after a restart request, and one opens |

A replayed execution is its state observation, its action, the notifications
it emitted and the state it recorded writing. A retry is its action and the
messages it sent. Items of different nodes are interleaved so that each
message is received after it is sent. As in the model's network, any queued
copy of a message can be the one received, so receives are matched to sends
by content.

The e2e tests do not wait for the timeout from Opening to Open, so the
scenario accepts Opening. Which kind of opening a scenario should end with is
left to the e2e tests: the replay already checks each recorded open kind
against the model. The scenario is checked after the replay, so its failures
report how many actions and observations replayed.

## Why this is the commit order

CCF gives each transaction that writes a new version, in the order in which
transactions commit, and a transaction that writes nothing reads the state at
the version it reports. So ordering a node's executions by version, with each
write before the transactions that read it, is the order in which they took
effect. A retry reads one snapshot, and its messages depend only on the phase
and chosen node, which are written together, so it can run right after the
`sm_state` write it read. Executions whose transactions did not commit are not
logged, and have no effect on the KV.

A successful replay shows that one model execution explains every record:
each action is enabled, and each observation matches. It does not show
behaviour that no record shows, or liveness.

## Fixtures

`fixtures/` holds the trace lines of the quorum, failover and multiple-timeout
scenarios of one SNP run. Each scenario's `invalid/` and `valid/` hold traces
that the replayer must reject and accept, as diffs against the recorded ones.
`field.KIND.FIELD.N.diff` differs from them only in `FIELD` of the `N`th `KIND`
record, and the others are named after how they differ. Commit order is
covered by named invalid traces rather than by ones that differ only in
`version`. `check-fixtures.sh` replays the recorded, valid and invalid traces:

```bash
cd lean/disaster-recovery/replayer
lake build
./check-fixtures.sh
```

To refresh the fixtures from a traced SNP run, download its
`logs-caci-snp-genoa` artifact and keep the `RDP_TRACE` part of each line of
the three scenarios' node logs. The `scenario.json` files do not change. The
valid and invalid traces are diffs against the recorded ones, so refreshing
the recorded traces means recreating each diff, as its name describes.

```bash
gh run download RUN_ID --repo microsoft/CCF --name logs-caci-snp-genoa --dir artifact
W=artifact/build/workspace/platform_snp_platform_tests_recovery_decision_protocol
F=lean/disaster-recovery/replayer/fixtures
refresh() { for s in "${@:2}"; do grep -o 'RDP_TRACE .*' "$W$s/out" > "$F/$1/$(basename "$W$s").out"; done; }
refresh quorum _3 _4 _5
refresh timeout _timeout_3
refresh multiple-timeout _multiple_timeout_3 _multiple_timeout_4 _multiple_timeout_5
```
