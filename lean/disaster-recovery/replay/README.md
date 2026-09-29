# Trace replay

`disaster-recovery-replay` checks the node logs of one e2e recovery scenario
against the model:

```text
node logs -(Replay/Records.lean)-> records
          -(Replay/Reduction.lean)-> actions and observations
          -(Replay.lean)-> success or discrepancy
```

Run it from `lean/disaster-recovery`:

```bash
lake exe disaster-recovery-replay --participants N --open-kind QUORUM|FAILOVER LOG...
```

It waits up to 20 seconds for the nodes to log a complete scenario, then
replays it through `Model.transitionSystem` and prints how many actions and
observations it replayed. Any malformed record, reduction error, disabled
action or observation mismatch fails it immediately. Each instruction names
the log line and the reduction rule it comes from, so a failure points back to
both.

The SNP Genoa CI job runs its tests with `CCF_RECOVERY_TRACE=1`, which
`tests/infra/remote.py` passes on to the nodes, so the recovery decision
protocol scenarios only run traced there. After the quorum, failover and
multiple-timeout scenarios in `tests/e2e_operations.py`,
`tests/infra/recovery_trace.py` runs the replayer on the nodes' logs.

## Records

When the `CCF_RECOVERY_TRACE` environment variable is set to a non-empty
value, `src/node/recovery_decision_protocol.cpp` logs
`RDP_TRACE` followed by one JSON object. Every record has `node`,
`expected_locations`, `sequence`, a per-node counter from 0, and `kind`:

| Kind                                                              | Emitted when                                              |
| ----------------------------------------------------------------- | --------------------------------------------------------- |
| `committed`                                                       | The global hook sees a committed phase write, in `post`   |
| `gossip_accepted`, `vote_accepted`, `iamopen_accepted`, `timeout` | A handler succeeded, before its transaction commits       |
| `send`                                                            | A retry is about to dispatch one message, named by `send` |

Handler records hold the phase and timeout phase that `advance()` read and
wrote (`pre`, `pre_timeout`, `post`, `post_timeout`), the `gossips` or
`votes` it evaluated, and any `chosen` node, `open_kind` or `restart` it read,
wrote or requested. Receives name their sender in `source` and the send record
of their message in `caused_by`, as `NODE:SEQUENCE`. Sends of one retry share
a `batch`. Gossip records and sends carry the gossiped `txid`, as
`"view.seqno"`. A log line containing `Failed to trace
recovery-decision-protocol` fails the reduction, as does a receive without
`caused_by`.

## Rules

Records are ordered by each node's `sequence`, not by their position in the
logs. Each receive must name a send of the same message class to its node,
from its source, with the same gossip TxID, and the records must have an
order in which every send precedes its receives.

| Rule                   | Effect                                                                                                  |
| ---------------------- | ------------------------------------------------------------------------------------------------------- |
| `participation`        | A node's first `committed` record, for Gossiping, marks it as a participant                             |
| `retry`, `stale-retry` | A batch is one model retry from a committed state in the batch's phase, placed at the oldest such state |
| `execution`            | An execution that read the latest committed state, and is its message's last execution, took effect     |
| `superseded-execution` | A receive executed again later did not take effect                                                      |
| `stale-execution`      | An execution that read an older committed state did not take effect                                     |
| `gossiping-vote`       | A vote read while Gossiping took effect before the executions that did not read votes                   |
| `committed-write`      | `committed` records confirm the effective phase writes, in order                                        |
| `scenario`             | Each participant ends Open with the expected open kind, or Joining with a restart requested             |

An effective execution is replayed as its state observation, its action, the
notifications it emitted, and the state it recorded writing. A retry is
replayed as its action and the messages it sent. Executions that did not take
effect are not replayed, and their messages stay in the network, as any
undelivered message does.

Sends and timeouts before the participation record are rejected, because the
retry and failover timers start when it is emitted. Receives may come before
it: handlers read locally committed state, and the transaction that starts
the protocol may not be globally committed yet. The newest phase writes may
remain without a `committed` record. A participant that neither completed,
with a `committed` Open record, nor requested a restart in Joining keeps the
logs incomplete.

## What the trace does not tell you

Handler records are emitted before their transactions commit. A handler may be
executed again after a conflict, with the same `caused_by`, or fail to commit.
So the reduction infers which executions took effect. It keeps every account
of a node's executions that the node's later records and `committed` records
allow, and fails if none remains. It then replays the account in which most
executions took effect, preferring accounts in which the node finishes.
Accounts that differ only in state no later record reads are merged.

A record's `sequence` is taken after its reads, so every state it read was
written by lower-sequence executions, or is the initial state. The execution's
own writes are the exception: gossip and vote inserts are in the `gossips` and
`votes` it recorded, and an IAmOpen records its own Joining write and chosen
node, not the phase it read.

Timeouts carry no `caused_by`, so a timeout executed again after a conflict
looks like two timeouts. The reduction treats the first as stale when later
records show the state that the second read.

A vote received while Gossiping only adds its sender to the votes, which no
Gossiping execution reads. It may commit before a lower-sequence execution
that moved the node to Voting, so the reduction replays it before that
execution. It cannot take effect after a record has read the votes in
Voting.

A retry reads one committed state, which may be older than the latest record
of its node. Every committed state in its batch's phase, with, for Voting, the
chosen node it votes for, sends the same messages. So it is replayed at the
oldest one, before any receive that its messages may have caused. It is a
`stale-retry` if its node had already left that state when it sent.

`Config.isValid` requires an instance identifier, which traces do not carry,
so the replayer uses a fixed one. A node that never gossips never reads its
recovered TxID, so the replayer uses `0.0` for it. The model does not store
notifications in the network state, so the replayer re-runs the node's local
step to check them, as the properties do.

A successful replay shows that the reduced execution satisfies the model's
guards and the selected observations. It does not show that the reduction
rules describe every C++ execution. Review them against the C++ they name.
