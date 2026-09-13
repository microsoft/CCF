# Recovery decision protocol trace format

The media type is newline-delimited JSON. Each nonempty line is one committed
semantic observation. This format is used by CI with the producer and validator
from the same source revision; it is not a versioned compatibility contract.

## Record

Every record is a JSON object with these required fields:

| Field                | Type             | Meaning                             |
| -------------------- | ---------------- | ----------------------------------- |
| `instance`           | string           | Stable recovery instance identifier |
| `expected_locations` | array of strings | Stable configured location names    |
| `node`               | string           | Observed node/location name         |
| `sequence`           | natural number   | Per-node sequence, starting at zero |
| `kind`               | string           | Event kind from the table below     |

These fields are optional unless the event requires them:

| Field        | Type             | Meaning                                                                   |
| ------------ | ---------------- | ------------------------------------------------------------------------- |
| `message_id` | string           | Globally unique ID for an observed send or receive                        |
| `caused_by`  | string           | `message_id` of the send that caused a receive                            |
| `source`     | string           | Sender location name                                                      |
| `view`       | natural number   | Gossip TxID view                                                          |
| `seqno`      | natural number   | Gossip TxID sequence number                                               |
| `pre`        | phase string     | Observable phase before the event                                         |
| `post`       | phase string     | Observable phase after the event                                          |
| `open_kind`  | open-kind string | `QUORUM` or `FAILOVER` for an `open` observation                          |
| `send`       | string           | Send class and destination: `gossip:NAME`, `vote:NAME`, or `iamopen:NAME` |

Phase strings are `GOSSIPING`, `VOTING`, `OPENING`, `JOINING`, and `OPEN`.
Unknown fields are ignored as instrumentation metadata.
All integers must be nonnegative Lean `Nat` values.

## Event kinds

| Kind               | Required event fields                                                                                 | Canonical boundary                          |
| ------------------ | ----------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| `start`            | `pre`, `post`                                                                                         | Protocol state initialized                  |
| `gossip_accepted`  | `message_id`, `caused_by`, `source`, `view`, `seqno`, `pre`, `post`                                   | Validated gossip callback committed         |
| `vote_accepted`    | `message_id`, `caused_by`, `source`, `pre`, `post`                                                    | Validated vote callback committed           |
| `iamopen_accepted` | `message_id`, `caused_by`, `source`, `pre`, `post`                                                    | IAmOpen selected peer and Joining committed |
| `timeout`          | `pre`, `post`                                                                                         | Timeout transaction committed               |
| `send`             | `send` in `class:destination` form, `message_id`, `pre`, `post`; gossip also requires `view`, `seqno` | Transport send observed                     |
| `open`             | `open_kind`, `pre`, `post`                                                                            | Service-open transition committed           |
| `join_restart`     | `pre`, `post`                                                                                         | Joining/restart side effect committed       |
| `complete`         | `pre`, `post`                                                                                         | Opening-to-Open completion committed        |

Every receive uses `caused_by` to identify an earlier `send`. The validator
checks the sender, destination, message class, gossip TxID payload, and single
consumption of that send. Message IDs, causal IDs, and source names must be
nonempty, and message IDs cannot be reused. Non-receive events must omit
`caused_by`.

Each participating configured node has one `start` event at sequence zero. The
first creates the replay system; later starts activate other configured nodes
without resetting it. Non-start events for a node
before its start are rejected. Configured but unavailable nodes may have no
start event. Subsequent records must preserve `instance` and
`expected_locations`, refer to a configured node, and increment that node's
sequence exactly. Empty instance IDs, empty configurations, empty location
names, and duplicate configured names are rejected.

The NDJSON record order is a topological linearization of the distributed
trace. Per-node `sequence` and `caused_by` edges define the ordering; wall-clock
timestamps do not.

## Strict replay

A trace describes a complete successful execution: every transport send,
accepted receive, committed timeout, and one-shot effect is explicit.
`DisasterRecoveryTrace/Protocol/Trace/Replay.lean` folds these events over one deterministic `SystemState`.
It retains only observed sends, consumed causal IDs, per-node sequences, and
pending ordered retry-send batches and `open`, `join_restart`, or `complete`
effects.

The validator rejects the first event that is not enabled by the canonical
model or whose recorded pre/post state, cause, or effect does not match. It
reports this shortest failing prefix with the current phase and expected event
classes.

Rejected HTTP/validation inputs do not mutate the modeled state and are not
part of this trace format. Supporting rejection behavior or incomplete traces
would require explicit changes to the instrumentation and deterministic replay.

## C++ instrumentation

Configure CCF with `-DCCF_RECOVERY_TRACE=ON` to enable implementation tracing.
Accepted receive and timeout events are written to
`public:ccf.internal.recovery_decision_protocol.trace_events` in the same
transaction as the modeled state change. A global commit hook emits them only
after commit, followed by any `open`, `join_restart`, or `complete` effect from
that transition. Aborted transactions therefore emit nothing.
In trace-enabled builds the joiner restart request is issued by the trace hook
after the committed receive and `join_restart` records are emitted. Default
builds issue the restart from the committed state hook. Both modes therefore
wait for global commit before requesting restart.

The committed start hook emits `start` before scheduling retry and failover
tasks. Transport sends are emitted immediately before dispatch and propagate
their generated `message_id` in the internal request as `trace_message_id`;
the committed receive records it as `caused_by`.
If a retry observes a locally committed phase that is not yet globally visible
to the trace hook, tracing defers that retry invocation. Once phases match, the
trace lock serializes the complete send batch against later commit publication.

Each log record contains `RDP_TRACE ` followed by the event object.
`../../tests/infra/recovery_trace.py` passes the original participating node log
paths and scenario expectations to the Lean validator without reading or
rewriting their contents. Lean extracts the records from text logs or JSON
`msg` envelopes, topologically orders them by per-node sequence and causal send
edges, and replays them. The quorum, failover, and multiple-timeout SNP e2e
scenarios call this helper. The original logs are retained with the SNP job's
uploaded artifacts, so a failed replay can be reproduced locally.

Lean additionally requires scenario-specific terminal evidence before accepting
the trace: the expected number of participating nodes and open kind, at least
one completed opener, and a `complete` or `join_restart` event for every
participating node. While logs are growing, it waits for missing records and
terminal evidence up to the supplied deadline. Contradictory or malformed
complete records fail immediately; an unterminated final line remains
incomplete and cannot be accepted.

## Example

```json
{
  "instance": "example",
  "expected_locations": ["node0"],
  "node": "node0",
  "sequence": 0,
  "kind": "start",
  "pre": "GOSSIPING",
  "post": "GOSSIPING"
}
```

No recovery-decision-protocol traces are checked into the repository. Every
raw log passed to the validator in CI is captured from the running C++
implementation.
