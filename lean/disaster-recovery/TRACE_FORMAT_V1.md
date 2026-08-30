# Recovery decision protocol trace format, version 1

The media type is newline-delimited JSON. Each nonempty line is one committed
semantic observation. The version string is:

```text
ccf.recovery_decision_protocol.trace/1
```

## Record

Every record is a JSON object with these required fields:

| Field                | Type             | Meaning                             |
| -------------------- | ---------------- | ----------------------------------- |
| `version`            | string           | Exactly the version above           |
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
Unknown fields are ignored for forward-compatible instrumentation metadata.
All integers must be nonnegative Lean `Nat` values.

## Event kinds

| Kind               | Required event fields                                               | Canonical boundary                          |
| ------------------ | ------------------------------------------------------------------- | ------------------------------------------- |
| `start`            | `pre`, `post`                                                       | Protocol state initialized                  |
| `gossip_accepted`  | `message_id`, `caused_by`, `source`, `view`, `seqno`, `pre`, `post` | Validated gossip callback committed         |
| `vote_accepted`    | `message_id`, `caused_by`, `source`, `pre`, `post`                  | Validated vote callback committed           |
| `iamopen_accepted` | `message_id`, `caused_by`, `source`, `pre`, `post`                  | IAmOpen selected peer and Joining committed |
| `timeout`          | `pre`, `post`                                                       | Timeout transaction committed               |
| `send`             | `send` in `class:destination` form, `message_id`, `pre`, `post`     | Transport send observed                     |
| `open`             | `open_kind`, `pre`, `post`                                          | Service-open transition committed           |
| `join_restart`     | `pre`, `post`                                                       | Joining/restart side effect committed       |
| `complete`         | `pre`, `post`                                                       | Opening-to-Open completion committed        |

Every receive uses `caused_by` to identify an earlier `send`. The validator
checks the sender, destination, message class, and single consumption of that
send. Message IDs, causal IDs, and source names must be nonempty, and message
IDs cannot be reused. Non-receive events must omit `caused_by`.

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

Version 1 is a complete successful-execution trace: every transport send,
accepted receive, committed timeout, and one-shot effect is explicit.
`Trace/Replay.lean` folds these events over one deterministic `SystemState`.
It retains only observed sends, consumed causal IDs, per-node sequences, and
pending `open`, `join_restart`, or `complete` effects.

The validator rejects the first event that is not enabled by the canonical
model or whose recorded pre/post state, cause, or effect does not match. It
reports this shortest failing prefix with the current phase and expected event
classes.

Rejected HTTP/validation inputs do not mutate the modeled state and are not
part of version 1. A future need to validate rejection behavior or incomplete
traces should use a new contract version rather than adding implicit behavior
to this deterministic replay.

## C++ instrumentation

Configure CCF with `-DCCF_RECOVERY_TRACE=ON` to enable implementation tracing.
Accepted receive and timeout events are written to
`public:ccf.internal.recovery_decision_protocol.trace_events` in the same
transaction as the modeled state change. A global commit hook emits them only
after commit, followed by any `open`, `join_restart`, or `complete` effect from
that transition. Aborted transactions therefore emit nothing.
In trace-enabled builds the joiner restart request is issued by this hook after
the committed receive and `join_restart` records are emitted; default builds
retain the existing immediate restart path.

The committed start hook emits `start` before scheduling retry and failover
tasks. Transport sends are emitted immediately before dispatch and propagate
their generated `message_id` in the internal request as `trace_message_id`;
the committed receive records it as `caused_by`.
If a retry observes a locally committed phase that is not yet globally visible
to the trace hook, tracing defers that retry invocation. Once phases match, the
trace lock serializes the complete send batch against later commit publication.

Each log record contains `RDP_TRACE ` followed by the event object.
`tests/infra/recovery_trace.py` extracts records from all participating node
logs, topologically orders them by per-node sequence and causal send edges,
writes NDJSON, and invokes the Lean validator. The quorum, failover, and
multiple-timeout SNP e2e scenarios call this helper.

The e2e helper additionally requires scenario-specific terminal evidence before
accepting the trace: the expected open kind, at least one completed opener, and
a `complete` or `join_restart` event for every participating node.

## Example

```json
{
  "version": "ccf.recovery_decision_protocol.trace/1",
  "instance": "example",
  "expected_locations": ["node0"],
  "node": "node0",
  "sequence": 0,
  "kind": "start",
  "pre": "GOSSIPING",
  "post": "GOSSIPING"
}
```

Accepted quorum, failover-with-unavailable-locations, and multi-node examples
are `fixtures/accepted.ndjson`, `fixtures/accepted-failover.ndjson`, and
`fixtures/accepted-multinode.ndjson`. Deliberately rejected state and causal
examples are `fixtures/rejected.ndjson` and `fixtures/rejected-cause.ndjson`.
