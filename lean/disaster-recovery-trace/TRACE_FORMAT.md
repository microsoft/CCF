# Recovery decision protocol trace format

The media type is newline-delimited JSON. Each nonempty line is one raw trace
record. Transaction semantics are emitted speculatively and become canonical
only when a later lifecycle record commits their attempt. This format is used
by CI with the producer and validator from the same source revision; it is not
a versioned compatibility contract.

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
| `attempt`    | natural number   | Per-node speculative execution identifier                                 |
| `message_id` | string           | Globally unique ID for an observed send or receive                        |
| `caused_by`  | string           | `message_id` of the send that caused a receive                            |
| `source`     | string           | Sender location name                                                      |
| `view`       | natural number   | Gossip payload or transaction lifecycle TxID view                         |
| `seqno`      | natural number   | Gossip payload or transaction lifecycle TxID sequence number              |
| `pre`        | phase string     | Observable phase before a semantic event                                  |
| `post`       | phase string     | Observable phase after a semantic event                                   |
| `open_kind`  | open-kind string | `QUORUM` or `FAILOVER` for an `open` observation                          |
| `send`       | string           | Send class and destination: `gossip:NAME`, `vote:NAME`, or `iamopen:NAME` |

Phase strings are `GOSSIPING`, `VOTING`, `OPENING`, `JOINING`, and `OPEN`.
Unknown fields are ignored as instrumentation metadata.
All integers must be nonnegative Lean `Nat` values.

## Event kinds

| Kind                 | Required event fields                                                                                 | Meaning                                     |
| -------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| `start`              | `pre`, `post`                                                                                         | Directly committed protocol initialization  |
| `send`               | `send` in `class:destination` form, `message_id`, `pre`, `post`; gossip also requires `view`, `seqno` | Immediate permanent transport observation   |
| `gossip_accepted`    | `attempt`, `message_id`, `caused_by`, `source`, `view`, `seqno`, `pre`, `post`                        | Speculative accepted gossip                 |
| `vote_accepted`      | `attempt`, `message_id`, `caused_by`, `source`, `pre`, `post`                                         | Speculative accepted vote                   |
| `iamopen_accepted`   | `attempt`, `message_id`, `caused_by`, `source`, `pre`, `post`                                         | Speculative accepted IAmOpen                |
| `timeout`            | `attempt`, `pre`, `post`                                                                              | Speculative timeout                         |
| `open`               | `attempt`, `open_kind`, `pre`, `post`                                                                 | Speculative service-open observation        |
| `join_restart`       | `attempt`, `pre`, `post`                                                                              | Speculative Joining/restart observation     |
| `complete`           | `attempt`, `pre`, `post`                                                                              | Speculative Opening-to-Open completion      |
| `globally_committed` | `attempt`, `view`, `seqno`                                                                            | Apply the buffered attempt                  |
| `rolled_back`        | `attempt`, `view`, `seqno`                                                                            | Discard a locally committed attempt         |
| `aborted`            | `attempt`                                                                                             | Discard a superseded conflict-retry attempt |

`start` and `send` must omit `attempt`. Every speculative semantic event must
have one. Transaction lifecycle records have no `pre` or `post`;
`globally_committed` and `rolled_back` carry the final transaction TxID, while
`aborted` must not carry a TxID.

Every receive uses `caused_by` to identify an earlier `send`. The validator
checks the sender, destination, message class, and gossip TxID payload. A
committed receive consumes the send once. Rolling back or aborting an attempt
does not consume it, so a committed retry may use the same cause. Message IDs,
causal IDs, and source names must be nonempty, and message IDs cannot be reused,
including IDs on discarded speculative receives. Non-receive events must omit
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

All semantic records from one execution have the same `(node, attempt)` and
are contiguous in that node's sequence. Other nodes' records may appear between
them in the topological order. Each group starts with one accepted receive or
timeout and may contain its correlated `open`, `join_restart`, or `complete`
observation. A later lifecycle record for the same key either applies the
buffered records in emitted order or discards them. Reusing an attempt key,
returning to a closed active attempt group, or resolving an unknown or already
resolved attempt is invalid. An attempt may remain unresolved at the end of the
available logs; it is ignored for canonical and terminal checks.

## Strict replay

A valid terminal trace describes a complete successful committed execution:
every observed transport send and transaction lifecycle record is explicit.
`DisasterRecoveryTrace/Protocol/Trace/Replay.lean` folds these events over one deterministic `SystemState`.
It buffers speculative semantic records by attempt. A `globally_committed`
record applies the whole buffer; `rolled_back` and `aborted` discard it.
Unresolved buffers remain inert. Sends and starts are handled immediately.
Sends validated against a locally visible speculative projection remain
permanent even if that attempt later rolls back.
If lifecycle resolution races ahead of a task's first traced send, the
pre-resolution projections with enabled sends remain available until that first
send chooses a batch. That choice expires the alternatives; the selected
batch's phase remains fixed until its remaining sends are observed.
Ordered retry-send batches remain valid when speculative or lifecycle records
interleave with their individual sends.

The validator rejects the first event that is not enabled by the canonical
model or whose recorded pre/post state, cause, or effect does not match. It
reports this shortest failing prefix with the current phase and expected event
classes.

Rejected HTTP or validation inputs do not mutate the modeled state and are not
part of this trace format.

## C++ instrumentation

Configure CCF with `-DCCF_RECOVERY_TRACE=ON` to enable implementation tracing.
Tracing observes normal protocol execution without changing transaction,
restart, or retry behavior. Accepted receive, timeout, and correlated effect
records are emitted together under a fresh attempt before the transaction
outcome is known. The final transaction callback emits `globally_committed` or
`rolled_back`; a conflict retry first emits `aborted` for the superseded
attempt. Transport sends are emitted immediately and carry `message_id` in the
protocol request in both traced and default builds. A receive records that value
as `caused_by`. The `join_restart` effect is recorded only on entry into
`JOINING`, not for later timeouts that leave the node in `JOINING`.

Each log record contains `RDP_TRACE ` followed by the event object.
`../../tests/infra/recovery_trace.py` passes the original participating node log
paths and scenario expectations to the Lean validator without reading or
rewriting their contents. Lean extracts the records from text logs or JSON
`msg` envelopes, topologically orders them by per-node sequence and causal send
edges, and replays them. The quorum, failover, and multiple-timeout SNP e2e
scenarios call this helper. The original logs are retained with the SNP job's
uploaded artifacts, so a failed replay can be reproduced locally.

Lean additionally requires committed scenario-specific terminal evidence before
accepting the trace: the expected number of participating nodes and open kind,
at least one completed opener, and a committed `complete` or `join_restart`
event for every participating node. Speculative discarded or unresolved
records do not supply open-kind or terminal evidence. While logs are growing,
the validator waits for missing records and terminal evidence up to the
supplied deadline. Contradictory or malformed committed records fail
immediately; an unterminated final line remains incomplete and cannot be
accepted. The accepted count is the number of raw ordered records, including
lifecycle and discarded records.

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
