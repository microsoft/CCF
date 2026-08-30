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

| Kind               | Required event fields                                           | Canonical boundary                          |
| ------------------ | --------------------------------------------------------------- | ------------------------------------------- |
| `start`            | `pre`, `post`                                                   | Protocol state initialized                  |
| `gossip_accepted`  | `message_id`, `source`, `view`, `seqno`, `pre`, `post`          | Validated gossip callback committed         |
| `gossip_rejected`  | `message_id`, `source`, `view`, `seqno`, `pre`, `post`          | Validation or protocol rejection            |
| `vote_accepted`    | `message_id`, `source`, `pre`, `post`                           | Validated vote callback committed           |
| `vote_rejected`    | `message_id`, `source`, `pre`, `post`                           | Validation rejection                        |
| `iamopen_accepted` | `message_id`, `source`, `pre`, `post`                           | IAmOpen selected peer and Joining committed |
| `iamopen_rejected` | `message_id`, `source`, `pre`, `post`                           | Validation or Opening/Open rejection        |
| `timeout`          | `pre`, `post`                                                   | Timeout transaction committed               |
| `retry`            | `pre`, `post`                                                   | Retry task observed                         |
| `send`             | `send` in `class:destination` form, `message_id`, `pre`, `post` | Transport send observed                     |
| `open`             | `open_kind`, `pre`, `post`                                      | Service-open transition committed           |
| `join_restart`     | `pre`, `post`                                                   | Joining/restart side effect committed       |
| `complete`         | `pre`, `post`                                                   | Opening-to-Open completion committed        |

Receive events may use `caused_by` to identify the observed send. A referenced
send is checked for the expected sender, destination, and message class. If the
send was not logged, the validator may match it against a compatible hidden
send from a node that has already started. Message IDs, causal IDs, and source
names must be nonempty. Message IDs cannot be reused. Rejected events branch
over rejection at the explicit validation boundary and rejection by the
protocol state. A send ID may cause at most one receive event.

Even without `caused_by`, an accepted receive from a configured source must
match a send that source could have emitted earlier. A rejected receive without
`caused_by` may represent rejection at the untrusted validation boundary. A
nonempty accepted source outside `expected_locations` is treated as an external
input, matching the current C++ behavior; the validator checks the local receive
transition but cannot constrain that external sender.

Non-receive events must omit `caused_by`.

Each participating configured node has one `start` event at sequence zero. The
first creates the initial candidate system; later starts activate other
configured nodes without resetting candidates. Non-start events for a node
before its start are rejected. Configured but unavailable nodes may have no
start event. Subsequent records must preserve `instance` and
`expected_locations`, refer to a configured node, and increment that node's
sequence exactly. Empty instance IDs, empty configurations, empty location
names, and duplicate configured names are rejected.

The NDJSON record order must be a topological linearization of the distributed
trace. It must order a node's start and any observed transition enabling an
omitted send before the receive caused by that send. The collector must retain
this hidden happens-before edge while merging, even if it omits the send record
from the final trace. Per-node `sequence`, message causality, and these hidden
edges define the ordering; wall-clock timestamps do not. Unknown fields may
carry collector-specific merge metadata.

## Under-observation

An implementation trace need not expose every retry or network send. The
validator maintains compatible candidates containing a `SystemState` and the
send classes that could have been emitted by earlier hidden retries, plus
unobserved one-shot effects produced by committed transitions. This history
allows delayed delivery after a sender changes phase without merging
incompatible executions. `open`, `join_restart`, and `complete` each consume
one matching pending effect from the observed node, so one node cannot replay
its transition or consume another node's effect.
An explicit send may also match an earlier send capability: this models a
retry task that selected its work before a concurrent protocol commit and
dispatched it afterward.
The validator computes a finite hidden closure over retry/send stuttering
before and after each observation. It does not guess protocol-state changes.
`pre` and `post` filter all candidates. Message IDs constrain causal matching
but are not protocol state.

The canonical v1 transition relation is deterministic, so a successful v1
prefix currently retains one candidate. Candidate sets and separate histories
remain explicit so later under-observed refinements can introduce genuine
alternatives without changing the validation architecture.

If no candidate remains, validation stops at the shortest failing prefix and
prints the observed incompatible kind plus expected compatible events from the
last nonempty candidate set. A successful parse with no compatible execution is
never reported as success.

## C++ instrumentation

Configure CCF with `-DCCF_RECOVERY_TRACE=ON` to enable implementation tracing.
Accepted receive and timeout events are written to
`public:ccf.internal.recovery_decision_protocol.trace_events` in the same
transaction as the modeled state change. A global commit hook emits them only
after commit, followed by any `open`, `join_restart`, or `complete` effect from
that transition. Aborted transactions therefore emit nothing.

The committed start hook emits `start` before scheduling retry and failover
tasks. Transport sends are emitted immediately before dispatch and propagate
their generated `message_id` in the internal request as `trace_message_id`;
the committed receive records it as `caused_by`.

Each log record contains `RDP_TRACE ` followed by the event object.
`tests/infra/recovery_trace.py` extracts records from all participating node
logs, topologically orders them by per-node sequence and causal send edges,
writes NDJSON, and invokes the Lean validator. The quorum, failover, and
multiple-timeout SNP e2e scenarios call this helper.

Validation/HTTP rejection events that perform no state mutation remain
optional; the current C++ instrumentation records successful committed paths.

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
