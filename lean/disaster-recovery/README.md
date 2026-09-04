# Lean disaster recovery model

This package contains the canonical Lean model of CCF's C++ recovery decision
protocol and its permanent safety and liveness proofs. It is pinned to Lean
4.28.0 and Mathlib `v4.28.0`.

## Model

`DisasterRecovery.Protocol.Model` models one protocol node. Its state machine
covers Gossiping, Voting, Opening, Joining, and Open, including the separate
timeout lane, retries, duplicate receives, strict-majority voting, failover,
restart, and completion.

`DisasterRecovery.Protocol.Global` lifts the local transition function to a
system with active nodes, in-flight messages, immutable send history, and
terminal effects. Deliveries consume previously sent envelopes, so receives
cannot appear without a modeled send.

The model follows the current C++ behavior in which a successfully validated
location is not rejected merely because it is absent from
`expectedLocations`. In particular, an accepted gossip from an unexpected
location can satisfy a size threshold. `CanonicalTests.lean` checks this
intentional accepted-unexpected-location behavior so that the implementation
discrepancy remains explicit.

`Validation.accepted` and `Validation.rejected` are the boundary at which the
model receives the result of C++ quote and certificate validation. The model
does not formalize or prove the cryptography that produces that result.

## Proof coverage and limits

`DisasterRecovery.Protocol.Temporal` proves local safety properties and
Opening-to-Open progress under weak timeout fairness.

`DisasterRecovery.Protocol.Invariants` proves global well-formedness,
message provenance, locality of transitions, append-only send history, and
monotonic terminal histories for reachable states.

`DisasterRecovery.Protocol.Quorum` proves that votes are unique and backed by
prior sends, strict-majority quorums intersect, and any two quorum openings in
a reachable execution select the same opener. This safety result does not
require fairness.

`DisasterRecovery.Protocol.Committed` proves TxID maximum properties and
committed-prefix preservation under two explicit premises:

- `DurableCommit` requires at least one configured recovered ledger to cover
  the committed TxID.
- `FullGossipSelection` requires a real sent vote whose selection snapshot
  contains exactly the configured recovered TxIDs.

A quorum opening alone does not imply `FullGossipSelection`, because voting may
begin after a gossip timeout. The committed-prefix result deliberately does not
derive or hide either durability or full-gossip evidence.

`DisasterRecovery.Protocol.GlobalTemporal` proves conditional global progress.
Its theorems assume the relevant retry, message-delivery, and timeout fairness
premises. Progress for every active node additionally requires
`BroadcastBeforeCompletion`: an opener must send its `IAmOpen` announcement to
every other active node before it completes. Ordinary weak fairness does not
order actions that are enabled only for a finite interval, so this broadcast
ordering is a separate premise. The proofs do not construct a scheduler that
satisfies the fairness and broadcast-before-completion premises.

## Files

| File | Purpose |
| --- | --- |
| `DisasterRecovery/Protocol/Model.lean` | C++-aligned local transition model |
| `DisasterRecovery/Protocol/Temporal.lean` | Local safety and liveness |
| `DisasterRecovery/Protocol/Global.lean` | Distributed transition semantics |
| `DisasterRecovery/Protocol/Invariants.lean` | Reachability invariants |
| `DisasterRecovery/Protocol/Quorum.lean` | Quorum uniqueness |
| `DisasterRecovery/Protocol/Committed.lean` | Committed-prefix safety |
| `DisasterRecovery/Protocol/GlobalTemporal.lean` | Global liveness |
| `CanonicalTests.lean` | Executable canonical behavior checks |
| `AxiomChecks.lean` | Transitive project `sorryAx` rejection |

## Validation

Run from this directory:

```console
lake exe cache get
lake build
lake env lean -DwarningAsError=true AxiomChecks.lean
lake exe canonical-checks
```
