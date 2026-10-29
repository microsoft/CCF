# Consistency model

An executable Lean model of CCF's externally visible consistency semantics.
It models a dummy append-and-read application, not the consensus implementation.

## Source map

| Area                                          | Lean source                                                      |
| --------------------------------------------- | ---------------------------------------------------------------- |
| Typed events, IDs, ledger entries, and state  | [`Model/Types.lean`](consistency/Model/Types.lean)               |
| Executable history queries                    | [`Model/History.lean`](consistency/Model/History.lean)           |
| Guarded actions                               | [`Model/Transitions.lean`](consistency/Model/Transitions.lean)   |
| Initialization and transition system          | [`Model.lean`](consistency/Model.lean)                           |
| History selection and transaction-ID ordering | [`Properties/History.lean`](consistency/Properties/History.lean) |
| Property statements and proof links           | [`Properties.lean`](consistency/Properties.lean)                 |
| Supporting proofs                             | [`Proofs/`](consistency/Proofs)                                  |

Shared transition systems and executions come from [`ccf_common`](../common/README.md).
The package root publicly reexports the model and properties.

## Model

There is one model: a multi-node service with forwarded reads.
Read-only requests, elections, and invalidation are always supported, subject to their action guards.
`Model.transitionSystem` supplies initialization and an executable `State -> Action -> Option State` step function.
`Model.step` dispatches each action to a transition function with the same name.
`none` means an action is disabled.
Only protocol actions are represented; there is no explicit stuttering action.
Nondeterministic choices, including request-history positions, response positions, branches, and prefix lengths, are action parameters.

The global state contains an append-only client history and one append-only ledger branch per leader view.
An election appends a new branch copied from a prefix compatible with known commitments; it does not mutate older branches.
Writes and forwarded reads can still select former leaders' branches.
Write execution, initial response, and committed/invalid status reporting are separate actions.
The commit frontier is derived from explicitly received committed-status events, not an internal consensus variable.
An early invalid-status response can exclude a current-view suffix from future commitment even before an election.
Commitment also excludes every known invalid transaction ID from the candidate's full ledger prefix, including entries copied from earlier views.
This checks each entry's original view and sequence number, so an invalid transaction does not prevent committing a replacement at the same sequence number in a different view.
Election can still copy speculative invalid entries, but no write observing those entries can commit.

Views, branch indices, sequence numbers, and action-history indices are one-based.
Zero and out-of-range indices disable actions rather than silently selecting the first element.
Request IDs begin at zero and are allocated across both transaction kinds.
Write values and request identifiers use the natural-number type alias `Model.TxContent`.
`Model.TxType` distinguishes read-write (`rw`) and read-only (`ro`) transactions.
Property helpers use zero-based history positions internally; this preserves all relative-order comparisons.
The initial view is always 2, matching CCF; view 1 is reserved as an empty branch and cannot process requests.
The model has no configuration parameters.
Other ledger transactions occupy sequence numbers but do not appear in application observations.

There are no sessions, fairness assumptions, liveness claims, disaster recovery, pending/unknown statuses, or non-forwarded reads.
The model has no bounds on history length or the number of views.
There is no refinement proof connecting this abstraction to the [Raft model](../ccf-raft/README.md), and no implementation trace validation.

## Properties

[`Properties.lean`](consistency/Properties.lean) exposes full theorem statements over valid executions of the actual model, following the other Lean packages' style.
All 17 safety theorems have completed proofs, with implementations under [`Proofs/`](consistency/Proofs).
There are no unfinished proofs.
Each safety theorem has an adjacent witness lemma over the same multi-node model with reads.

### Proof status

Every theorem is proved without depending on unfinished theorems.
The primary consistency guarantee is expressed by `committed_rw_ordered_serializable` and `committed_rw_ordered_real_time` together.
Committed writes serialize in transaction-ID order, and that order respects request-to-initial-response intervals rather than waiting for committed-status notifications.
Completed proofs use only the standard allowed axioms `propext`, `Classical.choice`, and `Quot.sound`, not `sorryAx`.

### Witness coverage

The 17 public witness lemmas exhibit valid executions with populated domains.
Each witness states only the relevant domains and antecedents, without repeating the safety conclusion or adding unrelated observation, ordering, or status requirements.
Their implementations in [`Witnesses.lean`](consistency/Proofs/Witnesses.lean) replay enabled model actions, prove the final states reachable, and obtain valid finite traces through the shared execution definitions.
They do not assume the safety theorems they accompany.

- An execution without elections has two committed writes and two read responses with nonempty observations.
  The reads demonstrate that distinct requests can return the same transaction ID and observation.
  In this execution, a later request arrives after the earlier write's initial response but before its committed-status notification.
  The sorted committed responses contain an actual adjacent pair with strictly increasing observation lengths.
- An execution invalidates two old-view writes, elects a replacement branch, and commits two replacement writes.
  Distinct ledger positions activate all three status-propagation clauses.
  An invalid write coexists with a nonempty committed observation that excludes it.
  Forwarded reads then observe both the new leader's branch and the former leader's stale branch.
- The three equality-guarded uniqueness witnesses explicitly inhabit their equality antecedents by comparing an actual response with itself.
  They do not require distinct colliding responses.

## Validation

Install Lean through [elan](https://lean-lang.org/install/), then run from this package directory:

```sh
lake exe cache get
lake check --inadvisably-no-sandbox
lake exe check-imports
lake lint
../../scripts/lean-format-checks.sh consistency
```

The repository's Lean workflow discovers this Lake package automatically.
`lake check` builds with warnings treated as errors and performs kernel and axiom-dependency checks.
The checks use the standard axiom allowlist without allowing `sorryAx`.
`lake exe check-imports` checks that the library root imports every package module.
The unsandboxed check executes build-time code, which must be trusted.
