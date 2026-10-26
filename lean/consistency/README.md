# Consistency model

An executable Lean model of CCF's externally visible consistency semantics.
It models a dummy append-and-read application, not the consensus implementation.
The package, library, root module, and namespace are all named `consistency`.

## Source map

| Area                                          | Lean source                                                            |
| --------------------------------------------- | ---------------------------------------------------------------------- |
| Typed events, IDs, ledger entries, and state  | [`Model/Types.lean`](consistency/Model/Types.lean)                     |
| Executable history queries                    | [`Model/History.lean`](consistency/Model/History.lean)                 |
| Guarded actions                               | [`Model/Transitions.lean`](consistency/Model/Transitions.lean)         |
| Initialization and four variants              | [`Model.lean`](consistency/Model.lean)                                 |
| History selection and transaction-ID ordering | [`Properties/History.lean`](consistency/Properties/History.lean)       |
| Property statements and proof links           | [`Properties.lean`](consistency/Properties.lean)                       |
| Executable history predicates                 | [`Properties/Predicates.lean`](consistency/Properties/Predicates.lean) |
| Supporting proofs                             | [`Proofs/`](consistency/Proofs)                                        |

Shared transition systems and executions come from [`ccf_common`](../common/README.md).
The package root publicly reexports the model and properties.

## Model

`Model.singleNode`, `Model.multiNode`, `Model.singleNodeReads`, and `Model.multiNodeReads` select single- or multi-node execution, with or without reads.
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
`Config.firstBranch` is positive and defaults to 1; setting it to 2 reserves an initial empty branch.
Other ledger transactions occupy sequence numbers but do not appear in application observations.

There are no sessions, fairness assumptions, liveness claims, disaster recovery, pending/unknown statuses, or non-forwarded reads.
The model has no bounds on history length or the number of views.
There is no refinement proof connecting this abstraction to the [Raft model](../ccf-raft/README.md), and no implementation trace validation.

## Properties

[`Properties.lean`](consistency/Properties.lean) exposes full theorem statements over valid executions of the actual model, following the other Lean packages' style.
All 28 theorems have completed proofs, with implementations under [`Proofs/`](consistency/Proofs).
There are no unfinished proofs.
Single-node-only theorems explicitly assume `config.multiNode = false`.
`history_monotonic` and `ledgers_monotonic` state the temporal append-only claims.

Executable history predicates live in [`Properties/Predicates.lean`](consistency/Properties/Predicates.lean), independently of the theorem entrypoint.
They remain transparent to decidability inference so the predicates can be evaluated without importing theorem implementations.
Theorem names use snake_case; the corresponding predicate names use lowerCamelCase:

| Theorems                                                                                                                                           | Scope of guarantee                                                                               |
| -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `all_rw_received_is_first_sent`, `all_ro_received_is_first_sent`, `all_received_is_first_sent`                                                     | Responses follow requests; read-only cases are vacuous without reads                             |
| `unique_txs`, `same_observations`, `unique_tx_requests`, `unique_tx_ids`                                                                           | All variants                                                                                     |
| `unique_seq_nums`                                                                                                                                  | Single-node only                                                                                 |
| `unique_seq_nums_committed`                                                                                                                        | All variants                                                                                     |
| `committed_or_invalid`, `once_committed_prev_committed`, `once_committed_next_invalid`, `once_invalid_next_invalid`, `committed_or_invalid_strong` | All variants; propagation constrains reported statuses, not delivery of additional status events |
| `only_observe_sent_requests`, `at_most_once_observed`                                                                                              | All variants                                                                                     |
| `all_committed_observed`                                                                                                                           | Committed writes in all variants                                                                 |
| `all_committed_observed_ro`                                                                                                                        | Single-node reads only; not a multi-node guarantee                                               |
| `invalid_not_observed`                                                                                                                             | Single-node only, vacuously without invalid statuses                                             |
| `invalid_not_observed_by_committed`                                                                                                                | Committed writes in all variants, with full-prefix invalid-ID exclusion                          |
| `rw_serializable`                                                                                                                                  | Single-node only; divergent speculative branches need not be serializable                        |
| `committed_rw_serializable`, `committed_rw_linearizable`                                                                                           | Committed writes in all variants                                                                 |
| `committed_rw_ordered_real_time`, `committed_rw_ordered_serializable`, `committed_rw_ordered_spec_linearizable`                                    | Committed writes in all variants                                                                 |

The central theorem statement is `committed_rw_ordered_spec_linearizable`, corresponding to the executable `committedRwOrderedSpecLinearizable` predicate.
Its real-time interval ends at the initial write response, not at the later notification that the write committed.
Its serial ordering is the lexicographic transaction-ID order.
Ordered serializability compares adjacent committed-response payloads after deduplication and sorting, requires strict observation extension, and requires the later response to end with its own write.
Intervening writes need not have received explicit committed-status notifications.
The adjacent-pair condition is vacuous for empty and singleton response sets.
Distinct equal-ID payloads retain first-occurrence order during sorting; intended uniqueness and same-observation properties rule out those ties.

`commonGuarantees` and `variantGuarantees` collect the intended claims without treating the known non-guarantees as requirements.
They are predicate definitions, not proved guarantees.

### Proof status

Every theorem is proved without depending on unfinished theorems.
This includes the primary `committed_rw_ordered_spec_linearizable` claim.
Completed proofs use only the standard allowed axioms `propext`, `Classical.choice`, and `Quot.sound`, not `sorryAx`.

The supporting invariants are separated from the public statements:

| Proof modules                                                                                                                                                     | Supporting facts                                                                                                                                        |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`Structural.lean`](consistency/Proofs/Structural.lean), [`History.lean`](consistency/Proofs/History.lean), [`Responses.lean`](consistency/Proofs/Responses.lean) | Append-only structure, request causality and allocation, and response uniqueness                                                                        |
| [`Observations.lean`](consistency/Proofs/Observations.lean)                                                                                                       | Ledger write uniqueness, request provenance, and response observation safety                                                                            |
| [`LedgerIdentity.lean`](consistency/Proofs/LedgerIdentity.lean)                                                                                                   | Every entry anchors its prefix to its original view's branch; responses retain snapshots of those prefixes                                              |
| [`Commitment.lean`](consistency/Proofs/Commitment.lean)                                                                                                           | All known committed entries remain in the current branch, including across elections                                                                    |
| [`ViewOrder.lean`](consistency/Proofs/ViewOrder.lean), [`Statuses.lean`](consistency/Proofs/Statuses.lean)                                                        | Nondecreasing ledger views and separation of committed prefixes from same-view invalid suffixes                                                         |
| [`RealTime.lean`](consistency/Proofs/RealTime.lean), [`Ordered.lean`](consistency/Proofs/Ordered.lean)                                                            | Real-time order follows from request provenance and committed-prefix comparability; sorted committed responses strictly extend observations             |
| [`SingleNode.lean`](consistency/Proofs/SingleNode.lean), [`Reads.lean`](consistency/Proofs/Reads.lean)                                                            | Fixed-view execution and reads observing all earlier responded writes                                                                                   |
| [`InvalidObservations.lean`](consistency/Proofs/InvalidObservations.lean)                                                                                         | Write contents identify a unique original transaction ID across branches; committed prefixes exclude invalid IDs, including later invalidation attempts |

The original commitment rule admitted a counterexample to `invalid_not_observed_by_committed`.
For the default multi-node configuration, the following sequence invalidates write 0 at `1.1`, copies it into a new branch, and attempts to commit write 1 at `2.2` while observing the invalid write:

```lean
[.request .rw, .execute 1 1, .respond 1 1 1, .invalidate 2,
 .elect 1 1, .request .rw, .execute 4 2, .respond 4 2 2, .commit 5]
```

The first eight actions remain enabled, preserving early invalidation and election behavior.
The final commitment is now disabled because its prefix contains the invalid ID `1.1`.
The theorem statement is unchanged; the proof covers both invalidation before commitment and attempted invalidation after commitment.

### History associations

`invalidNotObserved` associates an invalid-status event with a write by transaction ID before excluding that write from another write's observations.
`invalidNotObservedByCommitted` additionally selects committed observers by transaction ID.
`committedRequests` selects requests whose matching response is explicitly known committed.
Typed event and ledger constructors enforce their shape constraints directly.

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
