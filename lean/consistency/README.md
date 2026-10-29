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

## Model

The model represents a multi-node service with forwarded reads, elections, and invalidation.
`Model.transitionSystem` supplies initialization and an executable step function; `none` means an action is disabled.

The global state contains an append-only client history and one append-only ledger branch per leader view.
An election copies a prefix compatible with known commitments into a new branch, preserving older branches.
Writes and forwarded reads can still select former leaders' branches.
Write execution, initial response, and committed/invalid status reporting are separate actions.
Commitment is tracked through received status reports.
Committed writes cannot observe known invalid writes, including entries copied from earlier views, but a different-view replacement at the same sequence number can commit.

Views, branch indices, sequence numbers, and action-history indices are one-based.
Request IDs begin at zero and are allocated across both transaction kinds.
Property helpers use zero-based history positions.
The initial view is 2; view 1 is reserved and cannot process requests.

The model covers safety only, not liveness, disaster recovery, or non-forwarded reads.
There is no refinement proof connecting it to the [Raft model](../ccf-raft/README.md) or implementation trace validation.

## Properties

[`Properties.lean`](consistency/Properties.lean) contains 17 proved safety theorems over valid model executions, each with an adjacent non-vacuity witness.
The primary consistency guarantee is expressed by `committed_rw_ordered_serializable` and `committed_rw_ordered_real_time` together.
Committed writes serialize in transaction-ID order, and that order respects request-to-initial-response intervals rather than waiting for committed-status notifications.
Supporting proofs live under [`Proofs/`](consistency/Proofs); [`Witnesses.lean`](consistency/Proofs/Witnesses.lean) constructs the witness executions by replaying model actions.

## Validation

Install Lean through [elan](https://lean-lang.org/install/), then run from this package directory:

```sh
lake exe cache get
lake check --inadvisably-no-sandbox
lake exe check-imports
lake lint
../../scripts/lean-format-checks.sh consistency
```

`lake check` checks proofs against the kernel and standard axiom allowlist, without allowing unfinished proofs.
`lake exe check-imports` checks module coverage and dependency direction.
The unsandboxed check executes build-time code, which must be trusted.
