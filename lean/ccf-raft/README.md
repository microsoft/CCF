# CCF Raft model and properties

This package contains an executable Lean model of CCF Raft (`src/consensus/aft/raft.h`) and safety property statements.
It is the model-and-properties layer stacked on [#8576](https://github.com/microsoft/CCF/pull/8576).
Safety proofs and implementation trace validation are pending follow-on layers, not part of this package yet.
[The Lean module guide](../AGENT.md) describes the module layout.

## Contents

| Purpose                            | Location                                      |
| ---------------------------------- | --------------------------------------------- |
| Node state, log entries, queries   | `CCFRaft/Model/NodeState.lean`                |
| Membership and retirement queries  | `CCFRaft/Model/ClusterConfig.lean`            |
| Messages between nodes             | `CCFRaft/Model/Messages.lean`                 |
| Single-node protocol               | `CCFRaft/Model/Node.lean`                     |
| Network composition                | `CCFRaft/Model.lean`, `ccf_common` dependency |
| Property statements                | `CCFRaft/Properties.lean`                     |
| Definitions used by statements     | `CCFRaft/Properties/Utils.lean`               |
| Model regressions and layer checks | `CCFRaft/Tests/`                              |
| Generated import-all root          | `CCFRaft.lean`                                |

Human review covers the model, the property statements and their helpers.
The [`ccf_common` package](https://github.com/microsoft/CCF/tree/cc22c58d61e628b90f1f5b49194c7e6722f1ec2c/lean/common) provides transition systems, traces, output-recording capabilities and network composition in the `CCF` namespace.
Its `Effect` is `StateT Outputs Option`, so a disabled local step fails without retaining outputs.
The dependency is pinned to the merged common-package commit because this stack's parent predates that merge; no local `Shared` copy is maintained.
This Git subdirectory dependency builds common sources directly from Lake's checkout, without the `copy = true` path-dependency mode.

## Model

The model namespace is `CCFRaft.Model.Node`.
Some callsites use fully qualified names to distinguish it from a generic `Node` type parameter.
`Model/NodeState.lean` defines state, log entries and pure queries such as `termAt` and `maxCommittableIndex`.
Log positions are one-based; index zero denotes the empty prefix.
An entry is either a signature or a transaction with an identifier and an ordered list of `TransactionEffect`s: `reconfiguration` or `retiredCommitted`.
An ordinary transaction has no effects, and a signature cannot carry any.

`Model/ClusterConfig.lean` defines `InitialConfig`, initialization and membership-dependent queries.
`configurationHistory config log` includes initial membership at index zero and each reconfiguration effect at its transaction's log position.
Multiple configuration effects in one transaction share that index and retain their order.
`activeConfigurations config log commitIndex` retains the last committed configuration and every pending one; if several configurations share a committed index, only the last remains active.
`configurationMembers` takes the union of a supplied configuration list.

`retirementIndexInLog` finds the first transition from membership to absence, ignoring absence before joining.
`firstLogIndexAfter` finds a matching entry strictly after a supplied index.
`retiredCommittedNodes` unions nodes named by retirement records; passing `log.take commitIndex` restricts it to committed records.
`NodeState.retirementCompletedNodes` identifies removed peers whose removal is committed but whose final retirement record is not yet committed.
`NodeState.retirement` derives the retirement index, following signature and membership phase from the current log and commit frontier, so rollback needs no metadata refresh.
Only `retiredCommittedIndex` is stored: it remembers the first commit frontier covering the retirement record, not the record's position.
`NodeState.commitThrough` preserves that historical value.

`Model/Messages.lean` defines AppendEntries and RequestVote packets, including pre-vote and vote-proposal variants.
`Model/Node.lean` implements `Node.step`, which handles an internal input or a delivered message.
There are four composite inputs:

- `append entries` appends a nonempty batch atomically, applying each transaction's effects in order before attempting to advance commit.
- `sendEntries destination endIndex` sends from the peer's `sentIndex` to the selected end; equal indices produce a heartbeat.
- `timeout .election` or `timeout .checkQuorum` is a logical timeout, not a model of elapsed time or acknowledgement clocks.
- `nominateSuccessor` selects an eligible peer by highest replication progress, then latest active membership index, then highest node ID.

Multiple reconfigurations per transaction remain allowed.
Hooks run before appending an entry, so heartbeats to newly added peers use the pre-append log length.
A failed guard disables the entire step and discards all intermediate state and outputs.
An enabled event returns the next node state and records messages through the capabilities' `send` callback.

Commit is internal: a current-term acknowledgement, promotion or append runs the same quorum-based calculation in its own step.
A current-term signature can commit when a majority of every active configuration has reached it, including the singleton case.
Retirement nomination is atomic within `advanceCommit`, using the precommit eligible peers and configurations before clearing leadership.
A standalone nomination requires a leader and sends nothing if no eligible peer exists.
Promotion also sends an empty AppendEntries to every eligible peer.

`eligiblePeers` reconstructs peers from active configurations and completed retirements.
Unlike CCF's persistent peer inventory, it does not retain peers whose introduction was rolled back.
This is an intentional approximation, not an implementation-equivalence claim.

Except for vote proposals and AppendEntries responses delivered to nonleaders, a newer-term message moves the receiver to that term as a follower before handling it.
A pre-vote round starts without incrementing the term, but newer-term pre-vote messages can advance the receiver's term.
A same-term AppendEntries request makes a candidate or pre-vote candidate step down.
AppendEntries ACKs count only in the leader's current term.
A log-mismatch NACK instead carries a possible matching log term, so an older-term NACK can rewind `sentIndex`, bounded below by `matchIndex`.

Entering a pre-vote round or candidacy votes for self and can synchronously advance on a self-quorum.
Otherwise pre-vote broadcasts pre-vote requests; candidacy broadcasts regular vote requests even if the self-vote already promoted it.
Requests go to every other active member, and a quorum advances the election in the step that counted it.
Every AppendEntries request is consumed: stale terms and previous-entry mismatches get NACKs, while requests below the commit index or conflicting with a log that may no longer roll back are dropped without a response.

`Model.lean` composes one copy of `Node.step` per listed node with `CCF.MultiNodeTransitionSystem`.
Bootstrap members start at `BOOTSTRAP_TERM` (2); only the initial leader has the bootstrap configuration transaction, with identifier `default`.
All commit indices start at zero, other logs are empty, and listed nonbootstrap nodes have no role at term zero.
The network is a multiset of envelopes: delivery selects any queued envelope, allowing reordering, and an envelope never delivered models message loss.
Nodes share no state except the network.
A leader may add any node to a configuration, and transaction identifiers need not be unique.

## Properties and pending layers

Each claim quantifies every node and transaction identifier type, every `InitialConfig`, every node list and every valid trace of `Model.transitionSystem`.

- `ElectionSafety`: no two distinct nodes lead in the same term.
- `CommittedLogsPrefix`: any two committed logs in a trace are prefix-comparable, across nodes and states.
- `CommittedFrontierIsSignature`: every positive commit index points to a signature.

Each property has a `Witness` claim describing a nontrivial valid execution.
The election witness has two distinct leaders without requiring equal terms; it is not a witness to the safety property's entire antecedent.
These are statements, not established safety theorems.
No property proof implementations, proof export module, proof-coverage checks or replay code are included.
The later proof layer must establish the claims without weakening them; the later trace-validation layer must separately align the model with captured implementation executions.
Neither liveness nor fairness is claimed.

## Validation

Install Lean via [elan](https://lean-lang.org/install/), then run from this directory:

```sh
lake exe cache get
lake exe mk_all --check --module --lib CCFRaft
lake build --wfail --fail-fast
lake lint
lake exe canonical-checks
lake check --inadvisably-no-sandbox
../../scripts/lean-format-checks.sh ccf-raft
```

The default targets build the complete import-all library and the model-only canonical-checks executable.
`--wfail` and the package's warning-as-error option reject warnings, including `sorry`.
`lake lint` runs Lean's built-in linters.
The package pins Lean and Mathlib 4.35.0 to match `ccf_common`.
`lake check --inadvisably-no-sandbox` exports and kernel-checks all default targets, including their common-package dependencies, and allows only the standard axioms `propext`, `Classical.choice` and `Quot.sound`.
This audits the included infrastructure and regression theorems, not absent safety proofs.
As in the common-package integration, the command disables sandbox isolation: build-time code must be trusted, and Lake warns that the run is not trustworthy.
The kernel recheck and axiom-dependency audit remain enabled.
`Tests/Architecture.lean` rejects proof imports and reversed shared/model/property dependencies.
`Tests/AppendTransactions.lean` contains kernel-checked append regressions; `Tests/CanonicalTests.lean` exercises model behavior without replay dependencies.
CI runs these same package checks.

The sources use Lean's module system, with public imports preserving exports and exposed definitions preserving transparency for the later proof layer.
After adding or removing modules, regenerate the import-all root with `lake exe mk_all --module --lib CCFRaft`.
The formatting script runs the pinned [leanfmt](https://github.com/duckki/leanfmt) dependency over tracked package sources.
Pass `-f` before the package name to apply fixes only when the entire selected write scope is intended.
