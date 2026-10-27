# CCF-Raft model

An executable Lean model of CCF's consensus implementation ([`src/consensus/aft/raft.h`](../../src/consensus/aft/raft.h)) and the safety properties it is intended to satisfy.
It assumes familiarity with the [CCF consensus documentation](../../doc/architecture/consensus/index.rst).

## Source map

| Area                                   | Source                                                                                                                           |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Node state, log entries, log queries   | [`Model/NodeState.lean`](CCFRaft/Model/NodeState.lean)                                                                           |
| Configurations, quorums, retirement    | [`Model/ClusterConfig.lean`](CCFRaft/Model/ClusterConfig.lean) (`activeConfigurations`, `hasQuorum`, `NodeState.retirement`)     |
| Messages                               | [`Model/Messages.lean`](CCFRaft/Model/Messages.lean)                                                                             |
| Protocol policy (one node's step)      | [`Model/Node.lean`](CCFRaft/Model/Node.lean) (`Node.step`, `receive`, `act`, `highestCommittableIndex`, `eligiblePeers`)         |
| Initial states and network composition | [`Model.lean`](CCFRaft/Model.lean) (`initialNodeState`, `transitionSystem`)                                                      |
| Safety theorems and witness lemmas     | [`Properties.lean`](CCFRaft/Properties.lean)                                                                                     |
| Supporting proofs and executions       | [`Proofs/`](CCFRaft/Proofs)                                                                                                      |
| Action-trace tests and import layering | [`Tests/CanonicalTraces.lean`](CCFRaft/Tests/CanonicalTraces.lean), [`Tests/Architecture.lean`](CCFRaft/Tests/Architecture.lean) |

Transition systems, traces, effects and network composition come from the local [`ccf_common` package](../common/README.md).
Each node reads membership, quorums and retirement from its own ledger; there is no model-wide configuration after initialization.
Initialization takes a nonempty initial voting membership, whose smallest member starts as primary with the genesis configuration transaction.
Actions are local inputs (including timeouts) or delivery of a queued message; no clock is modeled.

## Scope

Node join and snapshot installation are not modeled.
There are no liveness properties or fairness assumptions.

## Validation

Install Lean via [elan](https://lean-lang.org/install/), then run from this directory:

```sh
lake exe cache get
lake check --inadvisably-no-sandbox
lake exe check-imports
lake lint
../../scripts/lean-format-checks.sh ccf-raft
```

`lake check` builds the default target with compiler warnings, including `sorry`, treated as errors, before separately replaying the compiled proofs in Lean's kernel and rejecting nonstandard axioms.
Kernel tracing reports the declarations checked during compilation; cached modules do not emit fresh compilation traces.
CI runs this before import coverage, formatting, and linting so the initial build and its traces occur in this step.
The build also runs two explicit action traces from an initialized network: committing a client request, and adding two nodes then electing a new primary and committing another request.
The reconfiguration trace checks each node's ledger before delivery, after setup, after replication and commitment, after election, and after the new primary's client request.
These are regression examples, not exhaustive checking.
`lake check` runs without sandboxing here, so build-time code must be trusted.
`CCFRaft.lean` reexports `Properties.lean` and its public imports transitively, while importing tests privately.
The shared `check-imports` command rejects modules missing from that import closure.

## Proofs

`Properties.lean` contains the full theorem and witness-lemma statements, with one-line proof links into `Proofs/`.
Import `CCFRaft.Properties` and use `CCFRaft.Properties.<name>` for these declarations.
`Proofs/Direct/` establishes node-local commit invariants; `Proofs/Safety/` establishes the cross-node history invariant used for election safety and committed-log comparability.
`Proofs/Witnesses.lean` supplies concrete executions checked by the kernel.

To list the safety-invariant declarations used by the exported theorems, run `lake env lean scripts/invariant-dependencies.lean`.

## TLA+ safety properties

`PropertiesTLA.lean` is a separate experiment that measures how much Lean is needed to prove TLA+ safety properties of this model.
It states each property as a theorem paired with a witness lemma, and proves both:

- `LogInv` and `THEOREM Spec => []LogInv` from `tla/consensus/ccfraft.tla` (lines 1400-1407), using `Committed(i)` (line 490).
- `CommittedLogAppendOnlyProp` and its theorem from `ccfraft.tla` (lines 1639-1645).

The statements match the TLA+ semantically rather than syntactically, as invariants of `Model.transitionSystem`.
For these safety properties, `Spec => []P` means `P` holds in every reachable state, and `Spec => [][A]_vars` means `A` holds on every enabled step from a reachable state, since stuttering steps satisfy it trivially; `Fairness` plays no part.
`Committed(i)` is `committedLog`.
`LogInv` compares committed logs of different nodes in the same state, unlike `committed_logs_prefix` in `Properties.lean`, which compares any two states of a trace.
The `AppendOnlyProp` of `tla/consensus/abs.tla` (line 101), read through ccfraft's `MappingToAbs` (line 1727), keeps only the terms of each committed log, so it follows from `CommittedLogAppendOnlyProp`.
The Lean model is not proved equivalent to the TLA+ specification, and no TLAPS proof is involved.

Each theorem body calls a helper in `ProofTLA/`, which holds the whole proof.
`ProofTLA/` imports only the model, `ccf_common` and Mathlib, and is independent of any other proof layer.
`Tests/ArchitectureTLA.lean` enforces this and fails the build if a theorem depends on an axiom other than `propext`, `Classical.choice` and `Quot.sound`.
`Tests/PropertiesTLA.lean` checks that `committedLog` is `Committed(i)`, that every reachable state holds each configured node exactly once, and that both claims cover every state and adjacent step of valid finite or infinite traces.
The package checks under Validation cover these modules through `CCFRaft.lean`.

To compare proof sizes, count lines from this directory:

```sh
wc -l CCFRaft/PropertiesTLA.lean
find CCFRaft/ProofTLA -name '*.lean' -print0 | sort -z | xargs -0 wc -l
```
