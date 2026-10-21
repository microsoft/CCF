# CCF Raft model

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
| Safety properties and witnesses        | [`Properties.lean`](CCFRaft/Properties.lean)                                                                                     |
| Proofs of properties and witnesses     | [`Proof.lean`](CCFRaft/Proof.lean) (exported theorems), [`Proofs/`](CCFRaft/Proofs) (implementations)                            |
| Action-trace tests and import layering | [`Tests/CanonicalTraces.lean`](CCFRaft/Tests/CanonicalTraces.lean), [`Tests/Architecture.lean`](CCFRaft/Tests/Architecture.lean) |

Transition systems, traces, effects and network composition come from the local [`ccf_common` package](../common/README.md).
Each node reads membership, quorums and retirement from its own ledger; there is no model-wide configuration after initialization.
Initialization takes a nonempty initial voting membership, whose smallest member starts as primary with the genesis configuration transaction.
Actions are local inputs (including timeouts) or delivery of a queued message; no clock is modeled.

## Properties

[`Properties.lean`](CCFRaft/Properties.lean) states four properties of `Model.transitionSystem`, each with a `Witness` statement exhibiting the situation it constrains:

- Safety property:
  - `CommittedLogsPrefix`: any two committed logs in a trace are prefix-comparable.
  - `SingleNodeCommittedLogMonotonic`: a successful step from any state with unique node IDs preserves each node's committed prefix.
- `ElectionSafety`: no two distinct nodes are primary in the same term.
- `CommittedFrontierIsSignature`: every positive commit index points to a signature.

## Scope

Node join and snapshot installation are not modeled.
There are no liveness properties or fairness assumptions.

## Validation

Install Lean via [elan](https://lean-lang.org/install/), then run from this directory:

```sh
lake exe cache get
lake build --wfail --fail-fast
lake exe check-imports
lake lint
lake check --inadvisably-no-sandbox
../../scripts/lean-format-checks.sh ccf-raft
```

`lake build --wfail` rejects warnings, including `sorry`, and runs two explicit action traces from an initialized network: committing a client request, and adding two nodes then electing a new primary and committing another request.
The reconfiguration trace checks each node's ledger before delivery, after setup, after replication and commitment, after election, and after the new primary's client request.
These are regression examples, not exhaustive checking.
`Tests/ProofCoverage.lean` fails the build unless every property and witness has an exported theorem in `Proof.lean`.
`lake check` re-checks the build in Lean's kernel and rejects nonstandard axioms; it runs without sandboxing, so build-time code must be trusted.
`CCFRaft.lean` reexports `Proof.lean` and its public imports transitively, while importing tests privately.
The shared `check-imports` command rejects modules missing from that import closure.

## Proofs

`Proof.lean` proves all four properties and their witnesses directly against `Model.transitionSystem`.
`Proofs/Direct/` establishes node-local commit invariants; `Proofs/Safety/` establishes the cross-node history invariant used for election safety and committed-log comparability.
`Proofs/Witnesses.lean` supplies concrete executions checked by the kernel.

To list the safety-invariant declarations used by the exported theorems, run `lake env lean scripts/invariant-dependencies.lean`.
