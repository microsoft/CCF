# CCF Raft model

An executable Lean model of CCF's consensus implementation ([`src/consensus/aft/raft.h`](../../src/consensus/aft/raft.h)) and the safety properties it is intended to satisfy.
It assumes familiarity with the [CCF consensus documentation](../../doc/architecture/consensus/index.rst).
The safety claims and their witness statements are unproved and live in `Conjectures.lean`, not `Theorems.lean`.

## Source map

| Area                                   | Source                                                                                                                           |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Node state, log entries, log queries   | [`Model/NodeState.lean`](CCFRaft/Model/NodeState.lean)                                                                           |
| Configurations, quorums, retirement    | [`Model/ClusterConfig.lean`](CCFRaft/Model/ClusterConfig.lean) (`activeConfigurations`, `hasQuorum`, `NodeState.retirement`)     |
| Messages                               | [`Model/Messages.lean`](CCFRaft/Model/Messages.lean)                                                                             |
| Protocol policy (one node's step)      | [`Model/Node.lean`](CCFRaft/Model/Node.lean) (`Node.step`, `receive`, `act`, `highestCommittableIndex`, `eligiblePeers`)         |
| Initial states and network composition | [`Model.lean`](CCFRaft/Model.lean) (`initialNodeState`, `transitionSystem`)                                                      |
| Unproved safety claims and witnesses   | [`Conjectures.lean`](CCFRaft/Conjectures.lean)                                                                                   |
| Action-trace tests and import layering | [`Tests/CanonicalTraces.lean`](CCFRaft/Tests/CanonicalTraces.lean), [`Tests/Architecture.lean`](CCFRaft/Tests/Architecture.lean) |

Transition systems, traces, effects and network composition come from the local [`ccf_common` package](../common/README.md).
Each node reads membership, quorums and retirement from its own ledger; there is no model-wide configuration after initialization.
Initialization takes a nonempty initial voting membership, whose smallest member starts as primary with the genesis configuration transaction.
Actions are local inputs (including timeouts) or delivery of a queued message; no clock is modeled.

## Conjectures

[`Conjectures.lean`](CCFRaft/Conjectures.lean) defines four unproved claims in `CCFRaft.Conjectures`, each with an unproved `Witness` statement describing the situation it constrains:

- Safety property:
  - `CommittedLogsPrefix`: any two committed logs in a trace are prefix-comparable.
  - `SingleNodeCommittedLogMonotonic`: a successful step from any state with unique node IDs preserves each node's committed prefix.
- `ElectionSafety`: no two distinct nodes are primary in the same term.
- `CommittedFrontierIsSignature`: every positive commit index points to a signature.

Once proved, claims and their witnesses belong as explicit theorem statements in `Theorems.lean`, with proof implementations under `Proofs/`, as described in the [Lean module guide](../AGENT.md).

## Scope

Node join and snapshot installation are not modeled.
There are no liveness properties or fairness assumptions.

## Validation

Install Lean via [elan](https://lean-lang.org/install/), then run from this directory:

```sh
lake exe cache get
lake exe mk_all --check --module --lib CCFRaft
lake build --wfail --fail-fast
lake lint
lake check --inadvisably-no-sandbox
../../scripts/lean-format-checks.sh ccf-raft
```

`lake build --wfail` rejects warnings, including `sorry`, and runs two explicit action traces from an initialized network: committing a client request, and adding two nodes then electing a new primary and committing another request.
The reconfiguration trace checks each node's ledger before delivery, after setup, after replication and commitment, after election, and after the new primary's client request.
These are regression examples, not exhaustive checking.
`lake check` re-checks the build in Lean's kernel and rejects nonstandard axioms; it runs without sandboxing, so build-time code must be trusted.
After adding or removing a module, regenerate `CCFRaft.lean` with `lake exe mk_all --module --lib CCFRaft`.
