# CCF Raft model

An executable Lean model of CCF's consensus implementation ([`src/consensus/aft/raft.h`](../../src/consensus/aft/raft.h)) and the safety properties it is intended to satisfy.
It assumes familiarity with the [CCF consensus documentation](../../doc/architecture/consensus/index.rst).
[`Proof.lean`](CCFRaft/Proof.lean) proves the properties and their witnesses; see [Proofs](#proofs).

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
| Proof coverage                         | [`Tests/ProofCoverage.lean`](CCFRaft/Tests/ProofCoverage.lean)                                                                   |

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
lake exe mk_all --check --module --lib CCFRaft
lake build --wfail --fail-fast
lake lint
lake check --inadvisably-no-sandbox
../../scripts/lean-format-checks.sh ccf-raft
```

`lake build --wfail` rejects warnings, including `sorry`, and runs two explicit action traces from an initialized network: committing a client request, and adding two nodes then electing a new primary and committing another request.
The reconfiguration trace checks each node's ledger before delivery, after setup, after replication and commitment, after election, and after the new primary's client request.
These are regression examples, not exhaustive checking.
`Tests/ProofCoverage.lean` fails the build unless every property and witness has an exported theorem in `Proof.lean`.
`lake check` re-checks the build in Lean's kernel and rejects nonstandard axioms; it runs without sandboxing, so build-time code must be trusted.
After adding or removing a module, regenerate `CCFRaft.lean` with `lake exe mk_all --module --lib CCFRaft`.

## Proofs

`Proof.lean` proves each property and witness in `Properties.lean`.
The proofs target the current `Model.transitionSystem` directly, with no refinement to another model.
They say nothing about liveness, fairness, or the C++ implementation.

- `Proofs/Direct/` proves node-local facts: commit bounds, signature commit frontiers, and committed-log growth.
  `NodeInvariant` lifts a predicate preserved by every local step to every node of every reachable state.
  `AppendOnly.lean` proves `SingleNodeCommittedLogMonotonic` from any state with distinct node identifiers, without a reachability invariant: each step keeps the committed log as a prefix of the new log and never lowers the commit index.
- `Proofs/Safety/` proves a cross-node invariant over the execution history: terms led, entries accepted and acknowledged, and messages sent.
  `Summary.lean` and `Step.lean` summarize each node step once; the invariant clauses are proved from those summaries.
  Membership comes only from local logs, so the invariant also keeps every nonempty log rooted at the initial primary's genesis configuration transaction and every primary's log nonempty; any two quorums checked against agreeing logs therefore intersect.
  Reconfiguration and retirement facts come from each transaction's metadata; a transaction carries at most one configuration, but one batch may append several reconfiguration transactions.
- `Proofs/Election.lean` and `Proofs/CommittedLogs.lean` derive `ElectionSafety` and `CommittedLogsPrefix` from that invariant.
- `Proofs/Witnesses.lean` proves the witnesses with concrete executions evaluated by the kernel.
  Each infinite trace is a lasso: a finite stem of enabled actions followed by a nonempty cycle of enabled actions that returns exactly to the stem's final state, so no step stutters.
  States contain functions and so lack decidable equality; `kernel_rfl` asks the kernel alone to check that a cycle returns to the same state.

[`scripts/invariant-dependencies.lean`](scripts/invariant-dependencies.lean) lists the `Proofs.Safety` declarations in the kernel dependency closure of the exported theorems, to help remove unused lemmas.
Run it with `lake env lean scripts/invariant-dependencies.lean`.

## Trace replay

The [trace replayer](replay/README.md) checks finite driver observations against direct model transitions, independently of proofs.
It preserves recorded delivery order and packet multiplicity, rejects ambiguous observations, and never repairs model state.
The current native Fluentd capture path and its explicit pre-vote and retirement-index limitations are documented there.

Build with `lake build --wfail --fail-fast` and run `lake exe replay-checks`.
The CI kernel check selects `CCFRaft`, `ccfraft-replay` and `replay-checks` separately because the executables have distinct `main` declarations.
Replay compatibility does not establish universal production inclusion, infinite extension, fairness or liveness.
