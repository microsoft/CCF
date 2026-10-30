# CCF-Raft model

An executable Lean model of CCF's consensus implementation ([`src/consensus/aft/raft.h`](../../src/consensus/aft/raft.h)) and the safety properties it is intended to satisfy.
It assumes familiarity with the [CCF consensus documentation](../../doc/architecture/consensus/index.rst).

## Source map

| Area                                   | Source                                                                                                                       |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Node state, log entries, log queries   | [`Model/NodeState.lean`](CCFRaft/Model/NodeState.lean)                                                                       |
| Configurations, quorums, retirement    | [`Model/ClusterConfig.lean`](CCFRaft/Model/ClusterConfig.lean) (`activeConfigurations`, `hasQuorum`, `NodeState.retirement`) |
| Messages                               | [`Model/Messages.lean`](CCFRaft/Model/Messages.lean)                                                                         |
| Protocol policy (one node's step)      | [`Model/Node.lean`](CCFRaft/Model/Node.lean) (`Node.step`, `receive`, `act`, `highestCommittableIndex`, `eligiblePeers`)     |
| Initial states and network composition | [`Model.lean`](CCFRaft/Model.lean) (`initialNodeState`, `transitionSystem`)                                                  |
| Safety theorems and witness lemmas     | [`Properties.lean`](CCFRaft/Properties.lean)                                                                                 |
| Supporting proofs and executions       | [`Proofs/`](CCFRaft/Proofs)                                                                                                  |
| Action-trace tests                     | [`Tests/CanonicalTraces.lean`](CCFRaft/Tests/CanonicalTraces.lean)                                                           |

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
lake build --wfail --fail-fast
lake exe check-imports
lake lint
lake exe replay-checks
../../scripts/lean-format-checks.sh ccf-raft
```

Run `lake check` only in CI, not locally.
The [per-root kernel checks](replay/README.md#kernel-checks) build with compiler warnings, including `sorry`, treated as errors, before separately replaying the compiled proofs in Lean's kernel and rejecting nonstandard axioms.
Kernel tracing reports the declarations checked during compilation; cached modules do not emit fresh compilation traces.
CI runs this before import coverage, formatting, and linting so the initial build and its traces occur in this step.
The build also runs explicit action traces from an initialized network: committing a client request, and adding two nodes then electing a new primary and committing another request.
The reconfiguration trace checks each node's ledger before delivery, after setup, after replication and commitment, after election, and after the new primary's client request.
Append regressions check configuration heartbeats followed by flushing, pre-commit packet headers, per-entry flushing, term-bounded packets, and atomic rejection of invalid flush choices.
These are regression examples, not exhaustive checking.
`lake check` runs without sandboxing here, so build-time code must be trusted.
`CCFRaft.lean` reexports `Properties.lean` and the replay API transitively, while importing tests privately.
The shared `check-imports` command rejects modules missing from that import closure.

## Proofs

`Properties.lean` contains the full theorem and witness-lemma statements, with one-line proof links into `Proofs/`.
Import `CCFRaft.Properties` and use `CCFRaft.Properties.<name>` for these declarations.
`Proofs/Direct/` establishes node-local commit invariants; `Proofs/Safety/` establishes the cross-node history invariant used for election safety and committed-log comparability.
`Proofs/Witnesses.lean` supplies concrete executions checked by the kernel.

To list the safety-invariant declarations used by the exported theorems, run `lake env lean scripts/invariant-dependencies.lean`.

## Trace replay

The [trace replayer](replay/README.md) checks finite driver observations against direct model transitions, independently of proofs.
It uses strict FIFO selection per directed node pair, preserves packet multiplicity, and never repairs model state.
The current native Fluentd capture path and replay's assurance limits are documented there.
