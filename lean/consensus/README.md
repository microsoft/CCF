# CCF consensus protocol model

An executable Lean model of the CCF consensus protocol ([`src/consensus/aft/cft.h`](../../src/consensus/aft/cft.h)) and the safety properties it is intended to satisfy.
It assumes familiarity with the [CCF consensus protocol documentation](../../doc/architecture/consensus/index.rst).

## Source map

| Area                                   | Source                                                                                                                         |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Node state, log entries, log queries   | [`Model/NodeState.lean`](Consensus/Model/NodeState.lean)                                                                       |
| Configurations, quorums, retirement    | [`Model/ClusterConfig.lean`](Consensus/Model/ClusterConfig.lean) (`activeConfigurations`, `hasQuorum`, `NodeState.retirement`) |
| Messages                               | [`Model/Messages.lean`](Consensus/Model/Messages.lean)                                                                         |
| Protocol policy (one node's step)      | [`Model/Node.lean`](Consensus/Model/Node.lean) (`Node.step`, `receive`, `act`, `highestCommittableIndex`, `eligiblePeers`)     |
| Initial states and network composition | [`Model.lean`](Consensus/Model.lean) (`initialNodeState`, `transitionSystem`)                                                  |
| Safety theorems and witness lemmas     | [`Properties.lean`](Consensus/Properties.lean)                                                                                 |
| Supporting proofs and executions       | [`Proofs/`](Consensus/Proofs)                                                                                                  |
| Action-trace tests                     | [`Tests/CanonicalTraces.lean`](Consensus/Tests/CanonicalTraces.lean)                                                           |

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
../../scripts/lean-format-checks.sh consensus
```

Run `lake check` only in CI, not locally.
The [kernel check](replay/README.md#kernel-checks) builds with compiler warnings, including `sorry`, treated as errors, before replaying the compiled proofs in Lean's kernel and rejecting nonstandard axioms.
Kernel tracing reports the declarations checked during compilation; cached modules do not emit fresh compilation traces.
CI runs this before import coverage, formatting, and linting so the initial build and its traces occur in this step.
The build also runs explicit action traces from an initialized network: committing a client request, and adding two nodes then electing a new primary and committing another request.
The reconfiguration trace checks each node's ledger before delivery, after setup, after replication and commitment, after election, and after the new primary's client request.
Append regressions check configuration heartbeats followed by flushing, pre-commit packet headers, per-entry flushing, term-bounded packets, and atomic rejection of invalid flush choices.
These are regression examples, not exhaustive checking.
`lake check` checks both default targets, `Consensus` and `consensus-replay`, in one invocation.
It runs without sandboxing here, so build-time code must be trusted.
`Consensus.lean` reexports `Properties.lean` and the replay API transitively, while importing tests privately.
The shared `check-imports` command rejects modules missing from that import closure.

## Proofs

`Properties.lean` contains the full theorem and witness-lemma statements, with one-line proof links into `Proofs/`.
Import `Consensus.Properties` and use `Consensus.Properties.<name>` for these declarations.
Proof modules follow the shared [dependency import contract](../common/README.md#dependency-imports); import additional Mathlib facilities explicitly rather than relying on incidental reexports.
`Proofs/Direct.lean` establishes node-local commit invariants; `Proofs/SafetyInvariant.lean` establishes the cross-node history invariant, in the `Consensus.Proofs.Safety` namespace, used for election safety and committed-log comparability.
`Proofs/Witnesses.lean` supplies concrete executions checked by the kernel.
The proof modules do not import each other, so Lake checks them in parallel; lemmas needed by more than one module are duplicated as private declarations to minimise verification wall-clock time.

To list the safety-invariant declarations used by the exported theorems, run `lake env lean scripts/invariant-dependencies.lean`.

## Trace replay

The [trace replayer](replay/README.md) checks finite driver observations against direct model transitions, independently of proofs.
It uses strict FIFO selection per directed node pair, preserves packet multiplicity, and never repairs model state.
The current native Fluentd capture path and replay's assurance limits are documented there.
