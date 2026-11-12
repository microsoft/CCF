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
| Valid initial memberships              | [`Properties/Config.lean`](Consensus/Properties/Config.lean)                                                                   |
| Supporting proofs and executions       | [`Proofs/`](Consensus/Proofs)                                                                                                  |
| Action-trace tests                     | [`Tests/CanonicalTraces.lean`](Consensus/Tests/CanonicalTraces.lean)                                                           |

Transition systems, traces, effects and network composition come from the local [`ccf_common` package](../common/README.md).
Each node reads membership, quorums and retirement from its own ledger; there is no model-wide configuration after initialization.
Initialization takes a nonempty initial voting membership, whose smallest member starts as primary with the genesis configuration transaction.
Production starts with singleton voting membership; the model also accepts multi-node initial configurations supported by the consensus testing infrastructure.
Actions are local inputs (including timeouts) or delivery of a queued message; no clock is modeled.

## Scope

Like CCF's `init_as_backup`, a fresh node may initialize once as a follower: with an empty ledger in term zero, or from another node's committed ledger prefix ending at a signature, in that signature's term.
Crashes are not modeled, so a committed prefix keeps its history, and a valid snapshot, fetched from another node or read from a local file, is such a prefix ([`Model.networkStep`](Consensus/Model.lean)).
The join protocol is not modeled: a configuration may add any node, and a fresh node may instead follow from its first AppendEntries.
Node identities are never reused, so a configuration may not name a node removed by an earlier configuration in the same log.
`deadlock_free_after_bootstrap` proves the [shared deadlock-freedom property](../common/README.md#transition-systems) for every state reachable once bootstrapping completes, for any initial configuration.
Bootstrapping completes when some node commits a signature; a singleton bootstrap node commits its first signature as soon as it emits it.
`deadlock_free_after_bootstrap_witness` shows that every valid initial configuration reaches such a state.
There are no fairness assumptions or guarantees of eventual election or commitment.

The proof takes the longest committed log prefix and its latest configuration.
A member of that configuration acknowledged the prefix, so its log still contains it and the signature that ends it.
That member cannot have been retired, because a retirement confirmation in the prefix would name a node removed before that configuration, so it is primary or may start an election.

### Counterexamples

Both assumptions are needed.
Before bootstrapping completes, start with voting membership `{0}` and declared nodes `[0, 1]`:

1. Node 0 appends an unsigned transaction changing membership to `{0, 1}`.
   The append sends a heartbeat to node 1 before adding the transaction.
2. Node 0 executes its CheckQuorum timeout and becomes a follower.
   This action is enabled once there is another active member; the model has no clock.
3. Deliver the heartbeat to node 1.
   It becomes a follower in term 2 and rejects the heartbeat because its empty log lacks the preceding genesis entry, queuing a negative acknowledgement.
4. Deliver the acknowledgement to node 0, which ignores it because it is no longer primary.

The network queue is now empty, both nodes are followers, and neither has a signature covering a configuration that permits it to start an election.
The C++ consensus implementation can stall in the same way if CheckQuorum fires before the first signature.

Without the identity guard, a primary may re-add a removed node together with a confirmation of that node's retirement, then retire itself.
Its nominated successor is the re-added node, which is retired-committed and cannot campaign, so no node can act.

## Validation

Install Lean via [elan](https://lean-lang.org/install/), then run from this directory:

```sh
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
The build also runs explicit action traces from an initialized network: committing a client request, and adding two nodes, one joining from a snapshot, then electing a new primary and committing another request.
The reconfiguration trace checks each node's ledger before delivery, after setup, after replication and commitment, after election, and after the new primary's client request.
Append regressions check configuration heartbeats followed by flushing, pre-commit packet headers, per-entry flushing, term-bounded packets, and atomic rejection of invalid flush choices.
These are regression examples, not exhaustive checking.
`lake check` checks both default targets, `Consensus` and `consensus-replay`, in one invocation.
It runs without sandboxing here, so build-time code must be trusted.
`Consensus.lean` reexports `Properties.lean` and the replay API transitively, while importing tests privately.
The shared `check-imports` command rejects modules missing from that import closure.

## Proofs

[`Properties.lean`](Consensus/Properties.lean) contains the full theorem and witness-lemma statements, with one-line proof links into `Proofs/`.
Import `Consensus.Properties` and use `Consensus.Properties.<name>` for these declarations.
Proof modules follow the shared [dependency import contract](../common/README.md#dependency-imports); import additional facilities explicitly rather than relying on incidental reexports.
`Proofs/Direct.lean` establishes node-local commit invariants; `Proofs/SafetyInvariant.lean` establishes the cross-node history invariant, in the `Consensus.Proofs.Safety` namespace, used for election safety and committed-log comparability.
[`Proofs/Witnesses.lean`](Consensus/Proofs/Witnesses.lean) supplies the checked witness implementations, using shared execution-construction helpers in [`Proofs/GenericWitnesses.lean`](Consensus/Proofs/GenericWitnesses.lean).
The safety-invariant proof remains independent of the witness construction, allowing Lake to check them in parallel.
`Proofs/Deadlock.lean` proves deadlock freedom after bootstrapping on top of the cross-node history invariant, so it imports `Proofs/SafetyInvariant.lean` with `import all`.

To list the safety-invariant declarations used by the exported theorems, run `lake env lean scripts/invariant-dependencies.lean`.

## Trace replay

The [trace replayer](replay/README.md) checks finite driver observations against direct model transitions, independently of proofs.
It checks each native send against the model, delivers any matching queued packet, treats undelivered packets as lost, and never repairs model state.
The current native Fluentd capture path and replay's assurance limits are documented there.
