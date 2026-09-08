# Lean disaster recovery model

This package contains the canonical Lean model of CCF's C++ recovery decision
protocol and its permanent safety and liveness proofs. It is pinned to Lean
4.33.1 and Mathlib `v4.33.1`.

## Model

`DisasterRecovery.Protocol.Model` models one protocol node. Its state machine
covers Gossiping, Voting, Opening, Joining, and Open, including the separate
timeout lane, retries, duplicate receives, strict-majority voting, failover,
restart, and completion.

`DisasterRecovery.Protocol.Global` lifts the local transition function to a
system with active nodes, in-flight messages, immutable send history, and
terminal effects. Deliveries consume previously sent envelopes, so receives
cannot appear without a modeled send.

The model follows the current C++ behavior in which a successfully validated
location is not rejected merely because it is absent from
`expectedLocations`. In particular, an accepted gossip from an unexpected
location can satisfy a size threshold. `CanonicalTests.lean` checks this
intentional accepted-unexpected-location behavior so that the implementation
discrepancy remains explicit.

`Validation.accepted` and `Validation.rejected` are the boundary at which the
model receives the result of C++ quote and certificate validation. The model
does not formalize or prove the cryptography that produces that result.

## Review guide

Start with `DisasterRecovery/Properties.lean`: it exposes 15 system-level
`theorem` statements, each with an explicit application of its checked proof.
Review those statements and every definition or assumption they use in
`DisasterRecovery/Protocol/`. Machine checking does not establish that the
model matches the C++ implementation or that its assumptions describe a real
deployment.

The 233 supporting declarations are `lemma`s in
`DisasterRecovery/Proofs/`. Their implementations can normally be omitted from
line-by-line human review once the build and axiom audit pass. Mathlib's
`lemma` is a synonym for `theorem`, not a weaker form of checking. The public
statements remain explicitly linked to these lemmas rather than being detached
specifications.

Declaration namespaces follow the module paths. Model definitions live under
`DisasterRecovery.Protocol.<Module>`, supporting lemmas under
`DisasterRecovery.Proofs.<Module>`, and the 15 reviewed theorems under
`DisasterRecovery.Properties`. For example,
`DisasterRecovery.Properties.gossip_freezes_after_choice` explicitly applies
`DisasterRecovery.Proofs.Temporal.gossip_freezes_after_choice` from
`DisasterRecovery/Proofs/Temporal.lean`. Local and global properties share the
`DisasterRecovery.Properties` namespace; their `Config` and `Execution` types
come from the corresponding protocol modules.

Only the Lean files under `DisasterRecovery/Proofs/` are marked
`linguist-generated` in the repository's `.gitattributes`, so GitHub can collapse
them without collapsing the review-required model and properties. Changes to imports, the review boundary,
the toolchain, dependencies, or checking machinery still require human review.
`DisasterRecovery.lean`, `CanonicalTests.lean`, the Lake configuration and lockfile,
and the CI workflow are part of that review surface.

## Proof coverage and limits

`DisasterRecovery.Proofs.Temporal` proves local safety properties and
Opening-to-Open progress under weak timeout fairness.

`DisasterRecovery.Proofs.Invariants` proves global well-formedness,
message provenance, locality of transitions, append-only send history, and
monotonic terminal histories for reachable states.

`DisasterRecovery.Proofs.Quorum` proves that votes are unique and backed by
prior sends, strict-majority quorums intersect, and any two quorum openings in
a reachable execution select the same opener. This safety result does not
require fairness.

`DisasterRecovery.Proofs.Committed` proves TxID maximum properties and
committed-prefix preservation under two explicit premises:

- `DurableCommit` requires at least one configured recovered ledger to cover
  the committed TxID.
- `FullGossipSelection` requires a real sent vote whose selection snapshot
  contains exactly the configured recovered TxIDs.

A quorum opening alone does not imply `FullGossipSelection`, because voting may
begin after a gossip timeout. The committed-prefix result deliberately does not
derive or hide either durability or full-gossip evidence.

`DisasterRecovery.Proofs.GlobalTemporal` proves conditional global progress.
Its theorems assume the relevant retry, message-delivery, and timeout fairness
premises. Progress for every active node additionally requires
`BroadcastBeforeCompletion`: an opener must send its `IAmOpen` announcement to
every other active node before it completes. Ordinary weak fairness does not
order actions that are enabled only for a finite interval, so this broadcast
ordering is a separate premise. The proofs do not construct a scheduler that
satisfies the fairness and broadcast-before-completion premises.

The `global_progress` property also requires a reachable initial state and a
nonempty active set. Its terminal outcome means completion or a requested
joining restart. The stronger statements that all other nodes request a restart
retain their explicit `OnlyOpenerCompletesFrom` or `QuorumOnlyCompletions`
premises; they do not rule out failover completions without such a premise.

## Files

| File                                            | Review role     | Purpose                                              |
| ----------------------------------------------- | --------------- | ---------------------------------------------------- |
| `DisasterRecovery/Properties.lean`              | Human           | Selected system properties and checked proof links   |
| `DisasterRecovery/Protocol/Model.lean`          | Human           | C++-aligned local transition model                   |
| `DisasterRecovery/Protocol/Global.lean`         | Human           | Distributed transitions and reachability             |
| `DisasterRecovery/Protocol/Temporal.lean`       | Human           | Local execution and fairness definitions             |
| `DisasterRecovery/Protocol/Invariants.lean`     | Human           | Well-formedness and message-provenance predicates    |
| `DisasterRecovery/Protocol/Quorum.lean`         | Human           | Vote and quorum-opening predicates                   |
| `DisasterRecovery/Protocol/Committed.lean`      | Human           | Prefix ordering, durability and full-gossip premises |
| `DisasterRecovery/Protocol/GlobalTemporal.lean` | Human           | Global execution, fairness and termination premises  |
| `DisasterRecovery/Proofs/*.lean`                | Machine-checked | Supporting lemmas and proof implementations          |
| `DisasterRecovery.lean`                         | Human           | Complete library import and audit root               |
| `CanonicalTests.lean`                           | Human           | Executable canonical behavior checks                 |

## Validation

Run from this directory:

```console
lake exe cache get
lake exe mk_all --check --lib DisasterRecovery
lake build --wfail
lake lint
lake exe canonical-checks
```

`lake build --wfail` treats build warnings, including uses of `sorry` and
`admit`, as errors. `lake lint` runs
[`axiom-audit`](https://github.com/leanprover-community/axiom-audit) over the
`DisasterRecovery` library's transitive axiom dependencies. Only `propext`,
`Classical.choice`, and `Quot.sound` are allowed, so `sorryAx`, user-defined
axioms, and `native_decide` dependencies are rejected.

The build compiles the reviewed statements and their proof implementations;
`lake exe canonical-checks` separately exercises the transition model.
`mk_all --check` verifies that `DisasterRecovery.lean` imports every library
module, preventing newly added proofs from being silently omitted from the
build and audit. Run `lake exe mk_all --lib DisasterRecovery` to refresh the
import root when adding a module.

When refreshing the auditor dependency, use
`lake --keep-toolchain update axiomAudit` to retain the package's pinned
Lean and Mathlib versions.
