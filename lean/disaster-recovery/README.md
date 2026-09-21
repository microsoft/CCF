# Lean disaster recovery model

This package contains the canonical Lean model of CCF's C++ recovery decision
protocol and its permanent safety proofs.

See [the Lean module guide](../AGENT.md) for module ownership and the
separation between property statements and proof machinery.

## Model

`DisasterRecovery/Model.lean` assembles the DR protocol from a local state machine
and a reusable network. Import `DisasterRecovery.Model` without loading property
definitions or proofs. `DisasterRecovery/Properties.lean` defines the named
claims without importing their proofs. `DisasterRecovery/Proof.lean` exports
theorems establishing those claims. The package-level `DisasterRecovery.lean`
imports every module for the build and axiom audit.

Reusable infrastructure lives under `DisasterRecovery/Shared/`.
`DisasterRecovery.Shared.TransitionSystem` defines the shared API:
`init : State -> Prop` and `step : State -> Action -> Option State`.
A step returns `none` when the action is disabled. An enabled action can return
`some` with unchanged state. `TransitionSystem.Reachable` closes the initial
states under successful steps.

`DisasterRecovery.Model.Local` models one protocol node. Its state machine
covers Gossiping, Voting, Opening, Joining, and Open, including the separate
timeout lane, retries, duplicate receives, strict-majority voting, failover,
restart, and completion.

`Local.transitionSystem config location` uses `NodeState` directly for standalone
exploration. `Local.transition` exposes state changes and non-send effects,
including opening, restart, completion, and rejection diagnostics. Effects are outputs,
not accumulated node history. An ignored receive returns unchanged node state
with a diagnostic; it is not a disabled action.

`DisasterRecovery.Shared.Capabilities` defines the host-provided send callback:
`send : Message -> Node -> Effect Node Message Unit`. The host owns the outbox.
Its callback appends messages without inspecting the network or recipient state.
Local receives the callback and does not construct or thread the outbox.
`Effect Node Message` is `StateM (List (Prod Node Message))`, with transparent
accumulation semantics rather than opaque mutable references.

`Local.step host config recovered state event` returns
`Option (Effect Location Message NodeState)`.
The outer `Option` decides enabledness before any sends execute. An enabled
computation returns the next state and cannot subsequently return "disabled".
Receive and timeout steps run the local transition once. Retry branches call
`host.send` directly, supplying the node's recovered transaction ID for gossip.
They do not build or convert intermediate send-effect lists. Their guards disable
empty retries before any send executes.

`DisasterRecovery.Shared.Global` supplies the reusable network. Its state
contains only node states, active nodes, and queued messages. Envelopes contain only source,
target, and payload. `Global.Protocol` supplies local initial predicates,
optional effect computations, and receive and autonomous-input adapters.
`Global.lift` constructs a network transition system from that interface.
`Global.runStep` supplies the send callback and executes an enabled computation
on an empty outbox, returning its state and collected messages.

Delivery atomically consumes one queued occurrence, runs the receiving node,
and appends its outgoing messages with that node as their source. The local step
runs once; there is no separate outgoing-message callback.
If any part is disabled, no successor state
is produced. An identical new reply may remain queued after the old occurrence
is consumed. Autonomous actions do not consume queued messages, even when a
protocol deliberately maps one to local receive logic.

`Model.Config` owns the DR configuration and recovered transaction IDs.
`Model.protocol` supplies the adapters. DR exposes only retry and timeout as
autonomous inputs, so its receives come from queued messages. Sends remain
retry-driven, active nodes remain fixed, and empty retries are disabled.
`Model.transitionSystem` combines configuration validity with the network's
initial-state predicate; `Model.Reachable` uses shared reachability.

The model has no send history, source-state snapshots, or terminal-event
histories. These belong to proof-side ghost executions under
`DisasterRecovery/Proofs/`, not to the network or local-state interfaces.

`DisasterRecovery/Properties/` contains the state and execution predicates needed
to understand the claims. Historical premises describe actual model executions,
not a proof-specific ghost state. These helpers and `Properties.lean` depend only
on the model, shared definitions, and other property helpers. Supporting proofs
remain grouped by topic under `DisasterRecovery.Proofs`.

The model follows the current C++ behavior in which a successfully validated
location is not rejected merely because it is absent from
`expectedLocations`. In particular, an accepted gossip from an unexpected
location can satisfy a size threshold.
`DisasterRecovery/Tests/CanonicalTests.lean` checks this intentional
accepted-unexpected-location behavior so that the implementation discrepancy
remains explicit.

`Validation.accepted` and `Validation.rejected` are the boundary at which the
model receives the result of C++ quote and certificate validation. The model
does not formalize or prove the cryptography that produces that result.

## Review guide

Start with `DisasterRecovery/Properties.lean`: it exposes system-level
claims as named `Prop` definitions. `DisasterRecovery/Proof.lean` links each
claim to its checked proof without repeating the statement.
Review those statements and every definition or assumption they use in
`DisasterRecovery/Model.lean`, `DisasterRecovery/Shared/`,
`DisasterRecovery/Model/`, and `DisasterRecovery/Properties/`.
Also review the projection and
lifting statements in `DisasterRecovery/Proofs/Lifting.lean`: these connect the ghost
execution to the actual model.
Machine checking does not establish that the
model matches the C++ implementation or that its assumptions describe a real
deployment.

Supporting proofs live in `DisasterRecovery/Proofs/`.
Their implementations can normally be omitted from
line-by-line human review once the build and axiom audit pass. Mathlib's
`lemma` is a synonym for `theorem`, not a weaker form of checking. The public
statements remain explicitly linked to these lemmas rather than being detached
specifications.

Lean module directories and filenames use PascalCase. Declaration namespaces
follow the module paths. The generic network, DR assembly, and local protocol
use `DisasterRecovery.Shared.Global`, `DisasterRecovery.Model`, and
`DisasterRecovery.Model.Local`, respectively. Property helpers live under
`DisasterRecovery.Properties.Helpers`, supporting lemmas under
`DisasterRecovery.Proofs.<Module>`, and the exported theorems under
`DisasterRecovery.Proof`. For example,
`DisasterRecovery.Proof.gossip_freezes_after_choice` explicitly applies
`DisasterRecovery.Proofs.Local.gossip_freezes_after_choice` from
`DisasterRecovery/Proofs/Local.lean` to establish the corresponding named
property. Local and global property definitions share the
`DisasterRecovery.Properties` namespace.

Only the Lean files under `DisasterRecovery/Proofs/` are marked
`linguist-generated` in the repository's `.gitattributes`, so GitHub can collapse
them without collapsing the review-required model and properties. Changes to imports, the review boundary,
the toolchain, dependencies, or checking machinery still require human review.
`DisasterRecovery.lean`, `DisasterRecovery/Tests/*.lean`, the Lake
configuration and lockfile, and the CI workflow are part of that review surface.

## Proof coverage and limits

`DisasterRecovery.Proofs.Local` proves local transition-safety properties.
It also proves that the send callback cannot affect DR's enabledness or returned
node state, even when the computation starts with a nonempty output accumulator.

Ghost executions retain the send-time evidence and event histories needed by
the safety proofs. `Proofs.ExecutionLocal` and `Proofs.Execution` define the
instrumented transitions; `Proofs.Predicates` defines their invariants.
`Proofs.Lifting.model_execution_lifts` lifts every finite execution from a
reachable model state, preserving the projected action sequence and endpoint
states. It does not merely show that some ghost executions obey the model.
Initial-state, step, and reachable-state lifting lemmas cover the same
correspondence.

`Shared.Execution` defines runs and traces independently of the protocol proofs.
`Properties.History.History config state` describes an initialized model execution
ending at `state`. Its transitions record the actual before-state, action, and
after-state; the trace requires valid, contiguous steps. Send observations refer
to executed retries, not merely states in which a node could send.

The proof implementations transfer safety results from decorated executions to
the actual model. Ghost histories and erasure witnesses stay inside `Proofs/`;
they are not assumptions in the public property definitions. Current-node
quorum uniqueness and historical quorum uniqueness have separate public
statements.

`Proofs.History.history_correspondence` relates every model history to a decorated
execution, including correspondence of actual sends. The history obligations in
the public well-formedness and quorum invariants cover every model history ending
at the state, rather than selecting a convenient ghost witness.

`DisasterRecovery.Proofs.Invariants` proves global well-formedness,
message provenance, locality of transitions, append-only send history, and
monotonic terminal histories for reachable states.

`DisasterRecovery.Proofs.Quorum` proves that votes are unique and backed by
prior sends, strict-majority quorums intersect, and any two quorum openings in
a reachable execution select the same opener. This safety result is independent
of scheduling assumptions.

`DisasterRecovery.Proofs.Committed` proves TxID maximum properties and
committed-prefix preservation under two explicit premises:

- `DurableCommit` requires at least one configured recovered ledger to cover
  the committed TxID.
- `FullGossipSelection` requires an actual vote send in the model execution,
  with the sender's gossip containing exactly the configured recovered TxIDs.

A quorum opening alone does not imply `FullGossipSelection`, because voting may
begin after a gossip timeout. The committed-prefix result deliberately does not
derive or hide either durability or full-gossip evidence.

Liveness, fairness, progress, and termination properties are out of scope at
this stage.

## Files

| File                                            | Review role     | Purpose                                              |
| ----------------------------------------------- | --------------- | ---------------------------------------------------- |
| `DisasterRecovery/Model.lean`                   | Human           | DR configuration and network composition             |
| `DisasterRecovery/Shared/TransitionSystem.lean` | Human           | Shared initial-state and optional-transition API     |
| `DisasterRecovery/Shared/Capabilities.lean`     | Human           | Host-provided send callback and accumulating effects |
| `DisasterRecovery/Shared/Execution.lean`        | Human           | Protocol-independent runs and contiguous traces      |
| `DisasterRecovery/Properties.lean`              | Human           | Named property statements without proof dependencies |
| `DisasterRecovery/Proof.lean`                   | Human           | Theorem links establishing the named properties      |
| `DisasterRecovery/Model/Local.lean`             | Human           | C++-aligned local transition model                   |
| `DisasterRecovery/Shared/Global.lean`           | Human           | Reusable atomic message-passing network              |
| `DisasterRecovery/Properties/Helpers.lean`      | Human           | Safety predicates, prefix ordering, and assumptions  |
| `DisasterRecovery/Properties/History.lean`      | Human           | Model-history observations and historical predicates |
| `DisasterRecovery/Proofs/*.lean`                | Machine-checked | Supporting lemmas and proof implementations          |
| `DisasterRecovery.lean`                         | Human           | Complete library import and audit root               |
| `DisasterRecovery/Tests/CanonicalTests.lean`    | Human           | Executable canonical behavior checks                 |
| `DisasterRecovery/Tests/Network.lean`           | Human           | Generic network and synthetic-receive checks         |
| `DisasterRecovery/Tests/Architecture.lean`      | Human           | Shared, model, and property dependency checks        |
| `DisasterRecovery/Tests/History.lean`           | Human           | Actual-send and model-history regression cases       |

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
`Tests/Architecture.lean` checks the compiled import graph for `Properties.lean`.
It rejects proof imports, including transitive dependencies, and imports that
reverse the shared, model, and property layers.
`mk_all --check` verifies that `DisasterRecovery.lean` imports every library
module, including the tests module, preventing newly added proofs from being
silently omitted from the build and audit. Run
`lake exe mk_all --lib DisasterRecovery` to refresh the import root when adding
a module.

When refreshing the auditor dependency, use
`lake --keep-toolchain update axiomAudit` to retain the package's pinned
Lean and Mathlib versions.
