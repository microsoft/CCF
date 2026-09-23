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

`Local.step` is the single event dispatcher. Its enabled computation returns
only the next node state. It calls `host.send` for messages and `host.notify`
for opening, restart, completion, and rejection notifications. An ignored
receive leaves the node state unchanged and emits a notification; it is not
a disabled action.

`DisasterRecovery.Shared.Capabilities` defines the two output-only callbacks.
Both return `Unit`. `Outputs Node Message Notification` holds separate
`outgoing` and `notifications` lists. `Effect Node Message Notification` is
`StateM (Outputs Node Message Notification)`.

`Capabilities.record node` supplies the recording callbacks used by both
network execution and local property statements. Sends append complete envelopes
with `node` as source; notifications append only to the notification list.
Neither callback inspects the network or recipient state. The lists preserve
their own order, not the relative order between sends and notifications.
Local does not construct or thread the output accumulator.

`Local.step host config recovered state event` returns
`Option (Effect Location Message Notification NodeState)`.
The outer `Option` decides enabledness before any sends or notifications execute.
An enabled computation cannot subsequently return "disabled".
Receive and timeout handling live directly in `step`. Retry branches call
`host.send` directly, supplying the node's recovered transaction ID for gossip.
They do not build or convert intermediate send-effect lists. Their guards disable
empty retries before any send executes.

`DisasterRecovery.Shared.MultiNodeTransitionSystem` supplies the reusable network. Its state
contains only node states, active nodes, and queued messages. Envelopes contain only source,
target, and payload. `MultiNodeTransitionSystem.Protocol` supplies local initial predicates,
optional effect computations, and receive and autonomous-input adapters.
`MultiNodeTransitionSystem.lift` constructs a network transition system from that interface.
`MultiNodeTransitionSystem.next` handles both action kinds directly. It selects the node and local
event, checks node availability, supplies recording capabilities, and executes the
enabled computation with both output lists empty. It then updates the node and
appends `effects.outgoing` directly to the global queue, without a conversion pass.
Notifications do not enter the queue or persistent global state.

Delivery atomically consumes one queued occurrence, runs the receiving node,
and appends its outgoing messages with that node as their source. The local step
runs once; there is no separate outgoing-message callback.
Delivery can select any queued message, not just the head.
If any part is disabled, no successor state
is produced. An identical new reply may remain queued after the old occurrence
is consumed. Autonomous actions do not consume queued messages, even when a
protocol deliberately maps one to local receive logic.

`Model.Config` owns the DR configuration and recovered transaction IDs.
`Model.protocol` supplies the adapters shared by global assembly and local
property statements. Its step looks up the node's recovered TxID and calls Local
directly. `Model.transitionSystem` passes that protocol to `MultiNodeTransitionSystem.lift` and
combines configuration validity with the network's initial-state predicate.
DR exposes only retry and timeout as
autonomous inputs, so its receives come from queued messages. Sends remain
retry-driven, active nodes remain fixed, and empty retries are disabled.
`Model.GlobalHelper.receive` translates a delivered message into a local event.
This network adapter lives outside `Model.Local`.
Tests construct initial states with `Tests.initial`; the model specifies them
through its initialization predicate.

`MultiNodeTransitionSystem.LocalStep` records a node, before-state, local action, after-state,
and collected effects. `Properties.LocalStep` specializes it to DR. `protocol.ValidStep s` holds exactly when the protocol's
recorded execution succeeds with the state and effects in `s`. This relation
does not require reachability, node activity, or a queued input message.
Local properties quantify these records, constrain their actions and before-states,
and assert facts about their after-states and notifications. They constrain
successful steps only; they do not assert that receives must be enabled.

Global properties use the same record-and-validity pattern:

```lean
forall (config : Model.Config) (trace : Properties.GlobalTrace),
	trace.Valid (Model.transitionSystem config) -> ...
```

`GlobalTrace` specializes `Shared.Execution.Trace` to the DR model. A trace is a
list of states, initial state first. It records no actions. `trace.Valid system`
requires a nonempty list, an initial first state, and some enabled action between
each pair of adjacent states. It does not assume a safety invariant. Properties
quantify every valid finite trace, so they cover every valid prefix.

Each property has a `Witness` claim stating that its premises hold together in
some execution or local step, so the property is not vacuous.

Canonical tests construct their own standalone transition system by executing
`Local.step` with recording capabilities and taking its returned node state.
Empty retries are disabled in both standalone exploration and the network model.

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

Start with `DisasterRecovery/Properties.lean`: it exposes local-step and global
claims as named `Prop` definitions. `DisasterRecovery/Proof.lean` links each
claim to its checked proof without repeating the statement.
The statements inline structural, quorum, and commit-ordering conditions rather
than referring to single-property invariant bundles. `Properties/Utils.lean`
holds the helpers the statements share: `GlobalTrace`, `LocalStep`,
`Trace.NotificationAt`, `ReceivedOwnGossip`, `LogUpToDate`, and
`UpToDateWithQuorum`.
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
use `DisasterRecovery.Shared.MultiNodeTransitionSystem`, `DisasterRecovery.Model`, and
`DisasterRecovery.Model.Local`, respectively. Property helpers live under
`DisasterRecovery.Properties.Utils`, supporting lemmas under
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
It also proves that the callbacks cannot affect DR's enabledness or returned
node state, even with nonempty pending outputs. Notification assertions use
recording capabilities, not arbitrary host callbacks.

The local claims cover frozen gossip, rejected gossip, quorum advancement, and
aligned opening completion. `QuorumAdvanceOpens` concerns timeout or accepted-vote
steps from voting with an already-sufficient quorum. It does not assert that
retries or rejected messages advance the phase. The general advancement lemma
remains in the supporting proofs.

Ghost executions retain the send-time evidence and event histories needed by
the safety proofs. `Proofs.ExecutionLocal` and `Proofs.Execution` define the
instrumented transitions; `Proofs.Predicates` defines their invariants.
`Proofs.Lifting.model_execution_lifts` lifts every finite execution from a
reachable model state, preserving the projected action sequence and endpoint
states. It does not merely show that some ghost executions obey the model.
Initial-state, step, and reachable-state lifting lemmas cover the same
correspondence.

`Shared.Execution` defines runs and traces independently of the protocol proofs.
`Trace.Valid.reachable` shows every state of a valid trace is reachable, and
`reachable_iff_trace` shows valid traces cover exactly the reachable states.

`Trace.NotificationAt config trace step node notification` relates trace states
`step` and `step + 1`. Some action by `node` must take the first to the second,
and `node`'s local run for that action must emit `notification` and produce
`node`'s state in `step + 1`. The trace records no actions, so the action is
existentially quantified.

The proof implementations transfer safety results from decorated executions to
the actual model. Ghost histories and erasure witnesses stay inside `Proofs/`;
they are not assumptions in the public property definitions.
`QuorumOpenerUnique` states that any two steps emitting quorum-opening
notifications in a valid trace belong to the same node.

`Proofs.History.history_correspondence` relates every valid model trace to a
decorated execution, including correspondence of actual sends.
Well-formedness and quorum invariants remain supporting ghost lemmas, not public
properties. Public claims require model execution validity, not a convenient
ghost witness.

`DisasterRecovery.Proofs.Invariants` proves global well-formedness,
message provenance, locality of transitions, append-only send history, and
monotonic terminal histories for reachable states.

`DisasterRecovery.Proofs.Quorum` proves that votes are unique and backed by
prior sends, strict-majority quorums intersect, and any two quorum openings in
a reachable execution select the same opener. This safety result is independent
of scheduling assumptions.

The commit-safety claims now conclude `UpToDateWithQuorum config openerTxID`.
This means the opener passes Raft's log freshness check against a strict majority
of configured recovered ledgers. `LogUpToDate candidate voter` compares their last
signed TxIDs by view first, then sequence number, matching
[`recv_request_vote`](../../src/consensus/aft/raft.h).
Valid model configurations provide one recovered ledger per configured node.

`QuorumOpenPreservesCommit` requires the voters in an opened state to have received
their own gossip somewhere in the trace. `FullGossipPreservesCommit` instead
requires a state with complete gossip at every node, and covers failover openings too.
Neither premise orders the gossip state relative to the opened state.

This is an election freshness condition, not a definition of Raft commitment.
[`update_commit`](../../src/consensus/aft/raft.h) requires replication agreement and
a current-term signature. The
[Raft safety specification](../../tla/consensus/ccfraft.tla) states committed-log
preservation using actual prefixes. DR stores only last signed TxIDs, so relating
its freshness condition to prefix preservation requires valid Raft log histories
and the relevant membership configuration. That connection is not proved here;
DR models one fixed configuration, not Raft reconfiguration.

The previous `ContainsRaftCommittable` condition only bounded TxIDs dominated by
a majority of summaries. It was not the Raft voting condition: with four nodes
at `(1,5), (1,5), (1,10), (1,10)`, it admitted `(1,5)`, which passes only two voters'
freshness checks. `UpToDateWithQuorum` rejects it. `Tests/RaftFreshness.lean` checks
this distinction, strict-majority boundaries, and the view-first comparison.
Protocol proof migration remains paused; the revised claims are not yet proved.

Liveness, fairness, progress, and termination properties are out of scope at
this stage.

## Files

| File                                                     | Review role     | Purpose                                               |
| -------------------------------------------------------- | --------------- | ----------------------------------------------------- |
| `DisasterRecovery/Model.lean`                            | Human           | DR configuration and network composition              |
| `DisasterRecovery/Shared/TransitionSystem.lean`          | Human           | Shared initial-state and optional-transition API      |
| `DisasterRecovery/Shared/Capabilities.lean`              | Human           | Host-provided send callback and accumulating effects  |
| `DisasterRecovery/Shared/Execution.lean`                 | Human           | Protocol-independent runs and contiguous traces       |
| `DisasterRecovery/Properties.lean`                       | Human           | Named property statements without proof dependencies  |
| `DisasterRecovery/Proof.lean`                            | Human           | Theorem links establishing the named properties       |
| `DisasterRecovery/Model/Local.lean`                      | Human           | C++-aligned local transition model                    |
| `DisasterRecovery/Model/GlobalHelper.lean`               | Human           | Network-to-local event adapter                        |
| `DisasterRecovery/Shared/MultiNodeTransitionSystem.lean` | Human           | Reusable atomic message-passing network               |
| `DisasterRecovery/Properties/Utils.lean`                 | Human           | Trace, local-step, Raft freshness, and gossip helpers |
| `DisasterRecovery/Proofs/*.lean`                         | Machine-checked | Supporting lemmas and proof implementations           |
| `DisasterRecovery.lean`                                  | Human           | Complete library import and audit root                |
| `DisasterRecovery/Tests/CanonicalTests.lean`             | Human           | Executable canonical behavior checks                  |
| `DisasterRecovery/Tests/Network.lean`                    | Human           | Generic network and synthetic-receive checks          |
| `DisasterRecovery/Tests/Architecture.lean`               | Human           | Module boundaries and removed model API checks        |
| `DisasterRecovery/Tests/Trace.lean`                      | Human           | Actual sends, outputs, and trace regression cases     |
| `DisasterRecovery/Tests/Execution.lean`                  | Human           | Generic state-trace validity checks                   |
| `DisasterRecovery/Tests/RaftFreshness.lean`              | Human           | Raft freshness and strict-majority boundary checks    |
| `DisasterRecovery/Tests/Initial.lean`                    | Human           | Test-only initial-state constructor                   |

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
