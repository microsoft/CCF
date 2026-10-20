# CCF Raft model

This Lake package is an executable Lean model of CCF's Raft implementation (`src/consensus/aft/raft.h`), together with the safety properties it is intended to satisfy.
The properties are stated but not yet proved.

## Layout

| Module                             | Contents                                                       |
| ---------------------------------- | -------------------------------------------------------------- |
| `CCFRaft/Model/NodeState.lean`     | Node state, log entries and pure log queries                   |
| `CCFRaft/Model/ClusterConfig.lean` | Ledger-derived membership and retirement queries               |
| `CCFRaft/Model/Messages.lean`      | Messages exchanged between nodes                               |
| `CCFRaft/Model/Node.lean`          | `Node.step`: one node's response to an input or a message      |
| `CCFRaft/Model.lean`               | Model configuration, initialization and network composition    |
| `CCFRaft/Properties.lean`          | Safety property statements and their witnesses                 |
| `CCFRaft/Tests/`                   | Regression theorems, behavior checks and import-boundary rules |
| `CCFRaft.lean`                     | Generated root importing every module                          |

Transition systems, traces, output-recording effects and network composition come from the local [`ccf_common` package](../common/README.md), under the `CCF` namespace.
Both `lakefile.toml` and `lake-manifest.json` reference `../common`, without copying or fetching another CCF checkout.

`Properties.lean` defines `GlobalTrace` alongside the property statements.

`NodeState.lean` holds the state and simple log accessors.
`ClusterConfig.lean` holds configuration and membership queries, including `MembershipState` and `latestMembershipIndex`, plus the configuration-majority and quorum predicates.
`MembershipState.noRetirementObserved` means no membership removal is recorded in the local log; it does not imply that the node has joined.
`NodeState.isRetiredCommitted` queries the derived membership phase, not just the historical commit latch.
`latestConfigurationMembers` reads the final supplied configuration's membership.
Protocol helpers such as `NodeState.recordCommit` and `findHighestPossibleMatch` live in `Node.lean`.

`NodeID` and `ReqID` are aliases for `Nat`; the model, messages and properties take no identifier-type parameters.
Each transaction entry records a request identifier and its consensus metadata.
`TransactionMetadata.retirementConfirmations` names the nodes whose retirement that transaction confirms; the field does not imply that the confirmation transaction has committed.
Once a node's confirmation commits, `NodeState.retiredCommittedIndex` records the confirmation transaction's original one-based log index, matching the version supplied by C++'s nodes-table global commit hook, rather than the covering signature's index.
That first commitment also clears the node's role and primary knowledge on both primary and follower paths; a retiring primary still nominates a successor using its precommit state.
This is a one-time retirement effect, not a restriction on role changes caused by later messages.
Successor nomination orders node IDs numerically when replication progress and configuration membership tie.
`ModelConfig` lives in `Model.lean` and supplies initial voting membership and a primary of type `configuration`, so it is a member by construction.
The modeled node list is supplied separately and may include nodes outside the initial voting membership.
Election timeouts always start a pre-vote round; a same-term primary nomination still starts a regular election directly.
On same-term AppendEntries, a candidate or pre-vote candidate becomes a follower and clears both received-vote tallies and primary knowledge before checking the log, while preserving its vote cast in that term.
Adopting a higher term uses the same reset and also clears the vote cast, matching C++'s `become_aware_of_new_term`.
Vote, pre-vote and AppendEntries responses from outside `eligiblePeers` are discarded before term adoption.
Requests are not subject to that sender filter; higher-term requests can still advance the term even if their vote or entries are subsequently rejected.
`eligiblePeers` approximates C++'s retained `all_other_nodes` using ledger-derived membership and completed retirements; peers introduced only by rolled-back configurations are still not retained in this model.

## Message names

`Message` constructors use the protocol names from `raft.h`, in lower camel case with an explicit `Request` or `Response` suffix.
The C++ `raft_request_pre_vote` and `raft_propose_request_vote` messages correspond to `requestPreVoteRequest` and `proposeRequestVoteRequest`; their handlers are `handleRequestPreVoteRequest` and `handleProposeRequestVoteRequest`.
The other constructors are `appendEntriesRequest`, `appendEntriesResponse`, `requestVoteRequest`, `requestVoteResponse` and `requestPreVoteResponse`.
Pre-vote and regular-vote messages still share the `RequestVoteRequest` and `RequestVoteResponse` payload structures; the names do not change their contents or behavior.

## Initialization and local knowledge

`ModelConfig` is used only to initialize node states; `Node.step` and the membership queries take no model-wide configuration.
Only the initial primary starts with the unsigned configuration transaction.
Other initial members start as followers with empty logs; nodes outside the initial membership start without a protocol role.
An empty log has no known membership, and no configuration is injected at index zero.

Membership, quorum and retirement queries read each node's own ledger.
No quorum exists without a configuration, and campaigning requires locally signed membership or locally recorded completed retirement.
A running node can receive replication before it is eligible to campaign; the network's `active` list controls execution independently of membership.
The initial primary can replicate and sign its genesis transaction through ordinary primary actions, without a persistent initial-primary exception.
Rolling back a configuration or its covering signature immediately changes the corresponding local queries.
When AppendEntries overlaps the local log, matching terms retain the existing entries; a new follower rolls back only to immediately before the first term conflict, matching C++.
Committing a signature requires a separate majority in every active configuration whose transaction is at or before that signature.
A later pending configuration does not block an earlier signature; this intentionally differs from the current C++ `update_commit` policy, tracked in [#8606](https://github.com/microsoft/CCF/issues/8606).
Election quorums still require majorities in every active configuration.

Service creation is represented by initialization rather than an action.
Explicit join and snapshot-install lifecycle actions are not modeled.

## Validation

The package's `lean-toolchain` is a symlink to [`../lean-toolchain`](../lean-toolchain), shared with the disaster recovery package.

Install Lean via [elan](https://lean-lang.org/install/), then run from this directory:

```sh
lake exe cache get
lake exe mk_all --check --module --lib CCFRaft
lake build --wfail --fail-fast
lake lint
lake check --inadvisably-no-sandbox
../../scripts/lean-format-checks.sh ccf-raft
```

The Lean CI workflow groups formatting and linting in one step and import-root, build and kernel checks in another.
The Mathlib-free `ccf_common` package also receives build, lint and kernel checks; it does not run the Mathlib cache or `mk_all` tools.

- `mk_all --check` fails if `CCFRaft.lean` does not import every module.
- `lake build --wfail` builds the library, treating warnings, including `sorry`, as errors.
- Canonical behavior checks run through `#eval` when `Tests/CanonicalTests.lean` is compiled; failures fail the build.
- `lake check` re-checks all default targets with Lean's kernel and fails on any axiom other than `propext`, `Classical.choice` and `Quot.sound`.
  It runs without sandbox isolation, so build-time code must be trusted; Lake prints a warning saying so.
- The formatting script runs the pinned [leanfmt](https://github.com/duckki/leanfmt).
  Pass `-f` before the package name to rewrite files in place.

`Properties.lean` states four properties of `Model.transitionSystem`:

- `ElectionSafety`: no two distinct nodes are primary in the same term.
- `CommittedLogsPrefix`: any two committed logs in a trace are prefix-comparable.
- `SingleNodeCommittedLogMonotonic`: a successful network step from a state with unique node IDs preserves each node's committed prefix, without assuming reachability.
- `CommittedFrontierIsSignature`: every positive commit index points to a signature.

The other three properties quantify over valid countably infinite traces, with states indexed by `Nat`.
Validity requires an initial state and an enabled action between every adjacent pair, without fairness or implicit stuttering.
These claims only cover states on infinite executions; they do not independently cover finite executions that cannot extend forever.
Each has a `Witness` statement exhibiting the situation it constrains, such as two distinct primaries.
The single-node witness requires unique starting node IDs and a successful step that strictly extends a nonempty committed log.
Liveness is not stated.

Modules are layered in order: `ccf_common`, then the model, then the properties.
A module may import only from its own layer or an earlier one, and nothing may import a proof module or a package-local `CCFRaft.Shared` copy of `ccf_common`.
`Tests/Architecture.lean` enforces this ordering when the package builds.

After adding or removing a module, regenerate `CCFRaft.lean` with `lake exe mk_all --module --lib CCFRaft`.
