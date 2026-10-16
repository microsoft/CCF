# CCF Raft model

This Lake package is an executable Lean model of CCF's Raft implementation (`src/consensus/aft/raft.h`), together with the safety properties it is intended to satisfy.
The properties are stated but not yet proved.

## Layout

| Module                             | Contents                                                       |
| ---------------------------------- | -------------------------------------------------------------- |
| `CCFRaft/Model/NodeState.lean`     | Node state, log entries and pure log queries                   |
| `CCFRaft/Model/ClusterConfig.lean` | Initial configuration, membership and retirement queries       |
| `CCFRaft/Model/Messages.lean`      | Messages exchanged between nodes                               |
| `CCFRaft/Model/Node.lean`          | `Node.step`: one node's response to an input or a message      |
| `CCFRaft/Model.lean`               | Composition of nodes into a network                            |
| `CCFRaft/Properties.lean`          | Safety property statements and their witnesses                 |
| `CCFRaft/Tests/`                   | Regression theorems, behavior checks and import-boundary rules |
| `CCFRaft.lean`                     | Generated root importing every module                          |

Transition systems, traces, output-recording effects and network composition come from the local [`ccf_common` package](../common/README.md), under the `CCF` namespace.
Both `lakefile.toml` and `lake-manifest.json` reference `../common`, without copying or fetching another CCF checkout.

`Properties.lean` defines `GlobalTrace` alongside the property statements.

`NodeState.lean` holds the state and simple log accessors. `ClusterConfig.lean`
holds configuration and membership queries, including `MembershipState` and
`latestMembershipIndex`, plus the configuration-majority and quorum predicates.
`MembershipState.noRetirementObserved` means no membership removal is recorded
in the local log; it does not imply that the node has joined.
`NodeState.isRetiredCommitted` queries the derived membership phase, not just
the historical commit latch.
`latestConfigurationMembers` reads the final supplied configuration's membership.
Protocol helpers such as `NodeState.recordCommit`
and `findHighestPossibleMatch` live in `Node.lean`.

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

The Lean CI workflow runs these checks for each package, grouping formatting and linting in one step and import-root, build and kernel checks in another.

- `mk_all --check` fails if `CCFRaft.lean` does not import every module.
- `lake build --wfail` builds the library, treating warnings, including `sorry`, as errors.
- Canonical behavior checks run through `#eval` when `Tests/CanonicalTests.lean` is compiled; failures fail the build.
- `lake check` re-checks all default targets with Lean's kernel and fails on any axiom other than `propext`, `Classical.choice` and `Quot.sound`.
  It runs without sandbox isolation, so build-time code must be trusted; Lake prints a warning saying so.
- The formatting script runs the pinned [leanfmt](https://github.com/duckki/leanfmt).
  Pass `-f` before the package name to rewrite files in place.

`Properties.lean` states four properties of `Model.transitionSystem`:

- `ElectionSafety`: no two distinct nodes lead in the same term.
- `CommittedLogsPrefix`: any two committed logs in a trace are prefix-comparable.
- `SingleNodeCommittedLogMonotonic`: a successful network step from a state with unique node IDs preserves each node's committed prefix, without assuming reachability.
- `CommittedFrontierIsSignature`: every positive commit index points to a signature.

The other three properties quantify over valid traces.
Each has a `Witness` statement exhibiting the situation it constrains, such as two distinct leaders.
The single-node witness requires unique starting node IDs and a successful step that strictly extends a nonempty committed log.
Liveness is not stated.

Modules are layered in order: `ccf_common`, then the model, then the properties.
A module may import only from its own layer or an earlier one, and nothing may import a proof module or a package-local `CCFRaft.Shared` copy of `ccf_common`.
`Tests/Architecture.lean` enforces this ordering when the package builds.

After adding or removing a module, regenerate `CCFRaft.lean` with `lake exe mk_all --module --lib CCFRaft`.
