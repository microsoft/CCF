# Disaster recovery models in Lean

This project contains two deliberately separate models:

- `DisasterRecovery.Model` is an executable reimplementation of the legacy
  model in `tla/disaster-recovery/`.
- `DisasterRecovery.Protocol.Model` is a production-oriented model of the C++
  recovery decision protocol.

The legacy model remains the comparison oracle; differences in the canonical
model are not silently backported. The project is pinned to Lean 4.28.0 and
Mathlib `v4.28.0` (resolved revision
`8f9d9cff6bd728b17a24e163c9402775d9e6a365`).

## Status and scope

The legacy Lean model and the Rust/Stateright model have identical canonical
graphs for one, two, and three nodes. This includes the initial state, every
reachable state, every labeled transition in both directions, and all nine
legacy predicate valuations.

The canonical Lean model is separate because the production C++ protocol
intentionally differs from the legacy model in several places. It has formal
phase-refinement and fairness-aware progress results. A small global semantics
adds active nodes, in-flight messages, immutable send history, and terminal
effects around that same canonical transition function. The versioned trace
validator also replays committed C++ instrumentation against the canonical
model.

The migration is approximately 5,000 lines across 25 new files:

| Area                                      | Files | Approximate lines | Purpose                                                         |
| ----------------------------------------- | ----: | ----------------: | --------------------------------------------------------------- |
| Exact legacy Lean model                   |     4 |               650 | Stateright state, actions, timers, network, predicates, and BFS |
| Canonical protocol and proofs             |     6 |             1,900 | C++ behavior, global semantics, invariants, and temporal proofs |
| Trace validation                          |     5 |               760 | NDJSON format, deterministic replay, and CLI                    |
| Equivalence tooling                       |     2 |               710 | Rust graph exporter and bidirectional Rust/Lean comparison      |
| Project, documentation, and configuration |     6 |               530 | Lake/Mathlib setup, entry points, and documentation             |
| Pull-request CI                           |     1 |                80 | Lean model and bounded equivalence checks                       |

### Principal files

| File                                                                                         | Lines | Role                                                               |
| -------------------------------------------------------------------------------------------- | ----: | ------------------------------------------------------------------ |
| [`DisasterRecovery/Model.lean`](DisasterRecovery/Model.lean)                                 |   392 | Exact executable legacy semantics                                  |
| [`DisasterRecovery/Checker.lean`](DisasterRecovery/Checker.lean)                             |   152 | BFS enumeration, property checking, and canonical graph export     |
| [`DisasterRecovery/Protocol/Model.lean`](DisasterRecovery/Protocol/Model.lean)               |   286 | Production-oriented C++ protocol model                             |
| [`DisasterRecovery/Protocol/Refinement.lean`](DisasterRecovery/Protocol/Refinement.lean)     |   332 | Canonical-to-legacy formal phase refinement                        |
| [`DisasterRecovery/Protocol/Temporal.lean`](DisasterRecovery/Protocol/Temporal.lean)         |   230 | Execution streams, fairness, safety, and progress proofs           |
| [`DisasterRecovery/Protocol/Global.lean`](DisasterRecovery/Protocol/Global.lean)             |   154 | Global active-node, network, send-history, and effect semantics    |
| [`DisasterRecovery/Protocol/Invariants.lean`](DisasterRecovery/Protocol/Invariants.lean)     |   860 | Global provenance, locality, monotonicity, and reachability proofs |
| [`DisasterRecovery/Protocol/Trace/Format.lean`](DisasterRecovery/Protocol/Trace/Format.lean) |   141 | Versioned NDJSON types and parser                                  |
| [`DisasterRecovery/Protocol/Trace/Replay.lean`](DisasterRecovery/Protocol/Trace/Replay.lean) |   452 | Deterministic implementation-trace replay                          |
| [`compare.py`](compare.py)                                                                   |   343 | Exhaustive canonical graph comparison                              |
| [`../../tla/disaster-recovery/src/export.rs`](../../tla/disaster-recovery/src/export.rs)     |   370 | Canonical export of the actual Stateright model                    |
| [`TRACE_FORMAT_V1.md`](TRACE_FORMAT_V1.md)                                                   |   145 | Contract for future committed C++ trace events                     |

The migration also updates the existing Stateright CLI and documentation, adds
weekly exhaustive verification, and adds
`.github/workflows/lean-shallow.yml` for relevant Lean, Rust, and C++ pull
requests.

## How equivalence is established

There are two distinct arguments: executable bounded equivalence with the Rust
model, and formal refinement between the two Lean models.

### Executable Rust/Lean equivalence

1. [`tla/disaster-recovery/src/export.rs`](../../tla/disaster-recovery/src/export.rs)
   traverses the actual Stateright model through the public
   `Model::next_steps` interface. It emits canonical full-state keys, explicit
   action labels, and the values returned by the nine registered Rust property
   functions.
2. [`DisasterRecovery/Checker.lean`](DisasterRecovery/Checker.lean) performs
   independent BFS enumeration of the Lean legacy model and emits the same
   `ccf-legacy-dr-graph-v1` representation.
3. [`compare.py`](compare.py) compares:
   - the initial state;
   - the complete normalized reachable-state sets;
   - labeled edge sets in both directions;
   - all nine property valuations for every state; and
   - the final canonical files byte for byte.

Run the complete comparison from this directory:

```console
python3 compare.py --nodes 1 2 3
```

The checked graph sizes are:

| Nodes | Reachable states | Labeled transitions |
| ----: | ---------------: | ------------------: |
|     1 |                1 |                   0 |
|     2 |               54 |                  95 |
|     3 |          105,558 |             552,282 |

This is exhaustive evidence for the checked finite configurations. It is not an
unbounded theorem about the Rust executable: such a theorem would require a
formal semantics for Rust and Stateright.

### Formal Lean refinement

[`DisasterRecovery/Protocol/Refinement.lean`](DisasterRecovery/Protocol/Refinement.lean)
contains the unbounded Lean proofs:

- `canonical_step_simulates` proves that every canonical protocol step projects
  to a reflexive-transitive legacy phase step.
- `compatibility_trace_simulates` composes that result across finite traces.
- `odd_quorum_matches_legacy` proves threshold equality for odd node counts.
- `even_quorum_exceeds_legacy_by_one` records the intentional even-node
  discrepancy.
- `reached_open_is_preserved` proves preservation of the collapsed Open
  predicate.

[`DisasterRecovery/Protocol/Temporal.lean`](DisasterRecovery/Protocol/Temporal.lean)
defines evolving executions and suffix-based weak fairness.
`fair_aligned_opening_progress` proves that an execution beginning in aligned
Opening eventually reaches Open when timeout firing is weakly fair.

These theorems relate the canonical and legacy Lean abstractions. They do not
claim that the canonical C++-aligned model is identical to the Rust model.

## Property coverage

### Kernel-checked canonical properties

| Property                                                                                   | Lean theorem(s)                                                            |
| ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| A valid timeout is aligned with the protocol timeout lane                                  | `valid_timeout_requires_alignment`                                         |
| Once a node chooses a recovery source, later gossip is rejected without changing state     | `gossip_freezes_after_choice`                                              |
| Gossip rejected by validation does not change protocol state                               | `rejected_gossip_stutters`                                                 |
| Receiving the same vote again is idempotent                                                | `duplicate_vote_is_idempotent`                                             |
| Opening and Open nodes reject `IAmOpen` without changing state                             | `opening_rejects_iamopen`, `open_rejects_iamopen`                          |
| An aligned Voting timeout with no votes cannot open                                        | `aligned_voting_timeout_without_votes_stutters`                            |
| An aligned Gossiping timeout with no gossip aborts without changing state                  | `aligned_empty_gossip_timeout_aborts`                                      |
| A quorum in Voting transitions to Opening with `QUORUM` and the opening effect             | `quorum_advance_opens`                                                     |
| An aligned Opening timeout transitions to Open and emits completion                        | `aligned_opening_timeout_completes`, `aligned_timeout_transitions_to_open` |
| Every non-timeout event preserves aligned Opening                                          | `non_timeout_step_preserves_aligned_opening`                               |
| Weak timeout fairness makes an execution starting in aligned Opening eventually reach Open | `fair_aligned_opening_progress`                                            |

These are theorem-checked for arbitrary configurations and states satisfying
their explicit premises. The progress theorem assumes weak fairness; the safety
theorems do not.

### Kernel-checked global foundations

`DisasterRecovery.Protocol.Global` permits only retry, delivery of an in-flight
message, and aligned local timeout actions. Every delivery is therefore tied to
a prior modeled send rather than an arbitrary receive input. Its reachability
relation requires the active locations to be unique and configured.

`DisasterRecovery.Protocol.Global.WellFormed` records the foundational
invariants needed by the remaining distributed proofs. The principal results
are:

- `reachable_well_formed`: every globally reachable state has the configured
  node keys and matching state locations, unique configured active nodes, valid
  sent-message provenance, only previously sent messages in flight, active
  senders, and terminal histories attributed to active nodes;
- `valid_envelope_effect` and `valid_gossip_uses_recovered_txid`: every
  envelope comes from a retry effect over its captured source state, and every
  gossip payload is the recovered TxID configured for that source;
- `retry_system_eq`, `deliver_other_node_eq`, and
  `timeout_other_node_eq`: retry does not mutate protocol state, while delivery
  and timeout mutate at most their target node;
- `deliver_network_eq`, `timeout_network_eq`, and `next_sent_extends`: delivery
  removes exactly one matching envelope, timeout leaves the network unchanged,
  and sent-message history is append-only; and
- `next_openings_monotonic`, `next_restarts_monotonic`, and
  `next_completed_monotonic`: observed terminal effects are never removed.

These are global semantic foundations, not yet the planned quorum-path
uniqueness, committed-prefix preservation, or fair global termination
theorems.

### Kernel-checked refinement properties

| Property                                                         | Lean theorem(s)                                                     |
| ---------------------------------------------------------------- | ------------------------------------------------------------------- |
| Every canonical step projects to zero or more legacy phase steps | `canonical_step_simulates`, `compatibility_step_simulates`          |
| Finite canonical traces project to legacy weak phase traces      | `compatibility_trace_simulates`                                     |
| Canonical and legacy initial phases correspond                   | `initial_phase_correspondence`, `three_node_initial_correspondence` |
| Canonical and legacy quorum thresholds agree for odd node counts | `odd_quorum_matches_legacy`                                         |
| Canonical quorum is one larger for even node counts              | `even_quorum_exceeds_legacy_by_one`                                 |
| Canonical Opening/Open is exactly projected legacy Open          | `reached_open_is_preserved`                                         |
| Canonical quorum opening projects to non-timeout legacy Open     | `quorum_kind_projects_to_non_timeout_open`                          |
| Splitting canonical Opening and Open is a legacy stutter         | `opening_to_open_is_stuttering`                                     |
| Full single-node initial states intentionally differ             | `single_node_full_initial_models_differ`                            |

The refinement is phase-level. Gossip sets, votes, timeout-lane state, node
metadata, and retry effects are not claimed to be data-bisimilar.

### Executable bounded properties

The legacy BFS checker retains all nine Stateright expectations:

- eventual Open, plus the unanimous-vote and majority-vote non-timeout
  implications;
- always no pre-failover fork, no all-OpenJoin/no-vote deadlock, and persistence
  of the legacy committed transaction threshold; and
- reachability of Open, timeout Open, and majority non-timeout Open.

For the canonical model, exhaustive one- and two-node checks additionally
assert that Voting has a chosen node, Opening/Open has an open kind, and a
restart request occurs only in Joining. These are executable finite-state
checks, not general Lean theorems.

## Legacy source mapping

| Rust/Stateright source                   | Lean definition                       |
| ---------------------------------------- | ------------------------------------- |
| `ModelCfg`, `Id`, and `Txid`             | node-count argument, `Id`, and `Txid` |
| `GossipStruct`, `VoteStruct`, and `Msg`  | `Gossip`, `Vote`, and `Msg`           |
| `NextStep` and actor `State`             | `Phase` and `ActorState`              |
| `Timer::ElectionTimeout`                 | one Boolean timer-set entry per actor |
| `Network::UnorderedNonDuplicating`       | sorted `List Envelope` multiset       |
| `ActorModelState`                        | `GlobalState`                         |
| `on_start`                               | `startActor` and `initialState`       |
| `advance_step` and `advance_several`     | `advanceStep` and `advanceSeveral`    |
| `on_msg` and `on_timeout`                | `onMessage` and `onTimeout`           |
| `Model::actions` and `Model::next_state` | `actions` and `nextState`             |
| predicates registered in `main.rs`       | `legacyValuations`                    |

The following legacy details are intentional:

- A node's transaction ID is its actor ID.
- Gossip and vote collections are sets with canonical sorted representations.
- The network is an unordered multiset. Equal envelopes retain their
  multiplicity, while only one delivery action is offered for that envelope.
  Each delivery removes one occurrence.
- The network is reliable: there is no message-loss action.
- Every node has one election timer. Resetting an unchanged timer is a
  Stateright no-op and does not create a transition.
- Rust `on_msg` calls `Cow::to_mut` before inspecting the message. Consequently
  even an otherwise inert message delivery is a transition that removes one
  envelope.
- Gossip collection freezes after `submitted_vote` becomes nonempty.
- `advance_several` takes the Vote to OpenJoin step and then immediately takes
  the OpenJoin to Open step when the same event enables both.
- `IAmOpen` changes every non-Open phase, including Join, to Join.
- Rust phases map only abstractly to the implementation: Vote is gossiping,
  OpenJoin is voting, `Open { timeout }` collapses opening and open, and Join is
  joining.

Constant-empty Stateright fields (`history`, random choices, actor storage) and
the all-false crash vector are omitted from the graph key. They cannot change
in this model.

## Legacy predicates

The nine valuations preserve the code in `tla/disaster-recovery/src/main.rs`,
including names that overstate or obscure what the Boolean predicate checks.

| Expectation | Legacy name                               | State predicate                                                                           |
| ----------- | ----------------------------------------- | ----------------------------------------------------------------------------------------- |
| Eventually  | Unanimous votes => no chance of a fork    | Unanimous submitted vote receive-sets imply a non-timeout Open exists                     |
| Eventually  | Open                                      | Some actor is Open                                                                        |
| Eventually  | Majority votes => no fork                 | The legacy sorted-prefix majority test implies a non-timeout Open exists                  |
| Always      | No open with timeout, no fork             | If no timeout Open exists, at most one actor is Open                                      |
| Always      | Deadlock                                  | Not(all actors are OpenJoin and no Vote envelope exists)                                  |
| Always      | Persist committed txs                     | If no timeout Open exists, every Open actor's ID/txid is at least the middle actor's txid |
| Sometimes   | Open is possible                          | Actor count greater than one implies some actor is Open                                   |
| Sometimes   | Unsafe open with timeout                  | Some timeout Open exists                                                                  |
| Sometimes   | Majority vote still opens without timeout | The legacy majority test and a non-timeout Open both hold                                 |

`Eventually` is checked on the finite graph as the least fixed point containing
states where the predicate is true and states whose nonempty successor set is
entirely in that fixed point. This is cycle-complete and stronger than
Stateright 0.31's terminal-path `Eventually` implementation, which can report
false negatives on cycles. Compatibility valuations and this Lean temporal
interpretation are therefore kept separate. `Always` and `Sometimes` quantify
over reachable states. These are executable bounded checks, not theorems about
the Rust program, and they add no fairness assumption.

## Canonical C++ model

The canonical model keeps one `NodeState` per fixed location and separates the
main phase from the timeout phase. Its executable `step` relation covers:

- `GOSSIPING`, `VOTING`, `OPENING`, `JOINING`, and `OPEN`;
- lexicographic gossip selection by `(view, seqno, location-name)`;
- gossip completion after all expected locations or an aligned timeout, with
  nonempty gossip required;
- quorum size `n / 2 + 1`, failover after a valid timeout, and no open after an
  aligned voting timeout with zero votes;
- timeout-lane advancement after the main state machine except on the same
  early-return/error paths as C++;
- retries, duplicate/idempotent receives, IAmOpen rejection in Opening/Open,
  join/restart, and the Opening-to-Open timeout;
- an explicit `Validation.accepted`/`rejected` boundary. It assumes the C++
  quote and certificate checks have returned a result; it proves nothing about
  cryptography.

`Location` is the configured location name, the protocol's semantic identity
and final TxID tie-break. Network addresses and certificates are opaque
metadata: they affect validation and transport, not this state relation.

### C++ source mapping

| C++ source or branch                                                         | Canonical definition                                       |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `self_healing_open.h`: `Location`, `StateMachine`, `OpenKinds`, service maps | `Location`, `Phase`, `OpenKind`, and fields of `NodeState` |
| `try_start()` writes both states to `GOSSIPING`                              | `initialNode`                                              |
| `wrap_recovery_decision_protocol()` quote/certificate checks                 | `Validation` input boundary                                |
| gossip callback freezes after chosen node and inserts once                   | `receiveGossip` branch of `step`                           |
| vote callback inserts into a service set                                     | `receiveVote` branch of `step`                             |
| IAmOpen callback rejects Opening/Open, otherwise chooses and joins           | `receiveIAmOpen` branch of `step`                          |
| `advance()`: `valid_timeout` and Gossiping branch                            | `validTimeout` and gossip branch of `advance`              |
| `advance()`: Voting quorum/failover/zero-vote return                         | voting branch of `advance`                                 |
| `advance()`: Joining restart ringbuffer write                                | `Effect.restart`                                           |
| `advance()`: inert Joining fallthrough under the timeout-lane invariant      | Joining branch of `advance`                                |
| `advance()`: Opening aligned timeout                                         | Opening branch and `Effect.complete`                       |
| final timeout-state switch in `advance()`                                    | `advanceTimeoutState`, sequenced after main advancement    |
| retry timer's Gossiping/Voting/Opening switch                                | `.retry` and `Effect.send`                                 |
| timeout handler calls `advance(tx, true)`                                    | `.timeout`                                                 |

The handler wrapper validates and records messages before dispatch, then calls
`advance(tx, false)`. The model represents those committed semantic boundaries
as one receive event.

### Confirmed implementation/model discrepancy

The C++ handlers do not reject a successfully validated location name merely
because it is absent from `expected_locations`. Sends use the configured list,
but gossip/vote maps and their size thresholds can include unexpected names.
`CanonicalTests.lean` demonstrates that one unexpected accepted gossip can
satisfy a one-location threshold. The model preserves this behavior. The phase
refinement theorem covers this step; expected-source restrictions appear only
in `LegacyDataAssumptions` for richer data comparisons.

The strict version 1 trace requires every accepted receive to reference an
instrumented send, so it covers configured protocol participants rather than
the unexpected external-source path. That implementation discrepancy remains
explicit in the canonical model and its tests.

## Temporal results

`DisasterRecovery.Protocol.Temporal` defines suffix predicates directly over
natural-numbered streams and bundles an evolving state/event stream in
`Execution`. Its `step_succ` field requires each next state to be the result of
`Protocol.step` on the current state and event. Weak fairness requires that, on
every suffix where an action is continuously enabled, that action fires on the
same suffix. Strong fairness requires infinitely-often enablement to imply
infinitely-often firing.

Safety lemmas retain timeout alignment, gossip freeze, rejection stuttering,
duplicate-vote idempotence, Opening/Open IAmOpen rejection, zero-vote timeout
stuttering, empty-gossip timeout abort behavior, quorum opening, and
Opening-to-Open completion. `non_timeout_step_preserves_aligned_opening` proves
that every non-timeout event preserves `AlignedOpening`, while
`aligned_timeout_transitions_to_open` proves that an aligned timeout changes the
phase to Open. `fair_aligned_opening_progress` proves that an execution whose
initial state is `AlignedOpening` eventually reaches phase Open, assuming weak
fairness for timeout firing while `AlignedOpening` is enabled. This is not a
global termination theorem; reaching aligned Opening still requires separate
message-delivery and timeout progress assumptions.

## Legacy compatibility

`DisasterRecovery.Protocol.Refinement` intentionally does not claim
bisimulation or unrestricted data refinement. `canonical_step_simulates` proves
that every canonical single-node `Protocol.step`, for every event and state,
projects to a reflexive-transitive legacy phase step. No odd-node,
expected-source, embedded-TxID, or quorum-only premise is used for this phase
theorem. `CompatibilityStep` records only that the post-state is the executable
canonical result, and `compatibility_step_simulates` derives its legacy phase
step from `Protocol.step` semantics.

The phase projection drops the timeout lane, gossips, votes, chosen node, and
restart state, makes retries and data-only updates stutter, maps Gossiping to
legacy Vote and Voting to legacy OpenJoin, and collapses canonical Opening/Open
to legacy Open with its quorum/failover kind. `CompatibilityTrace` contains
canonical steps, and `compatibility_trace_simulates` composes their derived
legacy weak steps. `retryCompatibility` and `voteQuorumCompatibility` are
canonical-step constructors, not phase simulation assumptions.

`LegacyDataAssumptions` separately records the odd-node, expected-source,
embedded-TxID, and quorum-only restrictions relevant to a richer data/property
comparison; the current file does not claim such a data refinement. Initial
phase correspondence, the full three-node legacy-shaped initial phase
correspondence, collapsed-Open property preservation, quorum-kind projection,
and the single-node full-initial-state mismatch are proved.

The threshold proofs state exactly:

- for `n = 2*k + 1`, canonical `n / 2 + 1` equals legacy `(n + 1) / 2`;
- for `n = 2*k`, canonical quorum is legacy quorum plus one.

Only predicates that depend on reaching collapsed Open and choosing the quorum
path are preserved by the current projection. Timeout-open, majority, deadlock,
and transaction-persistence legacy predicates are not claimed preserved:
timeout semantics, thresholds, TxIDs, initial gossip, retries, and phase
splitting differ. `single_node_full_initial_models_differ` is a proved
counterexample to full initial-state equality.

## Trace validation

The versioned NDJSON contract is documented in
[`TRACE_FORMAT_V1.md`](TRACE_FORMAT_V1.md). Version 1 records complete
successful executions: sends, accepted receives, committed timeouts, and
one-shot effects are explicit.

[`Trace/Format.lean`](DisasterRecovery/Protocol/Trace/Format.lean) parses the
wire format. [`Trace/Replay.lean`](DisasterRecovery/Protocol/Trace/Replay.lean)
then folds each event over one deterministic canonical `SystemState`. Replay
retains only per-node sequences, observed and consumed causal sends, exact
ordered retry-send batches, and node-scoped pending `open`, `join_restart`, or
`complete` effects.

The validator checks configuration consistency, starts, globally unique message
IDs, send-batch completeness, exact send/receive causality including gossip
TxIDs, canonical pre/post phases, terminal completion, and single consumption
of committed effects. On failure it reports the shortest failing prefix and
current protocol phase.

### Implementation trace validation

`CCF_RECOVERY_TRACE` enables C++ tracing without changing default builds.
Protocol transactions append semantic events to an internal public trace map;
its global commit hook emits `RDP_TRACE` records only after commit. Sends are
logged before dispatch with causal IDs propagated to accepted receive records.
For trace-enabled joiners, the hook emits the committed receive and
`join_restart` records before requesting host restart.
Trace-enabled periodic retries defer work while their locally committed phase
is ahead of the globally visible trace phase. Once phases match, the trace lock
serializes the complete send batch against later commit publication.

[`tests/infra/recovery_trace.py`](../../tests/infra/recovery_trace.py) extracts
records from all recovery nodes and topologically orders them from per-node
sequence and causal edges, without comparing clocks. It then invokes the Lean
validator. The quorum, failover, and multiple-timeout recovery scenarios call
this helper, and both SNP CI jobs build CCF with tracing enabled and provide the
Lean validator binary.

The helper writes `*.recovery.ndjson` before validation. SNP CI uploads these
generated files with node logs for debugging and local replay. No
recovery-decision-protocol trace files are checked into the repository. Every
NDJSON trace passed to the validator in CI comes from the running C++
implementation.

## Commands

From this directory:

```console
lake build
lake exe semantic-checks
lake exe canonical-checks
lake exe disaster-recovery check --nodes 3
python3 compare.py
```

The checker prints shortest BFS traces for unmet expectations, representative
`Sometimes` examples, and exits nonzero on failure. The semantic checks cover
immediate single-node open, frozen gossip, unordered delivery, timeout open,
`IAmOpen` joining, and duplicate envelope multiplicity.

The Rust and Lean exporters emit tab-separated `ccf-legacy-dr-graph-v1`:

```text
format	ccf-legacy-dr-graph-v1
nodes	N
init	CANONICAL_ID
state	CANONICAL_ID	STATE_KEY	NINE_PROPERTY_BITS
edge	SOURCE_ID	NORMALIZED_ACTION	DESTINATION_ID
```

Canonical IDs are assigned by lexicographically sorting state keys. State keys
encode actor states, set timers, and envelope multiplicities. Actions are
normalized as `deliver(src,dst,msg)` or `timeout(id,election)` rather than Rust
debug text.

`compare.py` exhaustively compares the initial state, normalized reachable
state set, bidirectional labeled edge set, and all nine valuations for node
counts 1, 2, and 3. This executable comparison is the evidence for parity in
this slice. A Lean-only theorem could not establish behavior of the Rust and
Stateright executables without formal semantics for them.

The Rust comparison exporter is checked separately from
`tla/disaster-recovery/` with `cargo check` and `cargo build`.

`.github/workflows/lean-shallow.yml` builds the Lean library and trace validator,
runs semantic and canonical checks, checks the three-node legacy properties,
and compares the one- and two-node Rust/Lean graphs. The weekly continuous
verification workflow additionally runs the exhaustive three-node comparison.
Only the SNP jobs feed real C++ traces to the validator. The Rust job remains in
place until the replacement criteria below are met.

### Current CI evidence

Draft PR [microsoft/CCF#8241](https://github.com/microsoft/CCF/pull/8241)
validated commit `c8dd40a7` on both proof and hardware paths:

- [Lean shallow verification](https://github.com/microsoft/CCF/actions/runs/33315731130/job/99268715043)
  built every Lean target and compared the bounded Rust/Lean graphs.
- [Milan SNP](https://github.com/microsoft/CCF/actions/runs/33315731084/job/99268714883)
  validated committed quorum, failover, and multiple-timeout implementation
  traces.
- [Genoa SNP](https://github.com/microsoft/CCF/actions/runs/33315731084/job/99268714839)
  validated the same implementation traces on the second SNP generation.

## Replacement criteria

The Stateright model can be removed only after:

1. bounded bidirectional graph comparison remains green for all configurations
   previously checked with Stateright;
2. the canonical Lean model and its proof targets cover every retained legacy
   property, or an intentional semantic change is reviewed explicitly; and
3. committed traces from the quorum, failover, and multiple-timeout C++ e2e
   scenarios validate against the canonical Lean model.

The migration now implements all three mechanisms. Stateright should remain
until the bounded comparison and SNP implementation-trace jobs have established
a stable green history.
