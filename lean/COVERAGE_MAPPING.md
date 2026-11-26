# Lean Specification to Implementation Coverage Mapping

This document maps each formal specification under `lean/` to the corresponding C++ implementation source files in CCF.
Each specification lists:

- **Core implementation files**: C++ source and header files whose logic is directly modeled by the specification.
- **Questionable or partial inclusions**: files where coverage is partial, indirect, limited to thin wrappers or shared types, restricted to trace instrumentation, or abstracted away by the model.

Test files, test drivers, and Python trace-replay runners (such as `src/consensus/aft/test/driver.cpp`, `src/kv/test/kv_trace.cpp`, `tests/infra/consistency_trace.py`, and `tests/infra/recovery_trace.py`) are excluded because they do not implement production CCF behavior.
Two packages under `lean/` are support packages rather than protocol specifications and therefore have no implementation mapping:

- [`lean/common/`](common/README.md) (`ccf_common`): protocol-independent Lean transition-system, execution, finset, sequence, function, and parser infrastructure shared across specifications (only `CCF.TxID` mirrors the primitive type in `include/ccf/tx_id.h`).
- [`lean/mathlib-equivalence/`](mathlib-equivalence/README.md): proofs that the lightweight definitions in `lean/common/` are equivalent to their Mathlib counterparts.

## Current coverage summary

Generated with [`scripts/lean_coverage_report.py`](../scripts/lean_coverage_report.py) against `microsoft/CCF` Coverage run #989 (ID 45855065141, artifacts `coverage-history-main` and `coverage-report-html` on `main`, scope: core implementation files only, with [`lean/kv/coverage_mask.json`](kv/coverage_mask.json) applied).

| Item               | Files | Code LoC | Spec LoC | Total Lean LoC | Lines (Hit/Total) | Line Cov | Branches (Hit/Total) | Branch Cov |
| ------------------ | ----: | -------: | -------: | -------------: | ----------------: | -------: | -------------------: | ---------: |
| consensus          |     3 |    2,601 |      955 |         12,792 |       2,046/2,137 |   95.74% |            719/1,006 |     71.47% |
| consistency        |     8 |    2,584 |      594 |          4,986 |       1,629/1,994 |   81.70% |              385/552 |     69.75% |
| disaster-recovery  |     4 |    1,361 |      473 |          8,299 |         781/1,050 |   74.38% |              166/348 |     47.70% |
| kv (masked)        |    13 |    1,728 |    1,071 |          4,648 |       1,057/1,100 |   96.09% |                    - |          - |
| **Total (unique)** |    28 |    8,274 |    3,093 |         30,725 |       5,513/6,281 |   87.77% |                    - |          - |

Code LoC counts non-blank, non-comment C/C++ lines.
Spec LoC counts non-blank, non-comment Lean lines in `Model` and `Properties`.
Total Lean LoC includes `Proofs`, `TraceValidation`/`Replay`, and `Tests` (shared `lean/common` adds 939 LoC).
Line-range masks applied: [`lean/kv/coverage_mask.json`](kv/coverage_mask.json) (unmasked `kv` is 3,294 Code LoC, 2,297/2,409 lines at 95.35%, and 600/734 branches at 81.74% in run #989; run `--no-masks` to reproduce whole-file totals).
Masked branch coverage requires an `llvm-cov` JSON export (artifact `coverage-export-json`, added in [#8857](https://github.com/microsoft/CCF/pull/8857), or `--export-json`); rows with masked files show `-` for branches until `coverage-export-json` is available on the run.
Mapped files absent from the `llvm-cov` report (0 instrumented lines, still counted in Code LoC): `include/ccf/common_endpoint_registry.h`, `src/node/recovery_decision_protocol.h`, `include/ccf/kv/untyped_map_handle.h`, `src/kv/tx_pimpl.h`, `include/ccf/kv/version.h`.

## Consensus (`lean/consensus`)

Specification: [`lean/consensus/README.md`](consensus/README.md).
Models the CCF CFT/AFT consensus protocol, including elections, pre-vote, log replication, signature-gated commitment, reconfiguration quorums, retirement phases, successor nomination, rollback, and backup initialization from a committed prefix.

### Core implementation files

- [`src/consensus/aft/cft.h`](../src/consensus/aft/cft.h): main `aft::Aft` consensus state machine implementing elections, `AppendEntries` replication and conflict resolution, quorum checks across active configurations, commit advancement (`update_commit`), reconfiguration (`add_configuration`), retirement (`set_retired_committed`, successor nomination), check-quorum, rollback, and `init_as_backup`.
- [`src/consensus/aft/impl/state.h`](../src/consensus/aft/impl/state.h): `aft::State`, `aft::ViewHistory`, and `aft::AtomicLeadershipState` storing term/view, log and commit indices, committable indices, leadership/membership state, and retirement indices.
- [`src/consensus/aft/cft_types.h`](../src/consensus/aft/cft_types.h): consensus wire message types (`AppendEntries`, `AppendEntriesResponse`, `RequestVote`, `RequestVoteResponse`, `RequestPreVote`, `RequestPreVoteResponse`, `ProposeRequestVote`, `CftMsgType`) and the `aft::Store` / `aft::Adaptor` bridge into KV.

### Questionable or partial inclusions

- **Partial coverage within [`src/consensus/aft/cft.h`](../src/consensus/aft/cft.h)**: wall-clock timers and periodic tasks, election-timeout randomization, uncommitted-transaction backpressure, learner/non-voting nuances, and legacy `append_entries_signed_response` wire handling are abstracted away rather than modeled.
- [`src/consensus/consensus_types.h`](../src/consensus/consensus_types.h): defines `consensus::AppendEntriesIndex` (`idx`, `prev_idx`), inherited by `aft::AppendEntries`.
  Inclusion is questionable because the file contains only trivial header/JSON boilerplate.
- [`src/node/hooks.h`](../src/node/hooks.h): `ConfigurationChangeHook` translates `public:ccf.gov.nodes.info` writes (`TRUSTED`, `RETIRED`, deletions, and `retired_committed`) into `consensus->add_configuration(...)` and `consensus->trace_retired_committed_tx(...)`.
  Inclusion is questionable because the model attaches configuration and retirement-confirmation metadata directly to log entries rather than modeling KV table hooks, though bugs here directly break the consensus reconfiguration/retirement inputs.
- [`src/node/node_state.h`](../src/node/node_state.h): invokes `init_as_backup`, `force_become_primary`, `set_retired_committed`, `remove_deleted_nodes`, and `nominate_successor` during bootstrap, snapshot installation, and global commit hooks.
  Inclusion is questionable because consensus wiring is a small fraction of this large node-lifecycle file, and the join protocol, snapshot transport/deserialization, and crash recovery in `node_state.h` are explicitly out of scope of `lean/consensus`.
- [`src/node/retired_nodes_cleanup.h`](../src/node/retired_nodes_cleanup.h) and [`src/node/rpc/node_frontend.h`](../src/node/rpc/node_frontend.h) (`set_retired_committed`): schedule and execute the transaction that sets `retired_committed = true` for globally retired nodes.
  Inclusion is questionable because the model only constrains when retirement-confirmation entries are valid in the log, without modeling the background task or HTTP endpoint that produces them.
- [`src/kv/kv_types.h`](../src/kv/kv_types.h): defines `ccf::kv::Configuration`, `LeadershipState`, `MembershipState`, `RetirementPhase`, and the `ccf::kv::Consensus` / `ConfigurableConsensus` abstract interfaces implemented by `aft::Aft`.
  Inclusion is questionable because it is a broad shared types/interface header spanning KV, consensus, and history.
- [`include/ccf/tx_id.h`](../include/ccf/tx_id.h): defines `ccf::TxID`, `ccf::View`, and `ccf::SeqNo` underlying log-freshness comparisons (`CCF.TxID.le`).
  Inclusion is questionable because it is a pervasive primitive type across CCF.
- [`src/consensus/aft/cft_trace_msgpack.h`](../src/consensus/aft/cft_trace_msgpack.h): defines `ccf.cft` msgpack trace events consumed by `consensus-replay`.
  Inclusion is questionable because it is trace-capture instrumentation rather than protocol logic, although errors here affect trace-validation fidelity.
- [`src/consensus/aft/consensus_channels.h`](../src/consensus/aft/consensus_channels.h), [`src/consensus/aft/commit_observer.h`](../src/consensus/aft/commit_observer.h), [`src/consensus/ledger_enclave.h`](../src/consensus/ledger_enclave.h), and [`src/consensus/ledger_enclave_types.h`](../src/consensus/ledger_enclave_types.h): abstract interfaces and ledger framing invoked by `aft::Aft`.
  Inclusion is questionable because network delivery, ledger persistence/framing, and commit-observer callbacks are abstracted away by the model; bugs in these adapters could still violate model assumptions (such as ledger entry integrity or rollback truncation).
- [`src/node/node_to_node.h`](../src/node/node_to_node.h), [`src/node/node_to_node_channel_manager.h`](../src/node/node_to_node_channel_manager.h), [`src/node/channels.h`](../src/node/channels.h), and [`src/node/node_transport.h`](../src/node/node_transport.h): concrete authenticated node-to-node transport implementing `ConsensusChannels`.
  Inclusion is questionable (likely exclude) because message delivery and loss are modeled abstractly as an in-flight envelope queue in `CCF.MultiNodeTransitionSystem`.

## Consistency (`lean/consistency`)

Specification: [`lean/consistency/README.md`](consistency/README.md).
Models CCF's externally visible consistency contract (serializability and real-time ordering of committed writes, forwarded reads, elections, and `Committed`/`Invalid` status reporting) for an abstract append-and-read application.
Because this is a service-level specification rather than a 1-to-1 model of a single C++ component (and has no refinement proof to `lean/consensus` or `lean/kv`), the boundary between directly mapped and supporting files is inherently broader than for the other specifications.

### Core implementation files

- [`include/ccf/tx_status.h`](../include/ccf/tx_status.h): defines `ccf::TxStatus`, `ccf::FinalTxStatus`, and `ccf::evaluate_tx_status(...)`, which computes `Unknown`, `Pending`, `Committed`, and `Invalid` from `(target_view, target_seqno)`, local view history, and `(committed_view, committed_seqno)` (directly mirroring `commit` and `mayInvalidate` in `consistency/Model/Transitions.lean`).
- [`src/endpoints/base_endpoint_registry.cpp`](../src/endpoints/base_endpoint_registry.cpp) and [`include/ccf/base_endpoint_registry.h`](../include/ccf/base_endpoint_registry.h): implement `get_status_for_txid_v1`, `get_last_committed_txid_v1`, and `get_view_history_v1`/`v2` delegating to consensus.
- [`src/endpoints/common_endpoint_registry.cpp`](../src/endpoints/common_endpoint_registry.cpp) and [`include/ccf/common_endpoint_registry.h`](../include/ccf/common_endpoint_registry.h): expose the `/tx` and `/commit` client endpoints that report transaction status and commit points (the source of `tx_status` observations in `consistency-replay`).
- [`src/node/rpc/frontend.h`](../src/node/rpc/frontend.h): `RpcFrontend` handles client request execution, session-consistency view checks (`check_session_consistency`), forwarding to the primary (`redirect_or_forward`, `forward`), transaction commit/retry (`commit_transaction`), and returning transaction IDs via `locally_committed_func`.
- [`src/endpoints/endpoint_registry.cpp`](../src/endpoints/endpoint_registry.cpp) and [`include/ccf/endpoint_registry.h`](../include/ccf/endpoint_registry.h): implement `default_locally_committed_func`, which populates the `x-ms-ccf-transaction-id` response header on initial client responses.

### Questionable or partial inclusions

- [`src/consensus/aft/cft.h`](../src/consensus/aft/cft.h) and [`src/consensus/aft/impl/state.h`](../src/consensus/aft/impl/state.h): enforce the election, view-history (`ViewHistory`), replication, and commit guarantees that uphold the consistency model's invariants, and emit the `ccf.cft` events (`become_leader`, `send_request_vote`, `replicate_entry`, `commit`) consumed by `consistency-replay`.
  Inclusion is questionable because `lean/consistency` explicitly models external consistency rather than consensus internals (which are mapped under `lean/consensus`), yet its trace validation depends directly on these files.
- [`src/kv/kv_types.h`](../src/kv/kv_types.h): implements `Consensus::evaluate_tx_status(View, SeqNo)` by combining `get_view(seqno)` and `get_committed_txid()` and calling `ccf::evaluate_tx_status(...)`.
  Inclusion is questionable because it is a thin wrapper inside a large shared interface header.
- [`src/kv/store.h`](../src/kv/store.h), [`src/kv/committable_tx.h`](../src/kv/committable_tx.h), [`src/kv/tx.cpp`](../src/kv/tx.cpp), and [`src/kv/apply_changes.h`](../src/kv/apply_changes.h): provide local transactional execution, `TxID` assignment (`CommittableTx::get_txid`), and rollback on view change.
  Inclusion is questionable because `lean/consistency` abstracts application state to a single append-only list without multi-map concurrency or OCC details (covered by `lean/kv`).
- [`src/node/rpc/forwarder.h`](../src/node/rpc/forwarder.h) and [`src/node/rpc/forwarder_types.h`](../src/node/rpc/forwarder_types.h): implement RPC forwarding of writes and reads from backups to the primary, carrying `active_view` in `ForwardedCommandHeader_v3`.
  Inclusion is questionable because `lean/consistency` assumes forwarded reads and writes execute on a leader's branch, while client reads are not traced by `consistency-replay` and forwarding transport/timeouts are not modeled.
- [`src/node/commit_callback_subsystem.h`](../src/node/commit_callback_subsystem.h) and [`src/node/commit_callback_interface.h`](../src/node/commit_callback_interface.h): evaluate `ccf::evaluate_tx_status` on commit notifications to fire terminal (`Committed`/`Invalid`) callbacks.
  Inclusion is questionable because it implements the same finality rules for asynchronous commit waiters, but `consistency-replay` only records client `/tx` polling responses.
- [`src/node/gov/handlers/transactions.h`](../src/node/gov/handlers/transactions.h): exposes `/gov/service/transactions/{transactionId}` and `/gov/service/transactions/commit` via `get_status_for_txid_v1` and `get_last_committed_txid_v1`.
  Inclusion is questionable because it is a thin governance API wrapper over `BaseEndpointRegistry`.
- [`src/js/extensions/ccf/consensus.cpp`](../src/js/extensions/ccf/consensus.cpp): exposes `ccf.consensus.getStatusForTxId`, `getLastCommittedTxId`, and `getViewForSeqno` to JavaScript handlers.
  Inclusion is questionable because it is a thin JS binding and `lean/consistency` does not model JavaScript execution.
- [`src/node/rpc/user_frontend.h`](../src/node/rpc/user_frontend.h), [`src/node/rpc/member_frontend.h`](../src/node/rpc/member_frontend.h), and [`src/endpoints/endpoint.cpp`](../src/endpoints/endpoint.cpp): `RpcFrontend` subclasses and endpoint forwarding/redirection policy setters (`ForwardingRequired`, `RedirectionStrategy`).
  Inclusion is questionable because these are thin wiring/configuration layers, and HTTP redirection or non-forwarded backup reads are explicitly out of scope of `lean/consistency`.
- [`src/consensus/aft/cft_trace_msgpack.h`](../src/consensus/aft/cft_trace_msgpack.h): declares the `ccf.cft` trace events replayed by `consistency-replay`.
  Inclusion is questionable because it is trace instrumentation rather than consistency logic.
- [`include/ccf/tx_id.h`](../include/ccf/tx_id.h): shared `ccf::TxID`, `ccf::View`, and `ccf::SeqNo` definitions.

## Disaster Recovery (`lean/disaster-recovery`)

Specification: [`lean/disaster-recovery/README.md`](disaster-recovery/README.md).
Models CCF's self-healing open recovery decision protocol: per-node phases (`Gossiping`, `Voting`, `Opening`, `Joining`, `Open`), independent timeout lane, deterministic gossip selection by `(view, seqno, location)`, quorum vs failover opening, retries, and restart notifications.

### Core implementation files

- [`src/node/recovery_decision_protocol.cpp`](../src/node/recovery_decision_protocol.cpp): `RecoveryDecisionProtocolSubsystem` implementing `reset_state`, `try_start`, `advance`, gossip/vote/IAmOpen/timeout transitions, deterministic maximum selection, periodic retry and failover timers (`start_message_retry_timers`, `start_failover_timers`), message sending (`send_gossip_unsafe`, `send_vote_unsafe`, `send_iamopen_unsafe`), and `RDP_TRACE` logging.
- [`src/node/recovery_decision_protocol.h`](../src/node/recovery_decision_protocol.h): `RecoveryDecisionProtocolSubsystem` declaration, protocol request payloads (`TaggedWithNodeInfo`, `GossipRequest`, `IAmOpenRequest`), and `AdvanceTrace`.
- [`src/node/rpc/self_healing_open_handlers.h`](../src/node/rpc/self_healing_open_handlers.h): inbound endpoints `/recovery_decision_protocol/{gossip,vote,iamopen,timeout}` implementing quote/certificate checks (`wrap_recovery_decision_protocol`), gossip freeze after choosing, duplicate gossip skipping, vote insertion, `IAmOpen` handling (ignoring once `OPENING`/`OPEN`, transitioning to `JOINING` otherwise), primary validation on timeouts, calling `advance()`, and post-commit trace emission.
- [`include/ccf/service/tables/self_healing_open.h`](../include/ccf/service/tables/self_healing_open.h): protocol enums (`StateMachine`, `OpenKinds`), `Location`, `RequestNodeInfo`, `NodeInfo`, and the `RECOVERY_DECISION_PROTOCOL_*` KV tables.

### Questionable or partial inclusions

- [`include/ccf/node/configuration.h`](../include/ccf/node/configuration.h): defines `RecoveryDecisionProtocolConfig` (`expected_locations`, `message_retry_timeout`, `failover_timeout`) and `SealingRecoveryConfig` (`location`).
  Inclusion is questionable because almost all of the file configures unrelated node subsystems, and concrete timer intervals are abstracted away by the model.
- [`src/node/node_state.h`](../src/node/node_state.h): owns `RecoveryDecisionProtocolSubsystem`, provides `last_recovered_signed_idx` (used to form the gossiped `TxID`), and implements `transition_service_to_open(...)` and `request_restart()` called from `advance()`.
  Inclusion is questionable because only a small portion of `node_state.h` interacts with this protocol, and the downstream service-opening and restart actions are modeled only as abstract host notifications (`Notification.opening`, `Notification.restart`).
- [`src/node/rpc/node_frontend.h`](../src/node/rpc/node_frontend.h): installs the protocol endpoints (`init_recovery_decision_protocol_handlers`) and invokes `reset_state` / `try_start` during service creation/recovery.
  Inclusion is questionable because this is thin lifecycle wiring inside a large node RPC frontend.
- [`src/node/rpc/node_interface.h`](../src/node/rpc/node_interface.h), [`src/node/rpc/node_operation.h`](../src/node/rpc/node_operation.h), and [`src/node/rpc/node_operation_interface.h`](../src/node/rpc/node_operation_interface.h): forwarding accessors exposing `recovery_decision_protocol()` from `NodeState` to handlers.
  Inclusion is questionable (likely exclude) because they contain only accessor boilerplate.
- [`src/node/quote.cpp`](../src/node/quote.cpp), [`include/ccf/node/quote.h`](../include/ccf/node/quote.h), and [`src/node/rpc/node_frontend_utils.h`](../src/node/rpc/node_frontend_utils.h): implement `verify_quote` and `quote_verification_error` invoked by `wrap_recovery_decision_protocol`.
  Inclusion is questionable because the Lean model abstracts quote and certificate validation as an opaque `Validation.accepted | Validation.rejected` input without modeling attestation cryptography.
- [`src/node/open_service.h`](../src/node/open_service.h), [`src/node/recovered_service_opening_task.h`](../src/node/recovered_service_opening_task.h), and [`src/node/runtime_control.h`](../src/node/runtime_control.h): implement actual service opening and process restart after `advance()` requests them.
  Inclusion is questionable because `lean/disaster-recovery` stops at emitting `Notification.opening` and `Notification.restart`.
- [`src/node/local_sealing.h`](../src/node/local_sealing.h), [`src/node/local_sealing.cpp`](../src/node/local_sealing.cpp), [`src/service/tables/local_sealing.h`](../src/service/tables/local_sealing.h), and [`include/ccf/service/local_sealing.h`](../include/ccf/service/local_sealing.h): implement SNP local sealing used alongside sealing-based recovery.
  Inclusion is questionable (likely exclude) because key sealing and unsealing are outside the decision protocol state machine.
- [`src/http_client/curl.h`](../src/http_client/curl.h): HTTP/TLS client used to dispatch protocol messages and self-addressed timeouts.
  Inclusion is questionable (likely exclude) because network transport is abstracted away by `CCF.MultiNodeTransitionSystem`.
- [`include/ccf/tx_id.h`](../include/ccf/tx_id.h): shared `ccf::TxID` definition used for gossip payloads and freshness comparisons (`LogUpToDate`).

## Key-Value Store (`lean/kv`)

Specification: [`lean/kv/README.md`](kv/README.md) and [`doc/build_apps/kv/semantics.rst`](../doc/build_apps/kv/semantics.rst).
Models the observable single-node semantics of CCF's transactional KV store: lazy current-snapshot metadata capture, lazy per-map local and globally committed view capture, point and map-wide reads/writes/iteration, optimistic concurrency control, atomic multi-map local application, compaction, and rollback.

### Core implementation files

- [`src/kv/store.h`](../src/kv/store.h): `ccf::kv::Store` and `StoreState` store lifecycle, `current_txid_and_commit_term`, `next_version` (including stale-term rejection), `get_map` / `add_dynamic_map`, `commit` replication result handling, `compact`, and `rollback`.
  See partial-coverage notes below for unmodeled features in this file.
- [`src/kv/untyped_map.h`](../src/kv/untyped_map.h): `ccf::kv::untyped::Map`, `Roll`, `LocalCommit`, `HandleCommitter` (`prepare` OCC conflict checks on per-key reads, whole-map `read_version`, and `rollback_counter`; `commit` frame publication), `create_change_set` (per-map local and globally committed view capture and compacted-version checks), and map-level `compact` and `rollback`.
  See partial-coverage notes below for unmodeled features in this file.
- [`src/kv/untyped_change_set.h`](../src/kv/untyped_change_set.h): `ccf::kv::untyped::ChangeSet` holding pinned `state`, pinned `committed` view, `start_version`, `rollback_counter`, `read_version`, `reads`, and `writes`.
  Serialization helpers and `SnapshotChangeSet` in this file are unmodeled.
- [`src/kv/untyped_map_handle.cpp`](../src/kv/untyped_map_handle.cpp) and [`include/ccf/kv/untyped_map_handle.h`](../include/ccf/kv/untyped_map_handle.h): `ccf::kv::untyped::MapHandle` implementing `get`, `has`, `put`, `remove`, `clear`, `get_version_of_previous_write`, `get_globally_committed`, `has_globally_committed`, `foreach`, `size`, `range`, `read_key`, and `foreach_state_and_writes`.
- [`src/kv/apply_changes.h`](../src/kv/apply_changes.h): `apply_changes(...)` implementing ordered map locking, atomic multi-map `prepare()`, dynamic new-map conflict checks, version resolution, and atomic `commit()`.
  Signature `expected_rollback_count` checks and `ConsensusHook` collection in this file are unmodeled.
- [`src/kv/tx.cpp`](../src/kv/tx.cpp), [`src/kv/tx_pimpl.h`](../src/kv/tx_pimpl.h), and [`include/ccf/kv/tx.h`](../include/ccf/kv/tx.h): `BaseTx`, `ReadOnlyTx`, and `Tx` implementing lazy initial snapshot capture (`read_txid`, `commit_view`), lazy per-map `ChangeSet` acquisition and dynamic map creation, handle reuse over a shared `ChangeSet`, and `CompactedVersionConflict` reporting.
  `TxDiff` in `include/ccf/kv/tx.h` is unmodeled.
- [`src/kv/committable_tx.h`](../src/kv/committable_tx.h): `CommittableTx::commit(...)` handling read-only commits, invoking `apply_changes`, returning `FAIL_CONFLICT` or stale-term `FAIL_NO_REPLICATE`, and submitting applied writes to `Store::commit`.
  See partial-coverage notes below for unmodeled features in this file.
- [`src/kv/compacted_version_conflict.h`](../src/kv/compacted_version_conflict.h): `CompactedVersionConflict` exception corresponding to `map_unavailable`.
- [`src/kv/version_v.h`](../src/kv/version_v.h) and [`include/ccf/kv/version.h`](../include/ccf/kv/version.h): `Version`, `NoVersion`, and `VersionV<V>` pairing stored values with their write version.

### Questionable or partial inclusions

- **Unmodeled paths inside the core KV files above**: as documented in [`doc/build_apps/kv/semantics.rst`](../doc/build_apps/kv/semantics.rst) and flagged with `trace::unsupported(...)` in `src/kv/`, the following mechanisms inside `store.h`, `untyped_map.h`, `untyped_change_set.h`, `committable_tx.h`, and `tx.h` are explicitly outside `lean/kv`:
  - Snapshot creation, serialization, and import (`Snapshot`, `SnapshotChangeSet`, `SnapshotHandleCommitter`, `deserialise_snapshot*`, `SnapshotPublicMaps`).
  - Ledger entry deserialization and `commit_deserialised`.
  - `ReservedTx`, `set_read_txid`, `TxFlag` (ledger chunking and snapshot flags), `WriteSetObserver`, `swap_private_maps`, and `StoreState::clear`.
  - Map hooks and global commit hooks (`set_map_hook`, `set_global_hook`, `post_commit`, `post_compact`).
  - Security domains (`PUBLIC`/`PRIVATE`), encryption, transaction size limits (`MaxTransactionSizeExceeded`), and `TxDiff` / `MapDiff`.
  - Backward compaction: `Store::compact` lowers its compaction point if called with a smaller version, whereas the model treats backward compaction as a no-op and rejects backward compaction traces.
- [`src/kv/kv_types.h`](../src/kv/kv_types.h): defines `AbstractStore`, `AbstractMap`, `AbstractChangeSet`, `AbstractCommitter`, `CommitResult`, and `SecurityDomain`.
  Inclusion is questionable because it is an abstract interface and shared-types header spanning KV, consensus, history, hooks, and serialization.
- Typed C++ wrappers and public interfaces ([`include/ccf/kv/map_handle.h`](../include/ccf/kv/map_handle.h), [`include/ccf/kv/set_handle.h`](../include/ccf/kv/set_handle.h), [`include/ccf/kv/value_handle.h`](../include/ccf/kv/value_handle.h), [`include/ccf/kv/unit_value_handle.h`](../include/ccf/kv/unit_value_handle.h), [`include/ccf/kv/map.h`](../include/ccf/kv/map.h), [`include/ccf/kv/set.h`](../include/ccf/kv/set.h), [`include/ccf/kv/value.h`](../include/ccf/kv/value.h), [`include/ccf/kv/unit_value.h`](../include/ccf/kv/unit_value.h), [`include/ccf/kv/unit.h`](../include/ccf/kv/unit.h), [`include/ccf/kv/untyped.h`](../include/ccf/kv/untyped.h), [`include/ccf/kv/abstract_handle.h`](../include/ccf/kv/abstract_handle.h), [`include/ccf/kv/get_name.h`](../include/ccf/kv/get_name.h), [`include/ccf/kv/read_only_store.h`](../include/ccf/kv/read_only_store.h)): delegate directly to `ccf::kv::untyped::MapHandle` and `Store`.
  Inclusion is questionable because they invoke the modeled untyped operations, while their type adapters and serializers are explicitly outside `lean/kv`.
- [`src/ds/champ_map.h`](../src/ds/champ_map.h) and [`src/ds/dl_list.h`](../src/ds/dl_list.h): persistent hash-array mapped trie (`champ::Map`) backing map states and doubly linked list (`ds::DLList`) backing `Roll::commits`.
  Inclusion is questionable because KV snapshot immutability and commit-roll traversal rely on their correctness, yet `lean/kv` represents maps as abstract association lists and does not verify CHAMP or `DLList` internals.
- [`src/kv/trace.h`](../src/kv/trace.h) and [`src/kv/trace.cpp`](../src/kv/trace.cpp): opt-in `CCF_KV_TRACING` instrumentation compiled out of normal builds.
  Inclusion is questionable because these files do not implement KV runtime semantics, though they form part of the trace-validation trust boundary.
- [`src/node/retry_on_compacted_version_conflict.h`](../src/node/retry_on_compacted_version_conflict.h) and [`src/node/rpc/frontend.h`](../src/node/rpc/frontend.h): catch `CompactedVersionConflict` and `FAIL_CONFLICT` to retry transactions.
  Inclusion is questionable (likely exclude) because [`doc/build_apps/kv/semantics.rst`](../doc/build_apps/kv/semantics.rst) explicitly excludes automatic endpoint re-execution and retry policy.
- [`src/js/extensions/ccf/kv.cpp`](../src/js/extensions/ccf/kv.cpp) and [`include/ccf/js/extensions/ccf/kv.h`](../include/ccf/js/extensions/ccf/kv.h): JavaScript KV bindings (`get`, `set`, `delete`, `has`, etc.).
  Inclusion is questionable (likely exclude) because [`doc/build_apps/kv/semantics.rst`](../doc/build_apps/kv/semantics.rst) explicitly states that the model does not verify JavaScript bindings or namespace/access restrictions.
- **Explicitly excluded KV files** (reviewed and intentionally not mapped to `lean/kv`):
  - Serialization and entry format: [`src/kv/kv_serialiser.h`](../src/kv/kv_serialiser.h), [`src/kv/raw_serialise.h`](../src/kv/raw_serialise.h), [`src/kv/deserialise.h`](../src/kv/deserialise.h), [`src/kv/generic_serialise_wrapper.h`](../src/kv/generic_serialise_wrapper.h), [`src/kv/serialised_entry_format.h`](../src/kv/serialised_entry_format.h), [`include/ccf/kv/serialisers/blit_serialiser.h`](../include/ccf/kv/serialisers/blit_serialiser.h), [`include/ccf/kv/serialisers/json_serialiser.h`](../include/ccf/kv/serialisers/json_serialiser.h), and [`include/ccf/kv/serialisers/serialised_entry.h`](../include/ccf/kv/serialisers/serialised_entry.h).
  - Encryption and claims: [`src/kv/encryptor.h`](../src/kv/encryptor.h), [`src/kv/null_encryptor.h`](../src/kv/null_encryptor.h), and [`src/kv/claims.h`](../src/kv/claims.h).
  - Snapshots and ledger chunking: [`src/kv/snapshot.h`](../src/kv/snapshot.h), [`src/kv/ledger_chunker.h`](../src/kv/ledger_chunker.h), and [`src/kv/ledger_chunker_interface.h`](../src/kv/ledger_chunker_interface.h).
  - Diffs, hooks, and internal table naming: [`src/kv/untyped_map_diff.cpp`](../src/kv/untyped_map_diff.cpp), [`include/ccf/kv/untyped_map_diff.h`](../include/ccf/kv/untyped_map_diff.h), [`include/ccf/kv/map_diff.h`](../include/ccf/kv/map_diff.h), [`include/ccf/kv/hooks.h`](../include/ccf/kv/hooks.h), and [`src/kv/internal_table_names.h`](../src/kv/internal_table_names.h).
