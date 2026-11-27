# Lean Specification to Implementation Coverage Mapping

This document defines the mapping between CCF's four formal specifications under `lean/` and the C++ implementation source files that realize them.
[`scripts/lean_coverage_report.py`](../scripts/lean_coverage_report.py) parses this document together with each specification's anchor-validated `lean/<spec>/coverage_mask.json` file to compute C++ code LoC, Lean specification LoC, and CI line/branch coverage over the modeled sections, alongside matching whole-file and removed-region metrics from the same `llvm-cov` JSON export.
Each specification also has a companion `lean/<spec>/UNCOVERED_LINES.md` inventorying uncovered lines and candidate tests.

Two packages under `lean/` are support libraries rather than protocol specifications and have no C++ implementation mapping:

- [`lean/common/`](common/README.md) (`ccf_common`): protocol-independent Lean transition-system, execution, finset, sequence, function, and parser infrastructure shared across specifications (only `CCF.TxID` mirrors the primitive type in `include/ccf/tx_id.h`).
- [`lean/mathlib-equivalence/`](mathlib-equivalence/README.md): proofs that the lightweight definitions in `lean/common/` are equivalent to their Mathlib counterparts.

## Scope methodology and taxonomy

The mapping partitions the modeled C++ surface strictly across the four specifications: every C++ line belongs to at most one specification (`scripts/lean_coverage_report.py` enforces cross-spec disjointness), so per-specification counts sum directly to the unique total without double-counting.

### What is in scope

A C++ file or function is mapped to a specification when it directly implements:

1. **Modeled state and protocol types**: core state structures, enums, tables, and message payloads mirrored by `Model/` (including companion headers of exclude-masked component files so C++ type declarations are counted alongside Lean's `Types.lean`/`Messages.lean`).
2. **Modeled transitions, guards, and observables**: functions implementing `Model.step` state transitions, quorum/conflict/freshness/status checks, and client-visible responses or notifications.
3. **Admission and boundary guards enforcing model assumptions**: validation checks that uphold a model's input preconditions (such as quote/certificate pinning for `Validation.rejected`, `/timeout` primary-certificate authentication enforcing local `Input.timeout`, session-view checks, and `try`/`catch` error cleanup preventing false `TxID` emission).
4. **Defensive invariants and LLVM artifacts**: unreachable `std::logic_error` checks, documented semantic discrepancies (such as `Store::compact` backward compaction), and LLVM closing-brace coverage artifacts remain unmasked in scope and are itemized in `<spec>/UNCOVERED_LINES.md`.

### What is out of scope

The following kinds of C++ code are excluded uniformly across all four specifications:

1. **Trace instrumentation, tests, and replay drivers**: `CCF_KV_TRACING` (`#ifdef` blocks and `src/kv/trace.{h,cpp}`), `RDP_TRACE` (`AdvanceTrace` and trace helpers), `cft_trace_msgpack.h`, `trace_retired_committed_tx`, `get_state_for_trace`, test harnesses, and Python trace runners.
2. **Network transport, persistence framing, and host task scheduling**: node-to-node channels, `Forwarder` transport, `libcurl` HTTP/TLS clients (`dispatch_authenticated_message`, `start_failover_timers`), ledger enclave framing, `JobBoard` periodic registration, and backpressure/batch-size heuristics.
3. **Cryptography, attestation internals, sealing, and Merkle receipts**: quote verification internals (`quote.cpp`), SNP local sealing, KV encryption/claims, `TxHistory`, `/receipt`, and `/receipt/cose`.
4. **Explicitly unmodeled features**: snapshots and snapshot import, ledger deserialization, `ReservedTx`, `TxFlag`, `TxDiff`/`MapDiff`, KV hooks, disaster-recovery-only consensus hooks (`remove_deleted_nodes`, 4-arg `force_become_primary`, `enable_all_domains`), HTTP 307 redirection, `/commit`, OpenAPI generation, URI path-template routing, client authentication policies, and request metrics.
5. **Cross-cutting containers, callers, wrappers, and generic libraries**: node lifecycle (`node_state.h`, `node_frontend.h`), shared interface/primitive headers (`kv_types.h`, `tx_id.h`, `consensus_types.h`, `configuration.h`), typed C++ serializer wrappers, QuickJS bindings, governance wrappers, `champ_map.h`, and `dl_list.h`.

### Masking discipline

- Predominantly modeled component files (`consensus`, `disaster-recovery`, `kv`) use **`exclude`** masks so newly added code is counted by default and every exclusion carries a justification.
- Sparse multi-purpose RPC/endpoint files (`consistency`) use whole-function **`include`** masks rather than excluding hundreds of unrelated lines.
- Every mask range is validated by `scripts/lean_coverage_report.py` for non-empty identifier-bearing start anchors, matching end anchors, lexical `{`/`}` brace balance, non-overlap, and cross-spec disjointness.
- Bare `catch` blocks, authentication/validation guards, and defensive error arms of modeled functions are never masked out.

### Methodological caveats

- **CI test coverage is not trace-validated coverage**: line and branch percentages measure how thoroughly CCF's CI test suite (`coverage.yml`) exercises the mapped C++ regions, not which lines ran under a Lean trace replayer (and `coverage.yml` builds with `CCF_KV_TRACING=OFF` and without `CCF_RECOVERY_TRACE=1`).
- **No C++ refinement proof**: code LoC, CI coverage, trace replay, and Lean proofs over abstract models provide complementary assurance rather than a machine-checked C++ refinement proof.
- **Service-level vs component-level mapping**: `lean/consistency` specifies an external client-visible contract whose guarantees depend on consensus and KV code accounted under `lean/consensus` and `lean/kv` to keep rows disjoint; its current replayer validates writes and status reports, not client reads.
- **Uniform `llvm-cov export` branch deduplication**: kept, whole-file unmasked, and removed-region metrics are all computed from the same `coverage-export-json` artifact, which deduplicates branches per source coordinate across C++ template instantiations (taking the maximum hit count per outcome).
- **Declaration-only headers**: companion headers with zero instrumented lines contribute to Code LoC (balancing Lean type/message declarations) and contribute `0/0` to line/branch denominators.

## Current coverage summary

Generated with [`scripts/lean_coverage_report.py`](../scripts/lean_coverage_report.py) against `microsoft/CCF` Coverage run #997 (ID `45962731034`, `main` commit `6a9d9d870`, artifacts `coverage-history-main` and `coverage-export-json`).
All three tables below (in-scope masked, whole-file unmasked, and removed regions) use the same `coverage-export-json` artifact so line counts and template-deduplicated branch counts are directly comparable.

### In-scope modeled sections (masked)

| Item                       | Files | Code LoC | Spec LoC | Total Lean LoC | Lines (Hit/Total) | Line Cov | Branches (Hit/Total) | Branch Cov |
| -------------------------- | ----: | -------: | -------: | -------------: | ----------------: | -------: | -------------------: | ---------: |
| consensus (masked)         |     4 |    2,400 |      955 |         12,792 |       1,851/1,932 |   95.81% |              465/502 |     92.63% |
| consistency (masked)       |     5 |      682 |      594 |          4,986 |           470/571 |   82.31% |              119/138 |     86.23% |
| disaster-recovery (masked) |     4 |    1,061 |      473 |          8,299 |           636/814 |   78.13% |              124/168 |     73.81% |
| kv (masked)                |    13 |    1,642 |    1,071 |          4,648 |       1,087/1,129 |   96.28% |              233/246 |     94.72% |
| **Total (unique)**         |    26 |    5,785 |    3,093 |         30,725 |       4,044/4,446 |   90.96% |            941/1,054 |     89.28% |

### Whole-file unmasked comparison (`--no-masks`, same export)

| Item               | Files | Code LoC | Spec LoC | Total Lean LoC | Lines (Hit/Total) | Line Cov | Branches (Hit/Total) | Branch Cov |
| ------------------ | ----: | -------: | -------: | -------------: | ----------------: | -------: | -------------------: | ---------: |
| consensus          |     4 |    2,693 |      955 |         12,792 |       2,086/2,171 |   96.08% |              531/574 |     92.51% |
| consistency        |     5 |    2,242 |      594 |          4,986 |       1,582/1,891 |   83.66% |              354/422 |     83.89% |
| disaster-recovery  |     4 |    1,361 |      473 |          8,299 |         780/1,046 |   74.57% |              130/192 |     67.71% |
| kv                 |    13 |    3,294 |    1,071 |          4,648 |       2,286/2,397 |   95.37% |              501/544 |     92.10% |
| **Total (unique)** |    26 |    9,590 |    3,093 |         30,725 |       6,734/7,505 |   89.73% |          1,516/1,732 |     87.53% |

### Mask-excluded regions (`--show-removed`, same export)

| Removed regions   | Masked Files | Excluded LoC | Lines (Hit/Total) | Line Cov | Branches (Hit/Total) | Branch Cov |
| ----------------- | -----------: | -----------: | ----------------: | -------: | -------------------: | ---------: |
| consensus         |            4 |          293 |           219/223 |   98.21% |                64/70 |     91.43% |
| consistency       |            4 |        1,560 |       1,112/1,320 |   84.24% |              235/284 |     82.75% |
| disaster-recovery |            3 |          300 |           144/232 |   62.07% |                 6/24 |     25.00% |
| kv                |            9 |        1,652 |       1,199/1,268 |   94.56% |              268/298 |     89.93% |
| **Total**         |           20 |        3,805 |       2,674/3,043 |   87.87% |              573/676 |     84.76% |

Code LoC counts non-blank, non-comment C/C++ lines.
Spec LoC counts non-blank, non-comment Lean lines in `Model` and `Properties`.
Total Lean LoC includes `Proofs`, `TraceValidation`/`Replay`, and `Tests` (shared `lean/common` adds 939 LoC).
Line-range masks applied: [`lean/consensus/coverage_mask.json`](consensus/coverage_mask.json), [`lean/consistency/coverage_mask.json`](consistency/coverage_mask.json), [`lean/disaster-recovery/coverage_mask.json`](disaster-recovery/coverage_mask.json), and [`lean/kv/coverage_mask.json`](kv/coverage_mask.json).
Removed-region line coverage is higher than or within 2 percentage points of kept-region coverage for `consensus` (98.21% vs 95.81%), `consistency` (84.24% vs 82.31%), and `kv` (94.56% vs 96.28%); the lower removed-region coverage in `disaster-recovery` (62.07% vs 78.13%) comes from the 72 disabled `RDP_TRACE` lines (`CCF_RECOVERY_TRACE` is unset in `coverage.yml`) and `start_failover_timers`.
Mapped files with 0 instrumented lines in `llvm-cov` (still counted in Code LoC): `src/node/recovery_decision_protocol.h`, `include/ccf/kv/untyped_map_handle.h`, `src/kv/tx_pimpl.h`, `include/ccf/kv/version.h` (plus `src/consensus/aft/cft_types.h` once its unmodeled `aft::Store`/`Adaptor` bridge and `std::formatter` are masked out).
Provenance note: run #997 (`6a9d9d870`) includes 23 additional lines in `src/consensus/aft/cft.h` (inside `Aft::rollback`) relative to this branch's base commit `a2cea642a`, accounting for the 16-line tail difference between kept+removed (`2,155`) and whole-file (`2,171`) in `consensus`; rebasing onto `main` will align `cft.h` line numbers identically.

## Consensus (`lean/consensus`)

Specification: [`lean/consensus/README.md`](consensus/README.md).
Line-range mask: [`lean/consensus/coverage_mask.json`](consensus/coverage_mask.json).
Uncovered lines analysis: [`lean/consensus/UNCOVERED_LINES.md`](consensus/UNCOVERED_LINES.md).
Models the CCF CFT/AFT consensus protocol, including elections, pre-vote, log replication, signature-gated commitment, reconfiguration quorums, retirement phases, successor nomination, CheckQuorum step-down, rollback, and backup initialization from a committed prefix.

### In-scope implementation files

- [`src/consensus/aft/cft.h`](../src/consensus/aft/cft.h) (masked in [`lean/consensus/coverage_mask.json`](consensus/coverage_mask.json)): main `aft::Aft` consensus state machine implementing elections, pre-vote, `AppendEntries` replication and conflict resolution, quorum checks across active configurations, commit advancement (`update_commit`), reconfiguration (`add_configuration`), retirement (`set_retired_committed`, successor nomination), `periodic` (CheckQuorum majority step-down and election/heartbeat dispatch), `recv_message` (including error arms), rollback, bootstrap (`force_become_primary()`), and `init_as_backup`.
- [`src/consensus/aft/impl/state.h`](../src/consensus/aft/impl/state.h) (masked in [`lean/consensus/coverage_mask.json`](consensus/coverage_mask.json)): `aft::State`, `aft::ViewHistory`, and `aft::AtomicLeadershipState` storing term/view, log and commit indices, committable indices, leadership/membership state, and retirement indices.
- [`src/consensus/aft/cft_types.h`](../src/consensus/aft/cft_types.h) (masked in [`lean/consensus/coverage_mask.json`](consensus/coverage_mask.json)): consensus wire message types (`AppendEntries`, `AppendEntriesResponse`, `RequestVote`, `RequestVoteResponse`, `RequestPreVote`, `RequestPreVoteResponse`, `ProposeRequestVote`, `CftMsgType`) and `starting_view_change`.
- [`src/node/hooks.h`](../src/node/hooks.h) (masked in [`lean/consensus/coverage_mask.json`](consensus/coverage_mask.json)): `ConfigurationChangeHook`, which translates `public:ccf.gov.nodes.info` writes (`PENDING`, `TRUSTED`, `RETIRED`, deletions) into consensus configuration deltas passed to `add_configuration` during replication and follower apply (implementing `TransactionMetadata.configuration` in `Consensus/Model/NodeState.lean`).

### Out-of-scope subsystems and abstractions

- **Masked out of the in-scope consensus files**:
  - `JobBoard` periodic task registration (`register_periodic_tasks`), ledger-backlog and uncommitted-transaction backpressure (`should_apply_backpressure`, `ledger->is_backlogged()` drop in `recv_message`), byte-size batching heuristics (`update_batch_size`), and periodic signature scheduling (`get_signature_disposition`, `can_sign_unsafe`).
  - Disaster-recovery-only paths outside `lean/consensus`: `remove_deleted_nodes` (node deletion without retirement and identity reuse), four-argument `force_become_primary`, and `enable_all_domains`.
  - External RPC/snapshot view-history queries unused by consensus transitions (`get_view_history`, `get_view_history_since`, `ViewHistory::get_history_until`, `ViewHistory::get_history_since`), read-only status diagnostics (`get_details`), `CommitObserver` callbacks, and trace-capture helpers (`trace_retired_committed_tx`, `get_state_for_trace`, and `hooks.h` lines 90-93).
  - The KV `aft::Store`/`aft::Adaptor` bridge (abstracted by `NodeState.log`) and `std::formatter<aft::CftMsgType>` logging formatter in `cft_types.h`.
- **Excluded external files**:
  - Node lifecycle and retirement-transaction drivers (`src/node/node_state.h`, `src/node/retired_nodes_cleanup.h`, `src/node/rpc/node_frontend.h`): the join protocol, snapshot transport/deserialization, crash recovery, and background retirement-confirmation scheduling are outside `lean/consensus`.
  - Transport, ledger framing, and observers (`src/consensus/consensus_types.h`, `src/consensus/aft/consensus_channels.h`, `src/consensus/aft/commit_observer.h`, `src/consensus/ledger_enclave.h`, `src/consensus/ledger_enclave_types.h`, `src/node/node_to_node.h`, `src/node/node_to_node_channel_manager.h`, `src/node/channels.h`, `src/node/node_transport.h`): message delivery, loss, and ledger persistence are abstracted by `CCF.MultiNodeTransitionSystem` and `NodeState.log`.
  - Trace instrumentation and shared vocabulary headers (`src/consensus/aft/cft_trace_msgpack.h`, `src/kv/kv_types.h`, `include/ccf/tx_id.h`).

## Consistency (`lean/consistency`)

Specification: [`lean/consistency/README.md`](consistency/README.md).
Line-range mask: [`lean/consistency/coverage_mask.json`](consistency/coverage_mask.json).
Uncovered lines analysis: [`lean/consistency/UNCOVERED_LINES.md`](consistency/UNCOVERED_LINES.md).
Models CCF's externally visible consistency contract (serializability and real-time ordering of committed writes, forwarded reads, elections, and `Committed`/`Invalid` status reporting) for an abstract append-and-read application.

### In-scope implementation files

- [`include/ccf/tx_status.h`](../include/ccf/tx_status.h): defines `ccf::TxStatus`, `ccf::FinalTxStatus`, `tx_status_to_str`, and `ccf::evaluate_tx_status(...)`, which computes `Unknown`, `Pending`, `Committed`, and `Invalid` from `(target_view, target_seqno)`, local view history, and `(committed_view, committed_seqno)`.
- [`src/endpoints/base_endpoint_registry.cpp`](../src/endpoints/base_endpoint_registry.cpp) (`include`-masked in [`lean/consistency/coverage_mask.json`](consistency/coverage_mask.json)): `get_status_for_txid_v1`, delegating status evaluation to consensus.
- [`src/endpoints/common_endpoint_registry.cpp`](../src/endpoints/common_endpoint_registry.cpp) (`include`-masked in [`lean/consistency/coverage_mask.json`](consistency/coverage_mask.json)): `GetTxStatus` and the `/tx` client endpoint handler that returns transaction status observations.
- [`src/endpoints/endpoint_registry.cpp`](../src/endpoints/endpoint_registry.cpp) (`include`-masked in [`lean/consistency/coverage_mask.json`](consistency/coverage_mask.json)): `default_locally_committed_func` (populating `x-ms-ccf-transaction-id` on initial client responses), default forwarding policies in `make_endpoint`/`make_read_only_endpoint`/`make_command_endpoint`, `execute_*_endpoint`, and `set_consensus`.
- [`src/node/rpc/frontend.h`](../src/node/rpc/frontend.h) (`include`-masked in [`lean/consistency/coverage_mask.json`](consistency/coverage_mask.json)): `RpcFrontend` request execution (`process`, `process_forwarded`, `process_command_inner` including exception cleanup), session-consistency view checks (`check_session_consistency`), backup forwarding (`redirect_or_forward`, `forward`), and transaction commit/retry (`commit_transaction`).

### Out-of-scope subsystems and abstractions

- **Excluded from the `include`-masked RPC/endpoint files**:
  - Unmodeled client/registry endpoints and APIs: `/commit`, `get_last_committed_txid_v1`, `get_view_history_v1`/`v2`, `get_view_for_seqno_v1` (absent from `consistency/Model`, which models per-write final status observations rather than commit-frontier or view-history queries), OpenAPI generation (`/api`, `build_api`, `generate_openapi_document_v1`), historical Merkle/COSE receipts (`/receipt`, `/receipt/cose`), and node/user/member/host-time lookups.
  - HTTP routing, access control, redirection, and operational plumbing: URI path-template regex parsing and lookup, HTTP 404/405/`OPTIONS` formatting, operator-feature/unsecured-interface allowlists, HTTP 307 redirection helpers (`resolve_redirect_location`, `check_redirect`, `get_redirections_config`), client authentication policies, forwarding timeout config, latency metrics, pre-KV command handling, uncommitted-tx backpressure, proposal Merkle-root injection, and periodic ticks.
- **Excluded external files**:
  - Sparse registry declaration headers (`include/ccf/base_endpoint_registry.h`, `include/ccf/common_endpoint_registry.h`, `include/ccf/endpoint_registry.h`): omitted because their `.cpp` counterparts use targeted `include` masks and the remaining header lines are predominantly unrelated declarations and prototypes.
  - Underlying consensus and KV engines (`src/consensus/aft/*`, `src/kv/*`): accounted under `lean/consensus` and `lean/kv` to keep specifications strictly disjoint (note that the `/tx` call chain crosses one unmapped 9-line pass-through in `src/kv/kv_types.h`, `Consensus::evaluate_tx_status`, into `ccf::evaluate_tx_status`).
  - Forwarding transport, deferred commit callbacks, and thin API surfaces (`src/node/rpc/forwarder.h`, `src/node/rpc/forwarder_types.h`, `src/node/commit_callback_subsystem.h`, `src/node/commit_callback_interface.h`, `src/node/gov/handlers/transactions.h`, `src/js/extensions/ccf/consensus.cpp`, `src/node/rpc/user_frontend.h`, `src/node/rpc/member_frontend.h`, `src/endpoints/endpoint.cpp`, `src/consensus/aft/cft_trace_msgpack.h`, `include/ccf/tx_id.h`): forwarding network transport, hold-until-commit deferred responses, non-forwarded backup reads, HTTP redirection overrides, governance/JS wrappers, and trace definitions are outside `lean/consistency`.

## Disaster Recovery (`lean/disaster-recovery`)

Specification: [`lean/disaster-recovery/README.md`](disaster-recovery/README.md).
Line-range mask: [`lean/disaster-recovery/coverage_mask.json`](disaster-recovery/coverage_mask.json).
Uncovered lines analysis: [`lean/disaster-recovery/UNCOVERED_LINES.md`](disaster-recovery/UNCOVERED_LINES.md).
Models CCF's self-healing open recovery decision protocol: per-node phases (`Gossiping`, `Voting`, `Opening`, `Joining`, `Open`), independent timeout lane, deterministic gossip selection by `(view, seqno, location)`, quorum vs failover opening, retries, validation rejection, and restart notifications.

### In-scope implementation files

- [`src/node/recovery_decision_protocol.cpp`](../src/node/recovery_decision_protocol.cpp) (masked in [`lean/disaster-recovery/coverage_mask.json`](disaster-recovery/coverage_mask.json)): `RecoveryDecisionProtocolSubsystem` implementing `reset_state`, `try_start`, `advance`, gossip/vote/IAmOpen/timeout transitions, deterministic maximum selection, retry-phase dispatch (`start_message_retry_timers`, `stop_timers`), message builders (`get_node_info`, `get_iamopen_request`), and message fanout (`send_gossip_unsafe`, `send_vote_unsafe`, `send_iamopen_unsafe`).
- [`src/node/recovery_decision_protocol.h`](../src/node/recovery_decision_protocol.h) (masked in [`lean/disaster-recovery/coverage_mask.json`](disaster-recovery/coverage_mask.json)): `RecoveryDecisionProtocolSubsystem` declaration and protocol request payloads (`TaggedWithNodeInfo`, `GossipRequest`, `IAmOpenRequest`).
- [`src/node/rpc/self_healing_open_handlers.h`](../src/node/rpc/self_healing_open_handlers.h) (masked in [`lean/disaster-recovery/coverage_mask.json`](disaster-recovery/coverage_mask.json)): inbound endpoints `/recovery_decision_protocol/{gossip,vote,iamopen,timeout}`, including subsystem/configuration admission guards, quote verification and certificate-pinning rejection (`Validation.rejected`), `/timeout` primary-certificate authentication (enforcing the local `Input.timeout` assumption), gossip freeze and deduplication, vote insertion, `IAmOpen` handling, and `advance()`.
- [`include/ccf/service/tables/self_healing_open.h`](../include/ccf/service/tables/self_healing_open.h): protocol enums (`StateMachine`, `OpenKinds`), `Location`, `RequestNodeInfo`, `NodeInfo`, `service_fingerprint_from_pem`, and the `RECOVERY_DECISION_PROTOCOL_*` KV tables.

### Out-of-scope subsystems and abstractions

- **Masked out of the in-scope disaster-recovery files**:
  - `RDP_TRACE` instrumentation (`tracing_enabled`, `trace_safely`, `emit_trace`, `record_trace_send`, `prepare_trace_step`, `trace_committed_step`, `AdvanceTrace`, `trace_on_commit`, and inline `trace_safely` blocks).
  - Wall-clock failover timer scheduling with cURL self-HTTP dispatch (`start_failover_timers`) and cURL HTTP/TLS message transport (`dispatch_authenticated_message`): timeouts and network delivery are abstracted as `Input.timeout` and `CCF.MultiNodeTransitionSystem` envelopes in `DisasterRecovery/Model.lean`.
- **Excluded external files**:
  - TEE attestation cryptography and SNP local sealing (`src/node/quote.cpp`, `include/ccf/node/quote.h`, `src/node/rpc/node_frontend_utils.h`, `src/node/local_sealing.h`, `src/node/local_sealing.cpp`, `src/service/tables/local_sealing.h`, `include/ccf/service/local_sealing.h`): `Local.lean` abstracts quote cryptography as `Validation.accepted | .rejected` and does not model key sealing.
  - Downstream service opening, process restart, and host lifecycle wiring (`src/node/node_state.h`, `src/node/rpc/node_frontend.h`, `src/node/rpc/node_interface.h`, `src/node/rpc/node_operation.h`, `src/node/rpc/node_operation_interface.h`, `src/node/open_service.h`, `src/node/recovered_service_opening_task.h`, `src/node/runtime_control.h`, `include/ccf/node/configuration.h`): `Local.step` stops at emitting `Notification.opening` and `Notification.restart`.
  - HTTP/TLS client transport and shared primitive types (`src/http_client/curl.h`, `include/ccf/tx_id.h`).

## Key-Value Store (`lean/kv`)

Specification: [`lean/kv/README.md`](kv/README.md) and [`doc/build_apps/kv/semantics.rst`](../doc/build_apps/kv/semantics.rst).
Line-range mask: [`lean/kv/coverage_mask.json`](kv/coverage_mask.json).
Uncovered lines analysis: [`lean/kv/UNCOVERED_LINES.md`](kv/UNCOVERED_LINES.md).
Models the observable single-node semantics of CCF's transactional KV store: lazy current-snapshot metadata capture, lazy per-map local and globally committed view capture, point and map-wide reads/writes/iteration, optimistic concurrency control, atomic multi-map local application, compaction, and rollback.

### In-scope implementation files

- [`src/kv/store.h`](../src/kv/store.h) (masked in [`lean/kv/coverage_mask.json`](kv/coverage_mask.json)): `ccf::kv::Store` and `StoreState` lifecycle, `current_txid_and_commit_term`, `next_version` (including stale-term rejection), `get_map`/`add_dynamic_map`, `commit` replication result handling, `compact`, and `rollback`.
- [`src/kv/untyped_map.h`](../src/kv/untyped_map.h) (masked in [`lean/kv/coverage_mask.json`](kv/coverage_mask.json)): `ccf::kv::untyped::Map`, `Roll`, `LocalCommit`, `HandleCommitter` (`prepare` OCC conflict checks on per-key reads, whole-map `read_version`, and `rollback_counter`; `commit` frame publication), `create_change_set` (per-map local and globally committed view capture and compacted-version checks), and map-level `compact` and `rollback`.
- [`src/kv/untyped_change_set.h`](../src/kv/untyped_change_set.h) (masked in [`lean/kv/coverage_mask.json`](kv/coverage_mask.json)): `ccf::kv::untyped::ChangeSet` holding pinned `state`, pinned `committed` view, `start_version`, `rollback_counter`, `read_version`, `reads`, and `writes`.
- [`src/kv/untyped_map_handle.cpp`](../src/kv/untyped_map_handle.cpp) (masked in [`lean/kv/coverage_mask.json`](kv/coverage_mask.json)) and [`include/ccf/kv/untyped_map_handle.h`](../include/ccf/kv/untyped_map_handle.h): `ccf::kv::untyped::MapHandle` implementing `get`, `has`, `put`, `remove`, `clear`, `get_version_of_previous_write`, `get_globally_committed`, `has_globally_committed`, `foreach`, `size`, `range`, `read_key`, and `foreach_state_and_writes`.
- [`src/kv/apply_changes.h`](../src/kv/apply_changes.h) (masked in [`lean/kv/coverage_mask.json`](kv/coverage_mask.json)): `apply_changes(...)` implementing ordered map locking, atomic multi-map `prepare()`, dynamic new-map conflict checks, version resolution, and atomic `commit()`.
- [`src/kv/tx.cpp`](../src/kv/tx.cpp) (masked in [`lean/kv/coverage_mask.json`](kv/coverage_mask.json)), [`src/kv/tx_pimpl.h`](../src/kv/tx_pimpl.h) (masked in [`lean/kv/coverage_mask.json`](kv/coverage_mask.json)), and [`include/ccf/kv/tx.h`](../include/ccf/kv/tx.h) (masked in [`lean/kv/coverage_mask.json`](kv/coverage_mask.json)): `BaseTx`, `ReadOnlyTx`, and `Tx` implementing lazy initial snapshot capture (`read_txid`, `commit_view`), lazy per-map `ChangeSet` acquisition and dynamic map creation, handle reuse over a shared `ChangeSet`, and `CompactedVersionConflict` reporting.
- [`src/kv/committable_tx.h`](../src/kv/committable_tx.h) (masked in [`lean/kv/coverage_mask.json`](kv/coverage_mask.json)): `CommittableTx::commit(...)` handling read-only commits, invoking `apply_changes`, returning `FAIL_CONFLICT` or stale-term `FAIL_NO_REPLICATE`, and submitting applied writes to `Store::commit`.
- [`src/kv/compacted_version_conflict.h`](../src/kv/compacted_version_conflict.h): `CompactedVersionConflict` exception corresponding to `map_unavailable`.
- [`src/kv/version_v.h`](../src/kv/version_v.h) and [`include/ccf/kv/version.h`](../include/ccf/kv/version.h): `Version`, `NoVersion`, and `VersionV<V>` pairing stored values with their write version.

### Out-of-scope subsystems and abstractions

- **Masked out of the in-scope KV files** (documented in [`doc/build_apps/kv/semantics.rst`](../doc/build_apps/kv/semantics.rst) and flagged with `trace::unsupported(...)` in `src/kv/`):
  - Snapshot creation, serialization, and import (`Snapshot`, `SnapshotChangeSet`, `SnapshotHandleCommitter`, `deserialise_snapshot*`, `SnapshotPublicMaps`), ledger deserialization (`fill_maps`, `deserialize`, `commit_deserialised`), and wire serialization helpers.
  - `ReservedTx`, `set_read_txid`, `TxFlag`/`StoreFlag` (ledger chunking and snapshot flags), `WriteSetObserver`, `swap_private_maps`, `StoreState::clear`, `Map::clear` outside a transaction, and `TxDiff`/`MapDiff` (`track_deletes_on_missing_keys`).
  - Map and global hooks (`set_map_hook`, `set_global_hook`, `post_commit`, `post_compact`, `ConsensusHook` collection), `StoreReadiness`, `TxHistory`/`ILedgerChunker`/`Encryptor` plumbing, and compiled-out `#ifdef CCF_KV_TRACING` instrumentation blocks.
  - Note: backward compaction in `Store::compact` (which lowers the cutoff if given a smaller version, whereas `lean/kv` treats it as a no-op and rejects backward traces) remains unmasked as a documented domain restriction.
- **Excluded external files**:
  - Serialization, encryption, claims, snapshots, chunking, diffs, hooks, and shared interfaces: `src/kv/kv_types.h`, `src/kv/kv_serialiser.h`, `src/kv/raw_serialise.h`, `src/kv/deserialise.h`, `src/kv/generic_serialise_wrapper.h`, `src/kv/serialised_entry_format.h`, `include/ccf/kv/serialisers/{blit_serialiser,json_serialiser,serialised_entry}.h`, `src/kv/encryptor.h`, `src/kv/null_encryptor.h`, `src/kv/claims.h`, `src/kv/snapshot.h`, `src/kv/ledger_chunker.h`, `src/kv/ledger_chunker_interface.h`, `src/kv/untyped_map_diff.cpp`, `include/ccf/kv/{untyped_map_diff,map_diff,hooks}.h`, and `src/kv/internal_table_names.h`.
  - Typed C++ serializer handles and wrappers (`include/ccf/kv/{map,set,value,unit_value}_handle.h`, `include/ccf/kv/{map,set,value,unit_value,unit,untyped,abstract_handle,get_name,read_only_store}.h`) and JavaScript bindings (`src/js/extensions/ccf/kv.cpp`, `include/ccf/js/extensions/ccf/kv.h`): `lean/kv` models untyped byte-key/value maps without type serializers or JS bindings.
  - Generic persistent data structures (`src/ds/champ_map.h`, `src/ds/dl_list.h`), caller retry loops (`src/node/retry_on_compacted_version_conflict.h`, `src/node/rpc/frontend.h`), and opt-in trace emitters (`src/kv/trace.h`, `src/kv/trace.cpp`).
