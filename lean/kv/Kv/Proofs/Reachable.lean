-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Proofs.Segment

@[expose] public section

namespace Kv.Proofs.Trace

open Kv.Model
      hiding Store Tx advance compactStore rollbackStore tryApply step transitionSystem
open Kv.Correspondence Kv.TraceValidation Kv.Properties Kv.Proofs.Capture
  Kv.Proofs.Correspondence

private theorem step_iff_transition (w next : World) (r : Record)
    : transitionSystem.step w r = some next ↔ step w r = .ok next := by
  simp only [transitionSystem]
  cases step w r <;> simp [Except.toOption]

private theorem projected_store (w : World) (sid : Nat) (s : Store)
    (live : find w.stores sid = some s)
    : find (project w).stores sid = some s.toStore := by
  simp only [project_store, live, Option.map_some]

/-- Accepted selected-store segments serialize their actual pre-event applied attempts. -/
theorem replay_segment_serializability_claim
    : ∀ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
        transitionSystem.Reachable w
        → find w.stores sid = some s
        → (∀ r ∈ rs, SegmentEvent sid r.event)
        → CCF.Execution.Run transitionSystem w rs final
        → ∃ after txs,
            find final.stores sid = some after
            ∧ projectApplications w sid rs = .ok txs
            ∧ serialTransactions s.head.data s.head.version txs = some after.head.data
            ∧ after.head.version = s.head.version + txs.length :=
  Segment.replay_segment_serializability

/-- Replay-reachable store safety follows from arbitrary semantic reachability safety. -/
theorem reachable_store_invariants_claim
    : ∀ (w : World) (sid : Nat) (s : Store),
        transitionSystem.Reachable w
        → find w.stores sid = some s
        → History s.history s.head.version
          ∧ s.history.head? = some s.head
          ∧ s.global ≤ s.head.version
          ∧ (atCut s s.global).version = s.global := by
  intro w sid s reachable live
  exact SemanticInvariant.semantic_reachable_store_invariants (project w) sid s.toStore
    (reachable_projects w reachable) (projected_store w sid s live)

/-- Replay-reachable unique data and bounded previous versions inherit semantic safety. -/
theorem reachable_store_data_invariants_claim
    : ∀ (w : World) (sid : Nat) (s : Store),
        transitionSystem.Reachable w
        → find w.stores sid = some s
        → Unique s.head.data ∧ CellsBounded s.head.data s.head.version := by
  intro w sid s reachable live
  exact SemanticInvariant.semantic_reachable_store_data_invariants (project w) sid s.toStore
    (reachable_projects w reachable) (projected_store w sid s live)

private theorem global_provenance (w : World) (sid tid : Nat) (map : String)
    (t : Tx) (view : GlobalView) (reachable : transitionSystem.Reachable w)
    (source : txOf w sid tid = .ok t) (captured : find t.globalViews map = some view)
    : view.frame = {}
      ∨ ∃ origin : Store,
          view.frame = atCut origin origin.global
          ∧ view.frame.version = origin.global
          ∧ CellsBounded view.frame.data origin.global := by
  have live : find (project w).txs tid = some t.toTx := by
    simp only [project_tx, (tx_found source).1, Option.map_some]
  have provenance := SemanticInvariant.semantic_global_provenance (project w) tid t.toTx map view
    (reachable_projects w reachable) live captured
  rcases provenance with empty | ⟨origin, facts⟩
  · exact Or.inl empty
  · exact Or.inr ⟨{ toStore := origin, termKnown := false }, facts⟩

/-- Accepted global reads use the map's captured global frame and semantic provenance. -/
theorem step_global_read_from_captured_map_claim
    : ∀ (w next : World) (sid tid seq : Nat) (map key : String) (value : Option String)
        (t : Tx) (view : GlobalView),
        transitionSystem.Reachable w
        → txOf w sid tid = .ok t
        → find t.globalViews map = some view
        → transitionSystem.step w ⟨seq, .get sid tid map key value true⟩ = some next
        → value = (find view.frame.data (map, key)).map Cell.value
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  intro w next sid tid seq map key value t view reachable source captured accepted
  obtain ⟨_, event, _⟩ := record_checked ((step_iff_transition _ _ _).mp accepted)
  obtain ⟨_, _, guarded, _, _, _⟩ := event_checked event
  obtain ⟨actual, tx, guarded⟩ := bind_ok guarded
  cases source.symm.trans tx
  obtain ⟨_, _, guarded⟩ := bind_ok guarded
  try dsimp only at guarded
  obtain ⟨actualView, found, guarded⟩ := bind_ok guarded
  cases captured.symm.trans (present_ok found)
  exact ⟨(beq_iff_eq.mp (expect_ok guarded)).symm,
    global_provenance w sid tid map t view reachable source captured⟩

/-- Accepted global presence reads use the map's captured frame and semantic provenance. -/
theorem step_global_has_from_captured_map_claim
    : ∀ (w next : World) (sid tid seq : Nat) (map key : String) (value : Bool)
        (t : Tx) (view : GlobalView),
        transitionSystem.Reachable w
        → txOf w sid tid = .ok t
        → find t.globalViews map = some view
        → transitionSystem.step w ⟨seq, .has sid tid map key value true⟩ = some next
        → value = (find view.frame.data (map, key)).isSome
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  intro w next sid tid seq map key value t view reachable source captured accepted
  obtain ⟨_, event, _⟩ := record_checked ((step_iff_transition _ _ _).mp accepted)
  obtain ⟨_, _, guarded, _, _, _⟩ := event_checked event
  obtain ⟨actual, tx, guarded⟩ := bind_ok guarded
  cases source.symm.trans tx
  obtain ⟨_, _, guarded⟩ := bind_ok guarded
  try dsimp only at guarded
  obtain ⟨actualView, found, guarded⟩ := bind_ok guarded
  cases captured.symm.trans (present_ok found)
  exact ⟨(beq_iff_eq.mp (expect_ok guarded)).symm,
    global_provenance w sid tid map t view reachable source captured⟩

end Kv.Proofs.Trace

namespace Kv.Proofs.Properties

open Kv.Model
      hiding Store Tx advance compactStore rollbackStore tryApply step transitionSystem
open Kv.Correspondence Kv.TraceValidation Kv.Properties Kv.Proofs.Capture
  Kv.Proofs.Correspondence

/-- Trace-reachable transaction snapshot seriality inherits arbitrary semantic reachability. -/
theorem transaction_snapshot_serial
    : ∀ (w : World) (tid : Nat) (t : Tx) (snap : Snapshot),
        transitionSystem.Reachable w
        → find w.txs tid = some t
        → t.snapshot = some snap
        → serialRun t.data [] t.normal.log = some t.normal.writes := by
  intro w tid t snap reachable live captured
  have projected : find (project w).txs tid = some t.toTx := by
    simp only [project_tx, live, Option.map_some]
  exact SemanticInvariant.semantic_transaction_snapshot_serial (project w) tid t.toTx snap
    (reachable_projects w reachable) projected captured

/-- Trace-reachable application seriality inherits arbitrary semantic reachability. -/
theorem transaction_application_serial
    : ∀ (w : World) (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot),
        transitionSystem.Reachable w
        → storeOf w sid = .ok s
        → txOf w sid tid = .ok t
        → t.snapshot = some snap
        → canApply s t = true
        → serialRun s.head.data [] t.normal.log = some t.normal.writes := by
  intro w sid tid s t snap reachable store tx captured permitted
  exact SemanticInvariant.semantic_transaction_application_serial (project w) sid tid s.toStore t.toTx
    snap (reachable_projects w reachable) (lookup_project store tx) captured permitted

private theorem branch_projects (s final : Store) (ts : List Tx)
    (branch : AppliedBranch s ts final)
    : SemanticAppliedBranch s.toStore (ts.map Tx.toTx) final.toStore := by
  induction branch with
  | nil s => exact .nil _
  | cons s middle final t ts one _rest ih =>
      obtain ⟨core, applied, equal⟩ := Option.map_eq_some_iff.mp one
      have projected := congrArg Store.toStore equal
      change core = middle.toStore at projected
      exact .cons _ _ _ _ _ (by simpa only [projected] using applied) ih
  | compact s final v ts _rest ih => exact .compact _ _ _ _ ih

private theorem serial_projects (db : Data) (version : Nat) (ts : List Tx)
    : semanticSerialTransactions db version (ts.map Tx.toTx)
      = serialTransactions db version ts := by
  induction ts generalizing db version with
  | nil => rfl
  | cons t ts ih =>
      simp only [List.map_cons, semanticSerialTransactions, serialTransactions]
      congr 1
      funext writes
      exact ih _ _

/-- Decorated application-order branches inherit the stronger all-semantic-runs seriality theorem. -/
theorem executable_branch_serializability
    : ∀ (s final : Store) (ts : List Tx),
        (∀ t ∈ ts,
          ∃ (w : World) (tid : Nat),
            transitionSystem.Reachable w ∧ find w.txs tid = some t)
        → AppliedBranch s ts final
        → serialTransactions s.head.data s.head.version ts = some final.head.data := by
  intro s final ts reachable branch
  rw [← serial_projects]
  apply SemanticInvariant.semantic_executable_branch_serializability _ _ _
    _ (branch_projects s final ts branch)
  intro core member
  obtain ⟨t, member, equal⟩ := List.mem_map.mp member
  obtain ⟨w, tid, initialized, live⟩ := reachable t member
  refine ⟨project w, tid, reachable_projects w initialized, ?_⟩
  simp only [project_tx, live, Option.map_some, equal]

/-- Durable cut preservation through rollback holds for trace-reachable stores by semantic safety. -/
theorem durable_cut_survives_rollback
    : ∀ (w : World) (sid : Nat) (s : Store) (v term cut : Nat),
        transitionSystem.Reachable w
        → find w.stores sid = some s
        → cut ≤ s.global
        → s.global ≤ v
        → (atCut (rollbackStore s v term) cut).data = (atCut s cut).data := by
  intro w sid s v term cut reachable live within boundary
  have projected : find (project w).stores sid = some s.toStore := by
    simp only [project_store, live, Option.map_some]
  exact SemanticInvariant.semantic_durable_cut_survives_rollback (project w) sid v term
    cut s.toStore (reachable_projects w reachable) projected within boundary

end Kv.Proofs.Properties
