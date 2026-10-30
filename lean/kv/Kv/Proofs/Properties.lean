-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Proofs.Execution
public import Kv.Proofs.Trace

@[expose] public section

namespace Kv.Proofs.Properties

open Kv.Model Kv.Properties

theorem replay_segment_serializability
    : ∀ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → (∀ r ∈ rs, SegmentEvent sid r.event)
        → CCF.Execution.Run Model.transitionSystem w rs final
        → ∃ after txs,
            find final.stores sid = some after
            ∧ projectApplications w sid rs = .ok txs
            ∧ serialTransactions s.head.data s.head.version txs = some after.head.data
            ∧ after.head.version = s.head.version + txs.length := by
  intro w final sid s rs reachable live segment accepted
  exact Proofs.Trace.replay_segment_serializability w final sid s
    (Invariants.reachable_invariant w reachable) rs live segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem reachable_store_invariants
    : ∀ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → History s.history s.head.version
          ∧ s.history.head? = some s.head
          ∧ s.global ≤ s.head.version
          ∧ (atCut s s.global).version = s.global := by
  intro w sid s reachable live
  exact Proofs.Trace.reachable_store_invariants w (Invariants.reachable_invariant w reachable) sid s live

theorem reachable_store_data_invariants
    : ∀ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → Unique s.head.data ∧ CellsBounded s.head.data s.head.version := by
  intro w sid s reachable live
  exact Proofs.Trace.reachable_store_data_invariants w (Invariants.reachable_invariant w reachable) sid s live

theorem step_capture_metadata
    : ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store) (t : Tx),
        storeOf w sid = .ok s
        → Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next
        → find next.txs tid = some t
        → ∃ snap, t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = term := by
  intro w next sid tid version global term seq s t source accepted capturedTx
  exact Proofs.Trace.step_capture_metadata w next sid tid version global term seq s t source ((Proofs.Execution.step_iff_transition _ _ _).mp accepted) capturedTx

theorem step_capture_cut_values
    : ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store),
        storeOf w sid = .ok s
        → Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next
        → version = s.head.version ∧ global = s.global := by
  intro w next sid tid version global term seq s source accepted
  exact Proofs.Trace.step_capture_cut_values w next sid tid version global term seq s source ((Proofs.Execution.step_iff_transition _ _ _).mp accepted)

theorem capture_replay_preserves_metadata
    : ∀ (w capturedWorld final : World) (sid tid version global term seq : Nat)
        (s : Store) (t : Tx) (tail : List Record),
        storeOf w sid = .ok s
        → Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some capturedWorld
        → find capturedWorld.txs tid = some t
        → (∀ r ∈ tail, AttemptEvent tid r.event)
        → CCF.Execution.Run Model.transitionSystem capturedWorld tail final
        → ∃ after snap,
            find final.txs tid = some after
            ∧ after.snapshot = some snap
            ∧ snap.current = s.head
            ∧ snap.term = term := by
  intro w capturedWorld final sid tid version global term seq s t tail source capture live segment accepted
  exact Proofs.Trace.capture_replay_preserves_metadata w capturedWorld final sid tid version global term seq s t tail source ((Proofs.Execution.step_iff_transition _ _ _).mp capture) live segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem replay_snapshot_fixed
    : ∀ (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot) (rs : List Record),
        find w.txs tid = some before
        → before.snapshot = some snap
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run Model.transitionSystem w rs final
        → ∃ after, find final.txs tid = some after ∧ after.snapshot = some snap := by
  intro w final tid before snap rs live captured segment accepted
  exact Proofs.Trace.replay_snapshot_fixed w final tid before snap rs live captured segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem step_map_capture
    : ∀ (w next : World) (sid tid localVersion globalVersion seq : Nat) (map : String)
        (s : Store) (before after : Tx) (snap : Snapshot),
        storeOf w sid = .ok s
        → txOf w sid tid = .ok before
        → before.snapshot = some snap
        → Model.transitionSystem.step w
            ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some next
        → find next.txs tid = some after
        → find after.globalViews map = some (captureGlobal s snap map)
          ∧ localVersion = (revision (captureLocal s snap map) map).version
          ∧ globalVersion = (revision (captureGlobal s snap map).frame map).version := by
  intro w next sid tid localVersion globalVersion seq map s before after snap store tx snapshot accepted live
  exact Proofs.Trace.step_map_capture w next sid tid localVersion globalVersion seq map s before after snap store tx snapshot ((Proofs.Execution.step_iff_transition _ _ _).mp accepted) live

theorem replay_map_global_fixed
    : ∀ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        → find before.globalViews map = some view
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run Model.transitionSystem w rs final
        → ∃ after,
            find final.txs tid = some after ∧ find after.globalViews map = some view := by
  intro w final tid before map view rs live captured segment accepted
  exact Proofs.Trace.replay_map_global_fixed w final tid before map view rs live captured segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem capture_replay_preserves_map
    : ∀ (w capturedWorld final : World) (sid tid localVersion globalVersion seq : Nat)
        (map : String) (s : Store) (before capturedTx : Tx) (snap : Snapshot)
        (tail : List Record),
        storeOf w sid = .ok s
        → txOf w sid tid = .ok before
        → before.snapshot = some snap
        → Model.transitionSystem.step w
            ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some capturedWorld
        → find capturedWorld.txs tid = some capturedTx
        → (∀ r ∈ tail, AttemptEvent tid r.event)
        → CCF.Execution.Run Model.transitionSystem capturedWorld tail final
        → ∃ after,
            find final.txs tid = some after
            ∧ find after.globalViews map = some (captureGlobal s snap map)
            ∧ localVersion = (revision (captureLocal s snap map) map).version
            ∧ globalVersion
              = (revision (captureGlobal s snap map).frame map).version := by
  intro w capturedWorld final sid tid localVersion globalVersion seq map s before capturedTx snap tail store tx snapshot capture live segment accepted
  exact Proofs.Trace.capture_replay_preserves_map w capturedWorld final sid tid localVersion globalVersion seq map s before capturedTx snap tail store tx snapshot ((Proofs.Execution.step_iff_transition _ _ _).mp capture) live segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem step_global_read_from_captured_map
    : ∀ (w next : World) (sid tid seq : Nat) (map key : String) (value : Option String)
        (t : Tx) (view : GlobalView),
        Model.transitionSystem.Reachable w
        → txOf w sid tid = .ok t
        → find t.globalViews map = some view
        → Model.transitionSystem.step w ⟨seq, .get sid tid map key value true⟩ = some next
        → value = (find view.frame.data (map, key)).map Cell.value
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  intro w next sid tid seq map key value t view reachable source captured accepted
  exact Proofs.Trace.step_global_read_from_captured_map w next sid tid seq
    (Invariants.reachable_invariant w reachable) map key value t view source captured ((Proofs.Execution.step_iff_transition _ _ _).mp accepted)

theorem step_global_has_from_captured_map
    : ∀ (w next : World) (sid tid seq : Nat) (map key : String) (value : Bool) (t : Tx)
        (view : GlobalView),
        Model.transitionSystem.Reachable w
        → txOf w sid tid = .ok t
        → find t.globalViews map = some view
        → Model.transitionSystem.step w ⟨seq, .has sid tid map key value true⟩ = some next
        → value = (find view.frame.data (map, key)).isSome
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  intro w next sid tid seq map key value t view reachable source captured accepted
  exact Proofs.Trace.step_global_has_from_captured_map w next sid tid seq
    (Invariants.reachable_invariant w reachable) map key value t view source captured ((Proofs.Execution.step_iff_transition _ _ _).mp accepted)

theorem discarded_handle_cannot_apply
    : ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        → (m, view) ∈ t.globalViews
        → (∀ f ∈ s.history, (revision f m == revision view.current m) = false)
        → canApply s t = false := by
  intro s t snap m view hs hm gone
  exact Proofs.Model.discarded_handle_cannot_apply s t snap hs m view hm gone

theorem replay_map_local_fixed
    : ∀ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        → find before.globalViews map = some view
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run Model.transitionSystem w rs final
        → ∃ after,
            find final.txs tid = some after
            ∧ image after.data map = image before.data map := by
  intro w final tid before map view rs live captured segment accepted
  exact Proofs.Trace.replay_map_local_fixed w final tid before map view rs live captured segment
    ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem discarded_birth_cannot_apply
    : ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        → (m, view) ∈ t.globalViews
        → (∀ f ∈ s.history, (find f.births m == find view.current.births m) = false)
        → canApply s t = false := by
  intro s t snap m view hs hm gone
  exact Proofs.Model.discarded_birth_cannot_apply s t snap hs m view hm gone

end Kv.Proofs.Properties
