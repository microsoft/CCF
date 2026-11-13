-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Invariants
public import CCF.Execution
public import CCF.Witnessed

import Kv.Proofs.Reachable
import Kv.Proofs.Replay
import Kv.Proofs.Witnesses

/-!
The witnessed claims of `Kv/Properties.lean`, each assembled from its safety theorem and its
witness.
`Properties.lean` restates each claim and refers to its proof here.
-/

@[expose] public section

namespace Kv.Proofs.Claims

open Kv.Model
open Kv.Properties

/-- The claim `transaction_snapshot_serial` of `Properties.lean`. -/
theorem transaction_snapshot_serial
    : witnessed% ∀ (w : World) (tid : Nat) (t : Tx) (snap : Snapshot),
                  {
                    pre :=
                      Model.transitionSystem.Reachable w
                      ∧ find w.txs tid = some t
                      ∧ t.snapshot = some snap
                    post := serialRun t.data [] t.normal.log = some t.normal.writes
                    witness := t.normal.log ≠ []
                  } :=
  ⟨
    fun _ _ _ _ ⟨h1, h2, h3⟩ =>
      Proofs.Properties.transaction_snapshot_serial _ _ _ _ h1 h2 h3,
    Proofs.Witnesses.transaction_snapshot_serial_witness
  ⟩

/-- The claim `transaction_application_serial` of `Properties.lean`. -/
theorem transaction_application_serial
    : witnessed% ∀ (w : World) (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot),
                  {
                    pre :=
                      Model.transitionSystem.Reachable w
                      ∧ storeOf w sid = .ok s
                      ∧ txOf w sid tid = .ok t
                      ∧ t.snapshot = some snap
                      ∧ canApply s t = true
                    post := serialRun s.head.data [] t.normal.log = some t.normal.writes
                    witness := t.normal.log ≠ []
                  } :=
  ⟨
    fun _ _ _ _ _ _ ⟨h1, h2, h3, h4, h5⟩ =>
      Proofs.Properties.transaction_application_serial _ _ _ _ _ _ h1 h2 h3 h4 h5,
    Proofs.Witnesses.transaction_application_serial_witness
  ⟩

/-- The claim `executable_branch_serializability` of `Properties.lean`. -/
theorem executable_branch_serializability
    : witnessed% ∀ (s final : Store) (ts : List Tx),
                  {
                    pre :=
                      (∀ t ∈ ts,
                        ∃ (w : World) (tid : Nat),
                          Model.transitionSystem.Reachable w ∧ find w.txs tid = some t)
                      ∧ AppliedBranch s ts final
                    post :=
                      serialTransactions s.head.data s.head.version ts
                      = some final.head.data
                    witness := ts ≠ []
                  } :=
  ⟨
    fun _ _ _ ⟨h1, h2⟩ => Proofs.Properties.executable_branch_serializability _ _ _ h1 h2,
    Proofs.Witnesses.executable_branch_serializability_witness
  ⟩

/-- The claim `replay_segment_serializability` of `Properties.lean`. -/
theorem replay_segment_serializability
    : witnessed% ∀ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
                  {
                    pre :=
                      Model.transitionSystem.Reachable w
                      ∧ find w.stores sid = some s
                      ∧ (∀ r ∈ rs, SegmentEvent sid r.event)
                      ∧ CCF.Execution.Run Model.transitionSystem w rs final
                    post :=
                      ∃ after txs,
                        find final.stores sid = some after
                        ∧ projectApplications w sid rs = .ok txs
                        ∧ serialTransactions s.head.data s.head.version txs
                          = some after.head.data
                        ∧ after.head.version = s.head.version + txs.length
                    witness := rs ≠ []
                  } :=
  ⟨
    fun _ _ _ _ _ ⟨h1, h2, h3, h4⟩ =>
      Proofs.Trace.replay_segment_serializability_claim _ _ _ _ _ h1 h2 h3 h4,
    Proofs.Witnesses.replay_segment_serializability_witness
  ⟩

/-- The claim `reachable_store_invariants` of `Properties.lean`. -/
theorem reachable_store_invariants
    : witnessed% ∀ (w : World) (sid : Nat) (s : Store),
                  {
                    pre :=
                      Model.transitionSystem.Reachable w ∧ find w.stores sid = some s
                    post :=
                      History s.history s.head.version
                      ∧ s.history.head? = some s.head
                      ∧ s.global ≤ s.head.version
                      ∧ (atCut s s.global).version = s.global
                  } :=
  ⟨
    fun _ _ _ ⟨h1, h2⟩ => Proofs.Trace.reachable_store_invariants_claim _ _ _ h1 h2,
    Proofs.Witnesses.reachable_store_invariants_witness
  ⟩

/-- The claim `reachable_store_data_invariants` of `Properties.lean`. -/
theorem reachable_store_data_invariants
    : witnessed% ∀ (w : World) (sid : Nat) (s : Store),
                  {
                    pre :=
                      Model.transitionSystem.Reachable w ∧ find w.stores sid = some s
                    post := Unique s.head.data ∧ CellsBounded s.head.data s.head.version
                  } :=
  ⟨
    fun _ _ _ ⟨h1, h2⟩ => Proofs.Trace.reachable_store_data_invariants_claim _ _ _ h1 h2,
    Proofs.Witnesses.reachable_store_data_invariants_witness
  ⟩

/-- The claim `step_capture_metadata` of `Properties.lean`. -/
theorem step_capture_metadata
    : witnessed% ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store)
                    (t : Tx),
                  {
                    pre :=
                      storeOf w sid = .ok s
                      ∧ Model.transitionSystem.step w
                          ⟨seq, .snapshot sid tid version global term⟩
                        = some next
                      ∧ find next.txs tid = some t
                    post :=
                      ∃ snap,
                        t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = term
                  } :=
  ⟨
    fun _ _ _ _ _ _ _ _ _ _ ⟨h1, h2, h3⟩ =>
      Proofs.Trace.step_capture_metadata_claim _ _ _ _ _ _ _ _ _ _ h1 h2 h3,
    Proofs.Witnesses.step_capture_metadata_witness
  ⟩

/-- The claim `step_capture_cut_values` of `Properties.lean`. -/
theorem step_capture_cut_values
    : witnessed% ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store),
                  {
                    pre :=
                      storeOf w sid = .ok s
                      ∧ Model.transitionSystem.step w
                          ⟨seq, .snapshot sid tid version global term⟩
                        = some next
                    post := version = s.head.version ∧ global = s.global
                  } :=
  ⟨
    fun _ _ _ _ _ _ _ _ _ ⟨h1, h2⟩ =>
      Proofs.Trace.step_capture_cut_values_claim _ _ _ _ _ _ _ _ _ h1 h2,
    Proofs.Witnesses.step_capture_cut_values_witness
  ⟩

/-- The claim `capture_replay_preserves_metadata` of `Properties.lean`. -/
theorem capture_replay_preserves_metadata
    : witnessed% ∀ (w capturedWorld final : World) (sid tid version global term seq : Nat)
                    (s : Store) (t : Tx) (tail : List Record),
                  {
                    pre :=
                      storeOf w sid = .ok s
                      ∧ Model.transitionSystem.step w
                          ⟨seq, .snapshot sid tid version global term⟩
                        = some capturedWorld
                      ∧ find capturedWorld.txs tid = some t
                      ∧ (∀ r ∈ tail, AttemptEvent tid r.event)
                      ∧ CCF.Execution.Run Model.transitionSystem capturedWorld tail final
                    post :=
                      ∃ after snap,
                        find final.txs tid = some after
                        ∧ after.snapshot = some snap
                        ∧ snap.current = s.head
                        ∧ snap.term = term
                    witness := tail ≠ []
                  } :=
  ⟨
    fun _ _ _ _ _ _ _ _ _ _ _ _ ⟨h1, h2, h3, h4, h5⟩ =>
      Proofs.Trace.capture_replay_preserves_metadata_claim _ _ _ _ _ _ _ _ _ _ _ _ h1 h2
        h3 h4 h5,
    Proofs.Witnesses.capture_replay_preserves_metadata_witness
  ⟩

/-- The claim `replay_snapshot_fixed` of `Properties.lean`. -/
theorem replay_snapshot_fixed
    : witnessed% ∀ (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot)
                    (rs : List Record),
                  {
                    pre :=
                      find w.txs tid = some before
                      ∧ before.snapshot = some snap
                      ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
                      ∧ CCF.Execution.Run Model.transitionSystem w rs final
                    post :=
                      ∃ after,
                        find final.txs tid = some after ∧ after.snapshot = some snap
                    witness := rs ≠ []
                  } :=
  ⟨
    fun _ _ _ _ _ _ ⟨h1, h2, h3, h4⟩ =>
      Proofs.Trace.replay_snapshot_fixed_claim _ _ _ _ _ _ h1 h2 h3 h4,
    Proofs.Witnesses.replay_snapshot_fixed_witness
  ⟩

/-- The claim `step_map_capture` of `Properties.lean`. -/
theorem step_map_capture
    : witnessed% ∀ (w next : World) (sid tid localVersion globalVersion seq : Nat)
                    (map : String) (s : Store) (before after : Tx) (snap : Snapshot),
                  {
                    pre :=
                      storeOf w sid = .ok s
                      ∧ txOf w sid tid = .ok before
                      ∧ before.snapshot = some snap
                      ∧ Model.transitionSystem.step w
                          ⟨seq, .acquire sid tid map localVersion globalVersion⟩
                        = some next
                      ∧ find next.txs tid = some after
                    post :=
                      find after.globalViews map = some (captureGlobal s snap map)
                      ∧ localVersion = (revision (captureLocal s snap map) map).version
                      ∧ globalVersion
                        = (revision (captureGlobal s snap map).frame map).version
                  } :=
  ⟨
    fun _ _ _ _ _ _ _ _ _ _ _ _ ⟨h1, h2, h3, h4, h5⟩ =>
      Proofs.Trace.step_map_capture_claim _ _ _ _ _ _ _ _ _ _ _ _ h1 h2 h3 h4 h5,
    Proofs.Witnesses.step_map_capture_witness
  ⟩

/-- The claim `replay_map_global_fixed` of `Properties.lean`. -/
theorem replay_map_global_fixed
    : witnessed% ∀ (w final : World) (tid : Nat) (before : Tx) (map : String)
                    (view : GlobalView) (rs : List Record),
                  {
                    pre :=
                      find w.txs tid = some before
                      ∧ find before.globalViews map = some view
                      ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
                      ∧ CCF.Execution.Run Model.transitionSystem w rs final
                    post :=
                      ∃ after,
                        find final.txs tid = some after
                        ∧ find after.globalViews map = some view
                    witness := rs ≠ []
                  } :=
  ⟨
    fun _ _ _ _ _ _ _ ⟨h1, h2, h3, h4⟩ =>
      Proofs.Trace.replay_map_global_fixed_claim _ _ _ _ _ _ _ h1 h2 h3 h4,
    Proofs.Witnesses.replay_map_global_fixed_witness
  ⟩

/-- The claim `replay_map_local_fixed` of `Properties.lean`. -/
theorem replay_map_local_fixed
    : witnessed% ∀ (w final : World) (tid : Nat) (before : Tx) (map : String)
                    (view : GlobalView) (rs : List Record),
                  {
                    pre :=
                      find w.txs tid = some before
                      ∧ find before.globalViews map = some view
                      ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
                      ∧ CCF.Execution.Run Model.transitionSystem w rs final
                    post :=
                      ∃ after,
                        find final.txs tid = some after
                        ∧ image after.data map = image before.data map
                    witness := rs ≠ []
                  } :=
  ⟨
    fun _ _ _ _ _ _ _ ⟨h1, h2, h3, h4⟩ =>
      Proofs.Trace.replay_map_local_fixed_claim _ _ _ _ _ _ _ h1 h2 h3 h4,
    Proofs.Witnesses.replay_map_global_fixed_witness
  ⟩

/-- The claim `capture_replay_preserves_map` of `Properties.lean`. -/
theorem capture_replay_preserves_map
    : witnessed% ∀ (w capturedWorld final : World)
                    (sid tid localVersion globalVersion seq : Nat) (map : String)
                    (s : Store) (before capturedTx : Tx) (snap : Snapshot)
                    (tail : List Record),
                  {
                    pre :=
                      storeOf w sid = .ok s
                      ∧ txOf w sid tid = .ok before
                      ∧ before.snapshot = some snap
                      ∧ Model.transitionSystem.step w
                          ⟨seq, .acquire sid tid map localVersion globalVersion⟩
                        = some capturedWorld
                      ∧ find capturedWorld.txs tid = some capturedTx
                      ∧ (∀ r ∈ tail, AttemptEvent tid r.event)
                      ∧ CCF.Execution.Run Model.transitionSystem capturedWorld tail final
                    post :=
                      ∃ after,
                        find final.txs tid = some after
                        ∧ find after.globalViews map = some (captureGlobal s snap map)
                        ∧ localVersion = (revision (captureLocal s snap map) map).version
                        ∧ globalVersion
                          = (revision (captureGlobal s snap map).frame map).version
                    witness := tail ≠ []
                  } :=
  ⟨
    fun _ _ _ _ _ _ _ _ _ _ _ _ _ _ ⟨h1, h2, h3, h4, h5, h6, h7⟩ =>
      Proofs.Trace.capture_replay_preserves_map_claim _ _ _ _ _ _ _ _ _ _ _ _ _ _ h1 h2 h3
        h4 h5 h6 h7,
    Proofs.Witnesses.capture_replay_preserves_map_witness
  ⟩

/-- The claim `captureGlobal_placeholder` of `Properties.lean`. -/
theorem captureGlobal_placeholder
    : witnessed% ∀ (s : Store) (snap : Snapshot) (map : String),
                  {
                    pre :=
                      find (captureLocal s snap map).births map = none
                    post := (captureGlobal s snap map).frame = {}
                  } :=
  ⟨
    Proofs.Trace.captureGlobal_placeholder,
    Proofs.Witnesses.captureGlobal_placeholder_witness
  ⟩

/-- The claim `captureGlobal_committed` of `Properties.lean`. -/
theorem captureGlobal_committed
    : witnessed% ∀ (s : Store) (snap : Snapshot) (map : String) (birth : Stamp),
                  {
                    pre :=
                      find (captureLocal s snap map).births map = some birth
                    post := (captureGlobal s snap map).frame = atCut s s.global
                  } :=
  ⟨Proofs.Trace.captureGlobal_committed, Proofs.Witnesses.captureGlobal_committed_witness⟩

/-- The claim `step_global_read_from_captured_map` of `Properties.lean`. -/
theorem step_global_read_from_captured_map
    : witnessed% ∀ (w next : World) (sid tid seq : Nat) (map key : String)
                    (value : Option String) (t : Tx) (view : GlobalView),
                  {
                    pre :=
                      Model.transitionSystem.Reachable w
                      ∧ txOf w sid tid = .ok t
                      ∧ find t.globalViews map = some view
                      ∧ Model.transitionSystem.step w
                          ⟨seq, .get sid tid map key value true⟩
                        = some next
                    post :=
                      value = (find view.frame.data (map, key)).map Cell.value
                      ∧ (view.frame = {}
                          ∨ ∃ origin : Store,
                              view.frame = atCut origin origin.global
                              ∧ view.frame.version = origin.global
                              ∧ CellsBounded view.frame.data origin.global)
                    witness := value.isSome = true
                  } :=
  ⟨
    fun _ _ _ _ _ _ _ _ _ _ ⟨h1, h2, h3, h4⟩ =>
      Proofs.Trace.step_global_read_from_captured_map_claim _ _ _ _ _ _ _ _ _ _ h1 h2 h3
        h4,
    let ⟨w, next, sid, tid, seq, map, key, value, t, view, h⟩ :=
      Proofs.Witnesses.step_global_read_from_captured_map_witness
    ⟨
      w,
      next,
      sid,
      tid,
      seq,
      map,
      key,
      some value,
      t,
      view,
      h.1,
      h.2.1,
      h.2.2.1,
      h.2.2.2,
      rfl
    ⟩
  ⟩

/-- The claim `step_global_has_from_captured_map` of `Properties.lean`. -/
theorem step_global_has_from_captured_map
    : witnessed% ∀ (w next : World) (sid tid seq : Nat) (map key : String) (value : Bool)
                    (t : Tx) (view : GlobalView),
                  {
                    pre :=
                      Model.transitionSystem.Reachable w
                      ∧ txOf w sid tid = .ok t
                      ∧ find t.globalViews map = some view
                      ∧ Model.transitionSystem.step w
                          ⟨seq, .has sid tid map key value true⟩
                        = some next
                    post :=
                      value = (find view.frame.data (map, key)).isSome
                      ∧ (view.frame = {}
                          ∨ ∃ origin : Store,
                              view.frame = atCut origin origin.global
                              ∧ view.frame.version = origin.global
                              ∧ CellsBounded view.frame.data origin.global)
                    witness := value = true
                  } :=
  ⟨
    fun _ _ _ _ _ _ _ _ _ _ ⟨h1, h2, h3, h4⟩ =>
      Proofs.Trace.step_global_has_from_captured_map_claim _ _ _ _ _ _ _ _ _ _ h1 h2 h3
        h4,
    let ⟨w, next, sid, tid, seq, map, key, t, view, h⟩ :=
      Proofs.Witnesses.step_global_has_from_captured_map_witness
    ⟨w, next, sid, tid, seq, map, key, true, t, view, h.1, h.2.1, h.2.2.1, h.2.2.2, rfl⟩
  ⟩

/-- The claim `compact_above_head_noop` of `Properties.lean`. -/
theorem compact_above_head_noop
    : witnessed% ∀ (s : Store) (v : Nat),
                  {
                    pre :=
                      s.head.version < v
                    post := compactStore s v = s
                  } :=
  ⟨Proofs.Model.compact_above_head_noop, Proofs.Witnesses.compact_above_head_noop_witness⟩

/-- The claim `rollback_keeps_prefix` of `Properties.lean`. -/
theorem rollback_keeps_prefix
    : witnessed% ∀ (s : Store) (v term : Nat) (f : Frame),
                  {
                    pre := f ∈ s.history ∧ f.version ≤ s.global
                    post := f ∈ (rollbackStore s v term).history
                    witness := f.data ≠ []
                  } :=
  ⟨
    fun _ _ _ _ ⟨h1, h2⟩ => Proofs.Model.rollback_keeps_prefix _ _ _ _ h1 h2,
    let ⟨s, f, h⟩ := Proofs.Witnesses.rollback_keeps_prefix_witness
    ⟨s, 0, 0, f, h⟩
  ⟩

/-- The claim `rollback_discards_suffix` of `Properties.lean`. -/
theorem rollback_discards_suffix
    : witnessed% ∀ (s : Store) (v term : Nat) (f : Frame),
                  {
                    pre := v < f.version ∧ s.global ≤ v
                    post := f ∉ (rollbackStore s v term).history
                    witness := f ∈ s.history
                  } :=
  ⟨
    fun _ _ _ _ ⟨h1, h2⟩ => Proofs.Model.rollback_discards_suffix _ _ _ _ h1 h2,
    let ⟨s, v, f, member, above, below⟩ :=
      Proofs.Witnesses.rollback_discards_suffix_witness
    ⟨s, v, 0, f, above, below, member⟩
  ⟩

/-- The claim `durable_cut_survives_rollback` of `Properties.lean`. -/
theorem durable_cut_survives_rollback
    : witnessed% ∀ (w : World) (sid : Nat) (s : Store) (v term cut : Nat),
                  {
                    pre :=
                      Model.transitionSystem.Reachable w
                      ∧ find w.stores sid = some s
                      ∧ cut ≤ s.global
                      ∧ s.global ≤ v
                    post := (atCut (rollbackStore s v term) cut).data = (atCut s cut).data
                    witness := (atCut s cut).data ≠ []
                  } :=
  ⟨
    fun _ _ _ _ _ _ ⟨h1, h2, h3, h4⟩ =>
      Proofs.Properties.durable_cut_survives_rollback _ _ _ _ _ _ h1 h2 h3 h4,
    let ⟨w, sid, s, v, cut, h⟩ := Proofs.Witnesses.durable_cut_survives_rollback_witness
    ⟨w, sid, s, v, 0, cut, h⟩
  ⟩

/-- The claim `stale_term_cannot_apply` of `Properties.lean`. -/
theorem stale_term_cannot_apply
    : witnessed% ∀ (s : Store) (t : Tx) (snap : Snapshot),
                  {
                    pre :=
                      t.snapshot = some snap ∧ s.term ≠ snap.term
                    post := canApply s t = false
                  } :=
  ⟨
    fun _ _ _ ⟨h1, h2⟩ => Proofs.Model.stale_term_cannot_apply _ _ _ h1 h2,
    Proofs.Witnesses.stale_term_cannot_apply_witness
  ⟩

/-- The claim `discarded_handle_cannot_apply` of `Properties.lean`. -/
theorem discarded_handle_cannot_apply
    : witnessed% ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String)
                    (view : GlobalView),
                  {
                    pre :=
                      t.snapshot = some snap
                      ∧ (m, view) ∈ t.globalViews
                      ∧ (∀ f ∈ s.history,
                          (revision f m == revision view.current m) = false)
                    post := canApply s t = false
                  } :=
  ⟨
    fun _ _ _ _ _ ⟨h1, h2, h3⟩ =>
      Proofs.Properties.discarded_handle_cannot_apply _ _ _ _ _ h1 h2 h3,
    Proofs.Witnesses.discarded_handle_cannot_apply_witness
  ⟩

/-- The claim `discarded_birth_cannot_apply` of `Properties.lean`. -/
theorem discarded_birth_cannot_apply
    : witnessed% ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String)
                    (view : GlobalView),
                  {
                    pre :=
                      t.snapshot = some snap
                      ∧ (m, view) ∈ t.globalViews
                      ∧ (∀ f ∈ s.history,
                          (find f.births m == find view.current.births m) = false)
                    post := canApply s t = false
                  } :=
  ⟨
    fun _ _ _ _ _ ⟨h1, h2, h3⟩ =>
      Proofs.Properties.discarded_birth_cannot_apply _ _ _ _ _ h1 h2 h3,
    Proofs.Witnesses.discarded_birth_cannot_apply_witness
  ⟩

/-- The claim `compacted_map_unavailable` of `Properties.lean`. -/
theorem compacted_map_unavailable
    : witnessed% ∀ (s : Store) (f : Frame) (m : String) (birth : Stamp),
                  {
                    pre :=
                      find f.births m = some birth
                      ∧ (revision f m).version < (revision (atCut s s.global) m).version
                    post := mapAvailable s f m = false
                  } :=
  ⟨
    fun _ _ _ _ ⟨h1, h2⟩ => Proofs.Model.compacted_map_unavailable _ _ _ _ h1 h2,
    Proofs.Witnesses.compacted_map_unavailable_witness
  ⟩

/-- The claim `absent_map_available` of `Properties.lean`. -/
theorem absent_map_available
    : witnessed% ∀ (s : Store) (f : Frame) (m : String),
                  {
                    pre :=
                      find f.births m = none
                      ∧ image f.data m = []
                      ∧ find f.revisions m = none
                    post := mapAvailable s f m = true
                  } :=
  ⟨
    fun _ _ _ ⟨h1, h2, h3⟩ => Proofs.Model.absent_map_available _ _ _ h1 h2 h3,
    let ⟨f, m, h⟩ := Proofs.Witnesses.absent_map_available_witness
    ⟨default, f, m, h⟩
  ⟩

/-- The claim `absent_placeholder_has_no_values` of `Properties.lean`. -/
theorem absent_placeholder_has_no_values
    : witnessed% ∀ (s : Store) (f : Frame) (m key : String),
                  {
                    pre := find f.births m = none ∧ mapAvailable s f m = true
                    post := find f.data (m, key) = none
                  } :=
  ⟨
    fun _ _ _ _ ⟨h1, h2⟩ => Proofs.Model.absent_placeholder_has_no_values _ _ _ _ h1 h2,
    let ⟨s, f, m, h⟩ := Proofs.Witnesses.absent_placeholder_has_no_values_witness
    ⟨s, f, m, "", h⟩
  ⟩

end Kv.Proofs.Claims
