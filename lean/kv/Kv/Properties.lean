-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Kv.Proofs.Model
import Kv.Proofs.Trace

/-!
# Human-reviewed KV properties

Review these statements with the definitions and assumptions in `Kv/Protocol/`.
Each theorem explicitly applies its checked implementation in `Kv.Proofs`.
Intermediate facts and proof steps stay in the proof modules.
-/

namespace Kv.Properties

section Generic
variable {M K V : Type} [DecidableEq M] [DecidableEq K]

/-! ## Reads and atomic publication -/

theorem read_your_write (db : DB M K V) (ws : Writes M K V) (a : Addr M K) (v : V) :
    valueAt db (set ws a (some v)) a = some v :=
  Proofs.Model.read_your_write db ws a v

theorem read_your_deletion (db : DB M K V) (ws : Writes M K V) (a : Addr M K) :
    valueAt db (set ws a none) a = none :=
  Proofs.Model.read_your_deletion db ws a

theorem absent_read (db : DB M K V) (ws : Writes M K V) (a : Addr M K)
    (hw : find ws a = none) (hd : find db a = none) :
    valueAt db ws a = none :=
  Proofs.Model.absent_read db ws a hw hd

theorem staged_noninterference (db : DB M K V) (ws : Writes M K V)
    (a b : Addr M K) (v : Option V) (h : a ≠ b) :
    valueAt db (set ws a v) b = valueAt db ws b :=
  Proofs.Model.staged_noninterference db ws a b v h

theorem previous_ignores_pending (db : DB M K V) (a : Addr M K) :
    previousAt db a = (find db a).map Cell.version :=
  Proofs.Model.previous_ignores_pending db a

theorem publish_lookup (db : DB M K V) (version : Nat) (ws : Writes M K V)
    (a : Addr M K) :
    find (publish db version ws) a =
      match find ws a with
      | none => find db a
      | some none => none
      | some (some v) => some { value := v, version } :=
  Proofs.Model.publish_lookup db version ws a

theorem publication_noninterference (db : DB M K V) (version : Nat)
    (ws : Writes M K V) (a : Addr M K) (h : find ws a = none) :
    find (publish db version ws) a = find db a :=
  Proofs.Model.publication_noninterference db version ws a h

theorem publish_unique (db : DB M K V) (version : Nat) (ws : Writes M K V)
    (h : Unique db) : Unique (publish db version ws) :=
  Proofs.Model.publish_unique db version ws h

variable [DecidableEq V]

theorem branch_normal_serializability (db final : DB M K V)
    (programs : List (AppliedProgram M K V))
    (h : BranchExecution db programs final) :
    serialBranch db programs = some final :=
  Proofs.Model.branch_normal_serializability db final programs h

end Generic

theorem apply_atomic (s : Store) (writes : Pending) :
    (advance s writes).head.data = publish s.head.data (s.head.version + 1) writes :=
  Proofs.Model.apply_atomic s writes

/-! ## Snapshot witnesses and normal-view serializability -/

theorem transaction_snapshot_witness (t : Tx) (snap : Snapshot)
    (hs : t.snapshot = some snap) :
    serialRun snap.current.data [] t.normal.log = some t.normal.writes :=
  Proofs.Model.transaction_snapshot_witness t snap hs

theorem transaction_application_serial_witness (s : Store) (t : Tx) (snap : Snapshot)
    (hs : t.snapshot = some snap) (hv : canApply s t = true) :
    serialRun s.head.data [] t.normal.log = some t.normal.writes :=
  Proofs.Model.transaction_application_serial_witness s t snap hs hv

theorem executable_branch_serializability (s final : Store) (ts : List Tx)
    (h : AppliedBranch s ts final) :
    serialTransactions s.head.data s.head.version ts = some final.head.data :=
  Proofs.Model.executable_branch_serializability s final ts h

theorem replay_segment_serializability (w final : World) (sid : Nat) (s : Store)
    (rs : List Record) (live : find w.stores sid = some s)
    (segment : ∀ r ∈ rs, SegmentEvent sid r.event)
    (accepted : replay w rs = .ok final) :
    ∃ after txs, find final.stores sid = some after ∧
      projectApplications w sid rs = .ok txs ∧
      serialTransactions s.head.data s.head.version txs = some after.head.data ∧
      after.head.version = s.head.version + txs.length :=
  Proofs.Trace.replay_segment_serializability w final sid s rs live segment accepted

/-! ## Reachable store invariants -/

theorem reachable_store_invariants (w : World) (reachable : Reachable w)
    (sid : Nat) (s : Store) (live : find w.stores sid = some s) :
    History s.history s.head.version ∧ s.history.head? = some s.head ∧
      s.global ≤ s.head.version ∧ (atCut s s.global).version = s.global :=
  Proofs.Trace.reachable_store_invariants w reachable sid s live

theorem reachable_store_data_invariants (w : World) (reachable : Reachable w)
    (sid : Nat) (s : Store) (live : find w.stores sid = some s) :
    Unique s.head.data ∧ CellsBounded s.head.data s.head.version :=
  Proofs.Trace.reachable_store_data_invariants w reachable sid s live

/-! ## Current snapshot capture and preservation -/

theorem step_capture_metadata (w next : World) (sid tid version global term seq : Nat)
    (s : Store) (t : Tx) (source : storeOf w sid = .ok s)
    (accepted : step w ⟨seq, .snapshot sid tid version global term⟩ = .ok next)
    (capturedTx : find next.txs tid = some t) :
    ∃ snap, t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = term :=
  Proofs.Trace.step_capture_metadata w next sid tid version global term seq s t
    source accepted capturedTx

theorem step_capture_cut_values (w next : World) (sid tid version global term seq : Nat)
    (s : Store) (source : storeOf w sid = .ok s)
    (accepted : step w ⟨seq, .snapshot sid tid version global term⟩ = .ok next) :
    version = s.head.version ∧ global = s.global :=
  Proofs.Trace.step_capture_cut_values w next sid tid version global term seq s source accepted

theorem capture_replay_preserves_metadata (w capturedWorld final : World)
    (sid tid version global term seq : Nat) (s : Store) (t : Tx) (tail : List Record)
    (source : storeOf w sid = .ok s)
    (capture : step w ⟨seq, .snapshot sid tid version global term⟩ = .ok capturedWorld)
    (live : find capturedWorld.txs tid = some t)
    (segment : ∀ r ∈ tail, AttemptEvent tid r.event)
    (accepted : replay capturedWorld tail = .ok final) :
    ∃ after snap, find final.txs tid = some after ∧ after.snapshot = some snap ∧
      snap.current = s.head ∧ snap.term = term :=
  Proofs.Trace.capture_replay_preserves_metadata w capturedWorld final
    sid tid version global term seq s t tail source capture live segment accepted

theorem replay_snapshot_fixed (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot)
    (rs : List Record) (live : find w.txs tid = some before)
    (captured : before.snapshot = some snap)
    (segment : ∀ r ∈ rs, AttemptEvent tid r.event)
    (accepted : replay w rs = .ok final) :
    ∃ after, find final.txs tid = some after ∧ after.snapshot = some snap :=
  Proofs.Trace.replay_snapshot_fixed w final tid before snap rs live captured segment accepted

/-! ## Per-map globally committed views -/

theorem step_map_capture (w next : World) (sid tid localVersion globalVersion seq : Nat)
    (map : String) (s : Store) (before after : Tx) (snap : Snapshot)
    (store : storeOf w sid = .ok s) (tx : txOf w sid tid = .ok before)
    (snapshot : before.snapshot = some snap)
    (accepted : step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩ = .ok next)
    (live : find next.txs tid = some after) :
    find after.globalViews map = some (captureGlobal s snap map) ∧
      localVersion = (revision snap.current map).version ∧
      globalVersion = (revision (captureGlobal s snap map).frame map).version :=
  Proofs.Trace.step_map_capture w next sid tid localVersion globalVersion seq
    map s before after snap store tx snapshot accepted live

theorem replay_map_global_fixed (w final : World) (tid : Nat) (before : Tx)
    (map : String) (view : GlobalView) (rs : List Record)
    (live : find w.txs tid = some before) (captured : find before.globalViews map = some view)
    (segment : ∀ r ∈ rs, AttemptEvent tid r.event)
    (accepted : replay w rs = .ok final) :
    ∃ after, find final.txs tid = some after ∧ find after.globalViews map = some view :=
  Proofs.Trace.replay_map_global_fixed w final tid before map view rs live captured segment accepted

theorem capture_replay_preserves_map (w capturedWorld final : World)
    (sid tid localVersion globalVersion seq : Nat) (map : String)
    (s : Store) (before capturedTx : Tx) (snap : Snapshot) (tail : List Record)
    (store : storeOf w sid = .ok s) (tx : txOf w sid tid = .ok before)
    (snapshot : before.snapshot = some snap)
    (capture : step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩ = .ok capturedWorld)
    (live : find capturedWorld.txs tid = some capturedTx)
    (segment : ∀ r ∈ tail, AttemptEvent tid r.event)
    (accepted : replay capturedWorld tail = .ok final) :
    ∃ after, find final.txs tid = some after ∧
      find after.globalViews map = some (captureGlobal s snap map) ∧
      localVersion = (revision snap.current map).version ∧
      globalVersion = (revision (captureGlobal s snap map).frame map).version :=
  Proofs.Trace.capture_replay_preserves_map w capturedWorld final
    sid tid localVersion globalVersion seq map s before capturedTx snap tail
    store tx snapshot capture live segment accepted

theorem captureGlobal_placeholder (s : Store) (snap : Snapshot) (map : String)
    (absent : find snap.current.births map = none) :
    (captureGlobal s snap map).frame = {} :=
  Proofs.Trace.captureGlobal_placeholder s snap map absent

theorem captureGlobal_committed (s : Store) (snap : Snapshot) (map : String) (birth : Stamp)
    (existing : find snap.current.births map = some birth) :
    (captureGlobal s snap map).frame = atCut s s.global :=
  Proofs.Trace.captureGlobal_committed s snap map birth existing

theorem step_global_read_from_captured_map (w next : World) (sid tid seq : Nat)
    (map key : String) (value : Option String) (t : Tx) (view : GlobalView)
    (source : txOf w sid tid = .ok t) (captured : find t.globalViews map = some view)
    (accepted : step w ⟨seq, .get sid tid map key value true⟩ = .ok next) :
    value = (find view.frame.data (map, key)).map Cell.value ∧
      (view.frame = {} ∨ ∃ origin : Store, view.frame = atCut origin origin.global ∧
        view.frame.version = origin.global ∧ CellsBounded view.frame.data origin.global) :=
  Proofs.Trace.step_global_read_from_captured_map w next sid tid seq
    map key value t view source captured accepted

theorem step_global_has_from_captured_map (w next : World) (sid tid seq : Nat)
    (map key : String) (value : Bool) (t : Tx) (view : GlobalView)
    (source : txOf w sid tid = .ok t) (captured : find t.globalViews map = some view)
    (accepted : step w ⟨seq, .has sid tid map key value true⟩ = .ok next) :
    value = (find view.frame.data (map, key)).isSome ∧
      (view.frame = {} ∨ ∃ origin : Store, view.frame = atCut origin origin.global ∧
        view.frame.version = origin.global ∧ CellsBounded view.frame.data origin.global) :=
  Proofs.Trace.step_global_has_from_captured_map w next sid tid seq
    map key value t view source captured accepted

/-! ## Compaction, rollback, and invalidated attempts -/

theorem compact_above_head_noop (s : Store) (v : Nat) (h : s.head.version < v) :
    compactStore s v = s :=
  Proofs.Model.compact_above_head_noop s v h

theorem rollback_keeps_prefix (s : Store) (v term : Nat) (f : Frame)
    (h : f ∈ s.history) (hv : f.version ≤ s.global) :
    f ∈ (rollbackStore s v term).history :=
  Proofs.Model.rollback_keeps_prefix s v term f h hv

theorem rollback_discards_suffix (s : Store) (v term : Nat) (f : Frame)
    (h : v < f.version) (boundary : s.global ≤ v) :
    f ∉ (rollbackStore s v term).history :=
  Proofs.Model.rollback_discards_suffix s v term f h boundary

theorem durable_cut_survives_rollback (s : Store) (v term cut : Nat)
    (hcut : cut ≤ s.global) (hboundary : s.global ≤ v) :
    (atCut (rollbackStore s v term) cut).data = (atCut s cut).data :=
  Proofs.Model.durable_cut_survives_rollback s v term cut hcut hboundary

theorem stale_term_cannot_apply (s : Store) (t : Tx) (snap : Snapshot)
    (hs : t.snapshot = some snap) (ht : s.term ≠ snap.term) :
    canApply s t = false :=
  Proofs.Model.stale_term_cannot_apply s t snap hs ht

theorem discarded_handle_cannot_apply (s : Store) (t : Tx) (snap : Snapshot)
    (hs : t.snapshot = some snap) (m : String) (view : GlobalView) (hm : (m, view) ∈ t.globalViews)
    (gone : ∀ f ∈ s.history, (revision f m == revision snap.current m) = false) :
    canApply s t = false :=
  Proofs.Model.discarded_handle_cannot_apply s t snap hs m view hm gone

theorem discarded_birth_cannot_apply (s : Store) (t : Tx) (snap : Snapshot)
    (hs : t.snapshot = some snap) (m : String) (view : GlobalView) (hm : (m, view) ∈ t.globalViews)
    (gone : ∀ f ∈ s.history, (find f.births m == find snap.current.births m) = false) :
    canApply s t = false :=
  Proofs.Model.discarded_birth_cannot_apply s t snap hs m view hm gone

theorem compacted_map_unavailable (s : Store) (f : Frame) (m : String)
    (birth : Stamp) (existing : find f.births m = some birth)
    (h : (revision f m).version < (revision (atCut s s.global) m).version) :
    mapAvailable s f m = false :=
  Proofs.Model.compacted_map_unavailable s f m birth existing h

theorem absent_map_available (s : Store) (f : Frame) (m : String)
    (absent : find f.births m = none) (empty : image f.data m = [])
    (unwritten : find f.revisions m = none) :
    mapAvailable s f m = true :=
  Proofs.Model.absent_map_available s f m absent empty unwritten

theorem absent_placeholder_has_no_values (s : Store) (f : Frame) (m key : String)
    (absent : find f.births m = none) (permitted : mapAvailable s f m = true) :
    find f.data (m, key) = none :=
  Proofs.Model.absent_placeholder_has_no_values s f m key absent permitted

end Kv.Properties
