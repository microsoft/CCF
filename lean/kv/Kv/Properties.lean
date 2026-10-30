-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Invariants

import Kv.Proofs.Properties
import Kv.Proofs.Witnesses

@[expose] public section

/-!
# Human-reviewed KV properties

Review these statements with the definitions in `Kv/Model/`, `Kv/Model.lean`, and
`Kv/Properties/`. Each theorem links to its implementation in `Kv/Proofs/`.
Each claim with premises has an adjacent witness that its premises can hold.
-/

namespace Kv.Properties

open Kv.Model

/-! ## Reads and atomic publication -/

/-- A staged put is visible to the transaction that staged it. -/
theorem read_your_write
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
        (a : Addr M K) (v : V),
        valueAt db (set ws a (some v)) a = some v := by
  exact Proofs.Model.read_your_write

/-- A staged removal is visible to the transaction that staged it. -/
theorem read_your_deletion
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
        (a : Addr M K),
        valueAt db (set ws a none) a = none := by
  exact Proofs.Model.read_your_deletion

/-- A key neither staged nor committed reads as absent. -/
theorem absent_read
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
        (a : Addr M K),
        find ws a = none → find db a = none → valueAt db ws a = none := by
  exact Proofs.Model.absent_read

/-- Witness: a key can be neither staged nor committed. -/
theorem absent_read_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        find ws a = none ∧ find db a = none := by
  exact Proofs.Witnesses.absent_read_witness

/-- Staging a write at one address does not change reads at another. -/
theorem staged_noninterference
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
        (a b : Addr M K) (v : Option V),
        a ≠ b → valueAt db (set ws a v) b = valueAt db ws b := by
  exact Proofs.Model.staged_noninterference

/-- Witness: two addresses can differ. -/
theorem staged_noninterference_witness : ∃ a b : Addr String String, a ≠ b := by
  exact Proofs.Witnesses.staged_noninterference_witness

/-- Reading the committed version ignores staged writes. -/
theorem previous_ignores_pending
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (a : Addr M K),
        previousAt db a = (find db a).map Cell.version := by
  exact Proofs.Model.previous_ignores_pending

/-- Publishing replaces each written cell, stamped with the new version, and keeps the rest. -/
theorem publish_lookup
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (version : Nat)
        (ws : Writes M K V) (a : Addr M K),
        find (publish db version ws) a
        = match find ws a with
          | none => find db a
          | some none => none
          | some (some v) => some { value := v, version } := by
  exact Proofs.Model.publish_lookup

/-- Publishing leaves unwritten addresses unchanged. -/
theorem publication_noninterference
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (version : Nat)
        (ws : Writes M K V) (a : Addr M K),
        find ws a = none → find (publish db version ws) a = find db a := by
  exact Proofs.Model.publication_noninterference

/-- Witness: an address can be unwritten. -/
theorem publication_noninterference_witness
    : ∃ (ws : Writes String String String) (a : Addr String String),
        find ws a = none := by
  exact Proofs.Witnesses.publication_noninterference_witness

/-- Publishing preserves key uniqueness. -/
theorem publish_unique
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (version : Nat)
        (ws : Writes M K V),
        Unique db → Unique (publish db version ws) := by
  exact Proofs.Model.publish_unique

/-- Witness: a database can have unique keys. -/
theorem publish_unique_witness : ∃ db : DB String String String, Unique db := by
  exact Proofs.Witnesses.publish_unique_witness

/-- Applying an attempt publishes its entire write set at the next version. -/
theorem apply_atomic
    : ∀ (s : Store) (writes : Pending),
        (advance s writes).head.data
        = publish s.head.data (s.head.version + 1) writes := by
  exact Proofs.Model.apply_atomic

/-! ## Serial snapshot runs and normal-view serializability -/

/-- An attempt's operation log runs serially on its captured snapshot to its staged writes. -/
theorem transaction_snapshot_serial
    : ∀ (t : Tx) (snap : Snapshot),
        t.snapshot = some snap
        → serialRun snap.current.data [] t.normal.log = some t.normal.writes := by
  exact Proofs.Model.transaction_snapshot_serial

/-- Witness: an attempt with a snapshot can have a nonempty log. -/
theorem transaction_snapshot_serial_witness
    : ∃ (t : Tx) (snap : Snapshot), t.snapshot = some snap ∧ t.normal.log ≠ [] := by
  exact Proofs.Witnesses.transaction_snapshot_serial_witness

/-- An attempt that may apply runs serially on the current head to the same staged writes. -/
theorem transaction_application_serial
    : ∀ (s : Store) (t : Tx) (snap : Snapshot),
        t.snapshot = some snap
        → canApply s t = true
        → serialRun s.head.data [] t.normal.log = some t.normal.writes := by
  exact Proofs.Model.transaction_application_serial

/-- Witness: an attempt with a nonempty log can apply. -/
theorem transaction_application_serial_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot),
        t.snapshot = some snap ∧ canApply s t = true ∧ t.normal.log ≠ [] := by
  exact Proofs.Witnesses.transaction_application_serial_witness

/-- A branch of applied attempts matches running their logs serially from the start. -/
theorem executable_branch_serializability
    : ∀ (s final : Store) (ts : List Tx),
        AppliedBranch s ts final
        → serialTransactions s.head.data s.head.version ts = some final.head.data := by
  exact Proofs.Model.executable_branch_serializability

/-- Witness: a nonempty branch of applied attempts exists. -/
theorem executable_branch_serializability_witness
    : ∃ (s final : Store) (ts : List Tx), AppliedBranch s ts final ∧ ts ≠ [] := by
  exact Proofs.Witnesses.executable_branch_serializability_witness

/-- In an accepted record segment that keeps store `sid` alive, the applications projected
onto that store run serially to its final head. -/
theorem replay_segment_serializability
    : ∀ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
        find w.stores sid = some s
        → (∀ r ∈ rs, SegmentEvent sid r.event)
        → CCF.Execution.Run Model.transitionSystem w rs final
        → ∃ after txs,
            find final.stores sid = some after
            ∧ projectApplications w sid rs = .ok txs
            ∧ serialTransactions s.head.data s.head.version txs = some after.head.data
            ∧ after.head.version = s.head.version + txs.length := by
  exact Proofs.Properties.replay_segment_serializability

/-- Witness: an accepted nonempty segment can keep a store alive. -/
theorem replay_segment_serializability_witness
    : ∃ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
        find w.stores sid = some s
        ∧ (∀ r ∈ rs, SegmentEvent sid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem w rs final
        ∧ rs ≠ [] := by
  exact Proofs.Witnesses.replay_segment_serializability_witness

/-! ## Reachable store invariants -/

/-- Every live store in a reachable world has a well-formed history whose head is newest, and a
global version within it that is the version of its global cut. -/
theorem reachable_store_invariants
    : ∀ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → History s.history s.head.version
          ∧ s.history.head? = some s.head
          ∧ s.global ≤ s.head.version
          ∧ (atCut s s.global).version = s.global := by
  exact Proofs.Properties.reachable_store_invariants

/-- Witness: a reachable world can have a live store. -/
theorem reachable_store_invariants_witness
    : ∃ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s := by
  exact Proofs.Witnesses.reachable_store_invariants_witness

/-- Every live store's head data in a reachable world has unique keys and versions no later than
the head. -/
theorem reachable_store_data_invariants
    : ∀ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → Unique s.head.data ∧ CellsBounded s.head.data s.head.version := by
  exact Proofs.Properties.reachable_store_data_invariants

/-- Witness: a reachable world can have a live store. -/
theorem reachable_store_data_invariants_witness
    : ∃ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s := by
  exact Proofs.Witnesses.reachable_store_data_invariants_witness

/-! ## Current snapshot capture and preservation -/

/-- Capturing a snapshot records the store's head and the reported term. -/
theorem step_capture_metadata
    : ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store) (t : Tx),
        storeOf w sid = .ok s
        → Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next
        → find next.txs tid = some t
        → ∃ snap, t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = term := by
  exact Proofs.Properties.step_capture_metadata

/-- Witness: a snapshot capture can be accepted. -/
theorem step_capture_metadata_witness
    : ∃ (w next : World) (sid tid version global term seq : Nat) (s : Store) (t : Tx),
        storeOf w sid = .ok s
        ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next
        ∧ find next.txs tid = some t := by
  exact Proofs.Witnesses.step_capture_metadata_witness

/-- An accepted snapshot capture reports the store's head and global versions. -/
theorem step_capture_cut_values
    : ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store),
        storeOf w sid = .ok s
        → Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next
        → version = s.head.version ∧ global = s.global := by
  exact Proofs.Properties.step_capture_cut_values

/-- Witness: a snapshot capture can be accepted. -/
theorem step_capture_cut_values_witness
    : ∃ (w next : World) (sid tid version global term seq : Nat) (s : Store),
        storeOf w sid = .ok s
        ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next := by
  exact Proofs.Witnesses.step_capture_cut_values_witness

/-- A captured snapshot's head and term are unchanged by later records that do not end the
attempt. -/
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
  exact Proofs.Properties.capture_replay_preserves_metadata

/-- Witness: a snapshot capture can be followed by an accepted nonempty run that keeps the attempt. -/
theorem capture_replay_preserves_metadata_witness
    : ∃ (w capturedWorld final : World) (sid tid version global term seq : Nat)
        (s : Store) (t : Tx) (tail : List Record),
        storeOf w sid = .ok s
        ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some capturedWorld
        ∧ find capturedWorld.txs tid = some t
        ∧ (∀ r ∈ tail, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem capturedWorld tail final
        ∧ tail ≠ [] := by
  exact Proofs.Witnesses.capture_replay_preserves_metadata_witness

/-- An attempt's captured snapshot is unchanged by later records that do not end it. -/
theorem replay_snapshot_fixed
    : ∀ (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot) (rs : List Record),
        find w.txs tid = some before
        → before.snapshot = some snap
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run Model.transitionSystem w rs final
        → ∃ after, find final.txs tid = some after ∧ after.snapshot = some snap := by
  exact Proofs.Properties.replay_snapshot_fixed

/-- Witness: an attempt with a snapshot can be followed by an accepted nonempty run that keeps it. -/
theorem replay_snapshot_fixed_witness
    : ∃ (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot) (rs : List Record),
        find w.txs tid = some before
        ∧ before.snapshot = some snap
        ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem w rs final
        ∧ rs ≠ [] := by
  exact Proofs.Witnesses.replay_snapshot_fixed_witness

/-! ## Per-map globally committed views -/

/-- Acquiring a map records its global view and checks the reported revision versions. -/
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
          ∧ localVersion = (revision snap.current map).version
          ∧ globalVersion = (revision (captureGlobal s snap map).frame map).version := by
  exact Proofs.Properties.step_map_capture

/-- Witness: a map acquisition can be accepted. -/
theorem step_map_capture_witness
    : ∃ (w next : World) (sid tid localVersion globalVersion seq : Nat) (map : String)
        (s : Store) (before after : Tx) (snap : Snapshot),
        storeOf w sid = .ok s
        ∧ txOf w sid tid = .ok before
        ∧ before.snapshot = some snap
        ∧ Model.transitionSystem.step w
            ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some next
        ∧ find next.txs tid = some after := by
  exact Proofs.Witnesses.step_map_capture_witness

/-- A map's captured global view is unchanged by later records that do not end the attempt. -/
theorem replay_map_global_fixed
    : ∀ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        → find before.globalViews map = some view
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run Model.transitionSystem w rs final
        → ∃ after,
            find final.txs tid = some after ∧ find after.globalViews map = some view := by
  exact Proofs.Properties.replay_map_global_fixed

/-- Witness: an attempt with an acquired map can be followed by an accepted nonempty run that keeps it. -/
theorem replay_map_global_fixed_witness
    : ∃ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        ∧ find before.globalViews map = some view
        ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem w rs final
        ∧ rs ≠ [] := by
  exact Proofs.Witnesses.replay_map_global_fixed_witness

/-- A map acquisition's global view and reported versions persist through later records that do
not end the attempt. -/
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
            ∧ localVersion = (revision snap.current map).version
            ∧ globalVersion
              = (revision (captureGlobal s snap map).frame map).version := by
  exact Proofs.Properties.capture_replay_preserves_map

/-- Witness: a map acquisition can be followed by an accepted nonempty run that keeps the attempt. -/
theorem capture_replay_preserves_map_witness
    : ∃ (w capturedWorld final : World) (sid tid localVersion globalVersion seq : Nat)
        (map : String) (s : Store) (before capturedTx : Tx) (snap : Snapshot)
        (tail : List Record),
        storeOf w sid = .ok s
        ∧ txOf w sid tid = .ok before
        ∧ before.snapshot = some snap
        ∧ Model.transitionSystem.step w
            ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some capturedWorld
        ∧ find capturedWorld.txs tid = some capturedTx
        ∧ (∀ r ∈ tail, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem capturedWorld tail final
        ∧ tail ≠ [] := by
  exact Proofs.Witnesses.capture_replay_preserves_map_witness

/-- The global view of a map not yet created is the empty frame. -/
theorem captureGlobal_placeholder
    : ∀ (s : Store) (snap : Snapshot) (map : String),
        find snap.current.births map = none → (captureGlobal s snap map).frame = {} := by
  exact Proofs.Trace.captureGlobal_placeholder

/-- Witness: a snapshot can lack a map. -/
theorem captureGlobal_placeholder_witness
    : ∃ (snap : Snapshot) (map : String), find snap.current.births map = none := by
  exact Proofs.Witnesses.captureGlobal_placeholder_witness

/-- The global view of an existing map is the store's global cut. -/
theorem captureGlobal_committed
    : ∀ (s : Store) (snap : Snapshot) (map : String) (birth : Stamp),
        find snap.current.births map = some birth
        → (captureGlobal s snap map).frame = atCut s s.global := by
  exact Proofs.Trace.captureGlobal_committed

/-- Witness: a snapshot can contain a map. -/
theorem captureGlobal_committed_witness
    : ∃ (snap : Snapshot) (map : String) (birth : Stamp),
        find snap.current.births map = some birth := by
  exact Proofs.Witnesses.captureGlobal_committed_witness

/-- A global read returns the captured view's value, and that view is empty or a store's global
cut with no cell newer than it. -/
theorem step_global_read_from_captured_map
    : ∀ (w next : World) (sid tid seq : Nat) (map key : String) (value : Option String)
        (t : Tx) (view : GlobalView),
        txOf w sid tid = .ok t
        → find t.globalViews map = some view
        → Model.transitionSystem.step w ⟨seq, .get sid tid map key value true⟩ = some next
        → value = (find view.frame.data (map, key)).map Cell.value
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  exact Proofs.Properties.step_global_read_from_captured_map

/-- Witness: a global read of a committed value can be accepted. -/
theorem step_global_read_from_captured_map_witness
    : ∃ (w next : World) (sid tid seq : Nat) (map key value : String) (t : Tx)
        (view : GlobalView),
        txOf w sid tid = .ok t
        ∧ find t.globalViews map = some view
        ∧ Model.transitionSystem.step w ⟨seq, .get sid tid map key (some value) true⟩
          = some next := by
  exact Proofs.Witnesses.step_global_read_from_captured_map_witness

/-- A global presence test reflects the captured view, and that view is empty or a store's
global cut with no cell newer than it. -/
theorem step_global_has_from_captured_map
    : ∀ (w next : World) (sid tid seq : Nat) (map key : String) (value : Bool) (t : Tx)
        (view : GlobalView),
        txOf w sid tid = .ok t
        → find t.globalViews map = some view
        → Model.transitionSystem.step w ⟨seq, .has sid tid map key value true⟩ = some next
        → value = (find view.frame.data (map, key)).isSome
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  exact Proofs.Properties.step_global_has_from_captured_map

/-- Witness: a global presence test of a committed key can be accepted. -/
theorem step_global_has_from_captured_map_witness
    : ∃ (w next : World) (sid tid seq : Nat) (map key : String) (t : Tx)
        (view : GlobalView),
        txOf w sid tid = .ok t
        ∧ find t.globalViews map = some view
        ∧ Model.transitionSystem.step w ⟨seq, .has sid tid map key true true⟩
          = some next := by
  exact Proofs.Witnesses.step_global_has_from_captured_map_witness

/-! ## Compaction, rollback, and invalidated attempts -/

/-- Compacting beyond the head leaves the store unchanged. -/
theorem compact_above_head_noop
    : ∀ (s : Store) (v : Nat), s.head.version < v → compactStore s v = s := by
  exact Proofs.Model.compact_above_head_noop

/-- Witness: a version can be beyond the head. -/
theorem compact_above_head_noop_witness
    : ∃ (s : Store) (v : Nat), s.head.version < v := by
  exact Proofs.Witnesses.compact_above_head_noop_witness

/-- Rollback keeps every frame at or below the global version. -/
theorem rollback_keeps_prefix
    : ∀ (s : Store) (v term : Nat) (f : Frame),
        f ∈ s.history → f.version ≤ s.global → f ∈ (rollbackStore s v term).history := by
  exact Proofs.Model.rollback_keeps_prefix

/-- Witness: a nonempty frame can be on the branch at or below the global version. -/
theorem rollback_keeps_prefix_witness
    : ∃ (s : Store) (f : Frame), f ∈ s.history ∧ f.version ≤ s.global ∧ f.data ≠ [] := by
  exact Proofs.Witnesses.rollback_keeps_prefix_witness

/-- Rollback discards every frame above the requested version. -/
theorem rollback_discards_suffix
    : ∀ (s : Store) (v term : Nat) (f : Frame),
        v < f.version → s.global ≤ v → f ∉ (rollbackStore s v term).history := by
  exact Proofs.Model.rollback_discards_suffix

/-- Witness: a frame on the branch can be above a version at or above the global version. -/
theorem rollback_discards_suffix_witness
    : ∃ (s : Store) (v : Nat) (f : Frame),
        f ∈ s.history ∧ v < f.version ∧ s.global ≤ v := by
  exact Proofs.Witnesses.rollback_discards_suffix_witness

/-- Rollback preserves the data at every cut at or below the global version. -/
theorem durable_cut_survives_rollback
    : ∀ (s : Store) (v term cut : Nat),
        cut ≤ s.global
        → s.global ≤ v
        → (atCut (rollbackStore s v term) cut).data = (atCut s cut).data := by
  exact Proofs.Model.durable_cut_survives_rollback

/-- Witness: a nonempty cut can be at or below the global version. -/
theorem durable_cut_survives_rollback_witness
    : ∃ (s : Store) (v cut : Nat),
        cut ≤ s.global ∧ s.global ≤ v ∧ (atCut s cut).data ≠ [] := by
  exact Proofs.Witnesses.durable_cut_survives_rollback_witness

/-- An attempt whose snapshot term differs from the store's cannot apply. -/
theorem stale_term_cannot_apply
    : ∀ (s : Store) (t : Tx) (snap : Snapshot),
        t.snapshot = some snap → s.term ≠ snap.term → canApply s t = false := by
  exact Proofs.Model.stale_term_cannot_apply

/-- Witness: an attempt's snapshot term can differ from the store's. -/
theorem stale_term_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot),
        t.snapshot = some snap ∧ s.term ≠ snap.term := by
  exact Proofs.Witnesses.stale_term_cannot_apply_witness

/-- An attempt whose acquired map revision is no longer on the branch cannot apply. -/
theorem discarded_handle_cannot_apply
    : ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        → (m, view) ∈ t.globalViews
        → (∀ f ∈ s.history, (revision f m == revision snap.current m) = false)
        → canApply s t = false := by
  exact Proofs.Properties.discarded_handle_cannot_apply

/-- Witness: an attempt can hold a map whose revision is no longer on the branch. -/
theorem discarded_handle_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (revision f m == revision snap.current m) = false) := by
  exact Proofs.Witnesses.discarded_handle_cannot_apply_witness

/-- An attempt whose acquired map creation is no longer on the branch cannot apply. -/
theorem discarded_birth_cannot_apply
    : ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        → (m, view) ∈ t.globalViews
        → (∀ f ∈ s.history, (find f.births m == find snap.current.births m) = false)
        → canApply s t = false := by
  exact Proofs.Properties.discarded_birth_cannot_apply

/-- Witness: an attempt can hold a map whose creation is no longer on the branch. -/
theorem discarded_birth_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (find f.births m == find snap.current.births m) = false) := by
  exact Proofs.Witnesses.discarded_birth_cannot_apply_witness

/-- A map revised before the global cut's revision is unavailable. -/
theorem compacted_map_unavailable
    : ∀ (s : Store) (f : Frame) (m : String) (birth : Stamp),
        find f.births m = some birth
        → (revision f m).version < (revision (atCut s s.global) m).version
        → mapAvailable s f m = false := by
  exact Proofs.Model.compacted_map_unavailable

/-- Witness: a map can be revised before the global cut's revision. -/
theorem compacted_map_unavailable_witness
    : ∃ (s : Store) (f : Frame) (m : String) (birth : Stamp),
        find f.births m = some birth
        ∧ (revision f m).version < (revision (atCut s s.global) m).version := by
  exact Proofs.Witnesses.compacted_map_unavailable_witness

/-- A map that does not exist, has no data, and was never revised is available. -/
theorem absent_map_available
    : ∀ (s : Store) (f : Frame) (m : String),
        find f.births m = none
        → image f.data m = []
        → find f.revisions m = none
        → mapAvailable s f m = true := by
  exact Proofs.Model.absent_map_available

/-- Witness: a map can be absent, empty, and unrevised. -/
theorem absent_map_available_witness
    : ∃ (f : Frame) (m : String),
        find f.births m = none ∧ image f.data m = [] ∧ find f.revisions m = none := by
  exact Proofs.Witnesses.absent_map_available_witness

/-- An available map that does not exist has no values. -/
theorem absent_placeholder_has_no_values
    : ∀ (s : Store) (f : Frame) (m key : String),
        find f.births m = none
        → mapAvailable s f m = true
        → find f.data (m, key) = none := by
  exact Proofs.Model.absent_placeholder_has_no_values

/-- Witness: an absent map can be available. -/
theorem absent_placeholder_has_no_values_witness
    : ∃ (s : Store) (f : Frame) (m : String),
        find f.births m = none ∧ mapAvailable s f m = true := by
  exact Proofs.Witnesses.absent_placeholder_has_no_values_witness

end Kv.Properties
