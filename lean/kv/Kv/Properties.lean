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

/-- An accepted put in a reachable world is visible to the attempt that staged it. -/
theorem read_your_write
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid tid seq : Nat) (map key value : String) (after : Tx),
    (Model.transitionSystem.step w ⟨seq, .put sid tid map key value⟩ = some next
      /\ txOf next sid tid = .ok after)
    -> valueAt after.data after.normal.writes (map, key) = some value := by
  exact Proofs.Model.read_your_write

/-- Witness: before a write is staged, the read can return a different value. -/
theorem read_your_write_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String) (v : String),
        valueAt db ws a ≠ some v := by
  exact Proofs.Witnesses.read_your_write_witness

/-- An accepted removal in a reachable world is visible to the attempt that staged it. -/
theorem read_your_deletion
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid tid seq : Nat) (map key : String) (after : Tx),
    (Model.transitionSystem.step w ⟨seq, .remove sid tid map key⟩ = some next
      /\ txOf next sid tid = .ok after)
    -> valueAt after.data after.normal.writes (map, key) = none := by
  exact Proofs.Model.read_your_deletion

/-- Witness: before a removal is staged, the read can return a value. -/
theorem read_your_deletion_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        valueAt db ws a ≠ none := by
  exact Proofs.Witnesses.read_your_deletion_witness

/-- An address neither staged nor present in a live attempt's pinned data reads as absent. -/
theorem absent_read
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (sid tid : Nat) (t : Tx) (a : Addr String String),
    (txOf w sid tid = .ok t
      /\ find t.normal.writes a = none
      /\ find t.data a = none)
    -> valueAt t.data t.normal.writes a = none := by
  exact Proofs.Model.absent_read

/-- Witness: a key can be neither staged nor committed. -/
theorem absent_read_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        find ws a = none ∧ find db a = none := by
  exact Proofs.Witnesses.absent_read_witness

/-- An accepted put or removal leaves other addresses in the same attempt unchanged. -/
theorem staged_noninterference
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid tid seq : Nat) (before after : Tx) (a b : Addr String String)
    (value : Option String),
    let event := match value with
      | some v => Event.put sid tid a.1 a.2 v
      | none => Event.remove sid tid a.1 a.2
    (txOf w sid tid = .ok before
      /\ Model.transitionSystem.step w ⟨seq, event⟩ = some next
      /\ txOf next sid tid = .ok after
      /\ a ≠ b)
    -> valueAt after.data after.normal.writes b = valueAt before.data before.normal.writes b := by
  exact Proofs.Model.staged_noninterference

/-- Witness: two addresses can differ. -/
theorem staged_noninterference_witness : ∃ a b : Addr String String, a ≠ b := by
  exact Proofs.Witnesses.staged_noninterference_witness

/-- An accepted previous-version read ignores the live attempt's pending writes. -/
theorem previous_ignores_pending
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid tid seq : Nat) (map key : String) (version : Option Nat)
    (t : Tx),
    (txOf w sid tid = .ok t
      /\ Model.transitionSystem.step w ⟨seq, .previous sid tid map key version⟩ = some next)
    -> version = (find t.data (map, key)).map Cell.version := by
  exact Proofs.Model.previous_ignores_pending

/-- Witness: a key can have both a committed version and a staged write. -/
theorem previous_ignores_pending_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        previousAt db a ≠ none ∧ find ws a ≠ none := by
  exact Proofs.Witnesses.previous_ignores_pending_witness

/-- An accepted application replaces written cells and keeps unwritten cells. -/
theorem publish_lookup
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid tid seq version term : Nat) (writes : Pending)
    (before after : Store) (t : Tx) (a : Addr String String),
    (storeOf w sid = .ok before
      /\ txOf w sid tid = .ok t
      /\ Model.transitionSystem.step w ⟨seq, .apply sid tid version term writes⟩ = some next
      /\ storeOf next sid = .ok after)
    -> find after.head.data a = match find t.normal.writes a with
      | none => find before.head.data a
      | some none => none
      | some (some value) => some { value, version } := by
  exact Proofs.Model.publish_lookup

/-- Witness: one write set can leave, remove and write addresses. -/
theorem publish_lookup_witness
    : ∃ (ws : Writes String String String) (kept removed written : Addr String String)
        (v : String),
        find ws kept = none
        ∧ find ws removed = some none
        ∧ find ws written = some (some v) := by
  exact Proofs.Witnesses.publish_lookup_witness

/-- An accepted application leaves addresses outside its staged write set unchanged. -/
theorem publication_noninterference
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid tid seq version term : Nat) (writes : Pending)
    (before after : Store) (t : Tx) (a : Addr String String),
    (storeOf w sid = .ok before
      /\ txOf w sid tid = .ok t
      /\ Model.transitionSystem.step w ⟨seq, .apply sid tid version term writes⟩ = some next
      /\ storeOf next sid = .ok after
      /\ find t.normal.writes a = none)
    -> find after.head.data a = find before.head.data a := by
  exact Proofs.Model.publication_noninterference

/-- Witness: an address can be unwritten. -/
theorem publication_noninterference_witness
    : ∃ (ws : Writes String String String) (a : Addr String String),
        find ws a = none := by
  exact Proofs.Witnesses.publication_noninterference_witness

/--
An accepted application in a reachable world produces unique committed keys.
This specialization is covered by `reachable_store_data_invariants` at the successor world.
-/
theorem publish_unique
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid tid seq version term : Nat) (writes : Pending)
    (after : Store),
    (Model.transitionSystem.step w ⟨seq, .apply sid tid version term writes⟩ = some next
      /\ storeOf next sid = .ok after)
    -> Unique after.head.data := by
  exact Proofs.Model.publish_unique

/-- Witness: a database can have unique keys. -/
theorem publish_unique_witness : ∃ db : DB String String String, Unique db := by
  exact Proofs.Witnesses.publish_unique_witness

/-- An accepted application atomically publishes the attempt's entire staged write set. -/
theorem apply_atomic
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid tid seq version term : Nat) (writes : Pending)
    (before after : Store) (t : Tx),
    (storeOf w sid = .ok before
      /\ txOf w sid tid = .ok t
      /\ Model.transitionSystem.step w ⟨seq, .apply sid tid version term writes⟩ = some next
      /\ storeOf next sid = .ok after)
    -> after.head.data = publish before.head.data (before.head.version + 1) t.normal.writes := by
  exact Proofs.Model.apply_atomic

/-- Witness: one applied write set can span two maps. -/
theorem apply_atomic_witness
    : ∃ (writes : Pending) (a b : Addr String String),
        a.1 ≠ b.1 ∧ find writes a ≠ none ∧ find writes b ≠ none := by
  exact Proofs.Witnesses.apply_atomic_witness

/-! ## Serial snapshot runs and normal-view serializability -/

/-- An attempt's operation log runs serially on its pinned local views to its staged writes. -/
theorem transaction_snapshot_serial
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (tid : Nat) (t : Tx) (snap : Snapshot),
    (find w.txs tid = some t
      /\ t.snapshot = some snap)
    -> serialRun t.data [] t.normal.log = some t.normal.writes := by
  intro w tid t snap reachable live captured
  exact Proofs.Model.transaction_snapshot_serial t snap
    ((Proofs.Invariants.reachable_invariant w reachable).txs tid t live).normal captured

/-- Witness: an attempt with a snapshot can have a nonempty log. -/
theorem transaction_snapshot_serial_witness
    : ∃ (w : World) (tid : Nat) (t : Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        ∧ find w.txs tid = some t
        ∧ t.snapshot = some snap
        ∧ t.normal.log ≠ [] := by
  exact Proofs.Witnesses.transaction_snapshot_serial_witness

/-- An attempt that may apply runs serially on the current head to the same staged writes. -/
theorem transaction_application_serial
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot),
    (storeOf w sid = .ok s
      /\ txOf w sid tid = .ok t
      /\ t.snapshot = some snap
      /\ canApply s t = true)
    -> serialRun s.head.data [] t.normal.log = some t.normal.writes := by
  intro w sid tid s t snap reachable _store tx captured applies
  exact Proofs.Model.transaction_application_serial s t snap
    (Proofs.Invariants.txOf_invariant w
      (Proofs.Invariants.reachable_invariant w reachable) sid tid t tx).normal
    captured applies

/-- Witness: an attempt with a nonempty log can apply. -/
theorem transaction_application_serial_witness
    : ∃ (w : World) (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        ∧ storeOf w sid = .ok s
        ∧ txOf w sid tid = .ok t
        ∧ t.snapshot = some snap
        ∧ canApply s t = true
        ∧ t.normal.log ≠ [] := by
  exact Proofs.Witnesses.transaction_application_serial_witness

/--
Applications on one reachable store branch run serially from its starting head.
Unlike the algebraic `AppliedBranch` claim, the attempts come from one actual model run.
This specialization is covered by `replay_segment_serializability`, which also counts versions.
-/
theorem executable_branch_serializability
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (final : World) (sid : Nat) (s : Store) (rs : List Record),
    (find w.stores sid = some s
      /\ (∀ r ∈ rs, SegmentEvent sid r.event)
      /\ CCF.Execution.Run Model.transitionSystem w rs final)
    -> exists after txs,
      find final.stores sid = some after
      /\ projectApplications w sid rs = .ok txs
      /\ serialTransactions s.head.data s.head.version txs = some after.head.data := by
  intro s final ts reachable branch
  apply Proofs.Model.executable_branch_serializability s final ts _ branch
  intro t member
  obtain ⟨w, tid, reached, live⟩ := reachable t member
  exact ((Proofs.Invariants.reachable_invariant w reached).txs tid t live).normal

/-- Witness: a nonempty branch of applied attempts exists. -/
theorem executable_branch_serializability_witness
    : ∃ (s final : Store) (ts : List Tx),
        (∀ t ∈ ts,
          ∃ (w : World) (tid : Nat),
            Model.transitionSystem.Reachable w ∧ find w.txs tid = some t)
        ∧ AppliedBranch s ts final
        ∧ ts ≠ [] := by
  exact Proofs.Witnesses.executable_branch_serializability_witness

/-- In an accepted record segment that keeps store `sid` alive, the applications projected
onto that store run serially to its final head. -/
theorem replay_segment_serializability
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (final : World) (sid : Nat) (s : Store) (rs : List Record),
    (find w.stores sid = some s
      /\ (∀ r ∈ rs, SegmentEvent sid r.event)
      /\ CCF.Execution.Run Model.transitionSystem w rs final)
    -> exists after txs,
        find final.stores sid = some after
        /\ projectApplications w sid rs = .ok txs
        /\ serialTransactions s.head.data s.head.version txs = some after.head.data
        /\ after.head.version = s.head.version + txs.length := by
  exact Proofs.Properties.replay_segment_serializability

/-- Witness: an accepted nonempty segment can keep a store alive. -/
theorem replay_segment_serializability_witness
    : ∃ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
        Model.transitionSystem.Reachable w
        ∧ find w.stores sid = some s
        ∧ (∀ r ∈ rs, SegmentEvent sid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem w rs final
        ∧ rs ≠ [] := by
  exact Proofs.Witnesses.replay_segment_serializability_witness

/-! ## Reachable store invariants -/

/-- Every live store in a reachable world has a well-formed history whose head is newest, and a
global version within it that is the version of its global cut. -/
theorem reachable_store_invariants
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (sid : Nat) (s : Store),
    find w.stores sid = some s
    -> History s.history s.head.version
      /\ s.history.head? = some s.head
      /\ s.global ≤ s.head.version
      /\ (atCut s s.global).version = s.global := by
  exact Proofs.Properties.reachable_store_invariants

/-- Witness: a reachable world can have a live store. -/
theorem reachable_store_invariants_witness
    : ∃ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s := by
  exact Proofs.Witnesses.reachable_store_invariants_witness

/-- Every live store's head data in a reachable world has unique keys and versions no later than
the head. -/
theorem reachable_store_data_invariants
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (sid : Nat) (s : Store),
    find w.stores sid = some s
    -> Unique s.head.data /\ CellsBounded s.head.data s.head.version := by
  exact Proofs.Properties.reachable_store_data_invariants

/-- Witness: a reachable world can have a live store. -/
theorem reachable_store_data_invariants_witness
    : ∃ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s := by
  exact Proofs.Witnesses.reachable_store_data_invariants_witness

/-! ## Current snapshot capture and preservation -/

/-- A reachable snapshot capture records the current head and the reported term. -/
theorem step_capture_metadata
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid tid version global term seq : Nat) (s : Store) (t : Tx),
    (storeOf w sid = .ok s
      /\ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩ = some next
      /\ find next.txs tid = some t)
    -> exists snap, t.snapshot = some snap /\ snap.current = s.head /\ snap.term = term := by
  exact Proofs.Properties.step_capture_metadata

/-- Witness: a snapshot capture can be accepted. -/
theorem step_capture_metadata_witness
    : ∃ (w next : World) (sid tid version global term seq : Nat) (s : Store) (t : Tx),
        storeOf w sid = .ok s
        ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next
        ∧ find next.txs tid = some t := by
  exact Proofs.Witnesses.step_capture_metadata_witness

/-- A reachable snapshot capture reports the current head and global versions. -/
theorem step_capture_cut_values
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid tid version global term seq : Nat) (s : Store),
    (storeOf w sid = .ok s
      /\ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩ = some next)
    -> version = s.head.version /\ global = s.global := by
  exact Proofs.Properties.step_capture_cut_values

/-- Witness: a snapshot capture can be accepted. -/
theorem step_capture_cut_values_witness
    : ∃ (w next : World) (sid tid version global term seq : Nat) (s : Store),
        storeOf w sid = .ok s
        ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next := by
  exact Proofs.Witnesses.step_capture_cut_values_witness

/-- A snapshot captured from a reachable world retains its head and term in the same attempt. -/
theorem capture_replay_preserves_metadata
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (capturedWorld final : World) (sid tid version global term seq : Nat) (s : Store)
    (t : Tx) (tail : List Record),
    (storeOf w sid = .ok s
      /\ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some capturedWorld
      /\ find capturedWorld.txs tid = some t
      /\ (∀ r ∈ tail, AttemptEvent tid r.event)
      /\ CCF.Execution.Run Model.transitionSystem capturedWorld tail final)
    -> exists after snap,
      find final.txs tid = some after
      /\ after.snapshot = some snap
      /\ snap.current = s.head
      /\ snap.term = term := by
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

/-- A reachable attempt's snapshot is fixed until the attempt ends. -/
theorem replay_snapshot_fixed
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (final : World) (tid : Nat) (before : Tx) (snap : Snapshot) (rs : List Record),
    (find w.txs tid = some before
      /\ before.snapshot = some snap
      /\ (∀ r ∈ rs, AttemptEvent tid r.event)
      /\ CCF.Execution.Run Model.transitionSystem w rs final)
    -> exists after, find final.txs tid = some after /\ after.snapshot = some snap := by
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

/-- A reachable acquisition captures the global view and checks both reported revisions. -/
theorem step_map_capture
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid tid localVersion globalVersion seq : Nat) (map : String)
    (s : Store) (before after : Tx) (snap : Snapshot),
    (storeOf w sid = .ok s
      /\ txOf w sid tid = .ok before
      /\ before.snapshot = some snap
      /\ Model.transitionSystem.step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some next
      /\ find next.txs tid = some after)
    -> find after.globalViews map = some (captureGlobal s snap map)
      /\ localVersion = (revision (captureLocal s snap map) map).version
      /\ globalVersion = (revision (captureGlobal s snap map).frame map).version := by
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

/-- A reachable attempt's acquired global view is fixed until the attempt ends. -/
theorem replay_map_global_fixed
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
    (rs : List Record),
    (find w.txs tid = some before
      /\ find before.globalViews map = some view
      /\ (∀ r ∈ rs, AttemptEvent tid r.event)
      /\ CCF.Execution.Run Model.transitionSystem w rs final)
    -> exists after,
      find final.txs tid = some after /\ find after.globalViews map = some view := by
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

/-- A reachable attempt's acquired local map data is fixed until the attempt ends. -/
theorem replay_map_local_fixed
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
    (rs : List Record),
    (find w.txs tid = some before
      /\ find before.globalViews map = some view
      /\ (∀ r ∈ rs, AttemptEvent tid r.event)
      /\ CCF.Execution.Run Model.transitionSystem w rs final)
    -> exists after,
      find final.txs tid = some after /\ image after.data map = image before.data map := by
  exact Proofs.Properties.replay_map_local_fixed

/-- Witness: an acquired map can survive a nonempty accepted segment. -/
theorem replay_map_local_fixed_witness
    : ∃ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        ∧ find before.globalViews map = some view
        ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem w rs final
        ∧ rs ≠ [] := by
  exact Proofs.Witnesses.replay_map_global_fixed_witness

/-- A reachable acquisition's global view and reported revisions persist in the same attempt. -/
theorem capture_replay_preserves_map
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (capturedWorld final : World) (sid tid localVersion globalVersion seq : Nat)
    (map : String) (s : Store) (before capturedTx : Tx) (snap : Snapshot)
    (tail : List Record),
    (storeOf w sid = .ok s
      /\ txOf w sid tid = .ok before
      /\ before.snapshot = some snap
      /\ Model.transitionSystem.step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some capturedWorld
      /\ find capturedWorld.txs tid = some capturedTx
      /\ (∀ r ∈ tail, AttemptEvent tid r.event)
      /\ CCF.Execution.Run Model.transitionSystem capturedWorld tail final)
    -> exists after,
      find final.txs tid = some after
      /\ find after.globalViews map = some (captureGlobal s snap map)
      /\ localVersion = (revision (captureLocal s snap map) map).version
      /\ globalVersion = (revision (captureGlobal s snap map).frame map).version := by
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

/-- A live attempt acquiring a not-yet-created map would capture an empty global frame. -/
theorem captureGlobal_placeholder
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot) (map : String),
    (storeOf w sid = .ok s
      /\ txOf w sid tid = .ok t
      /\ t.snapshot = some snap
      /\ find (captureLocal s snap map).births map = none)
    -> (captureGlobal s snap map).frame = {} := by
  exact Proofs.Trace.captureGlobal_placeholder

/-- Witness: a snapshot can lack a map. -/
theorem captureGlobal_placeholder_witness
    : ∃ (s : Store) (snap : Snapshot) (map : String),
        find (captureLocal s snap map).births map = none := by
  exact Proofs.Witnesses.captureGlobal_placeholder_witness

/-- A live attempt acquiring an existing map would capture the store's global cut. -/
theorem captureGlobal_committed
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot) (map : String)
    (birth : Stamp),
    (storeOf w sid = .ok s
      /\ txOf w sid tid = .ok t
      /\ t.snapshot = some snap
      /\ find (captureLocal s snap map).births map = some birth)
    -> (captureGlobal s snap map).frame = atCut s s.global := by
  exact Proofs.Trace.captureGlobal_committed

/-- Witness: a snapshot can contain a map. -/
theorem captureGlobal_committed_witness
    : ∃ (s : Store) (snap : Snapshot) (map : String) (birth : Stamp),
        find (captureLocal s snap map).births map = some birth := by
  exact Proofs.Witnesses.captureGlobal_committed_witness

/-- A global read returns the captured view's value, and that view is empty or a store's global
cut with no cell newer than it. -/
theorem step_global_read_from_captured_map
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid tid seq : Nat) (map key : String) (value : Option String)
    (t : Tx) (view : GlobalView),
    (txOf w sid tid = .ok t
      /\ find t.globalViews map = some view
      /\ Model.transitionSystem.step w ⟨seq, .get sid tid map key value true⟩ = some next)
    -> value = (find view.frame.data (map, key)).map Cell.value
      /\ (view.frame = {}
          \/ exists origin : Store,
              view.frame = atCut origin origin.global
              /\ view.frame.version = origin.global
              /\ CellsBounded view.frame.data origin.global) := by
  exact Proofs.Properties.step_global_read_from_captured_map

/-- Witness: a global read of a committed value can be accepted. -/
theorem step_global_read_from_captured_map_witness
    : ∃ (w next : World) (sid tid seq : Nat) (map key value : String) (t : Tx)
        (view : GlobalView),
        Model.transitionSystem.Reachable w
        ∧ txOf w sid tid = .ok t
        ∧ find t.globalViews map = some view
        ∧ Model.transitionSystem.step w ⟨seq, .get sid tid map key (some value) true⟩
          = some next := by
  exact Proofs.Witnesses.step_global_read_from_captured_map_witness

/-- A global presence test reflects the captured view, and that view is empty or a store's
global cut with no cell newer than it. -/
theorem step_global_has_from_captured_map
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid tid seq : Nat) (map key : String) (value : Bool) (t : Tx)
    (view : GlobalView),
    (txOf w sid tid = .ok t
      /\ find t.globalViews map = some view
      /\ Model.transitionSystem.step w ⟨seq, .has sid tid map key value true⟩ = some next)
    -> value = (find view.frame.data (map, key)).isSome
      /\ (view.frame = {}
          \/ exists origin : Store,
              view.frame = atCut origin origin.global
              /\ view.frame.version = origin.global
              /\ CellsBounded view.frame.data origin.global) := by
  exact Proofs.Properties.step_global_has_from_captured_map

/-- Witness: a global presence test of a committed key can be accepted. -/
theorem step_global_has_from_captured_map_witness
    : ∃ (w next : World) (sid tid seq : Nat) (map key : String) (t : Tx)
        (view : GlobalView),
        Model.transitionSystem.Reachable w
        ∧ txOf w sid tid = .ok t
        ∧ find t.globalViews map = some view
        ∧ Model.transitionSystem.step w ⟨seq, .has sid tid map key true true⟩
          = some next := by
  exact Proofs.Witnesses.step_global_has_from_captured_map_witness

/-! ## Compaction, rollback, and invalidated attempts -/

/-- An accepted above-head compaction leaves the live store unchanged. -/
theorem compact_above_head_noop
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid seq version requested : Nat) (s after : Store),
    (storeOf w sid = .ok s
      /\ s.head.version < requested
      /\ Model.transitionSystem.step w ⟨seq, .compact sid version requested⟩ = some next
      /\ storeOf next sid = .ok after)
    -> after = s := by
  exact Proofs.Model.compact_above_head_noop

/-- Witness: a version can be beyond the head. -/
theorem compact_above_head_noop_witness
    : ∃ (s : Store) (v : Nat), s.head.version < v := by
  exact Proofs.Witnesses.compact_above_head_noop_witness

/-- An accepted rollback retains every frame at or below the live store's global version. -/
theorem rollback_keeps_prefix
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid seq version requested term : Nat) (s after : Store)
    (f : Frame),
    (storeOf w sid = .ok s
      /\ Model.transitionSystem.step w ⟨seq, .rollback sid version requested term⟩ = some next
      /\ storeOf next sid = .ok after
      /\ f ∈ s.history
      /\ f.version ≤ s.global)
    -> f ∈ after.history := by
  exact Proofs.Model.rollback_keeps_prefix

/-- Witness: a nonempty frame can be on the branch at or below the global version. -/
theorem rollback_keeps_prefix_witness
    : ∃ (s : Store) (f : Frame), f ∈ s.history ∧ f.version ≤ s.global ∧ f.data ≠ [] := by
  exact Proofs.Witnesses.rollback_keeps_prefix_witness

/-- An accepted rollback discards frames above its effective version. -/
theorem rollback_discards_suffix
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid seq version requested term : Nat) (s after : Store)
    (f : Frame),
    (storeOf w sid = .ok s
      /\ Model.transitionSystem.step w ⟨seq, .rollback sid version requested term⟩ = some next
      /\ storeOf next sid = .ok after
      /\ f ∈ s.history
      /\ version < f.version)
    -> f ∉ after.history := by
  exact Proofs.Model.rollback_discards_suffix

/-- Witness: a frame on the branch can be above a version at or above the global version. -/
theorem rollback_discards_suffix_witness
    : ∃ (s : Store) (v : Nat) (f : Frame),
        f ∈ s.history ∧ v < f.version ∧ s.global ≤ v := by
  exact Proofs.Witnesses.rollback_discards_suffix_witness

/-- An accepted rollback preserves the data of every globally durable cut. -/
theorem durable_cut_survives_rollback
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (next : World) (sid seq version requested term cut : Nat) (s after : Store),
    (storeOf w sid = .ok s
      /\ Model.transitionSystem.step w ⟨seq, .rollback sid version requested term⟩ = some next
      /\ storeOf next sid = .ok after
      /\ cut ≤ s.global)
    -> (atCut after cut).data = (atCut s cut).data := by
  intro w sid s v term cut reachable live below boundary
  exact Proofs.Model.durable_cut_survives_rollback s v term cut
    ((Proofs.Invariants.reachable_invariant w reachable).stores sid s live) below boundary

/-- Witness: a nonempty cut can be at or below the global version. -/
theorem durable_cut_survives_rollback_witness
    : ∃ (w : World) (sid : Nat) (s : Store) (v cut : Nat),
        Model.transitionSystem.Reachable w
        ∧ find w.stores sid = some s
        ∧ cut ≤ s.global
        ∧ s.global ≤ v
        ∧ (atCut s cut).data ≠ [] := by
  exact Proofs.Witnesses.durable_cut_survives_rollback_witness

/-- A live attempt whose snapshot term differs from its store's cannot apply. -/
theorem stale_term_cannot_apply
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot),
    (storeOf w sid = .ok s
      /\ txOf w sid tid = .ok t
      /\ t.snapshot = some snap
      /\ s.term ≠ snap.term)
    -> canApply s t = false := by
  exact Proofs.Model.stale_term_cannot_apply

/-- Witness: an attempt's snapshot term can differ from the store's. -/
theorem stale_term_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot),
        t.snapshot = some snap ∧ s.term ≠ snap.term := by
  exact Proofs.Witnesses.stale_term_cannot_apply_witness

/-- A live attempt with an acquired revision absent from its store's branch cannot apply. -/
theorem discarded_handle_cannot_apply
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot) (m : String)
    (view : GlobalView),
    (storeOf w sid = .ok s
      /\ txOf w sid tid = .ok t
      /\ t.snapshot = some snap
      /\ (m, view) ∈ t.globalViews
      /\ (∀ f ∈ s.history, (revision f m == revision view.current m) = false))
    -> canApply s t = false := by
  exact Proofs.Properties.discarded_handle_cannot_apply

/-- Witness: an attempt can hold a map whose revision is no longer on the branch. -/
theorem discarded_handle_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (revision f m == revision view.current m) = false) := by
  exact Proofs.Witnesses.discarded_handle_cannot_apply_witness

/-- A live attempt with an acquired map creation absent from its store's branch cannot apply. -/
theorem discarded_birth_cannot_apply
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot) (m : String)
    (view : GlobalView),
    (storeOf w sid = .ok s
      /\ txOf w sid tid = .ok t
      /\ t.snapshot = some snap
      /\ (m, view) ∈ t.globalViews
      /\ (∀ f ∈ s.history, (find f.births m == find view.current.births m) = false))
    -> canApply s t = false := by
  exact Proofs.Properties.discarded_birth_cannot_apply

/-- Witness: an attempt can hold a map whose creation is no longer on the branch. -/
theorem discarded_birth_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (find f.births m == find view.current.births m) = false) := by
  exact Proofs.Witnesses.discarded_birth_cannot_apply_witness

/-- An acquired map revision older than the live store's global revision is unavailable. -/
theorem compacted_map_unavailable
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (sid tid : Nat) (s : Store) (t : Tx) (m : String) (view : GlobalView)
    (birth : Stamp),
    (storeOf w sid = .ok s
      /\ txOf w sid tid = .ok t
      /\ find t.globalViews m = some view
      /\ find view.current.births m = some birth
      /\ (revision view.current m).version < (revision (atCut s s.global) m).version)
    -> mapAvailable s view.current m = false := by
  exact Proofs.Model.compacted_map_unavailable

/-- Witness: a map can be revised before the global cut's revision. -/
theorem compacted_map_unavailable_witness
    : ∃ (s : Store) (f : Frame) (m : String) (birth : Stamp),
        find f.births m = some birth
        ∧ (revision f m).version < (revision (atCut s s.global) m).version := by
  exact Proofs.Witnesses.compacted_map_unavailable_witness

/--
An absent, empty, unrevised map cut for a live attempt is available.
This specialization only considers `captureLocal` frames, which are empty when the map is absent;
it no longer describes arbitrary frames.
-/
theorem absent_map_available
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot) (m : String),
    let f := captureLocal s snap m
    (storeOf w sid = .ok s
      /\ txOf w sid tid = .ok t
      /\ t.snapshot = some snap
      /\ find f.births m = none
      /\ image f.data m = []
      /\ find f.revisions m = none)
    -> mapAvailable s f m = true := by
  exact Proofs.Model.absent_map_available

/-- Witness: a map can be absent, empty, and unrevised. -/
theorem absent_map_available_witness
    : ∃ (f : Frame) (m : String),
        find f.births m = none ∧ image f.data m = [] ∧ find f.revisions m = none := by
  exact Proofs.Witnesses.absent_map_available_witness

/--
An available absent map cut for a live attempt contains no values.
As above, the absent `captureLocal` frame is empty by construction, unlike an arbitrary frame.
-/
theorem absent_placeholder_has_no_values
    : ∀ w ∈ Model.transitionSystem.Reachable,
    forall (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot) (m key : String),
    let f := captureLocal s snap m
    (storeOf w sid = .ok s
      /\ txOf w sid tid = .ok t
      /\ t.snapshot = some snap
      /\ find f.births m = none
      /\ mapAvailable s f m = true)
    -> find f.data (m, key) = none := by
  exact Proofs.Model.absent_placeholder_has_no_values

/-- Witness: an absent map can be available. -/
theorem absent_placeholder_has_no_values_witness
    : ∃ (s : Store) (f : Frame) (m : String),
        find f.births m = none ∧ mapAvailable s f m = true := by
  exact Proofs.Witnesses.absent_placeholder_has_no_values_witness

end Kv.Properties
