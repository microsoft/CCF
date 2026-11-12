-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Executions

@[expose] public section

namespace Kv.Proofs.CoreWitnesses

open Kv.Model Kv.Properties

private instance (tid : Nat) : DecidablePred (AttemptAction tid) :=
  fun a => by cases a <;> unfold AttemptAction <;> infer_instance

private def committedCell : DB String String String := [(("a", "00"), ⟨"11", 1⟩)]

theorem read_your_write_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String) (v : String),
        valueAt db ws a ≠ some v :=
  ⟨committedCell, [], ("a", "00"), "22", by decide⟩

theorem read_your_deletion_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        valueAt db ws a ≠ none :=
  ⟨committedCell, [], ("a", "00"), by decide⟩

theorem previous_ignores_pending_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        previousAt db a ≠ none ∧ find ws a ≠ none :=
  ⟨committedCell, [(("a", "00"), some "22")], ("a", "00"), by decide, by decide⟩

theorem publish_lookup_witness
    : ∃ (ws : Writes String String String) (kept removed written : Addr String String)
        (v : String),
        find ws kept = none
        ∧ find ws removed = some none
        ∧ find ws written = some (some v) :=
  ⟨
    [(("a", "01"), none), (("a", "02"), some "22")],
    ("a", "00"),
    ("a", "01"),
    ("a", "02"),
    "22",
    by decide,
    by decide,
    by decide
  ⟩

theorem apply_atomic_witness
    : ∃ (writes : Pending) (a b : Addr String String),
        a.1 ≠ b.1 ∧ find writes a ≠ none ∧ find writes b ≠ none :=
  ⟨
    [(("a", "00"), some "11"), (("b", "00"), none)],
    ("a", "00"),
    ("b", "00"),
    by decide,
    by decide,
    by decide
  ⟩

theorem absent_read_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        find ws a = none ∧ find db a = none :=
  ⟨[], [], ("a", "00"), rfl, rfl⟩

theorem staged_noninterference_witness : ∃ a b : Addr String String, a ≠ b :=
  ⟨("a", "00"), ("a", "01"), by decide⟩

theorem publication_noninterference_witness
    : ∃ (ws : Writes String String String) (a : Addr String String), find ws a = none :=
  ⟨[], ("a", "00"), rfl⟩

theorem publish_unique_witness : ∃ db : DB String String String, Unique db :=
  ⟨[], List.nodup_nil⟩

private def inputs : List Action :=
  [
    .storeCreate 1 0,
    .txCreate 1 1,
    .snapshot 1 1,
    .acquire 1 1 "a",
    .operation 1 1 (.write "a" "00" (some "11")),
    .commitBegin 1 1,
    .apply 1 1,
    .commitResult 1 1 .success,
    .txEnd 1 1,
    .compact 1 1,
    .txCreate 1 2,
    .snapshot 1 2,
    .acquire 1 2 "a",
    .operation 1 2 (.get "a" "00" true),
    .operation 1 2 (.has "a" "00" true)
  ]

private def input (n : Nat) : Action := inputs.getD n (.storeEnd 1)

private def state : Nat → State
  | 0 => {}
  | n + 1 => (step (state n) (input n)).getD {}

private def enabled : Nat → Bool
  | 0 => true
  | n + 1 => enabled n && (step (state n) (input n)).isSome

private theorem all_enabled : enabled 15 = true := by decide +kernel

private theorem state_step {n : Nat} (lt : n < 15)
    : transitionSystem.step (state n) (input n) = some (state (n + 1)) := by
  have enabled_le {m n : Nat} (le : m ≤ n) (h : enabled n = true) : enabled m = true := by
    induction le with
    | refl => exact h
    | step _ ih =>
        simp only [enabled, Bool.and_eq_true] at h
        exact ih h.1
  have h := enabled_le lt all_enabled
  simp only [enabled, Bool.and_eq_true] at h
  change step (state n) (input n) = some (state (n + 1))
  simp only [state]
  cases selected : step (state n) (input n) with
  | none => simp [selected] at h
  | some => rfl

private theorem state_reachable {n : Nat} (bound : n ≤ 15)
    : transitionSystem.Reachable (state n) := by
  induction n with
  | zero => exact .initial rfl
  | succ n ih => exact .step (ih (Nat.le_of_succ_le bound)) (state_step bound)

private theorem state_run {i k : Nat} (bound : i + k ≤ 15)
    : CCF.Execution.Run transitionSystem (state i) ((List.range' i k).map input)
        (state (i + k)) := by
  induction k generalizing i with
  | zero => exact .nil _
  | succ k ih =>
      have same : i + (k + 1) = i + 1 + k :=
        (Nat.add_assoc i k 1).symm.trans (Nat.add_right_comm i k 1)
      rw [same]
      exact .cons (state_step (Nat.lt_of_lt_of_le (Nat.lt_add_of_pos_right (Nat.succ_pos k)) bound))
        (ih (same ▸ bound))

private theorem unrestricted_segment (w : State) (sid : Nat) (actions : List Action)
    (safe : ∀ a ∈ actions, ∀ before, SegmentAction before sid a)
    : SegmentInputs w sid actions := by
  induction actions generalizing w with
  | nil => trivial
  | cons a rest ih =>
      exact ⟨safe a (List.mem_cons_self) w,
        fun next _ => ih next (fun b member => safe b (List.mem_cons_of_mem _ member))⟩

private theorem written_segment
    : SegmentInputs (state 1) 1 ((List.range' 1 9).map input) := by
  apply unrestricted_segment
  simp [input, inputs, SegmentAction, List.range'_succ, List.range'_zero]

private def storeAt (n : Nat) : Store := (find (state n).stores 1).getD {}
private def txAt (n tid : Nat) : Tx := (find (state n).txs tid).getD { store := 1 }

private def snapAt (n tid : Nat) : Snapshot :=
  (txAt n tid).snapshot.getD { current := {}, term := 0 }

private def viewAt (n tid : Nat) : GlobalView :=
  (find (txAt n tid).globalViews "a").getD { frame := {} }

/-- An actual semantic snapshot witnesses capture metadata. -/
theorem step_capture_metadata_witness
    : ∃ (w next : State) (sid tid : Nat) (s : Store) (t : Tx) (output : Output),
        find w.stores sid = some s
        ∧ execute w (.snapshot sid tid) = some (next, output)
        ∧ find next.txs tid = some t :=
  ⟨
    state 2,
    state 3,
    1,
    1,
    storeAt 2,
    txAt 3 1,
    .snapshot 0 0 0,
    by decide +kernel,
    by decide +kernel,
    by decide +kernel
  ⟩

/-- Snapshot output witnesses the source store's actual cuts. -/
theorem step_capture_cut_values_witness
    : ∃ (w next : State) (sid tid version global term : Nat) (s : Store),
        find w.stores sid = some s
        ∧ execute w (.snapshot sid tid) = some (next, .snapshot version global term) :=
  ⟨state 2, state 3, 1, 1, 0, 0, 0, storeAt 2, by decide +kernel, by decide +kernel⟩

/-- A semantic acquisition witnesses captured frames and revision outputs. -/
theorem step_map_capture_witness
    : ∃ (w next : State) (sid tid localVersion globalVersion : Nat) (map : String)
        (s : Store) (before after : Tx) (snap : Snapshot),
        lookupTx w sid tid = some (s, before)
        ∧ before.snapshot = some snap
        ∧ execute w (.acquire sid tid map)
          = some (next, .acquired localVersion globalVersion)
        ∧ find next.txs tid = some after :=
  ⟨
    state 3,
    state 4,
    1,
    1,
    0,
    0,
    "a",
    storeAt 3,
    txAt 3 1,
    txAt 4 1,
    snapAt 3 1,
    by decide +kernel,
    by decide +kernel,
    by decide +kernel,
    by decide +kernel
  ⟩

/-- A nonempty semantic execution preserves an already captured current frame. -/
theorem execution_snapshot_fixed_witness
    : ∃ (w final : State) (tid : Nat) (before : Tx) (snap : Snapshot)
        (actions : List Action),
        find w.txs tid = some before
        ∧ before.snapshot = some snap
        ∧ (∀ a ∈ actions, AttemptAction tid a)
        ∧ CCF.Execution.Run transitionSystem w actions final
        ∧ actions ≠ [] :=
  ⟨
    state 3,
    state 6,
    1,
    txAt 3 1,
    snapAt 3 1,
    (List.range' 3 3).map input,
    by decide +kernel,
    by decide +kernel,
    by decide +kernel,
    state_run (by decide),
    by decide +kernel
  ⟩

/-- A nonempty semantic execution preserves an acquired global frame. -/
theorem execution_map_global_fixed_witness
    : ∃ (w final : State) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (actions : List Action),
        find w.txs tid = some before
        ∧ find before.globalViews map = some view
        ∧ (∀ a ∈ actions, AttemptAction tid a)
        ∧ CCF.Execution.Run transitionSystem w actions final
        ∧ actions ≠ [] :=
  ⟨
    state 4,
    state 7,
    1,
    txAt 4 1,
    "a",
    viewAt 4 1,
    (List.range' 4 3).map input,
    by decide +kernel,
    by decide +kernel,
    by decide +kernel,
    state_run (by decide),
    by decide +kernel
  ⟩

/-- Writes and application witness nonempty execution with fixed pinned local data. -/
theorem execution_map_local_fixed_witness
    : ∃ (w final : State) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (actions : List Action),
        find w.txs tid = some before
        ∧ find before.globalViews map = some view
        ∧ (∀ a ∈ actions, AttemptAction tid a)
        ∧ CCF.Execution.Run transitionSystem w actions final
        ∧ actions ≠ [] :=
  ⟨
    state 4,
    state 7,
    1,
    txAt 4 1,
    "a",
    viewAt 4 1,
    (List.range' 4 3).map input,
    by decide +kernel,
    by decide +kernel,
    by decide +kernel,
    state_run (by decide),
    by decide +kernel
  ⟩

/-- Actual capture followed by a nonempty semantic execution witnesses metadata preservation. -/
theorem capture_execution_preserves_metadata_witness
    : ∃ (w captured final : State) (sid tid : Nat) (s : Store) (t : Tx)
        (output : Output) (actions : List Action),
        find w.stores sid = some s
        ∧ execute w (.snapshot sid tid) = some (captured, output)
        ∧ find captured.txs tid = some t
        ∧ (∀ a ∈ actions, AttemptAction tid a)
        ∧ CCF.Execution.Run transitionSystem captured actions final
        ∧ actions ≠ [] :=
  ⟨
    state 2,
    state 3,
    state 6,
    1,
    1,
    storeAt 2,
    txAt 3 1,
    .snapshot 0 0 0,
    (List.range' 3 3).map input,
    by decide +kernel,
    by decide +kernel,
    by decide +kernel,
    by decide +kernel,
    state_run (by decide),
    by decide +kernel
  ⟩

/-- Actual map capture followed by publication witnesses frame/revision preservation. -/
theorem capture_execution_preserves_map_witness
    : ∃ (w captured final : State) (sid tid localVersion globalVersion : Nat)
        (map : String) (s : Store) (before acquired : Tx) (snap : Snapshot)
        (actions : List Action),
        lookupTx w sid tid = some (s, before)
        ∧ before.snapshot = some snap
        ∧ execute w (.acquire sid tid map)
          = some (captured, .acquired localVersion globalVersion)
        ∧ find captured.txs tid = some acquired
        ∧ (∀ a ∈ actions, AttemptAction tid a)
        ∧ CCF.Execution.Run transitionSystem captured actions final
        ∧ actions ≠ [] :=
  ⟨
    state 3,
    state 4,
    state 7,
    1,
    1,
    0,
    0,
    "a",
    storeAt 3,
    txAt 3 1,
    txAt 4 1,
    snapAt 3 1,
    (List.range' 4 3).map input,
    by decide +kernel,
    by decide +kernel,
    by decide +kernel,
    by decide +kernel,
    by decide +kernel,
    state_run (by decide),
    by decide +kernel
  ⟩

/-- A present global value is produced by a reachable semantic execution. -/
theorem step_global_read_from_captured_map_witness
    : ∃ (w next : State) (sid tid : Nat) (s : Store) (t : Tx) (map key value : String)
        (view : GlobalView),
        transitionSystem.Reachable w
        ∧ lookupTx w sid tid = some (s, t)
        ∧ find t.globalViews map = some view
        ∧ execute w (.operation sid tid (.get map key true))
          = some (next, .value (some value)) :=
  ⟨
    state 13,
    state 14,
    1,
    2,
    storeAt 13,
    txAt 13 2,
    "a",
    "00",
    "11",
    viewAt 13 2,
    state_reachable (by decide),
    by decide +kernel,
    by decide +kernel,
    by decide +kernel
  ⟩

/-- Global presence is produced by a reachable semantic execution. -/
theorem step_global_has_from_captured_map_witness
    : ∃ (w next : State) (sid tid : Nat) (s : Store) (t : Tx) (map key : String)
        (view : GlobalView),
        transitionSystem.Reachable w
        ∧ lookupTx w sid tid = some (s, t)
        ∧ find t.globalViews map = some view
        ∧ execute w (.operation sid tid (.has map key true))
          = some (next, .presence true) :=
  ⟨
    state 14,
    state 15,
    1,
    2,
    storeAt 14,
    txAt 14 2,
    "a",
    "00",
    viewAt 14 2,
    state_reachable (by decide),
    by decide +kernel,
    by decide +kernel,
    by decide +kernel
  ⟩

/-- A nonempty actual semantic segment includes publication and compaction. -/
theorem execution_segment_serializability_witness
    : ∃ (w final : State) (sid : Nat) (s : Store) (actions : List Action),
        transitionSystem.Reachable w
        ∧ find w.stores sid = some s
        ∧ SegmentInputs w sid actions
        ∧ CCF.Execution.Run transitionSystem w actions final
        ∧ actions ≠ [] :=
  ⟨
    state 1,
    state 10,
    1,
    storeAt 1,
    (List.range' 1 9).map input,
    state_reachable (by decide),
    by decide +kernel,
    written_segment,
    state_run (by decide),
    by decide +kernel
  ⟩

private def written : Store := advance {} [(("a", "00"), some "11")]
private def writtenSnap : Snapshot := { current := written.head, term := 0 }

private def writtenTx : Tx :=
  {
    store := 1
    snapshot := some writtenSnap
    globalViews := [("a", captureGlobal written writtenSnap "a")]
  }

/-- An absent map witnesses empty global capture. -/
theorem captureGlobal_placeholder_witness
    : ∃ (s : Store) (snap : Snapshot) (map : String),
        find (captureLocal s snap map).births map = none :=
  ⟨{}, ⟨{}, 0⟩, "a", rfl⟩

/-- A previously written map witnesses committed global capture. -/
theorem captureGlobal_committed_witness
    : ∃ (s : Store) (snap : Snapshot) (map : String) (birth : Stamp),
        find (captureLocal s snap map).births map = some birth :=
  ⟨written, writtenSnap, "a", ⟨1, 1⟩, by decide +kernel⟩

/-- An above-head compaction request can occur. -/
theorem compact_above_head_noop_witness : ∃ (s : Store) (v : Nat), s.head.version < v :=
  ⟨{}, 1, Nat.zero_lt_one⟩

/-- A nonempty durable frame witnesses rollback prefix preservation. -/
theorem rollback_keeps_prefix_witness
    : ∃ (s : Store) (f : Frame), f ∈ s.history ∧ f.version ≤ s.global ∧ f.data ≠ [] :=
  ⟨
    compactStore written 1,
    written.head,
    by decide +kernel,
    by decide +kernel,
    by decide +kernel
  ⟩

/-- A nonempty suffix frame can be discarded by rollback. -/
theorem rollback_discards_suffix_witness
    : ∃ (s : Store) (v : Nat) (f : Frame), f ∈ s.history ∧ v < f.version ∧ s.global ≤ v :=
  ⟨written, 0, written.head, by decide +kernel, by decide +kernel, by decide +kernel⟩

/-- A reachable nonempty durable cut witnesses rollback safety. -/
theorem durable_cut_survives_rollback_witness
    : ∃ (w : State) (sid : Nat) (s : Store) (v cut : Nat),
        transitionSystem.Reachable w
        ∧ find w.stores sid = some s
        ∧ cut ≤ s.global
        ∧ s.global ≤ v
        ∧ (atCut s cut).data ≠ [] :=
  ⟨
    state 10,
    1,
    storeAt 10,
    1,
    1,
    state_reachable (by decide),
    by decide +kernel,
    by decide +kernel,
    by decide +kernel,
    by decide +kernel
  ⟩

/-- A captured term can differ from the current store's term. -/
theorem stale_term_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot),
        t.snapshot = some snap ∧ s.term ≠ snap.term :=
  ⟨{}, { store := 0, snapshot := some ⟨{}, 1⟩ }, _, rfl, by decide⟩

/-- Rollback can remove the acquired map revision. -/
theorem discarded_handle_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (revision f m == revision view.current m) = false) :=
  ⟨
    rollbackStore written 0 1,
    writtenTx,
    writtenSnap,
    "a",
    captureGlobal written writtenSnap "a",
    rfl,
    by decide +kernel,
    by decide +kernel
  ⟩

/-- Rollback can remove the acquired map birth identity. -/
theorem discarded_birth_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (find f.births m == find view.current.births m) = false) :=
  ⟨
    rollbackStore written 0 1,
    writtenTx,
    writtenSnap,
    "a",
    captureGlobal written writtenSnap "a",
    rfl,
    by decide +kernel,
    by decide +kernel
  ⟩

/-- A committed map revision can advance beyond an older local frame. -/
theorem compacted_map_unavailable_witness
    : ∃ (s : Store) (f : Frame) (m : String) (birth : Stamp),
        find f.births m = some birth
        ∧ (revision f m).version < (revision (atCut s s.global) m).version :=
  ⟨
    compactStore (advance written [(("a", "00"), some "22")]) 2,
    written.head,
    "a",
    ⟨1, 1⟩,
    by decide +kernel,
    by decide +kernel
  ⟩

/-- Truly absent maps have empty data and no prior revision. -/
theorem absent_map_available_witness
    : ∃ (f : Frame) (m : String),
        find f.births m = none ∧ image f.data m = [] ∧ find f.revisions m = none :=
  ⟨{}, "a", rfl, rfl, rfl⟩

/-- The empty-map placeholder path is permitted. -/
theorem absent_placeholder_has_no_values_witness
    : ∃ (s : Store) (f : Frame) (m : String),
        find f.births m = none ∧ mapAvailable s f m = true :=
  ⟨{}, {}, "a", rfl, rfl⟩

end Kv.Proofs.CoreWitnesses
