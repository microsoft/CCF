-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Executions

import Kv.Proofs.Core
import Kv.Proofs.CoreWitnesses
import Kv.Proofs.Safety
import Kv.Proofs.ModelExecution
import Kv.Proofs.Semantics
import Kv.Proofs.SemanticInvariant

@[expose] public section

/-! The canonical KV safety catalogue concerns only semantic model states, outputs and executions.
Each full statement and adjacent nonvacuity witness links to its checked proof implementation.
Trace conformance proofs remain separate under `Kv.Proofs.Correspondence`. -/

namespace Kv.Properties

open Kv.Model

/-- Every semantic-reachable store has a complete history, current head, and bounded global cut. -/
theorem reachable_store_invariants
    : ∀ (w : Model.State) (sid : Nat) (s : Model.Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → History s.history s.head.version
          ∧ s.history.head? = some s.head
          ∧ s.global ≤ s.head.version
          ∧ (atCut s s.global).version = s.global := by
  exact Proofs.SemanticInvariant.semantic_reachable_store_invariants

/-- Witness: semantic actions reach a live store without any trace metadata. -/
theorem reachable_store_invariants_witness
    : ∃ (w : Model.State) (sid : Nat) (s : Model.Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s := by
  exact Proofs.SemanticInvariant.semantic_reachable_store_invariants_witness

/-- Every semantic-reachable head has unique keys and bounded previous-write versions. -/
theorem reachable_store_data_invariants
    : ∀ (w : Model.State) (sid : Nat) (s : Model.Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → Unique s.head.data ∧ CellsBounded s.head.data s.head.version := by
  exact Proofs.SemanticInvariant.semantic_reachable_store_data_invariants

/-- Witness: semantic actions reach a store satisfying the data-safety premises. -/
theorem reachable_store_data_invariants_witness
    : ∃ (w : Model.State) (sid : Nat) (s : Model.Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s := by
  exact Proofs.SemanticInvariant.semantic_reachable_store_data_invariants_witness

/-- Every semantic-reachable captured program reproduces its writes on pinned local data. -/
theorem transaction_snapshot_serial
    : ∀ (w : Model.State) (tid : Nat) (t : Model.Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        → find w.txs tid = some t
        → t.snapshot = some snap
        → serialRun t.data [] t.normal.log = some t.normal.writes := by
  exact Proofs.SemanticInvariant.semantic_transaction_snapshot_serial

/-- Witness: a nonempty program is reachable using only semantic actions. -/
theorem transaction_snapshot_serial_witness
    : ∃ (w : Model.State) (tid : Nat) (t : Model.Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        ∧ find w.txs tid = some t
        ∧ t.snapshot = some snap
        ∧ t.normal.log ≠ [] := by
  exact Proofs.SemanticInvariant.semantic_transaction_snapshot_serial_witness

/-- Every OCC-valid semantic-reachable program serializes against the application head. -/
theorem transaction_application_serial
    : ∀ (w : Model.State) (sid tid : Nat) (s : Model.Store) (t : Model.Tx)
        (snap : Snapshot),
        Model.transitionSystem.Reachable w
        → Model.lookupTx w sid tid = some (s, t)
        → t.snapshot = some snap
        → canApply s t = true
        → serialRun s.head.data [] t.normal.log = some t.normal.writes := by
  exact Proofs.SemanticInvariant.semantic_transaction_application_serial

/-- Witness: a nonempty semantic-reachable program passes OCC. -/
theorem transaction_application_serial_witness
    : ∃ (w : Model.State) (sid tid : Nat) (s : Model.Store) (t : Model.Tx)
        (snap : Snapshot),
        Model.transitionSystem.Reachable w
        ∧ Model.lookupTx w sid tid = some (s, t)
        ∧ t.snapshot = some snap
        ∧ canApply s t = true
        ∧ t.normal.log ≠ [] := by
  exact Proofs.SemanticInvariant.semantic_transaction_application_serial_witness

/-- Application-order branches of arbitrary semantic-reachable programs serialize with compaction. -/
theorem executable_branch_serializability
    : ∀ (s final : Model.Store) (ts : List Model.Tx),
        (∀ t ∈ ts,
          ∃ (w : Model.State) (tid : Nat),
            Model.transitionSystem.Reachable w ∧ find w.txs tid = some t)
        → SemanticAppliedBranch s ts final
        → semanticSerialTransactions s.head.data s.head.version ts
          = some final.head.data := by
  exact Proofs.SemanticInvariant.semantic_executable_branch_serializability

/-- Witness: a nonempty application-order branch uses a semantic-reachable attempt. -/
theorem executable_branch_serializability_witness
    : ∃ (s final : Model.Store) (ts : List Model.Tx),
        (∀ t ∈ ts,
          ∃ (w : Model.State) (tid : Nat),
            Model.transitionSystem.Reachable w ∧ find w.txs tid = some t)
        ∧ SemanticAppliedBranch s ts final
        ∧ ts ≠ [] := by
  exact Proofs.SemanticInvariant.semantic_executable_branch_serializability_witness

/-- Actual semantic publication computes the complete multi-map effect and next version. -/
theorem application_atomic
    : ∀ (w next : Model.State) (sid tid version term : Nat) (writes : Pending),
        Model.execute w (.apply sid tid) = some (next, .applied version term writes)
        → ∃ (s : Model.Store) (t : Model.Tx),
            Model.lookupTx w sid tid = some (s, t)
            ∧ canApply s t = true
            ∧ writes = t.normal.writes
            ∧ version = s.head.version + 1
            ∧ term = s.term
            ∧ find next.stores sid = some (Model.advance s writes)
            ∧ (Model.advance s writes).head.data
              = publish s.head.data version writes := by
  exact Proofs.Semantics.semantic_apply_atomic

/-- Witness: an actual semantic publication affects two maps without a trace envelope. -/
theorem application_atomic_witness
    : ∃ (w next : Model.State) (sid tid version term : Nat) (writes : Pending),
        Model.execute w (.apply sid tid) = some (next, .applied version term writes)
        ∧ ∃ a b : Addr String String,
            a.1 ≠ b.1 ∧ find writes a ≠ none ∧ find writes b ≠ none := by
  exact Proofs.Semantics.semantic_apply_atomic_witness

/-- A staged put is visible to the transaction that staged it. -/
theorem read_your_write
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
        (a : Addr M K) (v : V),
        valueAt db (set ws a (some v)) a = some v := by
  exact Proofs.Core.read_your_write

/-- Witness: before a write is staged, the read can return a different value. -/
theorem read_your_write_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String) (v : String),
        valueAt db ws a ≠ some v := by
  exact Proofs.CoreWitnesses.read_your_write_witness

/-- A staged removal is visible to the transaction that staged it. -/
theorem read_your_deletion
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
        (a : Addr M K),
        valueAt db (set ws a none) a = none := by
  exact Proofs.Core.read_your_deletion

/-- Witness: before a removal is staged, the read can return a value. -/
theorem read_your_deletion_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        valueAt db ws a ≠ none := by
  exact Proofs.CoreWitnesses.read_your_deletion_witness

/-- A key neither staged nor committed reads as absent. -/
theorem absent_read
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
        (a : Addr M K),
        find ws a = none → find db a = none → valueAt db ws a = none := by
  exact Proofs.Core.absent_read

/-- Witness: a key can be neither staged nor committed. -/
theorem absent_read_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        find ws a = none ∧ find db a = none := by
  exact Proofs.CoreWitnesses.absent_read_witness

/-- Staging a write at one address does not change reads at another. -/
theorem staged_noninterference
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
        (a b : Addr M K) (v : Option V),
        a ≠ b → valueAt db (set ws a v) b = valueAt db ws b := by
  exact Proofs.Core.staged_noninterference

/-- Witness: two addresses can differ. -/
theorem staged_noninterference_witness : ∃ a b : Addr String String, a ≠ b := by
  exact Proofs.CoreWitnesses.staged_noninterference_witness

/-- Reading the committed version ignores staged writes. -/
theorem previous_ignores_pending
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (a : Addr M K),
        previousAt db a = (find db a).map Cell.version := by
  exact Proofs.Core.previous_ignores_pending

/-- Witness: a key can have both a committed version and a staged write. -/
theorem previous_ignores_pending_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        previousAt db a ≠ none ∧ find ws a ≠ none := by
  exact Proofs.CoreWitnesses.previous_ignores_pending_witness

/-- Publishing replaces each written cell, stamped with the new version, and keeps the rest. -/
theorem publish_lookup
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (version : Nat)
        (ws : Writes M K V) (a : Addr M K),
        find (publish db version ws) a
        = match find ws a with
          | none => find db a
          | some none => none
          | some (some v) => some { value := v, version } := by
  exact Proofs.Core.publish_lookup

/-- Witness: one write set can leave, remove and write addresses. -/
theorem publish_lookup_witness
    : ∃ (ws : Writes String String String) (kept removed written : Addr String String)
        (v : String),
        find ws kept = none
        ∧ find ws removed = some none
        ∧ find ws written = some (some v) := by
  exact Proofs.CoreWitnesses.publish_lookup_witness

/-- Publishing leaves unwritten addresses unchanged. -/
theorem publication_noninterference
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (version : Nat)
        (ws : Writes M K V) (a : Addr M K),
        find ws a = none → find (publish db version ws) a = find db a := by
  exact Proofs.Core.publication_noninterference

/-- Witness: an address can be unwritten. -/
theorem publication_noninterference_witness
    : ∃ (ws : Writes String String String) (a : Addr String String),
        find ws a = none := by
  exact Proofs.CoreWitnesses.publication_noninterference_witness

/-- Publishing preserves key uniqueness. -/
theorem publish_unique
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (version : Nat)
        (ws : Writes M K V),
        Unique db → Unique (publish db version ws) := by
  exact Proofs.Core.publish_unique

/-- Witness: a database can have unique keys. -/
theorem publish_unique_witness : ∃ db : DB String String String, Unique db := by
  exact Proofs.CoreWitnesses.publish_unique_witness

/-- Applying an attempt publishes its entire write set at the next version. -/
theorem apply_atomic
    : ∀ (s : Store) (writes : Pending),
        (advance s writes).head.data
        = publish s.head.data (s.head.version + 1) writes := by
  exact Proofs.Core.apply_atomic

/-- Witness: one applied write set can span two maps. -/
theorem apply_atomic_witness
    : ∃ (writes : Pending) (a b : Addr String String),
        a.1 ≠ b.1 ∧ find writes a ≠ none ∧ find writes b ≠ none := by
  exact Proofs.CoreWitnesses.apply_atomic_witness

/-- The global view of a map not yet created is the empty frame. -/
theorem captureGlobal_placeholder
    : ∀ (s : Store) (snap : Snapshot) (map : String),
        find (captureLocal s snap map).births map = none
        → (captureGlobal s snap map).frame = {} := by
  exact Proofs.Core.captureGlobal_placeholder

/-- An absent map witnesses empty global capture. -/
theorem captureGlobal_placeholder_witness
    : ∃ (s : Store) (snap : Snapshot) (map : String),
        find (captureLocal s snap map).births map = none := by
  exact Proofs.CoreWitnesses.captureGlobal_placeholder_witness

/-- The global view of an existing map is the store's global cut. -/
theorem captureGlobal_committed
    : ∀ (s : Store) (snap : Snapshot) (map : String) (birth : Stamp),
        find (captureLocal s snap map).births map = some birth
        → (captureGlobal s snap map).frame = atCut s s.global := by
  exact Proofs.Core.captureGlobal_committed

/-- A previously written map witnesses committed global capture. -/
theorem captureGlobal_committed_witness
    : ∃ (s : Store) (snap : Snapshot) (map : String) (birth : Stamp),
        find (captureLocal s snap map).births map = some birth := by
  exact Proofs.CoreWitnesses.captureGlobal_committed_witness

/-- Compacting beyond the head leaves the store unchanged. -/
theorem compact_above_head_noop
    : ∀ (s : Store) (v : Nat), s.head.version < v → compactStore s v = s := by
  exact Proofs.Core.compact_above_head_noop

/-- An above-head compaction request can occur. -/
theorem compact_above_head_noop_witness
    : ∃ (s : Store) (v : Nat), s.head.version < v := by
  exact Proofs.CoreWitnesses.compact_above_head_noop_witness

/-- Rollback keeps every frame at or below the global version. -/
theorem rollback_keeps_prefix
    : ∀ (s : Store) (v term : Nat) (f : Frame),
        f ∈ s.history → f.version ≤ s.global → f ∈ (rollbackStore s v term).history := by
  exact Proofs.Core.rollback_keeps_prefix

/-- A nonempty durable frame witnesses rollback prefix preservation. -/
theorem rollback_keeps_prefix_witness
    : ∃ (s : Store) (f : Frame), f ∈ s.history ∧ f.version ≤ s.global ∧ f.data ≠ [] := by
  exact Proofs.CoreWitnesses.rollback_keeps_prefix_witness

/-- Rollback discards every frame above the requested version. -/
theorem rollback_discards_suffix
    : ∀ (s : Store) (v term : Nat) (f : Frame),
        v < f.version → s.global ≤ v → f ∉ (rollbackStore s v term).history := by
  exact Proofs.Core.rollback_discards_suffix

/-- A nonempty suffix frame can be discarded by rollback. -/
theorem rollback_discards_suffix_witness
    : ∃ (s : Store) (v : Nat) (f : Frame),
        f ∈ s.history ∧ v < f.version ∧ s.global ≤ v := by
  exact Proofs.CoreWitnesses.rollback_discards_suffix_witness

/-- An attempt whose snapshot term differs from the store's cannot apply. -/
theorem stale_term_cannot_apply
    : ∀ (s : Store) (t : Tx) (snap : Snapshot),
        t.snapshot = some snap → s.term ≠ snap.term → canApply s t = false := by
  exact Proofs.Core.stale_term_cannot_apply

/-- A captured term can differ from the current store's term. -/
theorem stale_term_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot),
        t.snapshot = some snap ∧ s.term ≠ snap.term := by
  exact Proofs.CoreWitnesses.stale_term_cannot_apply_witness

/-- An attempt whose acquired map revision is no longer on the branch cannot apply. -/
theorem discarded_handle_cannot_apply
    : ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        → (m, view) ∈ t.globalViews
        → (∀ f ∈ s.history, (revision f m == revision view.current m) = false)
        → canApply s t = false := by
  exact Proofs.Core.discarded_handle_cannot_apply

/-- Rollback can remove the acquired map revision. -/
theorem discarded_handle_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (revision f m == revision view.current m) = false) := by
  exact Proofs.CoreWitnesses.discarded_handle_cannot_apply_witness

/-- An attempt whose acquired map creation is no longer on the branch cannot apply. -/
theorem discarded_birth_cannot_apply
    : ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        → (m, view) ∈ t.globalViews
        → (∀ f ∈ s.history, (find f.births m == find view.current.births m) = false)
        → canApply s t = false := by
  exact Proofs.Core.discarded_birth_cannot_apply

/-- Rollback can remove the acquired map birth identity. -/
theorem discarded_birth_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (find f.births m == find view.current.births m) = false) := by
  exact Proofs.CoreWitnesses.discarded_birth_cannot_apply_witness

/-- A map revised before the global cut's revision is unavailable. -/
theorem compacted_map_unavailable
    : ∀ (s : Store) (f : Frame) (m : String) (birth : Stamp),
        find f.births m = some birth
        → (revision f m).version < (revision (atCut s s.global) m).version
        → mapAvailable s f m = false := by
  exact Proofs.Core.compacted_map_unavailable

/-- A committed map revision can advance beyond an older local frame. -/
theorem compacted_map_unavailable_witness
    : ∃ (s : Store) (f : Frame) (m : String) (birth : Stamp),
        find f.births m = some birth
        ∧ (revision f m).version < (revision (atCut s s.global) m).version := by
  exact Proofs.CoreWitnesses.compacted_map_unavailable_witness

/-- A map that does not exist, has no data, and was never revised is available. -/
theorem absent_map_available
    : ∀ (s : Store) (f : Frame) (m : String),
        find f.births m = none
        → image f.data m = []
        → find f.revisions m = none
        → mapAvailable s f m = true := by
  exact Proofs.Core.absent_map_available

/-- Truly absent maps have empty data and no prior revision. -/
theorem absent_map_available_witness
    : ∃ (f : Frame) (m : String),
        find f.births m = none ∧ image f.data m = [] ∧ find f.revisions m = none := by
  exact Proofs.CoreWitnesses.absent_map_available_witness

/-- An available map that does not exist has no values. -/
theorem absent_placeholder_has_no_values
    : ∀ (s : Store) (f : Frame) (m key : String),
        find f.births m = none
        → mapAvailable s f m = true
        → find f.data (m, key) = none := by
  exact Proofs.Core.absent_placeholder_has_no_values

/-- The empty-map placeholder path is permitted. -/
theorem absent_placeholder_has_no_values_witness
    : ∃ (s : Store) (f : Frame) (m : String),
        find f.births m = none ∧ mapAvailable s f m = true := by
  exact Proofs.CoreWitnesses.absent_placeholder_has_no_values_witness

/-- Capturing a current snapshot computes the frozen head and commit term. -/
theorem step_capture_metadata
    : ∀ (w next : State) (sid tid : Nat) (s : Store) (t : Tx) (output : Output),
        find w.stores sid = some s
        → execute w (.snapshot sid tid) = some (next, output)
        → find next.txs tid = some t
        → ∃ snap,
            t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = s.term := by
  exact Proofs.Safety.step_capture_metadata

/-- An actual semantic snapshot witnesses capture metadata. -/
theorem step_capture_metadata_witness
    : ∃ (w next : State) (sid tid : Nat) (s : Store) (t : Tx) (output : Output),
        find w.stores sid = some s
        ∧ execute w (.snapshot sid tid) = some (next, output)
        ∧ find next.txs tid = some t := by
  exact Proofs.CoreWitnesses.step_capture_metadata_witness

/-- Snapshot output contains the actual local/global cuts and commit term. -/
theorem step_capture_cut_values
    : ∀ (w next : State) (sid tid version global term : Nat) (s : Store),
        find w.stores sid = some s
        → execute w (.snapshot sid tid) = some (next, .snapshot version global term)
        → version = s.head.version ∧ global = s.global ∧ term = s.term := by
  exact Proofs.Safety.step_capture_cut_values

/-- Snapshot output witnesses the source store's actual cuts. -/
theorem step_capture_cut_values_witness
    : ∃ (w next : State) (sid tid version global term : Nat) (s : Store),
        find w.stores sid = some s
        ∧ execute w (.snapshot sid tid) = some (next, .snapshot version global term) := by
  exact Proofs.CoreWitnesses.step_capture_cut_values_witness

/-- Semantic acquisition installs its selected local/global frames and computes their revisions. -/
theorem step_map_capture
    : ∀ (w next : State) (sid tid localVersion globalVersion : Nat) (map : String)
        (s : Store) (before after : Tx) (snap : Snapshot),
        lookupTx w sid tid = some (s, before)
        → before.snapshot = some snap
        → execute w (.acquire sid tid map)
          = some (next, .acquired localVersion globalVersion)
        → find next.txs tid = some after
        → find after.globalViews map = some (captureGlobal s snap map)
          ∧ localVersion = (revision (captureLocal s snap map) map).version
          ∧ globalVersion = (revision (captureGlobal s snap map).frame map).version := by
  exact Proofs.Safety.step_map_capture

/-- A semantic acquisition witnesses captured frames and revision outputs. -/
theorem step_map_capture_witness
    : ∃ (w next : State) (sid tid localVersion globalVersion : Nat) (map : String)
        (s : Store) (before after : Tx) (snap : Snapshot),
        lookupTx w sid tid = some (s, before)
        ∧ before.snapshot = some snap
        ∧ execute w (.acquire sid tid map)
          = some (next, .acquired localVersion globalVersion)
        ∧ find next.txs tid = some after := by
  exact Proofs.CoreWitnesses.step_map_capture_witness

/-- Every attempt-preserving semantic execution keeps an existing current snapshot fixed. -/
theorem execution_snapshot_fixed
    : ∀ (w final : State) (tid : Nat) (before : Tx) (snap : Snapshot)
        (inputs : List Action),
        find w.txs tid = some before
        → before.snapshot = some snap
        → (∀ a ∈ inputs, AttemptAction tid a)
        → CCF.Execution.Run transitionSystem w inputs final
        → ∃ after, find final.txs tid = some after ∧ after.snapshot = some snap := by
  exact Proofs.Safety.execution_snapshot_fixed

/-- A nonempty semantic execution preserves an already captured current frame. -/
theorem execution_snapshot_fixed_witness
    : ∃ (w final : State) (tid : Nat) (before : Tx) (snap : Snapshot)
        (actions : List Action),
        find w.txs tid = some before
        ∧ before.snapshot = some snap
        ∧ (∀ a ∈ actions, AttemptAction tid a)
        ∧ CCF.Execution.Run transitionSystem w actions final
        ∧ actions ≠ [] := by
  exact Proofs.CoreWitnesses.execution_snapshot_fixed_witness

/-- Every attempt-preserving semantic execution keeps already acquired global frames fixed. -/
theorem execution_map_global_fixed
    : ∀ (w final : State) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (inputs : List Action),
        find w.txs tid = some before
        → find before.globalViews map = some view
        → (∀ a ∈ inputs, AttemptAction tid a)
        → CCF.Execution.Run transitionSystem w inputs final
        → ∃ after,
            find final.txs tid = some after ∧ find after.globalViews map = some view := by
  exact Proofs.Safety.execution_map_global_fixed

/-- A nonempty semantic execution preserves an acquired global frame. -/
theorem execution_map_global_fixed_witness
    : ∃ (w final : State) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (actions : List Action),
        find w.txs tid = some before
        ∧ find before.globalViews map = some view
        ∧ (∀ a ∈ actions, AttemptAction tid a)
        ∧ CCF.Execution.Run transitionSystem w actions final
        ∧ actions ≠ [] := by
  exact Proofs.CoreWitnesses.execution_map_global_fixed_witness

/-- Later acquisitions and publications cannot change an already acquired map's pinned local data. -/
theorem execution_map_local_fixed
    : ∀ (w final : State) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (inputs : List Action),
        find w.txs tid = some before
        → find before.globalViews map = some view
        → (∀ a ∈ inputs, AttemptAction tid a)
        → CCF.Execution.Run transitionSystem w inputs final
        → ∃ after,
            find final.txs tid = some after
            ∧ image after.data map = image before.data map := by
  exact Proofs.Safety.execution_map_local_fixed

/-- Writes and application witness nonempty execution with fixed pinned local data. -/
theorem execution_map_local_fixed_witness
    : ∃ (w final : State) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (actions : List Action),
        find w.txs tid = some before
        ∧ find before.globalViews map = some view
        ∧ (∀ a ∈ actions, AttemptAction tid a)
        ∧ CCF.Execution.Run transitionSystem w actions final
        ∧ actions ≠ [] := by
  exact Proofs.CoreWitnesses.execution_map_local_fixed_witness

/-- Metadata computed by capture survives the rest of an attempt-preserving semantic execution. -/
theorem capture_execution_preserves_metadata
    : ∀ (w captured final : State) (sid tid : Nat) (s : Store) (t : Tx)
        (output : Output) (inputs : List Action),
        find w.stores sid = some s
        → execute w (.snapshot sid tid) = some (captured, output)
        → find captured.txs tid = some t
        → (∀ a ∈ inputs, AttemptAction tid a)
        → CCF.Execution.Run transitionSystem captured inputs final
        → ∃ after snap,
            find final.txs tid = some after
            ∧ after.snapshot = some snap
            ∧ snap.current = s.head
            ∧ snap.term = s.term := by
  exact Proofs.Safety.capture_execution_preserves_metadata

/-- Actual capture followed by a nonempty semantic execution witnesses metadata preservation. -/
theorem capture_execution_preserves_metadata_witness
    : ∃ (w captured final : State) (sid tid : Nat) (s : Store) (t : Tx)
        (output : Output) (actions : List Action),
        find w.stores sid = some s
        ∧ execute w (.snapshot sid tid) = some (captured, output)
        ∧ find captured.txs tid = some t
        ∧ (∀ a ∈ actions, AttemptAction tid a)
        ∧ CCF.Execution.Run transitionSystem captured actions final
        ∧ actions ≠ [] := by
  exact Proofs.CoreWitnesses.capture_execution_preserves_metadata_witness

/-- Acquired frames and computed revisions survive an attempt-preserving semantic execution. -/
theorem capture_execution_preserves_map
    : ∀ (w captured final : State) (sid tid localVersion globalVersion : Nat)
        (map : String) (s : Store) (before acquired : Tx) (snap : Snapshot)
        (inputs : List Action),
        lookupTx w sid tid = some (s, before)
        → before.snapshot = some snap
        → execute w (.acquire sid tid map)
          = some (captured, .acquired localVersion globalVersion)
        → find captured.txs tid = some acquired
        → (∀ a ∈ inputs, AttemptAction tid a)
        → CCF.Execution.Run transitionSystem captured inputs final
        → ∃ after,
            find final.txs tid = some after
            ∧ find after.globalViews map = some (captureGlobal s snap map)
            ∧ localVersion = (revision (captureLocal s snap map) map).version
            ∧ globalVersion
              = (revision (captureGlobal s snap map).frame map).version := by
  exact Proofs.Safety.capture_execution_preserves_map

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
        ∧ actions ≠ [] := by
  exact Proofs.CoreWitnesses.capture_execution_preserves_map_witness

/-- Global read outputs are computed from the frozen map frame with committed-prefix provenance. -/
theorem step_global_read_from_captured_map
    : ∀ (w next : State) (sid tid : Nat) (s : Store) (t : Tx) (map key : String)
        (value : Option String) (view : GlobalView),
        transitionSystem.Reachable w
        → lookupTx w sid tid = some (s, t)
        → find t.globalViews map = some view
        → execute w (.operation sid tid (.get map key true)) = some (next, .value value)
        → value = (find view.frame.data (map, key)).map Cell.value
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  exact Proofs.Safety.step_global_read_from_captured_map

/-- A present global value is produced by a reachable semantic execution. -/
theorem step_global_read_from_captured_map_witness
    : ∃ (w next : State) (sid tid : Nat) (s : Store) (t : Tx) (map key value : String)
        (view : GlobalView),
        transitionSystem.Reachable w
        ∧ lookupTx w sid tid = some (s, t)
        ∧ find t.globalViews map = some view
        ∧ execute w (.operation sid tid (.get map key true))
          = some (next, .value (some value)) := by
  exact Proofs.CoreWitnesses.step_global_read_from_captured_map_witness

/-- Global presence outputs are computed from the frozen frame with committed-prefix provenance. -/
theorem step_global_has_from_captured_map
    : ∀ (w next : State) (sid tid : Nat) (s : Store) (t : Tx) (map key : String)
        (value : Bool) (view : GlobalView),
        transitionSystem.Reachable w
        → lookupTx w sid tid = some (s, t)
        → find t.globalViews map = some view
        → execute w (.operation sid tid (.has map key true))
          = some (next, .presence value)
        → value = (find view.frame.data (map, key)).isSome
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  exact Proofs.Safety.step_global_has_from_captured_map

/-- Global presence is produced by a reachable semantic execution. -/
theorem step_global_has_from_captured_map_witness
    : ∃ (w next : State) (sid tid : Nat) (s : Store) (t : Tx) (map key : String)
        (view : GlobalView),
        transitionSystem.Reachable w
        ∧ lookupTx w sid tid = some (s, t)
        ∧ find t.globalViews map = some view
        ∧ execute w (.operation sid tid (.has map key true))
          = some (next, .presence true) := by
  exact Proofs.CoreWitnesses.step_global_has_from_captured_map_witness

/-- Actual semantic executions serialize the selected store's applications in their real order. -/
theorem execution_segment_serializability
    : ∀ (w final : State) (sid : Nat) (s : Store) (inputs : List Action),
        transitionSystem.Reachable w
        → find w.stores sid = some s
        → SegmentInputs w sid inputs
        → CCF.Execution.Run transitionSystem w inputs final
        → ∃ after txs,
            find final.stores sid = some after
            ∧ applicationInputs w sid inputs = some txs
            ∧ semanticSerialTransactions s.head.data s.head.version txs
              = some after.head.data
            ∧ after.head.version = s.head.version + txs.length := by
  exact Proofs.ModelExecution.execution_segment_serializability

/-- A nonempty actual semantic segment includes publication and compaction. -/
theorem execution_segment_serializability_witness
    : ∃ (w final : State) (sid : Nat) (s : Store) (actions : List Action),
        transitionSystem.Reachable w
        ∧ find w.stores sid = some s
        ∧ SegmentInputs w sid actions
        ∧ CCF.Execution.Run transitionSystem w actions final
        ∧ actions ≠ [] := by
  exact Proofs.CoreWitnesses.execution_segment_serializability_witness

/-- Rollback preserves the data at every cut at or below the global version. -/
theorem durable_cut_survives_rollback
    : ∀ (w : State) (sid v term cut : Nat) (s : Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → cut ≤ s.global
        → s.global ≤ v
        → (atCut (rollbackStore s v term) cut).data = (atCut s cut).data := by
  exact Proofs.SemanticInvariant.semantic_durable_cut_survives_rollback

/-- A reachable nonempty durable cut witnesses rollback safety. -/
theorem durable_cut_survives_rollback_witness
    : ∃ (w : State) (sid : Nat) (s : Store) (v cut : Nat),
        transitionSystem.Reachable w
        ∧ find w.stores sid = some s
        ∧ cut ≤ s.global
        ∧ s.global ≤ v
        ∧ (atCut s cut).data ≠ [] := by
  exact Proofs.CoreWitnesses.durable_cut_survives_rollback_witness

end Kv.Properties
