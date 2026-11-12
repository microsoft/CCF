-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Invariants
public import CCF.Execution

import Kv.Proofs.Reachable
import Kv.Proofs.Replay
import Kv.Proofs.Witnesses
import Kv.Proofs.Correspondence
import Kv.Proofs.Semantics
import Kv.Proofs.SemanticInvariant

@[expose] public section

/-!
# Human-reviewed KV properties

Review these statements with the definitions in `Kv/Model/`, `Kv/Model.lean`, and
`Kv/Properties/`. Each theorem links to its implementation in `Kv/Proofs/`.
Each claim with premises has an adjacent witness that its premises can hold.
-/

namespace Kv.Properties

open Kv.Model
      hiding Store Tx advance compactStore rollbackStore tryApply step transitionSystem
open Kv.TraceValidation

/-! ## Semantic execution and trace correspondence -/

/-- Every semantic-reachable store has a complete history, current head, and bounded global cut. -/
theorem semantic_reachable_store_invariants
    : ∀ (w : Model.State) (sid : Nat) (s : Model.Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → History s.history s.head.version
          ∧ s.history.head? = some s.head
          ∧ s.global ≤ s.head.version
          ∧ (atCut s s.global).version = s.global := by
  exact Proofs.SemanticInvariant.semantic_reachable_store_invariants

/-- Witness: semantic actions reach a live store without any trace metadata. -/
theorem semantic_reachable_store_invariants_witness
    : ∃ (w : Model.State) (sid : Nat) (s : Model.Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s := by
  exact Proofs.SemanticInvariant.semantic_reachable_store_invariants_witness

/-- Every semantic-reachable head has unique keys and bounded previous-write versions. -/
theorem semantic_reachable_store_data_invariants
    : ∀ (w : Model.State) (sid : Nat) (s : Model.Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → Unique s.head.data ∧ CellsBounded s.head.data s.head.version := by
  exact Proofs.SemanticInvariant.semantic_reachable_store_data_invariants

/-- Witness: semantic actions reach a store satisfying the data-safety premises. -/
theorem semantic_reachable_store_data_invariants_witness
    : ∃ (w : Model.State) (sid : Nat) (s : Model.Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s := by
  exact Proofs.SemanticInvariant.semantic_reachable_store_data_invariants_witness

/-- Every semantic-reachable captured program reproduces its writes on pinned local data. -/
theorem semantic_transaction_snapshot_serial
    : ∀ (w : Model.State) (tid : Nat) (t : Model.Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        → find w.txs tid = some t
        → t.snapshot = some snap
        → serialRun t.data [] t.normal.log = some t.normal.writes := by
  exact Proofs.SemanticInvariant.semantic_transaction_snapshot_serial

/-- Witness: a nonempty program is reachable using only semantic actions. -/
theorem semantic_transaction_snapshot_serial_witness
    : ∃ (w : Model.State) (tid : Nat) (t : Model.Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        ∧ find w.txs tid = some t
        ∧ t.snapshot = some snap
        ∧ t.normal.log ≠ [] := by
  exact Proofs.SemanticInvariant.semantic_transaction_snapshot_serial_witness

/-- Every OCC-valid semantic-reachable program serializes against the application head. -/
theorem semantic_transaction_application_serial
    : ∀ (w : Model.State) (sid tid : Nat) (s : Model.Store) (t : Model.Tx)
        (snap : Snapshot),
        Model.transitionSystem.Reachable w
        → Model.lookupTx w sid tid = some (s, t)
        → t.snapshot = some snap
        → canApply s t = true
        → serialRun s.head.data [] t.normal.log = some t.normal.writes := by
  exact Proofs.SemanticInvariant.semantic_transaction_application_serial

/-- Witness: a nonempty semantic-reachable program passes OCC. -/
theorem semantic_transaction_application_serial_witness
    : ∃ (w : Model.State) (sid tid : Nat) (s : Model.Store) (t : Model.Tx)
        (snap : Snapshot),
        Model.transitionSystem.Reachable w
        ∧ Model.lookupTx w sid tid = some (s, t)
        ∧ t.snapshot = some snap
        ∧ canApply s t = true
        ∧ t.normal.log ≠ [] := by
  exact Proofs.SemanticInvariant.semantic_transaction_application_serial_witness

/-- Application-order branches of arbitrary semantic-reachable programs serialize with compaction. -/
theorem semantic_executable_branch_serializability
    : ∀ (s final : Model.Store) (ts : List Model.Tx),
        (∀ t ∈ ts,
          ∃ (w : Model.State) (tid : Nat),
            Model.transitionSystem.Reachable w ∧ find w.txs tid = some t)
        → SemanticAppliedBranch s ts final
        → semanticSerialTransactions s.head.data s.head.version ts
          = some final.head.data := by
  exact Proofs.SemanticInvariant.semantic_executable_branch_serializability

/-- Witness: a nonempty application-order branch uses a semantic-reachable attempt. -/
theorem semantic_executable_branch_serializability_witness
    : ∃ (s final : Model.Store) (ts : List Model.Tx),
        (∀ t ∈ ts,
          ∃ (w : Model.State) (tid : Nat),
            Model.transitionSystem.Reachable w ∧ find w.txs tid = some t)
        ∧ SemanticAppliedBranch s ts final
        ∧ ts ≠ [] := by
  exact Proofs.SemanticInvariant.semantic_executable_branch_serializability_witness

/-- Actual semantic publication computes the complete multi-map effect and next version. -/
theorem semantic_apply_atomic
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
theorem semantic_apply_atomic_witness
    : ∃ (w next : Model.State) (sid tid version term : Nat) (writes : Pending),
        Model.execute w (.apply sid tid) = some (next, .applied version term writes)
        ∧ ∃ a b : Addr String String,
            a.1 ≠ b.1 ∧ find writes a ≠ none ∧ find writes b ≠ none := by
  exact Proofs.Semantics.semantic_apply_atomic_witness

/-- Every accepted trace record exercises the semantic model or stutters for bookkeeping. -/
theorem step_projects
    : ∀ (w next : World) (r : Record),
        TraceValidation.transitionSystem.step w r = some next
        → CCF.Execution.Run Model.transitionSystem (project w) (actions w r.event)
            (project next) := by
  exact Proofs.Correspondence.step_projects

/-- Witness: a nonempty input creates a semantic store, rather than only recording scopes. -/
theorem step_projects_witness
    : ∃ (w next : World) (r : Record),
        TraceValidation.transitionSystem.step w r = some next
        ∧ actions w r.event ≠ [] := by
  exact Proofs.Correspondence.step_projects_witness

/-- Reported observations match the actual output of the translated semantic execution. -/
theorem step_reports
    : ∀ (w next : World) (r : Record),
        TraceValidation.transitionSystem.step w r = some next
        → ∃ output,
            executeActions (project w) (actions w r.event) = some (project next, output)
            ∧ reportedMatches r.event output = true := by
  exact Proofs.Correspondence.step_reports

/-- Witness: a read report is checked against the semantic absence result. -/
theorem step_reports_witness
    : ∃ (w next : World) (r : Record),
        TraceValidation.transitionSystem.step w r = some next
        ∧ r.event = .get 1 1 "m" "k" none false := by
  exact Proofs.Correspondence.step_reports_witness

/-- Accepted typed replay executes exactly the inputs translated along its own worlds. -/
theorem replay_projects
    : ∀ (w final : World) (records : List Record),
        replay w records = .ok final
        → ∃ inputs,
            semanticInputs w records = .ok inputs
            ∧ CCF.Execution.Run Model.transitionSystem (project w) inputs
                (project final) := by
  exact Proofs.Correspondence.replay_projects

/-- Witness: a nonempty typed replay has a semantic execution. -/
theorem replay_projects_witness
    : ∃ (w final : World) (records : List Record),
        replay w records = .ok final ∧ records ≠ [] := by
  exact Proofs.Correspondence.replay_projects_witness

/-- Trace-reachable projections are reachable by the executable semantic system. -/
theorem reachable_projects
    : ∀ w : World,
        TraceValidation.transitionSystem.Reachable w
        → Model.transitionSystem.Reachable (project w) := by
  exact Proofs.Correspondence.reachable_projects

/-- Witness: such a projection contains a live semantic store. -/
theorem reachable_projects_witness
    : ∃ (w : World) (sid : Nat) (s : Model.Store),
        TraceValidation.transitionSystem.Reachable w
        ∧ find (project w).stores sid = some s := by
  exact Proofs.Correspondence.reachable_projects_witness

/-! ## Reads and atomic publication -/

/-- A staged put is visible to the transaction that staged it. -/
theorem read_your_write
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
        (a : Addr M K) (v : V),
        valueAt db (set ws a (some v)) a = some v := by
  exact Proofs.Model.read_your_write

/-- Witness: before a write is staged, the read can return a different value. -/
theorem read_your_write_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String) (v : String),
        valueAt db ws a ≠ some v := by
  exact Proofs.Witnesses.read_your_write_witness

/-- A staged removal is visible to the transaction that staged it. -/
theorem read_your_deletion
    : ∀ {M K V : Type} [DecidableEq M] [DecidableEq K] (db : DB M K V) (ws : Writes M K V)
        (a : Addr M K),
        valueAt db (set ws a none) a = none := by
  exact Proofs.Model.read_your_deletion

/-- Witness: before a removal is staged, the read can return a value. -/
theorem read_your_deletion_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        valueAt db ws a ≠ none := by
  exact Proofs.Witnesses.read_your_deletion_witness

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

/-- Witness: a key can have both a committed version and a staged write. -/
theorem previous_ignores_pending_witness
    : ∃ (db : DB String String String) (ws : Writes String String String)
        (a : Addr String String),
        previousAt db a ≠ none ∧ find ws a ≠ none := by
  exact Proofs.Witnesses.previous_ignores_pending_witness

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

/-- Witness: one write set can leave, remove and write addresses. -/
theorem publish_lookup_witness
    : ∃ (ws : Writes String String String) (kept removed written : Addr String String)
        (v : String),
        find ws kept = none
        ∧ find ws removed = some none
        ∧ find ws written = some (some v) := by
  exact Proofs.Witnesses.publish_lookup_witness

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

/-- Witness: one applied write set can span two maps. -/
theorem apply_atomic_witness
    : ∃ (writes : Pending) (a b : Addr String String),
        a.1 ≠ b.1 ∧ find writes a ≠ none ∧ find writes b ≠ none := by
  exact Proofs.Witnesses.apply_atomic_witness

/-! ## Serial snapshot runs and normal-view serializability -/

/-- An attempt's operation log runs serially on its pinned local views to its staged writes. -/
theorem transaction_snapshot_serial
    : ∀ (w : World) (tid : Nat) (t : Tx) (snap : Snapshot),
        TraceValidation.transitionSystem.Reachable w
        → find w.txs tid = some t
        → t.snapshot = some snap
        → serialRun t.data [] t.normal.log = some t.normal.writes := by
  exact Proofs.Properties.transaction_snapshot_serial

/-- Witness: an attempt with a snapshot can have a nonempty log. -/
theorem transaction_snapshot_serial_witness
    : ∃ (w : World) (tid : Nat) (t : Tx) (snap : Snapshot),
        TraceValidation.transitionSystem.Reachable w
        ∧ find w.txs tid = some t
        ∧ t.snapshot = some snap
        ∧ t.normal.log ≠ [] := by
  exact Proofs.Witnesses.transaction_snapshot_serial_witness

/-- An attempt that may apply runs serially on the current head to the same staged writes. -/
theorem transaction_application_serial
    : ∀ (w : World) (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot),
        TraceValidation.transitionSystem.Reachable w
        → storeOf w sid = .ok s
        → txOf w sid tid = .ok t
        → t.snapshot = some snap
        → canApply s t = true
        → serialRun s.head.data [] t.normal.log = some t.normal.writes := by
  exact Proofs.Properties.transaction_application_serial

/-- Witness: an attempt with a nonempty log can apply. -/
theorem transaction_application_serial_witness
    : ∃ (w : World) (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot),
        TraceValidation.transitionSystem.Reachable w
        ∧ storeOf w sid = .ok s
        ∧ txOf w sid tid = .ok t
        ∧ t.snapshot = some snap
        ∧ canApply s t = true
        ∧ t.normal.log ≠ [] := by
  exact Proofs.Witnesses.transaction_application_serial_witness

/-- A branch of applied attempts matches running their logs serially from the start. -/
theorem executable_branch_serializability
    : ∀ (s final : Store) (ts : List Tx),
        (∀ t ∈ ts,
          ∃ (w : World) (tid : Nat),
            TraceValidation.transitionSystem.Reachable w ∧ find w.txs tid = some t)
        → AppliedBranch s ts final
        → serialTransactions s.head.data s.head.version ts = some final.head.data := by
  exact Proofs.Properties.executable_branch_serializability

/-- Witness: a nonempty branch of applied attempts exists. -/
theorem executable_branch_serializability_witness
    : ∃ (s final : Store) (ts : List Tx),
        (∀ t ∈ ts,
          ∃ (w : World) (tid : Nat),
            TraceValidation.transitionSystem.Reachable w ∧ find w.txs tid = some t)
        ∧ AppliedBranch s ts final
        ∧ ts ≠ [] := by
  exact Proofs.Witnesses.executable_branch_serializability_witness

/-- In an accepted record segment that keeps store `sid` alive, the applications projected
onto that store run serially to its final head. -/
theorem replay_segment_serializability
    : ∀ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
        TraceValidation.transitionSystem.Reachable w
        → find w.stores sid = some s
        → (∀ r ∈ rs, SegmentEvent sid r.event)
        → CCF.Execution.Run TraceValidation.transitionSystem w rs final
        → ∃ after txs,
            find final.stores sid = some after
            ∧ projectApplications w sid rs = .ok txs
            ∧ serialTransactions s.head.data s.head.version txs = some after.head.data
            ∧ after.head.version = s.head.version + txs.length := by
  exact Proofs.Trace.replay_segment_serializability_claim

/-- Witness: an accepted nonempty segment can keep a store alive. -/
theorem replay_segment_serializability_witness
    : ∃ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
        TraceValidation.transitionSystem.Reachable w
        ∧ find w.stores sid = some s
        ∧ (∀ r ∈ rs, SegmentEvent sid r.event)
        ∧ CCF.Execution.Run TraceValidation.transitionSystem w rs final
        ∧ rs ≠ [] := by
  exact Proofs.Witnesses.replay_segment_serializability_witness

/-! ## Reachable store invariants -/

/-- Every live store in a reachable world has a well-formed history whose head is newest, and a
global version within it that is the version of its global cut. -/
theorem reachable_store_invariants
    : ∀ (w : World) (sid : Nat) (s : Store),
        TraceValidation.transitionSystem.Reachable w
        → find w.stores sid = some s
        → History s.history s.head.version
          ∧ s.history.head? = some s.head
          ∧ s.global ≤ s.head.version
          ∧ (atCut s s.global).version = s.global := by
  exact Proofs.Trace.reachable_store_invariants_claim

/-- Witness: a reachable world can have a live store. -/
theorem reachable_store_invariants_witness
    : ∃ (w : World) (sid : Nat) (s : Store),
        TraceValidation.transitionSystem.Reachable w ∧ find w.stores sid = some s := by
  exact Proofs.Witnesses.reachable_store_invariants_witness

/-- Every live store's head data in a reachable world has unique keys and versions no later than
the head. -/
theorem reachable_store_data_invariants
    : ∀ (w : World) (sid : Nat) (s : Store),
        TraceValidation.transitionSystem.Reachable w
        → find w.stores sid = some s
        → Unique s.head.data ∧ CellsBounded s.head.data s.head.version := by
  exact Proofs.Trace.reachable_store_data_invariants_claim

/-- Witness: a reachable world can have a live store. -/
theorem reachable_store_data_invariants_witness
    : ∃ (w : World) (sid : Nat) (s : Store),
        TraceValidation.transitionSystem.Reachable w ∧ find w.stores sid = some s := by
  exact Proofs.Witnesses.reachable_store_data_invariants_witness

/-! ## Current snapshot capture and preservation -/

/-- Capturing a snapshot records the store's head and the reported term. -/
theorem step_capture_metadata
    : ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store) (t : Tx),
        storeOf w sid = .ok s
        → TraceValidation.transitionSystem.step w
            ⟨seq, .snapshot sid tid version global term⟩
          = some next
        → find next.txs tid = some t
        → ∃ snap, t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = term := by
  exact Proofs.Trace.step_capture_metadata_claim

/-- Witness: a snapshot capture can be accepted. -/
theorem step_capture_metadata_witness
    : ∃ (w next : World) (sid tid version global term seq : Nat) (s : Store) (t : Tx),
        storeOf w sid = .ok s
        ∧ TraceValidation.transitionSystem.step w
            ⟨seq, .snapshot sid tid version global term⟩
          = some next
        ∧ find next.txs tid = some t := by
  exact Proofs.Witnesses.step_capture_metadata_witness

/-- An accepted snapshot capture reports the store's head and global versions. -/
theorem step_capture_cut_values
    : ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store),
        storeOf w sid = .ok s
        → TraceValidation.transitionSystem.step w
            ⟨seq, .snapshot sid tid version global term⟩
          = some next
        → version = s.head.version ∧ global = s.global := by
  exact Proofs.Trace.step_capture_cut_values_claim

/-- Witness: a snapshot capture can be accepted. -/
theorem step_capture_cut_values_witness
    : ∃ (w next : World) (sid tid version global term seq : Nat) (s : Store),
        storeOf w sid = .ok s
        ∧ TraceValidation.transitionSystem.step w
            ⟨seq, .snapshot sid tid version global term⟩
          = some next := by
  exact Proofs.Witnesses.step_capture_cut_values_witness

/-- A captured snapshot's head and term are unchanged by later records that do not end the
attempt. -/
theorem capture_replay_preserves_metadata
    : ∀ (w capturedWorld final : World) (sid tid version global term seq : Nat)
        (s : Store) (t : Tx) (tail : List Record),
        storeOf w sid = .ok s
        → TraceValidation.transitionSystem.step w
            ⟨seq, .snapshot sid tid version global term⟩
          = some capturedWorld
        → find capturedWorld.txs tid = some t
        → (∀ r ∈ tail, AttemptEvent tid r.event)
        → CCF.Execution.Run TraceValidation.transitionSystem capturedWorld tail final
        → ∃ after snap,
            find final.txs tid = some after
            ∧ after.snapshot = some snap
            ∧ snap.current = s.head
            ∧ snap.term = term := by
  exact Proofs.Trace.capture_replay_preserves_metadata_claim

/-- Witness: a snapshot capture can be followed by an accepted nonempty run that keeps the attempt. -/
theorem capture_replay_preserves_metadata_witness
    : ∃ (w capturedWorld final : World) (sid tid version global term seq : Nat)
        (s : Store) (t : Tx) (tail : List Record),
        storeOf w sid = .ok s
        ∧ TraceValidation.transitionSystem.step w
            ⟨seq, .snapshot sid tid version global term⟩
          = some capturedWorld
        ∧ find capturedWorld.txs tid = some t
        ∧ (∀ r ∈ tail, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run TraceValidation.transitionSystem capturedWorld tail final
        ∧ tail ≠ [] := by
  exact Proofs.Witnesses.capture_replay_preserves_metadata_witness

/-- An attempt's captured snapshot is unchanged by later records that do not end it. -/
theorem replay_snapshot_fixed
    : ∀ (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot) (rs : List Record),
        find w.txs tid = some before
        → before.snapshot = some snap
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run TraceValidation.transitionSystem w rs final
        → ∃ after, find final.txs tid = some after ∧ after.snapshot = some snap := by
  exact Proofs.Trace.replay_snapshot_fixed_claim

/-- Witness: an attempt with a snapshot can be followed by an accepted nonempty run that keeps it. -/
theorem replay_snapshot_fixed_witness
    : ∃ (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot) (rs : List Record),
        find w.txs tid = some before
        ∧ before.snapshot = some snap
        ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run TraceValidation.transitionSystem w rs final
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
        → TraceValidation.transitionSystem.step w
            ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some next
        → find next.txs tid = some after
        → find after.globalViews map = some (captureGlobal s snap map)
          ∧ localVersion = (revision (captureLocal s snap map) map).version
          ∧ globalVersion = (revision (captureGlobal s snap map).frame map).version := by
  exact Proofs.Trace.step_map_capture_claim

/-- Witness: a map acquisition can be accepted. -/
theorem step_map_capture_witness
    : ∃ (w next : World) (sid tid localVersion globalVersion seq : Nat) (map : String)
        (s : Store) (before after : Tx) (snap : Snapshot),
        storeOf w sid = .ok s
        ∧ txOf w sid tid = .ok before
        ∧ before.snapshot = some snap
        ∧ TraceValidation.transitionSystem.step w
            ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some next
        ∧ find next.txs tid = some after := by
  exact Proofs.Witnesses.step_map_capture_witness

/-- A map's captured local and global views are unchanged by later records that do not end the attempt. -/
theorem replay_map_global_fixed
    : ∀ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        → find before.globalViews map = some view
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run TraceValidation.transitionSystem w rs final
        → ∃ after,
            find final.txs tid = some after ∧ find after.globalViews map = some view := by
  exact Proofs.Trace.replay_map_global_fixed_claim

/-- Witness: an attempt with an acquired map can be followed by an accepted nonempty run that keeps it. -/
theorem replay_map_global_fixed_witness
    : ∃ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        ∧ find before.globalViews map = some view
        ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run TraceValidation.transitionSystem w rs final
        ∧ rs ≠ [] := by
  exact Proofs.Witnesses.replay_map_global_fixed_witness

/-- Acquired local data is unchanged by later records, including rollback and other map acquisitions. -/
theorem replay_map_local_fixed
    : ∀ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        → find before.globalViews map = some view
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run TraceValidation.transitionSystem w rs final
        → ∃ after,
            find final.txs tid = some after
            ∧ image after.data map = image before.data map := by
  exact Proofs.Trace.replay_map_local_fixed_claim

/-- Witness: an acquired map can survive a nonempty accepted segment. -/
theorem replay_map_local_fixed_witness
    : ∃ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        ∧ find before.globalViews map = some view
        ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run TraceValidation.transitionSystem w rs final
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
        → TraceValidation.transitionSystem.step w
            ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some capturedWorld
        → find capturedWorld.txs tid = some capturedTx
        → (∀ r ∈ tail, AttemptEvent tid r.event)
        → CCF.Execution.Run TraceValidation.transitionSystem capturedWorld tail final
        → ∃ after,
            find final.txs tid = some after
            ∧ find after.globalViews map = some (captureGlobal s snap map)
            ∧ localVersion = (revision (captureLocal s snap map) map).version
            ∧ globalVersion
              = (revision (captureGlobal s snap map).frame map).version := by
  exact Proofs.Trace.capture_replay_preserves_map_claim

/-- Witness: a map acquisition can be followed by an accepted nonempty run that keeps the attempt. -/
theorem capture_replay_preserves_map_witness
    : ∃ (w capturedWorld final : World) (sid tid localVersion globalVersion seq : Nat)
        (map : String) (s : Store) (before capturedTx : Tx) (snap : Snapshot)
        (tail : List Record),
        storeOf w sid = .ok s
        ∧ txOf w sid tid = .ok before
        ∧ before.snapshot = some snap
        ∧ TraceValidation.transitionSystem.step w
            ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some capturedWorld
        ∧ find capturedWorld.txs tid = some capturedTx
        ∧ (∀ r ∈ tail, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run TraceValidation.transitionSystem capturedWorld tail final
        ∧ tail ≠ [] := by
  exact Proofs.Witnesses.capture_replay_preserves_map_witness

/-- The global view of a map not yet created is the empty frame. -/
theorem captureGlobal_placeholder
    : ∀ (s : Store) (snap : Snapshot) (map : String),
        find (captureLocal s snap map).births map = none
        → (captureGlobal s snap map).frame = {} := by
  exact Proofs.Trace.captureGlobal_placeholder

/-- Witness: a snapshot can lack a map. -/
theorem captureGlobal_placeholder_witness
    : ∃ (s : Store) (snap : Snapshot) (map : String),
        find (captureLocal s snap map).births map = none := by
  exact Proofs.Witnesses.captureGlobal_placeholder_witness

/-- The global view of an existing map is the store's global cut. -/
theorem captureGlobal_committed
    : ∀ (s : Store) (snap : Snapshot) (map : String) (birth : Stamp),
        find (captureLocal s snap map).births map = some birth
        → (captureGlobal s snap map).frame = atCut s s.global := by
  exact Proofs.Trace.captureGlobal_committed

/-- Witness: a snapshot can contain a map. -/
theorem captureGlobal_committed_witness
    : ∃ (s : Store) (snap : Snapshot) (map : String) (birth : Stamp),
        find (captureLocal s snap map).births map = some birth := by
  exact Proofs.Witnesses.captureGlobal_committed_witness

/-- A global read returns the captured view's value, and that view is empty or a store's global
cut with no cell newer than it. -/
theorem step_global_read_from_captured_map
    : ∀ (w next : World) (sid tid seq : Nat) (map key : String) (value : Option String)
        (t : Tx) (view : GlobalView),
        TraceValidation.transitionSystem.Reachable w
        → txOf w sid tid = .ok t
        → find t.globalViews map = some view
        → TraceValidation.transitionSystem.step w ⟨seq, .get sid tid map key value true⟩
          = some next
        → value = (find view.frame.data (map, key)).map Cell.value
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  exact Proofs.Trace.step_global_read_from_captured_map_claim

/-- Witness: a global read of a committed value can be accepted. -/
theorem step_global_read_from_captured_map_witness
    : ∃ (w next : World) (sid tid seq : Nat) (map key value : String) (t : Tx)
        (view : GlobalView),
        TraceValidation.transitionSystem.Reachable w
        ∧ txOf w sid tid = .ok t
        ∧ find t.globalViews map = some view
        ∧ TraceValidation.transitionSystem.step w
            ⟨seq, .get sid tid map key (some value) true⟩
          = some next := by
  exact Proofs.Witnesses.step_global_read_from_captured_map_witness

/-- A global presence test reflects the captured view, and that view is empty or a store's
global cut with no cell newer than it. -/
theorem step_global_has_from_captured_map
    : ∀ (w next : World) (sid tid seq : Nat) (map key : String) (value : Bool) (t : Tx)
        (view : GlobalView),
        TraceValidation.transitionSystem.Reachable w
        → txOf w sid tid = .ok t
        → find t.globalViews map = some view
        → TraceValidation.transitionSystem.step w ⟨seq, .has sid tid map key value true⟩
          = some next
        → value = (find view.frame.data (map, key)).isSome
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  exact Proofs.Trace.step_global_has_from_captured_map_claim

/-- Witness: a global presence test of a committed key can be accepted. -/
theorem step_global_has_from_captured_map_witness
    : ∃ (w next : World) (sid tid seq : Nat) (map key : String) (t : Tx)
        (view : GlobalView),
        TraceValidation.transitionSystem.Reachable w
        ∧ txOf w sid tid = .ok t
        ∧ find t.globalViews map = some view
        ∧ TraceValidation.transitionSystem.step w ⟨seq, .has sid tid map key true true⟩
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
    : ∀ (w : World) (sid : Nat) (s : Store) (v term cut : Nat),
        TraceValidation.transitionSystem.Reachable w
        → find w.stores sid = some s
        → cut ≤ s.global
        → s.global ≤ v
        → (atCut (rollbackStore s v term) cut).data = (atCut s cut).data := by
  exact Proofs.Properties.durable_cut_survives_rollback

/-- Witness: a nonempty cut can be at or below the global version. -/
theorem durable_cut_survives_rollback_witness
    : ∃ (w : World) (sid : Nat) (s : Store) (v cut : Nat),
        TraceValidation.transitionSystem.Reachable w
        ∧ find w.stores sid = some s
        ∧ cut ≤ s.global
        ∧ s.global ≤ v
        ∧ (atCut s cut).data ≠ [] := by
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
        → (∀ f ∈ s.history, (revision f m == revision view.current m) = false)
        → canApply s t = false := by
  exact Proofs.Properties.discarded_handle_cannot_apply

/-- Witness: an attempt can hold a map whose revision is no longer on the branch. -/
theorem discarded_handle_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (revision f m == revision view.current m) = false) := by
  exact Proofs.Witnesses.discarded_handle_cannot_apply_witness

/-- An attempt whose acquired map creation is no longer on the branch cannot apply. -/
theorem discarded_birth_cannot_apply
    : ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        → (m, view) ∈ t.globalViews
        → (∀ f ∈ s.history, (find f.births m == find view.current.births m) = false)
        → canApply s t = false := by
  exact Proofs.Properties.discarded_birth_cannot_apply

/-- Witness: an attempt can hold a map whose creation is no longer on the branch. -/
theorem discarded_birth_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (find f.births m == find view.current.births m) = false) := by
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
