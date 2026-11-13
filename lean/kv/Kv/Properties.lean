-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Invariants
public import CCF.Execution
public import CCF.Witnessed

import Kv.Proofs.Claims
import Kv.Proofs.Witnesses

@[expose] public section

/-!
# Human-reviewed KV properties

Review these statements with the definitions in `Kv/Model/`, `Kv/Model.lean`, and
`Kv/Properties/`. Each theorem links to its implementation in `Kv/Proofs/`.
Each claim with premises has a witness that its premises can hold.
A claim stated with `witnessed% ∀ xs, { pre := p, post := q, witness := w }` is both
`∀ xs, p → q` and the witness `∃ xs, p ∧ w`.
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

/-- An attempt's operation log runs serially on its pinned local views to its staged writes.
Witness: an attempt with a snapshot can have a nonempty log. -/
theorem transaction_snapshot_serial
    : witnessed% ∀ (w : World) (tid : Nat) (t : Tx) (snap : Snapshot),
                  {
                    pre :=
                      Model.transitionSystem.Reachable w
                      ∧ find w.txs tid = some t
                      ∧ t.snapshot = some snap
                    post := serialRun t.data [] t.normal.log = some t.normal.writes
                    witness := t.normal.log ≠ []
                  } := by
  exact Proofs.Claims.transaction_snapshot_serial

/-- An attempt that may apply runs serially on the current head to the same staged writes.
Witness: an attempt with a nonempty log can apply. -/
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
                  } := by
  exact Proofs.Claims.transaction_application_serial

/-- A branch of applied attempts matches running their logs serially from the start.
Witness: a nonempty branch of applied attempts exists. -/
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
                  } := by
  exact Proofs.Claims.executable_branch_serializability

/-- In an accepted record segment that keeps store `sid` alive, the applications projected
onto that store run serially to its final head.
Witness: an accepted nonempty segment can keep a store alive. -/
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
                  } := by
  exact Proofs.Claims.replay_segment_serializability

/-! ## Reachable store invariants -/

/-- Every live store in a reachable world has a well-formed history whose head is newest, and a
global version within it that is the version of its global cut.
Witness: a reachable world can have a live store. -/
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
                  } := by
  exact Proofs.Claims.reachable_store_invariants

/-- Every live store's head data in a reachable world has unique keys and versions no later than
the head.
Witness: a reachable world can have a live store. -/
theorem reachable_store_data_invariants
    : witnessed% ∀ (w : World) (sid : Nat) (s : Store),
                  {
                    pre :=
                      Model.transitionSystem.Reachable w ∧ find w.stores sid = some s
                    post := Unique s.head.data ∧ CellsBounded s.head.data s.head.version
                  } := by
  exact Proofs.Claims.reachable_store_data_invariants

/-! ## Current snapshot capture and preservation -/

/-- Capturing a snapshot records the store's head and the reported term.
Witness: a snapshot capture can be accepted. -/
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
                  } := by
  exact Proofs.Claims.step_capture_metadata

/-- An accepted snapshot capture reports the store's head and global versions.
Witness: a snapshot capture can be accepted. -/
theorem step_capture_cut_values
    : witnessed% ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store),
                  {
                    pre :=
                      storeOf w sid = .ok s
                      ∧ Model.transitionSystem.step w
                          ⟨seq, .snapshot sid tid version global term⟩
                        = some next
                    post := version = s.head.version ∧ global = s.global
                  } := by
  exact Proofs.Claims.step_capture_cut_values

/-- A captured snapshot's head and term are unchanged by later records that do not end the
attempt.
Witness: a snapshot capture can be followed by an accepted nonempty run that keeps the attempt. -/
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
                  } := by
  exact Proofs.Claims.capture_replay_preserves_metadata

/-- An attempt's captured snapshot is unchanged by later records that do not end it.
Witness: an attempt with a snapshot can be followed by an accepted nonempty run that keeps it. -/
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
                  } := by
  exact Proofs.Claims.replay_snapshot_fixed

/-! ## Per-map globally committed views -/

/-- Acquiring a map records its global view and checks the reported revision versions.
Witness: a map acquisition can be accepted. -/
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
                  } := by
  exact Proofs.Claims.step_map_capture

/-- A map's captured local and global views are unchanged by later records that do not end the attempt.
Witness: an attempt with an acquired map can be followed by an accepted nonempty run that keeps it. -/
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
                  } := by
  exact Proofs.Claims.replay_map_global_fixed

/-- Acquired local data is unchanged by later records, including rollback and other map acquisitions.
Witness: an acquired map can survive a nonempty accepted segment. -/
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
                  } := by
  exact Proofs.Claims.replay_map_local_fixed

/-- A map acquisition's global view and reported versions persist through later records that do
not end the attempt.
Witness: a map acquisition can be followed by an accepted nonempty run that keeps the attempt. -/
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
                  } := by
  exact Proofs.Claims.capture_replay_preserves_map

/-- The global view of a map not yet created is the empty frame.
Witness: a snapshot can lack a map. -/
theorem captureGlobal_placeholder
    : witnessed% ∀ (s : Store) (snap : Snapshot) (map : String),
                  {
                    pre :=
                      find (captureLocal s snap map).births map = none
                    post := (captureGlobal s snap map).frame = {}
                  } := by
  exact Proofs.Claims.captureGlobal_placeholder

/-- The global view of an existing map is the store's global cut.
Witness: a snapshot can contain a map. -/
theorem captureGlobal_committed
    : witnessed% ∀ (s : Store) (snap : Snapshot) (map : String) (birth : Stamp),
                  {
                    pre :=
                      find (captureLocal s snap map).births map = some birth
                    post := (captureGlobal s snap map).frame = atCut s s.global
                  } := by
  exact Proofs.Claims.captureGlobal_committed

/-- A global read returns the captured view's value, and that view is empty or a store's global
cut with no cell newer than it.
Witness: a global read of a committed value can be accepted. -/
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
                  } := by
  exact Proofs.Claims.step_global_read_from_captured_map

/-- A global presence test reflects the captured view, and that view is empty or a store's
global cut with no cell newer than it.
Witness: a global presence test of a committed key can be accepted. -/
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
                  } := by
  exact Proofs.Claims.step_global_has_from_captured_map

/-! ## Compaction, rollback, and invalidated attempts -/

/-- Compacting beyond the head leaves the store unchanged.
Witness: a version can be beyond the head. -/
theorem compact_above_head_noop
    : witnessed% ∀ (s : Store) (v : Nat),
                  {
                    pre :=
                      s.head.version < v
                    post := compactStore s v = s
                  } := by
  exact Proofs.Claims.compact_above_head_noop

/-- Rollback keeps every frame at or below the global version.
Witness: a nonempty frame can be on the branch at or below the global version. -/
theorem rollback_keeps_prefix
    : witnessed% ∀ (s : Store) (v term : Nat) (f : Frame),
                  {
                    pre := f ∈ s.history ∧ f.version ≤ s.global
                    post := f ∈ (rollbackStore s v term).history
                    witness := f.data ≠ []
                  } := by
  exact Proofs.Claims.rollback_keeps_prefix

/-- Rollback discards every frame above the requested version.
Witness: a frame on the branch can be above a version at or above the global version. -/
theorem rollback_discards_suffix
    : witnessed% ∀ (s : Store) (v term : Nat) (f : Frame),
                  {
                    pre := v < f.version ∧ s.global ≤ v
                    post := f ∉ (rollbackStore s v term).history
                    witness := f ∈ s.history
                  } := by
  exact Proofs.Claims.rollback_discards_suffix

/-- Rollback preserves the data at every cut at or below the global version.
Witness: a nonempty cut can be at or below the global version. -/
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
                  } := by
  exact Proofs.Claims.durable_cut_survives_rollback

/-- An attempt whose snapshot term differs from the store's cannot apply.
Witness: an attempt's snapshot term can differ from the store's. -/
theorem stale_term_cannot_apply
    : witnessed% ∀ (s : Store) (t : Tx) (snap : Snapshot),
                  {
                    pre :=
                      t.snapshot = some snap ∧ s.term ≠ snap.term
                    post := canApply s t = false
                  } := by
  exact Proofs.Claims.stale_term_cannot_apply

/-- An attempt whose acquired map revision is no longer on the branch cannot apply.
Witness: an attempt can hold a map whose revision is no longer on the branch. -/
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
                  } := by
  exact Proofs.Claims.discarded_handle_cannot_apply

/-- An attempt whose acquired map creation is no longer on the branch cannot apply.
Witness: an attempt can hold a map whose creation is no longer on the branch. -/
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
                  } := by
  exact Proofs.Claims.discarded_birth_cannot_apply

/-- A map revised before the global cut's revision is unavailable.
Witness: a map can be revised before the global cut's revision. -/
theorem compacted_map_unavailable
    : witnessed% ∀ (s : Store) (f : Frame) (m : String) (birth : Stamp),
                  {
                    pre :=
                      find f.births m = some birth
                      ∧ (revision f m).version < (revision (atCut s s.global) m).version
                    post := mapAvailable s f m = false
                  } := by
  exact Proofs.Claims.compacted_map_unavailable

/-- A map that does not exist, has no data, and was never revised is available.
Witness: a map can be absent, empty, and unrevised. -/
theorem absent_map_available
    : witnessed% ∀ (s : Store) (f : Frame) (m : String),
                  {
                    pre :=
                      find f.births m = none
                      ∧ image f.data m = []
                      ∧ find f.revisions m = none
                    post := mapAvailable s f m = true
                  } := by
  exact Proofs.Claims.absent_map_available

/-- An available map that does not exist has no values.
Witness: an absent map can be available. -/
theorem absent_placeholder_has_no_values
    : witnessed% ∀ (s : Store) (f : Frame) (m key : String),
                  {
                    pre := find f.births m = none ∧ mapAvailable s f m = true
                    post := find f.data (m, key) = none
                  } := by
  exact Proofs.Claims.absent_placeholder_has_no_values

end Kv.Properties
