-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Invariants
public import CCF.Execution

/-!
Non-vacuity witnesses for the claims in `Kv.Properties`, together with the executable model's
read, publication and store claims. Trace claims are witnessed by prefixes and segments of one
accepted trace, evaluated by the kernel; store claims by directly constructed stores; read and
publication claims by small concrete association lists.

Each proof module under `Kv/Proofs/` is self-contained: lemmas needed by more than one module are
duplicated as private declarations, so the proof modules do not import each other and Lake can
check them in parallel. This layout is chosen to minimize verification wall-clock time.
-/

@[expose] public section

namespace Kv.Proofs.Execution
end Kv.Proofs.Execution

namespace Kv.Proofs.Invariants
end Kv.Proofs.Invariants

namespace Kv.Proofs.Model
end Kv.Proofs.Model

namespace Kv.Proofs.Trace
end Kv.Proofs.Trace

namespace Kv.Proofs.Properties
end Kv.Proofs.Properties

namespace Kv.Proofs.Witnesses
end Kv.Proofs.Witnesses

namespace Kv.Proofs.Execution

open Kv.Model

private theorem step_iff_transition (w next : World) (r : Record)
    : transitionSystem.step w r = some next ↔ step w r = .ok next := by
  simp only [transitionSystem]
  cases step w r <;> simp [Except.toOption]

end Kv.Proofs.Execution

namespace Kv.Proofs.Invariants

open Kv.Model Kv.Properties

/-- Store histories are contiguous, headed by the current frame, and contain the global cut. -/
private structure StoreInvariant (s : Store) : Prop where
  /-- Every frame follows by publishing writes to its predecessor. -/
  historyShape : History s.history s.head.version
  /-- The head is the newest frame. -/
  headFirst : s.history.head? = some s.head
  /-- The global version does not exceed the head. -/
  globalBound : s.global ≤ s.head.version

end Kv.Proofs.Invariants

namespace Kv.Proofs.Invariants

open Kv.Model Kv.Properties
variable {M K V : Type}

private theorem find_set_same [DecidableEq K] (xs : Assoc K V) (k : K) (v : V)
    : find (set xs k v) k = some v := by
  simp [Model.set, find]

private theorem find_erase_same [DecidableEq K] (xs : Assoc K V) (k : K)
    : find (erase xs k) k = none := by
  induction xs with
  | nil => rfl
  | cons p xs ih =>
      rcases p with ⟨a, v⟩
      by_cases h : a = k <;> simp_all [erase, find]

private theorem find_erase_other [DecidableEq K] (xs : Assoc K V) (a k : K) (h : a ≠ k)
    : find (erase xs a) k = find xs k := by
  induction xs with
  | nil => rfl
  | cons p xs ih =>
      rcases p with ⟨b, v⟩
      by_cases hba : b = a <;> by_cases hbk : b = k <;> simp_all [erase, find]

private theorem find_set_other [DecidableEq K] (xs : Assoc K V) (a k : K) (v : V)
    (h : a ≠ k)
    : find (set xs a v) k = find xs k := by
  simp [Model.set, find, h, find_erase_other xs a k h]

private theorem history_extension (s : Store) (valid : StoreInvariant s) (f : Frame)
    (writes : Pending) (version : f.version = s.head.version + 1)
    (data : f.data = publish s.head.data (s.head.version + 1) writes)
    : History (f :: s.history) (s.head.version + 1) :=
  .succ f s.head.version s.history version
    ⟨writes, by simpa only [valid.headFirst, Option.getD_some] using data⟩
    valid.historyShape

private theorem store_initial : StoreInvariant {} :=
  ⟨.zero, rfl, Nat.le_refl 0⟩

private theorem advance_invariant (s : Store) (valid : StoreInvariant s)
    (writes : Pending)
    : StoreInvariant (advance s writes) :=
  ⟨
    history_extension s valid _ writes rfl rfl,
    rfl,
    Nat.le_trans valid.globalBound (Nat.le_succ _)
  ⟩

private theorem bind_ok {α β : Type} {x : Except Failure α} {f : α → Except Failure β}
    {b : β} (h : (x >>= f) = .ok b)
    : ∃ a, x = .ok a ∧ f a = .ok b := by
  cases x with
  | error => cases h
  | ok a => exact ⟨a, rfl, h⟩

private theorem pure_ok {α : Type} {a b : α} (h : (pure a : Except Failure α) = .ok b)
    : a = b := by
  cases h; rfl

private theorem withTx_ok {w next : World} {sid tid : Nat} {f : Tx → Except Failure Tx}
    (h : withTx w sid tid f = .ok next)
    : ∃ t t',
        txOf w sid tid = .ok t
        ∧ f t = .ok t'
        ∧ next = { w with txs := set w.txs tid t' } := by
  obtain ⟨t, tx, h⟩ := bind_ok h
  obtain ⟨t', f, h⟩ := bind_ok h
  exact ⟨t, t', tx, f, (pure_ok h).symm⟩

private theorem present_ok {α : Type} {value : Option α} {message : String} {a : α}
    (h : present value message = .ok a)
    : value = some a := by
  cases value with
  | none => cases h
  | some => cases h; rfl

private theorem require_ok {condition : Bool} {message : String} {u : Unit}
    (h : require condition message = .ok u)
    : condition = true := by
  cases condition
  · cases h
  · rfl

private theorem expect_ok {condition : Bool} {message : String} {u : Unit}
    (h : expect condition message = .ok u)
    : condition = true := by
  cases condition
  · cases h
  · rfl

private theorem acquireMap_ok {s : Store} {t next : Tx} {map : String}
    {version global : Nat} (accepted : acquireMap s t map version global = .ok next)
    : ∃ snap,
        t.snapshot = some snap
        ∧ find t.globalViews map = none
        ∧ (version = (revision (captureGlobal s snap map).current map).version
            ∧ global = (revision (captureGlobal s snap map).frame map).version)
        ∧ t.normal.log.all (fun op => op.map != map) = true
        ∧ next
          = {
            t with
              globalViews := set t.globalViews map (captureGlobal s snap map)
              data := pinData t.data map (captureGlobal s snap map).current.data
          } := by
  obtain ⟨_, -, accepted⟩ := bind_ok accepted
  obtain ⟨_, -, accepted⟩ := bind_ok accepted
  obtain ⟨snap, captured, accepted⟩ := bind_ok accepted
  obtain ⟨_, fresh, accepted⟩ := bind_ok accepted
  obtain ⟨_, versions, accepted⟩ := bind_ok accepted
  obtain ⟨_, -, accepted⟩ := bind_ok accepted
  split at accepted
  next unused =>
    cases pure_ok accepted
    have versions := expect_ok versions
    simp only [Bool.and_eq_true, beq_iff_eq] at versions
    exact ⟨snap, present_ok captured, Option.isNone_iff_eq_none.mp (require_ok fresh), versions,
      unused, rfl⟩
  next => cases accepted

private theorem step_ok {w next : World} {r : Record} (accepted : step w r = .ok next)
    : ∃ eventNext,
        stepEvent w r.event = .ok eventNext
        ∧ next = { eventNext with lastSeq := some r.seq, count := w.count + 1 } := by
  obtain ⟨_, -, accepted⟩ := bind_ok accepted
  obtain ⟨_, -, accepted⟩ := bind_ok accepted
  obtain ⟨seq, event⟩ := r
  dsimp only at accepted ⊢
  split at accepted <;> try split at accepted
  all_goals first
    | obtain ⟨_, invalid, -⟩ := bind_ok accepted; cases invalid
    | obtain ⟨eventNext, event, accepted⟩ := bind_ok accepted
      exact ⟨eventNext, event, (pure_ok accepted).symm⟩

end Kv.Proofs.Invariants

namespace Kv.Proofs.Model

open Kv.Model Kv.Proofs.Invariants Kv.Properties
section Generic
variable {M K V : Type} [DecidableEq M] [DecidableEq K]

private theorem find_image (db : DB M K V) (m : M) (key : K)
    : find (image db m) key = find db (m, key) := by
  induction db with
  | nil => rfl
  | cons entry db ih =>
      rcases entry with ⟨⟨map, k⟩, cell⟩
      by_cases hm : map = m <;> by_cases hk : k = key <;>
        simp_all [image, find, Prod.mk.injEq]

private theorem empty_map_has_no_values (db : DB M K V) (m : M) (key : K)
    (empty : image db m = [])
    : find db (m, key) = none := by
  rw [← find_image, empty]
  rfl

private theorem erase_keys (xs : Assoc K V) (k : K)
    : (erase xs k).map Prod.fst = (xs.map Prod.fst).filter (· != k) :=
  (List.filter_map (f := Prod.fst) (p := (· != k)) (l := xs)).symm

private theorem erase_unique (xs : Assoc K V) (k : K) (h : Kv.Properties.Unique xs)
    : Kv.Properties.Unique (erase xs k) := by
  unfold Kv.Properties.Unique
  rw [erase_keys]
  exact List.Pairwise.filter _ h

private theorem set_unique (xs : Assoc K V) (k : K) (v : V) (h : Kv.Properties.Unique xs)
    : Kv.Properties.Unique (set xs k v) := by
  simp only [Kv.Properties.Unique, Model.set, List.map_cons, List.nodup_cons]
  constructor
  · simp [erase_keys, eq_comm]
  · exact erase_unique xs k h

theorem publish_lookup (db : DB M K V) (version : Nat) (ws : Writes M K V) (a : Addr M K)
    : find (publish db version ws) a
      = match find ws a with
        | none => find db a
        | some none => none
        | some (some v) => some { value := v, version } := by
  induction ws with
  | nil => rfl
  | cons p ws ih =>
      rcases p with ⟨b, value⟩
      by_cases h : b = a
      · subst b
        cases value <;> simp [publish, find, find_set_same, find_erase_same]
      · cases value <;> simp [publish, find, h, find_set_other, find_erase_other, ← ih, publish]

theorem publish_unique (db : DB M K V) (version : Nat) (ws : Writes M K V)
    (h : Kv.Properties.Unique db)
    : Kv.Properties.Unique (publish db version ws) := by
  induction ws with
  | nil => exact h
  | cons p ws ih =>
      rcases p with ⟨a, v⟩
      cases v with
      | none => exact erase_unique _ a ih
      | some value => exact set_unique _ a ⟨value, version⟩ ih

theorem publication_noninterference (db : DB M K V) (version : Nat)
    (ws : Writes M K V) (a : Addr M K) (h : find ws a = none)
    : find (publish db version ws) a = find db a := by
  simp [publish_lookup, h]

theorem read_your_write (db : DB M K V) (ws : Writes M K V) (a : Addr M K) (v : V)
    : valueAt db (set ws a (some v)) a = some v := by
  simp [valueAt, find_set_same]

theorem read_your_deletion (db : DB M K V) (ws : Writes M K V) (a : Addr M K)
    : valueAt db (set ws a none) a = none := by
  simp [valueAt, find_set_same]

theorem absent_read (db : DB M K V) (ws : Writes M K V) (a : Addr M K)
    (hw : find ws a = none) (hd : find db a = none)
    : valueAt db ws a = none := by
  simp [valueAt, hw, hd]

theorem staged_noninterference (db : DB M K V) (ws : Writes M K V)
    (a b : Addr M K) (v : Option V) (h : a ≠ b)
    : valueAt db (set ws a v) b = valueAt db ws b := by
  simp [valueAt, find_set_other ws a b v h]

theorem previous_ignores_pending (db : DB M K V) (a : Addr M K)
    : previousAt db a = (find db a).map Cell.version :=
  rfl

end Generic
end Kv.Proofs.Model

namespace Kv.Proofs.Model

open Kv.Model Kv.Proofs.Invariants Kv.Properties

theorem apply_atomic (s : Store) (writes : Pending)
    : (advance s writes).head.data = publish s.head.data (s.head.version + 1) writes :=
  rfl

theorem compact_above_head_noop (s : Store) (v : Nat) (h : s.head.version < v)
    : compactStore s v = s := by
  simp [compactStore, Nat.not_le.mpr h]

theorem compacted_map_unavailable (s : Store) (f : Frame) (m : String)
    (birth : Stamp) (existing : find f.births m = some birth)
    (h : (revision f m).version < (revision (atCut s s.global) m).version)
    : mapAvailable s f m = false := by
  simp [mapAvailable, existing, Nat.not_le.mpr h]

theorem absent_map_available (s : Store) (f : Frame) (m : String)
    (absent : find f.births m = none) (empty : image f.data m = [])
    (unwritten : find f.revisions m = none)
    : mapAvailable s f m = true := by
  simp [mapAvailable, absent, empty, unwritten]

theorem absent_placeholder_has_no_values (s : Store) (f : Frame) (m key : String)
    (absent : find f.births m = none) (permitted : mapAvailable s f m = true)
    : find f.data (m, key) = none := by
  have empty : image f.data m = [] := by
    have checked : image f.data m = [] ∧ find f.revisions m = none := by
      simpa [mapAvailable, absent] using permitted
    exact checked.1
  exact empty_map_has_no_values f.data m key empty

theorem rollback_keeps_prefix (s : Store) (v term : Nat) (f : Frame)
    (h : f ∈ s.history) (hv : f.version ≤ s.global)
    : f ∈ (rollbackStore s v term).history := by
  simp only [rollbackStore, List.mem_filter, decide_eq_true_eq]
  exact ⟨h, Nat.le_trans hv (Nat.le_max_left _ _)⟩

theorem rollback_discards_suffix (s : Store) (v term : Nat) (f : Frame)
    (h : v < f.version) (boundary : s.global ≤ v)
    : f ∉ (rollbackStore s v term).history := by
  have hbound : rollbackCut s v ≤ v := Nat.max_le.mpr ⟨boundary, Nat.min_le_right _ _⟩
  simp [rollbackStore, Nat.not_le.mpr (Nat.lt_of_le_of_lt hbound h)]

theorem stale_term_cannot_apply (s : Store) (t : Tx) (snap : Snapshot)
    (hs : t.snapshot = some snap) (ht : s.term ≠ snap.term)
    : canApply s t = false := by
  simp [canApply, validLineage, hs, ht]

private theorem discarded_handle_cannot_apply (s : Store) (t : Tx) (snap : Snapshot)
    (hs : t.snapshot = some snap) (m : String) (view : GlobalView)
    (hm : (m, view) ∈ t.globalViews)
    (gone : ∀ f ∈ s.history, (revision f m == revision view.current m) = false)
    : canApply s t = false := by
  apply Bool.eq_false_iff.mpr
  intro h
  have hh : (!t.unavailable = true ∧ validLineage s t = true) ∧
      validates s.head.data t.normal.deps = true := by simpa [canApply] using h
  have hp : (s.term == snap.term) = true ∧
      t.globalViews.all (fun (name, view) => mapLineage s view.current name) = true := by
    simpa [validLineage, hs] using hh.1.2
  have hall := hp.2
  have hit := List.all_eq_true.mp hall (m, view) hm
  obtain ⟨f, hf, he⟩ := List.any_eq_true.mp hit
  simp [gone f hf] at he

private theorem discarded_birth_cannot_apply (s : Store) (t : Tx) (snap : Snapshot)
    (hs : t.snapshot = some snap) (m : String) (view : GlobalView)
    (hm : (m, view) ∈ t.globalViews)
    (gone : ∀ f ∈ s.history, (find f.births m == find view.current.births m) = false)
    : canApply s t = false := by
  apply Bool.eq_false_iff.mpr
  intro h
  have hh : (!t.unavailable = true ∧ validLineage s t = true) ∧
      validates s.head.data t.normal.deps = true := by simpa [canApply] using h
  have hp : (s.term == snap.term) = true ∧
      t.globalViews.all (fun (name, view) => mapLineage s view.current name) = true := by
    simpa [validLineage, hs] using hh.1.2
  have hit := List.all_eq_true.mp hp.2 (m, view) hm
  obtain ⟨f, hf, he⟩ := List.any_eq_true.mp hit
  simp [gone f hf] at he

end Kv.Proofs.Model

namespace Kv.Proofs.Trace

open Kv.Model Kv.Proofs.Invariants Kv.Properties Kv.Proofs.Model

private theorem step_event_result (w next : World) (r : Record)
    (accepted : step w r = .ok next)
    : ∃ eventNext,
        stepEvent w r.event = .ok eventNext
        ∧ next.stores = eventNext.stores
        ∧ next.txs = eventNext.txs := by
  obtain ⟨eventNext, event, rfl⟩ := step_ok accepted
  exact ⟨eventNext, event, rfl, rfl⟩

private theorem stepEvent_capture_metadata (w next : World)
    (sid tid version global term : Nat) (s : Store) (t : Tx)
    (source : storeOf w sid = .ok s)
    (accepted : stepEvent w (.snapshot sid tid version global term) = .ok next)
    (capturedTx : find next.txs tid = some t)
    : ∃ snap, t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = term := by
  refine ⟨{ current := s.head, term }, ?_, rfl, rfl⟩
  obtain ⟨_, store, accepted⟩ := bind_ok accepted
  cases source.symm.trans store
  obtain ⟨_, _, -, h, rfl⟩ := withTx_ok accepted
  obtain ⟨_, -, h⟩ := bind_ok h
  split at h
  · obtain ⟨_, -, h⟩ := bind_ok h
    cases pure_ok h
    simp only [find_set_same, Option.some.injEq] at capturedTx
    subst capturedTx
    rfl
  · cases h

private theorem step_capture_metadata (w next : World)
    (sid tid version global term seq : Nat) (s : Store) (t : Tx)
    (source : storeOf w sid = .ok s)
    (accepted : step w ⟨seq, .snapshot sid tid version global term⟩ = .ok next)
    (capturedTx : find next.txs tid = some t)
    : ∃ snap, t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = term := by
  obtain ⟨eventNext, eventStep, _, txs⟩ := step_event_result w next _ accepted
  exact stepEvent_capture_metadata w eventNext sid tid version global term s t source
    eventStep (by simpa [txs] using capturedTx)

private theorem stepEvent_capture_cut_values (w next : World)
    (sid tid version global term : Nat) (s : Store) (source : storeOf w sid = .ok s)
    (accepted : stepEvent w (.snapshot sid tid version global term) = .ok next)
    : version = s.head.version ∧ global = s.global := by
  obtain ⟨_, store, accepted⟩ := bind_ok accepted
  cases source.symm.trans store
  obtain ⟨_, _, -, h, -⟩ := withTx_ok accepted
  obtain ⟨_, -, h⟩ := bind_ok h
  split at h
  · obtain ⟨_, metadata, -⟩ := bind_ok h
    have metadata := expect_ok metadata
    simp only [Bool.and_eq_true, beq_iff_eq] at metadata
    exact metadata.1
  · cases h

theorem captureGlobal_placeholder (s : Store) (snap : Snapshot) (map : String)
    (absent : find (captureLocal s snap map).births map = none)
    : (captureGlobal s snap map).frame = {} := by
  simp [captureGlobal, absent]

theorem captureGlobal_committed (s : Store) (snap : Snapshot) (map : String)
    (birth : Stamp) (existing : find (captureLocal s snap map).births map = some birth)
    : (captureGlobal s snap map).frame = atCut s s.global := by
  simp [captureGlobal, existing]

private theorem stepEvent_map_capture (w next : World)
    (sid tid localVersion globalVersion : Nat) (map : String) (s : Store)
    (before after : Tx) (snap : Snapshot) (store : storeOf w sid = .ok s)
    (tx : txOf w sid tid = .ok before) (snapshot : before.snapshot = some snap)
    (accepted : stepEvent w (.acquire sid tid map localVersion globalVersion) = .ok next)
    (live : find next.txs tid = some after)
    : find after.globalViews map = some (captureGlobal s snap map)
      ∧ localVersion = (revision (captureLocal s snap map) map).version
      ∧ globalVersion = (revision (captureGlobal s snap map).frame map).version := by
  have captureGlobal_current (s : Store) (snap : Snapshot) (map : String)
      : (captureGlobal s snap map).current = captureLocal s snap map := by
    dsimp only [captureGlobal]
    split <;> rfl
  obtain ⟨_, store', accepted⟩ := bind_ok accepted
  cases store.symm.trans store'
  obtain ⟨_, _, tx', h, rfl⟩ := withTx_ok accepted
  cases tx.symm.trans tx'
  obtain ⟨_, captured, -, versions, _, rfl⟩ := acquireMap_ok h
  cases snapshot.symm.trans captured
  simp only [find_set_same, Option.some.injEq] at live
  subst live
  rw [captureGlobal_current] at versions
  exact ⟨find_set_same _ _ _, versions⟩

private theorem step_map_capture (w next : World)
    (sid tid localVersion globalVersion seq : Nat) (map : String) (s : Store)
    (before after : Tx) (snap : Snapshot) (store : storeOf w sid = .ok s)
    (tx : txOf w sid tid = .ok before) (snapshot : before.snapshot = some snap)
    (accepted : step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩ = .ok next)
    (live : find next.txs tid = some after)
    : find after.globalViews map = some (captureGlobal s snap map)
      ∧ localVersion = (revision (captureLocal s snap map) map).version
      ∧ globalVersion = (revision (captureGlobal s snap map).frame map).version := by
  obtain ⟨eventNext, eventStep, _, txs⟩ := step_event_result w next _ accepted
  exact stepEvent_map_capture w eventNext sid tid localVersion globalVersion map s before
    after snap store tx snapshot eventStep (by simpa [txs] using live)

theorem step_capture_metadata_claim
    : ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store) (t : Tx),
        storeOf w sid = .ok s
        → Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next
        → find next.txs tid = some t
        → ∃ snap, t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = term := by
  intro w next sid tid version global term seq s t source accepted capturedTx
  exact Proofs.Trace.step_capture_metadata w next sid tid version global term seq s t source ((Proofs.Execution.step_iff_transition _ _ _).mp accepted) capturedTx

theorem step_capture_cut_values_claim
    : ∀ (w next : World) (sid tid version global term seq : Nat) (s : Store),
        storeOf w sid = .ok s
        → Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next
        → version = s.head.version ∧ global = s.global := by
  have step_capture_cut_values (w next : World) (sid tid version global term seq : Nat)
      (s : Store) (source : storeOf w sid = .ok s)
      (accepted : step w ⟨seq, .snapshot sid tid version global term⟩ = .ok next)
      : version = s.head.version ∧ global = s.global := by
    obtain ⟨eventNext, eventStep, _, _⟩ := step_event_result w next _ accepted
    exact stepEvent_capture_cut_values w eventNext sid tid version global term s source eventStep
  intro w next sid tid version global term seq s source accepted
  exact step_capture_cut_values w next sid tid version global term seq s source
    ((Proofs.Execution.step_iff_transition _ _ _).mp accepted)

theorem step_map_capture_claim
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

end Kv.Proofs.Trace

namespace Kv.Proofs.Properties

open Kv.Model Kv.Properties

theorem discarded_handle_cannot_apply
    : ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        → (m, view) ∈ t.globalViews
        → (∀ f ∈ s.history, (revision f m == revision view.current m) = false)
        → canApply s t = false := by
  intro s t snap m view hs hm gone
  exact Proofs.Model.discarded_handle_cannot_apply s t snap hs m view hm gone

theorem discarded_birth_cannot_apply
    : ∀ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        → (m, view) ∈ t.globalViews
        → (∀ f ∈ s.history, (find f.births m == find view.current.births m) = false)
        → canApply s t = false := by
  intro s t snap m view hs hm gone
  exact Proofs.Model.discarded_birth_cannot_apply s t snap hs m view hm gone

end Kv.Proofs.Properties

namespace Kv.Proofs.Witnesses

open Kv.Model Kv.Properties Kv.Proofs.Invariants

private instance (sid : Nat) : DecidablePred (SegmentEvent sid) :=
  fun e => by
    cases e <;> unfold SegmentEvent <;> infer_instance

private instance (tid : Nat) : DecidablePred (AttemptEvent tid) :=
  fun e => by
    cases e <;> unfold AttemptEvent <;> infer_instance

/-- One attempt writes a key and commits; after compaction, a second reads it globally. -/
private def trace : List Record :=
  [
    ⟨1, .traceStart 1⟩,
    ⟨2, .caseBegin "witness"⟩,
    ⟨3, .storeCreate 1⟩,
    ⟨4, .txCreate 1 1⟩,
    ⟨5, .snapshot 1 1 0 0 0⟩,
    ⟨6, .acquire 1 1 "a" 0 0⟩,
    ⟨7, .put 1 1 "a" "00" "11"⟩,
    ⟨8, .commitBegin 1 1⟩,
    ⟨9, .apply 1 1 1 0 [(("a", "00"), some "11")]⟩,
    ⟨10, .commitResult 1 1 .success 1⟩,
    ⟨11, .txEnd 1 1⟩,
    ⟨12, .compact 1 1 1⟩,
    ⟨13, .txCreate 1 2⟩,
    ⟨14, .snapshot 1 2 1 1 0⟩,
    ⟨15, .acquire 1 2 "a" 1 1⟩,
    ⟨16, .get 1 2 "a" "00" (some "11") true⟩,
    ⟨17, .has 1 2 "a" "00" true true⟩
  ]

/-- The `n + 1`th record of `trace`. -/
private def record (n : Nat) : Record := trace.getD n ⟨0, .traceEnd 0⟩

/-- The world after the first `n` records of `trace`, defined step by step so the kernel
evaluates each prefix once; a rejected record would yield the empty world. -/
private def world : Nat → World
  | 0 => {}
  | n + 1 => ((step (world n) (record n)).toOption).getD {}

/-- The first `n` records of `trace` are accepted. -/
private def accepted : Nat → Bool
  | 0 => true
  | n + 1 => accepted n && (step (world n) (record n)).toOption.isSome

/-- Store `sid` of `world n`. -/
private def storeAt (n sid : Nat) : Store := (find (world n).stores sid).getD {}

/-- Attempt `tid` of `world n`. -/
private def txAt (n tid : Nat) : Tx := (find (world n).txs tid).getD { store := 0 }

/-- A store that has applied one write to map `a`. -/
private def written : Store := advance {} [(("a", "00"), some "11")]

private def writtenSnapshot : Snapshot := ⟨written.head, 0⟩

/-- An attempt that acquired map `a` in `writtenSnapshot`. -/
private def writtenTx : Tx :=
  {
    store := 1,
    snapshot := some writtenSnapshot,
    globalViews := [("a", captureGlobal written writtenSnapshot "a")]
  }

/-- The concrete facts the witnesses need, checked together by one kernel evaluation so that
each world and store is computed once. -/
private structure Facts : Prop where
  accepted : accepted 17 = true
  store3 : (find (world 3).stores 1).isSome = true
  segment3 : ∀ r ∈ (List.range' 3 9).map record, SegmentEvent 1 r.event
  store4 : (find (world 4).stores 1).isSome = true
  tx5 : (find (world 5).txs 1).isSome = true
  snapshot5 : (txAt 5 1).snapshot.isSome = true
  attempt5 : ∀ r ∈ (List.range' 5 5).map record, AttemptEvent 1 r.event
  tx7 : (find (world 7).txs 1).isSome = true
  snapshot7 : (txAt 7 1).snapshot.isSome = true
  log7 : (txAt 7 1).normal.log ≠ []
  store8 : (find (world 8).stores 1).isSome = true
  tx8 : (find (world 8).txs 1).isSome = true
  owner8 : (txAt 8 1).store = 1
  snapshot8 : (txAt 8 1).snapshot.isSome = true
  canApply8 : canApply (storeAt 8 1) (txAt 8 1) = true
  log8 : (txAt 8 1).normal.log ≠ []
  store12 : (find (world 12).stores 1).isSome = true
  cut12 : 1 ≤ (storeAt 12 1).global
  bound12 : (storeAt 12 1).global ≤ 1
  durable12 : (atCut (storeAt 12 1) 1).data ≠ []
  store13 : (find (world 13).stores 1).isSome = true
  store14 : (find (world 14).stores 1).isSome = true
  tx14 : (find (world 14).txs 2).isSome = true
  owner14 : (txAt 14 2).store = 1
  snapshot14 : (txAt 14 2).snapshot.isSome = true
  store15 : (find (world 15).stores 1).isSome = true
  tx15 : (find (world 15).txs 2).isSome = true
  owner15 : (txAt 15 2).store = 1
  view15 : (find (txAt 15 2).globalViews "a").isSome = true
  attempt15 : ∀ r ∈ (List.range' 15 2).map record, AttemptEvent 2 r.event
  store16 : (find (world 16).stores 1).isSome = true
  tx16 : (find (world 16).txs 2).isSome = true
  owner16 : (txAt 16 2).store = 1
  view16 : (find (txAt 16 2).globalViews "a").isSome = true
  captured : (find (captureLocal written writtenSnapshot "a").births "a").isSome = true
  compactedHead : (compactStore written 1).head.version ≤ (compactStore written 1).global
  compactedData : (compactStore written 1).head.data ≠ []
  writtenHead : 0 < written.head.version
  writtenGlobal : written.global ≤ 0
  discardedRevision
    : ∀ f ∈ (rollbackStore written 0 1).history,
        (revision f "a"
          == revision (captureGlobal written writtenSnapshot "a").current "a")
        = false
  discardedBirth
    : ∀ f ∈ (rollbackStore written 0 1).history,
        (find f.births "a"
          == find (captureGlobal written writtenSnapshot "a").current.births "a")
        = false
  birth : (find written.head.births "a").isSome = true
  compacted
    : (revision written.head "a").version
      < (revision
          (atCut (compactStore (advance written [(("a", "00"), some "22")]) 2)
            (compactStore (advance written [(("a", "00"), some "22")]) 2).global)
          "a").version

/-- A single Boolean check implying every hypothesis `A` of a curried constructor
`A → ... → R`. -/
private class Checks (F R : Prop) where
  /-- Every hypothesis holds. -/
  check : Bool
  /-- A passing check discharges every hypothesis. -/
  sound : check = true → F → R

private instance (R : Prop) : Checks R R := ⟨true, fun _ mk => mk⟩

private instance (A F R : Prop) [Decidable A] [rest : Checks F R] : Checks (A → F) R where
  check := decide A && rest.check
  sound h mk :=
    have h := Bool.and_eq_true_iff.mp h
    rest.sound h.2 (mk (of_decide_eq_true h.1))

private theorem facts : Facts := Checks.sound (by decide +kernel) Facts.mk

private theorem step_world {n : Nat} (all : accepted 17 = true) (lt : n < 17)
    : transitionSystem.step (world n) (record n) = some (world (n + 1)) := by
  have accepted_le {m n : Nat} (le : m ≤ n) (h : accepted n = true)
      : accepted m = true := by
    induction le with
    | refl => exact h
    | step _ ih =>
        simp only [accepted, Bool.and_eq_true] at h
        exact ih h.1
  have h := accepted_le lt all
  simp only [accepted, Bool.and_eq_true] at h
  simp only [transitionSystem, world]
  cases hs : step (world n) (record n) with
  | error => simp [hs, Except.toOption] at h
  | ok => rfl

private theorem world_reachable {n : Nat} (all : accepted 17 = true) (le : n ≤ 17)
    : transitionSystem.Reachable (world n) := by
  induction n with
  | zero => exact .initial rfl
  | succ n ih => exact .step (ih (Nat.le_of_succ_le le)) (step_world all le)

private theorem run_world {i k : Nat} (all : accepted 17 = true) (le : i + k ≤ 17)
    : CCF.Execution.Run transitionSystem (world i) ((List.range' i k).map record)
        (world (i + k)) := by
  induction k generalizing i with
  | zero => exact .nil _
  | succ k ih =>
      have same : i + (k + 1) = i + 1 + k :=
        (Nat.add_assoc i k 1).symm.trans (Nat.add_right_comm i k 1)
      rw [same]
      exact .cons (step_world all (Nat.lt_of_lt_of_le (Nat.lt_add_of_pos_right (Nat.succ_pos k)) le))
        (ih (same ▸ le))

private theorem some_get {α : Type} {o : Option α} (h : o.isSome = true)
    : o = some (o.get h) :=
  (Option.some_get h).symm

private theorem find_store {n sid : Nat} (h : (find (world n).stores sid).isSome = true)
    : find (world n).stores sid = some (storeAt n sid) := by
  unfold storeAt
  cases found : find (world n).stores sid with
  | none => simp [found] at h
  | some => rfl

private theorem find_tx {n tid : Nat} (h : (find (world n).txs tid).isSome = true)
    : find (world n).txs tid = some (txAt n tid) := by
  unfold txAt
  cases found : find (world n).txs tid with
  | none => simp [found] at h
  | some => rfl

private theorem storeOf_world {n sid : Nat}
    (h : (find (world n).stores sid).isSome = true)
    : storeOf (world n) sid = .ok (storeAt n sid) := by
  simp only [storeOf, find_store h, present]

private theorem txOf_world {n sid tid : Nat}
    (store : (find (world n).stores sid).isSome = true)
    (tx : (find (world n).txs tid).isSome = true) (owner : (txAt n tid).store = sid)
    : txOf (world n) sid tid = .ok (txAt n tid) := by
  simp [txOf, storeOf_world store, find_tx tx, present, require, owner, bind, Except.bind]
  rfl

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

theorem transaction_snapshot_serial_witness
    : ∃ (w : World) (tid : Nat) (t : Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        ∧ find w.txs tid = some t
        ∧ t.snapshot = some snap
        ∧ t.normal.log ≠ [] :=
  ⟨
    world 7,
    1,
    txAt 7 1,
    _,
    world_reachable facts.accepted (by decide),
    find_tx facts.tx7,
    some_get facts.snapshot7,
    facts.log7
  ⟩

theorem transaction_application_serial_witness
    : ∃ (w : World) (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        ∧ storeOf w sid = .ok s
        ∧ txOf w sid tid = .ok t
        ∧ t.snapshot = some snap
        ∧ canApply s t = true
        ∧ t.normal.log ≠ [] :=
  ⟨
    world 8,
    1,
    1,
    storeAt 8 1,
    txAt 8 1,
    _,
    world_reachable facts.accepted (by decide),
    storeOf_world facts.store8,
    txOf_world facts.store8 facts.tx8 facts.owner8,
    some_get facts.snapshot8,
    facts.canApply8,
    facts.log8
  ⟩

theorem executable_branch_serializability_witness
    : ∃ (s final : Store) (ts : List Tx),
        (∀ t ∈ ts,
          ∃ (w : World) (tid : Nat),
            Model.transitionSystem.Reachable w ∧ find w.txs tid = some t)
        ∧ AppliedBranch s ts final
        ∧ ts ≠ [] :=
  ⟨
    storeAt 8 1,
    advance (storeAt 8 1) (txAt 8 1).normal.writes,
    [txAt 8 1],
    List.forall_mem_singleton.mpr
      ⟨world 8, 1, world_reachable facts.accepted (by decide), find_tx facts.tx8⟩,
    .cons _ _ _ _ _ (by simp [tryApply, facts.canApply8]) (.nil _),
    List.cons_ne_nil _ _
  ⟩

theorem replay_segment_serializability_witness
    : ∃ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
        Model.transitionSystem.Reachable w
        ∧ find w.stores sid = some s
        ∧ (∀ r ∈ rs, SegmentEvent sid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem w rs final
        ∧ rs ≠ [] :=
  ⟨
    world 3,
    _,
    1,
    _,
    (List.range' 3 9).map record,
    world_reachable facts.accepted (by decide),
    find_store facts.store3,
    facts.segment3,
    run_world facts.accepted (by decide),
    List.cons_ne_nil _ _
  ⟩

private theorem reachable_live_store
    : ∃ (w : World) (sid : Nat) (s : Store),
        transitionSystem.Reachable w ∧ find w.stores sid = some s :=
  ⟨world 12, 1, _, world_reachable facts.accepted (by decide), find_store facts.store12⟩

theorem reachable_store_invariants_witness
    : ∃ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s :=
  reachable_live_store

theorem reachable_store_data_invariants_witness
    : ∃ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s :=
  reachable_live_store

theorem step_capture_metadata_witness
    : ∃ (w next : World) (sid tid version global term seq : Nat) (s : Store) (t : Tx),
        storeOf w sid = .ok s
        ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next
        ∧ find next.txs tid = some t :=
  ⟨
    world 13,
    _,
    1,
    2,
    1,
    1,
    0,
    14,
    _,
    _,
    storeOf_world facts.store13,
    step_world facts.accepted (by decide),
    find_tx facts.tx14
  ⟩

theorem step_capture_cut_values_witness
    : ∃ (w next : World) (sid tid version global term seq : Nat) (s : Store),
        storeOf w sid = .ok s
        ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some next :=
  ⟨
    world 13,
    _,
    1,
    2,
    1,
    1,
    0,
    14,
    _,
    storeOf_world facts.store13,
    step_world facts.accepted (by decide)
  ⟩

theorem capture_replay_preserves_metadata_witness
    : ∃ (w capturedWorld final : World) (sid tid version global term seq : Nat)
        (s : Store) (t : Tx) (tail : List Record),
        storeOf w sid = .ok s
        ∧ Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some capturedWorld
        ∧ find capturedWorld.txs tid = some t
        ∧ (∀ r ∈ tail, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem capturedWorld tail final
        ∧ tail ≠ [] :=
  ⟨
    world 4,
    _,
    _,
    1,
    1,
    0,
    0,
    0,
    5,
    _,
    _,
    (List.range' 5 5).map record,
    storeOf_world facts.store4,
    step_world facts.accepted (by decide),
    find_tx facts.tx5,
    facts.attempt5,
    run_world facts.accepted (by decide),
    List.cons_ne_nil _ _
  ⟩

theorem replay_snapshot_fixed_witness
    : ∃ (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot) (rs : List Record),
        find w.txs tid = some before
        ∧ before.snapshot = some snap
        ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem w rs final
        ∧ rs ≠ [] :=
  ⟨
    world 5,
    _,
    1,
    _,
    _,
    (List.range' 5 5).map record,
    find_tx facts.tx5,
    some_get facts.snapshot5,
    facts.attempt5,
    run_world facts.accepted (by decide),
    List.cons_ne_nil _ _
  ⟩

theorem step_map_capture_witness
    : ∃ (w next : World) (sid tid localVersion globalVersion seq : Nat) (map : String)
        (s : Store) (before after : Tx) (snap : Snapshot),
        storeOf w sid = .ok s
        ∧ txOf w sid tid = .ok before
        ∧ before.snapshot = some snap
        ∧ Model.transitionSystem.step w
            ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some next
        ∧ find next.txs tid = some after :=
  ⟨
    world 14,
    _,
    1,
    2,
    1,
    1,
    15,
    "a",
    _,
    _,
    _,
    _,
    storeOf_world facts.store14,
    txOf_world facts.store14 facts.tx14 facts.owner14,
    some_get facts.snapshot14,
    step_world facts.accepted (by decide),
    find_tx facts.tx15
  ⟩

theorem replay_map_global_fixed_witness
    : ∃ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        ∧ find before.globalViews map = some view
        ∧ (∀ r ∈ rs, AttemptEvent tid r.event)
        ∧ CCF.Execution.Run Model.transitionSystem w rs final
        ∧ rs ≠ [] :=
  ⟨
    world 15,
    _,
    2,
    _,
    "a",
    _,
    (List.range' 15 2).map record,
    find_tx facts.tx15,
    some_get facts.view15,
    facts.attempt15,
    run_world facts.accepted (by decide),
    List.cons_ne_nil _ _
  ⟩

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
        ∧ tail ≠ [] :=
  ⟨
    world 14,
    _,
    _,
    1,
    2,
    1,
    1,
    15,
    "a",
    _,
    _,
    _,
    _,
    (List.range' 15 2).map record,
    storeOf_world facts.store14,
    txOf_world facts.store14 facts.tx14 facts.owner14,
    some_get facts.snapshot14,
    step_world facts.accepted (by decide),
    find_tx facts.tx15,
    facts.attempt15,
    run_world facts.accepted (by decide),
    List.cons_ne_nil _ _
  ⟩

theorem captureGlobal_placeholder_witness
    : ∃ (s : Store) (snap : Snapshot) (map : String),
        find (captureLocal s snap map).births map = none :=
  ⟨{}, ⟨{}, 0⟩, "a", rfl⟩

theorem captureGlobal_committed_witness
    : ∃ (s : Store) (snap : Snapshot) (map : String) (birth : Stamp),
        find (captureLocal s snap map).births map = some birth :=
  ⟨written, writtenSnapshot, "a", _, some_get facts.captured⟩

theorem step_global_read_from_captured_map_witness
    : ∃ (w next : World) (sid tid seq : Nat) (map key value : String) (t : Tx)
        (view : GlobalView),
        Model.transitionSystem.Reachable w
        ∧ txOf w sid tid = .ok t
        ∧ find t.globalViews map = some view
        ∧ Model.transitionSystem.step w ⟨seq, .get sid tid map key (some value) true⟩
          = some next :=
  ⟨
    world 15,
    _,
    1,
    2,
    16,
    "a",
    "00",
    "11",
    _,
    _,
    world_reachable facts.accepted (by decide),
    txOf_world facts.store15 facts.tx15 facts.owner15,
    some_get facts.view15,
    step_world facts.accepted (by decide)
  ⟩

theorem step_global_has_from_captured_map_witness
    : ∃ (w next : World) (sid tid seq : Nat) (map key : String) (t : Tx)
        (view : GlobalView),
        Model.transitionSystem.Reachable w
        ∧ txOf w sid tid = .ok t
        ∧ find t.globalViews map = some view
        ∧ Model.transitionSystem.step w ⟨seq, .has sid tid map key true true⟩
          = some next :=
  ⟨
    world 16,
    _,
    1,
    2,
    17,
    "a",
    "00",
    _,
    _,
    world_reachable facts.accepted (by decide),
    txOf_world facts.store16 facts.tx16 facts.owner16,
    some_get facts.view16,
    step_world facts.accepted (by decide)
  ⟩

theorem compact_above_head_noop_witness : ∃ (s : Store) (v : Nat), s.head.version < v :=
  ⟨{}, 1, Nat.zero_lt_one⟩

theorem rollback_keeps_prefix_witness
    : ∃ (s : Store) (f : Frame), f ∈ s.history ∧ f.version ≤ s.global ∧ f.data ≠ [] :=
  ⟨
    compactStore written 1,
    _,
    List.mem_of_mem_head? (rfl : (compactStore written 1).history.head? = some _),
    facts.compactedHead,
    facts.compactedData
  ⟩

theorem rollback_discards_suffix_witness
    : ∃ (s : Store) (v : Nat) (f : Frame),
        f ∈ s.history ∧ v < f.version ∧ s.global ≤ v := by
  have written_valid : StoreInvariant written :=
    advance_invariant {} store_initial _
  exact ⟨
      written,
      0,
      _,
      List.mem_of_mem_head? written_valid.headFirst,
      facts.writtenHead,
      facts.writtenGlobal
    ⟩

theorem durable_cut_survives_rollback_witness
    : ∃ (w : World) (sid : Nat) (s : Store) (v cut : Nat),
        Model.transitionSystem.Reachable w
        ∧ find w.stores sid = some s
        ∧ cut ≤ s.global
        ∧ s.global ≤ v
        ∧ (atCut s cut).data ≠ [] :=
  ⟨
    world 12,
    1,
    storeAt 12 1,
    1,
    1,
    world_reachable facts.accepted (by decide),
    find_store facts.store12,
    facts.cut12,
    facts.bound12,
    facts.durable12
  ⟩

theorem stale_term_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot),
        t.snapshot = some snap ∧ s.term ≠ snap.term :=
  ⟨{}, { store := 0, snapshot := some ⟨{}, 1⟩ }, _, rfl, by decide⟩

theorem discarded_handle_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (revision f m == revision view.current m) = false) :=
  ⟨
    rollbackStore written 0 1,
    writtenTx,
    writtenSnapshot,
    "a",
    _,
    rfl,
    List.mem_singleton_self _,
    facts.discardedRevision
  ⟩

theorem discarded_birth_cannot_apply_witness
    : ∃ (s : Store) (t : Tx) (snap : Snapshot) (m : String) (view : GlobalView),
        t.snapshot = some snap
        ∧ (m, view) ∈ t.globalViews
        ∧ (∀ f ∈ s.history, (find f.births m == find view.current.births m) = false) :=
  ⟨
    rollbackStore written 0 1,
    writtenTx,
    writtenSnapshot,
    "a",
    _,
    rfl,
    List.mem_singleton_self _,
    facts.discardedBirth
  ⟩

theorem compacted_map_unavailable_witness
    : ∃ (s : Store) (f : Frame) (m : String) (birth : Stamp),
        find f.births m = some birth
        ∧ (revision f m).version < (revision (atCut s s.global) m).version :=
  ⟨
    compactStore (advance written [(("a", "00"), some "22")]) 2,
    written.head,
    "a",
    _,
    some_get facts.birth,
    facts.compacted
  ⟩

theorem absent_map_available_witness
    : ∃ (f : Frame) (m : String),
        find f.births m = none ∧ image f.data m = [] ∧ find f.revisions m = none :=
  ⟨{}, "a", rfl, rfl, rfl⟩

theorem absent_placeholder_has_no_values_witness
    : ∃ (s : Store) (f : Frame) (m : String),
        find f.births m = none ∧ mapAvailable s f m = true :=
  ⟨{}, {}, "a", rfl, rfl⟩

end Kv.Proofs.Witnesses
