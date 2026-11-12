-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Semantics

@[expose] public section

namespace Kv.Proofs.Core

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

theorem discarded_handle_cannot_apply (s : Store) (t : Tx) (snap : Snapshot)
    (m : String) (view : GlobalView) (hs : t.snapshot = some snap)
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

theorem discarded_birth_cannot_apply (s : Store) (t : Tx) (snap : Snapshot)
    (m : String) (view : GlobalView) (hs : t.snapshot = some snap)
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

theorem captureGlobal_placeholder (s : Store) (snap : Snapshot) (map : String)
    (absent : find (captureLocal s snap map).births map = none)
    : (captureGlobal s snap map).frame = {} := by
  simp [captureGlobal, absent]

theorem captureGlobal_committed (s : Store) (snap : Snapshot) (map : String)
    (birth : Stamp) (existing : find (captureLocal s snap map).births map = some birth)
    : (captureGlobal s snap map).frame = atCut s s.global := by
  simp [captureGlobal, existing]

end Kv.Proofs.Core
