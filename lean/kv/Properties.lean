-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model

namespace Kv

section Generic
variable {M K V : Type} [DecidableEq M] [DecidableEq K]

theorem find_set_same (xs : Assoc K V) (k : K) (v : V) :
    find (set xs k v) k = some v := by
  simp [set, find]

theorem find_erase_same (xs : Assoc K V) (k : K) :
    find (erase xs k) k = none := by
  induction xs with
  | nil => rfl
  | cons p xs ih =>
    rcases p with ⟨a, v⟩
    by_cases h : a = k <;> simp_all [erase, find]

theorem find_erase_other (xs : Assoc K V) (a k : K) (h : a ≠ k) :
    find (erase xs a) k = find xs k := by
  induction xs with
  | nil => rfl
  | cons p xs ih =>
    rcases p with ⟨b, v⟩
    by_cases hba : b = a <;> by_cases hbk : b = k <;> simp_all [erase, find]

theorem find_set_other (xs : Assoc K V) (a k : K) (v : V) (h : a ≠ k) :
    find (set xs a v) k = find xs k := by
  simp [set, find, h, find_erase_other xs a k h]

theorem find_image (db : DB M K V) (m : M) (key : K) :
    find (image db m) key = find db (m, key) := by
  induction db with
  | nil => rfl
  | cons entry db ih =>
    rcases entry with ⟨⟨map, k⟩, cell⟩
    by_cases hm : map = m <;> by_cases hk : k = key <;>
      simp_all [image, find, Prod.mk.injEq]

theorem empty_map_has_no_values (db : DB M K V) (m : M) (key : K)
    (empty : image db m = []) : find db (m, key) = none := by
  rw [← find_image, empty]
  rfl

theorem erase_keys (xs : Assoc K V) (k : K) :
    (erase xs k).map Prod.fst = (xs.map Prod.fst).filter (· != k) := by
  induction xs with
  | nil => rfl
  | cons p xs ih =>
    rcases p with ⟨a, v⟩
    by_cases h : a = k <;> simp_all [erase]

theorem erase_unique (xs : Assoc K V) (k : K) (h : Unique xs) :
    Unique (erase xs k) := by
  unfold Unique
  rw [erase_keys]
  exact List.Pairwise.filter _ h

theorem set_unique (xs : Assoc K V) (k : K) (v : V) (h : Unique xs) :
    Unique (set xs k v) := by
  simp only [Unique, set, List.map_cons, List.nodup_cons]
  constructor
  · simp [erase_keys]
  · exact erase_unique xs k h

theorem publish_lookup (db : DB M K V) (version : Nat) (ws : Writes M K V)
    (a : Addr M K) :
    find (publish db version ws) a =
      match find ws a with
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
    (h : Unique db) : Unique (publish db version ws) := by
  induction ws with
  | nil => exact h
  | cons p ws ih =>
    rcases p with ⟨a, v⟩
    cases v with
    | none => exact erase_unique _ a ih
    | some value => exact set_unique _ a ⟨value, version⟩ ih

theorem publication_noninterference (db : DB M K V) (version : Nat)
    (ws : Writes M K V) (a : Addr M K) (h : find ws a = none) :
    find (publish db version ws) a = find db a := by
  simp [publish_lookup, h]

theorem read_your_write (db : DB M K V) (ws : Writes M K V) (a : Addr M K) (v : V) :
    valueAt db (set ws a (some v)) a = some v := by
  simp [valueAt, find_set_same]

theorem read_your_deletion (db : DB M K V) (ws : Writes M K V) (a : Addr M K) :
    valueAt db (set ws a none) a = none := by
  simp [valueAt, find_set_same]

theorem absent_read (db : DB M K V) (ws : Writes M K V) (a : Addr M K)
    (hw : find ws a = none) (hd : find db a = none) :
    valueAt db ws a = none := by
  simp [valueAt, hw, hd]

theorem staged_noninterference (db : DB M K V) (ws : Writes M K V)
    (a b : Addr M K) (v : Option V) (h : a ≠ b) :
    valueAt db (set ws a v) b = valueAt db ws b := by
  simp [valueAt, find_set_other ws a b v h]

theorem previous_ignores_pending (db : DB M K V) (a : Addr M K) :
    previousAt db a = (find db a).map Cell.version := rfl

variable [DecidableEq V]

theorem validates_append (db : DB M K V) (a b : List (Dependency M K V)) :
    validates db (a ++ b) = (validates db a && validates db b) := by
  simp [validates]

/-- The reference transaction has no dependency tracking or OCC validation. -/
def serialStep (base : DB M K V) (ws : Writes M K V)
    (op : NormalOp M K V) : Option (Writes M K V) :=
  match op with
  | .read a observed =>
    if valueAt base ws a = observed then some ws else none
  | .previous a observed =>
    if previousAt base a = observed then some ws else none
  | .scan m observed =>
    if scanAt base ws m = observed then some ws else none
  | .write a value => some (set ws a value)

def serialRun (base : DB M K V) (ws : Writes M K V) :
    List (NormalOp M K V) → Option (Writes M K V)
  | [] => some ws
  | op :: ops => (serialStep base ws op).bind fun next => serialRun base next ops

theorem serialStep_eq (base : DB M K V) (ws : Writes M K V) (op : NormalOp M K V) :
    serialStep base ws op =
      if observes base ws op then some (stage ws op) else none := by
  cases op <;> simp [serialStep, observes, stage]

theorem dependency_rebase (snapshot current : DB M K V) (ws : Writes M K V)
    (op : NormalOp M K V)
    (hv : validates current (needs snapshot ws op) = true) :
    observes snapshot ws op = observes current ws op := by
  cases op with
  | read a v =>
    cases hw : find ws a with
    | none =>
      have heq : find current a = find snapshot a := by
        simpa [needs, hw, validates, Dependency.holds] using hv
      simp [observes, valueAt, hw, heq]
    | some value => simp [observes, valueAt, hw]
  | previous a v =>
    have heq : find current a = find snapshot a := by
      simpa [needs, validates, Dependency.holds] using hv
    simp [observes, previousAt, heq]
  | scan m vs =>
    have heq : image current m = image snapshot m := by
      simpa [needs, validates, Dependency.holds] using hv
    simp [observes, scanAt, heq]
  | write _ _ => rfl

theorem normalStep_prefix_valid (snapshot current : DB M K V)
    (n n' : Normal M K V) (op : NormalOp M K V)
    (hs : normalStep snapshot n op = some n')
    (hv : validates current n'.deps = true) :
    validates current n.deps = true := by
  unfold normalStep at hs
  split at hs
  next h =>
    cases hs
    have hh : validates current (needs snapshot n.writes op) = true ∧
        validates current n.deps = true := by simpa [validates_append] using hv
    exact hh.2
  next h => simp at hs

theorem normalStep_rebase (snapshot current : DB M K V)
    (n n' : Normal M K V) (op : NormalOp M K V)
    (hs : normalStep snapshot n op = some n')
    (hv : validates current n'.deps = true) :
    serialStep current n.writes op = some n'.writes := by
  unfold normalStep at hs
  split at hs
  next h =>
    cases hs
    have hh : validates current (needs snapshot n.writes op) = true ∧
        validates current n.deps = true := by simpa [validates_append] using hv
    have hneeds := hh.1
    have hobs := dependency_rebase snapshot current n.writes op hneeds
    rw [serialStep_eq, ← hobs]
    simp [h]
  next h => simp at hs

theorem normalRun_prefix_valid (snapshot current : DB M K V)
    (ops : List (NormalOp M K V)) (n n' : Normal M K V)
    (hr : normalRun snapshot n ops = some n')
    (hv : validates current n'.deps = true) :
    validates current n.deps = true := by
  induction ops generalizing n with
  | nil => simp [normalRun] at hr; subst n'; exact hv
  | cons op ops ih =>
    cases hs : normalStep snapshot n op with
    | none => simp [normalRun, hs] at hr
    | some next =>
      have ht : normalRun snapshot next ops = some n' := by
        simpa [normalRun, hs] using hr
      exact normalStep_prefix_valid snapshot current n next op hs (ih next ht)

/-- Arbitrary finite OCC programs, including cross-map/absent/scan reads,
replay with identical observations immediately before their application.
The only rebase premise is the executable dependency check, not a serial oracle. -/
theorem normalRun_serial_witness (snapshot current : DB M K V)
    (ops : List (NormalOp M K V)) (n n' : Normal M K V)
    (hr : normalRun snapshot n ops = some n')
    (hv : validates current n'.deps = true) :
    serialRun current n.writes ops = some n'.writes := by
  induction ops generalizing n with
  | nil => simp [normalRun] at hr; subst n'; rfl
  | cons op ops ih =>
    cases hs : normalStep snapshot n op with
    | none => simp [normalRun, hs] at hr
    | some next =>
      have ht : normalRun snapshot next ops = some n' := by
        simpa [normalRun, hs] using hr
      have hp := normalRun_prefix_valid snapshot current ops next n' ht hv
      have hstep := normalStep_rebase snapshot current n next op hs hp
      simp [serialRun, hstep, ih next ht]

theorem validates_self (snapshot : DB M K V) (ws : Writes M K V)
    (op : NormalOp M K V) :
    validates snapshot (needs snapshot ws op) = true := by
  cases op <;> simp [needs, validates, Dependency.holds]

theorem normalRun_snapshot_valid (snapshot : DB M K V) (ops : List (NormalOp M K V))
    (n n' : Normal M K V)
    (hn : validates snapshot n.deps = true)
    (hr : normalRun snapshot n ops = some n') :
    validates snapshot n'.deps = true := by
  induction ops generalizing n with
  | nil => simp [normalRun] at hr; subst n'; exact hn
  | cons op ops ih =>
    cases hs : normalStep snapshot n op with
    | none => simp [normalRun, hs] at hr
    | some next =>
      apply ih next
      · unfold normalStep at hs
        split at hs
        next h =>
          cases hs
          simp [validates_append, validates_self, hn]
        next h => simp at hs
      · simpa [normalRun, hs] using hr

theorem readonly_snapshot_witness (snapshot : DB M K V) (ops : List (NormalOp M K V))
    (n : Normal M K V) (hr : normalRun snapshot {} ops = some n) :
    serialRun snapshot [] ops = some n.writes :=
  normalRun_serial_witness snapshot snapshot ops {} n hr
    (normalRun_snapshot_valid snapshot ops {} n (by rfl) hr)

structure AppliedProgram (M K V : Type) where
  snapshot : DB M K V
  ops : List (NormalOp M K V)
  result : Normal M K V
  version : Nat

/-- OCC application mechanics on a branch. Rollback selects another branch;
replication return statuses deliberately do not occur here. -/
inductive BranchExecution : DB M K V → List (AppliedProgram M K V) → DB M K V → Prop
  | nil (db) : BranchExecution db [] db
  | apply (db tail : DB M K V) (p : AppliedProgram M K V) (ps)
      (executed : normalRun p.snapshot {} p.ops = some p.result)
      (validated : validates db p.result.deps = true)
      (rest : BranchExecution (publish db p.version p.result.writes) ps tail) :
      BranchExecution db (p :: ps) tail

def serialBranch (db : DB M K V) : List (AppliedProgram M K V) → Option (DB M K V)
  | [] => some db
  | p :: ps => (serialRun db [] p.ops).bind fun ws => serialBranch (publish db p.version ws) ps

/-- A genuine application-order witness for every finite branch of normal
programs admitted by OCC. The reference interpreter contains no validation. -/
theorem branch_normal_serializability (db final : DB M K V)
    (programs : List (AppliedProgram M K V))
    (h : BranchExecution db programs final) :
    serialBranch db programs = some final := by
  induction h with
  | nil db => rfl
  | apply db tail p ps hex hval rest ih =>
    have hw := normalRun_serial_witness p.snapshot db p.ops {} p.result hex hval
    simpa [serialBranch, hw] using ih

end Generic

theorem apply_atomic (s : Store) (writes : Pending) :
    (advance s writes).head.data = publish s.head.data (s.head.version + 1) writes := rfl

theorem apply_adds_one_version (s : Store) (writes : Pending) :
    (advance s writes).head.version = s.head.version + 1 := rfl

theorem compact_preserves_head (s : Store) (v : Nat) :
    (compactStore s v).head = s.head := by
  unfold compactStore
  split <;> rfl

theorem compact_preserves_history (s : Store) (v : Nat) :
    (compactStore s v).history = s.history := by
  unfold compactStore
  split <;> rfl

theorem compact_above_head_noop (s : Store) (v : Nat) (h : s.head.version < v) :
    compactStore s v = s := by
  simp [compactStore, Nat.not_le.mpr h]

theorem rollbackCut_exact (s : Store) (v : Nat)
    (boundary : s.global ≤ v) (within : v ≤ s.head.version) :
    rollbackCut s v = v := by
  simp [rollbackCut, Nat.min_eq_right within, Nat.max_eq_right boundary]

theorem rollback_effective_version (s : Store) (v term : Nat)
    (boundary : s.global ≤ v) (within : v ≤ s.head.version) :
    (rollbackStore s v term).head.version = v := by
  simp only [rollbackStore, rollbackCut_exact s v boundary within]
  exact (atCut_spec s v within).1

theorem runOp_preserves_snapshot (t next : Tx) (op : NormalOp String String String)
    (h : runOp t op = .ok next) : next.snapshot = t.snapshot := by
  unfold runOp at h
  split at h
  next => simp [invalid] at h
  next snap hs =>
    split at h
    next n hn =>
      simp [Pure.pure, Except.pure] at h
      cases h
      rfl
    next => simp [reject] at h

theorem find_filter_of_imp (xs : List α) (p q : α → Bool)
    (imp : ∀ x, q x = true → p x = true) :
    (xs.filter p).find? q = xs.find? q := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
    by_cases hp : p x = true <;> by_cases hq : q x = true <;>
      simp_all [List.find?]

theorem rollback_preserves_earlier_cuts (s : Store) (v term cut : Nat)
    (hcut : cut ≤ v) (hhead : cut ≤ s.head.version) :
    atCut (rollbackStore s v term) cut = atCut s cut := by
  unfold atCut rollbackStore
  congr 1
  apply find_filter_of_imp
  intro f h
  simp only [decide_eq_true_eq] at h ⊢
  apply Nat.le_trans h
  exact Nat.le_trans (Nat.le_min.mpr ⟨hhead, hcut⟩) (Nat.le_max_right _ _)

theorem durable_cut_survives_rollback (s : Store) (v term cut : Nat)
    (hcut : cut ≤ s.global) (hboundary : s.global ≤ v) :
    (atCut (rollbackStore s v term) cut).data = (atCut s cut).data := by
  rw [rollback_preserves_earlier_cuts s v term cut (Nat.le_trans hcut hboundary)
    (Nat.le_trans hcut s.globalBound)]

theorem compacted_map_unavailable (s : Store) (f : Frame) (m : String)
    (birth : Stamp) (existing : find f.births m = some birth)
    (h : (revision f m).version < (revision (atCut s s.global) m).version) :
    mapAvailable s f m = false := by
  simp [mapAvailable, existing, Nat.not_le.mpr h]

theorem absent_map_available (s : Store) (f : Frame) (m : String)
    (absent : find f.births m = none) (empty : image f.data m = [])
    (unwritten : find f.revisions m = none) :
    mapAvailable s f m = true := by
  simp [mapAvailable, absent, empty, unwritten]

theorem absent_placeholder_has_no_values (s : Store) (f : Frame) (m key : String)
    (absent : find f.births m = none) (permitted : mapAvailable s f m = true) :
    find f.data (m, key) = none := by
  have empty : image f.data m = [] := by
    have checked : image f.data m = [] ∧ find f.revisions m = none := by
      simpa [mapAvailable, absent] using permitted
    exact checked.1
  exact empty_map_has_no_values f.data m key empty

theorem withTx_preserves_stores (w next : World) (sid tid : Nat)
    (f : Tx → Except Failure Tx) (h : withTx w sid tid f = .ok next) :
    next.stores = w.stores := by
  simp only [withTx, Bind.bind, Pure.pure, Except.bind, Except.pure] at h
  cases ht : txOf w sid tid with
  | error err => simp [ht] at h
  | ok t =>
    cases hf : f t with
    | error err => simp [ht, hf] at h
    | ok t' =>
      simp [ht, hf] at h
      cases h
      rfl

theorem rollback_keeps_prefix (s : Store) (v term : Nat) (f : Frame)
    (h : f ∈ s.history) (hv : f.version ≤ s.global) :
    f ∈ (rollbackStore s v term).history := by
  simp only [rollbackStore, List.mem_filter, decide_eq_true_eq]
  exact ⟨h, Nat.le_trans hv (Nat.le_max_left _ _)⟩

theorem rollback_discards_suffix (s : Store) (v term : Nat) (f : Frame)
    (h : v < f.version) (boundary : s.global ≤ v) :
    f ∉ (rollbackStore s v term).history := by
  have hbound : rollbackCut s v ≤ v := Nat.max_le.mpr ⟨boundary, Nat.min_le_right _ _⟩
  simp [rollbackStore, Nat.not_le.mpr (Nat.lt_of_le_of_lt hbound h)]

theorem stale_term_cannot_apply (s : Store) (t : Tx) (snap : Snapshot)
    (hs : t.snapshot = some snap) (ht : s.term ≠ snap.term) :
    canApply s t = false := by
  simp [canApply, validLineage, hs, ht]

theorem discarded_handle_cannot_apply (s : Store) (t : Tx) (snap : Snapshot)
    (hs : t.snapshot = some snap) (m : String) (hm : m ∈ t.handles)
    (gone : ∀ f ∈ s.history, (revision f m == revision snap.current m) = false) :
    canApply s t = false := by
  apply Bool.eq_false_iff.mpr
  intro h
  have hh : (!t.unavailable = true ∧ validLineage s t = true) ∧
      validates s.head.data t.normal.deps = true := by simpa [canApply] using h
  have hp : (s.term == snap.term) = true ∧
      t.handles.all (mapLineage s snap.current) = true := by
    simpa [validLineage, hs] using hh.1.2
  have hall := hp.2
  have hit := List.all_eq_true.mp hall m hm
  obtain ⟨f, hf, he⟩ := List.any_eq_true.mp hit
  simp [gone f hf] at he

theorem discarded_birth_cannot_apply (s : Store) (t : Tx) (snap : Snapshot)
    (hs : t.snapshot = some snap) (m : String) (hm : m ∈ t.handles)
    (gone : ∀ f ∈ s.history, (find f.births m == find snap.current.births m) = false) :
    canApply s t = false := by
  apply Bool.eq_false_iff.mpr
  intro h
  have hh : (!t.unavailable = true ∧ validLineage s t = true) ∧
      validates s.head.data t.normal.deps = true := by simpa [canApply] using h
  have hp : (s.term == snap.term) = true ∧
      t.handles.all (mapLineage s snap.current) = true := by
    simpa [validLineage, hs] using hh.1.2
  have hit := List.all_eq_true.mp hp.2 m hm
  obtain ⟨f, hf, he⟩ := List.any_eq_true.mp hit
  simp [gone f hf] at he

theorem canApply_validates (s : Store) (t : Tx) (h : canApply s t = true) :
    validates s.head.data t.normal.deps = true := by
  have hh : (!t.unavailable && validLineage s t) = true ∧
      validates s.head.data t.normal.deps = true := by simpa [canApply] using h
  exact hh.2

theorem transaction_snapshot_witness (t : Tx) (snap : Snapshot)
    (hs : t.snapshot = some snap) :
    serialRun snap.current.data [] t.normal.log = some t.normal.writes := by
  have hc : normalRun snap.current.data {} t.normal.log = some t.normal := by
    simpa [hs] using t.certificate
  exact readonly_snapshot_witness snap.current.data t.normal.log t.normal hc

/-- This applies directly to the transactions consumed by the trace checker:
their stored, erased certificate is maintained by runOp, not assumed by replay. -/
theorem transaction_application_serial_witness (s : Store) (t : Tx) (snap : Snapshot)
    (hs : t.snapshot = some snap) (hv : canApply s t = true) :
    serialRun s.head.data [] t.normal.log = some t.normal.writes := by
  have hc : normalRun snap.current.data {} t.normal.log = some t.normal := by
    simpa [hs] using t.certificate
  exact normalRun_serial_witness snap.current.data s.head.data t.normal.log {} t.normal hc
    (canApply_validates s t hv)

theorem tryApply_serial_witness (s next : Store) (t : Tx)
    (ha : tryApply s t = some next) :
    serialRun s.head.data [] t.normal.log = some t.normal.writes ∧
      next.head.data = publish s.head.data (s.head.version + 1) t.normal.writes := by
  unfold tryApply at ha
  split at ha
  next hv =>
    cases ha
    refine ⟨?_, rfl⟩
    cases hs : t.snapshot with
    | none =>
      have hc : t.normal = {} := by simpa [hs] using t.certificate
      simp [hc, serialRun]
    | some snap => exact transaction_application_serial_witness s t snap hs hv
  next => simp at ha

/-- A branch of actual executable applications, including no_replicate ones.
The sequence supplied to the reference interpreter is the recorded operation
program of each transaction, not a list of final-state observations. -/
inductive AppliedBranch : Store → List Tx → Store → Prop
  | nil (s) : AppliedBranch s [] s
  | cons (s middle final : Store) (t : Tx) (ts : List Tx)
      (one : tryApply s t = some middle)
      (rest : AppliedBranch middle ts final) : AppliedBranch s (t :: ts) final
  | compact (s final : Store) (v : Nat) (ts : List Tx)
      (rest : AppliedBranch (compactStore s v) ts final) : AppliedBranch s ts final

def serialTransactions (db : Data) (version : Nat) : List Tx → Option Data
  | [] => some db
  | t :: ts => (serialRun db [] t.normal.log).bind fun writes =>
      serialTransactions (publish db (version + 1) writes) (version + 1) ts

theorem executable_branch_serializability (s final : Store) (ts : List Tx)
    (h : AppliedBranch s ts final) :
    serialTransactions s.head.data s.head.version ts = some final.head.data := by
  induction h with
  | nil s => rfl
  | compact s final v ts rest ih =>
    simpa only [compact_preserves_head] using ih
  | cons s middle final t ts one rest ih =>
    have hw := tryApply_serial_witness s middle t one
    have hversion : middle.head.version = s.head.version + 1 := by
      unfold tryApply at one
      split at one
      next => cases one; rfl
      next => simp at one
    simp only [serialTransactions, hw.1, Option.bind_some]
    rw [← hw.2, ← hversion]
    exact ih

theorem global_ignores_writes (snap : Snapshot) (a : Addr String String) :
    valueAt snap.committed.data ([] : Pending) a =
      (find snap.committed.data a).map Cell.value := by
  simp [valueAt, find]

/-- The typed transition relation is the graph of the single executable step.
Parsing, instrumentation, and IO are outside this relation. -/
inductive Transition (w : World) (r : Record) (next : World) : Prop
  | checked (accepted : step w r = .ok next)

theorem step_correspondence (w next : World) (r : Record) :
    step w r = .ok next ↔ Transition w r next :=
  ⟨Transition.checked, fun h => by cases h with | checked h => exact h⟩

inductive Execution : World → List Record → World → Prop
  | nil (w) : Execution w [] w
  | cons (w middle final) (r rs)
      (first : Transition w r middle) (rest : Execution middle rs final) :
      Execution w (r :: rs) final

theorem replay_correspondence (w final : World) (rs : List Record) :
    replay w rs = .ok final ↔ Execution w rs final := by
  induction rs generalizing w with
  | nil =>
    constructor
    · intro h; cases h; exact .nil _
    · intro h; cases h; rfl
  | cons r rs ih =>
    constructor
    · intro h
      cases hs : step w r with
      | error err => simp [replay, hs, Except.bind] at h
      | ok next =>
        have hr : replay next rs = .ok final := by simpa [replay, hs, Except.bind] using h
        exact .cons w next final r rs (.checked hs) ((ih next).mp hr)
    · intro h
      cases h with
      | cons _ middle _ _ _ first rest =>
        have hs := (step_correspondence w middle r).mpr first
        simpa [replay, hs, Except.bind] using (ih middle).mpr rest

end Kv
