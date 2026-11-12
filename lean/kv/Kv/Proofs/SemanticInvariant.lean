-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Semantics
public import CCF.Execution

@[expose] public section

namespace Kv.Proofs.SemanticInvariant

open Kv.Model Kv.Properties

variable {M K V : Type}

/-- The reports agree with the computed local operation. -/
private def observes {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (ws : Writes M K V)
    : NormalOp M K V → Bool
  | .read a v => decide (valueAt db ws a = v)
  | .previous a v => decide (previousAt db a = v)
  | .scan m vs => decide (scanAt db ws m = vs)
  | .write _ _ => true

/-- Validates reports before using the semantic dependency/write recorder. -/
private def normalStep {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (snapshot : DB M K V) (n : Normal M K V) (op : NormalOp M K V)
    : Option (Normal M K V) :=
  if observes snapshot n.writes op then some (recordOp snapshot n op) else none

private def normalRun {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (snapshot : DB M K V) (n : Normal M K V) (ops : List (NormalOp M K V))
    : Option (Normal M K V) :=
  ops.foldlM (normalStep snapshot) n

/-- Store histories are contiguous, headed by the current frame, and contain the global cut. -/
private structure StoreInvariant (s : Store) : Prop where
  /-- Every frame follows by publishing writes to its predecessor. -/
  historyShape : History s.history s.head.version
  /-- The head is the newest frame. -/
  headFirst : s.history.head? = some s.head
  /-- The global version does not exceed the head. -/
  globalBound : s.global ≤ s.head.version

/-- A global view is empty or was captured at a well-formed store's global cut. -/
private def GlobalInvariant (view : GlobalView) : Prop :=
  view.frame = {} ∨ ∃ s : Store, StoreInvariant s ∧ view.frame = atCut s s.global

/-- Replaying an attempt's log from its pinned data reproduces its normal view. -/
private def NormalInvariant (t : Tx) : Prop :=
  match t.snapshot with
  | none => t.normal = {}
  | some _ => normalRun t.data {} t.normal.log = some t.normal

/-- Consistency of an attempt's operation log and captured views. -/
private structure TxInvariant (t : Tx) : Prop where
  /-- The operation log reproduces the normal view. -/
  normal : NormalInvariant t
  /-- Each snapshot was captured from a well-formed store's head. -/
  snapshot
    : ∀ snap,
        t.snapshot = some snap → ∃ s : Store, StoreInvariant s ∧ snap.current = s.head
  /-- Each acquired global view has valid provenance. -/
  globals : ∀ map view, find t.globalViews map = some view → GlobalInvariant view

/-- Internal consistency of every live store and attempt. -/
private structure StateInvariant (w : State) : Prop where
  /-- Live stores have well-formed histories. -/
  stores : ∀ sid s, find w.stores sid = some s → StoreInvariant s
  /-- Live attempts have valid logs and captured views. -/
  txs : ∀ tid t, find w.txs tid = some t → TxInvariant t

/-- An attempt keeps its snapshot, pinned data and global views, and its invariant. -/
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

private theorem find_set_cases [DecidableEq K] (xs : Assoc K V) (id key : K) (v : V)
    : find (set xs id v) key = if id = key then some v else find xs key := by
  by_cases h : id = key <;> simp [h, find_set_same, find_set_other]

private theorem find_erase_cases [DecidableEq K] (xs : Assoc K V) (id key : K)
    : find (erase xs id) key = if id = key then none else find xs key := by
  by_cases h : id = key <;> simp [h, find_erase_same, find_erase_other]

private theorem normalRun_append [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (n : Normal M K V) (a b : List (NormalOp M K V))
    : normalRun db n (a ++ b)
      = (normalRun db n a).bind (fun next => normalRun db next b) := by
  unfold normalRun
  simp

private theorem normalStep_log [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (n n' : Normal M K V) (op : NormalOp M K V)
    (h : normalStep db n op = some n')
    : n'.log = n.log ++ [op] := by
  unfold normalStep at h
  split at h
  next => cases h; rfl
  next => simp at h

private theorem normalRun_extend [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (n n' : Normal M K V) (op : NormalOp M K V)
    (before : normalRun db {} n.log = some n)
    (one : normalStep db n op = some n')
    : normalRun db {} n'.log = some n' := by
  rw [normalStep_log db n n' op one, normalRun_append, before]
  simp [normalRun, one]

private theorem History.bounded (fs : List Frame) (n : Nat) (h : History fs n)
    : ∀ f ∈ fs, f.version ≤ n := by
  induction h with
  | zero =>
      intro g hg
      have he : g = {} := List.mem_singleton.mp hg
      subst g
      exact Nat.le_refl 0
  | succ f n fs hv _effect _tail ih =>
      intro g hg
      rcases List.mem_cons.mp hg with he | hm
      · subst g; exact Nat.le_of_eq hv
      · exact Nat.le_trans (ih g hm) (Nat.le_succ n)

private theorem History.cut (fs : List Frame) (n : Nat) (h : History fs n)
    (cut : Nat) (hc : cut ≤ n)
    : ∃ f,
        fs.find? (fun f => f.version ≤ cut) = some f
        ∧ f.version = cut
        ∧ History (fs.filter fun f => f.version ≤ cut) cut
        ∧ (fs.filter fun f => f.version ≤ cut).head? = some f := by
  induction h with
  | zero =>
      have hz : cut = 0 := Nat.le_zero.mp hc
      subst cut
      refine ⟨{}, ?_, rfl, ?_, ?_⟩
      · rfl
      · exact .zero
      · rfl
  | succ f n fs hv effect tail ih =>
      by_cases he : cut = n + 1
      · subst cut
        have hall : (f :: fs).filter (fun f => decide (f.version ≤ n + 1)) = f :: fs := by
          apply List.filter_eq_self.mpr
          intro g hg
          simp only [decide_eq_true_eq]
          exact History.bounded _ _ (.succ f n fs hv effect tail) g hg
        refine ⟨f, by simp [List.find?, hv], hv, ?_, by simp [hall]⟩
        rw [hall]
        exact .succ f n fs hv effect tail
      · have hlt : ¬n + 1 ≤ cut := fun h => he (Nat.le_antisymm hc h)
        have hc' : cut ≤ n := Nat.le_of_lt_succ (Nat.lt_of_le_of_ne hc he)
        obtain ⟨g, found, gv, shape, first⟩ := ih hc'
        refine ⟨g, ?_, gv, ?_, ?_⟩
        · simpa [List.find?, hv, hlt] using found
        · simpa [hv, hlt] using shape
        · simpa [hv, hlt] using first

private theorem atCut_spec (s : Store) (valid : StoreInvariant s)
    (cut : Nat) (hc : cut ≤ s.head.version)
    : (atCut s cut).version = cut
      ∧ History (s.history.filter fun f => f.version ≤ cut) cut
      ∧ (s.history.filter fun f => f.version ≤ cut).head? = some (atCut s cut) := by
  obtain ⟨f, found, version, shape, first⟩ :=
    History.cut s.history s.head.version valid.historyShape cut hc
  simpa [atCut, found] using And.intro version (And.intro shape first)

private theorem operation_normal (t : Tx) (valid : NormalInvariant t) (snap : Snapshot)
    (n : Normal String String String) (op : NormalOp String String String)
    (hs : t.snapshot = some snap)
    (hn : normalStep t.data t.normal op = some n)
    : match t.snapshot with
      | none => n = {}
      | some _ => normalRun t.data {} n.log = some n := by
  have old : normalRun t.data {} t.normal.log = some t.normal := by
    simpa [NormalInvariant, hs] using valid
  simpa [hs] using normalRun_extend t.data t.normal n op old hn

private theorem image_append (a b : Data) (m : String)
    : image (a ++ b) m = image a m ++ image b m := by
  simp [image]

private theorem image_cons (name key : String) (cell : Cell String) (db : Data)
    (m : String)
    : image (((name, key), cell) :: db) m
      = if name = m then (key, cell) :: image db m else image db m := by
  unfold image
  by_cases h : name = m
  · simp only [List.filterMap_cons, h, ↓reduceIte]
  · simp only [List.filterMap_cons, h, ↓reduceIte]

private theorem image_filter (db : Data) (m : String) (p : String → Bool)
    : image (db.filter fun (a, _) => p a.1) m = if p m then image db m else [] := by
  induction db with
  | nil => split <;> rfl
  | cons entry db ih =>
      obtain ⟨⟨name, key⟩, cell⟩ := entry
      rw [List.filter_cons, image_cons]
      by_cases h : name = m
      · subst h
        cases hp : p name
        · simpa only [hp, Bool.false_eq_true, ite_false] using ih
        · simp only [hp, ite_true, image_cons]
          rw [ih, hp]
          rfl
      · cases hp : p name
        · simpa only [hp, Bool.false_eq_true, ite_false, h] using ih
        · simp only [hp, ite_true, image_cons, h, ite_false]
          exact ih

private theorem pinData_other (db acquired : Data) (m other : String) (h : other ≠ m)
    : image (pinData db m acquired) other = image db other := by
  rw [pinData, image_append, image_filter db other (fun name => name != m),
    image_filter acquired other (fun name => name == m)]
  simp [h]

private theorem find_image (db : Data) (m key : String)
    : find (image db m) key = find db (m, key) := by
  induction db with
  | nil => rfl
  | cons entry db ih =>
      rcases entry with ⟨⟨name, k⟩, cell⟩
      by_cases hm : name = m <;> by_cases hk : k = key <;>
        simp_all [image, find, Prod.mk.injEq]

private theorem normalStep_pinData (db acquired : Data) (m : String)
    (n : Normal String String String) (op : NormalOp String String String)
    (h : op.map ≠ m)
    : normalStep (pinData db m acquired) n op = normalStep db n op := by
  have hi := pinData_other db acquired m op.map h
  cases op with
  | read a v | previous a v =>
      have hf := congrArg (fun entries => find entries a.2) hi
      simp only [NormalOp.map, find_image] at hf
      change find (pinData db m acquired) a = find db a at hf
      simp only [normalStep, recordOp, observes, valueAt, previousAt, needs, hf]
      rfl
  | scan name entries =>
      change image (pinData db m acquired) name = image db name at hi
      simp only [normalStep, recordOp, observes, scanAt, needs, hi]
      rfl
  | write => rfl

private theorem normalRun_pinData (db acquired : Data) (m : String)
    (n : Normal String String String) (ops : List (NormalOp String String String))
    (unused : ops.all (fun op => op.map != m) = true)
    : normalRun (pinData db m acquired) n ops = normalRun db n ops := by
  induction ops generalizing n with
  | nil => rfl
  | cons op ops ih =>
      have h : (op.map != m) = true ∧ ops.all (fun op => op.map != m) = true := by
        simpa only [List.all_cons, Bool.and_eq_true] using unused
      have other : op.map ≠ m := by simpa using h.1
      simp only [normalRun, List.foldlM_cons, normalStep_pinData db acquired m n op other]
      cases normalStep db n op with
      | none => rfl
      | some next => exact ih next h.2

private theorem acquisition_normal (t : Tx) (valid : NormalInvariant t) (m : String)
    (acquired : Data) (unused : t.normal.log.all (fun op => op.map != m) = true)
    : match t.snapshot with
      | none => t.normal = {}
      | some _ =>
          normalRun (pinData t.data m acquired) {} t.normal.log = some t.normal := by
  cases hs : t.snapshot with
  | none => simpa [NormalInvariant, hs] using valid
  | some snap =>
      simpa [NormalInvariant, hs,
        normalRun_pinData t.data acquired m {} t.normal.log unused]
        using valid

private theorem snapshot_normal (t : Tx) (valid : NormalInvariant t) (data : Data)
    (hs : t.snapshot = none)
    : normalRun data {} t.normal.log = some t.normal := by
  have hzero : t.normal = {} := by simpa [NormalInvariant, hs] using valid
  simp [hzero, normalRun]

private theorem history_extension (s : Store) (valid : StoreInvariant s) (f : Frame)
    (writes : Pending) (version : f.version = s.head.version + 1)
    (data : f.data = publish s.head.data (s.head.version + 1) writes)
    : History (f :: s.history) (s.head.version + 1) :=
  .succ f s.head.version s.history version
    ⟨writes, by simpa only [valid.headFirst, Option.getD_some] using data⟩
    valid.historyShape

private theorem cut_history (s : Store) (valid : StoreInvariant s)
    (cut : Nat) (within : cut ≤ s.head.version)
    : History (s.history.filter fun f => f.version ≤ cut) (atCut s cut).version := by
  have spec := atCut_spec s valid cut within
  rw [spec.1]
  exact spec.2.1

private theorem cut_global_bound (s : Store) (valid : StoreInvariant s) (cut : Nat)
    (within : cut ≤ s.head.version) (boundary : s.global ≤ cut)
    : s.global ≤ (atCut s cut).version := by
  rw [(atCut_spec s valid cut within).1]
  exact boundary

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

private theorem compact_invariant (s : Store) (valid : StoreInvariant s) (v : Nat)
    : StoreInvariant (compactStore s v) := by
  unfold compactStore
  split
  next within =>
    exact ⟨valid.historyShape, valid.headFirst, Nat.max_le.mpr ⟨valid.globalBound, within⟩⟩
  next => exact valid

private theorem rollback_invariant (s : Store) (valid : StoreInvariant s) (v term : Nat)
    : StoreInvariant (rollbackStore s v term) := by
  have within : rollbackCut s v ≤ s.head.version :=
    Nat.max_le.mpr ⟨valid.globalBound, Nat.min_le_left _ _⟩
  exact ⟨cut_history s valid _ within, (atCut_spec s valid _ within).2.2,
    cut_global_bound s valid _ within (Nat.le_max_left _ _)⟩

private theorem tx_initial (sid : Nat) : TxInvariant { store := sid } := by
  refine ⟨rfl, ?_, ?_⟩ <;> simp [find]

private theorem captureGlobal_invariant (s : Store) (valid : StoreInvariant s)
    (snap : Snapshot) (map : String)
    : GlobalInvariant (captureGlobal s snap map) := by
  dsimp only [captureGlobal]
  split
  · exact Or.inl rfl
  · exact Or.inr ⟨s, valid, rfl⟩

private theorem snapshot_invariant (s : Store) (store : StoreInvariant s) (term : Nat)
    (t : Tx) (valid : TxInvariant t) (fresh : t.snapshot = none)
    : TxInvariant { t with snapshot := some { current := s.head, term } } := by
  refine ⟨snapshot_normal t valid.normal t.data fresh, ?_, valid.globals⟩
  intro snap captured
  cases captured
  exact ⟨s, store, rfl⟩

private theorem tx_fields_invariant (t next : Tx) (valid : TxInvariant t)
    (snapshot : next.snapshot = t.snapshot) (data : next.data = t.data)
    (normal : next.normal = t.normal) (globals : next.globalViews = t.globalViews)
    : TxInvariant next := by
  rcases valid with ⟨hn, hs, hg⟩
  constructor
  · simpa [NormalInvariant, snapshot, data, normal] using hn
  · simpa [snapshot] using hs
  · simpa [globals] using hg

private theorem lookup_set_invariant [DecidableEq K] (P : V → Prop) (xs : Assoc K V)
    (valid : ∀ key value, find xs key = some value → P value)
    (id : K) (value : V) (holds : P value)
    : ∀ key next, find (set xs id value) key = some next → P next := by
  intro key next found
  rw [find_set_cases] at found
  split at found
  · cases found; exact holds
  · exact valid key next found

private theorem lookup_erase_invariant [DecidableEq K] (P : V → Prop) (xs : Assoc K V)
    (valid : ∀ key value, find xs key = some value → P value) (id : K)
    : ∀ key next, find (erase xs id) key = some next → P next := by
  intro key next found
  rw [find_erase_cases] at found
  split at found
  · contradiction
  · exact valid key next found

private theorem tryApply_invariant (s next : Store) (valid : StoreInvariant s) (t : Tx)
    (applied : tryApply s t = some next)
    : StoreInvariant next := by
  unfold tryApply at applied
  split at applied
  · cases applied; exact advance_invariant s valid t.normal.writes
  · contradiction

private theorem world_initial : StateInvariant {} := by
  constructor <;> simp [find]

section Generic
variable [DecidableEq M] [DecidableEq K]
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

private theorem publish_lookup (db : DB M K V) (version : Nat) (ws : Writes M K V)
    (a : Addr M K)
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

private theorem publish_unique (db : DB M K V) (version : Nat) (ws : Writes M K V)
    (h : Kv.Properties.Unique db)
    : Kv.Properties.Unique (publish db version ws) := by
  induction ws with
  | nil => exact h
  | cons p ws ih =>
      rcases p with ⟨a, v⟩
      cases v with
      | none => exact erase_unique _ a ih
      | some value => exact set_unique _ a ⟨value, version⟩ ih

end Generic
section Generic
variable [DecidableEq M] [DecidableEq K] [DecidableEq V]
private theorem validates_append (db : DB M K V) (a b : List (Dependency M K V))
    : validates db (a ++ b) = (validates db a && validates db b) := by
  simp [validates]

private theorem serialStep_eq (base : DB M K V) (ws : Writes M K V) (op : NormalOp M K V)
    : serialStep base ws op
      = if observes base ws op then some (stage ws op) else none := by
  cases op <;> simp [serialStep, observes, stage]

private theorem dependency_rebase (snapshot current : DB M K V) (ws : Writes M K V)
    (op : NormalOp M K V)
    (hv : validates current (needs snapshot ws op) = true)
    : observes snapshot ws op = observes current ws op := by
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
      apply decide_eq_decide.mpr
      simp only [previousAt, heq]
  | scan m vs =>
      have heq : image current m = image snapshot m := by
        simpa [needs, validates, Dependency.holds] using hv
      apply decide_eq_decide.mpr
      simp only [scanAt, heq]
  | write _ _ => rfl

private theorem normalStep_prefix_valid (snapshot current : DB M K V)
    (n n' : Normal M K V) (op : NormalOp M K V)
    (hs : normalStep snapshot n op = some n')
    (hv : validates current n'.deps = true)
    : validates current n.deps = true := by
  unfold normalStep at hs
  split at hs
  next h =>
    cases hs
    have hh : validates current (needs snapshot n.writes op) = true ∧
        validates current n.deps = true := by simpa [recordOp, validates_append] using hv
    exact hh.2
  next h => simp at hs

private theorem normalStep_rebase (snapshot current : DB M K V)
    (n n' : Normal M K V) (op : NormalOp M K V)
    (hs : normalStep snapshot n op = some n')
    (hv : validates current n'.deps = true)
    : serialStep current n.writes op = some n'.writes := by
  unfold normalStep at hs
  split at hs
  next h =>
    cases hs
    have hh : validates current (needs snapshot n.writes op) = true ∧
        validates current n.deps = true := by simpa [recordOp, validates_append] using hv
    have hneeds := hh.1
    have hobs := dependency_rebase snapshot current n.writes op hneeds
    rw [serialStep_eq, ← hobs]
    simp [h, recordOp]
  next h => simp at hs

private theorem normalRun_prefix_valid (snapshot current : DB M K V)
    (ops : List (NormalOp M K V)) (n n' : Normal M K V)
    (hr : normalRun snapshot n ops = some n')
    (hv : validates current n'.deps = true)
    : validates current n.deps = true := by
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
private theorem normalRun_serial (snapshot current : DB M K V)
    (ops : List (NormalOp M K V)) (n n' : Normal M K V)
    (hr : normalRun snapshot n ops = some n')
    (hv : validates current n'.deps = true)
    : serialRun current n.writes ops = some n'.writes := by
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

private theorem validates_self (snapshot : DB M K V) (ws : Writes M K V)
    (op : NormalOp M K V)
    : validates snapshot (needs snapshot ws op) = true := by
  cases op <;> simp [needs, validates, Dependency.holds]

private theorem normalRun_snapshot_valid (snapshot : DB M K V)
    (ops : List (NormalOp M K V)) (n n' : Normal M K V)
    (hn : validates snapshot n.deps = true) (hr : normalRun snapshot n ops = some n')
    : validates snapshot n'.deps = true := by
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
              simp [recordOp, validates_append, validates_self, hn]
            next h => simp at hs
          · simpa [normalRun, hs] using hr

private theorem readonly_snapshot_serial (snapshot : DB M K V)
    (ops : List (NormalOp M K V)) (n : Normal M K V)
    (hr : normalRun snapshot {} ops = some n)
    : serialRun snapshot [] ops = some n.writes :=
  normalRun_serial snapshot snapshot ops {} n hr
    (normalRun_snapshot_valid snapshot ops {} n (by rfl) hr)

end Generic
private theorem compact_preserves_head (s : Store) (v : Nat)
    : (compactStore s v).head = s.head := by
  unfold compactStore
  split <;> rfl

private theorem rollback_preserves_earlier_cuts (s : Store) (v term cut : Nat)
    (hcut : cut ≤ v) (hhead : cut ≤ s.head.version)
    : atCut (rollbackStore s v term) cut = atCut s cut := by
  have hmono : ∀ f : Frame, f.version ≤ cut → f.version ≤ rollbackCut s v := fun f h =>
    Nat.le_trans h (Nat.le_trans (Nat.le_min.mpr ⟨hhead, hcut⟩) (Nat.le_max_right _ _))
  unfold atCut rollbackStore
  congr 1
  rw [List.find?_filter]
  congr 1
  exact funext fun f => by by_cases h : f.version ≤ cut <;> simp [h, hmono f]

private theorem durable_cut_survives_rollback (s : Store) (v term cut : Nat)
    (valid : StoreInvariant s) (hcut : cut ≤ s.global) (hboundary : s.global ≤ v)
    : (atCut (rollbackStore s v term) cut).data = (atCut s cut).data := by
  rw [rollback_preserves_earlier_cuts s v term cut (Nat.le_trans hcut hboundary)
    (Nat.le_trans hcut valid.globalBound)]

private theorem transaction_snapshot_serial (t : Tx) (snap : Snapshot)
    (valid : NormalInvariant t) (hs : t.snapshot = some snap)
    : serialRun t.data [] t.normal.log = some t.normal.writes := by
  have hc : normalRun t.data {} t.normal.log = some t.normal := by
    simpa [NormalInvariant, hs] using valid
  exact readonly_snapshot_serial t.data t.normal.log t.normal hc

/-- A valid attempt that passes OCC agrees with serial execution on the current head. -/
private theorem transaction_application_serial (s : Store) (t : Tx) (snap : Snapshot)
    (valid : NormalInvariant t)
    (hs : t.snapshot = some snap) (hv : canApply s t = true)
    : serialRun s.head.data [] t.normal.log = some t.normal.writes := by
  have canApply_validates (s : Store) (t : Tx) (h : canApply s t = true)
      : validates s.head.data t.normal.deps = true := by
    have hh : (!t.unavailable && validLineage s t) = true ∧
        validates s.head.data t.normal.deps = true := by simpa [canApply] using h
    exact hh.2
  have hc : normalRun t.data {} t.normal.log = some t.normal := by
    simpa [NormalInvariant, hs] using valid
  exact normalRun_serial t.data s.head.data t.normal.log {} t.normal hc
    (canApply_validates s t hv)

private theorem tryApply_serial (s next : Store) (t : Tx) (valid : NormalInvariant t)
    (ha : tryApply s t = some next)
    : serialRun s.head.data [] t.normal.log = some t.normal.writes
      ∧ next.head.data = publish s.head.data (s.head.version + 1) t.normal.writes := by
  unfold tryApply at ha
  split at ha
  next hv =>
    cases ha
    refine ⟨?_, rfl⟩
    cases hs : t.snapshot with
    | none =>
        have hc : t.normal = {} := by simpa [NormalInvariant, hs] using valid
        simp [hc, serialRun]
    | some snap => exact transaction_application_serial s t snap valid hs hv
  next => simp at ha

private theorem executable_branch_serializability (s final : Store) (ts : List Tx)
    (valid : ∀ t ∈ ts, NormalInvariant t)
    (h : SemanticAppliedBranch s ts final)
    : semanticSerialTransactions s.head.data s.head.version ts
      = some final.head.data := by
  induction h with
  | nil s => rfl
  | compact s final v ts _rest ih =>
      simpa only [compact_preserves_head] using ih valid
  | cons s middle final t ts one rest ih =>
      have hw := tryApply_serial s middle t (valid t (by simp)) one
      have hversion : middle.head.version = s.head.version + 1 := by
        unfold tryApply at one
        split at one
        next => cases one; rfl
        next => simp at one
      simp only [semanticSerialTransactions, hw.1, Option.bind_some]
      rw [← hw.2, ← hversion]
      exact ih (fun tx member => valid tx (by simp [member]))

private theorem record_invariant (t : Tx) (valid : TxInvariant t) (snap : Snapshot)
    (captured : t.snapshot = some snap) (op : NormalOp String String String)
    (observed : observes t.data t.normal.writes op = true)
    : TxInvariant { t with normal := recordOp t.data t.normal op } := by
  refine ⟨?_, valid.snapshot, valid.globals⟩
  exact operation_normal t valid.normal snap _ op captured
    (by simp [normalStep, observed])

private theorem clear_invariant (t : Tx) (valid : TxInvariant t) (snap : Snapshot)
    (captured : t.snapshot = some snap) (m : String) (entries : Assoc String String)
    : TxInvariant
        (entries.foldl
          (fun acc (k, _) =>
            { acc with normal := recordOp acc.data acc.normal (.write (m, k) none) })
          t) := by
  induction entries generalizing t with
  | nil => exact valid
  | cons entry _rest ih =>
      exact ih _ (record_invariant t valid snap captured (.write (m, entry.1) none) rfl)
        captured

private theorem operation_invariant (t : Tx) (valid : TxInvariant t) (snap : Snapshot)
    (captured : t.snapshot = some snap) (op : Operation)
    : TxInvariant (executeOperation t op).1 := by
  cases op with
  | get m k global =>
      cases global
      · exact record_invariant t valid snap captured _ (by simp [observes])
      · exact valid
  | has m k global =>
      cases global
      · exact record_invariant t valid snap captured _ (by simp [observes])
      · exact valid
  | previous m k => exact record_invariant t valid snap captured _ (by simp [observes])
  | write m k v => exact record_invariant t valid snap captured _ rfl
  | size m =>
      exact record_invariant t valid snap captured _ (by simp [observes])
  | scan m =>
      exact record_invariant t valid snap captured _ (by simp [observes])
  | range m lower upper =>
      dsimp only [executeOperation, Operation.map]
      split
      · exact valid
      · exact record_invariant t valid snap captured _ (by simp [observes])
  | clear m =>
      exact clear_invariant _
        (record_invariant t valid snap captured _ (by simp [observes]))
        snap captured m _

private theorem option_bind_ok {α β : Type} {x : Option α} {f : α → Option β} {b : β}
    (accepted : x.bind f = some b)
    : ∃ a, x = some a ∧ f a = some b := by
  cases x with
  | none => cases accepted
  | some a => exact ⟨a, rfl, accepted⟩

private theorem lookup_invariant (w : State) (valid : StateInvariant w)
    (sid tid : Nat) (s : Store) (t : Tx) (found : lookupTx w sid tid = some (s, t))
    : StoreInvariant s ∧ TxInvariant t := by
  obtain ⟨store, hs, rest⟩ := option_bind_ok found
  obtain ⟨tx, ht, rest⟩ := option_bind_ok rest
  split at rest
  · cases rest
    exact ⟨valid.stores sid s hs, valid.txs tid t ht⟩
  · cases rest

private theorem update_tx (w : State) (valid : StateInvariant w) (tid : Nat) (t : Tx)
    (holds : TxInvariant t)
    : StateInvariant { w with txs := set w.txs tid t } :=
  ⟨valid.stores, lookup_set_invariant TxInvariant w.txs valid.txs tid t holds⟩

private theorem update_store (w : State) (valid : StateInvariant w) (sid : Nat)
    (s : Store) (holds : StoreInvariant s)
    : StateInvariant { w with stores := set w.stores sid s } :=
  ⟨lookup_set_invariant StoreInvariant w.stores valid.stores sid s holds, valid.txs⟩

private theorem acquired_invariant (s : Store) (store : StoreInvariant s) (t : Tx)
    (valid : TxInvariant t) (snap : Snapshot) (_captured : t.snapshot = some snap)
    (m : String) (unused : t.normal.log.all (fun op => op.map != m) = true)
    : TxInvariant
        {
          t with
            globalViews := set t.globalViews m (captureGlobal s snap m)
            data := pinData t.data m (captureGlobal s snap m).current.data
        } := by
  refine ⟨acquisition_normal t valid.normal m _ unused, valid.snapshot, ?_⟩
  exact lookup_set_invariant GlobalInvariant t.globalViews valid.globals m _
    (captureGlobal_invariant s store snap m)

private theorem execute_invariant (w next : State) (valid : StateInvariant w)
    (a : Action) (output : Output) (accepted : execute w a = some (next, output))
    : StateInvariant next := by
  cases a with
  | storeCreate sid term =>
      dsimp only [execute] at accepted
      split at accepted
      · cases accepted
      · cases accepted
        exact update_store w valid sid _ ⟨.zero, rfl, Nat.le_refl 0⟩
  | storeEnd sid =>
      obtain ⟨_, _, rest⟩ := option_bind_ok accepted
      try dsimp only at rest
      split at rest
      · cases rest
      · cases rest
        exact ⟨lookup_erase_invariant StoreInvariant w.stores valid.stores sid, valid.txs⟩
  | txCreate sid tid =>
      obtain ⟨_, _, rest⟩ := option_bind_ok accepted
      try dsimp only at rest
      split at rest
      · cases rest
      · cases rest
        exact update_tx w valid tid _ (tx_initial sid)
  | txEnd sid tid =>
      obtain ⟨_, _, rest⟩ := option_bind_ok accepted
      try dsimp only at rest
      cases rest
      exact ⟨valid.stores, lookup_erase_invariant TxInvariant w.txs valid.txs tid⟩
  | setTerm sid term =>
      obtain ⟨s, found, rest⟩ := option_bind_ok accepted
      try dsimp only at rest
      split at rest
      · cases rest
      · cases rest
        have inv := valid.stores sid s found
        exact update_store w valid sid _ ⟨inv.historyShape, inv.headFirst, inv.globalBound⟩
  | snapshot sid tid =>
      obtain ⟨⟨s, t⟩, found, rest⟩ := option_bind_ok accepted
      try dsimp only at rest
      have inv := lookup_invariant w valid sid tid s t found
      split at rest
      · cases rest
      · have fresh : t.snapshot = none := by
          have condition : (t.phase != .active || t.snapshot.isSome) = false := by
            apply Bool.eq_false_iff.mpr
            assumption
          cases captured : t.snapshot
          · rfl
          · simp [captured] at condition
        cases rest
        exact update_tx w valid tid _ (snapshot_invariant s inv.1 s.term t inv.2 fresh)
  | acquire sid tid m =>
      obtain ⟨⟨s, t⟩, found, rest⟩ := option_bind_ok accepted
      try dsimp only at rest
      have inv := lookup_invariant w valid sid tid s t found
      obtain ⟨snap, captured, rest⟩ := option_bind_ok rest
      try dsimp only at rest
      split at rest
      · cases rest
      · have unused : t.normal.log.all (fun op => op.map != m) = true := by
          have condition : (t.phase != .active || (find t.globalViews m).isSome
              || !t.normal.log.all (fun op => op.map != m)) = false := by
            apply Bool.eq_false_iff.mpr
            assumption
          cases used : t.normal.log.all (fun op => op.map != m) <;>
            simp [used] at condition ⊢
        split at rest
        · cases rest
          exact update_tx w valid tid _ (acquired_invariant s inv.1 t inv.2 snap captured m unused)
        · cases rest
          exact update_tx w valid tid _ (tx_fields_invariant t _ inv.2 rfl rfl rfl rfl)
  | operation sid tid op =>
      obtain ⟨⟨s, t⟩, found, rest⟩ := option_bind_ok accepted
      try dsimp only at rest
      have inv := lookup_invariant w valid sid tid s t found
      split at rest
      · cases rest
      · have captured : ∃ snap, t.snapshot = some snap := by
          cases captured : t.snapshot with
          | none => simp [captured] at *
          | some snap => exact ⟨snap, rfl⟩
        obtain ⟨snap, captured⟩ := captured
        cases rest
        exact update_tx w valid tid _ (operation_invariant t inv.2 snap captured op)
  | commitBegin sid tid =>
      obtain ⟨⟨s, t⟩, found, rest⟩ := option_bind_ok accepted
      try dsimp only at rest
      have inv := lookup_invariant w valid sid tid s t found
      split at rest
      · cases rest
      · cases rest
        exact update_tx w valid tid _ (tx_fields_invariant t _ inv.2 rfl rfl rfl rfl)
  | apply sid tid =>
      obtain ⟨⟨s, t⟩, found, rest⟩ := option_bind_ok accepted
      try dsimp only at rest
      have inv := lookup_invariant w valid sid tid s t found
      split at rest
      · cases rest
      · obtain ⟨store, applied, rest⟩ := option_bind_ok rest
        try dsimp only at rest
        cases rest
        exact update_tx _ (update_store w valid sid store
          (tryApply_invariant s store inv.1 t applied)) tid _
          (tx_fields_invariant t _ inv.2 rfl rfl rfl rfl)
  | commitResult sid tid result =>
      obtain ⟨⟨s, t⟩, found, rest⟩ := option_bind_ok accepted
      try dsimp only at rest
      have inv := lookup_invariant w valid sid tid s t found
      cases phase : t.phase <;> simp only [phase] at rest
      all_goals try split at rest
      all_goals try dsimp only at rest
      all_goals cases rest
      all_goals exact update_tx w valid tid _ (tx_fields_invariant t _ inv.2 rfl rfl rfl rfl)
  | compact sid requested =>
      obtain ⟨s, found, rest⟩ := option_bind_ok accepted
      try dsimp only at rest
      cases rest
      exact update_store w valid sid _ (compact_invariant s (valid.stores sid s found) requested)
  | rollback sid requested term =>
      obtain ⟨s, found, rest⟩ := option_bind_ok accepted
      try dsimp only at rest
      split at rest
      · cases rest
        exact valid
      · split at rest
        · cases rest
        · cases rest
          exact update_store w valid sid _ (rollback_invariant s (valid.stores sid s found) requested term)

private theorem reachable_invariant (w : State)
    (reachable : Model.transitionSystem.Reachable w)
    : StateInvariant w := by
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec Model.transitionSystem with
  | initial initialized =>
      cases initialized
      exact world_initial
  | @step w next action _ transition ih =>
      obtain ⟨pair, executed, state⟩ := Option.map_eq_some_iff.mp transition
      obtain ⟨semantic, output⟩ := pair
      cases state
      exact execute_invariant _ _ ih action output executed

private theorem History.head_cells_bounded (fs : List Frame) (n : Nat)
    (shape : History fs n)
    : CellsBounded (fs.head?.getD {}).data n := by
  have publish_cells_bounded (db : Data) (version : Nat) (writes : Pending)
      (before : CellsBounded db version)
      : CellsBounded (publish db version writes) version := by
    intro key cell found
    rw [publish_lookup] at found
    cases hw : find writes key with
    | none => exact before key cell (by simpa [hw] using found)
    | some value =>
        cases value with
        | none => simp [hw] at found
        | some v =>
            simp [hw] at found
            cases found
            exact Nat.le_refl _
  induction shape with
  | zero =>
      intro key cell found
      simp [find] at found
  | succ f n fs _version effect _tail ih =>
      obtain ⟨writes, published⟩ := effect
      simp only [List.head?_cons, Option.getD_some]
      rw [published]
      apply publish_cells_bounded
      intro key cell found
      exact Nat.le_trans (ih key cell found) (Nat.le_succ n)

private theorem History.head_unique (fs : List Frame) (n : Nat) (shape : History fs n)
    : Kv.Properties.Unique (fs.head?.getD {}).data := by
  induction shape with
  | zero => simp [Kv.Properties.Unique]
  | succ f n fs _version effect _tail ih =>
      obtain ⟨writes, published⟩ := effect
      simp only [List.head?_cons, Option.getD_some]
      rw [published]
      exact publish_unique _ _ _ ih

private theorem map_global_view_safety (view : GlobalView) (valid : GlobalInvariant view)
    : view.frame = {}
      ∨ ∃ origin : Store,
          view.frame = atCut origin origin.global
          ∧ view.frame.version = origin.global
          ∧ CellsBounded view.frame.data origin.global := by
  have atCut_cells_bounded (s : Store) (valid : StoreInvariant s)
      (cut : Nat) (within : cut ≤ s.head.version)
      : CellsBounded (atCut s cut).data cut := by
    have spec := atCut_spec s valid cut within
    have h := History.head_cells_bounded _ cut spec.2.1
    simpa only [spec.2.2, Option.getD_some] using h
  rcases valid with placeholder | ⟨origin, store, committed⟩
  · exact Or.inl placeholder
  · refine Or.inr ⟨origin, committed, ?_, ?_⟩
    · rw [committed]; exact (atCut_spec origin store origin.global store.globalBound).1
    · rw [committed]; exact atCut_cells_bounded origin store origin.global store.globalBound

/-- All semantic-reachable stores have complete publication histories and valid global cuts. -/
theorem semantic_reachable_store_invariants
    : ∀ (w : State) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → History s.history s.head.version
          ∧ s.history.head? = some s.head
          ∧ s.global ≤ s.head.version
          ∧ (atCut s s.global).version = s.global := by
  intro w sid s reachable found
  have inv := (reachable_invariant w reachable).stores sid s found
  exact ⟨inv.historyShape, inv.headFirst, inv.globalBound,
    (atCut_spec s inv s.global inv.globalBound).1⟩

/-- Every semantic-reachable head has unique keys and bounded previous-write versions. -/
theorem semantic_reachable_store_data_invariants
    : ∀ (w : State) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → Unique s.head.data ∧ CellsBounded s.head.data s.head.version := by
  intro w sid s reachable found
  have inv := (reachable_invariant w reachable).stores sid s found
  exact ⟨
    by
      simpa only [inv.headFirst, Option.getD_some]
        using History.head_unique s.history s.head.version inv.historyShape,
    by
      simpa only [inv.headFirst, Option.getD_some]
        using History.head_cells_bounded s.history s.head.version inv.historyShape
  ⟩

/-- Every semantic-reachable captured normal program reproduces its staged writes on pinned data. -/
theorem semantic_transaction_snapshot_serial
    : ∀ (w : State) (tid : Nat) (t : Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        → find w.txs tid = some t
        → t.snapshot = some snap
        → serialRun t.data [] t.normal.log = some t.normal.writes := by
  intro w tid t snap reachable found captured
  exact transaction_snapshot_serial t snap
    ((reachable_invariant w reachable).txs tid t found).normal captured

/-- OCC-valid semantic-reachable programs have an independent serial witness at application. -/
theorem semantic_transaction_application_serial
    : ∀ (w : State) (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        → lookupTx w sid tid = some (s, t)
        → t.snapshot = some snap
        → canApply s t = true
        → serialRun s.head.data [] t.normal.log = some t.normal.writes := by
  intro w sid tid s t snap reachable found captured permitted
  exact transaction_application_serial s t snap
    (lookup_invariant w (reachable_invariant w reachable) sid tid s t found).2.normal
    captured permitted

/-- Application order serializes arbitrary semantic-reachable attempts, with compaction interleavings. -/
theorem semantic_executable_branch_serializability
    : ∀ (s final : Store) (ts : List Tx),
        (∀ t ∈ ts,
          ∃ (w : State) (tid : Nat),
            Model.transitionSystem.Reachable w ∧ find w.txs tid = some t)
        → SemanticAppliedBranch s ts final
        → semanticSerialTransactions s.head.data s.head.version ts
          = some final.head.data := by
  intro s final ts reachable branch
  apply executable_branch_serializability s final ts _ branch
  intro t member
  obtain ⟨w, tid, initialized, found⟩ := reachable t member
  exact ((reachable_invariant w initialized).txs tid t found).normal

/-- Captured global frames of all semantic-reachable attempts have irrevocable provenance. -/
theorem semantic_global_provenance
    : ∀ (w : State) (tid : Nat) (t : Tx) (map : String) (view : GlobalView),
        Model.transitionSystem.Reachable w
        → find w.txs tid = some t
        → find t.globalViews map = some view
        → view.frame = {}
          ∨ ∃ origin : Store,
              view.frame = atCut origin origin.global
              ∧ view.frame.version = origin.global
              ∧ CellsBounded view.frame.data origin.global := by
  intro w tid t map view reachable found captured
  exact map_global_view_safety view
    (((reachable_invariant w reachable).txs tid t found).globals map view captured)

/-- A semantic-reachable store's durable cuts survive legal rollback. -/
theorem semantic_durable_cut_survives_rollback
    : ∀ (w : State) (sid v term cut : Nat) (s : Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → cut ≤ s.global
        → s.global ≤ v
        → (atCut (rollbackStore s v term) cut).data = (atCut s cut).data := by
  intro w sid v term cut s reachable found within boundary
  exact durable_cut_survives_rollback s v term cut
    ((reachable_invariant w reachable).stores sid s found) within boundary

private def witnessTx : Tx :=
  {
    store := 1
    snapshot := some { current := {}, term := 0 }
    globalViews := [("m", { frame := {} })]
    normal :=
      { writes := [(("m", "k"), some "v")], log := [.write ("m", "k") (some "v")] }
  }

private def witnessState : State := { stores := [(1, {})], txs := [(1, witnessTx)] }

private theorem witness_reachable : Model.transitionSystem.Reachable witnessState := by
  have r0 : Model.transitionSystem.Reachable ({} : State) := .initial rfl
  have r1 : Model.transitionSystem.Reachable ({ stores := [(1, {})] } : State) :=
    .step (action := .storeCreate 1 0) r0 rfl
  have r2 : Model.transitionSystem.Reachable
      ({ stores := [(1, {})], txs := [(1, { store := 1 })] } : State) :=
    .step (action := .txCreate 1 1) r1 rfl
  have r3 : Model.transitionSystem.Reachable ({
      stores := [(1, {})]
      txs := [(1, { store := 1, snapshot := some { current := {}, term := 0 } })]
    } : State) := .step (action := .snapshot 1 1) r2 rfl
  have r4 : Model.transitionSystem.Reachable ({
      stores := [(1, {})]
      txs := [(1, {
        store := 1
        snapshot := some { current := {}, term := 0 }
        globalViews := [("m", { frame := {} })]
      })]
    } : State) := .step (action := .acquire 1 1 "m") r3 rfl
  exact .step (action := .operation 1 1 (.write "m" "k" (some "v"))) r4 rfl

/-- A semantic-reachable store witnesses both store safety premises. -/
theorem semantic_reachable_store_invariants_witness
    : ∃ (w : State) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s :=
  ⟨witnessState, 1, {}, witness_reachable, rfl⟩

/-- A semantic-reachable head witnesses data invariant premises. -/
theorem semantic_reachable_store_data_invariants_witness
    : ∃ (w : State) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w ∧ find w.stores sid = some s :=
  ⟨witnessState, 1, {}, witness_reachable, rfl⟩

/-- A nonempty normal program is reachable using only semantic actions. -/
theorem semantic_transaction_snapshot_serial_witness
    : ∃ (w : State) (tid : Nat) (t : Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        ∧ find w.txs tid = some t
        ∧ t.snapshot = some snap
        ∧ t.normal.log ≠ [] :=
  ⟨
    witnessState,
    1,
    witnessTx,
    { current := {}, term := 0 },
    witness_reachable,
    rfl,
    rfl,
    by decide +kernel
  ⟩

/-- A nonempty semantic-reachable program can pass OCC. -/
theorem semantic_transaction_application_serial_witness
    : ∃ (w : State) (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        ∧ lookupTx w sid tid = some (s, t)
        ∧ t.snapshot = some snap
        ∧ canApply s t = true
        ∧ t.normal.log ≠ [] :=
  ⟨
    witnessState,
    1,
    1,
    {},
    witnessTx,
    { current := {}, term := 0 },
    witness_reachable,
    rfl,
    rfl,
    rfl,
    by decide +kernel
  ⟩

/-- A nonempty application-order branch uses a semantic-reachable attempt. -/
theorem semantic_executable_branch_serializability_witness
    : ∃ (s final : Store) (ts : List Tx),
        (∀ t ∈ ts,
          ∃ (w : State) (tid : Nat),
            Model.transitionSystem.Reachable w ∧ find w.txs tid = some t)
        ∧ SemanticAppliedBranch s ts final
        ∧ ts ≠ [] := by
  refine ⟨{}, advance {} witnessTx.normal.writes, [witnessTx], ?_, ?_, by decide +kernel⟩
  · intro t member
    simp only [List.mem_singleton] at member
    subst t
    exact ⟨witnessState, 1, witness_reachable, rfl⟩
  · exact .cons _ _ _ _ [] rfl (.nil _)

end Kv.Proofs.SemanticInvariant
