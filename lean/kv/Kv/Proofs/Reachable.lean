-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Invariants

/-!
The executable model's state invariants, their preservation by every accepted step, and the
claims that depend on them: store invariants, serializability of replayed segments, and global
reads from captured maps.

This module is self-contained: shared lemmas are duplicated as private declarations in each
proof module so that the proof modules can be checked in parallel.
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

private theorem replay_iff_run (w final : World) (rs : List Record)
    : CCF.Execution.Run transitionSystem w rs final ↔ replay w rs = .ok final := by
  induction rs generalizing w with
  | nil =>
      constructor
      · intro run
        cases run using @CCF.Execution.Run.casesOn transitionSystem
        rfl
      · intro accepted
        cases accepted
        exact .nil _
  | cons r rs ih =>
      constructor
      · intro run
        cases run using @CCF.Execution.Run.casesOn transitionSystem with
        | cons transition rest =>
            simp only [replay, (step_iff_transition _ _ _).mp transition, Except.bind]
            exact (ih _).mp rest
      · intro accepted
        simp only [replay] at accepted
        cases accepted' : step w r with
        | error failure => simp [accepted', Except.bind] at accepted
        | ok next =>
            simp only [accepted', Except.bind] at accepted
            exact .cons ((step_iff_transition _ _ _).mpr accepted') ((ih _).mpr accepted)

end Kv.Proofs.Execution

namespace Kv.Proofs.Invariants

open Kv.Model Kv.Properties

/-- Executes operations in order with `normalStep` to reconstruct the normal view. -/
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
private structure WorldInvariant (w : World) : Prop where
  /-- Live stores have well-formed histories. -/
  stores : ∀ sid s, find w.stores sid = some s → StoreInvariant s
  /-- Live attempts have valid logs and captured views. -/
  txs : ∀ tid t, find w.txs tid = some t → TxInvariant t

/-- An attempt keeps its snapshot, pinned data and global views, and its invariant. -/
private structure Frozen (t next : Tx) : Prop where
  /-- The captured snapshot is unchanged. -/
  snapshot : next.snapshot = t.snapshot
  /-- The pinned local data is unchanged. -/
  data : next.data = t.data
  /-- The captured global views are unchanged. -/
  globals : next.globalViews = t.globalViews
  /-- The attempt invariant is preserved. -/
  valid : TxInvariant t → TxInvariant next

/-- How an accepted event changes the live stores and attempts. -/
private inductive StepEffect (w : World) : Event → World → Prop
  /-- Stores and attempts are unchanged. -/
  | same {e : Event} {next : World} (stores : next.stores = w.stores)
    (txs : next.txs = w.txs) (noApply : ∀ sid, projectedApplication w sid e = [])
    : StepEffect w e next
  /-- A fresh store is created. -/
  | storeCreate {sid : Nat} {next : World} (stores : next.stores = set w.stores sid {})
    (txs : next.txs = w.txs)
    : StepEffect w (.storeCreate sid) next
  /-- A store is ended. -/
  | storeEnd {sid : Nat} {next : World} (stores : next.stores = erase w.stores sid)
    (txs : next.txs = w.txs)
    : StepEffect w (.storeEnd sid) next
  /-- A fresh attempt is created. -/
  | txCreate {sid tid : Nat} {next : World} (stores : next.stores = w.stores)
    (txs : next.txs = set w.txs tid { store := sid })
    : StepEffect w (.txCreate sid tid) next
  /-- An attempt is ended. -/
  | txEnd {sid tid : Nat} {next : World} (stores : next.stores = w.stores)
    (txs : next.txs = erase w.txs tid)
    : StepEffect w (.txEnd sid tid) next
  /-- A store is compacted. -/
  | compact {sid version requested : Nat} {next : World} {s : Store}
    (store : storeOf w sid = .ok s)
    (stores : next.stores = set w.stores sid (compactStore s requested))
    (txs : next.txs = w.txs)
    : StepEffect w (.compact sid version requested) next
  /-- A store is rolled back. -/
  | rollback {sid version requested term : Nat} {next : World} {s : Store}
    (store : storeOf w sid = .ok s)
    (stores : next.stores = set w.stores sid (rollbackStore s version term))
    (txs : next.txs = w.txs)
    : StepEffect w (.rollback sid version requested term) next
  /-- An attempt captures its snapshot; the store may learn its term. -/
  | snapshot {sid tid version global term : Nat} {next : World} {s established : Store}
    {t : Tx} (store : storeOf w sid = .ok s) (history : established.history = s.history)
    (head : established.head = s.head) (globalCut : established.global = s.global)
    (tx : find w.txs tid = some t) (fresh : t.snapshot = none)
    (stores : next.stores = set w.stores sid established)
    (txs
      : next.txs = set w.txs tid { t with snapshot := some { current := s.head, term } })
    : StepEffect w (.snapshot sid tid version global term) next
  /-- An attempt acquires a map. -/
  | acquire {sid tid version global : Nat} {m : String} {next : World} {s : Store}
    {t t' : Tx} (store : storeOf w sid = .ok s) (tx : txOf w sid tid = .ok t)
    (accepted : acquireMap s t m version global = .ok t')
    (stores : next.stores = w.stores) (txs : next.txs = set w.txs tid t')
    : StepEffect w (.acquire sid tid m version global) next
  /-- An attempt is applied to its store. -/
  | apply {sid tid version term : Nat} {writes : Pending} {next : World} {s new : Store}
    {t : Tx} (store : storeOf w sid = .ok s) (tx : txOf w sid tid = .ok t)
    (applied : tryApply s t = some new) (stores : next.stores = set w.stores sid new)
    (txs : next.txs = set w.txs tid { t with phase := .applied version })
    : StepEffect w (.apply sid tid version term writes) next
  /-- An attempt changes without moving its snapshot, pinned data or global views. -/
  | update {e : Event} {sid tid : Nat} {next : World} {t t' : Tx}
    (tx : txOf w sid tid = .ok t) (frozen : Frozen t t')
    (stores : next.stores = w.stores) (txs : next.txs = set w.txs tid t')
    (noApply : ∀ sid, projectedApplication w sid e = [])
    : StepEffect w e next

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
      simp only [normalStep, observes, valueAt, previousAt, needs, hf]
      rfl
  | scan name entries =>
      change image (pinData db m acquired) name = image db name at hi
      simp only [normalStep, observes, scanAt, needs, hi]
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

private theorem acquireMap_invariant (s : Store) (store : StoreInvariant s)
    (t next : Tx) (valid : TxInvariant t) (map : String) (version global : Nat)
    (accepted : acquireMap s t map version global = .ok next)
    : TxInvariant next := by
  obtain ⟨_, _, _, _, unused, rfl⟩ := acquireMap_ok accepted
  refine ⟨acquisition_normal t valid.normal map _ unused, valid.snapshot, ?_⟩
  intro name view found
  rw [find_set_cases] at found
  split at found
  · cases found
    exact captureGlobal_invariant s store _ map
  · exact valid.globals name view found

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

private theorem storeOf_invariant (w : World) (valid : WorldInvariant w) (sid : Nat)
    (s : Store) (found : storeOf w sid = .ok s)
    : StoreInvariant s := by
  cases h : find w.stores sid <;> simp [storeOf, present, invalid, h] at found
  next => cases found; exact valid.stores sid _ h

private theorem txOf_found (w : World) (sid tid : Nat) (t : Tx)
    (found : txOf w sid tid = .ok t)
    : find w.txs tid = some t := by
  obtain ⟨_, -, found⟩ := bind_ok found
  obtain ⟨_, lookup, found⟩ := bind_ok found
  obtain ⟨_, -, found⟩ := bind_ok found
  cases pure_ok found
  exact present_ok lookup

private theorem txOf_invariant (w : World) (valid : WorldInvariant w) (sid tid : Nat)
    (t : Tx) (found : txOf w sid tid = .ok t)
    : TxInvariant t :=
  valid.txs tid t (txOf_found w sid tid t found)

private theorem tryApply_invariant (s next : Store) (valid : StoreInvariant s) (t : Tx)
    (applied : tryApply s t = some next)
    : StoreInvariant next := by
  unfold tryApply at applied
  split at applied
  · cases applied; exact advance_invariant s valid t.normal.writes
  · contradiction

private theorem world_initial : WorldInvariant {} := by
  constructor <;> simp [find]

private theorem Frozen.refl (t : Tx) : Frozen t t := ⟨rfl, rfl, rfl, id⟩

private theorem Frozen.trans {a b c : Tx} (ab : Frozen a b) (bc : Frozen b c)
    : Frozen a c :=
  ⟨
    bc.snapshot.trans ab.snapshot,
    bc.data.trans ab.data,
    bc.globals.trans ab.globals,
    bc.valid ∘ ab.valid
  ⟩

private theorem Frozen.fields {t next : Tx} (snapshot : next.snapshot = t.snapshot)
    (data : next.data = t.data) (normal : next.normal = t.normal)
    (globals : next.globalViews = t.globalViews)
    : Frozen t next :=
  ⟨
    snapshot,
    data,
    globals,
    fun valid => tx_fields_invariant t next valid snapshot data normal globals
  ⟩

private theorem runOp_frozen {t next : Tx} {op : NormalOp String String String}
    (accepted : runOp t op = .ok next)
    : Frozen t next := by
  simp only [runOp, Pure.pure, Except.pure] at accepted
  split at accepted
  next => contradiction
  next snap hs =>
    split at accepted
    next n hn =>
      cases accepted
      exact ⟨rfl, rfl, rfl, fun valid =>
        ⟨operation_normal t valid.normal snap n op hs hn, valid.snapshot, valid.globals⟩⟩
    next => contradiction

private theorem clearWrites_frozen {t next : Tx} {map : String}
    {entries : Assoc String String} (accepted : clearWrites t map entries = .ok next)
    : Frozen t next := by
  unfold clearWrites at accepted
  induction entries generalizing t with
  | nil => cases accepted; exact Frozen.refl _
  | cons entry entries ih =>
      obtain ⟨middle, one, rest⟩ := bind_ok accepted
      exact (runOp_frozen one).trans (ih rest)

private theorem StepEffect.withTx {w next : World} {e : Event} {sid tid : Nat}
    {f : Tx → Except Failure Tx} (noApply : ∀ sid, projectedApplication w sid e = [])
    (frozen : ∀ t t', f t = .ok t' → Frozen t t')
    (accepted : withTx w sid tid f = .ok next)
    : StepEffect w e next := by
  obtain ⟨t, t', tx, h, rfl⟩ := withTx_ok accepted
  exact .update tx (frozen t t' h) rfl rfl noApply

private theorem stepEvent_effect_rollbackRejected (w next : World)
    (store requested term : Nat)
    (accepted : stepEvent w (.rollbackRejected store requested term) = .ok next)
    : StepEffect w (.rollbackRejected store requested term) next := by
  repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
  cases pure_ok accepted
  exact .same rfl rfl fun _ => rfl

private theorem stepEvent_effect_storeCreate (w next : World) (store : Nat)
    (accepted : stepEvent w (.storeCreate store) = .ok next)
    : StepEffect w (.storeCreate store) next := by
  repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
  cases pure_ok accepted
  exact .storeCreate rfl rfl

private theorem stepEvent_effect_storeEnd (w next : World) (store : Nat)
    (accepted : stepEvent w (.storeEnd store) = .ok next)
    : StepEffect w (.storeEnd store) next := by
  repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
  cases pure_ok accepted
  exact .storeEnd rfl rfl

private theorem stepEvent_effect_txCreate (w next : World) (store tx : Nat)
    (accepted : stepEvent w (.txCreate store tx) = .ok next)
    : StepEffect w (.txCreate store tx) next := by
  repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
  cases pure_ok accepted
  exact .txCreate rfl rfl

private theorem stepEvent_effect_txEnd (w next : World) (store tx : Nat)
    (accepted : stepEvent w (.txEnd store tx) = .ok next)
    : StepEffect w (.txEnd store tx) next := by
  repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
  cases pure_ok accepted
  exact .txEnd rfl rfl

private theorem stepEvent_effect_snapshot (w next : World)
    (sid tid version global term : Nat)
    (accepted : stepEvent w (.snapshot sid tid version global term) = .ok next)
    : StepEffect w (.snapshot sid tid version global term) next := by
  obtain ⟨s, store, accepted⟩ := bind_ok accepted
  obtain ⟨t, t', tx, h, rfl⟩ := withTx_ok accepted
  obtain ⟨_, -, h⟩ := bind_ok h
  split at h
  next fresh =>
    obtain ⟨_, -, h⟩ := bind_ok h
    cases pure_ok h
    have live := txOf_found _ sid tid t tx
    exact .snapshot store (by split <;> rfl) (by split <;> rfl) (by split <;> rfl)
      live fresh rfl rfl
  next => cases h

private theorem stepEvent_effect_apply (w next : World) (store tx version term : Nat)
    (writes : Pending)
    (accepted : stepEvent w (.apply store tx version term writes) = .ok next)
    : StepEffect w (.apply store tx version term writes) next := by
  obtain ⟨s, store, accepted⟩ := bind_ok accepted
  obtain ⟨t, tx, accepted⟩ := bind_ok accepted
  obtain ⟨_, -, accepted⟩ := bind_ok accepted
  obtain ⟨_, -, accepted⟩ := bind_ok accepted
  obtain ⟨_, -, accepted⟩ := bind_ok accepted
  obtain ⟨_, -, accepted⟩ := bind_ok accepted
  split at accepted
  next new applied =>
    obtain ⟨_, same, accepted⟩ := bind_ok accepted
    cases pure_ok same
    obtain ⟨_, -, accepted⟩ := bind_ok accepted
    cases pure_ok accepted
    exact .apply store tx applied rfl rfl
  next =>
    obtain ⟨_, rejected, -⟩ := bind_ok accepted
    cases rejected

private theorem stepEvent_effect_get (w next : World) (store tx : Nat) (map key : String)
    (value : Option String) (global : Bool)
    (accepted : stepEvent w (.get store tx map key value global) = .ok next)
    : StepEffect w (.get store tx map key value global) next := by
  refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
  obtain ⟨_, -, h⟩ := bind_ok h
  split at h
  · repeat obtain ⟨_, -, h⟩ := bind_ok h
    cases pure_ok h
    exact .refl _
  · exact runOp_frozen h

private theorem stepEvent_effect_has (w next : World) (store tx : Nat) (map key : String)
    (value : Bool) (global : Bool)
    (accepted : stepEvent w (.has store tx map key value global) = .ok next)
    : StepEffect w (.has store tx map key value global) next := by
  refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
  obtain ⟨_, -, h⟩ := bind_ok h
  split at h
  · repeat obtain ⟨_, -, h⟩ := bind_ok h
    cases pure_ok h
    exact .refl _
  · repeat obtain ⟨_, -, h⟩ := bind_ok h
    exact runOp_frozen h

private theorem stepEvent_effect_previous (w next : World) (store tx : Nat)
    (map key : String) (value : Option Nat)
    (accepted : stepEvent w (.previous store tx map key value) = .ok next)
    : StepEffect w (.previous store tx map key value) next := by
  refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
  repeat obtain ⟨_, -, h⟩ := bind_ok h
  exact runOp_frozen h

private theorem stepEvent_effect_put (w next : World) (store tx : Nat)
    (map key value : String)
    (accepted : stepEvent w (.put store tx map key value) = .ok next)
    : StepEffect w (.put store tx map key value) next := by
  refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
  repeat obtain ⟨_, -, h⟩ := bind_ok h
  exact runOp_frozen h

private theorem stepEvent_effect_remove (w next : World) (store tx : Nat)
    (map key : String) (accepted : stepEvent w (.remove store tx map key) = .ok next)
    : StepEffect w (.remove store tx map key) next := by
  refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
  repeat obtain ⟨_, -, h⟩ := bind_ok h
  exact runOp_frozen h

private theorem stepEvent_effect_size (w next : World) (store tx : Nat) (map : String)
    (value : Nat) (accepted : stepEvent w (.size store tx map value) = .ok next)
    : StepEffect w (.size store tx map value) next := by
  refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
  repeat obtain ⟨_, -, h⟩ := bind_ok h
  exact runOp_frozen h

private theorem stepEvent_effect_range (w next : World) (store tx : Nat) (map : String)
    (lower upper : Option String) (entries : Assoc String String)
    (accepted : stepEvent w (.range store tx map lower upper entries) = .ok next)
    : StepEffect w (.range store tx map lower upper entries) next := by
  refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
  obtain ⟨_, -, h⟩ := bind_ok h
  split at h
  · obtain ⟨_, -, h⟩ := bind_ok h
    cases pure_ok h
    exact .refl _
  · obtain ⟨_, -, h⟩ := bind_ok h
    exact runOp_frozen h

private theorem stepEvent_effect_clear (w next : World) (store tx : Nat) (map : String)
    (accepted : stepEvent w (.clear store tx map) = .ok next)
    : StepEffect w (.clear store tx map) next := by
  refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
  obtain ⟨_, -, h⟩ := bind_ok h
  obtain ⟨_, one, h⟩ := bind_ok h
  exact (runOp_frozen one).trans (clearWrites_frozen h)

private theorem stepEvent_effect_foreachBegin (w next : World) (store tx : Nat)
    (map : String) (iteration : Nat)
    (accepted : stepEvent w (.foreachBegin store tx map iteration) = .ok next)
    : StepEffect w (.foreachBegin store tx map iteration) next := by
  refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
  obtain ⟨_, -, h⟩ := bind_ok h
  obtain ⟨_, -, h⟩ := bind_ok h
  obtain ⟨_, one, h⟩ := bind_ok h
  cases pure_ok h
  exact (runOp_frozen one).trans (.fields rfl rfl rfl rfl)

private theorem stepEvent_effect_unavailable (w next : World) (store tx : Nat)
    (map : String) (accepted : stepEvent w (.unavailable store tx map) = .ok next)
    : StepEffect w (.unavailable store tx map) next := by
  obtain ⟨_, -, accepted⟩ := bind_ok accepted
  refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
  repeat obtain ⟨_, -, h⟩ := bind_ok h
  cases pure_ok h
  exact .fields rfl rfl rfl rfl

private theorem stepEvent_effect_commitResult (w next : World) (store tx : Nat)
    (result : Outcome) (version : Nat)
    (accepted : stepEvent w (.commitResult store tx result version) = .ok next)
    : StepEffect w (.commitResult store tx result version) next := by
  refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
  split at h
  next =>
    obtain ⟨_, -, h⟩ := bind_ok h
    cases pure_ok h
    exact .fields rfl rfl rfl rfl
  next =>
    obtain ⟨_, -, h⟩ := bind_ok h
    split at h
    · obtain ⟨_, -, h⟩ := bind_ok h
      cases pure_ok h
      exact .fields rfl rfl rfl rfl
    · cases pure_ok h
      exact .fields rfl rfl rfl rfl
  next =>
    obtain ⟨_, -, h⟩ := bind_ok h
    cases pure_ok h
    exact .fields rfl rfl rfl rfl

private theorem stepEvent_effect (w next : World) (e : Event)
    (accepted : stepEvent w e = .ok next)
    : StepEffect w e next := by
  cases e with
  | traceStart | caseBegin | caseEnd | subcaseBegin | subcaseEnd | traceEnd =>
      repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
      cases pure_ok accepted
      exact .same rfl rfl fun _ => rfl
  | rollbackRejected => exact stepEvent_effect_rollbackRejected w next _ _ _ accepted
  | unsupported => cases accepted
  | storeCreate => exact stepEvent_effect_storeCreate w next _ accepted
  | storeEnd => exact stepEvent_effect_storeEnd w next _ accepted
  | txCreate => exact stepEvent_effect_txCreate w next _ _ accepted
  | txEnd => exact stepEvent_effect_txEnd w next _ _ accepted
  | compact =>
      obtain ⟨s, store, accepted⟩ := bind_ok accepted
      repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
      cases pure_ok accepted
      exact .compact store rfl rfl
  | rollback =>
      obtain ⟨s, store, accepted⟩ := bind_ok accepted
      repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
      cases pure_ok accepted
      exact .rollback store rfl rfl
  | snapshot => exact stepEvent_effect_snapshot w next _ _ _ _ _ accepted
  | acquire =>
      obtain ⟨s, store, accepted⟩ := bind_ok accepted
      obtain ⟨t, t', tx, h, rfl⟩ := withTx_ok accepted
      exact .acquire store tx h rfl rfl
  | apply => exact stepEvent_effect_apply w next _ _ _ _ _ accepted
  | get => exact stepEvent_effect_get w next _ _ _ _ _ _ accepted
  | has => exact stepEvent_effect_has w next _ _ _ _ _ _ accepted
  | previous => exact stepEvent_effect_previous w next _ _ _ _ _ accepted
  | put => exact stepEvent_effect_put w next _ _ _ _ _ accepted
  | remove => exact stepEvent_effect_remove w next _ _ _ _ accepted
  | size => exact stepEvent_effect_size w next _ _ _ _ accepted
  | range => exact stepEvent_effect_range w next _ _ _ _ _ _ accepted
  | clear => exact stepEvent_effect_clear w next _ _ _ accepted
  | foreachBegin => exact stepEvent_effect_foreachBegin w next _ _ _ _ accepted
  | foreachEntry | foreachContinue | foreachEnd =>
      refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
      obtain ⟨⟨_, _⟩, -, h⟩ := bind_ok h
      repeat obtain ⟨_, -, h⟩ := bind_ok h
      cases pure_ok h
      exact .fields rfl rfl rfl rfl
  | unavailable => exact stepEvent_effect_unavailable w next _ _ _ accepted
  | commitBegin =>
      refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
      repeat obtain ⟨_, -, h⟩ := bind_ok h
      cases pure_ok h
      exact .fields rfl rfl rfl rfl
  | commitResult => exact stepEvent_effect_commitResult w next _ _ _ _ accepted

private theorem stepEvent_invariant (w next : World) (valid : WorldInvariant w)
    (e : Event) (accepted : stepEvent w e = .ok next)
    : WorldInvariant next := by
  cases stepEvent_effect w next e accepted with
  | same stores txs =>
      exact ⟨by rw [stores]; exact valid.stores, by rw [txs]; exact valid.txs⟩
  | storeCreate stores txs =>
      exact ⟨
        by rw [stores]; exact lookup_set_invariant _ _ valid.stores _ _ store_initial,
        by rw [txs]; exact valid.txs
      ⟩
  | storeEnd stores txs =>
      exact ⟨
        by rw [stores]; exact lookup_erase_invariant _ _ valid.stores _,
        by rw [txs]; exact valid.txs
      ⟩
  | txCreate stores txs =>
      exact ⟨
        by rw [stores]; exact valid.stores,
        by rw [txs]; exact lookup_set_invariant _ _ valid.txs _ _ (tx_initial _)
      ⟩
  | txEnd stores txs =>
      exact ⟨
        by rw [stores]; exact valid.stores,
        by rw [txs]; exact lookup_erase_invariant _ _ valid.txs _
      ⟩
  | compact store stores txs =>
      exact ⟨
        by
          rw [stores]
          exact lookup_set_invariant _ _ valid.stores _ _
            (compact_invariant _ (storeOf_invariant w valid _ _ store) _),
        by rw [txs]; exact valid.txs
      ⟩
  | rollback store stores txs =>
      exact ⟨
        by
          rw [stores]
          exact lookup_set_invariant _ _ valid.stores _ _
            (rollback_invariant _ (storeOf_invariant w valid _ _ store) _ _),
        by rw [txs]; exact valid.txs
      ⟩
  | snapshot store history head globalCut tx fresh stores txs =>
      have shape := storeOf_invariant w valid _ _ store
      refine ⟨?_, ?_⟩
      · rw [stores]
        refine lookup_set_invariant _ _ valid.stores _ _ ⟨?_, ?_, ?_⟩
        · rw [history, head]; exact shape.historyShape
        · rw [history, head]; exact shape.headFirst
        · rw [globalCut, head]; exact shape.globalBound
      · rw [txs]
        exact lookup_set_invariant _ _ valid.txs _ _
          (snapshot_invariant _ shape _ _ (valid.txs _ _ tx) fresh)
  | acquire store tx acquired stores txs =>
      exact ⟨
        by rw [stores]; exact valid.stores,
        by
          rw [txs]
          exact lookup_set_invariant _ _ valid.txs _ _
            (acquireMap_invariant _ (storeOf_invariant w valid _ _ store) _ _
              (txOf_invariant w valid _ _ _ tx) _ _ _ acquired)
      ⟩
  | apply store tx applied stores txs =>
      exact ⟨
        by
          rw [stores]
          exact lookup_set_invariant _ _ valid.stores _ _
            (tryApply_invariant _ _ (storeOf_invariant w valid _ _ store) _ applied),
        by
          rw [txs]
          exact lookup_set_invariant _ _ valid.txs _ _
            (tx_fields_invariant _ _ (txOf_invariant w valid _ _ _ tx) rfl rfl rfl rfl)
      ⟩
  | update tx frozen stores txs =>
      exact ⟨
        by rw [stores]; exact valid.stores,
        by
          rw [txs]
          exact lookup_set_invariant _ _ valid.txs _ _
            (frozen.valid (txOf_invariant w valid _ _ _ tx))
      ⟩

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

private theorem step_invariant (w next : World) (valid : WorldInvariant w) (r : Record)
    (accepted : step w r = .ok next)
    : WorldInvariant next := by
  obtain ⟨_, event, rfl⟩ := step_ok accepted
  have eventValid := stepEvent_invariant w _ valid r.event event
  exact ⟨eventValid.stores, eventValid.txs⟩

private theorem reachable_invariant (w : World) (reachable : transitionSystem.Reachable w)
    : WorldInvariant w := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | initial initialized => cases initialized; exact world_initial
  | step _ transition ih =>
      exact step_invariant _ _ ih _ ((Execution.step_iff_transition _ _ _).mp transition)

end Kv.Proofs.Invariants

namespace Kv.Proofs.Model

open Kv.Model Kv.Proofs.Invariants Kv.Properties
section Generic
variable {M K V : Type} [DecidableEq M] [DecidableEq K]

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
end Kv.Proofs.Model

namespace Kv.Proofs.Model

open Kv.Model Kv.Proofs.Invariants Kv.Properties
section Generic
variable {M K V : Type} [DecidableEq M] [DecidableEq K]
variable [DecidableEq V]

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
        validates current n.deps = true := by simpa [validates_append] using hv
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
        validates current n.deps = true := by simpa [validates_append] using hv
    have hneeds := hh.1
    have hobs := dependency_rebase snapshot current n.writes op hneeds
    rw [serialStep_eq, ← hobs]
    simp [h]
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
              simp [validates_append, validates_self, hn]
            next h => simp at hs
          · simpa [normalRun, hs] using hr

private theorem readonly_snapshot_serial (snapshot : DB M K V)
    (ops : List (NormalOp M K V)) (n : Normal M K V)
    (hr : normalRun snapshot {} ops = some n)
    : serialRun snapshot [] ops = some n.writes :=
  normalRun_serial snapshot snapshot ops {} n hr
    (normalRun_snapshot_valid snapshot ops {} n (by rfl) hr)

end Generic
end Kv.Proofs.Model

namespace Kv.Proofs.Model

open Kv.Model Kv.Proofs.Invariants Kv.Properties

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
    (h : AppliedBranch s ts final)
    : serialTransactions s.head.data s.head.version ts = some final.head.data := by
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
      simp only [serialTransactions, hw.1, Option.bind_some]
      rw [← hw.2, ← hversion]
      exact ih (fun tx member => valid tx (by simp [member]))

end Kv.Proofs.Model

namespace Kv.Proofs.Trace

open Kv.Model Kv.Proofs.Invariants Kv.Properties Kv.Proofs.Model

/-- The head of `after` is that of `before`, or follows from it by applying the listed attempt. -/
private inductive HeadEffect (before after : Store) : List Tx → Prop
  /-- The head data and version are unchanged. -/
  | stutter (data : after.head.data = before.head.data)
    (version : after.head.version = before.head.version)
    : HeadEffect before after []
  /-- One attempt is applied. -/
  | apply (tx : Tx) (one : tryApply before tx = some after) : HeadEffect before after [tx]

private theorem storeOf_ok (w : World) (sid : Nat) (s : Store)
    : storeOf w sid = .ok s ↔ find w.stores sid = some s := by
  cases h : find w.stores sid <;> simp [storeOf, present, invalid, h]

private theorem stable_update_store_effect (w next : World) (sid id : Nat)
    (s old new : Store) (hs : find w.stores sid = some s)
    (hold : find w.stores id = some old) (same : next.stores = set w.stores id new)
    (head : new.head = old.head)
    : ∃ after, find next.stores sid = some after ∧ HeadEffect s after [] := by
  by_cases h : id = sid
  · subst id
    have ho : old = s := Option.some.inj (hold.symm.trans hs)
    subst old
    exact ⟨new, by simp [same, find_set_same], .stutter (congrArg Frame.data head)
      (congrArg Frame.version head)⟩
  · exact ⟨s, by simpa [same, find_set_other _ id sid new h] using hs, .stutter rfl rfl⟩

private theorem stepEvent_store_effect (w next : World) (sid : Nat) (s : Store)
    (e : Event) (hs : find w.stores sid = some s) (segment : SegmentEvent sid e)
    (accepted : stepEvent w e = .ok next)
    : ∃ after,
        find next.stores sid = some after
        ∧ HeadEffect s after (projectedApplication w sid e) := by
  have unchanged_store_effect (w next : World) (sid : Nat) (s : Store) (e : Event)
      (hs : find w.stores sid = some s) (same : next.stores = w.stores)
      (noApply : projectedApplication w sid e = [])
      : ∃ after,
          find next.stores sid = some after
          ∧ HeadEffect s after (projectedApplication w sid e) := by
    refine ⟨s, ?_, ?_⟩
    · simpa [same] using hs
    · rw [noApply]
      exact .stutter rfl rfl
  have applied_update_store_effect (w next : World) (sid id tid : Nat)
      (s old new : Store) (t : Tx)
      (hs : find w.stores sid = some s) (hold : storeOf w id = .ok old)
      (htx : txOf w id tid = .ok t) (ha : tryApply old t = some new)
      (same : next.stores = set w.stores id new)
      : ∃ after,
          find next.stores sid = some after
          ∧ HeadEffect s after
              (if id = sid then (txOf w id tid).toOption.toList else []) := by
    have hf := (storeOf_ok w id old).mp hold
    by_cases h : id = sid
    · subst id
      have ho : old = s := Option.some.inj (hf.symm.trans hs)
      subst old
      refine ⟨new, by simp [same, find_set_same], ?_⟩
      simpa [htx, Except.toOption, Option.toList] using HeadEffect.apply t ha
    · refine ⟨s, by simpa [same, find_set_other _ id sid new h] using hs, ?_⟩
      simpa [h] using HeadEffect.stutter (before := s) rfl rfl
  cases stepEvent_effect w next e accepted with
  | same stores _ noApply =>
      exact unchanged_store_effect w next sid s _ hs stores (noApply sid)
  | storeCreate stores _ | rollback _ stores _ =>
      exact ⟨
        s,
        by rw [stores, find_set_other _ _ _ _ segment]; exact hs,
        .stutter rfl rfl
      ⟩
  | storeEnd stores _ =>
      exact ⟨
        s,
        by rw [stores, find_erase_other _ _ _ segment]; exact hs,
        .stutter rfl rfl
      ⟩
  | txCreate stores _ | txEnd stores _ | acquire _ _ _ stores _ =>
      exact unchanged_store_effect w next sid s _ hs stores rfl
  | compact store stores _ =>
      exact stable_update_store_effect w next sid _ s _ _ hs ((storeOf_ok _ _ _).mp store) stores
        (compact_preserves_head _ _)
  | snapshot store _ head _ _ _ stores _ =>
      exact stable_update_store_effect w next sid _ s _ _ hs ((storeOf_ok _ _ _).mp store) stores
        head
  | apply store tx applied stores _ =>
      exact applied_update_store_effect w next sid _ _ s _ _ _ hs store tx applied stores
  | update _ _ stores _ noApply =>
      exact unchanged_store_effect w next sid s _ hs stores (noApply sid)

private theorem step_event_result (w next : World) (r : Record)
    (accepted : step w r = .ok next)
    : ∃ eventNext,
        stepEvent w r.event = .ok eventNext
        ∧ next.stores = eventNext.stores
        ∧ next.txs = eventNext.txs := by
  obtain ⟨eventNext, event, rfl⟩ := step_ok accepted
  exact ⟨eventNext, event, rfl, rfl⟩

private theorem HeadEffect.serial_witness (before after : Store) (txs : List Tx)
    (valid : ∀ t ∈ txs, NormalInvariant t)
    (effect : HeadEffect before after txs)
    : serialTransactions before.head.data before.head.version txs = some after.head.data
      ∧ after.head.version = before.head.version + txs.length := by
  cases effect with
  | stutter data version => simp [serialTransactions, data, version]
  | apply tx one =>
      have h := tryApply_serial before after tx (valid tx (by simp)) one
      constructor
      · simpa [serialTransactions, h.1] using congrArg some h.2.symm
      · unfold tryApply at one
        split at one
        next => cases one; rfl
        next => simp at one

private theorem serialTransactions_append (db : Data) (version : Nat) (xs ys : List Tx)
    : serialTransactions db version (xs ++ ys)
      = (serialTransactions db version xs).bind
          (fun next => serialTransactions next (version + xs.length) ys) := by
  induction xs generalizing db version with
  | nil => rfl
  | cons tx xs ih =>
      cases h : serialRun db [] tx.normal.log with
      | none => simp [serialTransactions, h]
      | some writes =>
          simp [serialTransactions, h, ih, Nat.add_comm, Nat.add_left_comm]

private theorem projectedApplication_normal (w : World) (valid : WorldInvariant w)
    (sid : Nat) (e : Event)
    : ∀ t ∈ projectedApplication w sid e, NormalInvariant t := by
  cases e <;> simp only [projectedApplication]
  all_goals try exact fun _ member => False.elim (List.not_mem_nil member)
  rename_i id tid version term writes
  intro t member
  by_cases same : id = sid
  · subst id
    simp only [ite_true] at member
    cases lookup : txOf w sid tid with
    | error err => simp [lookup, Except.toOption] at member
    | ok tx =>
        have equal : t = tx := by
          simpa [lookup, Except.toOption, Option.toList] using member
        subst t
        exact (txOf_invariant w valid sid tid tx lookup).normal
  · simp [same] at member

/-- A selected store stays live throughout the segment. Its rollback/create/end
events partition segments; all other-store events are permitted. The projected
attempts are obtained from the real pre-event txOf, not supplied as a premise. -/
private theorem replay_segment_serializability (w final : World) (sid : Nat) (s : Store)
    (valid : WorldInvariant w)
    (rs : List Record) (live : find w.stores sid = some s)
    (segment : ∀ r ∈ rs, SegmentEvent sid r.event)
    (accepted : replay w rs = .ok final)
    : ∃ after txs,
        find final.stores sid = some after
        ∧ projectApplications w sid rs = .ok txs
        ∧ serialTransactions s.head.data s.head.version txs = some after.head.data
        ∧ after.head.version = s.head.version + txs.length := by
  have step_store_effect (w next : World) (sid : Nat) (s : Store) (r : Record)
      (hs : find w.stores sid = some s) (segment : SegmentEvent sid r.event)
      (accepted : step w r = .ok next)
      : ∃ after,
          find next.stores sid = some after
          ∧ HeadEffect s after (projectedApplication w sid r.event) := by
    obtain ⟨eventNext, he, stores, _⟩ := step_event_result w next r accepted
    obtain ⟨after, found, effect⟩ := stepEvent_store_effect w eventNext sid s r.event hs segment he
    exact ⟨after, by simpa [stores] using found, effect⟩
  induction rs generalizing w s with
  | nil =>
      cases accepted
      exact ⟨s, [], live, rfl, rfl, by simp⟩
  | cons r rs ih =>
      cases first : step w r with
      | error err => simp [replay, first, Except.bind] at accepted
      | ok middle =>
          have rest : replay middle rs = .ok final := by
            simpa [replay, first, Except.bind] using accepted
          obtain ⟨nextStore, nextLive, effect⟩ := step_store_effect w middle sid s r live
            (segment r (by simp)) first
          obtain ⟨after, tailTxs, afterLive, projected, tailSerial, tailVersion⟩ :=
            ih middle nextStore (step_invariant w middle valid r first) nextLive
              (fun e he => segment e (by simp [he])) rest
          have applications := projectedApplication_normal w valid sid r.event
          have one := HeadEffect.serial_witness s nextStore _ applications effect
          refine ⟨
            after,
            projectedApplication w sid r.event ++ tailTxs,
            afterLive,
            ?_,
            ?_,
            ?_
          ⟩
          · simp [projectApplications, first, projected, Bind.bind, Except.bind, Pure.pure, Except.pure]
          · rw [serialTransactions_append, one.1]
            simpa [← one.2] using tailSerial
          · simp only [List.length_append]
            rw [tailVersion, one.2]
            exact Nat.add_assoc _ _ _

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

theorem replay_segment_serializability_claim
    : ∀ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → (∀ r ∈ rs, SegmentEvent sid r.event)
        → CCF.Execution.Run Model.transitionSystem w rs final
        → ∃ after txs,
            find final.stores sid = some after
            ∧ projectApplications w sid rs = .ok txs
            ∧ serialTransactions s.head.data s.head.version txs = some after.head.data
            ∧ after.head.version = s.head.version + txs.length := by
  intro w final sid s rs reachable live segment accepted
  exact Proofs.Trace.replay_segment_serializability w final sid s
    (Invariants.reachable_invariant w reachable) rs live segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem reachable_store_invariants_claim
    : ∀ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → History s.history s.head.version
          ∧ s.history.head? = some s.head
          ∧ s.global ≤ s.head.version
          ∧ (atCut s s.global).version = s.global := by
  have reachable_store_invariants (w : World)
      (valid : WorldInvariant w)
      (sid : Nat) (s : Store) (_live : find w.stores sid = some s)
      : History s.history s.head.version
        ∧ s.history.head? = some s.head
        ∧ s.global ≤ s.head.version
        ∧ (atCut s s.global).version = s.global := by
    have store := valid.stores sid s _live
    exact ⟨store.historyShape, store.headFirst, store.globalBound,
      (atCut_spec s store s.global store.globalBound).1⟩
  intro w sid s reachable live
  exact reachable_store_invariants w (Invariants.reachable_invariant w reachable) sid s
    live

theorem reachable_store_data_invariants_claim
    : ∀ (w : World) (sid : Nat) (s : Store),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → Kv.Properties.Unique s.head.data ∧ CellsBounded s.head.data s.head.version := by
  have reachable_store_data_invariants (w : World)
      (valid : WorldInvariant w)
      (sid : Nat) (s : Store) (_live : find w.stores sid = some s)
      : Kv.Properties.Unique s.head.data ∧ CellsBounded s.head.data s.head.version := by
    have store := valid.stores sid s _live
    have unique := History.head_unique s.history s.head.version store.historyShape
    have bounded := History.head_cells_bounded s.history s.head.version store.historyShape
    simpa only [store.headFirst, Option.getD_some] using And.intro unique bounded
  intro w sid s reachable live
  exact reachable_store_data_invariants w (Invariants.reachable_invariant w reachable) sid
    s live

theorem step_global_read_from_captured_map_claim
    : ∀ (w next : World) (sid tid seq : Nat) (map key : String) (value : Option String)
        (t : Tx) (view : GlobalView),
        Model.transitionSystem.Reachable w
        → txOf w sid tid = .ok t
        → find t.globalViews map = some view
        → Model.transitionSystem.step w ⟨seq, .get sid tid map key value true⟩ = some next
        → value = (find view.frame.data (map, key)).map Cell.value
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  have stepEvent_get_global (w next : World) (sid tid : Nat) (map key : String)
      (value : Option String) (t : Tx) (view : GlobalView)
      (source : txOf w sid tid = .ok t) (captured : find t.globalViews map = some view)
      (accepted : stepEvent w (.get sid tid map key value true) = .ok next)
      : value = (find view.frame.data (map, key)).map Cell.value := by
    obtain ⟨_, _, tx, h, -⟩ := withTx_ok accepted
    cases source.symm.trans tx
    obtain ⟨_, -, h⟩ := bind_ok h
    obtain ⟨_, found, h⟩ := bind_ok h
    cases captured.symm.trans (present_ok found)
    obtain ⟨_, observed, -⟩ := bind_ok h
    exact (beq_iff_eq.mp (expect_ok observed)).symm
  have step_global_read_from_captured_map (w next : World) (sid tid seq : Nat)
      (valid : WorldInvariant w)
      (map key : String) (value : Option String) (t : Tx) (view : GlobalView)
      (source : txOf w sid tid = .ok t) (captured : find t.globalViews map = some view)
      (accepted : step w ⟨seq, .get sid tid map key value true⟩ = .ok next)
      : value = (find view.frame.data (map, key)).map Cell.value
        ∧ (view.frame = {}
            ∨ ∃ origin : Store,
                view.frame = atCut origin origin.global
                ∧ view.frame.version = origin.global
                ∧ CellsBounded view.frame.data origin.global) := by
    obtain ⟨eventNext, eventStep, _, _⟩ := step_event_result w next _ accepted
    exact ⟨stepEvent_get_global w eventNext sid tid map key value t view source captured eventStep,
      map_global_view_safety view
        ((txOf_invariant w valid sid tid t source).globals map view captured)⟩
  intro w next sid tid seq map key value t view reachable source captured accepted
  exact step_global_read_from_captured_map w next sid tid seq
    (Invariants.reachable_invariant w reachable) map key value t view source captured
    ((Proofs.Execution.step_iff_transition _ _ _).mp accepted)

theorem step_global_has_from_captured_map_claim
    : ∀ (w next : World) (sid tid seq : Nat) (map key : String) (value : Bool) (t : Tx)
        (view : GlobalView),
        Model.transitionSystem.Reachable w
        → txOf w sid tid = .ok t
        → find t.globalViews map = some view
        → Model.transitionSystem.step w ⟨seq, .has sid tid map key value true⟩ = some next
        → value = (find view.frame.data (map, key)).isSome
          ∧ (view.frame = {}
              ∨ ∃ origin : Store,
                  view.frame = atCut origin origin.global
                  ∧ view.frame.version = origin.global
                  ∧ CellsBounded view.frame.data origin.global) := by
  have stepEvent_has_global (w next : World) (sid tid : Nat) (map key : String)
      (value : Bool) (t : Tx) (view : GlobalView)
      (source : txOf w sid tid = .ok t) (captured : find t.globalViews map = some view)
      (accepted : stepEvent w (.has sid tid map key value true) = .ok next)
      : value = (find view.frame.data (map, key)).isSome := by
    obtain ⟨_, _, tx, h, -⟩ := withTx_ok accepted
    cases source.symm.trans tx
    obtain ⟨_, -, h⟩ := bind_ok h
    obtain ⟨_, found, h⟩ := bind_ok h
    cases captured.symm.trans (present_ok found)
    obtain ⟨_, observed, -⟩ := bind_ok h
    exact (beq_iff_eq.mp (expect_ok observed)).symm
  have step_global_has_from_captured_map (w next : World) (sid tid seq : Nat)
      (valid : WorldInvariant w)
      (map key : String) (value : Bool) (t : Tx) (view : GlobalView)
      (source : txOf w sid tid = .ok t) (captured : find t.globalViews map = some view)
      (accepted : step w ⟨seq, .has sid tid map key value true⟩ = .ok next)
      : value = (find view.frame.data (map, key)).isSome
        ∧ (view.frame = {}
            ∨ ∃ origin : Store,
                view.frame = atCut origin origin.global
                ∧ view.frame.version = origin.global
                ∧ CellsBounded view.frame.data origin.global) := by
    obtain ⟨eventNext, eventStep, _, _⟩ := step_event_result w next _ accepted
    exact ⟨stepEvent_has_global w eventNext sid tid map key value t view source captured eventStep,
      map_global_view_safety view
        ((txOf_invariant w valid sid tid t source).globals map view captured)⟩
  intro w next sid tid seq map key value t view reachable source captured accepted
  exact step_global_has_from_captured_map w next sid tid seq
    (Invariants.reachable_invariant w reachable) map key value t view source captured
    ((Proofs.Execution.step_iff_transition _ _ _).mp accepted)

end Kv.Proofs.Trace

namespace Kv.Proofs.Properties

open Kv.Model Kv.Properties

theorem transaction_snapshot_serial
    : ∀ (w : World) (tid : Nat) (t : Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        → find w.txs tid = some t
        → t.snapshot = some snap
        → serialRun t.data [] t.normal.log = some t.normal.writes := by
  intro w tid t snap reachable live captured
  exact Proofs.Model.transaction_snapshot_serial t snap
    ((Proofs.Invariants.reachable_invariant w reachable).txs tid t live).normal captured

theorem transaction_application_serial
    : ∀ (w : World) (sid tid : Nat) (s : Store) (t : Tx) (snap : Snapshot),
        Model.transitionSystem.Reachable w
        → storeOf w sid = .ok s
        → txOf w sid tid = .ok t
        → t.snapshot = some snap
        → canApply s t = true
        → serialRun s.head.data [] t.normal.log = some t.normal.writes := by
  intro w sid tid s t snap reachable _store tx captured applies
  exact Proofs.Model.transaction_application_serial s t snap
    (Proofs.Invariants.txOf_invariant w
      (Proofs.Invariants.reachable_invariant w reachable) sid tid t tx).normal
    captured applies

theorem executable_branch_serializability
    : ∀ (s final : Store) (ts : List Tx),
        (∀ t ∈ ts,
          ∃ (w : World) (tid : Nat),
            Model.transitionSystem.Reachable w ∧ find w.txs tid = some t)
        → AppliedBranch s ts final
        → serialTransactions s.head.data s.head.version ts = some final.head.data := by
  intro s final ts reachable branch
  apply Proofs.Model.executable_branch_serializability s final ts _ branch
  intro t member
  obtain ⟨w, tid, reached, live⟩ := reachable t member
  exact ((Proofs.Invariants.reachable_invariant w reached).txs tid t live).normal

theorem durable_cut_survives_rollback
    : ∀ (w : World) (sid : Nat) (s : Store) (v term cut : Nat),
        Model.transitionSystem.Reachable w
        → find w.stores sid = some s
        → cut ≤ s.global
        → s.global ≤ v
        → (atCut (rollbackStore s v term) cut).data = (atCut s cut).data := by
  intro w sid s v term cut reachable live below boundary
  exact Proofs.Model.durable_cut_survives_rollback s v term cut
    ((Proofs.Invariants.reachable_invariant w reachable).stores sid s live) below boundary

end Kv.Proofs.Properties
