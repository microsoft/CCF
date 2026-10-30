-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Invariants
public import Kv.Proofs.Execution

@[expose] public section

/-! Initialisation and preservation of the executable model's separate state invariants. -/

namespace Kv.Proofs.Invariants

open Kv.Model Kv.Properties

/-- Store histories are contiguous, headed by the current frame, and contain the global cut. -/
structure StoreInvariant (s : Store) : Prop where
  /-- Every frame follows by publishing writes to its predecessor. -/
  historyShape : History s.history s.head.version
  /-- The head is the newest frame. -/
  headFirst : s.history.head? = some s.head
  /-- The global version does not exceed the head. -/
  globalBound : s.global ≤ s.head.version

/-- A global view is empty or was captured at a well-formed store's global cut. -/
def GlobalInvariant (view : GlobalView) : Prop :=
  view.frame = {} ∨ ∃ s : Store, StoreInvariant s ∧ view.frame = atCut s s.global

/-- Replaying an attempt's log from its pinned data reproduces its normal view. -/
def NormalInvariant (t : Tx) : Prop :=
  match t.snapshot with
  | none => t.normal = {}
  | some _ => normalRun t.data {} t.normal.log = some t.normal

/-- Consistency of an attempt's operation log and captured views. -/
structure TxInvariant (t : Tx) : Prop where
  /-- The operation log reproduces the normal view. -/
  normal : NormalInvariant t
  /-- Each snapshot was captured from a well-formed store's head. -/
  snapshot
    : ∀ snap,
        t.snapshot = some snap → ∃ s : Store, StoreInvariant s ∧ snap.current = s.head
  /-- Each acquired global view has valid provenance. -/
  globals : ∀ map view, find t.globalViews map = some view → GlobalInvariant view

/-- Internal consistency of every live store and attempt. -/
structure WorldInvariant (w : World) : Prop where
  /-- Live stores have well-formed histories. -/
  stores : ∀ sid s, find w.stores sid = some s → StoreInvariant s
  /-- Live attempts have valid logs and captured views. -/
  txs : ∀ tid t, find w.txs tid = some t → TxInvariant t

variable {M K V : Type}

theorem find_set_same [DecidableEq K] (xs : Assoc K V) (k : K) (v : V)
    : find (set xs k v) k = some v := by
  simp [Model.set, find]

theorem find_erase_same [DecidableEq K] (xs : Assoc K V) (k : K)
    : find (erase xs k) k = none := by
  induction xs with
  | nil => rfl
  | cons p xs ih =>
      rcases p with ⟨a, v⟩
      by_cases h : a = k <;> simp_all [erase, find]

theorem find_erase_other [DecidableEq K] (xs : Assoc K V) (a k : K) (h : a ≠ k)
    : find (erase xs a) k = find xs k := by
  induction xs with
  | nil => rfl
  | cons p xs ih =>
      rcases p with ⟨b, v⟩
      by_cases hba : b = a <;> by_cases hbk : b = k <;> simp_all [erase, find]

theorem find_set_other [DecidableEq K] (xs : Assoc K V) (a k : K) (v : V) (h : a ≠ k)
    : find (set xs a v) k = find xs k := by
  simp [Model.set, find, h, find_erase_other xs a k h]

theorem find_set_cases [DecidableEq K] (xs : Assoc K V) (id key : K) (v : V)
    : find (set xs id v) key = if id = key then some v else find xs key := by
  by_cases h : id = key <;> simp [h, find_set_same, find_set_other]

theorem find_erase_cases [DecidableEq K] (xs : Assoc K V) (id key : K)
    : find (erase xs id) key = if id = key then none else find xs key := by
  by_cases h : id = key <;> simp [h, find_erase_same, find_erase_other]

theorem normalRun_append [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (n : Normal M K V) (a b : List (NormalOp M K V))
    : normalRun db n (a ++ b)
      = (normalRun db n a).bind (fun next => normalRun db next b) := by
  unfold normalRun
  simp

theorem normalStep_log [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (n n' : Normal M K V) (op : NormalOp M K V)
    (h : normalStep db n op = some n')
    : n'.log = n.log ++ [op] := by
  unfold normalStep at h
  split at h
  next => cases h; rfl
  next => simp at h

theorem normalRun_extend [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (db : DB M K V) (n n' : Normal M K V) (op : NormalOp M K V)
    (before : normalRun db {} n.log = some n)
    (one : normalStep db n op = some n')
    : normalRun db {} n'.log = some n' := by
  rw [normalStep_log db n n' op one, normalRun_append, before]
  simp [normalRun, one]

theorem History.bounded (fs : List Frame) (n : Nat) (h : History fs n)
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
      · subst g; omega
      · exact Nat.le_trans (ih g hm) (Nat.le_succ n)

theorem History.cut (fs : List Frame) (n : Nat) (h : History fs n)
    (cut : Nat) (hc : cut ≤ n)
    : ∃ f,
        fs.find? (fun f => f.version ≤ cut) = some f
        ∧ f.version = cut
        ∧ History (fs.filter fun f => f.version ≤ cut) cut
        ∧ (fs.filter fun f => f.version ≤ cut).head? = some f := by
  induction h with
  | zero =>
      have hz : cut = 0 := by omega
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
      · have hlt : ¬n + 1 ≤ cut := by omega
        have hc' : cut ≤ n := by omega
        obtain ⟨g, found, gv, shape, first⟩ := ih hc'
        refine ⟨g, ?_, gv, ?_, ?_⟩
        · simpa [List.find?, hv, hlt] using found
        · simpa [hv, hlt] using shape
        · simpa [hv, hlt] using first

theorem atCut_spec (s : Store) (valid : StoreInvariant s)
    (cut : Nat) (hc : cut ≤ s.head.version)
    : (atCut s cut).version = cut
      ∧ History (s.history.filter fun f => f.version ≤ cut) cut
      ∧ (s.history.filter fun f => f.version ≤ cut).head? = some (atCut s cut) := by
  obtain ⟨f, found, version, shape, first⟩ :=
    History.cut s.history s.head.version valid.historyShape cut hc
  simpa [atCut, found] using And.intro version (And.intro shape first)

theorem operation_normal (t : Tx) (valid : NormalInvariant t) (snap : Snapshot)
    (n : Normal String String String) (op : NormalOp String String String)
    (hs : t.snapshot = some snap)
    (hn : normalStep t.data t.normal op = some n)
    : match t.snapshot with
      | none => n = {}
      | some _ => normalRun t.data {} n.log = some n := by
  have old : normalRun t.data {} t.normal.log = some t.normal := by
    simpa [NormalInvariant, hs] using valid
  simpa [hs] using normalRun_extend t.data t.normal n op old hn

theorem image_append (a b : Data) (m : String)
    : image (a ++ b) m = image a m ++ image b m := by
  simp [image]

theorem image_filter (db : Data) (m : String) (p : String → Bool)
    : image (db.filter fun (a, _) => p a.1) m = if p m then image db m else [] := by
  induction db with
  | nil => simp [image]
  | cons entry db ih =>
      rcases entry with ⟨⟨name, key⟩, cell⟩
      by_cases h : name = m <;> cases hp : p name <;> cases hm : p m <;>
        simp_all [image]
      all_goals assumption

theorem pinData_other (db acquired : Data) (m other : String) (h : other ≠ m)
    : image (pinData db m acquired) other = image db other := by
  rw [pinData, image_append, image_filter db other (fun name => name != m),
    image_filter acquired other (fun name => name == m)]
  simp [h]

theorem find_image (db : Data) (m key : String)
    : find (image db m) key = find db (m, key) := by
  induction db with
  | nil => rfl
  | cons entry db ih =>
      rcases entry with ⟨⟨name, k⟩, cell⟩
      by_cases hm : name = m <;> by_cases hk : k = key <;>
        simp_all [image, find, Prod.mk.injEq]

theorem normalStep_pinData (db acquired : Data) (m : String)
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

theorem normalRun_pinData (db acquired : Data) (m : String)
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

theorem acquisition_normal (t : Tx) (valid : NormalInvariant t) (m : String)
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

theorem snapshot_normal (t : Tx) (valid : NormalInvariant t) (data : Data)
    (hs : t.snapshot = none)
    : normalRun data {} t.normal.log = some t.normal := by
  have hzero : t.normal = {} := by simpa [NormalInvariant, hs] using valid
  simp [hzero, normalRun]

theorem history_extension (s : Store) (valid : StoreInvariant s) (f : Frame)
    (writes : Pending) (version : f.version = s.head.version + 1)
    (data : f.data = publish s.head.data (s.head.version + 1) writes)
    : History (f :: s.history) (s.head.version + 1) :=
  .succ f s.head.version s.history version
    ⟨writes, by simpa only [valid.headFirst, Option.getD_some] using data⟩
    valid.historyShape

theorem cut_history (s : Store) (valid : StoreInvariant s)
    (cut : Nat) (within : cut ≤ s.head.version)
    : History (s.history.filter fun f => f.version ≤ cut) (atCut s cut).version := by
  have spec := atCut_spec s valid cut within
  rw [spec.1]
  exact spec.2.1

theorem cut_global_bound (s : Store) (valid : StoreInvariant s) (cut : Nat)
    (within : cut ≤ s.head.version) (boundary : s.global ≤ cut)
    : s.global ≤ (atCut s cut).version := by
  rw [(atCut_spec s valid cut within).1]
  exact boundary

theorem store_initial : StoreInvariant {} :=
  ⟨.zero, rfl, Nat.le_refl 0⟩

theorem advance_invariant (s : Store) (valid : StoreInvariant s) (writes : Pending)
    : StoreInvariant (advance s writes) :=
  ⟨
    history_extension s valid _ writes rfl rfl,
    rfl,
    Nat.le_trans valid.globalBound (Nat.le_succ _)
  ⟩

theorem compact_invariant (s : Store) (valid : StoreInvariant s) (v : Nat)
    : StoreInvariant (compactStore s v) := by
  unfold compactStore
  split
  next within =>
    exact ⟨valid.historyShape, valid.headFirst, Nat.max_le.mpr ⟨valid.globalBound, within⟩⟩
  next => exact valid

theorem rollback_invariant (s : Store) (valid : StoreInvariant s) (v term : Nat)
    : StoreInvariant (rollbackStore s v term) := by
  have within : rollbackCut s v ≤ s.head.version :=
    Nat.max_le.mpr ⟨valid.globalBound, Nat.min_le_left _ _⟩
  exact ⟨cut_history s valid _ within, (atCut_spec s valid _ within).2.2,
    cut_global_bound s valid _ within (Nat.le_max_left _ _)⟩

theorem tx_initial (sid : Nat) : TxInvariant { store := sid } := by
  refine ⟨rfl, ?_, ?_⟩ <;> simp [find]

theorem runOp_invariant (t next : Tx) (valid : TxInvariant t)
    (op : NormalOp String String String) (accepted : runOp t op = .ok next)
    : TxInvariant next := by
  simp only [runOp, Pure.pure, Except.pure] at accepted
  split at accepted
  next => contradiction
  next snap hs =>
    split at accepted
    next n hn =>
      cases accepted
      exact ⟨operation_normal t valid.normal snap n op hs hn, valid.snapshot, valid.globals⟩
    next => contradiction

theorem foldlM_invariant {A : Type} (items : List A) (f : Tx → A → Except Failure Tx)
    (preserve : ∀ t a next, TxInvariant t → f t a = .ok next → TxInvariant next)
    (t next : Tx) (valid : TxInvariant t) (accepted : items.foldlM f t = .ok next)
    : TxInvariant next := by
  induction items generalizing t with
  | nil => cases accepted; exact valid
  | cons a items ih =>
      simp only [List.foldlM_cons, Bind.bind, Except.bind] at accepted
      cases one : f t a with
      | error err => simp [one] at accepted
      | ok middle =>
          exact ih middle (preserve t a middle valid one) (by simpa [one] using accepted)

theorem clearWrites_invariant (t next : Tx) (valid : TxInvariant t)
    (map : String) (entries : Assoc String String)
    (accepted : clearWrites t map entries = .ok next)
    : TxInvariant next :=
  foldlM_invariant entries _
    (fun t (key, _) next ht h =>
      runOp_invariant t next ht (.write (map, key) none) h)
    t next valid accepted

theorem captureGlobal_invariant (s : Store) (valid : StoreInvariant s)
    (snap : Snapshot) (map : String)
    : GlobalInvariant (captureGlobal s snap map) := by
  dsimp only [captureGlobal]
  split
  · exact Or.inl rfl
  · exact Or.inr ⟨s, valid, rfl⟩

theorem acquireMap_invariant (s : Store) (store : StoreInvariant s)
    (t next : Tx) (valid : TxInvariant t) (map : String) (version global : Nat)
    (accepted : acquireMap s t map version global = .ok next)
    : TxInvariant next := by
  simp only [acquireMap, Bind.bind, Pure.pure, Except.bind, Except.pure,
    require, expect, invalid, reject] at accepted
  repeat' first
    | contradiction
    | cases accepted
    | split at accepted
  all_goals
    refine ⟨acquisition_normal t valid.normal map _ (by assumption), valid.snapshot, ?_⟩
    intro name view found
    rw [find_set_cases] at found
    split at found
    · cases found
      exact captureGlobal_invariant s store _ map
    · exact valid.globals name view found

theorem snapshot_invariant (s : Store) (store : StoreInvariant s) (term : Nat)
    (t : Tx) (valid : TxInvariant t) (fresh : t.snapshot = none)
    : TxInvariant { t with snapshot := some { current := s.head, term } } := by
  refine ⟨snapshot_normal t valid.normal t.data fresh, ?_, valid.globals⟩
  intro snap captured
  cases captured
  exact ⟨s, store, rfl⟩

theorem tx_fields_invariant (t next : Tx) (valid : TxInvariant t)
    (snapshot : next.snapshot = t.snapshot) (data : next.data = t.data)
    (normal : next.normal = t.normal) (globals : next.globalViews = t.globalViews)
    : TxInvariant next := by
  rcases valid with ⟨hn, hs, hg⟩
  constructor
  · simpa [NormalInvariant, snapshot, data, normal] using hn
  · simpa [snapshot] using hs
  · simpa [globals] using hg

theorem lookup_set_invariant [DecidableEq K] (P : V → Prop) (xs : Assoc K V)
    (valid : ∀ key value, find xs key = some value → P value)
    (id : K) (value : V) (holds : P value)
    : ∀ key next, find (set xs id value) key = some next → P next := by
  intro key next found
  rw [find_set_cases] at found
  split at found
  · cases found; exact holds
  · exact valid key next found

theorem lookup_erase_invariant [DecidableEq K] (P : V → Prop) (xs : Assoc K V)
    (valid : ∀ key value, find xs key = some value → P value) (id : K)
    : ∀ key next, find (erase xs id) key = some next → P next := by
  intro key next found
  rw [find_erase_cases] at found
  split at found
  · contradiction
  · exact valid key next found

theorem storeOf_invariant (w : World) (valid : WorldInvariant w) (sid : Nat) (s : Store)
    (found : storeOf w sid = .ok s)
    : StoreInvariant s := by
  cases h : find w.stores sid <;> simp [storeOf, present, invalid, h] at found
  next => cases found; exact valid.stores sid _ h

theorem txOf_found (w : World) (sid tid : Nat) (t : Tx) (found : txOf w sid tid = .ok t)
    : find w.txs tid = some t := by
  cases h : find w.txs tid <;>
    simp only [txOf, h, present, Bind.bind, Pure.pure, Except.bind, Except.pure,
      require, invalid] at found
  all_goals repeat' first
    | contradiction
    | rfl
    | cases found
    | split at found

theorem txOf_invariant (w : World) (valid : WorldInvariant w) (sid tid : Nat) (t : Tx)
    (found : txOf w sid tid = .ok t)
    : TxInvariant t :=
  valid.txs tid t (txOf_found w sid tid t found)

theorem tryApply_invariant (s next : Store) (valid : StoreInvariant s) (t : Tx)
    (applied : tryApply s t = some next)
    : StoreInvariant next := by
  unfold tryApply at applied
  split at applied
  · cases applied; exact advance_invariant s valid t.normal.writes
  · contradiction

theorem world_initial : WorldInvariant {} := by
  constructor <;> simp [find]

set_option maxRecDepth 4096 in
set_option maxHeartbeats 800000 in
theorem stepEvent_invariant (w next : World) (valid : WorldInvariant w) (e : Event)
    (accepted : stepEvent w e = .ok next)
    : WorldInvariant next := by
  cases e <;> simp only [stepEvent, withTx, Bind.bind, Pure.pure, Except.bind, Except.pure,
    require, expect, invalid, reject] at accepted
  all_goals repeat' first
    | contradiction
    | split at *
  all_goals simp only [Except.ok.injEq] at *
  all_goals subst_vars
  all_goals try first
    | exact valid
    | exact ⟨valid.stores, valid.txs⟩
    | exact ⟨lookup_set_invariant StoreInvariant _ valid.stores _ _ store_initial, valid.txs⟩
    | exact ⟨lookup_erase_invariant StoreInvariant _ valid.stores _, valid.txs⟩
    | exact ⟨valid.stores, lookup_set_invariant TxInvariant _ valid.txs _ _ (tx_initial _)⟩
    | exact ⟨valid.stores, lookup_erase_invariant TxInvariant _ valid.txs _⟩
    | exact ⟨lookup_set_invariant StoreInvariant _ valid.stores _ _
        (compact_invariant _ (storeOf_invariant w valid _ _ (by assumption)) _), valid.txs⟩
    | exact ⟨lookup_set_invariant StoreInvariant _ valid.stores _ _
        (rollback_invariant _ (storeOf_invariant w valid _ _ (by assumption)) _ _), valid.txs⟩
  all_goals
    have stores := fun sid s => storeOf_invariant w valid sid s
    have txs := fun sid tid t => txOf_invariant w valid sid tid t
    try refine ⟨valid.stores, lookup_set_invariant TxInvariant _ valid.txs _ _ ?_⟩
  all_goals try first
    | exact runOp_invariant _ _ (by apply txs; assumption) _ (by assumption)
    | exact clearWrites_invariant _ _ (runOp_invariant _ _ (by apply txs; assumption) _
        (by assumption)) _ _ (by assumption)
    | exact acquireMap_invariant _ (by apply stores; assumption) _ _
        (by apply txs; assumption) _ _ _ (by assumption)
    | exact tx_fields_invariant _ _ (by apply txs; assumption) rfl rfl rfl rfl
  all_goals first
    | solve | grind only [→ runOp_invariant, TxInvariant, NormalInvariant]
    | refine ⟨lookup_set_invariant StoreInvariant _ valid.stores _ _ ?_,
        lookup_set_invariant TxInvariant _ valid.txs _ _ ?_⟩
  all_goals
    have allTxs := valid.txs
    first
    | grind only [StoreInvariant]
    | grind only [→ tryApply_invariant]
    | grind only [→ txOf_found, snapshot_invariant, snapshot_normal,
        StoreInvariant, TxInvariant, NormalInvariant]

theorem step_invariant (w next : World) (valid : WorldInvariant w) (r : Record)
    (accepted : step w r = .ok next)
    : WorldInvariant next := by
  simp only [step, Bind.bind, Pure.pure, Except.bind, Except.pure,
    require, invalid] at accepted
  repeat' first
    | contradiction
    | cases accepted
    | split at accepted
  all_goals
    have eventValid := stepEvent_invariant w _ valid r.event (by assumption)
    exact ⟨eventValid.stores, eventValid.txs⟩

theorem reachable_invariant (w : World) (reachable : transitionSystem.Reachable w)
    : WorldInvariant w := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | initial initialized => cases initialized; exact world_initial
  | step _ transition ih =>
      exact step_invariant _ _ ih _ ((Execution.step_iff_transition _ _ _).mp transition)

end Kv.Proofs.Invariants
