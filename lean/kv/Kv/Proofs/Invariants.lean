-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Invariants
public import Kv.Proofs.Execution

@[expose] public section

/-! Initialisation and preservation of the executable model's separate state invariants. -/

namespace Kv.Proofs.Invariants

open Kv.Model Kv.Properties

/-- Executes operations in order with `normalStep` to reconstruct the normal view. -/
def normalRun {M K V : Type} [DecidableEq M] [DecidableEq K] [DecidableEq V]
    (snapshot : DB M K V) (n : Normal M K V) (ops : List (NormalOp M K V))
    : Option (Normal M K V) :=
  ops.foldlM (normalStep snapshot) n

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

/-- An attempt keeps its snapshot, pinned data and global views, and its invariant. -/
structure Frozen (t next : Tx) : Prop where
  /-- The captured snapshot is unchanged. -/
  snapshot : next.snapshot = t.snapshot
  /-- The pinned local data is unchanged. -/
  data : next.data = t.data
  /-- The captured global views are unchanged. -/
  globals : next.globalViews = t.globalViews
  /-- The attempt invariant is preserved. -/
  valid : TxInvariant t → TxInvariant next

/-- How an accepted event changes the live stores and attempts. -/
inductive StepEffect (w : World) : Event → World → Prop
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

private theorem image_cons (name key : String) (cell : Cell String) (db : Data)
    (m : String)
    : image (((name, key), cell) :: db) m
      = if name = m then (key, cell) :: image db m else image db m := by
  unfold image
  by_cases h : name = m
  · simp only [List.filterMap_cons, h, ↓reduceIte]
  · simp only [List.filterMap_cons, h, ↓reduceIte]

theorem image_filter (db : Data) (m : String) (p : String → Bool)
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

theorem bind_ok {α β : Type} {x : Except Failure α} {f : α → Except Failure β} {b : β}
    (h : (x >>= f) = .ok b)
    : ∃ a, x = .ok a ∧ f a = .ok b := by
  cases x with
  | error => cases h
  | ok a => exact ⟨a, rfl, h⟩

theorem pure_ok {α : Type} {a b : α} (h : (pure a : Except Failure α) = .ok b)
    : a = b := by
  cases h; rfl

theorem withTx_ok {w next : World} {sid tid : Nat} {f : Tx → Except Failure Tx}
    (h : withTx w sid tid f = .ok next)
    : ∃ t t',
        txOf w sid tid = .ok t
        ∧ f t = .ok t'
        ∧ next = { w with txs := set w.txs tid t' } := by
  obtain ⟨t, tx, h⟩ := bind_ok h
  obtain ⟨t', f, h⟩ := bind_ok h
  exact ⟨t, t', tx, f, (pure_ok h).symm⟩

theorem present_ok {α : Type} {value : Option α} {message : String} {a : α}
    (h : present value message = .ok a)
    : value = some a := by
  cases value with
  | none => cases h
  | some => cases h; rfl

theorem require_ok {condition : Bool} {message : String} {u : Unit}
    (h : require condition message = .ok u)
    : condition = true := by
  cases condition
  · cases h
  · rfl

theorem expect_ok {condition : Bool} {message : String} {u : Unit}
    (h : expect condition message = .ok u)
    : condition = true := by
  cases condition
  · cases h
  · rfl

theorem acquireMap_ok {s : Store} {t next : Tx} {map : String} {version global : Nat}
    (accepted : acquireMap s t map version global = .ok next)
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

theorem acquireMap_invariant (s : Store) (store : StoreInvariant s)
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
  obtain ⟨_, -, found⟩ := bind_ok found
  obtain ⟨_, lookup, found⟩ := bind_ok found
  obtain ⟨_, -, found⟩ := bind_ok found
  cases pure_ok found
  exact present_ok lookup

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

theorem Frozen.refl (t : Tx) : Frozen t t := ⟨rfl, rfl, rfl, id⟩

theorem Frozen.trans {a b c : Tx} (ab : Frozen a b) (bc : Frozen b c) : Frozen a c :=
  ⟨
    bc.snapshot.trans ab.snapshot,
    bc.data.trans ab.data,
    bc.globals.trans ab.globals,
    bc.valid ∘ ab.valid
  ⟩

theorem Frozen.fields {t next : Tx} (snapshot : next.snapshot = t.snapshot)
    (data : next.data = t.data) (normal : next.normal = t.normal)
    (globals : next.globalViews = t.globalViews)
    : Frozen t next :=
  ⟨
    snapshot,
    data,
    globals,
    fun valid => tx_fields_invariant t next valid snapshot data normal globals
  ⟩

theorem runOp_frozen {t next : Tx} {op : NormalOp String String String}
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

theorem clearWrites_frozen {t next : Tx} {map : String} {entries : Assoc String String}
    (accepted : clearWrites t map entries = .ok next)
    : Frozen t next := by
  unfold clearWrites at accepted
  induction entries generalizing t with
  | nil => cases accepted; exact Frozen.refl _
  | cons entry entries ih =>
      obtain ⟨middle, one, rest⟩ := bind_ok accepted
      exact (runOp_frozen one).trans (ih rest)

theorem StepEffect.withTx {w next : World} {e : Event} {sid tid : Nat}
    {f : Tx → Except Failure Tx} (noApply : ∀ sid, projectedApplication w sid e = [])
    (frozen : ∀ t t', f t = .ok t' → Frozen t t')
    (accepted : withTx w sid tid f = .ok next)
    : StepEffect w e next := by
  obtain ⟨t, t', tx, h, rfl⟩ := withTx_ok accepted
  exact .update tx (frozen t t' h) rfl rfl noApply

theorem stepEvent_effect (w next : World) (e : Event)
    (accepted : stepEvent w e = .ok next)
    : StepEffect w e next := by
  cases e with
  | traceStart | caseBegin | caseEnd | subcaseBegin | subcaseEnd | traceEnd =>
      repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
      cases pure_ok accepted
      exact .same rfl rfl fun _ => rfl
  | rollbackRejected =>
      repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
      cases pure_ok accepted
      exact .same rfl rfl fun _ => rfl
  | unsupported => cases accepted
  | storeCreate =>
      repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
      cases pure_ok accepted
      exact .storeCreate rfl rfl
  | storeEnd =>
      repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
      cases pure_ok accepted
      exact .storeEnd rfl rfl
  | txCreate =>
      repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
      cases pure_ok accepted
      exact .txCreate rfl rfl
  | txEnd =>
      repeat obtain ⟨_, -, accepted⟩ := bind_ok accepted
      cases pure_ok accepted
      exact .txEnd rfl rfl
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
  | snapshot sid tid version global term =>
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
  | acquire =>
      obtain ⟨s, store, accepted⟩ := bind_ok accepted
      obtain ⟨t, t', tx, h, rfl⟩ := withTx_ok accepted
      exact .acquire store tx h rfl rfl
  | apply =>
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
  | get | has =>
      refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
      obtain ⟨_, -, h⟩ := bind_ok h
      split at h
      · repeat obtain ⟨_, -, h⟩ := bind_ok h
        cases pure_ok h
        exact .refl _
      · repeat obtain ⟨_, -, h⟩ := bind_ok h
        exact runOp_frozen h
  | previous | put | remove | size =>
      refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
      repeat obtain ⟨_, -, h⟩ := bind_ok h
      exact runOp_frozen h
  | range =>
      refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
      obtain ⟨_, -, h⟩ := bind_ok h
      split at h
      · obtain ⟨_, -, h⟩ := bind_ok h
        cases pure_ok h
        exact .refl _
      · obtain ⟨_, -, h⟩ := bind_ok h
        exact runOp_frozen h
  | clear =>
      refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
      obtain ⟨_, -, h⟩ := bind_ok h
      obtain ⟨_, one, h⟩ := bind_ok h
      exact (runOp_frozen one).trans (clearWrites_frozen h)
  | foreachBegin =>
      refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
      obtain ⟨_, -, h⟩ := bind_ok h
      obtain ⟨_, -, h⟩ := bind_ok h
      obtain ⟨_, one, h⟩ := bind_ok h
      cases pure_ok h
      exact (runOp_frozen one).trans (.fields rfl rfl rfl rfl)
  | foreachEntry | foreachContinue | foreachEnd =>
      refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
      obtain ⟨⟨_, _⟩, -, h⟩ := bind_ok h
      repeat obtain ⟨_, -, h⟩ := bind_ok h
      cases pure_ok h
      exact .fields rfl rfl rfl rfl
  | unavailable =>
      obtain ⟨_, -, accepted⟩ := bind_ok accepted
      refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
      repeat obtain ⟨_, -, h⟩ := bind_ok h
      cases pure_ok h
      exact .fields rfl rfl rfl rfl
  | commitBegin =>
      refine StepEffect.withTx (fun _ => rfl) (fun t t' h => ?_) accepted
      repeat obtain ⟨_, -, h⟩ := bind_ok h
      cases pure_ok h
      exact .fields rfl rfl rfl rfl
  | commitResult =>
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

theorem stepEvent_invariant (w next : World) (valid : WorldInvariant w) (e : Event)
    (accepted : stepEvent w e = .ok next)
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

theorem step_ok {w next : World} {r : Record} (accepted : step w r = .ok next)
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

theorem step_invariant (w next : World) (valid : WorldInvariant w) (r : Record)
    (accepted : step w r = .ok next)
    : WorldInvariant next := by
  obtain ⟨_, event, rfl⟩ := step_ok accepted
  have eventValid := stepEvent_invariant w _ valid r.event event
  exact ⟨eventValid.stores, eventValid.txs⟩

theorem reachable_invariant (w : World) (reachable : transitionSystem.Reachable w)
    : WorldInvariant w := by
  induction reachable using @CCF.TransitionSystem.Reachable.rec transitionSystem with
  | initial initialized => cases initialized; exact world_initial
  | step _ transition ih =>
      exact step_invariant _ _ ih _ ((Execution.step_iff_transition _ _ _).mp transition)

end Kv.Proofs.Invariants
