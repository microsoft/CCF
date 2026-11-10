-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Invariants
public import CCF.Execution

/-!
Snapshot, map-capture and attempt-replay claims for accepted traces.

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

private theorem tx_fields_invariant (t next : Tx) (valid : TxInvariant t)
    (snapshot : next.snapshot = t.snapshot) (data : next.data = t.data)
    (normal : next.normal = t.normal) (globals : next.globalViews = t.globalViews)
    : TxInvariant next := by
  rcases valid with ⟨hn, hs, hg⟩
  constructor
  · simpa [NormalInvariant, snapshot, data, normal] using hn
  · simpa [snapshot] using hs
  · simpa [globals] using hg

private theorem txOf_found (w : World) (sid tid : Nat) (t : Tx)
    (found : txOf w sid tid = .ok t)
    : find w.txs tid = some t := by
  obtain ⟨_, -, found⟩ := bind_ok found
  obtain ⟨_, lookup, found⟩ := bind_ok found
  obtain ⟨_, -, found⟩ := bind_ok found
  cases pure_ok found
  exact present_ok lookup

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

private theorem absent_ne {xs : Assoc String GlobalView} {map wanted : String}
    {view : GlobalView} (absent : find xs map = none) (found : find xs wanted = some view)
    : map ≠ wanted :=
  fun same => by
    rw [same, found] at absent
    cases absent

/-- The attempt keeps its captured snapshot, global views and pinned map data. -/
private def Kept (before after : Tx) : Prop :=
  (∀ snap, before.snapshot = some snap → after.snapshot = some snap)
  ∧ ∀ map view,
      find before.globalViews map = some view
      → find after.globalViews map = some view
        ∧ image after.data map = image before.data map

private theorem Kept.refl (t : Tx) : Kept t t := ⟨fun _ h => h, fun _ _ h => ⟨h, rfl⟩⟩

private theorem Kept.frozen {t next : Tx} (frozen : Frozen t next) : Kept t next :=
  ⟨
    fun _ h => frozen.snapshot.trans h,
    fun _ _ h => by
      rw [frozen.globals, frozen.data]
      exact ⟨h, rfl⟩
  ⟩

private theorem stepEvent_attempt_kept (w next : World) (tid : Nat) (before : Tx)
    (e : Event) (live : find w.txs tid = some before) (segment : AttemptEvent tid e)
    (accepted : stepEvent w e = .ok next)
    : ∃ after, find next.txs tid = some after ∧ Kept before after := by
  have set_kept {xs : Assoc Nat Tx} {tid id : Nat} {before next : Tx}
      (live : find xs tid = some before) (kept : id = tid → Kept before next)
      : ∃ after, find (set xs id next) tid = some after ∧ Kept before after := by
    by_cases h : id = tid
    · subst h
      exact ⟨next, find_set_same _ _ _, kept rfl⟩
    · exact ⟨before, by rw [find_set_other _ _ _ _ h]; exact live, Kept.refl before⟩
  cases stepEvent_effect w next e accepted with
  | same _ txs | storeCreate _ txs | storeEnd _ txs | compact _ _ txs | rollback _ _ txs
    =>
      exact ⟨before, by rw [txs]; exact live, Kept.refl before⟩
  | txCreate _ txs =>
      exact ⟨
        before,
        by rw [txs, find_set_other _ _ _ _ segment]; exact live,
        Kept.refl before
      ⟩
  | txEnd _ txs =>
      exact ⟨
        before,
        by rw [txs, find_erase_other _ _ _ segment]; exact live,
        Kept.refl before
      ⟩
  | snapshot _ _ _ _ tx fresh _ txs =>
      rw [txs]
      refine set_kept live fun same => ?_
      subst same
      cases tx.symm.trans live
      exact ⟨fun _ h => (by rw [fresh] at h; cases h), fun _ _ h => ⟨h, rfl⟩⟩
  | acquire _ tx acquired _ txs =>
      rw [txs]
      refine set_kept live fun same => ?_
      subst same
      cases (txOf_found _ _ _ _ tx).symm.trans live
      obtain ⟨snap, _, fresh, _, _, rfl⟩ := acquireMap_ok acquired
      refine ⟨fun _ h => h, fun map view h => ?_⟩
      have other := absent_ne fresh h
      exact ⟨
        by rw [find_set_other _ _ _ _ other]; exact h,
        Invariants.pinData_other _ _ _ _ (Ne.symm other)
      ⟩
  | apply _ tx _ _ txs =>
      rw [txs]
      refine set_kept live fun same => ?_
      subst same
      cases (txOf_found _ _ _ _ tx).symm.trans live
      exact Kept.refl _
  | update tx frozen _ txs =>
      rw [txs]
      refine set_kept live fun same => ?_
      subst same
      cases (txOf_found _ _ _ _ tx).symm.trans live
      exact Kept.frozen frozen

private theorem replay_attempt_invariant (tid : Nat) (P : Tx → Prop)
    (preserve
      : ∀ (w next : World) (before after : Tx) (r : Record),
          find w.txs tid = some before
          → find next.txs tid = some after
          → P before
          → AttemptEvent tid r.event
          → step w r = .ok next
          → P after)
    (w final : World) (before : Tx)
    (rs : List Record) (live : find w.txs tid = some before)
    (holds : P before)
    (segment : ∀ r ∈ rs, AttemptEvent tid r.event)
    (accepted : replay w rs = .ok final)
    : ∃ after, find final.txs tid = some after ∧ P after := by
  have stepEvent_attempt_live (w next : World) (tid : Nat) (before : Tx) (e : Event)
      (live : find w.txs tid = some before) (segment : AttemptEvent tid e)
      (accepted : stepEvent w e = .ok next)
      : ∃ after, find next.txs tid = some after := by
    obtain ⟨after, found, -⟩ := stepEvent_attempt_kept w next tid before e live segment accepted
    exact ⟨after, found⟩
  induction rs generalizing w before with
  | nil => cases accepted; exact ⟨before, live, holds⟩
  | cons r rs ih =>
      cases one : step w r with
      | error err => simp [replay, one, Except.bind] at accepted
      | ok middle =>
          obtain ⟨eventNext, eventStep, _, txs⟩ := step_event_result w middle r one
          have thisSegment := segment r (by simp)
          obtain ⟨midTx, midLive⟩ := stepEvent_attempt_live w eventNext tid before r.event
            live thisSegment eventStep
          have midLive' : find middle.txs tid = some midTx := by simpa [txs] using midLive
          have midProperty :=
            preserve w middle before midTx r live midLive' holds thisSegment one
          apply ih middle midTx midLive' midProperty
          · intro e he; exact segment e (by simp [he])
          · simpa [replay, one, Except.bind] using accepted

private theorem replay_snapshot_fixed (w final : World) (tid : Nat) (before : Tx)
    (snap : Snapshot) (rs : List Record) (live : find w.txs tid = some before)
    (captured : before.snapshot = some snap)
    (segment : ∀ r ∈ rs, AttemptEvent tid r.event) (accepted : replay w rs = .ok final)
    : ∃ after, find final.txs tid = some after ∧ after.snapshot = some snap := by
  have stepEvent_snapshot_fixed (w next : World) (tid : Nat) (before after : Tx)
      (snap : Snapshot) (e : Event)
      (live : find w.txs tid = some before) (stillLive : find next.txs tid = some after)
      (captured : before.snapshot = some snap) (segment : AttemptEvent tid e)
      (accepted : stepEvent w e = .ok next)
      : after.snapshot = some snap := by
    obtain ⟨found, live', kept⟩ :=
      stepEvent_attempt_kept w next tid before e live segment accepted
    cases stillLive.symm.trans live'
    exact kept.1 snap captured
  have step_snapshot_fixed (w next : World) (tid : Nat) (before after : Tx)
      (snap : Snapshot) (r : Record)
      (live : find w.txs tid = some before) (stillLive : find next.txs tid = some after)
      (captured : before.snapshot = some snap) (segment : AttemptEvent tid r.event)
      (accepted : step w r = .ok next)
      : after.snapshot = some snap := by
    obtain ⟨eventNext, eventStep, _, txs⟩ := step_event_result w next r accepted
    apply stepEvent_snapshot_fixed w eventNext tid before after snap r.event live
      (by simpa [txs] using stillLive) captured segment eventStep
  exact replay_attempt_invariant tid (fun t => t.snapshot = some snap)
      (fun w next before after r => step_snapshot_fixed w next tid before after snap r)
      w final before rs live captured segment accepted

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

private theorem step_map_global_fixed (w next : World) (tid : Nat) (before after : Tx)
    (map : String) (view : GlobalView) (r : Record) (live : find w.txs tid = some before)
    (stillLive : find next.txs tid = some after)
    (captured : find before.globalViews map = some view)
    (segment : AttemptEvent tid r.event) (accepted : step w r = .ok next)
    : find after.globalViews map = some view := by
  have stepEvent_map_global_fixed (w next : World) (tid : Nat) (before after : Tx)
      (map : String) (view : GlobalView) (e : Event)
      (live : find w.txs tid = some before) (stillLive : find next.txs tid = some after)
      (captured : find before.globalViews map = some view) (segment : AttemptEvent tid e)
      (accepted : stepEvent w e = .ok next)
      : find after.globalViews map = some view := by
    obtain ⟨found, live', kept⟩ :=
      stepEvent_attempt_kept w next tid before e live segment accepted
    cases stillLive.symm.trans live'
    exact (kept.2 map view captured).1
  obtain ⟨eventNext, eventStep, _, txs⟩ := step_event_result w next r accepted
  exact stepEvent_map_global_fixed w eventNext tid before after map view r.event live
    (by simpa [txs] using stillLive) captured segment eventStep

private theorem replay_map_global_fixed (w final : World) (tid : Nat) (before : Tx)
    (map : String) (view : GlobalView) (rs : List Record)
    (live : find w.txs tid = some before)
    (captured : find before.globalViews map = some view)
    (segment : ∀ r ∈ rs, AttemptEvent tid r.event) (accepted : replay w rs = .ok final)
    : ∃ after, find final.txs tid = some after ∧ find after.globalViews map = some view :=
  replay_attempt_invariant tid (fun t => find t.globalViews map = some view)
    (fun w next before after r =>
      step_map_global_fixed w next tid before after map view r)
    w final before rs live captured segment accepted

theorem capture_replay_preserves_metadata_claim
    : ∀ (w capturedWorld final : World) (sid tid version global term seq : Nat)
        (s : Store) (t : Tx) (tail : List Record),
        storeOf w sid = .ok s
        → Model.transitionSystem.step w ⟨seq, .snapshot sid tid version global term⟩
          = some capturedWorld
        → find capturedWorld.txs tid = some t
        → (∀ r ∈ tail, AttemptEvent tid r.event)
        → CCF.Execution.Run Model.transitionSystem capturedWorld tail final
        → ∃ after snap,
            find final.txs tid = some after
            ∧ after.snapshot = some snap
            ∧ snap.current = s.head
            ∧ snap.term = term := by
  have capture_replay_preserves_metadata (w capturedWorld final : World)
      (sid tid version global term seq : Nat) (s : Store) (t : Tx) (tail : List Record)
      (source : storeOf w sid = .ok s)
      (capture : step w ⟨seq, .snapshot sid tid version global term⟩ = .ok capturedWorld)
      (live : find capturedWorld.txs tid = some t)
      (segment : ∀ r ∈ tail, AttemptEvent tid r.event)
      (accepted : replay capturedWorld tail = .ok final)
      : ∃ after snap,
          find final.txs tid = some after
          ∧ after.snapshot = some snap
          ∧ snap.current = s.head
          ∧ snap.term = term := by
    obtain ⟨snap, captured, current, snapshotTerm⟩ :=
      step_capture_metadata w capturedWorld sid tid version global term seq s t source capture live
    obtain ⟨after, afterLive, same⟩ := replay_snapshot_fixed capturedWorld final tid t snap
      tail live captured segment accepted
    exact ⟨after, snap, afterLive, same, current, snapshotTerm⟩
  intro w capturedWorld final sid tid version global term seq s t tail source capture live segment accepted
  exact capture_replay_preserves_metadata w capturedWorld final sid tid version global
    term seq s t tail source ((Proofs.Execution.step_iff_transition _ _ _).mp capture)
    live segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem replay_snapshot_fixed_claim
    : ∀ (w final : World) (tid : Nat) (before : Tx) (snap : Snapshot) (rs : List Record),
        find w.txs tid = some before
        → before.snapshot = some snap
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run Model.transitionSystem w rs final
        → ∃ after, find final.txs tid = some after ∧ after.snapshot = some snap := by
  intro w final tid before snap rs live captured segment accepted
  exact Proofs.Trace.replay_snapshot_fixed w final tid before snap rs live captured segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem replay_map_global_fixed_claim
    : ∀ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        → find before.globalViews map = some view
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run Model.transitionSystem w rs final
        → ∃ after,
            find final.txs tid = some after ∧ find after.globalViews map = some view := by
  intro w final tid before map view rs live captured segment accepted
  exact Proofs.Trace.replay_map_global_fixed w final tid before map view rs live captured segment ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem capture_replay_preserves_map_claim
    : ∀ (w capturedWorld final : World) (sid tid localVersion globalVersion seq : Nat)
        (map : String) (s : Store) (before capturedTx : Tx) (snap : Snapshot)
        (tail : List Record),
        storeOf w sid = .ok s
        → txOf w sid tid = .ok before
        → before.snapshot = some snap
        → Model.transitionSystem.step w
            ⟨seq, .acquire sid tid map localVersion globalVersion⟩
          = some capturedWorld
        → find capturedWorld.txs tid = some capturedTx
        → (∀ r ∈ tail, AttemptEvent tid r.event)
        → CCF.Execution.Run Model.transitionSystem capturedWorld tail final
        → ∃ after,
            find final.txs tid = some after
            ∧ find after.globalViews map = some (captureGlobal s snap map)
            ∧ localVersion = (revision (captureLocal s snap map) map).version
            ∧ globalVersion
              = (revision (captureGlobal s snap map).frame map).version := by
  have capture_replay_preserves_map (w capturedWorld final : World)
      (sid tid localVersion globalVersion seq : Nat) (map : String)
      (s : Store) (before capturedTx : Tx) (snap : Snapshot) (tail : List Record)
      (store : storeOf w sid = .ok s) (tx : txOf w sid tid = .ok before)
      (snapshot : before.snapshot = some snap)
      (capture
        : step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩ = .ok capturedWorld)
      (live : find capturedWorld.txs tid = some capturedTx)
      (segment : ∀ r ∈ tail, AttemptEvent tid r.event)
      (accepted : replay capturedWorld tail = .ok final)
      : ∃ after,
          find final.txs tid = some after
          ∧ find after.globalViews map = some (captureGlobal s snap map)
          ∧ localVersion = (revision (captureLocal s snap map) map).version
          ∧ globalVersion = (revision (captureGlobal s snap map).frame map).version := by
    obtain ⟨view, localRevision, globalRevision⟩ :=
      step_map_capture w capturedWorld sid tid localVersion globalVersion seq map s before capturedTx snap
        store tx snapshot capture live
    obtain ⟨after, afterLive, fixed⟩ :=
      replay_map_global_fixed capturedWorld final tid capturedTx map (captureGlobal s snap map)
        tail live view segment accepted
    exact ⟨after, afterLive, fixed, localRevision, globalRevision⟩
  intro w capturedWorld final sid tid localVersion globalVersion seq map s before capturedTx snap tail store tx snapshot capture live segment accepted
  exact capture_replay_preserves_map w capturedWorld final sid tid localVersion
    globalVersion seq map s before capturedTx snap tail store tx snapshot
    ((Proofs.Execution.step_iff_transition _ _ _).mp capture) live segment
    ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

theorem replay_map_local_fixed_claim
    : ∀ (w final : World) (tid : Nat) (before : Tx) (map : String) (view : GlobalView)
        (rs : List Record),
        find w.txs tid = some before
        → find before.globalViews map = some view
        → (∀ r ∈ rs, AttemptEvent tid r.event)
        → CCF.Execution.Run Model.transitionSystem w rs final
        → ∃ after,
            find final.txs tid = some after
            ∧ image after.data map = image before.data map := by
  have stepEvent_map_local_fixed (w next : World) (tid : Nat) (before after : Tx)
      (map : String) (view : GlobalView) (e : Event)
      (live : find w.txs tid = some before) (stillLive : find next.txs tid = some after)
      (captured : find before.globalViews map = some view) (segment : AttemptEvent tid e)
      (accepted : stepEvent w e = .ok next)
      : image after.data map = image before.data map := by
    obtain ⟨found, live', kept⟩ :=
      stepEvent_attempt_kept w next tid before e live segment accepted
    cases stillLive.symm.trans live'
    exact (kept.2 map view captured).2
  have replay_map_local_fixed (w final : World) (tid : Nat) (before : Tx) (map : String)
      (view : GlobalView) (rs : List Record) (live : find w.txs tid = some before)
      (captured : find before.globalViews map = some view)
      (segment : ∀ r ∈ rs, AttemptEvent tid r.event) (accepted : replay w rs = .ok final)
      : ∃ after,
          find final.txs tid = some after
          ∧ image after.data map = image before.data map := by
    obtain ⟨after, afterLive, _, fixed⟩ :=
      replay_attempt_invariant tid
        (fun t => find t.globalViews map = some view ∧ image t.data map = image before.data map)
        (fun w next start finish r live stillLive holds segment accepted => by
          refine ⟨step_map_global_fixed w next tid start finish map view r live stillLive
            holds.1 segment accepted, ?_⟩
          obtain ⟨eventNext, eventStep, _, txs⟩ := step_event_result w next r accepted
          exact (stepEvent_map_local_fixed w eventNext tid start finish map view r.event live
            (by simpa [txs] using stillLive) holds.1 segment eventStep).trans holds.2)
        w final before rs live ⟨captured, rfl⟩ segment accepted
    exact ⟨after, afterLive, fixed⟩
  intro w final tid before map view rs live captured segment accepted
  exact replay_map_local_fixed w final tid before map view rs live captured segment
    ((Proofs.Execution.replay_iff_run _ _ _).mp accepted)

end Kv.Proofs.Trace
