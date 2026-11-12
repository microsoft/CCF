-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Proofs.Correspondence
public import Kv.Correspondence.Invariants
public import Kv.Proofs.SemanticHelpers

@[expose] public section

namespace Kv.Proofs.Capture

open Kv.Model
      hiding Store Tx advance compactStore rollbackStore tryApply step transitionSystem
open Kv.Correspondence Kv.TraceValidation Kv.Properties Kv.Proofs.Correspondence
open Kv.Proofs.SemanticHelpers

/-- A successful diagnostic bind exposes its successful input and continuation. -/
theorem bind_ok {α β : Type} {x : Except Failure α} {f : α → Except Failure β}
    {b : β} (h : x.bind f = .ok b)
    : ∃ a, x = .ok a ∧ f a = .ok b := by
  cases x with
  | error => cases h
  | ok a => exact ⟨a, rfl, h⟩

/-- A successful lifecycle lookup exposes its live semantic reference. -/
theorem present_ok {α : Type} {value : Option α} {message : String} {a : α}
    (h : present value message = .ok a)
    : value = some a := by
  cases value with
  | none => cases h
  | some => cases h; rfl

/-- Successful protocol validation establishes its Boolean guard. -/
theorem require_ok {condition : Bool} {message : String} {u : Unit}
    (h : require condition message = .ok u)
    : condition = true := by
  cases condition
  · cases h
  · rfl

/-- Successful report validation establishes its Boolean guard. -/
theorem expect_ok {condition : Bool} {message : String} {u : Unit}
    (h : expect condition message = .ok u)
    : condition = true := by
  cases condition
  · cases h
  · rfl

/-- Diagnostic return values are exact. -/
theorem pure_ok {α : Type} {a b : α} (h : (pure a : Except Failure α) = .ok b)
    : a = b := by
  cases h
  rfl

/-- Successful store lookup means the decorated store is live. -/
theorem store_found {w : World} {sid : Nat} {s : Store} (found : storeOf w sid = .ok s)
    : find w.stores sid = some s :=
  present_ok found

/-- Successful transaction lookup establishes its live reference and ownership. -/
theorem tx_found {w : World} {sid tid : Nat} {t : Tx} (found : txOf w sid tid = .ok t)
    : find w.txs tid = some t ∧ t.store = sid := by
  obtain ⟨_, _, found⟩ := bind_ok found
  obtain ⟨actual, live, found⟩ := bind_ok found
  obtain ⟨_, owned, found⟩ := bind_ok found
  cases pure_ok found
  exact ⟨present_ok live, beq_iff_eq.mp (require_ok owned)⟩

/-- Semantic lookup agrees with successful decorated store/transaction lookup. -/
theorem lookup_project {w : World} {sid tid : Nat} {s : Store} {t : Tx}
    (store : storeOf w sid = .ok s) (tx : txOf w sid tid = .ok t)
    : Model.lookupTx (project w) sid tid = some (s.toStore, t.toTx) := by
  have live := tx_found tx
  simp [Model.lookupTx, project_store, project_tx, store_found store, live.1, live.2]

/-- Single-input adaptation invokes the authoritative executor with its exact output. -/
theorem execute_single {w next : Model.State} {action : Model.Action} {output : Output}
    (accepted : executeActions w [action] = some (next, output))
    : Model.execute w action = some (next, output) := by
  cases executed : Model.execute w action with
  | none => simp [executeActions, executed] at accepted
  | some pair =>
      obtain ⟨state, value⟩ := pair
      simpa [executeActions, executed] using accepted

/-- Two-input adaptation is a pair of real semantic executions. -/
theorem execute_pair {w next : Model.State} {a b : Model.Action} {output : Output}
    (accepted : executeActions w [a, b] = some (next, output))
    : ∃ middle value,
        Model.execute w a = some (middle, value)
        ∧ Model.execute middle b = some (next, output) := by
  dsimp only [executeActions, List.isEmpty_cons, Bool.false_eq_true, ↓reduceIte] at accepted
  obtain ⟨⟨middle, value⟩, first, accepted⟩ := option_bind_ok accepted
  exact ⟨middle, value, first, execute_single accepted⟩

private theorem snapshot_semantic {w next : Model.State} {sid tid : Nat}
    {s : Model.Store} {after : Model.Tx} {output : Output}
    (source : find w.stores sid = some s)
    (accepted : Model.execute w (.snapshot sid tid) = some (next, output))
    (live : find next.txs tid = some after)
    : after.snapshot = some { current := s.head, term := s.term }
      ∧ output = .snapshot s.head.version s.global s.term := by
  dsimp only [Model.execute] at accepted
  obtain ⟨⟨actualStore, before⟩, lookup, accepted⟩ := option_bind_ok accepted
  have store := (lookup_found lookup).1
  cases source.symm.trans store
  try dsimp only at accepted
  split at accepted
  · cases accepted
  · cases accepted
    simp only [find_set_same, Option.some.injEq] at live
    subst after
    exact ⟨rfl, rfl⟩

private theorem term_semantic {w next : Model.State} {sid term : Nat}
    {s : Model.Store} {output : Output}
    (source : find w.stores sid = some s)
    (accepted : Model.execute w (.setTerm sid term) = some (next, output))
    : find next.stores sid = some { s with term } := by
  dsimp only [Model.execute] at accepted
  obtain ⟨actual, store, accepted⟩ := option_bind_ok accepted
  cases source.symm.trans store
  try dsimp only at accepted
  split at accepted
  · cases accepted
  · cases accepted
    exact find_set_same _ _ _

/-- Captured metadata comes from semantic snapshot execution, including initial-term inference. -/
theorem step_capture_metadata (w next : World)
    (sid tid version global term seq : Nat) (s : Store) (t : Tx)
    (source : storeOf w sid = .ok s)
    (accepted : step w ⟨seq, .snapshot sid tid version global term⟩ = .ok next)
    (capturedTx : find next.txs tid = some t)
    : ∃ snap, t.snapshot = some snap ∧ snap.current = s.head ∧ snap.term = term := by
  obtain ⟨eventNext, event, equal⟩ := record_checked accepted
  obtain ⟨semantic, output, _, executed, reported, lifted⟩ := event_checked event
  have final : find semantic.txs tid = some t.toTx := by
    have projected := project_tx next tid
    rw [capturedTx] at projected
    subst next eventNext
    change find (project (liftState (metadata w _ output) semantic)).txs tid = _ at projected
    simpa only [lift_projects, Option.map_some] using projected
  have store : find (project w).stores sid = some s.toStore := by
    simp only [project_store, store_found source, Option.map_some]
  by_cases unknown : (find w.stores sid).any (fun s => !s.termKnown) = true
  · simp only [actions, unknown, ↓reduceIte, List.cons_append, List.nil_append] at executed
    obtain ⟨middle, value, initialTerm, snapshot⟩ := execute_pair executed
    obtain ⟨captured, computed⟩ :=
      snapshot_semantic (term_semantic store initialTerm) snapshot final
    rw [computed] at reported
    have termEqual := (decide_eq_true_eq.mp reported : _ ∧ _ ∧ term = term).2.2
    exact ⟨{ current := s.head, term }, captured, rfl, termEqual⟩
  · have known : (find w.stores sid).any (fun s => !s.termKnown) = false := by
      cases h : (find w.stores sid).any (fun s => !s.termKnown) <;> simp_all
    simp only [actions, known, Bool.false_eq_true, ↓reduceIte, List.nil_append] at executed
    obtain ⟨captured, computed⟩ := snapshot_semantic store (execute_single executed) final
    rw [computed] at reported
    have termEqual := (decide_eq_true_eq.mp reported : _ ∧ _ ∧ term = s.term).2.2
    refine ⟨{ current := s.head, term := s.term }, captured, rfl, termEqual.symm⟩

/-- Reported capture cuts are checked against the source store by trace guards. -/
theorem step_capture_cut_values (w next : World)
    (sid tid version global term seq : Nat) (s : Store) (source : storeOf w sid = .ok s)
    (accepted : step w ⟨seq, .snapshot sid tid version global term⟩ = .ok next)
    : version = s.head.version ∧ global = s.global := by
  obtain ⟨_, event, _⟩ := record_checked accepted
  obtain ⟨_, _, guarded, _, _, _⟩ := event_checked event
  obtain ⟨actualStore, store, guarded⟩ := bind_ok guarded
  cases source.symm.trans store
  obtain ⟨_, _, guarded⟩ := bind_ok guarded
  obtain ⟨_, _, guarded⟩ := bind_ok guarded
  try dsimp only at guarded
  split at guarded
  · have checked := expect_ok guarded
    simp only [Bool.and_eq_true, beq_iff_eq] at checked
    exact checked.1
  · cases guarded

/-- A successful map acquisition installs the semantic captured global frame and reports its cuts. -/
theorem step_map_capture (w next : World)
    (sid tid localVersion globalVersion seq : Nat) (map : String) (s : Store)
    (before after : Tx) (snap : Snapshot) (store : storeOf w sid = .ok s)
    (tx : txOf w sid tid = .ok before) (snapshot : before.snapshot = some snap)
    (accepted : step w ⟨seq, .acquire sid tid map localVersion globalVersion⟩ = .ok next)
    (live : find next.txs tid = some after)
    : find after.globalViews map = some (captureGlobal s snap map)
      ∧ localVersion = (revision (captureLocal s snap map) map).version
      ∧ globalVersion = (revision (captureGlobal s snap map).frame map).version := by
  obtain ⟨eventNext, event, equal⟩ := record_checked accepted
  obtain ⟨semantic, output, _, executed, reported, lifted⟩ := event_checked event
  have final : find semantic.txs tid = some after.toTx := by
    have projected := project_tx next tid
    rw [live] at projected
    subst next eventNext
    change find (project (liftState (metadata w _ output) semantic)).txs tid = _ at projected
    simpa only [lift_projects, Option.map_some] using projected
  have executed := execute_single executed
  dsimp only [Model.execute] at executed
  rw [lookup_project store tx] at executed
  obtain ⟨_, selected, executed⟩ := option_bind_ok executed
  cases selected
  dsimp only at executed
  obtain ⟨actualSnapshot, selected, executed⟩ := option_bind_ok executed
  cases snapshot.symm.trans selected
  try dsimp only at executed
  split at executed
  · cases executed
  · split at executed
    · cases executed
      simp only [find_set_same, Option.some.injEq] at final
      have views := congrArg (fun t : Model.Tx => find t.globalViews map) final
      simp only [find_set_same] at views
      have versions := decide_eq_true_eq.mp reported
      have current : (captureGlobal s snap map).current = captureLocal s snap map := by
        dsimp only [captureGlobal]
        split <;> rfl
      exact ⟨views.symm, by simpa only [current] using versions.1, versions.2⟩
    · cases executed
      simp [reportedMatches] at reported

end Kv.Proofs.Capture
