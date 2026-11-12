-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Proofs.SemanticHelpers
public import CCF.Execution

@[expose] public section

namespace Kv.Proofs.Retention

open Kv.Model
open Kv.Proofs.SemanticHelpers

/-- Semantic actions in a segment cannot destroy or recreate the selected attempt. -/
def AttemptAction (tid : Nat) : Action → Prop
  | .txCreate _ actual | .txEnd _ actual => actual ≠ tid
  | _ => True

/-- Captured metadata and each already acquired local/global view remain fixed. -/
structure Kept (before after : Model.Tx) : Prop where
  /-- Semantic ownership cannot change. -/
  store : after.store = before.store
  /-- A previously captured current frame and term remain fixed. -/
  snapshot : ∀ snap, before.snapshot = some snap → after.snapshot = some snap
  /-- Already acquired map frames and local data remain fixed. -/
  maps
    : ∀ map view,
        find before.globalViews map = some view
        → find after.globalViews map = some view
          ∧ image after.data map = image before.data map

private theorem kept_refl (t : Model.Tx) : Kept t t :=
  ⟨rfl, fun _ h => h, fun _ _ h => ⟨h, rfl⟩⟩

/-- Captured-view preservation composes across semantic execution. -/
theorem kept_trans {a b c : Model.Tx} (first : Kept a b) (second : Kept b c)
    : Kept a c := by
  refine ⟨second.store.trans first.store, fun snap h => second.snapshot snap (first.snapshot snap h), ?_⟩
  intro map view h
  have old := first.maps map view h
  have new := second.maps map view old.1
  exact ⟨new.1, new.2.trans old.2⟩

private theorem find_erase_other {K V : Type} [DecidableEq K] (xs : Assoc K V)
    (a k : K) (h : a ≠ k)
    : find (erase xs a) k = find xs k := by
  induction xs with
  | nil => rfl
  | cons entry xs ih =>
      rcases entry with ⟨b, v⟩
      by_cases hba : b = a <;> by_cases hbk : b = k <;> simp_all [erase, find]

private theorem find_set_other {K V : Type} [DecidableEq K] (xs : Assoc K V)
    (a k : K) (v : V) (h : a ≠ k)
    : find (set xs a v) k = find xs k := by
  simp [Model.set, find, h, find_erase_other xs a k h]

private theorem unchanged (w next : Model.State) (tid : Nat) (before : Model.Tx)
    (live : find w.txs tid = some before) (same : next.txs = w.txs)
    : ∃ after, find next.txs tid = some after ∧ Kept before after :=
  ⟨before, by rw [same]; exact live, kept_refl before⟩

private theorem updated (w : Model.State) (tid actual : Nat)
    (before source next : Model.Tx) (live : find w.txs tid = some before)
    (selected : find w.txs actual = some source) (kept : Kept source next)
    : ∃ after, find (set w.txs actual next) tid = some after ∧ Kept before after := by
  by_cases same : actual = tid
  · subst actual
    cases live.symm.trans selected
    exact ⟨next, find_set_same _ _ _, kept⟩
  · exact ⟨before, by rw [find_set_other _ _ _ _ same]; exact live, kept_refl before⟩

private theorem image_append (a b : Data) (m : String)
    : image (a ++ b) m = image a m ++ image b m := by simp [image]

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

private theorem normal_kept (t : Model.Tx) (normal : Normal String String String)
    : Kept t { t with normal } :=
  ⟨rfl, fun _ h => h, fun _ _ h => ⟨h, rfl⟩⟩

private theorem phase_kept (t : Model.Tx) (phase : Phase) : Kept t { t with phase } :=
  ⟨rfl, fun _ h => h, fun _ _ h => ⟨h, rfl⟩⟩

private theorem unavailable_kept (t : Model.Tx) : Kept t { t with unavailable := true } :=
  ⟨rfl, fun _ h => h, fun _ _ h => ⟨h, rfl⟩⟩

private theorem clear_kept (t : Model.Tx) (map : String) (entries : Assoc String String)
    : Kept t
        (entries.foldl
          (fun acc (k, _) =>
            { acc with normal := recordOp acc.data acc.normal (.write (map, k) none) })
          t) := by
  induction entries generalizing t with
  | nil => exact kept_refl t
  | cons entry entries ih =>
      exact kept_trans (normal_kept t _) (ih _)

private theorem operation_kept (t : Model.Tx) (op : Operation)
    : Kept t (executeOperation t op).1 := by
  cases op with
  | get m k global | has m k global =>
      cases global
      · exact normal_kept t _
      · exact kept_refl t
  | range m lower upper =>
      dsimp only [executeOperation, Operation.map]
      split
      · exact kept_refl t
      · exact normal_kept t _
  | clear m => exact kept_trans (normal_kept t _) (clear_kept _ m _)
  | previous | write | scan | size => exact normal_kept t _

private theorem acquire_kept (t : Model.Tx) (m : String) (view : GlobalView)
    (fresh : (find t.globalViews m).isSome = false)
    : Kept t
        {
          t with
            globalViews := set t.globalViews m view
            data := pinData t.data m view.current.data
        } := by
  refine ⟨rfl, fun _ h => h, ?_⟩
  intro map old captured
  have other : map ≠ m := by
    intro same
    subst map
    simp only [captured, Option.isSome_some, Bool.true_eq_false] at fresh
  exact ⟨
    by rw [find_set_other _ _ _ _ other.symm]; exact captured,
    pinData_other _ _ _ _ other
  ⟩

/-- Every successful semantic action preserves existing captured views in an attempt segment. -/
theorem execute_retains (w next : Model.State) (tid : Nat) (before : Model.Tx)
    (action : Action) (output : Output) (live : find w.txs tid = some before)
    (segment : AttemptAction tid action)
    (accepted : Model.execute w action = some (next, output))
    : ∃ after, find next.txs tid = some after ∧ Kept before after := by
  cases action with
  | storeCreate sid term =>
      dsimp only [execute] at accepted
      split at accepted
      · cases accepted
      · cases accepted
        exact unchanged w _ tid before live rfl
  | storeEnd sid =>
      dsimp only [execute] at accepted
      obtain ⟨_, _, accepted⟩ := option_bind_ok accepted
      split at accepted
      · cases accepted
      · cases accepted
        exact unchanged w _ tid before live rfl
  | txCreate sid actual =>
      dsimp only [execute] at accepted
      obtain ⟨_, _, accepted⟩ := option_bind_ok accepted
      split at accepted
      · cases accepted
      · cases accepted
        refine ⟨before, ?_, kept_refl before⟩
        rw [find_set_other _ _ _ _ segment]
        exact live
  | txEnd sid actual =>
      dsimp only [execute] at accepted
      obtain ⟨_, _, accepted⟩ := option_bind_ok accepted
      cases accepted
      exact ⟨before, by rw [find_erase_other _ _ _ segment]; exact live, kept_refl before⟩
  | setTerm sid term =>
      dsimp only [execute] at accepted
      obtain ⟨_, _, accepted⟩ := option_bind_ok accepted
      split at accepted
      · cases accepted
      · cases accepted
        exact unchanged w _ tid before live rfl
  | snapshot sid actual =>
      dsimp only [execute] at accepted
      obtain ⟨⟨s, t⟩, lookup, accepted⟩ := option_bind_ok accepted
      dsimp only at accepted
      split at accepted
      · cases accepted
      · rename_i enabled
        cases accepted
        apply updated w tid actual before t _ live (lookup_found lookup).2.1
        refine ⟨rfl, ?_, fun _ _ h => ⟨h, rfl⟩⟩
        intro snap captured
        simp [captured] at enabled
  | acquire sid actual m =>
      dsimp only [execute] at accepted
      obtain ⟨⟨s, t⟩, lookup, accepted⟩ := option_bind_ok accepted
      dsimp only at accepted
      obtain ⟨_, _, accepted⟩ := option_bind_ok accepted
      split at accepted
      · cases accepted
      · rename_i enabled
        have fresh : (find t.globalViews m).isSome = false := by
          cases found : (find t.globalViews m).isSome
          · rfl
          · simp [found] at enabled
        split at accepted
        · cases accepted
          exact updated w tid actual before t _ live (lookup_found lookup).2.1
            (acquire_kept t m _ fresh)
        · cases accepted
          exact updated w tid actual before t _ live (lookup_found lookup).2.1
            (unavailable_kept t)
  | operation sid actual op =>
      dsimp only [execute] at accepted
      obtain ⟨⟨s, t⟩, lookup, accepted⟩ := option_bind_ok accepted
      dsimp only at accepted
      split at accepted
      · cases accepted
      · cases accepted
        exact updated w tid actual before t _ live (lookup_found lookup).2.1 (operation_kept t op)
  | commitBegin sid actual =>
      dsimp only [execute] at accepted
      obtain ⟨⟨s, t⟩, lookup, accepted⟩ := option_bind_ok accepted
      dsimp only at accepted
      split at accepted
      · cases accepted
      · cases accepted
        exact updated w tid actual before t _ live (lookup_found lookup).2.1 (phase_kept t _)
  | apply sid actual =>
      dsimp only [execute] at accepted
      obtain ⟨⟨s, t⟩, lookup, accepted⟩ := option_bind_ok accepted
      dsimp only at accepted
      split at accepted
      · cases accepted
      · obtain ⟨_, _, accepted⟩ := option_bind_ok accepted
        cases accepted
        exact updated w tid actual before t _ live (lookup_found lookup).2.1 (phase_kept t _)
  | commitResult sid actual result =>
      dsimp only [execute] at accepted
      obtain ⟨⟨s, t⟩, lookup, accepted⟩ := option_bind_ok accepted
      dsimp only at accepted
      cases phase : t.phase <;> simp only [phase] at accepted
      all_goals try split at accepted
      all_goals try dsimp only at accepted
      all_goals cases accepted
      all_goals exact updated w tid actual before t _ live (lookup_found lookup).2.1 (phase_kept t _)
  | compact sid requested =>
      dsimp only [execute] at accepted
      obtain ⟨_, _, accepted⟩ := option_bind_ok accepted
      cases accepted
      exact unchanged w _ tid before live rfl
  | rollback sid requested term =>
      dsimp only [execute] at accepted
      obtain ⟨_, _, accepted⟩ := option_bind_ok accepted
      split at accepted
      · cases accepted
        exact unchanged w _ tid before live rfl
      · split at accepted
        · cases accepted
        · cases accepted
          exact unchanged w _ tid before live rfl

/-- Captured-view preservation holds throughout every actual semantic run in an attempt segment. -/
theorem run_retains (w final : Model.State) (tid : Nat) (before : Model.Tx)
    (actions : List Action) (live : find w.txs tid = some before)
    (segment : ∀ action ∈ actions, AttemptAction tid action)
    (run : CCF.Execution.Run Model.transitionSystem w actions final)
    : ∃ after, find final.txs tid = some after ∧ Kept before after := by
  induction actions generalizing w before with
  | nil =>
      cases run using @CCF.Execution.Run.casesOn Model.transitionSystem
      exact ⟨before, live, kept_refl before⟩
  | cons action rest ih =>
      cases run using @CCF.Execution.Run.casesOn Model.transitionSystem with
      | @cons _ next _ _ _ transition tail =>
          obtain ⟨⟨state, output⟩, executed, same⟩ := Option.map_eq_some_iff.mp transition
          dsimp only at same
          subst state
          obtain ⟨middle, middleLive, first⟩ :=
            execute_retains w next tid before action output live
              (segment action (List.mem_cons_self)) executed
          obtain ⟨after, finalLive, second⟩ :=
            ih next middle middleLive (fun a member => segment a (List.mem_cons_of_mem _ member)) tail
          exact ⟨after, finalLive, kept_trans first second⟩

end Kv.Proofs.Retention
