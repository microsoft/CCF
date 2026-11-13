-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Proofs.Reachable
public import Kv.Proofs.Replay
public import Kv.Properties.Invariants

@[expose] public section

namespace Kv.Proofs.ModelExecution

open Kv.Model Kv.Properties Kv.Proofs.SemanticHelpers

private def Legal (sid : Nat) (output : Output) : Model.Action → Prop
  | .storeCreate actual _ | .storeEnd actual => actual ≠ sid
  | .rollback actual _ _ => actual ≠ sid ∨ output = .rollbackRejected
  | _ => True

private inductive HeadEffect (before after : Model.Store) : List Model.Tx → Prop
  | stutter (head : after.head = before.head) : HeadEffect before after []
  | apply (t : Model.Tx) (one : Model.tryApply before t = some after)
    : HeadEffect before after [t]

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

private theorem unchanged (w next : Model.State) (sid : Nat) (before : Model.Store)
    (live : find w.stores sid = some before) (same : next.stores = w.stores)
    : ∃ after, find next.stores sid = some after ∧ HeadEffect before after [] :=
  ⟨before, by rw [same]; exact live, .stutter rfl⟩

private theorem stable_update (w : Model.State) (sid actual : Nat)
    (before old next : Model.Store)
    (live : find w.stores sid = some before) (selected : find w.stores actual = some old)
    (head : next.head = old.head)
    : ∃ after,
        find (set w.stores actual next) sid = some after
        ∧ HeadEffect before after [] := by
  by_cases same : actual = sid
  · subst actual
    cases live.symm.trans selected
    exact ⟨next, find_set_same _ _ _, .stutter head⟩
  · exact ⟨before, by rw [find_set_other _ _ _ _ same]; exact live, .stutter rfl⟩

private theorem execute_head (w next : Model.State) (sid : Nat) (before : Model.Store)
    (action : Model.Action) (output : Output) (live : find w.stores sid = some before)
    (legal : Legal sid output action)
    (accepted : Model.execute w action = some (next, output))
    : ∃ after,
        find next.stores sid = some after
        ∧ HeadEffect before after (appliedTransaction w sid action) := by
  cases action with
  | storeCreate actual term =>
      dsimp only [Model.execute] at accepted
      split at accepted
      · cases accepted
      · cases accepted
        exact ⟨before, by rw [find_set_other _ _ _ _ legal]; exact live, .stutter rfl⟩
  | storeEnd actual =>
      dsimp only [Model.execute] at accepted
      obtain ⟨_, _, accepted⟩ := option_bind_ok accepted
      split at accepted
      · cases accepted
      · cases accepted
        exact ⟨before, by rw [find_erase_other _ _ _ legal]; exact live, .stutter rfl⟩
  | txCreate actual tid =>
      dsimp only [Model.execute] at accepted
      obtain ⟨_, _, accepted⟩ := option_bind_ok accepted
      split at accepted
      · cases accepted
      · cases accepted
        exact unchanged w _ sid before live rfl
  | txEnd actual tid =>
      dsimp only [Model.execute] at accepted
      obtain ⟨_, _, accepted⟩ := option_bind_ok accepted
      cases accepted
      exact unchanged w _ sid before live rfl
  | setTerm actual term =>
      dsimp only [Model.execute] at accepted
      obtain ⟨old, selected, accepted⟩ := option_bind_ok accepted
      split at accepted
      · cases accepted
      · cases accepted
        exact stable_update w sid actual before old _ live selected rfl
  | snapshot actual tid =>
      dsimp only [Model.execute] at accepted
      obtain ⟨⟨s, t⟩, _, accepted⟩ := option_bind_ok accepted
      dsimp only at accepted
      split at accepted
      · cases accepted
      · cases accepted
        exact unchanged w _ sid before live rfl
  | acquire actual tid map =>
      dsimp only [Model.execute] at accepted
      obtain ⟨⟨s, t⟩, _, accepted⟩ := option_bind_ok accepted
      dsimp only at accepted
      obtain ⟨_, _, accepted⟩ := option_bind_ok accepted
      split at accepted
      · cases accepted
      · split at accepted
        · cases accepted
          exact unchanged w _ sid before live rfl
        · cases accepted
          exact unchanged w _ sid before live rfl
  | operation actual tid op =>
      dsimp only [Model.execute] at accepted
      obtain ⟨⟨s, t⟩, _, accepted⟩ := option_bind_ok accepted
      dsimp only at accepted
      split at accepted
      · cases accepted
      · cases accepted
        exact unchanged w _ sid before live rfl
  | commitBegin actual tid =>
      dsimp only [Model.execute] at accepted
      obtain ⟨⟨s, t⟩, _, accepted⟩ := option_bind_ok accepted
      dsimp only at accepted
      split at accepted
      · cases accepted
      · cases accepted
        exact unchanged w _ sid before live rfl
  | apply actual tid =>
      dsimp only [Model.execute] at accepted
      obtain ⟨⟨old, t⟩, lookup, accepted⟩ := option_bind_ok accepted
      dsimp only at accepted
      split at accepted
      · cases accepted
      · obtain ⟨applied, one, accepted⟩ := option_bind_ok accepted
        cases accepted
        by_cases same : actual = sid
        · subst actual
          cases live.symm.trans (lookup_found lookup).1
          refine ⟨applied, find_set_same _ _ _, ?_⟩
          simpa only [appliedTransaction, ↓reduceIte, lookup, Option.map_some,
            Option.toList_some]
            using HeadEffect.apply t one
        · refine ⟨before, ?_, ?_⟩
          · rw [find_set_other _ _ _ _ same]; exact live
          · simpa only [appliedTransaction, same, ↓reduceIte] using HeadEffect.stutter (before := before) rfl
  | commitResult actual tid result =>
      dsimp only [Model.execute] at accepted
      obtain ⟨⟨s, t⟩, _, accepted⟩ := option_bind_ok accepted
      dsimp only at accepted
      cases phase : t.phase <;> simp only [phase] at accepted
      all_goals try split at accepted
      all_goals try dsimp only at accepted
      all_goals cases accepted
      all_goals exact unchanged w _ sid before live rfl
  | compact actual requested =>
      dsimp only [Model.execute] at accepted
      obtain ⟨old, selected, accepted⟩ := option_bind_ok accepted
      cases accepted
      apply stable_update w sid actual before old _ live selected
      dsimp only [Model.compactStore]
      split <;> rfl
  | rollback actual requested term =>
      dsimp only [Model.execute] at accepted
      obtain ⟨_, _, accepted⟩ := option_bind_ok accepted
      split at accepted
      · cases accepted
        exact unchanged w _ sid before live rfl
      · split at accepted
        · cases accepted
        · cases accepted
          have other : actual ≠ sid := by
            rcases legal with other | impossible
            · exact other
            · cases impossible
          exact ⟨before, by rw [find_set_other _ _ _ _ other]; exact live, .stutter rfl⟩

private theorem segment_legal (w next : State) (sid : Nat) (a : Action) (output : Output)
    (segment : SegmentAction w sid a) (executed : execute w a = some (next, output))
    : Legal sid output a := by
  cases a <;> try trivial
  · rename_i actual requested term
    rcases segment with other | ⟨s, found, rejected⟩
    · exact Or.inl other
    · dsimp only [execute] at executed
      obtain ⟨old, selected, executed⟩ := option_bind_ok executed
      cases found.symm.trans selected
      simp only [rejected, ↓reduceIte] at executed
      cases executed
      exact Or.inr rfl

private theorem applications_reachable (w : State) (sid : Nat) (a : Action)
    (reachable : transitionSystem.Reachable w)
    : ∀ t ∈ appliedTransaction w sid a,
        ∃ (state : State) (tid : Nat),
          transitionSystem.Reachable state ∧ find state.txs tid = some t := by
  cases a <;> simp only [appliedTransaction]
  all_goals try solve | simp
  rename_i actual tid
  by_cases same : actual = sid
  · subst actual
    simp only [ite_true]
    cases selected : lookupTx w sid tid with
    | none => simp
    | some pair =>
        obtain ⟨s, t⟩ := pair
        simp only [Option.map_some, Option.toList_some, List.mem_singleton]
        intro core equal
        subst core
        exact ⟨w, tid, reachable, (lookup_found selected).2.1⟩
  · simp [same]

private theorem serial_witness (before after : Store) (ts : List Tx)
    (reachable
      : ∀ t ∈ ts,
          ∃ (w : State) (tid : Nat),
            transitionSystem.Reachable w ∧ find w.txs tid = some t)
    (effect : HeadEffect before after ts)
    : serialTransactions before.head.data before.head.version ts = some after.head.data
      ∧ after.head.version = before.head.version + ts.length := by
  cases effect with
  | stutter head => simp [serialTransactions, head]
  | apply t one =>
      refine ⟨SemanticInvariant.semantic_executable_branch_serializability before after [t]
        reachable (.cons _ _ _ _ [] one (.nil _)), ?_⟩
      dsimp only [tryApply] at one
      split at one
      · cases one
        rfl
      · cases one

private theorem serial_append (db : Data) (version : Nat) (xs ys : List Tx)
    : serialTransactions db version (xs ++ ys)
      = (serialTransactions db version xs).bind
          (fun next => serialTransactions next (version + xs.length) ys) := by
  induction xs generalizing db version with
  | nil => rfl
  | cons t xs ih =>
      cases h : serialRun db [] t.normal.log with
      | none => simp [serialTransactions, h]
      | some writes =>
          simp [serialTransactions, h, ih, Nat.add_comm, Nat.add_left_comm]

/-- Actual semantic executions serialize the selected store's applications in their real order. -/
theorem execution_segment_serializability
    : ∀ (w final : State) (sid : Nat) (s : Store) (inputs : List Action),
        transitionSystem.Reachable w
        → find w.stores sid = some s
        → SegmentInputs w sid inputs
        → CCF.Execution.Run transitionSystem w inputs final
        → ∃ after txs,
            find final.stores sid = some after
            ∧ applicationInputs w sid inputs = some txs
            ∧ serialTransactions s.head.data s.head.version txs = some after.head.data
            ∧ after.head.version = s.head.version + txs.length := by
  intro w final sid s inputs reachable live segment run
  induction inputs generalizing w s with
  | nil =>
      cases run using @CCF.Execution.Run.casesOn transitionSystem
      exact ⟨s, [], live, rfl, rfl, by simp⟩
  | cons a rest ih =>
      cases run using @CCF.Execution.Run.casesOn transitionSystem with
      | @cons _ middle _ _ _ transition tail =>
          obtain ⟨⟨state, output⟩, executed, same⟩ := Option.map_eq_some_iff.mp transition
          dsimp only at same
          subst state
          obtain ⟨nextStore, nextLive, effect⟩ :=
            execute_head w middle sid s a output live (segment_legal w middle sid a output segment.1 executed) executed
          obtain ⟨after, tailTxs, finalLive, projected, tailSerial, tailVersion⟩ :=
            ih middle nextStore (.step reachable transition) nextLive (segment.2 middle transition) tail
          have one :=
            serial_witness s nextStore _ (applications_reachable w sid a reachable) effect
          refine ⟨after, appliedTransaction w sid a ++ tailTxs, finalLive, ?_, ?_, ?_⟩
          · have stepEq : step w a = some middle := transition
            simp [applicationInputs, stepEq, projected]
          · rw [serial_append, one.1]
            simpa [← one.2] using tailSerial
          · simp only [List.length_append]
            rw [tailVersion, one.2]
            exact Nat.add_assoc _ _ _

end Kv.Proofs.ModelExecution
