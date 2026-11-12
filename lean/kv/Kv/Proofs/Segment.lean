-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Proofs.SemanticInvariant
public import Kv.Proofs.Capture

@[expose] public section

namespace Kv.Proofs.Segment

open Kv.Model
      hiding Store Tx advance compactStore rollbackStore tryApply step transitionSystem
open Kv.TraceValidation Kv.Properties Kv.Proofs.Capture Kv.Proofs.Correspondence
open Kv.Proofs.SemanticHelpers

private def Applications (w : Model.State) (sid : Nat) : Model.Action → List Model.Tx
  | .apply actual tid =>
      if actual = sid then ((Model.lookupTx w actual tid).map Prod.snd).toList else []
  | _ => []

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
        ∧ HeadEffect before after (Applications w sid action) := by
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
          simpa only [Applications, ↓reduceIte, lookup, Option.map_some,
            Option.toList_some]
            using HeadEffect.apply t one
        · refine ⟨before, ?_, ?_⟩
          · rw [find_set_other _ _ _ _ same]; exact live
          · simpa only [Applications, same, ↓reduceIte] using HeadEffect.stutter (before := before) rfl
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

private theorem applications_translate (w : World) (sid : Nat) (event : Event)
    (a : Model.Action) (shape : actions w event = [a])
    (guarded : guardEvent w event = .ok ())
    : Applications (project w) sid a
      = (projectedApplication w sid event).map Tx.toTx := by
  cases event <;> simp only [actions] at shape
  all_goals try solve
    | cases shape
      rfl
    | cases shape
  · rename_i actual tid version global term
    split at shape <;> simp_all [Applications, projectedApplication]
    cases shape
    rfl
  · rename_i actual tid version term writes
    cases shape
    obtain ⟨s, store, guarded⟩ := bind_ok guarded
    obtain ⟨t, tx, _⟩ := bind_ok guarded
    simp only [Applications, projectedApplication]
    rw [lookup_project store tx]
    by_cases same : actual = sid
    · subst actual
      simp [tx, Except.toOption]
    · simp [same]

private theorem single_legal (w : World) (sid : Nat) (event : Event) (a : Model.Action)
    (output : Output) (shape : actions w event = [a]) (segment : SegmentEvent sid event)
    (reported : reportedMatches event output = true)
    : Legal sid output a := by
  cases event <;> simp only [actions] at shape
  all_goals try solve
    | cases shape
      trivial
    | cases shape
      exact segment
    | cases shape
  · split at shape <;> simp_all [Legal]
    cases shape
    trivial
  · cases shape
    exact Or.inl segment
  · cases shape
    cases output <;> simp [reportedMatches] at reported
    exact Or.inr rfl

private theorem event_head (w next : World) (sid : Nat) (s : Store) (event : Event)
    (live : find w.stores sid = some s) (segment : SegmentEvent sid event)
    (accepted : stepEvent w event = .ok next)
    : ∃ after,
        find next.stores sid = some after
        ∧ HeadEffect s.toStore after.toStore
            ((projectedApplication w sid event).map Tx.toTx) := by
  obtain ⟨semantic, output, guarded, executed, reported, lifted⟩ := event_checked accepted
  have original : find (project w).stores sid = some s.toStore := by
    simp only [project_store, live, Option.map_some]
  have installed : project next = semantic := by rw [lifted, lift_projects]
  have single (a : Model.Action) (shape : actions w event = [a])
      : ∃ after, find next.stores sid = some after ∧
          HeadEffect s.toStore after.toStore ((projectedApplication w sid event).map Tx.toTx) := by
    obtain ⟨core, found, effect⟩ :=
      execute_head (project w) semantic sid s.toStore a output original
        (single_legal w sid event a output shape segment reported)
        (execute_single (by simpa only [shape] using executed))
    rw [applications_translate w sid event a shape guarded] at effect
    rw [← installed] at found
    obtain ⟨after, finalLive, same⟩ := project_store_exists next sid core found
    exact ⟨after, finalLive, by simpa only [same] using effect⟩
  have stutter (shape : actions w event = [])
      (noApply : projectedApplication w sid event = [])
      : ∃ after, find next.stores sid = some after ∧
          HeadEffect s.toStore after.toStore ((projectedApplication w sid event).map Tx.toTx) := by
    have equal : semantic = project w := by
      have pair : (semantic, output) = (project w, .unit) := by
        simpa only [shape, executeActions, Option.some.injEq] using executed.symm
      exact congrArg Prod.fst pair
    rw [← equal, ← installed] at original
    obtain ⟨after, finalLive, same⟩ := project_store_exists next sid s.toStore original
    refine ⟨after, finalLive, ?_⟩
    simpa only [noApply, List.map_nil, same]
      using HeadEffect.stutter (before := s.toStore) rfl
  cases event
  all_goals first
    | exact single _ rfl
    | exact stutter rfl rfl
    | skip
  rename_i actual tid version global term
  cases known : (find w.stores actual).any (fun s => !s.termKnown)
  · apply single (.snapshot actual tid)
    simp [actions, known]
  · simp only [actions, known, ↓reduceIte, List.cons_append, List.nil_append] at executed
    obtain ⟨middle, value, initial, capture⟩ := execute_pair executed
    obtain ⟨old, oldLive, first⟩ :=
      execute_head (project w) middle sid s.toStore (.setTerm actual term) value original trivial initial
    obtain ⟨core, found, second⟩ :=
      execute_head middle semantic sid old (.snapshot actual tid) output oldLive trivial capture
    cases first with
    | stutter first =>
        cases second with
        | stutter second =>
            rw [← installed] at found
            obtain ⟨after, finalLive, same⟩ := project_store_exists next sid core found
            refine ⟨after, finalLive, ?_⟩
            simpa only [same, projectedApplication, List.map_nil]
              using HeadEffect.stutter (before := s.toStore) (second.trans first)

private theorem serial_projects (db : Data) (version : Nat) (ts : List Tx)
    : semanticSerialTransactions db version (ts.map Tx.toTx)
      = serialTransactions db version ts := by
  induction ts generalizing db version with
  | nil => rfl
  | cons t ts ih =>
      simp only [List.map_cons, semanticSerialTransactions, serialTransactions]
      congr 1
      funext writes
      exact ih _ _

private theorem applications_reachable (w : World) (sid : Nat) (event : Event)
    (reachable : transitionSystem.Reachable w)
    : ∀ t ∈ (projectedApplication w sid event).map Tx.toTx,
        ∃ (semantic : Model.State) (tid : Nat),
          Model.transitionSystem.Reachable semantic ∧ find semantic.txs tid = some t := by
  cases event <;> simp only [projectedApplication]
  all_goals try solve | simp
  rename_i actual tid version term writes
  by_cases same : actual = sid
  · subst actual
    simp only [ite_true]
    cases selected : txOf w sid tid with
    | error => simp [Except.toOption]
    | ok t =>
        simp only [Except.toOption, Option.toList_some, List.map_cons, List.map_nil,
          List.mem_singleton]
        intro core equal
        subst core
        refine ⟨project w, tid, reachable_projects w reachable, ?_⟩
        simp only [project_tx, (tx_found selected).1, Option.map_some]
  · simp [same]

private theorem serial_witness (before after : Model.Store) (ts : List Model.Tx)
    (reachable
      : ∀ t ∈ ts,
          ∃ (w : Model.State) (tid : Nat),
            Model.transitionSystem.Reachable w ∧ find w.txs tid = some t)
    (effect : HeadEffect before after ts)
    : semanticSerialTransactions before.head.data before.head.version ts
        = some after.head.data
      ∧ after.head.version = before.head.version + ts.length := by
  cases effect with
  | stutter head => simp [semanticSerialTransactions, head]
  | apply t one =>
      refine ⟨SemanticInvariant.semantic_executable_branch_serializability before after [t]
        reachable (.cons _ _ _ _ [] one (.nil _)), ?_⟩
      dsimp only [Model.tryApply] at one
      split at one
      · cases one
        rfl
      · cases one

private theorem serialTransactions_append (db : Data) (version : Nat) (xs ys : List Tx)
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

private theorem step_iff_transition (w next : World) (r : Record)
    : transitionSystem.step w r = some next ↔ step w r = .ok next := by
  simp only [transitionSystem]
  cases step w r <;> simp [Except.toOption]

/-- Actual pre-event attempts serialize every accepted selected-store segment in application order. -/
theorem replay_segment_serializability
    : ∀ (w final : World) (sid : Nat) (s : Store) (rs : List Record),
        transitionSystem.Reachable w
        → find w.stores sid = some s
        → (∀ r ∈ rs, SegmentEvent sid r.event)
        → CCF.Execution.Run transitionSystem w rs final
        → ∃ after txs,
            find final.stores sid = some after
            ∧ projectApplications w sid rs = .ok txs
            ∧ serialTransactions s.head.data s.head.version txs = some after.head.data
            ∧ after.head.version = s.head.version + txs.length := by
  intro w final sid s rs reachable live segment run
  induction rs generalizing w s with
  | nil =>
      cases run using @CCF.Execution.Run.casesOn transitionSystem
      exact ⟨s, [], live, rfl, rfl, by simp⟩
  | cons r rs ih =>
      cases run using @CCF.Execution.Run.casesOn transitionSystem with
      | @cons _ middle _ _ _ transition tail =>
          have first := (step_iff_transition _ _ _).mp transition
          obtain ⟨eventNext, event, same⟩ := record_checked first
          obtain ⟨nextStore, nextLive, effect⟩ :=
            event_head w eventNext sid s r.event live (segment r (List.mem_cons_self))
              event
          have middleLive : find middle.stores sid = some nextStore := by
            simpa only [same] using nextLive
          obtain ⟨after, tailTxs, finalLive, projected, tailSerial, tailVersion⟩ :=
            ih middle nextStore (.step reachable transition) middleLive
              (fun e member => segment e (List.mem_cons_of_mem _ member)) tail
          have one := serial_witness s.toStore nextStore.toStore _
            (applications_reachable w sid r.event reachable) effect
          rw [serial_projects] at one
          have count : ((projectedApplication w sid r.event).map Tx.toTx).length =
              (projectedApplication w sid r.event).length := List.length_map Tx.toTx
          rw [count] at one
          refine ⟨
            after,
            projectedApplication w sid r.event ++ tailTxs,
            finalLive,
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

end Kv.Proofs.Segment
