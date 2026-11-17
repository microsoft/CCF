module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeRespSuccessor

@[expose] public section

/-!
# Obligation: `nomination` (not reviewed)

The driver's `nominate_successor`: a leader proposes a vote to the successor that
`find_successor` picks and changes nothing. The clean counterpart is the internal
`nominateSuccessor` input, whose successor is the same (`AeResp.tvSuccessor_eq`). A node
that is not a leader does nothing, matched by the empty clean run (the clean input would be
disabled by its primary guard).
-/

namespace Consensus.TraceValidation.Proofs.AeResp

open CCF.Sections (LocalRun)
open Consensus.Model.Node
open Consensus.TraceValidation (Names Env abs agrees inv msgInv)
open Consensus.TraceValidation.Exec (State Ctx Action M)

/-- What `nominate_successor` sends from `v`. -/
def nominationSends (names : Names) (v : State) : Outbox :=
  if v.leadership = .leader then
    ((tvSuccessor v).map
      fun s =>
        CCF.Envelope.mk (names.id v.nodeId) (names.id s)
          (Message.proposeRequestVoteRequest v.currentView)).toList
  else
    []

theorem findSuccessor_bind_run {α : Type} (f : Option Exec.NodeId -> M α) (c : Ctx)
    : (Exec.becomeRetired.findSuccessor >>= f).run c
      = (f (tvSuccessor c.vars)).run c := by
  rw [StateT.run_bind, findSuccessor_run]
  rfl

theorem nominateUnsafe_spec {env : Env}
    : Spec env Exec.nominateSuccessorUnsafe
        fun v o _ v' o' => v' = v /\ o' = o ++ nominationSends env.names v := by
  intro c a c' envOk h
  unfold Exec.nominateSuccessorUnsafe Exec.becomeRetired.nominateSuccessorUnsafe at h
  rw [getV_bind_run] at h
  by_cases leader : c.vars.leadership = .leader
  · simp only [leader, beq_self_eq_true, ↓reduceIte] at h
    rw [findSuccessor_bind_run] at h
    cases hs : tvSuccessor c.vars with
    | none =>
        rw [hs] at h
        simp only [StateT.run, Pure.pure, StateT.pure, Except.pure, Except.ok.injEq,
          Prod.mk.injEq] at h
        obtain ⟨_, rfl⟩ := h
        exact ⟨envOk, rfl, by simp [nominationSends, leader, hs]⟩
    | some s =>
        rw [hs] at h
        dsimp only at h
        have sp : Spec env
            (do
              Exec.trace "step_down_and_nominate_successor"
              Exec.emitStr "to_node_id" s
              Exec.send s (Message.proposeRequestVoteRequest c.vars.currentView))
            fun v o _ v' o' =>
              v' = v
              /\ o' = o ++ [CCF.Envelope.mk (env.names.id v.nodeId) (env.names.id s)
                  (Message.proposeRequestVoteRequest c.vars.currentView)] :=
          Spec.weaken
            (Spec.bind (Spec.trace _) fun _ => Spec.bind (Spec.emitStr _ _) fun _ => Spec.send _ _)
            fun v o _ v' o' ⟨_, v1, o1, ⟨e1, f1⟩, _, v2, o2, ⟨e2, f2⟩, e3, f3⟩ => by
              subst e1 f1 e2 f2 e3 f3
              exact ⟨rfl, rfl⟩
        obtain ⟨envEnd, hv, ho⟩ := sp c a c' envOk h
        exact ⟨envEnd, hv, by simp [ho, nominationSends, leader, hs]⟩
  · have nl : (c.vars.leadership == .leader) = false := by simpa using leader
    simp only [nl, Bool.false_eq_true, ↓reduceIte] at h
    simp only [StateT.run, Pure.pure, StateT.pure, Except.pure, Except.ok.injEq,
      Prod.mk.injEq] at h
    obtain ⟨_, rfl⟩ := h
    exact ⟨envOk, rfl, by simp [nominationSends, leader]⟩

theorem nominate_spec {env : Env}
    : Spec env Exec.nominateSuccessor
        fun v o _ v' o' => v' = v /\ o' = o ++ nominationSends env.names v :=
  Spec.weaken (Spec.bind (Spec.trace _) fun _ => nominateUnsafe_spec)
    fun _ _ _ _ _ ⟨_, _, _, ⟨e1, f1⟩, e2, f2⟩ => by
      subst e1 f1 e2 f2
      exact ⟨rfl, rfl⟩

end Consensus.TraceValidation.Proofs.AeResp

namespace Consensus.TraceValidation.Proofs

open CCF.Sections (LocalRun)
open Consensus.Model.Node
open Consensus.TraceValidation.Proofs.AeResp

theorem nominationSound (env : Env) : NominationSound env := by
  intro node saved actions c vars others cleanOthers _ hId invSaved _ _ ran _ finished _
  obtain ⟨hv, ho⟩ := Spec.run nominate_spec ran
  simp only [plainFinish, Except.ok.injEq] at finished
  subst finished
  rw [hv]
  rw [List.nil_append] at ho
  rw [ho]
  refine ⟨rfl, fun clean _ agreed unmatched => ?_⟩
  by_cases leader : saved.leadership = .leader
  · have parts := agreed
    simp only [agrees, Bool.and_eq_true, beq_iff_eq, and_assoc] at parts
    obtain ⟨cRole, cTerm, _⟩ := parts
    have primary : clean.role = .primary := by
      rw [cRole]
      simp [abs, absRole, leader]
    have succ := tvSuccessor_eq invSaved leader agreed
    rw [hId] at succ
    have selfNamed : env.names.name (env.names.id saved.nodeId) = saved.nodeId :=
      (ReplUpdateCommit.Hyps.ofInv invSaved).selfNamed
    refine ⟨[.nominateSuccessor], clean, ?_, agreed, unmatched, by simp [admit], ?_⟩
    · have step := LocalRun.cons (protocol := protocol env) (node := node) (state := clean)
        (middle := clean) (action := (protocol env).internal .nominateSuccessor)
        (effects := {
          outgoing := ((findSuccessor clean node).map fun t =>
            CCF.Envelope.mk node t
              (Message.proposeRequestVoteRequest clean.currentTerm)).toList }) ?_
        (LocalRun.nil _)
      · have sends : nominationSends env.names saved
            = ((findSuccessor clean node).map fun t =>
                CCF.Envelope.mk node t
                  (Message.proposeRequestVoteRequest clean.currentTerm)).toList := by
          rw [← succ, cTerm]
          cases hs : tvSuccessor saved <;> simp [nominationSends, leader, hId, abs, hs]
        rw [sends]
        simpa [cleanActions] using step
      · cases hs : findSuccessor clean node <;>
          simp [Consensus.Model.protocol, Consensus.Model.Node.step, act,
            Consensus.Model.Node.nominateSuccessor, guard, primary, hs,
            CCF.Capabilities.record, modify, modifyGet, MonadStateOf.modifyGet,
            StateT.run] <;> rfl
    · intro envelope mem
      simp only [nominationSends, leader, ↓reduceIte] at mem
      cases hs : tvSuccessor saved with
      | none => simp [hs] at mem
      | some s =>
          simp only [hs, Option.map_some, Option.toList_some, List.mem_singleton] at mem
          subst mem
          have ne := findSuccessor_ne (succ ▸ (by simp [hs] : (tvSuccessor saved).map
            env.names.id = some (env.names.id s)))
          simp only [msgInv, selfNamed, beq_self_eq_true, Bool.true_and, bne_iff_ne, ne_eq,
            Bool.and_true]
          exact fun e => ne (by rw [← e, hId])
  · refine ⟨[], clean, ?_, agreed, unmatched, by simp, ?_⟩
    · simpa [cleanActions, nominationSends, leader] using LocalRun.nil (protocol := protocol env)
        (node := node) clean
    · simp [nominationSends, leader]

end Consensus.TraceValidation.Proofs
