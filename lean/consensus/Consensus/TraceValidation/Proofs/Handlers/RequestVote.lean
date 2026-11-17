module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.VoteLemmas

@[expose] public section

/-!
# Obligation: `recv_request_vote` (not reviewed)

The hold is deterministic (`det_recvRequestVote`): a stale request is refused in the node's
view; otherwise the node adopts a newer view (`become_aware_of_new_term`), grants if it has
no leader, has not voted for another node and the candidate's log is at least as up to date,
records the vote, and answers. It is matched by the clean receive of the request alone:
`observeTerm` is `become_aware_of_new_term`, and the clean grant is M_tv's (`rvGrant_eq`,
through `lastCommittable_eq` and `getTerm_eq`).
-/

namespace Consensus.TraceValidation.Proofs

open CCF.Sections (LocalRun)
open Consensus.Model.Node
open Consensus.TraceValidation.Exec (State)
open Vote

theorem requestVoteSound (env : Env) : RequestVoteSound env := by
  intro node source r saved actions c vars others cleanOthers savedName savedId invSaved
    msgOk _ ran _ finished _
  simp only [plainFinish, Except.ok.injEq] at finished
  subst finished
  obtain ⟨hv, ho⟩ := Det.run (det_recvRequestVote env (env.names.name source) false r) ran
  have request := msgOk source _ rfl
  have hsrc : env.names.id (env.names.name source) = source := msgInv_source request
  have hnode : env.names.id (env.names.name node) = node := by rw [← savedName]; exact savedId
  refine ⟨by rw [hv]; exact rvVars_nodeId .., fun clean _ agreed unmatched => ?_⟩
  have reply : forall m : Message, (forall q, m ≠ .appendEntriesRequest q)
      -> c.outbox = [⟨node, source, m⟩]
      -> forall envelope, envelope ∈ c.outbox -> msgInv env.names envelope = true := by
    intro m hm hout envelope member
    rw [hout, List.mem_singleton] at member
    subst member
    exact msgInv_reply hnode request hm
  have run := fun clean' (out : CCF.Outputs NodeID Message Notification) step =>
    LocalRun.cons (protocol := protocol env) (node := node) (state := clean) (middle := clean')
      (action := (protocol env).receive source (.requestVoteRequest r)) (effects := out) step
      (LocalRun.nil _)
  have step := clean_vote node source clean r
  obtain ⟨hterm, hlog⟩ := agrees_term_log agreed
  by_cases stale : saved.currentView > r.term
  · have hu : updateTerm clean r.term = clean := updateTerm_of_ge (by omega)
    have refused : cleanGrant clean r source = false := by
      simp [cleanGrant, hterm]; omega
    rw [hu, refused] at step
    simp only [Bool.false_eq_true, ite_false] at step
    have hout : c.outbox
        = [⟨node, source, .requestVoteResponse
            { term := clean.currentTerm, voteGranted := false }⟩] := by
      rw [ho]; simp [rvOut, stale, rvResp, savedId, hsrc, hterm]
    refine ⟨[], clean, ?_, ?_, unmatched, by simp, reply _ (by simp) hout⟩
    · simpa [cleanActions, hout] using run _ _ step
    · rw [hv]; simpa [rvVars, stale] using agreed
  · obtain ⟨ha, ht⟩ := rvMid_agrees (r := r) agreed stale
    have grant := rvGrant_eq invSaved ha ht hsrc
    obtain ⟨hterm', -⟩ := agrees_term_log ha
    have hout : c.outbox
        = [⟨node, source, .requestVoteResponse
            { term := (updateTerm clean r.term).currentTerm,
              voteGranted := cleanGrant (updateTerm clean r.term) r source }⟩] := by
      rw [ho]; simp [rvOut, stale, rvResp, savedId, hsrc, hterm', grant]
    have unmatched' := unmatched_updateTerm r.term unmatched
    cases granted : cleanGrant (updateTerm clean r.term) r source
    · rw [granted] at step hout
      simp only [Bool.false_eq_true, ite_false] at step
      refine ⟨[], _, ?_, ?_, unmatched', by simp, reply _ (by simp) hout⟩
      · simpa [cleanActions, hout] using run _ _ step
      · rw [hv]; simpa [rvVars, stale, grant, granted] using ha
    · rw [granted] at step hout
      simp only [ite_true] at step
      have hl : (rvMid r saved).leaderId = none := by
        rw [← grant] at granted
        simp only [rvGrant, Bool.and_eq_true] at granted
        cases h : (rvMid r saved).leaderId <;> simp_all
      refine ⟨[], { updateTerm clean r.term with votedFor := some source }, ?_, ?_,
        unmatched_frame unmatched' fun p => ⟨p, rfl, rfl⟩, by simp,
        reply _ (by simp) hout⟩
      · simpa [cleanActions, hout] using run _ _ step
      · rw [hv]
        simpa [rvVars, stale, grant, granted] using agrees_vote ha hl hsrc

end Consensus.TraceValidation.Proofs
