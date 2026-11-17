module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.VoteLemmas

@[expose] public section

/-!
# Obligation: `recv_request_vote` for a pre-vote (not reviewed)

As `RequestVote`, without recording a vote: a stale request is refused in the node's view;
otherwise the node adopts a newer view and grants iff the candidate's log is at least as up
to date. It is matched by the clean receive of the request alone.
-/

namespace Consensus.TraceValidation.Proofs

open CCF.Sections (LocalRun)
open Consensus.Model.Node
open Consensus.TraceValidation.Exec (State)
open Vote

theorem requestPreVoteSound (env : Env) : RequestPreVoteSound env := by
  intro node source r saved actions c vars others cleanOthers savedName savedId invSaved
    msgOk _ ran _ finished _
  simp only [plainFinish, Except.ok.injEq] at finished
  subst finished
  obtain ⟨hv, ho⟩ := Det.run (det_recvRequestVote env (env.names.name source) true r) ran
  have request := msgOk source _ rfl
  have hsrc : env.names.id (env.names.name source) = source := msgInv_source request
  have hnode : env.names.id (env.names.name node) = node := by rw [← savedName]; exact savedId
  refine ⟨by rw [hv]; exact rvVars_nodeId .., fun clean _ agreed unmatched => ?_⟩
  have step := clean_preVote node source clean r
  have hrun := LocalRun.cons (protocol := protocol env) (node := node) (state := clean)
    (action := (protocol env).receive source (.requestPreVoteRequest r)) step (LocalRun.nil _)
  have reply : forall m : Message, (forall q, m ≠ .appendEntriesRequest q)
      -> c.outbox = [⟨node, source, m⟩]
      -> forall envelope, envelope ∈ c.outbox -> msgInv env.names envelope = true := by
    intro m hm hout envelope member
    rw [hout, List.mem_singleton] at member
    subst member
    exact msgInv_reply hnode request hm
  obtain ⟨hterm, hlog⟩ := agrees_term_log agreed
  by_cases stale : saved.currentView > r.term
  · have hu : updateTerm clean r.term = clean := updateTerm_of_ge (by omega)
    have hout : c.outbox
        = [⟨node, source, .requestPreVoteResponse
            { term := (updateTerm clean r.term).currentTerm,
              voteGranted := decide (r.term = (updateTerm clean r.term).currentTerm)
                && cleanLogOk (updateTerm clean r.term) r }⟩] := by
      rw [ho, hu]
      simp [rvOut, stale, rvResp, savedId, hsrc, hterm]
      omega
    refine ⟨[], _, ?_, ?_, unmatched_updateTerm r.term unmatched, by simp,
      reply _ (by simp) hout⟩
    · simpa [cleanActions, hout] using hrun
    · rw [hv, hu]; simpa [rvVars, stale] using agreed
  · obtain ⟨ha, ht⟩ := rvMid_agrees (r := r) agreed stale
    obtain ⟨hterm', hlog'⟩ := agrees_term_log ha
    obtain ⟨hlc, hgt, hal, -⟩ := rvMid_frame (names := env.names) r saved
    rw [hal] at hlog'
    have hok := logOk_eq invSaved hlog' r
    have hout : c.outbox
        = [⟨node, source, .requestPreVoteResponse
            { term := (updateTerm clean r.term).currentTerm,
              voteGranted := decide (r.term = (updateTerm clean r.term).currentTerm)
                && cleanLogOk (updateTerm clean r.term) r }⟩] := by
      rw [ho, ← hok, hterm', ht]
      simp [rvOut, stale, rvResp, savedId, hsrc, rvGrant, hlc, hgt, ht]
    refine ⟨[], _, ?_, ?_, unmatched_updateTerm r.term unmatched, by simp,
      reply _ (by simp) hout⟩
    · simpa [cleanActions, hout] using hrun
    · rw [hv]; simpa [rvVars, stale] using ha

end Consensus.TraceValidation.Proofs
