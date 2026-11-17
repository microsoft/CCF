module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.VoteResponse

@[expose] public section

/-!
# Obligation: `recv_request_vote_response` of a pre-vote (not reviewed)

The hold is matched by the clean receive of the pre-vote response alone (`voteResponse_spec`).
-/

namespace Consensus.TraceValidation.Proofs

open Vote

theorem requestPreVoteResponseSound (env : Env) : RequestPreVoteResponseSound env := by
  intro node source r saved init actions c vars others cleanOthers savedName savedId invSaved
    msgOk _ ran _ finished invVars
  simp only [plainFinish, Except.ok.injEq] at finished
  subst finished
  have hsrc := msgInv_source (msgOk source _ rfl)
  obtain ⟨nid, cl⟩ := Ae.Hoare.run (voteResponse_spec env true r savedId hsrc invSaved init)
    ⟨rfl, rfl⟩ ran
  refine ⟨nid, fun clean _ ag um => ?_⟩
  obtain ⟨clean', em, ag', um', mi⟩ := cl clean ag um invVars
  exact ⟨[], clean', localRun_receive env em, ag', um', by simp, mi⟩

end Consensus.TraceValidation.Proofs
