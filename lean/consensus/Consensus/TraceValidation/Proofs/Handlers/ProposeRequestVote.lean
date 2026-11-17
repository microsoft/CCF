module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.VotePropose

@[expose] public section

/-!
# Obligation: `recv_propose_request_vote` (not reviewed)

The hold is matched by the clean receive of the proposal alone (`propose_spec`).
-/

namespace Consensus.TraceValidation.Proofs

open Vote

theorem proposeRequestVoteSound (env : Env) : ProposeRequestVoteSound env := by
  intro node source t saved _ actions c vars others cleanOthers savedName savedId invSaved
    msgOk _ ran _ finished invVars
  simp only [plainFinish, Except.ok.injEq] at finished
  subst finished
  obtain ⟨nid, cl⟩ := Ae.Hoare.run (propose_spec env (source := source) t savedId invSaved)
    ⟨rfl, rfl⟩ ran
  refine ⟨nid, fun clean _ ag um => ?_⟩
  obtain ⟨clean', em, ag', um', mi⟩ := cl clean ag um invVars
  exact ⟨[], clean', localRun_receive env em, ag', um', by simp, mi⟩

end Consensus.TraceValidation.Proofs
