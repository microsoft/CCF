module

public import CCFRaft.Proofs.Replication.Lead
public import CCFRaft.Proofs.Direct.Framework
public import CCFRaft.Proofs.Safety.Summary
public import CCFRaft.Proofs.Safety.Commit

@[expose] public section

/-!
# Message terms in flight

A message in the protocol's network, delivered or not, carries at most its sender's
current term. The network keeps dropped messages, so this bounds old traffic that the
packet ledger no longer records.
-/

namespace CCFRaft.Proofs.Duel.Elected

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Proofs.Config
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication

variable [Config.InitialConfiguration]

/-- Every message in the network carries at most its sender's current term. -/
theorem network_terms {nodes : List NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : forall envelope,
        envelope ∈ state.network
        -> exists sender,
            (envelope.source, sender) ∈ state.nodes
            /\ envelope.payload.term <= sender.currentTerm := by
  induction reachable
    using @TransitionSystem.Reachable.rec
      (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) with
  | initial initialized =>
      intro envelope member
      rw [initialized.2.2.2.1] at member
      cases member
  | @step before after action prior stepped ih =>
      obtain ⟨tr⟩ := LocalTransition.ofStep stepped
      have summary := LocalTransition.summary tr
      have termLe : tr.pre.currentTerm <= tr.post.currentTerm :=
        CCFRaft.Proofs.Safety.Summary.term_le summary
      intro envelope member
      rcases tr.mem_network member with old | new
      · obtain ⟨sender, senderMem, le⟩ := ih envelope old
        by_cases same : envelope.source = tr.actor
        · have eq := state_unique (Direct.keys_nodup prior) senderMem (same ▸ tr.pre_mem)
          subst eq
          exact ⟨tr.post, same ▸ tr.post_mem, Nat.le_trans le termLe⟩
        · exact ⟨sender, tr.other_mem senderMem same, le⟩
      · obtain ⟨sourceEq, ok⟩ := CCFRaft.Proofs.Safety.Summary.sends summary envelope new
        refine ⟨tr.post, sourceEq ▸ tr.post_mem, ?_⟩
        cases payload : envelope.payload with
        | appendEntriesRequest request =>
            simp only [payload] at ok
            simp only [Message.term, ok.1.2.1, le_refl]
        | appendEntriesResponse response =>
            simp only [payload] at ok
            simp only [Message.term]
            rcases ok.1 with eq | ⟨index, eq⟩
            · omega
            · obtain ⟨history, _, inv⟩ := inv_of_reachable (.step prior stepped)
              rw [eq]
              exact termAt_le_term inv tr.post_mem index
        | requestVoteRequest request =>
            simp only [payload] at ok
            simp only [Message.term, ok.1, le_refl]
        | requestVoteResponse response =>
            simp only [payload] at ok
            simp only [Message.term, ok.1, le_refl]
        | requestPreVoteRequest request =>
            simp only [payload, Message.term] at ok
            simp only [Message.term, ok, le_refl]
        | requestPreVoteResponse response =>
            simp only [payload, Message.term] at ok
            simp only [Message.term, ok, le_refl]
        | proposeRequestVoteRequest term =>
            simp only [payload] at ok
            simp only [Message.term, ok.1, le_refl]

end CCFRaft.Proofs.Duel.Elected
