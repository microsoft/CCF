module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Proofs.Invariant.Facts
public import CCFRaft.Proofs.Invariant.NodeFacts
public import CCFRaft.Proofs.Ledger

@[expose] public section

set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Proofs.Config

open CCFRaft.Model.Node
open CCFRaft.Proofs.Ledger

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId]

private def withVotedFor
    (votedFor : Option Node)
    (result : NodeState Node TxId × AppendEntriesResponse)
    : NodeState Node TxId × AppendEntriesResponse :=
  ({ result.1 with votedFor := votedFor }, result.2)

variable [InitialConfig Node]
variable (self : Node)

lemma acceptAppendEntriesRequest_votedFor
    (node : NodeState Node TxId)
    (votedFor : Option Node)
    (request : AppendEntriesRequest Node TxId)
    : acceptAppendEntriesRequest? (inferInstance) self { node with votedFor := votedFor }
        request
      = (acceptAppendEntriesRequest? (inferInstance) self node request).map
          (withVotedFor votedFor) := by
  unfold acceptAppendEntriesRequest?
  dsimp only
  split_ifs <;> rfl

lemma canProduceAppendAckEventuallyAt_votedFor
    (node : NodeState Node TxId)
    (votedFor : Option Node)
    (request : AppendRequestKey Node TxId)
    (index : Nat)
    : canProduceAppendAckEventuallyAt { node with votedFor := votedFor } request index
      ↔ canProduceAppendAckEventuallyAt node request index := by
  unfold canProduceAppendAckEventuallyAt canProduceAppendAckAt
  rw [acceptAppendEntriesRequest_votedFor]
  constructor <;> rintro (direct | future)
  · left
    rcases direct with ⟨nextNode, response, handled, success, covered⟩
    rw [Option.map_eq_some_iff] at handled
    rcases handled with ⟨result, oldHandled, resultEq⟩
    rcases result with ⟨oldNextNode, oldResponse⟩
    simp [withVotedFor] at resultEq
    rcases resultEq with ⟨_, rfl⟩
    exact ⟨oldNextNode, oldResponse, oldHandled, success, covered⟩
  · exact Or.inr future
  · left
    rcases direct with ⟨nextNode, response, handled, success, covered⟩
    refine ⟨{ nextNode with votedFor := votedFor }, response, ?_, success, covered⟩
    rw [Option.map_eq_some_iff]
    exact ⟨(nextNode, response), handled, rfl⟩
  · exact Or.inr future

end CCFRaft.Proofs.Invariant
