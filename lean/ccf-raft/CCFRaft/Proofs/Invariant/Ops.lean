-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Messages
import CCFRaft.Proofs.Ledger

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Model.Local
open Concrete
open CCFRaft.Proofs.Ledger

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

/-- The fresh local state assigned when a configuration first adds a node. -/
def freshNodeState : NodeState Node TxId where
  role := .none
  currentTerm := 0
  log := []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := true
  votedFor := none
  votesGranted := ∅


/-- Start a campaign at one entry of the concrete node table. -/
def becomeCandidateState (state : Model.State Node TxId) (node : Node)
    : Model.State Node TxId :=
  { state with
    nodes := replaceNode state.nodes node (becomeCandidateNodeState (nodeOf state node) node) }

def advanceCommitState (state : Model.State Node TxId) (node : Node)
    : Model.State Node TxId :=
  { state with
    nodes := replaceNode state.nodes node (Model.Local.advanceCommit (nodeOf state node) node) }

def stepDownState (state : Model.State Node TxId) (node : Node)
    : Model.State Node TxId :=
  { state with
    nodes := replaceNode state.nodes node
      { nodeOf state node with role := .follower, isNewFollower := true } }

def demoteRetiredCommitted (state : Model.State Node TxId) (node : Node)
    : Model.State Node TxId :=
  { state with
    nodes := replaceNode state.nodes node (Model.Local.demoteRetiredCommitted (nodeOf state node)) }

/-- One occurrence is selected from the concrete network. -/
def Selected (source : Node) (network : List (Model.Envelope Node TxId))
    (envelope : Model.Envelope Node TxId) (remaining : List (Model.Envelope Node TxId))
    : Prop :=
  envelope.source = source /\ envelope ∈ network
    /\ remaining = Shared.MultiNodeTransitionSystem.removeOne envelope network

/-- Append the handler's reply to the remaining concrete network. -/
def reply (remaining : List (Model.Envelope Node TxId)) (response : AppendResponseKey Node)
    : List (Model.Envelope Node TxId) :=
  remaining ++ [appendResponseEnvelope response]

abbrev enqueue (network : List (Model.Envelope Node TxId)) (envelope : Model.Envelope Node TxId)
    : List (Model.Envelope Node TxId) :=
  network ++ [envelope]

theorem memEnqueue (network : List (Model.Envelope Node TxId))
    (newMessage message : Model.Envelope Node TxId) (destination : Node)
    (member : message ∈ enqueue network newMessage ∧ message.target = destination)
    : (message ∈ network ∧ message.target = destination)
      ∨ (destination = newMessage.target ∧ message = newMessage) := by
  rcases List.mem_append.mp member.1 with old | added
  · exact Or.inl ⟨old, member.2⟩
  · have same := List.mem_singleton.mp added
    exact Or.inr ⟨by simpa [same] using member.2.symm, same⟩

theorem selected_mem_iff {source : Node}
    {network remaining : List (Model.Envelope Node TxId)}
    {selected envelope : Model.Envelope Node TxId}
    (taken : Selected source network selected remaining) (different : envelope ≠ selected)
    : envelope ∈ remaining ↔ envelope ∈ network := by
  rw [taken.2.2, removeOne_eq_list_erase, List.mem_erase_of_ne different]

end CCFRaft.Proofs.Invariant
