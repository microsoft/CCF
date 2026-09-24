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

end CCFRaft.Proofs.Invariant
