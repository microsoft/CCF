module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Proofs.Invariant.Messages
public import CCFRaft.Proofs.Ledger

@[expose] public section

set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Proofs.Config

open CCFRaft.Model.Node
open CCF Concrete
open CCFRaft.Proofs.Ledger

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node]
  [LinearOrder Node] [Inhabited TxId]

/-- The fresh local state assigned when a configuration first adds a node. -/
def freshNodeState : NodeState Node TxId where
  role := .none
  currentTerm := 0
  log := []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := false
  votedFor := none
  votesGranted := ∅

/-- The local candidate state written by `becomeCandidate` before any promotion. -/
def becomeCandidateNodeState (state : NodeState Node TxId) (self : Node)
    : NodeState Node TxId :=
  {
    state with
      role := .candidate
      currentTerm := state.currentTerm + 1
      votedFor := some self
      leaderKnown := false
      votesGranted := {self}
      preVotesGranted := ∅
  }

/-- Start a campaign at one entry of the concrete node table. -/
def becomeCandidateState (state : Model.State Node TxId) (node : Node)
    : Model.State Node TxId :=
  {
    state with
      nodes :=
        replaceNode state.nodes node (becomeCandidateNodeState (nodeOf state node) node)
  }

/-- Commit advancement, before clearing the role of a node whose retirement commits. -/
def advanceCommitNodeState (state : NodeState Node TxId) (self : Node)
    : NodeState Node TxId :=
  state.commitThrough self (highestCommittableIndex (inferInstance) state self)

/--
Clear the role of a node whose retirement is committed.
-/
def demoteRetiredCommittedNode (_previous : NodeState Node TxId) (self : Node)
    (state : NodeState Node TxId) : NodeState Node TxId :=
  if (state.retirement (inferInstance) self).phase = .retiredCommitted then
    {
      state with
        role := .none
        leaderKnown := false
    }
  else
    state

/-- Whether `advanceCommit` commits a new frontier. -/
abbrev advancesCommit (state : NodeState Node TxId) (self : Node) : Prop :=
  state.commitIndex < highestCommittableIndex (inferInstance) state self

/-- Whether `advanceCommit` commits this leader's retirement, so it nominates a successor. -/
abbrev advanceCommitNominates (state : NodeState Node TxId) (self : Node) : Prop :=
  advancesCommit state self
  /\ ((advanceCommitNodeState state self).retirement (inferInstance) self).phase
      = .retiredCommitted
  /\ state.role = .leader

/-- The vote proposal `nominateSuccessor` sends, if there is a successor. -/
def nominationEnvelopes (state : NodeState Node TxId) (self : Node)
    : List (Model.Envelope Node TxId) :=
  (findSuccessor (inferInstance) state self).toList.map
    fun successor =>
      { source := self, target := successor, payload := .proposeVoteRequest state.currentTerm }

/-- The sends of `advanceCommit`: only a retiring leader's nomination. -/
def advanceCommitEnvelopes (state : NodeState Node TxId) (self : Node)
    : List (Model.Envelope Node TxId) :=
  if advanceCommitNominates state self then nominationEnvelopes state self else []

/-- The state returned by `advanceCommit`. -/
def advanceCommitResult (state : NodeState Node TxId) (self : Node) : NodeState Node TxId :=
  if highestCommittableIndex (inferInstance) state self <= state.commitIndex then
    state
  else
    demoteRetiredCommittedNode state self (advanceCommitNodeState state self)

theorem nominateSuccessor_run (state : NodeState Node TxId) (self : Node)
    (outputs : Outputs Node (Message Node TxId) Notification)
    : (nominateSuccessor (inferInstance) (Capabilities.record self) state self).run outputs
      = some ((), { outputs with outgoing := outputs.outgoing ++ nominationEnvelopes state self })
    := by
  unfold nominateSuccessor nominationEnvelopes
  cases findSuccessor (inferInstance) state self <;> simp [Capabilities.record]

/-- `advanceCommit` never fails; it sends only a retiring leader's nomination. -/
theorem advanceCommit_run (state : NodeState Node TxId) (self : Node)
    (outputs : Outputs Node (Message Node TxId) Notification)
    : (Model.Node.advanceCommit (inferInstance) (Capabilities.record self) state self).run
        outputs
      = some (advanceCommitResult state self,
          { outputs with outgoing := outputs.outgoing ++ advanceCommitEnvelopes state self }) := by
  unfold Model.Node.advanceCommit advanceCommitResult demoteRetiredCommittedNode
    advanceCommitEnvelopes advanceCommitNominates
  by_cases stale : highestCommittableIndex (inferInstance) state self <= state.commitIndex
  · simp [stale, Nat.not_lt.mpr stale]
  · have ahead : state.commitIndex < highestCommittableIndex (inferInstance) state self := by
      omega
    by_cases retired : ((advanceCommitNodeState state self).retirement (inferInstance)
          self).phase = .retiredCommitted
    all_goals simp only [advanceCommitNodeState] at retired
    · by_cases leader : state.role = .leader
      · simp [stale, ahead, retired, leader, advanceCommitNodeState, StateT.run_bind,
          nominateSuccessor_run]
      · simp [stale, retired, leader, advanceCommitNodeState]
    · simp [stale, retired, advanceCommitNodeState]

def advanceCommitState (state : Model.State Node TxId) (node : Node)
    : Model.State Node TxId :=
  {
    state with
      nodes :=
        replaceNode state.nodes node (advanceCommitNodeState (nodeOf state node) node)
  }

def demoteRetiredCommitted (state : Model.State Node TxId) (node : Node)
    : Model.State Node TxId :=
  {
    state with
      nodes :=
        replaceNode state.nodes node
          (demoteRetiredCommittedNode (nodeOf state node) node (nodeOf state node))
  }

def stepDownState (state : Model.State Node TxId) (node : Node) : Model.State Node TxId :=
  {
    state with
      nodes :=
        replaceNode state.nodes node
          { nodeOf state node with role := .follower, leaderKnown := false }
  }

/-- One occurrence is selected from the concrete network. -/
def Selected (source : Node) (network : List (Model.Envelope Node TxId))
    (envelope : Model.Envelope Node TxId) (remaining : List (Model.Envelope Node TxId))
    : Prop :=
  envelope.source = source
  /\ envelope ∈ network
  /\ remaining = CCF.MultiNodeTransitionSystem.removeOne envelope network

/-- Append the handler's reply to the remaining concrete network. -/
def reply (remaining : List (Model.Envelope Node TxId))
    (response : AppendResponseKey Node)
    : List (Model.Envelope Node TxId) :=
  remaining ++ [appendResponseEnvelope response]

abbrev enqueue (network : List (Model.Envelope Node TxId))
    (envelope : Model.Envelope Node TxId)
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
