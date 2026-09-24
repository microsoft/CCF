-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.View
import CCFRaft.Proofs.Ledger

set_option autoImplicit false
set_option maxHeartbeats 700000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

namespace CCFRaft.Proofs.Invariant

open CCFRaft.Model.Local (
  BOOTSTRAP_TERM Bootstrap Configuration Entry EntryContent INITIAL_CONFIGURATION
    INITIAL_LEADER INITIAL_PRE_VOTE_STATUS MembershipState NodeState PreVoteStatus Role
    activeConfigurations activeNodeUnion allConfigurations allRetiredCommittedNodes
    becomeCandidateNodeState campaignEligible configurationsInLog configurationsInLogFrom
    currentConfiguration currentConfigurationAt entryAt? findHighestPossibleMatch
    hasConfigurationMajority highestActiveConfigurationWithNode implicitConfiguration
    initialNodeState isSignatureAt lastCommittableIndex lastCommittableTerm
    latestConfiguration maxCommittableIndex maxCommittableIndexUpTo maxCommittableTerm
    messageEntries refreshRetirementState retiredCommittedIndexFrom
    retiredCommittedIndexInLog retiredCommittedNodesUpTo retiredCommittedNodesUpToFrom
    retirementCommittableIndexInLog retirementCompletedNodes
    retirementIndexFromConfigurations retirementIndexInLog signatureIndexAfterFrom termAt
    updateIndex
  )
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

/-- Replace the state of one node. -/
def updateNode (nodes : (Node -> NodeState Node TxId)) (node : Node)
    (value : NodeState Node TxId)
    : (Node -> NodeState Node TxId) :=
  Function.update nodes node value

/-- Replace the message queue of one destination. -/
def updateQueue
    (network : Node -> List (Message Node TxId))
    (destination : Node)
    (queue : List (Message Node TxId))
    : Node -> List (Message Node TxId) :=
  Function.update network destination queue

/--
A successor has maximal replication progress, with ties broken by membership
in the highest active configuration, matching CCF's successor nomination.
-/
def plausibleSuccessor (state : View Node TxId) (source destination : Node) : Prop :=
  let sourceState := state.nodes source
  let candidates := (activeNodeUnion sourceState).erase source
  destination ∈ candidates
  /\ ∀ candidate ∈ candidates,
      sourceState.matchIndex candidate <= sourceState.matchIndex destination
      /\ (sourceState.matchIndex candidate = sourceState.matchIndex destination
          -> highestActiveConfigurationWithNode sourceState candidate
              <= highestActiveConfigurationWithNode sourceState destination)

instance (state : View Node TxId) (source destination : Node)
    : Decidable (plausibleSuccessor state source destination) := by
  unfold plausibleSuccessor
  infer_instance

/--
The conditions which let a node start an election, checked when it handles a
vote proposal. The `timeout` and `becomePreVoteCandidate` guards repeat them.
-/
def candidateTransitionEnabled (state : View Node TxId) (node : Node) : Prop :=
  state.allocated node
  /\ ((state.nodes node).role = .follower
      \/ (state.nodes node).role = .preVoteCandidate
      \/ (state.nodes node).role = .candidate)
  /\ ((node ∈ activeNodeUnion (state.nodes node)
        /\ campaignEligible node (state.nodes node))
      \/ node ∈ (state.nodes node).retirementCompleted)
  /\ Not ((state.nodes node).membershipState = .retiredCommitted)

instance (state : View Node TxId) (node : Node)
    : Decidable (candidateTransitionEnabled state node) := by
  unfold candidateTransitionEnabled
  infer_instance

/-- Append a message to its destination queue, even if an equal one is pending.
Inlining before closure conversion captures the queue once at send time. -/
@[macro_inline]
def enqueue (network : Node -> List (Message Node TxId)) (message : Message Node TxId)
    : Node -> List (Message Node TxId) :=
  let destination := message.destination
  let queue := network destination
  updateQueue network destination (queue ++ [message])

/-- A same-term candidate steps down before retrying the unchanged request. -/
def returnToFollowerState?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    : Option (NodeState Node TxId) :=
  if request.term = state.currentTerm
      /\ (state.role = .candidate \/ state.role = .preVoteCandidate) then
    some { state with role := .follower, isNewFollower := true }
  else
    none

/-- Ignore replies after stepping down; otherwise update leader peer indices. -/
def handleAppendEntriesResponse?
    (state : NodeState Node TxId)
    (response : AppendEntriesResponse Node)
    : Option (NodeState Node TxId) :=
  if state.role != .leader then
    some state
  else if response.success = true /\ response.term = state.currentTerm then
    some
      {
        state with
          matchIndex :=
            updateIndex
              state.matchIndex
              response.source
              (max (state.matchIndex response.source) response.lastLogIndex)
      }
  else if response.success = false then
    let possible := findHighestPossibleMatch state.log response.lastLogIndex response.term
    some
      {
        state with
          sentIndex :=
            updateIndex
              state.sentIndex
              response.source
              (max
                (min possible (state.sentIndex response.source))
                (state.matchIndex response.source))
      }
  else if response.term < state.currentTerm then
    some state
  else
    none

/-- Handle a current-term RequestVote request and construct the reply. -/
def handleRequestVoteRequest?
    (state : NodeState Node TxId)
    (request : RequestVoteRequest Node)
    : Option (NodeState Node TxId × RequestVoteResponse Node) :=
  if request.term <= state.currentTerm then
    let grant : Bool :=
      decide
        (request.term = state.currentTerm
          /\ voteLogUpToDate state request
          /\ (state.votedFor = none \/ state.votedFor = some request.source))
    let nextState :=
      if grant then { state with votedFor := some request.source } else state
    some
      (
        nextState,
        {
          term := state.currentTerm
          voteGranted := grant
          source := request.destination
          destination := request.source
        }
      )
  else
    none

/-- Handle a RequestPreVote request without recording a vote. -/
def handleRequestPreVote? (state : NodeState Node TxId) (request : RequestPreVote Node)
    : Option (NodeState Node TxId × RequestPreVoteResponse Node) :=
  let ordinaryRequest := request.toRequestVoteRequest
  if request.term <= state.currentTerm then
    let grant : Bool :=
      decide (request.term = state.currentTerm /\ voteLogUpToDate state ordinaryRequest)
    some
      (
        state,
        {
          term := state.currentTerm
          voteGranted := grant
          source := request.destination
          destination := request.source
        }
      )
  else
    none

/-- Tally or discard a RequestVote response at the candidate. -/
def handleRequestVoteResponse?
    (state : NodeState Node TxId)
    (response : RequestVoteResponse Node)
    : Option (NodeState Node TxId) :=
  if response.term < state.currentTerm then
    some state
  else if state.role != .candidate then
    some state
  else if response.term = state.currentTerm then
    if response.voteGranted then
      some { state with votesGranted := insert response.source state.votesGranted }
    else
      some state
  else
    none

/-- Tally or discard a RequestPreVote response without changing `votedFor`. -/
def handleRequestPreVoteResponse?
    (state : NodeState Node TxId)
    (response : RequestPreVoteResponse Node)
    : Option (NodeState Node TxId) :=
  if response.term < state.currentTerm then
    some state
  else if state.role != .preVoteCandidate then
    some state
  else if response.term = state.currentTerm then
    if response.voteGranted then
      some { state with preVotesGranted := insert response.source state.preVotesGranted }
    else
      some state
  else
    none

/-- Build a RequestPreVote message from the pre-vote candidate's local state. -/
def makeRequestPreVote (state : View Node TxId) (source destination : Node)
    : RequestPreVote Node :=
  let sourceState := state.nodes source
  {
    term := sourceState.currentTerm
    lastCommittableTerm := lastCommittableTerm sourceState
    lastCommittableIndex := lastCommittableIndex sourceState
    source
    destination
  }

/-- Build a vote proposal from the leader's local state. -/
def makeProposeVoteRequest (state : View Node TxId) (source destination : Node)
    : ProposeVoteRequest Node :=
  {
    term := (state.nodes source).currentTerm
    source
    destination
  }

/--
Start an election on a same-term vote proposal when the node is eligible, and
otherwise leave the node state unchanged.
-/
def handleProposeVoteRequest?
    (state : View Node TxId)
    (destination : Node)
    (request : ProposeVoteRequest Node)
    : Option (NodeState Node TxId) :=
  let nodeState := state.nodes destination
  if request.term = nodeState.currentTerm
      /\ candidateTransitionEnabled state destination then
    some (becomeCandidateNodeState nodeState destination)
  else
    some nodeState

/-- Replace a destination queue with its remaining messages, then append a reply. -/
@[macro_inline]
def reply
    (network : Node -> List (Message Node TxId))
    (requestDestination : Node)
    (remaining : List (Message Node TxId))
    (response : AppendEntriesResponse Node)
    : Node -> List (Message Node TxId) :=
  enqueue
    (updateQueue network requestDestination remaining)
    (.appendEntriesResponse response)

/-- Build an AppendEntries request from the leader's state for one destination. -/
def makeAppendEntriesRequest
    (state : View Node TxId)
    (source destination : Node)
    (batchEnd : Nat)
    : AppendEntriesRequest Node TxId :=
  let sourceState := state.nodes source
  let previousIndex := sourceState.sentIndex destination
  {
    term := sourceState.currentTerm
    prevLogIndex := previousIndex
    prevLogTerm := termAt sourceState.log previousIndex
    entries := messageEntries sourceState.log previousIndex batchEnd
    leaderCommit := sourceState.commitIndex
    source
    destination
  }

/-- Nodes which the leader locally knows to have reached an index. -/
def acknowledgingNodes (state : View Node TxId) (leader : Node) (index : Nat)
    : Finset Node :=
  (activeNodeUnion (state.nodes leader)).filter
    fun node =>
      node = leader \/ (state.nodes leader).matchIndex node >= index

/--
True when every active configuration starting at or before an index has a
majority which reached that index.
-/
def hasMajorityAt (state : View Node TxId) (leader : Node) (index : Nat) : Prop :=
  (activeConfigurations (state.nodes leader)).all
    fun configuration =>
      decide
        (configuration.index <= index
          -> hasConfigurationMajority
              (acknowledgingNodes state leader index)
              configuration)

/-- Make the replication majority check executable. -/
instance (state : View Node TxId) (leader : Node) (index : Nat)
    : Decidable (hasMajorityAt state leader index) := by
  unfold hasMajorityAt
  infer_instance

/-- True when votes form a strict majority in every active configuration. -/
def hasElectionMajority (state : View Node TxId) (candidate : Node) : Prop :=
  (activeConfigurations (state.nodes candidate)).all
    fun configuration =>
      decide (hasConfigurationMajority (state.nodes candidate).votesGranted configuration)

instance (state : View Node TxId) (candidate : Node)
    : Decidable (hasElectionMajority state candidate) := by
  unfold hasElectionMajority
  infer_instance

/-- True when pre-votes form a strict majority in every active configuration. -/
def hasPreVoteMajority (state : View Node TxId) (candidate : Node) : Prop :=
  (activeConfigurations (state.nodes candidate)).all
    fun configuration =>
      decide
        (hasConfigurationMajority (state.nodes candidate).preVotesGranted configuration)

instance (state : View Node TxId) (candidate : Node)
    : Decidable (hasPreVoteMajority state candidate) := by
  unfold hasPreVoteMajority
  infer_instance

/-- Whether some active configuration contains a replica other than the node. -/
def hasOtherActiveReplica (state : View Node TxId) (node : Node) : Prop :=
  (activeNodeUnion (state.nodes node)).erase node |>.Nonempty

instance (state : View Node TxId) (node : Node)
    : Decidable (hasOtherActiveReplica state node) := by
  unfold hasOtherActiveReplica
  infer_instance

/-- Completed retirements not yet represented in a leader's log. -/
def pendingRetiredCommittedNodes (state : View Node TxId) (leader : Node) : Finset Node :=
  (state.nodes leader).retirementCompleted
  \ allRetiredCommittedNodes (state.nodes leader).log

/--
The highest current-term signature above the leader's commit index which a
majority has reached, or zero when there is none.
-/
def highestCommittableIndex (state : View Node TxId) (leader : Node) : Nat :=
  let leaderState := state.nodes leader
  (List.range (leaderState.log.length + 1)).foldl
    (fun best index =>
      if index > leaderState.commitIndex
          /\ isSignatureAt leaderState.log index = true
          /\ termAt leaderState.log index = leaderState.currentTerm
          /\ hasMajorityAt state leader index then
        max best index
      else
        best)
    0

/-- Whether advancing this leader's commit frontier completes its retirement. -/
def terminalRetirementCommit (state : View Node TxId) (node : Node) : Prop :=
  let nodeState := state.nodes node
  (refreshRetirementState node
    { nodeState with commitIndex := highestCommittableIndex state node }).membershipState
  = .retiredCommitted

instance (state : View Node TxId) (node : Node)
    : Decidable (terminalRetirementCommit state node) := by
  unfold terminalRetirementCommit
  infer_instance

/-- Apply `becomeCandidateNodeState` to one node of the global state. -/
@[simp]
def becomeCandidateState (state : View Node TxId) (node : Node) : View Node TxId :=
  let nodeState := state.nodes node
  {
    state with
      nodes :=
        updateNode state.nodes node (becomeCandidateNodeState nodeState node)
  }

/-- Advance a node's commit index and refresh its retirement metadata. -/
def advanceCommitState (state : View Node TxId) (node : Node) : View Node TxId :=
  let nodeState := state.nodes node
  let refreshed :=
    refreshRetirementState node
      { nodeState with commitIndex := highestCommittableIndex state node }
  { state with nodes := updateNode state.nodes node refreshed }

/-- Demote one node to follower without changing its term. -/
def stepDownState (state : View Node TxId) (node : Node) : View Node TxId :=
  let nodeState := state.nodes node
  {
    state with
      nodes :=
        updateNode state.nodes node
          { nodeState with role := .follower, isNewFollower := true }
  }

/--
Clear the role of a node whose retirement is committed, as CCF's
`become_retired(RetiredCommitted)` does.
-/
def demoteRetiredCommitted (state : View Node TxId) (node : Node) : View Node TxId :=
  let nodeState := state.nodes node
  if nodeState.membershipState = .retiredCommitted then
    { state with nodes := updateNode state.nodes node { nodeState with role := .none } }
  else
    state

/-- A concrete delivery selects and erases one occurrence, regardless of order. -/
def Selected (source : Node) (queue : List (Message Node TxId))
    (message : Message Node TxId) (remaining : List (Message Node TxId))
    : Prop :=
  message.source = source /\ message ∈ queue /\ remaining = queue.erase message

end CCFRaft.Proofs.Invariant
