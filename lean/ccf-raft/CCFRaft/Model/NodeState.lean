-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model.Configuration
import CCFRaft.Model.Log

/-!
# Node state

One node's consensus state and pure queries over it, given the
`InitialConfig`. `commitIndex` ends the committed prefix of the log.

No protocol steps here: `Local.lean` defines those.
-/

namespace CCFRaft.Model.Local

/-- The role a node holds. -/
inductive Role where
  /-- No leadership role, including fresh and newly retired nodes. -/
  | none
  /-- A replica that receives AppendEntries messages. -/
  | follower
  /-- A node collecting pre-votes without advancing its term. -/
  | preVoteCandidate
  /-- A node collecting votes in its current term. -/
  | candidate
  /-- A node that accepts client requests and sends AppendEntries. -/
  | leader
deriving DecidableEq, Repr

/-- The membership and retirement phases of a node. -/
inductive MembershipState where
  | active
  | retirementOrdered
  | retirementSigned
  | retirementCompleted
  | retiredCommitted
deriving DecidableEq, Repr

variable {Node TxId : Type}

/-- A node's local view of the log, elections, replication, and membership. -/
structure NodeState (Node TxId : Type) where
  /-- Leadership role, independent of membership and retirement status. -/
  role : Role
  /-- Election term the node is currently in; newer terms supersede older ones. -/
  currentTerm : Nat
  /-- Ordered entries, including any uncommitted suffix after `commitIndex`. -/
  log : List (Entry Node TxId)
  /-- Last committed log position, or zero if no entries are committed. -/
  commitIndex : Nat
  /-- Leader's send frontier for each peer; a rejection can move it backwards. -/
  sentIndex : Node -> Nat
  /-- Leader's highest acknowledged log position for each peer. -/
  matchIndex : Node -> Nat
  /-- Whether AppendEntries may roll back a conflicting uncommitted suffix. -/
  isNewFollower : Bool
  /-- Candidate this node voted for in its term, or `none` if it has not voted. -/
  votedFor : Option Node
  /--
  Whether the node has seen a leader in its current term, either by accepting
  its AppendEntries or by becoming leader. Such a node refuses regular votes.
  -/
  leaderKnown : Bool := false
  /-- Nodes supporting this node's regular election, including its own vote. -/
  votesGranted : Finset Node
  /-- Nodes supporting its preliminary election round, including its own vote. -/
  preVotesGranted : Finset Node := {}
  /-- Whether the node is active or progressing through retirement. -/
  membershipState : MembershipState := .active
  /-- First configuration log position that removes this node, if any. -/
  retirementIndex : Option Nat := none
  /-- First signature position after removal, making retirement committable. -/
  retirementCommittableIndex : Option Nat := none
  /--
  Commit frontier when a record confirming this node's completed retirement
  first became committed; not necessarily the position of that record.
  -/
  retiredCommittedIndex : Option Nat := none

namespace NodeState

/-- The prefix of a node's log up to its local commit index. -/
def committedLog (state : NodeState Node TxId) : List (Entry Node TxId) :=
  state.log.take state.commitIndex

end NodeState

variable [DecidableEq Node] [DecidableEq TxId]

/--
The starting state of one node. Initially configured members start at `BOOTSTRAP_TERM`.
Every other node starts with no role at term 0, waiting to be added.
-/
def initialNodeState (config : InitialConfig Node) (node : Node)
    : NodeState Node TxId where
  role :=
    if node = config.leader then
      .leader
    else if node ∈ config.configuration then
      .follower
    else
      .none
  currentTerm := if node ∈ config.configuration then BOOTSTRAP_TERM else 0
  log := []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := false
  votedFor := none
  leaderKnown := node = config.leader
  votesGranted := ∅

/-- The active configurations given a node's log and commit index. -/
def NodeState.activeConfigurations (config : InitialConfig Node)
    (state : NodeState Node TxId)
    : List (Configuration Node) :=
  Local.activeConfigurations config state.log state.commitIndex

/-- All nodes named by a node's active configurations. -/
def NodeState.activeMembers (config : InitialConfig Node) (state : NodeState Node TxId)
    : Finset Node :=
  configurationMembers (state.activeConfigurations config)

/-- Nodes removed by committed configurations but not retired-committed yet. -/
def NodeState.retirementCompleted (config : InitialConfig Node)
    (state : NodeState Node TxId)
    : Finset Node :=
  let committedLog := state.log.take state.commitIndex
  let committed :=
    (configurationHistory config state.log).filter
      fun configuration => configuration.index <= state.commitIndex
  let currentNodes :=
    committed.foldl (fun _ configuration => configuration.nodes) config.configuration
  ((configurationMembers committed \ currentNodes)
    \ retiredCommittedNodes committedLog).filter
    fun node => (retirementIndexInLog config node committedLog).isSome

/-- Recompute a node's retirement metadata from its log and commit index. -/
def refreshRetirementState (config : InitialConfig Node) (node : Node)
    (state : NodeState Node TxId)
    : NodeState Node TxId :=
  let retirementIndex := retirementIndexInLog config node state.log
  let retirementCommittableIndex :=
    retirementIndex.bind
      fun index =>
        firstLogIndexAfter state.log index (fun content => decide (content = .signature))
  let committedRetiredIndex :=
    state.retiredCommittedIndex.orElse
      fun _ =>
        if node ∈ retiredCommittedNodes (state.log.take state.commitIndex) then
          some state.commitIndex
        else
          none
  let membershipState :=
    match retirementIndex with
    | none => MembershipState.active
    | some index =>
        if committedRetiredIndex.isSome then
          .retiredCommitted
        else if index <= state.commitIndex then
          .retirementCompleted
        else if retirementCommittableIndex.isSome then
          .retirementSigned
        else
          .retirementOrdered
  {
    state with
      membershipState
      retirementIndex
      retirementCommittableIndex
      retiredCommittedIndex := committedRetiredIndex
  }

/--
A node may campaign once some known configuration containing it has reached
the node's signed log frontier. Configuration 0 therefore admits bootstrap
members even before the first signature.
-/
def campaignEligible (config : InitialConfig Node) (node : Node)
    (state : NodeState Node TxId)
    : Prop :=
  (state.activeConfigurations config).any
    fun configuration =>
      decide
        (node ∈ configuration.nodes
          /\ configuration.index <= maxCommittableIndex state.log)

instance (config : InitialConfig Node) (node : Node) (state : NodeState Node TxId)
    : Decidable (campaignEligible config node state) := by
  unfold campaignEligible
  infer_instance

/-- Enter the next term as a candidate and vote for self. -/
@[simp]
def becomeCandidateNodeState (state : NodeState Node TxId) (node : Node)
    : NodeState Node TxId :=
  {
    state with
      role := .candidate
      currentTerm := state.currentTerm + 1
      votedFor := some node
      leaderKnown := false
      votesGranted := {node}
      preVotesGranted := ∅
  }

/--
The log position a node reports when it campaigns: its commit index or its
latest signature, whichever is higher.
-/
def lastCommittableIndex (state : NodeState Node TxId) : Nat :=
  max state.commitIndex (maxCommittableIndex state.log)

/-- The term at `lastCommittableIndex`. -/
def lastCommittableTerm (state : NodeState Node TxId) : Nat :=
  termAt state.log (lastCommittableIndex state)

end CCFRaft.Model.Local
