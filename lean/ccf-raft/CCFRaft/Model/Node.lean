-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Mathlib.Data.Finset.Card
import Mathlib.Data.Finset.Lattice.Fold

set_option autoImplicit false

/-!
# Node state and ledger

The state one CCF Raft node stores, its log entries, and the functions a node
computes from its own log: configurations, retirement phases, and signatures.
Nothing here reads another node's state or the network.
-/

namespace CCFRaft.Model.Local

/--
Whether a node only answers pre-vote packets, or also starts its elections with
a pre-vote round.
-/
inductive PreVoteStatus where
  | capable
  | enabled
deriving DecidableEq, Repr

/-- Static configuration shared by every node: the bootstrap membership, its
leader, and each node's pre-vote mode. -/
class Bootstrap (Node : Type) [DecidableEq Node] where
  configuration : Finset Node
  leader : Node
  leader_mem : Membership.mem configuration leader
  preVoteStatus : Node -> PreVoteStatus := fun _ => .capable

/-- The initial leader. -/
def INITIAL_LEADER {Node : Type} [DecidableEq Node] [bootstrap : Bootstrap Node] : Node :=
  bootstrap.leader

/-- The term of the initial leader, matching CCF's forced-primary startup. -/
def BOOTSTRAP_TERM : Nat := 2

/-- Bootstrap membership known before its physical log entry is written. -/
def INITIAL_CONFIGURATION {Node : Type} [DecidableEq Node] [bootstrap : Bootstrap Node]
    : Finset Node :=
  bootstrap.configuration

/-- The pre-vote mode of each node. -/
def INITIAL_PRE_VOTE_STATUS {Node : Type} [DecidableEq Node] [bootstrap : Bootstrap Node]
    : Node -> PreVoteStatus :=
  bootstrap.preVoteStatus

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

/-- The payload kinds stored in the log. -/
inductive EntryContent (Node TxId : Type) where
  /-- An ordinary client transaction with its external identifier. -/
  | transaction (txId : TxId)
  /-- A signature over the preceding log prefix. -/
  | signature
  /-- A new configuration, identified by its one-based log index. -/
  | reconfiguration (nodes : Finset Node)
  /-- Nodes whose completed retirement is now durably recorded. -/
  | retiredCommitted (nodes : Finset Node)
deriving DecidableEq

/-- One entry in a node's log. -/
structure Entry (Node TxId : Type) where
  term : Nat
  content : EntryContent Node TxId
deriving DecidableEq

variable {Node TxId : Type}

/-- Protocol state stored locally by one node. -/
structure NodeState (Node TxId : Type) where
  role : Role
  currentTerm : Nat
  log : List (Entry Node TxId)
  commitIndex : Nat
  sentIndex : Node -> Nat
  matchIndex : Node -> Nat
  isNewFollower : Bool
  votedFor : Option Node
  votesGranted : Finset Node
  preVotesGranted : Finset Node := {}
  membershipState : MembershipState := .active
  retirementIndex : Option Nat := none
  retirementCommittableIndex : Option Nat := none
  /--
  The commit index at which this node's retired-committed entry first became
  committed.
  -/
  retiredCommittedIndex : Option Nat := none

namespace NodeState

/-- The prefix of a node's log up to its local commit index. -/
def committedLog (state : NodeState Node TxId) : List (Entry Node TxId) :=
  state.log.take state.commitIndex

end NodeState

variable [DecidableEq Node] [DecidableEq TxId]

/-- Replace one peer index in a node-local index table. -/
def updateIndex (indices : Node -> Nat) (node : Node) (value : Nat) : Node -> Nat :=
  Function.update indices node value

variable [Bootstrap Node]

/--
The starting state of one node. Bootstrap members start at `BOOTSTRAP_TERM`.
Every other node starts with no role at term 0, waiting to be added.
-/
def initialNodeState (node : Node) : NodeState Node TxId where
  role :=
    if node = INITIAL_LEADER then
      .leader
    else if node ∈ INITIAL_CONFIGURATION then
      .follower
    else
      .none
  currentTerm := if node ∈ INITIAL_CONFIGURATION then BOOTSTRAP_TERM else 0
  log := []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := true
  votedFor := none
  votesGranted := ∅

/-- A configuration and its one-based log index. -/
structure Configuration (Node : Type) where
  index : Nat
  nodes : Finset Node
deriving DecidableEq

/-- The bootstrap configuration at index 0, which has no log entry. -/
def implicitConfiguration : Configuration Node where
  index := 0
  nodes := INITIAL_CONFIGURATION

/-- Collect the reconfiguration entries of a log with their one-based indices. -/
def configurationsInLogFrom : Nat -> List (Entry Node TxId) -> List (Configuration Node)
  | _, [] => []
  | index, entry :: entries =>
      let remaining := configurationsInLogFrom (index + 1) entries
      match entry.content with
      | .reconfiguration nodes => { index, nodes } :: remaining
      | _ => remaining

/-- All configurations in a log, from reconfiguration entries only. -/
def configurationsInLog (log : List (Entry Node TxId)) : List (Configuration Node) :=
  configurationsInLogFrom 1 log

/-- All configurations of a log, including the bootstrap configuration. -/
def allConfigurations (log : List (Entry Node TxId)) : List (Configuration Node) :=
  implicitConfiguration :: configurationsInLog log

/-- The last configuration in a node's log. -/
def latestConfiguration (state : NodeState Node TxId) : Configuration Node :=
  (configurationsInLog state.log).foldl (fun _ configuration => configuration) implicitConfiguration

/-- The last configuration of a log at or before a commit index. -/
def currentConfigurationAt (log : List (Entry Node TxId)) (commitIndex : Nat)
    : Configuration Node :=
  (configurationsInLog log).foldl
    (fun current configuration =>
      if configuration.index <= commitIndex then configuration else current)
    implicitConfiguration

/-- The last configuration at or before the node's own commit index. -/
def currentConfiguration (state : NodeState Node TxId) : Configuration Node :=
  currentConfigurationAt state.log state.commitIndex

/--
The current configuration and every later configuration in the node's log.
-/
def activeConfigurations (state : NodeState Node TxId) : List (Configuration Node) :=
  let current := currentConfiguration state
  (allConfigurations state.log).filter
    fun configuration =>
      current.index <= configuration.index

/-- Union of the nodes in a node's active configurations. -/
def activeNodeUnion (state : NodeState Node TxId) : Finset Node :=
  (activeConfigurations state).foldl (fun nodes configuration => nodes ∪ configuration.nodes) ∅

/-- The highest active configuration index containing a node, or zero if none. -/
def highestActiveConfigurationWithNode (state : NodeState Node TxId) (node : Node) : Nat :=
  (activeConfigurations state).foldl
    (fun highest configuration =>
      if node ∈ configuration.nodes then
        max highest configuration.index
      else
        highest)
    0

/-- Find the first configuration which removes a previously included node. -/
def retirementIndexFromConfigurations (node : Node)
    : Bool -> List (Configuration Node) -> Option Nat
  | _, [] => none
  | previouslyIncluded, configuration :: configurations =>
      if node ∈ configuration.nodes then
        retirementIndexFromConfigurations node true configurations
      else if previouslyIncluded then
        some configuration.index
      else
        retirementIndexFromConfigurations node false configurations

/-- The index of the first configuration which removes a node. -/
def retirementIndexInLog (node : Node) (log : List (Entry Node TxId)) : Option Nat :=
  retirementIndexFromConfigurations node false (allConfigurations log)

/-- Find the first signature after a retirement configuration. -/
def signatureIndexAfterFrom : Nat -> Nat -> List (Entry Node TxId) -> Option Nat
  | _, _, [] => none
  | retirementIndex, index, entry :: entries =>
      if retirementIndex < index /\ entry.content = .signature then
        some index
      else
        signatureIndexAfterFrom retirementIndex (index + 1) entries

/-- The first signature which makes a retirement configuration committable. -/
def retirementCommittableIndexInLog (log : List (Entry Node TxId)) (retirementIndex : Nat)
    : Option Nat :=
  signatureIndexAfterFrom retirementIndex 1 log

/-- Find the first retired-committed entry naming a node. -/
def retiredCommittedIndexFrom (node : Node) : Nat -> List (Entry Node TxId) -> Option Nat
  | _, [] => none
  | index, entry :: entries =>
      match entry.content with
      | .retiredCommitted nodes =>
          if node ∈ nodes then
            some index
          else
            retiredCommittedIndexFrom node (index + 1) entries
      | _ => retiredCommittedIndexFrom node (index + 1) entries

/-- The index of the first retired-committed entry naming a node. -/
def retiredCommittedIndexInLog (node : Node) (log : List (Entry Node TxId)) : Option Nat :=
  retiredCommittedIndexFrom node 1 log

/-- Nodes named by retired-committed entries at or before a commit index. -/
def retiredCommittedNodesUpToFrom : Nat -> Nat -> List (Entry Node TxId) -> Finset Node
  | _, _, [] => ∅
  | commitIndex, index, entry :: entries =>
      let remaining := retiredCommittedNodesUpToFrom commitIndex (index + 1) entries
      if index <= commitIndex then
        match entry.content with
        | .retiredCommitted nodes => nodes ∪ remaining
        | _ => remaining
      else
        remaining

/-- Nodes whose retired-committed records are locally committed. -/
def retiredCommittedNodesUpTo (log : List (Entry Node TxId)) (commitIndex : Nat) : Finset Node :=
  retiredCommittedNodesUpToFrom commitIndex 1 log

/-- All nodes already named by any retired-committed log entry. -/
def allRetiredCommittedNodes (log : List (Entry Node TxId)) : Finset Node :=
  retiredCommittedNodesUpToFrom log.length 1 log

/-- Nodes removed by committed configurations but not retired-committed yet. -/
def retirementCompletedNodes (log : List (Entry Node TxId)) (commitIndex : Nat) : Finset Node :=
  let current := currentConfigurationAt log commitIndex
  let previouslyConfigured :=
    (allConfigurations log).foldl
      (fun nodes configuration =>
        if configuration.index < current.index then
          nodes ∪ configuration.nodes
        else
          nodes)
      ∅
  ((previouslyConfigured \ current.nodes) \ retiredCommittedNodesUpTo log commitIndex).filter
    fun node =>
      (retirementIndexInLog node (log.take commitIndex)).isSome

/-- Recompute a node's retirement metadata from its log and commit index. -/
def refreshRetirementState (node : Node) (state : NodeState Node TxId) : NodeState Node TxId :=
  let retirementIndex := retirementIndexInLog node state.log
  let retirementCommittableIndex :=
    retirementIndex.bind
      fun index =>
        retirementCommittableIndexInLog state.log index
  let committedRetiredIndex :=
    state.retiredCommittedIndex.orElse
      fun _ =>
        if (retiredCommittedIndexInLog node state.log).any
            (fun index => index <= state.commitIndex) then
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

/-- Read a one-based log index, returning `none` for index zero or past the end. -/
def entryAt? (log : List (Entry Node TxId)) (index : Nat) : Option (Entry Node TxId) :=
  if index = 0 then none else log[index - 1]?

/-- Read the term at a one-based index, using zero when no entry exists. -/
def termAt (log : List (Entry Node TxId)) (index : Nat) : Nat :=
  (entryAt? log index).map Entry.term |>.getD 0

/-- Check whether a one-based log position contains a signature. -/
def isSignatureAt (log : List (Entry Node TxId)) (index : Nat) : Bool :=
  match entryAt? log index with
  | some entry => decide (entry.content = .signature)
  | none => false

/-- The one-based index of the latest signature, or zero if the log has none. -/
def maxCommittableIndex (log : List (Entry Node TxId)) : Nat :=
  (List.range (log.length + 1)).foldl
    (fun best index =>
      if isSignatureAt log index then max best index else best)
    0

/--
A node may campaign once some known configuration containing it has reached
the node's signed log frontier. Configuration 0 therefore admits bootstrap
members even before the first signature.
-/
def campaignEligible (node : Node) (state : NodeState Node TxId) : Prop :=
  (activeConfigurations state).any
    fun configuration =>
      decide (node ∈ configuration.nodes /\ configuration.index <= maxCommittableIndex state.log)

instance (node : Node) (state : NodeState Node TxId) : Decidable (campaignEligible node state) := by
  unfold campaignEligible
  infer_instance

/-- Enter the next term as a candidate and vote for self. -/
@[simp]
def becomeCandidateNodeState (state : NodeState Node TxId) (node : Node) : NodeState Node TxId :=
  {
    state with
      role := .candidate
      currentTerm := state.currentTerm + 1
      votedFor := some node
      votesGranted := {node}
      preVotesGranted := ∅
  }

/-- The term of the latest signature, or zero if the log has none. -/
def maxCommittableTerm (log : List (Entry Node TxId)) : Nat :=
  termAt log (maxCommittableIndex log)

/-- The one-based index of the latest signature at or before a log position. -/
def maxCommittableIndexUpTo (log : List (Entry Node TxId)) (frontier : Nat) : Nat :=
  maxCommittableIndex (log.take frontier)

/--
The log position a node reports when it campaigns: its commit index or its
latest signature, whichever is higher.
-/
def lastCommittableIndex (state : NodeState Node TxId) : Nat :=
  max state.commitIndex (maxCommittableIndex state.log)

/-- The term at `lastCommittableIndex`. -/
def lastCommittableTerm (state : NodeState Node TxId) : Nat :=
  termAt state.log (lastCommittableIndex state)

/-- The log entries after `previousIndex` up to `batchEnd`. -/
def messageEntries (log : List (Entry Node TxId)) (previousIndex batchEnd : Nat)
    : List (Entry Node TxId) :=
  (log.drop previousIndex).take (batchEnd - previousIndex)

/-- The highest local index whose term could match a rejected request. -/
def findHighestPossibleMatch (log : List (Entry Node TxId)) (index term : Nat) : Nat :=
  (List.range (min index log.length + 1)).foldl
    (fun best candidate =>
      if candidate > 0 /\ termAt log candidate <= term then
        max best candidate
      else
        best)
    0

/-- True when a set of nodes is a strict majority of one configuration. -/
def hasConfigurationMajority (support : Finset Node) (configuration : Configuration Node) : Prop :=
  (support ∩ configuration.nodes).card * 2 > configuration.nodes.card

instance (support : Finset Node) (configuration : Configuration Node)
    : Decidable (hasConfigurationMajority support configuration) := by
  unfold hasConfigurationMajority
  infer_instance

end CCFRaft.Model.Local
