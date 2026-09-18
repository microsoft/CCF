-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Protocol.ExecutableTransitionSystem
import Mathlib.Data.Finmap

set_option autoImplicit false

/-!
# Raft model with reconfiguration, pre-vote, and retirement

Followers and candidates may start next-term elections repeatedly, and a message
may move another node directly across skipped terms. Handlers see only the
acting node's local state and an immutable message snapshot.
-/

namespace CCFRaft.Protocol.Model

/--
Whether a node only answers pre-vote packets, or also starts its elections with
a pre-vote round.
-/
inductive PreVoteStatus where
  | capable
  | enabled
  deriving DecidableEq, Repr

/-- Static inputs used to construct the initial state. -/
class Bootstrap (Node : Type) [DecidableEq Node] where
  configuration : Finset Node
  leader : Node
  leader_mem : Membership.mem configuration leader
  preVoteStatus : Node -> PreVoteStatus := fun _ => .capable

/-- The initial leader. -/
def INITIAL_LEADER
    {Node : Type}
    [DecidableEq Node]
    [bootstrap : Bootstrap Node] :
    Node :=
  bootstrap.leader
/-- The term of the initial leader, matching CCF's forced-primary startup. -/
def BOOTSTRAP_TERM : Nat := 2
/-- Bootstrap membership known before its physical log entry is written. -/
def INITIAL_CONFIGURATION
    {Node : Type}
    [DecidableEq Node]
    [bootstrap : Bootstrap Node] :
    Finset Node :=
  bootstrap.configuration

/-- The pre-vote mode of each node. -/
def INITIAL_PRE_VOTE_STATUS
    {Node : Type}
    [DecidableEq Node]
    [bootstrap : Bootstrap Node] :
    Node -> PreVoteStatus :=
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

/-- A replication request, as captured when the leader sends it. -/
structure AppendEntriesRequest (Node TxId : Type) where
  term : Nat
  prevLogIndex : Nat
  prevLogTerm : Nat
  entries : List (Entry Node TxId)
  leaderCommit : Nat
  source : Node
  destination : Node
  deriving DecidableEq

/-- ACK or NACK returned after processing an AppendEntries request. -/
structure AppendEntriesResponse (Node : Type) where
  term : Nat
  success : Bool
  lastLogIndex : Nat
  source : Node
  destination : Node
  deriving DecidableEq, Repr

/-! RequestVote messages carry the candidate's last committable position. -/

/-- Candidate log summary sent to a potential voter. -/
structure RequestVoteRequest (Node : Type) where
  term : Nat
  lastCommittableTerm : Nat
  lastCommittableIndex : Nat
  source : Node
  destination : Node
  deriving DecidableEq, Repr

/-- A voter's reply, granting or rejecting a vote. -/
structure RequestVoteResponse (Node : Type) where
  term : Nat
  voteGranted : Bool
  source : Node
  destination : Node
  deriving DecidableEq, Repr

/-- A pre-vote request, sent as its own message kind. -/
structure RequestPreVote (Node : Type) where
  term : Nat
  lastCommittableTerm : Nat
  lastCommittableIndex : Nat
  source : Node
  destination : Node
  deriving DecidableEq, Repr

/-- A voter's reply, granting or rejecting a pre-vote. -/
structure RequestPreVoteResponse (Node : Type) where
  term : Nat
  voteGranted : Bool
  source : Node
  destination : Node
  deriving DecidableEq, Repr

/-- A leader's same-term request that another replica start an election. -/
structure ProposeVoteRequest (Node : Type) where
  term : Nat
  source : Node
  destination : Node
  deriving DecidableEq, Repr

/-- Network messages used by replication and elections. -/
inductive Message (Node TxId : Type) where
  /-- A leader-to-follower replication request. -/
  | appendEntriesRequest (request : AppendEntriesRequest Node TxId)
  /-- A follower-to-leader acknowledgement or rejection. -/
  | appendEntriesResponse (response : AppendEntriesResponse Node)
  /-- A candidate-to-voter RequestVote request. -/
  | requestVoteRequest (request : RequestVoteRequest Node)
  /-- A voter-to-candidate RequestVote response. -/
  | requestVoteResponse (response : RequestVoteResponse Node)
  /-- A pre-vote candidate-to-voter RequestPreVote request. -/
  | requestPreVote (request : RequestPreVote Node)
  /-- A voter-to-pre-vote-candidate RequestPreVote response. -/
  | requestPreVoteResponse (response : RequestPreVoteResponse Node)
  /-- A leader-to-replica request to begin an ordinary election. -/
  | proposeVoteRequest (request : ProposeVoteRequest Node)
  deriving DecidableEq

variable {Node TxId : Type}

namespace Message

/-- Read the source ID of a message. -/
def source : Message Node TxId -> Node
  | .appendEntriesRequest request => request.source
  | .appendEntriesResponse response => response.source
  | .requestVoteRequest request => request.source
  | .requestVoteResponse response => response.source
  | .requestPreVote request => request.source
  | .requestPreVoteResponse response => response.source
  | .proposeVoteRequest request => request.source

/-- Read the destination ID of a message. -/
def destination : Message Node TxId -> Node
  | .appendEntriesRequest request => request.destination
  | .appendEntriesResponse response => response.destination
  | .requestVoteRequest request => request.destination
  | .requestVoteResponse response => response.destination
  | .requestPreVote request => request.destination
  | .requestPreVoteResponse response => response.destination
  | .proposeVoteRequest request => request.destination

/-- Read the term of a message. -/
def term : Message Node TxId -> Nat
  | .appendEntriesRequest request => request.term
  | .appendEntriesResponse response => response.term
  | .requestVoteRequest request => request.term
  | .requestVoteResponse response => response.term
  | .requestPreVote request => request.term
  | .requestPreVoteResponse response => response.term
  | .proposeVoteRequest request => request.term

/-- Whether a message is a pre-vote request or response. -/
def IsPreVote : Message Node TxId -> Prop
  | .requestPreVote _ => True
  | .requestPreVoteResponse _ => True
  | _ => False

/-- Whether a message carries no log, vote, or acknowledgement evidence. -/
def IsSafetyInert : Message Node TxId -> Prop
  | .requestPreVote _ => True
  | .requestPreVoteResponse _ => True
  | .proposeVoteRequest _ => True
  | _ => False

end Message

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
def committedLog
    (state : NodeState Node TxId) :
    List (Entry Node TxId) :=
  state.log.take state.commitIndex

end NodeState

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

/-- Finite storage for node-local protocol state. -/
structure NodeStore (Node TxId : Type) where
  entries : Finmap (fun _ : Node => NodeState Node TxId)

namespace NodeStore

variable [DecidableEq Node]

/-- Read a node's state, or `none` when the node is unallocated. -/
def node? (nodes : NodeStore Node TxId) (node : Node) :
    Option (NodeState Node TxId) :=
  nodes.entries.lookup node

/-- Read a node's state, using `freshNodeState` for an unallocated node. -/
def get (nodes : NodeStore Node TxId) (node : Node) :
    NodeState Node TxId :=
  (nodes.node? node).getD freshNodeState

instance : CoeFun (NodeStore Node TxId) (fun _ => Node -> NodeState Node TxId) where
  coe := get

/-- Whether storage has been allocated for a node identity. -/
def allocated (nodes : NodeStore Node TxId) (node : Node) : Prop :=
  nodes.node? node |>.isSome

instance (nodes : NodeStore Node TxId) (node : Node) :
    Decidable (nodes.allocated node) :=
  inferInstanceAs (Decidable (nodes.node? node |>.isSome))

/-- Insert or replace the state of one node. -/
def set
    (nodes : NodeStore Node TxId)
    (node : Node)
    (value : NodeState Node TxId) :
    NodeStore Node TxId :=
  ⟨nodes.entries.insert node value⟩

/-- A store with no allocated node identities. -/
def empty : NodeStore Node TxId :=
  ⟨∅⟩

/-- Allocate a finite set of keys with values computed from each key. -/
def ofFinset
    (keys : Finset Node)
    (value : Node -> NodeState Node TxId) :
    NodeStore Node TxId :=
  let entries :=
    keys.1.map fun node => Sigma.mk node (value node)
  ⟨{
    entries
    nodupKeys := by
      rw [← Multiset.nodup_keys]
      simpa [entries, Multiset.keys] using keys.2
  }⟩

/-- Add fresh states for a finite set without replacing existing states. -/
def allocate
    (nodes : NodeStore Node TxId)
    (added : Finset Node) :
    NodeStore Node TxId :=
  ⟨nodes.entries ∪ (ofFinset added fun _ => freshNodeState).entries⟩

end NodeStore

/--
Global state: node states, message queues, submitted transaction IDs, and join
history.
-/
structure State (Node TxId : Type) where
  nodes : NodeStore Node TxId
  network : Node -> List (Message Node TxId)
  submittedTxIds : Finset TxId
  hasJoined : Finset Node
  preVoteStatus : Node -> PreVoteStatus := fun _ => .capable
  retirementCompleted : Node -> Finset Node := fun _ => ∅

variable [DecidableEq Node] [DecidableEq TxId]

/-- Read a node's state from the global state, or `none` when unallocated. -/
def State.node? (state : State Node TxId) (node : Node) :
    Option (NodeState Node TxId) :=
  state.nodes.node? node

/-- Whether the global state has allocated storage for a node identity. -/
def State.allocated (state : State Node TxId) (node : Node) : Prop :=
  state.nodes.allocated node

instance (state : State Node TxId) (node : Node) :
    Decidable (state.allocated node) :=
  inferInstanceAs (Decidable (state.nodes.allocated node))

/-- Replace the state of one node. -/
def updateNode
    (nodes : NodeStore Node TxId)
    (node : Node)
    (value : NodeState Node TxId) :
    NodeStore Node TxId :=
  nodes.set node value

/-- Replace one peer index in a node-local index table. -/
def updateIndex
    (indices : Node -> Nat)
    (node : Node)
    (value : Nat) :
    Node -> Nat :=
  Function.update indices node value

/-- Replace the message queue of one destination. -/
def updateQueue
    (network : Node -> List (Message Node TxId))
    (destination : Node)
    (queue : List (Message Node TxId)) :
    Node -> List (Message Node TxId) :=
  Function.update network destination queue

variable [Bootstrap Node]

/--
The starting state of one node. Bootstrap members start at `BOOTSTRAP_TERM`,
every other node at term 0.
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

/-- Allocate local states for exactly the bootstrap configuration. -/
def initialNodes : NodeStore Node TxId :=
  NodeStore.ofFinset INITIAL_CONFIGURATION initialNodeState

/--
The starting global state: bootstrap members allocated, empty queues, and no
submitted transactions.
-/
def initialState : State Node TxId where
  nodes := initialNodes
  network := fun _ => []
  submittedTxIds := ∅
  hasJoined := INITIAL_CONFIGURATION
  preVoteStatus := INITIAL_PRE_VOTE_STATUS
  retirementCompleted := fun _ => ∅

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
def configurationsInLogFrom :
    Nat -> List (Entry Node TxId) -> List (Configuration Node)
  | _, [] => []
  | index, entry :: entries =>
      let remaining := configurationsInLogFrom (index + 1) entries
      match entry.content with
      | .reconfiguration nodes => { index, nodes } :: remaining
      | _ => remaining

/-- All configurations in a log, from reconfiguration entries only. -/
def configurationsInLog
    (log : List (Entry Node TxId)) :
    List (Configuration Node) :=
  configurationsInLogFrom 1 log

/-- All configurations of a log, including the bootstrap configuration. -/
def allConfigurations
    (log : List (Entry Node TxId)) :
    List (Configuration Node) :=
  implicitConfiguration :: configurationsInLog log

/-- The last configuration in a node's log. -/
def latestConfiguration
    (state : NodeState Node TxId) :
    Configuration Node :=
  (configurationsInLog state.log).foldl (fun _ configuration => configuration)
    implicitConfiguration

/-- The last configuration of a log at or before a commit index. -/
def currentConfigurationAt
    (log : List (Entry Node TxId))
    (commitIndex : Nat) : Configuration Node :=
  (configurationsInLog log).foldl
    (fun current configuration =>
      if configuration.index <= commitIndex then configuration else current)
    implicitConfiguration

/-- The last configuration at or before the node's own commit index. -/
def currentConfiguration
    (state : NodeState Node TxId) :
    Configuration Node :=
  currentConfigurationAt state.log state.commitIndex

/--
The current configuration and every later configuration in the node's log.
-/
def activeConfigurations
    (state : NodeState Node TxId) :
    List (Configuration Node) :=
  let current := currentConfiguration state
  (allConfigurations state.log).filter fun configuration =>
    current.index <= configuration.index

/-- Union of the nodes in a node's active configurations. -/
def activeNodeUnion (state : NodeState Node TxId) : Finset Node :=
  (activeConfigurations state).foldl
    (fun nodes configuration => nodes ∪ configuration.nodes)
    ∅

/-- The highest active configuration index containing a node, or zero if none. -/
def highestActiveConfigurationWithNode
    (state : NodeState Node TxId)
    (node : Node) : Nat :=
  (activeConfigurations state).foldl
    (fun highest configuration =>
      if node ∈ configuration.nodes then
        max highest configuration.index
      else
        highest)
    0

/--
A successor has maximal replication progress, with ties broken by membership
in the highest active configuration, matching CCF's successor nomination.
-/
def plausibleSuccessor
    (state : State Node TxId)
    (source destination : Node) : Prop :=
  let sourceState := state.nodes source
  let candidates := (activeNodeUnion sourceState).erase source
  destination ∈ candidates /\
    ∀ candidate ∈ candidates,
      sourceState.matchIndex candidate <=
          sourceState.matchIndex destination /\
        (sourceState.matchIndex candidate =
            sourceState.matchIndex destination ->
          highestActiveConfigurationWithNode sourceState candidate <=
            highestActiveConfigurationWithNode sourceState destination)

instance
    (state : State Node TxId)
    (source destination : Node) :
    Decidable (plausibleSuccessor state source destination) := by
  unfold plausibleSuccessor
  infer_instance

/-- Find the first configuration which removes a previously included node. -/
def retirementIndexFromConfigurations
    (node : Node) :
    Bool -> List (Configuration Node) -> Option Nat
  | _, [] => none
  | previouslyIncluded, configuration :: configurations =>
      if node ∈ configuration.nodes then
        retirementIndexFromConfigurations node true configurations
      else if previouslyIncluded then
        some configuration.index
      else
        retirementIndexFromConfigurations node false configurations

/-- The index of the first configuration which removes a node. -/
def retirementIndexInLog
    (node : Node)
    (log : List (Entry Node TxId)) :
    Option Nat :=
  retirementIndexFromConfigurations node false (allConfigurations log)

/-- Find the first signature after a retirement configuration. -/
def signatureIndexAfterFrom :
    Nat -> Nat -> List (Entry Node TxId) -> Option Nat
  | _, _, [] => none
  | retirementIndex, index, entry :: entries =>
      if retirementIndex < index /\ entry.content = .signature then
        some index
      else
        signatureIndexAfterFrom retirementIndex (index + 1) entries

/-- The first signature which makes a retirement configuration committable. -/
def retirementCommittableIndexInLog
    (log : List (Entry Node TxId))
    (retirementIndex : Nat) :
    Option Nat :=
  signatureIndexAfterFrom retirementIndex 1 log

/-- Find the first retired-committed entry naming a node. -/
def retiredCommittedIndexFrom
    (node : Node) :
    Nat -> List (Entry Node TxId) -> Option Nat
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
def retiredCommittedIndexInLog
    (node : Node)
    (log : List (Entry Node TxId)) :
    Option Nat :=
  retiredCommittedIndexFrom node 1 log

/-- Nodes named by retired-committed entries at or before a commit index. -/
def retiredCommittedNodesUpToFrom :
    Nat -> Nat -> List (Entry Node TxId) -> Finset Node
  | _, _, [] => ∅
  | commitIndex, index, entry :: entries =>
      let remaining :=
        retiredCommittedNodesUpToFrom commitIndex (index + 1) entries
      if index <= commitIndex then
        match entry.content with
        | .retiredCommitted nodes => nodes ∪ remaining
        | _ => remaining
      else
        remaining

/-- Nodes whose retired-committed records are locally committed. -/
def retiredCommittedNodesUpTo
    (log : List (Entry Node TxId))
    (commitIndex : Nat) :
    Finset Node :=
  retiredCommittedNodesUpToFrom commitIndex 1 log

/-- All nodes already named by any retired-committed log entry. -/
def allRetiredCommittedNodes
    (log : List (Entry Node TxId)) :
    Finset Node :=
  retiredCommittedNodesUpToFrom log.length 1 log

/-- Nodes removed by committed configurations but not retired-committed yet. -/
def retirementCompletedNodes
    (log : List (Entry Node TxId))
    (commitIndex : Nat) :
    Finset Node :=
  let current := currentConfigurationAt log commitIndex
  let previouslyConfigured :=
    (allConfigurations log).foldl
      (fun nodes configuration =>
        if configuration.index < current.index then
          nodes ∪ configuration.nodes
        else
          nodes)
      ∅
  ((previouslyConfigured \ current.nodes) \
    retiredCommittedNodesUpTo log commitIndex).filter fun node =>
      (retirementIndexInLog node (log.take commitIndex)).isSome

/-- Recompute a node's retirement metadata from its log and commit index. -/
def refreshRetirementState
    (node : Node)
    (state : NodeState Node TxId) :
    NodeState Node TxId :=
  let retirementIndex := retirementIndexInLog node state.log
  let retirementCommittableIndex :=
    retirementIndex.bind fun index =>
      retirementCommittableIndexInLog state.log index
  let committedRetiredIndex :=
    state.retiredCommittedIndex.orElse fun _ =>
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
  { state with
    membershipState
    retirementIndex
    retirementCommittableIndex
    retiredCommittedIndex := committedRetiredIndex }

/-- Record the retirement-completed nodes one observer must still replicate to.
Compute the snapshot at update time, not at each later function application. -/
@[macro_inline]
def refreshRetirementCompleted
    (retirementCompleted : Node -> Finset Node)
    (observer : Node)
    (state : NodeState Node TxId) :
    Node -> Finset Node :=
  Function.update retirementCompleted observer
    (retirementCompletedNodes state.log state.commitIndex)

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
def campaignEligible
    (node : Node)
    (state : NodeState Node TxId) : Prop :=
  (activeConfigurations state).any fun configuration =>
    decide (
      node ∈ configuration.nodes /\
        configuration.index <= maxCommittableIndex state.log)

instance (node : Node) (state : NodeState Node TxId) :
    Decidable (campaignEligible node state) := by
  unfold campaignEligible
  infer_instance

/--
The conditions which let a node start an election, checked when it handles a
vote proposal. The `timeout` and `becomePreVoteCandidate` guards repeat them.
-/
def candidateTransitionEnabled
    (state : State Node TxId)
    (node : Node) : Prop :=
  state.allocated node /\
    ((state.nodes node).role = .follower \/
      (state.nodes node).role = .preVoteCandidate \/
      (state.nodes node).role = .candidate) /\
    ((node ∈ activeNodeUnion (state.nodes node) /\
        campaignEligible node (state.nodes node)) \/
      node ∈ state.retirementCompleted node) /\
    Not ((state.nodes node).membershipState = .retiredCommitted)

instance
    (state : State Node TxId)
    (node : Node) :
    Decidable (candidateTransitionEnabled state node) := by
  unfold candidateTransitionEnabled
  infer_instance

/-- Enter the next term as a candidate and vote for self. -/
@[simp]
def becomeCandidateNodeState
    (state : NodeState Node TxId)
    (node : Node) :
    NodeState Node TxId :=
  { state with
    role := .candidate
    currentTerm := state.currentTerm + 1
    votedFor := some node
    votesGranted := {node}
    preVotesGranted := ∅ }

/-- The term of the latest signature, or zero if the log has none. -/
def maxCommittableTerm (log : List (Entry Node TxId)) : Nat :=
  termAt log (maxCommittableIndex log)

/-- The one-based index of the latest signature at or before a log position. -/
def maxCommittableIndexUpTo
    (log : List (Entry Node TxId))
    (frontier : Nat) : Nat :=
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
def messageEntries
    (log : List (Entry Node TxId))
    (previousIndex batchEnd : Nat) :
    List (Entry Node TxId) :=
  (log.drop previousIndex).take (batchEnd - previousIndex)

/-- Append a message to its destination queue, even if an equal one is pending.
Inlining before closure conversion captures the queue once at send time. -/
@[macro_inline]
def enqueue
    (network : Node -> List (Message Node TxId))
    (message : Message Node TxId) :
    Node -> List (Message Node TxId) :=
  let destination := message.destination
  let queue := network destination
  updateQueue network destination (queue ++ [message])

/-- Take the first message from one sender, keeping the order of the others. -/
def takeFirstFrom
    (source : Node) :
    List (Message Node TxId) ->
      Option (Message Node TxId × List (Message Node TxId))
  | [] => none
  | message :: tail =>
      if message.source = source then
        some (message, tail)
      else
        match takeFirstFrom source tail with
        | none => none
        | some (selected, remaining) =>
            some (selected, message :: remaining)

/-- Take the zero-based nth message from one sender, keeping the others in order.
Matches Network.tla's OrderDropMessage, with an explicit selection witness. -/
def takeOccurrenceFrom
    (source : Node) :
    Nat -> List (Message Node TxId) ->
      Option (Message Node TxId × List (Message Node TxId))
  | _, [] => none
  | occurrence, message :: tail =>
      if message.source = source then
        match occurrence with
        | 0 => some (message, tail)
        | n + 1 => do
            let (selected, remaining) <- takeOccurrenceFrom source n tail
            pure (selected, message :: remaining)
      else do
        let (selected, remaining) <- takeOccurrenceFrom source occurrence tail
        pure (selected, message :: remaining)

/-- Check that a request's previous index and term match the follower log. -/
def logOk
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Prop :=
  request.prevLogIndex = 0 \/
    (request.prevLogIndex <= state.log.length /\
      termAt state.log request.prevLogIndex = request.prevLogTerm)

/-- Check whether a heartbeat or all requested entry terms are already present. -/
def alreadyDone
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Prop :=
  request.entries = [] \/
    (request.prevLogIndex + request.entries.length <= state.log.length /\
      ((state.log.drop request.prevLogIndex).take request.entries.length).map
          Entry.term =
        request.entries.map Entry.term)

/-- Number of request entries that overlap the follower's existing suffix. -/
def overlapLength
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Nat :=
  min request.entries.length
    (state.log.length - request.prevLogIndex)

/-- Detect a differing term in the overlapping part of a request. -/
def hasTermConflict
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Prop :=
  Not (request.entries = []) /\
    Not (
      ((state.log.drop request.prevLogIndex).take
          (overlapLength state request)).map Entry.term =
        (request.entries.take (overlapLength state request)).map Entry.term)

/-- Check that a request safely extends a matching follower prefix. -/
def noConflictExtension
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) : Prop :=
  Not (request.entries = []) /\
    request.prevLogIndex <= state.log.length /\
    state.log.length < request.prevLogIndex + request.entries.length /\
    (state.log.drop request.prevLogIndex).take
        (state.log.length - request.prevLogIndex) =
      request.entries.take (state.log.length - request.prevLogIndex)

/-- Make the previous-entry consistency guard executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    Decidable (logOk state request) := by
  unfold logOk
  infer_instance

/-- Make the already-applied request guard executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    Decidable (alreadyDone state request) := by
  unfold alreadyDone
  infer_instance

/-- Make term-conflict detection executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    Decidable (hasTermConflict state request) := by
  unfold hasTermConflict
  infer_instance

/-- Make no-conflict extension detection executable. -/
instance (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    Decidable (noConflictExtension state request) := by
  unfold noConflictExtension
  infer_instance

/-- Advance the commit index to the latest signature the request covers. -/
def committedFromLeader
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (newLog : List (Entry Node TxId)) : Nat :=
  max state.commitIndex
    (maxCommittableIndexUpTo newLog
      (min request.leaderCommit
        (request.prevLogIndex + request.entries.length)))

/-- Build the ACK for an applied request. -/
def successResponse
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId)
    (lastLogIndex : Nat) :
    AppendEntriesResponse Node where
  term := state.currentTerm
  success := true
  lastLogIndex
  source := request.destination
  destination := request.source

/-- The highest local index whose term could match a rejected request. -/
def findHighestPossibleMatch
    (log : List (Entry Node TxId))
    (index term : Nat) : Nat :=
  (List.range (min index log.length + 1)).foldl
    (fun best candidate =>
      if candidate > 0 /\ termAt log candidate <= term then
        max best candidate
      else
        best)
    0

/-- Build the NACK for a stale or mismatched request. -/
def failureResponse
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    AppendEntriesResponse Node :=
  if request.term < state.currentTerm then
    { term := state.currentTerm
      success := false
      lastLogIndex := state.log.length
      source := request.destination
      destination := request.source }
  else
    let previousTerm :=
      if request.prevLogIndex = 0 then
        0
      else if request.prevLogIndex > state.log.length then
        0
      else
        termAt state.log state.log.length
    if previousTerm = 0 then
      { term := state.currentTerm
        success := false
        lastLogIndex := state.log.length
        source := request.destination
        destination := request.source }
    else
      let lastLogIndex :=
        findHighestPossibleMatch
          state.log request.prevLogIndex request.prevLogTerm
      { term := termAt state.log lastLogIndex
        success := false
        lastLogIndex
        source := request.destination
        destination := request.source }

/-- Reject stale-term requests or requests whose previous entry does not match. -/
def rejectAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if request.term < state.currentTerm \/
      (request.term = state.currentTerm /\
        state.role = .follower /\
        Not (logOk state request)) then
    some (state, failureResponse state request)
  else
    none

/-- ACK a request whose entries are already present, and adopt its commit index. -/
def appendEntriesAlreadyDone?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if alreadyDone state request then
    let commitIndex := committedFromLeader state request state.log
    let nextState := { state with commitIndex }
    some
      (nextState,
        successResponse nextState request
          (request.prevLogIndex + request.entries.length))
  else
    none

/-- Truncate a conflicting uncommitted suffix without consuming the request. -/
def conflictAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId) :=
  if hasTermConflict state request /\ state.isNewFollower then
    some
      { state with
        log := state.log.take request.prevLogIndex
        isNewFollower := false }
  else
    none

/-- Append a matching extension and return an ACK. -/
def noConflictAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if noConflictExtension state request then
    let newLog := state.log.take request.prevLogIndex ++ request.entries
    let commitIndex := committedFromLeader state request newLog
    -- Native receive runs commit callbacks at each newly applied signature.
    let firstRetirementCommit :=
      match retiredCommittedIndexInLog request.destination newLog with
      | none => commitIndex
      | some markerIndex =>
          match signatureIndexAfterFrom (max state.log.length markerIndex) 1 newLog with
          | none => commitIndex
          | some firstNewSignature => min commitIndex firstNewSignature
    let nextState := refreshRetirementState request.destination
      { state with log := newLog, commitIndex := firstRetirementCommit }
    let nextState := { nextState with commitIndex }
    some (nextState, successResponse nextState request newLog.length)
  else
    none

/-- Apply an accepted request: already done, clean extension, or truncate and retry. -/
def acceptAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  if request.term = state.currentTerm /\
      state.role = .follower /\
      logOk state request /\
      request.prevLogIndex >= state.commitIndex then
    match appendEntriesAlreadyDone? state request with
    | some result => some result
    | none =>
        match noConflictAppendEntriesRequest? state request with
        | some result => some result
        | none =>
            match conflictAppendEntriesRequest? state request with
            | none => none
            | some truncated =>
                match appendEntriesAlreadyDone? truncated request with
                | some result => some result
                | none => noConflictAppendEntriesRequest? truncated request
  else
    none

/-- Reject a request when required, otherwise apply it. -/
def handleAppendEntriesRequest?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId × AppendEntriesResponse Node) :=
  match rejectAppendEntriesRequest? state request with
  | some result => some result
  | none => acceptAppendEntriesRequest? state request

/-- A same-term candidate steps down before retrying the unchanged request. -/
def returnToFollowerState?
    (state : NodeState Node TxId)
    (request : AppendEntriesRequest Node TxId) :
    Option (NodeState Node TxId) :=
  if request.term = state.currentTerm /\
      (state.role = .candidate \/
        state.role = .preVoteCandidate) then
    some { state with role := .follower, isNewFollower := true }
  else
    none

/-- Ignore replies after stepping down; otherwise update leader peer indices. -/
def handleAppendEntriesResponse?
    (state : NodeState Node TxId)
    (response : AppendEntriesResponse Node) :
    Option (NodeState Node TxId) :=
  if state.role != .leader then
    some state
  else if response.success = true /\
      response.term = state.currentTerm then
    some
      { state with
        matchIndex :=
          updateIndex
            state.matchIndex
            response.source
            (max (state.matchIndex response.source) response.lastLogIndex) }
  else if response.success = false then
    let possible :=
      findHighestPossibleMatch state.log response.lastLogIndex response.term
    some
      { state with
        sentIndex :=
          updateIndex
            state.sentIndex
            response.source
            (max
              (min possible (state.sentIndex response.source))
              (state.matchIndex response.source)) }
  else if response.term < state.currentTerm then
    some state
  else
    none

/-- Compare a candidate log summary with a voter's local log. -/
def voteLogUpToDate
    (state : NodeState Node TxId)
    (request : RequestVoteRequest Node) : Prop :=
  request.lastCommittableTerm > maxCommittableTerm state.log \/
    (request.lastCommittableTerm = maxCommittableTerm state.log /\
      request.lastCommittableIndex >= maxCommittableIndex state.log)

instance (state : NodeState Node TxId) (request : RequestVoteRequest Node) :
    Decidable (voteLogUpToDate state request) := by
  unfold voteLogUpToDate
  infer_instance

/-- Read a RequestPreVote as a RequestVote request with the same fields. -/
def RequestPreVote.toRequestVoteRequest
    (request : RequestPreVote Node) :
    RequestVoteRequest Node where
  term := request.term
  lastCommittableTerm := request.lastCommittableTerm
  lastCommittableIndex := request.lastCommittableIndex
  source := request.source
  destination := request.destination

/-- Handle a current-term RequestVote request and construct the reply. -/
def handleRequestVoteRequest?
    (state : NodeState Node TxId)
    (request : RequestVoteRequest Node) :
    Option (NodeState Node TxId × RequestVoteResponse Node) :=
  if request.term <= state.currentTerm then
    let grant : Bool :=
      decide (
        request.term = state.currentTerm /\
          voteLogUpToDate state request /\
          (state.votedFor = none \/
            state.votedFor = some request.source))
    let nextState :=
      if grant then { state with votedFor := some request.source } else state
    some
      (nextState,
        { term := state.currentTerm
          voteGranted := grant
          source := request.destination
          destination := request.source })
  else
    none

/-- Handle a RequestPreVote request without recording a vote. -/
def handleRequestPreVote?
    (state : NodeState Node TxId)
    (request : RequestPreVote Node) :
    Option (NodeState Node TxId × RequestPreVoteResponse Node) :=
  let ordinaryRequest := request.toRequestVoteRequest
  if request.term <= state.currentTerm then
    let grant : Bool :=
      decide (
        request.term = state.currentTerm /\
          voteLogUpToDate state ordinaryRequest)
    some
      (state,
        { term := state.currentTerm
          voteGranted := grant
          source := request.destination
          destination := request.source })
  else
    none

/-- Tally or discard a RequestVote response at the candidate. -/
def handleRequestVoteResponse?
    (state : NodeState Node TxId)
    (response : RequestVoteResponse Node) :
    Option (NodeState Node TxId) :=
  if response.term < state.currentTerm then
    some state
  else if state.role != .candidate then
    some state
  else if response.term = state.currentTerm then
    if response.voteGranted then
      some
        { state with
          votesGranted := insert response.source state.votesGranted }
    else
      some state
  else
    none

/-- Tally or discard a RequestPreVote response without changing `votedFor`. -/
def handleRequestPreVoteResponse?
    (state : NodeState Node TxId)
    (response : RequestPreVoteResponse Node) :
    Option (NodeState Node TxId) :=
  if response.term < state.currentTerm then
    some state
  else if state.role != .preVoteCandidate then
    some state
  else if response.term = state.currentTerm then
    if response.voteGranted then
      some
        { state with
          preVotesGranted := insert response.source state.preVotesGranted }
    else
      some state
  else
    none

/-- Build a RequestVote message from the candidate's local state. -/
def makeRequestVoteRequest
    (state : State Node TxId)
    (source destination : Node) :
    RequestVoteRequest Node :=
  let sourceState := state.nodes source
  { term := sourceState.currentTerm
    lastCommittableTerm := lastCommittableTerm sourceState
    lastCommittableIndex := lastCommittableIndex sourceState
    source
    destination }

/-- Build a RequestPreVote message from the pre-vote candidate's local state. -/
def makeRequestPreVote
    (state : State Node TxId)
    (source destination : Node) :
    RequestPreVote Node :=
  let sourceState := state.nodes source
  { term := sourceState.currentTerm
    lastCommittableTerm := lastCommittableTerm sourceState
    lastCommittableIndex := lastCommittableIndex sourceState
    source
    destination }

/-- Build a vote proposal from the leader's local state. -/
def makeProposeVoteRequest
    (state : State Node TxId)
    (source destination : Node) :
    ProposeVoteRequest Node :=
  { term := (state.nodes source).currentTerm
    source
    destination }

/--
Start an election on a same-term vote proposal when the node is eligible, and
otherwise leave the node state unchanged.
-/
def handleProposeVoteRequest?
    (state : State Node TxId)
    (destination : Node)
    (request : ProposeVoteRequest Node) :
    Option (NodeState Node TxId) :=
  let nodeState := state.nodes destination
  if request.term = nodeState.currentTerm /\
      candidateTransitionEnabled state destination then
    some (becomeCandidateNodeState nodeState destination)
  else
    some nodeState

/-- Requests may introduce an unknown sender; responses require a known peer. -/
def messageSourceAllowed
    (state : State Node TxId)
    (message : Message Node TxId) : Prop :=
  match message with
  | .appendEntriesRequest _ => True
  | .requestVoteRequest _ => True
  | .requestPreVote _ => True
  | .appendEntriesResponse response => state.allocated response.source
  | .requestVoteResponse response => state.allocated response.source
  | .requestPreVoteResponse response => state.allocated response.source
  | .proposeVoteRequest _ => True

instance
    (state : State Node TxId)
    (message : Message Node TxId) :
    Decidable (messageSourceAllowed state message) := by
  cases message <;> simp only [messageSourceAllowed] <;> infer_instance

/--
The first queued message from a source with a newer term, ignoring vote
proposals, which never advance a term.
-/
def newerMessage?
    (state : State Node TxId)
    (source destination : Node) :
    Option (Message Node TxId) := do
  let (selected, _) <- takeFirstFrom source (state.network destination)
  match selected with
  | .proposeVoteRequest _ => none
  | _ =>
      if messageSourceAllowed state selected /\
          (state.nodes destination).currentTerm < selected.term then
        some selected
      else
        none

/-- Replace a destination queue with its remaining messages, then append a reply. -/
@[macro_inline]
def reply
    (network : Node -> List (Message Node TxId))
    (requestDestination : Node)
    (remaining : List (Message Node TxId))
    (response : AppendEntriesResponse Node) :
    Node -> List (Message Node TxId) :=
  enqueue
    (updateQueue network requestDestination remaining)
    (.appendEntriesResponse response)

/-- Process the first queued message from one sender at a destination. -/
def handleReceive?
    (state : State Node TxId)
    (source destination : Node) :
    Option (State Node TxId) :=
  match takeFirstFrom source (state.network destination) with
  | none => none
  | some (message, remaining) =>
      if message.destination != destination then
        none
      else
        match message with
        | .appendEntriesRequest request =>
            match returnToFollowerState? (state.nodes destination) request with
            | some nextNode =>
                some
                  { state with
                    nodes := updateNode state.nodes destination nextNode }
            | none =>
                match handleAppendEntriesRequest? (state.nodes destination) request with
                | none => none
                | some (nextNode, response) =>
                    let refreshedNode :=
                      refreshRetirementState destination nextNode
                    some
                      { state with
                        nodes :=
                          updateNode state.nodes destination refreshedNode
                        network :=
                          reply state.network destination remaining response
                        retirementCompleted :=
                          refreshRetirementCompleted
                            state.retirementCompleted destination refreshedNode }
        | .appendEntriesResponse response =>
            if state.allocated response.source then
              match
                handleAppendEntriesResponse? (state.nodes destination) response
              with
              | none => none
              | some nextNode =>
                  some
                    { state with
                      nodes := updateNode state.nodes destination nextNode
                      network :=
                        updateQueue state.network destination remaining }
            else
              some
                { state with
                  network :=
                    updateQueue state.network destination remaining }
        | .requestVoteRequest request =>
            match handleRequestVoteRequest? (state.nodes destination) request with
            | none => none
            | some (nextNode, response) =>
                some
                  { state with
                    nodes := updateNode state.nodes destination nextNode
                    network :=
                      enqueue
                        (updateQueue state.network destination remaining)
                        (.requestVoteResponse response) }
        | .requestVoteResponse response =>
            if state.allocated response.source then
              match
                handleRequestVoteResponse? (state.nodes destination) response
              with
              | none => none
              | some nextNode =>
                  some
                    { state with
                      nodes := updateNode state.nodes destination nextNode
                      network :=
                        updateQueue state.network destination remaining }
            else
              some
                { state with
                  network :=
                    updateQueue state.network destination remaining }
        | .requestPreVote request =>
            match
              handleRequestPreVote?
                (state.nodes destination)
                request
            with
            | none => none
            | some (nextNode, response) =>
                some
                  { state with
                    nodes := updateNode state.nodes destination nextNode
                    network :=
                      enqueue
                        (updateQueue state.network destination remaining)
                        (.requestPreVoteResponse response) }
        | .requestPreVoteResponse response =>
            if state.allocated response.source then
              match
                handleRequestPreVoteResponse?
                  (state.nodes destination)
                  response
              with
              | none => none
              | some nextNode =>
                  some
                    { state with
                      nodes := updateNode state.nodes destination nextNode
                      network :=
                        updateQueue state.network destination remaining }
            else
              some
                { state with
                  network :=
                    updateQueue state.network destination remaining }
        | .proposeVoteRequest request =>
            match handleProposeVoteRequest? state destination request with
            | none => none
            | some nextNode =>
                some
                  { state with
                    nodes := updateNode state.nodes destination nextNode
                    network :=
                      updateQueue state.network destination remaining }

/-- Build an AppendEntries request from the leader's state for one destination. -/
def makeAppendEntriesRequest
    (state : State Node TxId)
    (source destination : Node)
    (batchEnd : Nat) :
    AppendEntriesRequest Node TxId :=
  let sourceState := state.nodes source
  let previousIndex := sourceState.sentIndex destination
  { term := sourceState.currentTerm
    prevLogIndex := previousIndex
    prevLogTerm := termAt sourceState.log previousIndex
    entries := messageEntries sourceState.log previousIndex batchEnd
    leaderCommit := sourceState.commitIndex
    source
    destination }

/-- Nodes which the leader locally knows to have reached an index. -/
def acknowledgingNodes
    (state : State Node TxId)
    (leader : Node)
    (index : Nat) :
    Finset Node :=
  (activeNodeUnion (state.nodes leader)).filter fun node =>
    node = leader \/
      (state.nodes leader).matchIndex node >= index

/-- True when a set of nodes is a strict majority of one configuration. -/
def hasConfigurationMajority
    (support : Finset Node)
    (configuration : Configuration Node) : Prop :=
  (support ∩ configuration.nodes).card * 2 > configuration.nodes.card

instance (support : Finset Node) (configuration : Configuration Node) :
    Decidable (hasConfigurationMajority support configuration) := by
  unfold hasConfigurationMajority
  infer_instance

/--
True when every active configuration starting at or before an index has a
majority which reached that index.
-/
def hasMajorityAt
    (state : State Node TxId)
    (leader : Node)
    (index : Nat) : Prop :=
  (activeConfigurations (state.nodes leader)).all fun configuration =>
    decide (
      configuration.index <= index ->
        hasConfigurationMajority
          (acknowledgingNodes state leader index)
          configuration)

/-- Make the replication majority check executable. -/
instance (state : State Node TxId) (leader : Node) (index : Nat) :
    Decidable (hasMajorityAt state leader index) := by
  unfold hasMajorityAt
  infer_instance

/-- True when votes form a strict majority in every active configuration. -/
def hasElectionMajority
    (state : State Node TxId)
    (candidate : Node) : Prop :=
  (activeConfigurations (state.nodes candidate)).all fun configuration =>
    decide (
      hasConfigurationMajority
        (state.nodes candidate).votesGranted
        configuration)

instance (state : State Node TxId) (candidate : Node) :
    Decidable (hasElectionMajority state candidate) := by
  unfold hasElectionMajority
  infer_instance

/-- True when pre-votes form a strict majority in every active configuration. -/
def hasPreVoteMajority
    (state : State Node TxId)
    (candidate : Node) : Prop :=
  (activeConfigurations (state.nodes candidate)).all fun configuration =>
    decide (
      hasConfigurationMajority
        (state.nodes candidate).preVotesGranted
        configuration)

instance (state : State Node TxId) (candidate : Node) :
    Decidable (hasPreVoteMajority state candidate) := by
  unfold hasPreVoteMajority
  infer_instance

/-- Whether some active configuration contains a replica other than the node. -/
def hasOtherActiveReplica
    (state : State Node TxId)
    (node : Node) : Prop :=
  (activeNodeUnion (state.nodes node)).erase node |>.Nonempty

instance (state : State Node TxId) (node : Node) :
    Decidable (hasOtherActiveReplica state node) := by
  unfold hasOtherActiveReplica
  infer_instance

/-- Completed retirements not yet represented in a leader's log. -/
def pendingRetiredCommittedNodes
    (state : State Node TxId)
    (leader : Node) :
    Finset Node :=
  state.retirementCompleted leader \
    allRetiredCommittedNodes (state.nodes leader).log

/--
The highest current-term signature above the leader's commit index which a
majority has reached, or zero when there is none.
-/
def highestCommittableIndex
    (state : State Node TxId)
    (leader : Node) : Nat :=
  let leaderState := state.nodes leader
  (List.range (leaderState.log.length + 1)).foldl
    (fun best index =>
      if index > leaderState.commitIndex /\
          isSignatureAt leaderState.log index = true /\
          termAt leaderState.log index = leaderState.currentTerm /\
          hasMajorityAt state leader index then
        max best index
      else
        best)
    0

/-- Whether advancing this leader's commit frontier completes its retirement. -/
def terminalRetirementCommit
    (state : State Node TxId)
    (node : Node) : Prop :=
  let nodeState := state.nodes node
  (refreshRetirementState node
    { nodeState with
      commitIndex := highestCommittableIndex state node }).membershipState =
        .retiredCommitted

instance
    (state : State Node TxId)
    (node : Node) :
    Decidable (terminalRetirementCommit state node) := by
  unfold terminalRetirementCommit
  infer_instance

/-- One protocol step, with an explicit argument for every nondeterministic choice. -/
inductive Action (Node TxId : Type) where
  /-- Write the bootstrap configuration to the initial leader's empty log. -/
  | initializeConfiguration (node : Node)
  /-- Submit a fresh external transaction to a node. -/
  | clientRequest (node : Node) (txId : TxId)
  /-- Append a new nonempty configuration to a leader's log. -/
  | changeConfiguration (source : Node) (newConfiguration : Finset Node)
  /-- Record completed retirements which are not durably represented yet. -/
  | appendRetiredCommitted (node : Node)
  /-- Append a signature over a leader's nonempty log. -/
  | signCommittableMessages (node : Node)
  /-- Send a single-term batch or an empty heartbeat. -/
  | appendEntries (source destination : Node) (batchEnd : Nat)
  /-- Process the first queued message from one sender. -/
  | receive (source destination : Node)
  /-- Drop the nth message from one sender, keeping the others in order. -/
  | drop (source destination : Node) (occurrence : Nat)
  /-- Advance a leader to the commit index it can compute locally. -/
  | advanceCommitIndex (node : Node)
  /-- Start a next-term election when pre-vote is not enabled. -/
  | timeout (node : Node)
  /-- Start a pre-vote round without advancing the local term. -/
  | becomePreVoteCandidate (node : Node)
  /-- Convert a successful pre-vote round into a next-term election. -/
  | becomeCandidate (node : Node)
  /-- Send a RequestVote message from a candidate to another node. -/
  | requestVote (source destination : Node)
  /-- Send a RequestPreVote message to another node. -/
  | requestPreVote (source destination : Node)
  /-- Step down as leader in the current term after a failed quorum check. -/
  | checkQuorum (node : Node)
  /-- Observe a newer message term without consuming the message. -/
  | updateTerm (source destination : Node)
  /-- Promote a candidate after its local vote set reaches a majority. -/
  | becomeLeader (node : Node)
  /-- Ask one plausible successor to start an ordinary election. -/
  | proposeVote (source destination : Node)
  /-- Commit terminal retirement and propose a vote to a successor in one step. -/
  | advanceCommitIndexAndProposeVote (source destination : Node)
  deriving DecidableEq

/-- Apply `becomeCandidateNodeState` to one node of the global state. -/
@[simp]
def becomeCandidateState
    (state : State Node TxId)
    (node : Node) :
    State Node TxId :=
  let nodeState := state.nodes node
  { state with
    nodes :=
      updateNode state.nodes node
        (becomeCandidateNodeState nodeState node) }

/-- Advance a node's commit index and refresh its retirement metadata. -/
def advanceCommitState
    (state : State Node TxId)
    (node : Node) :
    State Node TxId :=
  let nodeState := state.nodes node
  let refreshed :=
    refreshRetirementState node
      { nodeState with
        commitIndex := highestCommittableIndex state node }
  { state with
    nodes := updateNode state.nodes node refreshed
    retirementCompleted :=
      refreshRetirementCompleted state.retirementCompleted node refreshed }

/-- Demote one node to follower without changing its term. -/
def stepDownState
    (state : State Node TxId)
    (node : Node) :
    State Node TxId :=
  let nodeState := state.nodes node
  { state with
    nodes :=
      updateNode state.nodes node
        { nodeState with role := .follower, isNewFollower := true } }

/--
Clear the role of a node whose retirement is committed, as CCF's
`become_retired(RetiredCommitted)` does.
-/
def demoteRetiredCommitted
    (state : State Node TxId)
    (node : Node) :
    State Node TxId :=
  let nodeState := state.nodes node
  if nodeState.membershipState = .retiredCommitted then
    { state with
      nodes := updateNode state.nodes node { nodeState with role := .none } }
  else
    state

/-- An action's guard and total update, including when the guard is false. -/
structure ActionDefinition (Node TxId : Type) where
  enabled : Prop
  next : State Node TxId

/-- Define each action's guard beside its state update. -/
@[reducible]
def definition
    (state : State Node TxId) :
    Action Node TxId -> ActionDefinition Node TxId
  | .initializeConfiguration node =>
      let nodeState := state.nodes node
      { enabled :=
          node = INITIAL_LEADER /\
            state.allocated node /\
            nodeState.role = .leader /\
            nodeState.currentTerm = BOOTSTRAP_TERM /\
            nodeState.log = [] /\
            nodeState.commitIndex = 0 /\
            nodeState.membershipState = .active /\
            state.hasJoined = INITIAL_CONFIGURATION
        next :=
          { state with
            nodes := updateNode state.nodes node
              { nodeState with
                log := [{ term := nodeState.currentTerm
                          content := .reconfiguration INITIAL_CONFIGURATION }] } } }
  | .clientRequest node txId =>
      let nodeState := state.nodes node
      let entry : Entry Node TxId :=
        { term := nodeState.currentTerm
          content := .transaction txId }
      let refreshed :=
        refreshRetirementState node
          { nodeState with log := nodeState.log ++ [entry] }
      { enabled :=
          state.allocated node /\
            nodeState.role = .leader /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            txId ∉ state.submittedTxIds /\
            Not (refreshed.membershipState = .retiredCommitted)
        next :=
          { state with
            nodes := updateNode state.nodes node refreshed
            submittedTxIds := insert txId state.submittedTxIds
            retirementCompleted :=
              refreshRetirementCompleted state.retirementCompleted node refreshed } }
  | .changeConfiguration source newConfiguration =>
      let sourceState := state.nodes source
      let previousConfiguration := (latestConfiguration sourceState).nodes
      let addedNodes := newConfiguration \ previousConfiguration
      let entry : Entry Node TxId :=
        { term := sourceState.currentTerm
          content := .reconfiguration newConfiguration }
      let appended := { sourceState with log := sourceState.log ++ [entry] }
      { enabled :=
          state.allocated source /\
            sourceState.role = .leader /\
            Not (sourceState.membershipState = .retiredCommitted) /\
            newConfiguration.Nonempty /\
            Not (newConfiguration = previousConfiguration) /\
            (∀ node ∈ addedNodes, node ∉ state.hasJoined) /\
            Not (
              (refreshRetirementState source appended).membershipState =
                .retiredCommitted)
        next :=
          let nextSourceState :=
            refreshRetirementState source
              { appended with
                sentIndex := fun peer =>
                  if peer ∈ addedNodes then
                    sourceState.log.length
                  else
                    sourceState.sentIndex peer }
          { state with
            nodes := updateNode (state.nodes.allocate addedNodes) source nextSourceState
            hasJoined := state.hasJoined ∪ addedNodes
            retirementCompleted :=
              refreshRetirementCompleted
                state.retirementCompleted source nextSourceState } }
  | .appendRetiredCommitted node =>
      let nodeState := state.nodes node
      let pending := pendingRetiredCommittedNodes state node
      let entry : Entry Node TxId :=
        { term := nodeState.currentTerm
          content := .retiredCommitted pending }
      let refreshed :=
        refreshRetirementState node
          { nodeState with log := nodeState.log ++ [entry] }
      { enabled :=
          state.allocated node /\
            nodeState.role = .leader /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            pending.Nonempty /\
            Not (refreshed.membershipState = .retiredCommitted)
        next :=
          { state with
            nodes := updateNode state.nodes node refreshed
            retirementCompleted :=
              refreshRetirementCompleted state.retirementCompleted node refreshed } }
  | .signCommittableMessages node =>
      let nodeState := state.nodes node
      let entry : Entry Node TxId :=
        { term := nodeState.currentTerm
          content := .signature }
      let refreshed :=
        refreshRetirementState node
          { nodeState with log := nodeState.log ++ [entry] }
      { enabled :=
          state.allocated node /\
            nodeState.role = .leader /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            Not (nodeState.log = []) /\
            Not (refreshed.membershipState = .retiredCommitted)
        next :=
          { state with
            nodes := updateNode state.nodes node refreshed
            retirementCompleted :=
              refreshRetirementCompleted state.retirementCompleted node refreshed } }
  | .appendEntries source destination batchEnd =>
      let sourceState := state.nodes source
      { enabled :=
          state.allocated source /\
            state.allocated destination /\
            sourceState.role = .leader /\
            Not (source = destination) /\
            (destination ∈ activeNodeUnion sourceState \/
              destination ∈ state.retirementCompleted source) /\
            sourceState.sentIndex destination <= batchEnd /\
            batchEnd <= sourceState.log.length /\
            ((messageEntries sourceState.log
              (sourceState.sentIndex destination) batchEnd).all fun entry =>
                entry.term == termAt sourceState.log batchEnd) = true /\
            (Not (sourceState.membershipState = .retiredCommitted) \/
              sourceState.sentIndex destination < batchEnd)
        next :=
          let request := makeAppendEntriesRequest state source destination batchEnd
          { state with
            nodes :=
              updateNode state.nodes source
                { sourceState with
                  sentIndex :=
                    updateIndex sourceState.sentIndex destination batchEnd }
            network := enqueue state.network (.appendEntriesRequest request) } }
  | .receive source destination =>
      let result := handleReceive? state source destination
      { enabled := state.allocated destination /\ result.isSome
        next := result.getD state }
  | .drop source destination occurrence =>
      let result := takeOccurrenceFrom source occurrence (state.network destination)
      { enabled := result.isSome
        next :=
          match result with
          | none => state
          | some (_, remaining) =>
              { state with network := updateQueue state.network destination remaining } }
  | .advanceCommitIndex node =>
      { enabled :=
          state.allocated node /\
            (state.nodes node).role = .leader /\
            (state.nodes node).commitIndex < highestCommittableIndex state node /\
            Not (terminalRetirementCommit state node)
        next := demoteRetiredCommitted (advanceCommitState state node) node }
  | .timeout node =>
      let nodeState := state.nodes node
      { enabled :=
          state.allocated node /\
            (nodeState.role = .follower \/
              nodeState.role = .preVoteCandidate \/
              nodeState.role = .candidate) /\
            ((node ∈ activeNodeUnion nodeState /\ campaignEligible node nodeState) \/
              node ∈ state.retirementCompleted node) /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            Not (state.preVoteStatus node = .enabled)
        next := becomeCandidateState state node }
  | .becomePreVoteCandidate node =>
      let nodeState := state.nodes node
      { enabled :=
          state.allocated node /\
            (nodeState.role = .follower \/
              nodeState.role = .preVoteCandidate \/
              nodeState.role = .candidate) /\
            ((node ∈ activeNodeUnion nodeState /\ campaignEligible node nodeState) \/
              node ∈ state.retirementCompleted node) /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            state.preVoteStatus node = .enabled
        next :=
          { state with
            nodes :=
              updateNode state.nodes node
                { nodeState with
                  role := .preVoteCandidate
                  preVotesGranted := {node} } } }
  | .becomeCandidate node =>
      let nodeState := state.nodes node
      { enabled :=
          state.allocated node /\
            nodeState.role = .preVoteCandidate /\
            ((node ∈ activeNodeUnion nodeState /\ campaignEligible node nodeState) \/
              node ∈ state.retirementCompleted node) /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            state.preVoteStatus node = .enabled /\
            hasPreVoteMajority state node
        next := becomeCandidateState state node }
  | .requestVote source destination =>
      { enabled :=
          state.allocated source /\
            state.allocated destination /\
            (state.nodes source).role = .candidate /\
            Not (source = destination) /\
            destination ∈ activeNodeUnion (state.nodes source)
        next :=
          let request := makeRequestVoteRequest state source destination
          { state with network := enqueue state.network (.requestVoteRequest request) } }
  | .requestPreVote source destination =>
      { enabled :=
          state.allocated source /\
            state.allocated destination /\
            (state.nodes source).role = .preVoteCandidate /\
            Not (source = destination) /\
            destination ∈ activeNodeUnion (state.nodes source)
        next :=
          let request := makeRequestPreVote state source destination
          { state with network := enqueue state.network (.requestPreVote request) } }
  | .checkQuorum node =>
      { enabled :=
          state.allocated node /\
            (state.nodes node).role = .leader /\
            hasOtherActiveReplica state node
        next := stepDownState state node }
  | .updateTerm source destination =>
      let result := newerMessage? state source destination
      { enabled := state.allocated destination /\ result.isSome
        next :=
          match result with
          | none => state
          | some selected =>
              let nodeState := state.nodes destination
              { state with
                nodes :=
                  updateNode state.nodes destination
                    { nodeState with
                      role :=
                        if nodeState.role = .follower then
                          .follower
                        else
                          .follower
                      currentTerm := selected.term
                      votedFor := none
                      isNewFollower := true
                      preVotesGranted := ∅ } } }
  | .becomeLeader node =>
      let nodeState := state.nodes node
      let log := nodeState.log.take (maxCommittableIndex nodeState.log)
      let truncated := { nodeState with log }
      { enabled :=
          state.allocated node /\
            nodeState.role = .candidate /\
            Not (nodeState.membershipState = .retiredCommitted) /\
            hasElectionMajority state node /\
            Not (
              (refreshRetirementState node truncated).membershipState =
                .retiredCommitted)
        next :=
          let nextNode :=
            refreshRetirementState node
              { truncated with
                role := .leader
                sentIndex := fun _ => log.length
                matchIndex := fun _ => 0 }
          { state with
            nodes := updateNode state.nodes node nextNode
            retirementCompleted :=
              refreshRetirementCompleted state.retirementCompleted node nextNode } }
  | .proposeVote source destination =>
      { enabled :=
          state.allocated source /\
            state.allocated destination /\
            (state.nodes source).role = .leader /\
            plausibleSuccessor state source destination
        next :=
          let request := makeProposeVoteRequest state source destination
          { state with network := enqueue state.network (.proposeVoteRequest request) } }
  | .advanceCommitIndexAndProposeVote source destination =>
      { enabled :=
          state.allocated source /\
            state.allocated destination /\
            (state.nodes source).role = .leader /\
            (state.nodes source).commitIndex < highestCommittableIndex state source /\
            terminalRetirementCommit state source /\
            plausibleSuccessor state source destination
        next :=
          let advanced :=
            demoteRetiredCommitted (advanceCommitState state source) source
          let request := makeProposeVoteRequest state source destination
          { advanced with
            network := enqueue advanced.network (.proposeVoteRequest request) } }

def Enabled (state : State Node TxId) (action : Action Node TxId) : Prop :=
  (definition state action).enabled

-- Unfold only the guard projection to derive its decision procedure.
instance (state : State Node TxId) (action : Action Node TxId) :
    Decidable (Enabled state action) := by
  cases action <;> dsimp [Enabled, definition] <;> infer_instance

def next (state : State Node TxId) (action : Action Node TxId) : State Node TxId :=
  (definition state action).next

def system : ExecutableTransitionSystem where
  State := State Node TxId
  Action := Action Node TxId
  initial := initialState
  Enabled
  enabledDecidable := fun _ _ => inferInstance
  next

/-- Apply actions in order, returning `none` when one of them is disabled. -/
def runActions
    (state : State Node TxId) :
    List (Action Node TxId) -> Option (State Node TxId)
  | [] => some state
  | action :: actions => do
      let nextState <- system.applyAction state action
      runActions nextState actions

/-- States reachable from `initialState` through enabled actions. -/
abbrev Reachable :=
  (system (Node := Node) (TxId := TxId)).Reachable

end CCFRaft.Protocol.Model
