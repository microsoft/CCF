-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Mathlib.Data.Finset.Card
import Mathlib.Data.Finset.Lattice.Fold

/-!
# Consensus state and replicated log

CCF nodes agree on an ordered log of transactions. A leader accepts new
transactions and sends log entries to followers, which keep their own copies.
Nodes elect a replacement leader when needed. Elections are numbered by
`term`; each log entry records the term in which it was written.

A log entry is not necessarily committed. Leaders append signature entries
to make log prefixes eligible for commitment, and replication quorums determine
when a leader can commit them. `commitIndex` marks the end of a node's committed
prefix. Log positions are one-based; index zero denotes an empty prefix.

Membership changes are also log entries. A configuration names the nodes
whose votes and replication acknowledgements count toward a quorum. Several
configurations can remain active while a change is uncommitted. Removing a
node progresses through retirement phases rather than immediately discarding
its protocol state.

The types and helpers below describe these concepts using only one node's
state and the initial configuration supplied by `InitialConfig`. They do not
perform protocol steps. `Messages.lean` defines the packets nodes exchange,
`Local.lean` defines the elections, replication, and other events that change
this state, and `Model.lean` connects the nodes through a network. The
node-level files share the `CCFRaft.Model.Local` namespace.
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

/--
Fixed inputs for the start of an execution: which nodes initially belong to the
cluster, which one starts as leader, and whether each node starts elections with
a pre-vote round. Later membership changes come from log entries, not updates
to this configuration.
-/
structure InitialConfig (Node : Type) [DecidableEq Node] where
  /-- Nodes whose votes and acknowledgements count before any membership change. -/
  configuration : Finset Node
  /-- The initially appointed leader; no election is needed to start. -/
  leader : Node
  /-- Evidence that the appointed leader belongs to the initial membership. -/
  leader_mem : leader ∈ configuration
  /-- Whether each node starts elections with a preliminary pre-vote round. -/
  preVoteStatus : Node -> PreVoteStatus := fun _ => .capable

/-- The term of the initial leader, matching CCF's forced-primary startup. -/
def BOOTSTRAP_TERM : Nat := 2

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

/-- Membership and its log index; index zero denotes the initial configuration. -/
structure Configuration (Node : Type) where
  index : Nat
  nodes : Finset Node
deriving DecidableEq

/--
Membership history in log order. The initial membership has index zero; later
configurations retain their one-based positions even when other entries lie
between them.
-/
def configurationHistory (config : InitialConfig Node) (log : List (Entry Node TxId))
    : List (Configuration Node) :=
  { index := 0, nodes := config.configuration }
  :: (log.zipIdx 1).filterMap
      fun (entry, index) =>
        match entry.content with
        | .reconfiguration nodes => some { index, nodes }
        | _ => none

/--
The last committed configuration and every pending configuration. Earlier
configurations cease to participate once a later one is committed.
-/
def activeConfigurations (config : InitialConfig Node) (log : List (Entry Node TxId))
    (commitIndex : Nat)
    : List (Configuration Node) :=
  let history := configurationHistory config log
  let currentIndex :=
    history.foldl
      (fun current configuration =>
        if configuration.index <= commitIndex then configuration.index else current)
      0
  history.filter fun configuration => currentIndex <= configuration.index

/-- All nodes named by any configuration in the supplied history or subset. -/
def configurationMembers (configurations : List (Configuration Node)) : Finset Node :=
  configurations.foldl (fun nodes configuration => nodes ∪ configuration.nodes) ∅

/-- The active configurations given a node's log and commit index. -/
def NodeState.activeConfigurations (config : InitialConfig Node)
    (state : NodeState Node TxId)
    : List (Configuration Node) :=
  Local.activeConfigurations config state.log state.commitIndex

/-- All nodes named by a node's active configurations. -/
def NodeState.activeMembers (config : InitialConfig Node) (state : NodeState Node TxId)
    : Finset Node :=
  configurationMembers (state.activeConfigurations config)

/--
The first transition from membership to absence. Absence before a node joins
is not retirement, and later rejoining does not change the first removal.
-/
def retirementIndexInLog (config : InitialConfig Node) (node : Node)
    (log : List (Entry Node TxId))
    : Option Nat :=
  let history := configurationHistory config log
  ((history.zip history.tail).find?
    fun (before, after) => decide (node ∈ before.nodes /\ node ∉ after.nodes)).map
    fun (_, after) => after.index

/-- The first matching entry's one-based index, strictly after `afterIndex`. -/
def firstLogIndexAfter (log : List (Entry Node TxId)) (afterIndex : Nat)
    (predicate : EntryContent Node TxId -> Bool)
    : Option Nat :=
  ((log.zipIdx 1).find?
    fun (entry, index) => decide (afterIndex < index) && predicate entry.content).map
    Prod.snd

/--
Nodes named by retirement records in the supplied log or prefix. Pass
`log.take commitIndex` to restrict this to locally committed records.
-/
def retiredCommittedNodes (log : List (Entry Node TxId)) : Finset Node :=
  log.foldl
    (fun retired entry =>
      match entry.content with
      | .retiredCommitted nodes => retired ∪ nodes
      | _ => retired)
    ∅

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
def hasConfigurationMajority (support : Finset Node) (configuration : Configuration Node)
    : Prop :=
  (support ∩ configuration.nodes).card * 2 > configuration.nodes.card

instance (support : Finset Node) (configuration : Configuration Node)
    : Decidable (hasConfigurationMajority support configuration) := by
  unfold hasConfigurationMajority
  infer_instance

end CCFRaft.Model.Local
