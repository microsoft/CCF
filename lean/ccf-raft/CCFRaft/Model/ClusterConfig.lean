module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model.NodeState

@[expose] public section

/-!
# Configurations

Cluster initialization, membership history and retirement queries.
-/

namespace CCFRaft.Model.Node

inductive MembershipState where
  /-- No membership removal observed; includes nodes that have never joined. -/
  | noRetirementObserved
  | retirementOrdered
  | retirementSigned
  | retirementCompleted
  | retiredCommitted
deriving DecidableEq, Repr

/--
Whether a node only answers pre-vote packets, or also starts its elections with
a pre-vote round.
-/
inductive PreVoteStatus where
  | capable
  | enabled
deriving DecidableEq, Repr

/-- Fixed for an execution; later membership changes come from the log. -/
structure InitialConfig (Node : Type) [DecidableEq Node] where
  configuration : Finset Node
  leader : Node
  leader_mem : leader ∈ configuration
  preVoteStatus : Node -> PreVoteStatus := fun _ => .capable

/-- The term of the initial leader, matching CCF's forced-primary startup. -/
def BOOTSTRAP_TERM : Nat := 2

variable {Node TxId : Type}

variable [DecidableEq Node] [DecidableEq TxId]

/-- Membership and its log index; index zero denotes the initial configuration. -/
structure Configuration (Node : Type) where
  index : Nat
  nodes : Finset Node
deriving DecidableEq

def entryConfigurations (content : EntryContent Node TxId) : List (Finset Node) :=
  content.effects.filterMap
    fun effect =>
      match effect with
      | .reconfiguration nodes => some nodes
      | .retiredCommitted _ => none

/--
Initial membership has index zero. Effects in one transaction share its log
index and retain their order, so configuration indices need not be unique.
-/
def configurationHistory (config : InitialConfig Node) (log : List (Entry Node TxId))
    : List (Configuration Node) :=
  { index := 0, nodes := config.configuration }
  :: (log.zipIdx 1).flatMap
      fun (entry, index) =>
        (entryConfigurations entry.content).map fun nodes => { index, nodes }

/--
The last committed configuration and every pending configuration. Earlier
configurations cease to participate once a later one is committed.
-/
def activeConfigurations (config : InitialConfig Node) (log : List (Entry Node TxId))
    (commitIndex : Nat)
    : List (Configuration Node) :=
  let history := configurationHistory config log
  -- Keep only the last configuration even when several share the committed index.
  let committed := history.filter fun configuration => configuration.index <= commitIndex
  history.drop (committed.length - 1)

def configurationMembers (configurations : List (Configuration Node)) : Finset Node :=
  configurations.foldl (fun nodes configuration => nodes ∪ configuration.nodes) ∅

/-- Members of the last supplied configuration, or none for an empty list. -/
def latestConfigurationMembers (configurations : List (Configuration Node))
    : Finset Node :=
  configurations.getLast?.map Configuration.nodes |>.getD ∅

def latestMembershipIndex (configurations : List (Configuration Node)) (node : Node)
    : Nat :=
  configurations.foldl
    (fun highest configuration =>
      if node ∈ configuration.nodes then max highest configuration.index else highest)
    0

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

/--
Nodes named by retirement records in the supplied log or prefix. Pass
`log.take commitIndex` to restrict this to locally committed records.
-/
def retiredCommittedNodes (log : List (Entry Node TxId)) : Finset Node :=
  log.foldl
    (fun retired entry =>
      entry.content.effects.foldl
        (fun retired effect =>
          match effect with
          | .retiredCommitted nodes => retired ∪ nodes
          | .reconfiguration _ => retired)
        retired)
    ∅

def hasConfigurationMajority (support : Finset Node) (configuration : Configuration Node)
    : Prop :=
  (support ∩ configuration.nodes).card * 2 > configuration.nodes.card

instance (support : Finset Node) (configuration : Configuration Node)
    : Decidable (hasConfigurationMajority support configuration) := by
  unfold hasConfigurationMajority
  infer_instance

abbrev hasQuorum (configurations : List (Configuration Node)) (voters : Finset Node)
    : Prop :=
  configurations.all
    fun configuration =>
      decide (hasConfigurationMajority voters configuration)

/--
The bootstrap transaction uses `default` as its identifier.
-/
def initialNodeState [Inhabited TxId] (config : InitialConfig Node) (node : Node)
    : NodeState Node TxId where
  role :=
    if node = config.leader then
      .leader
    else if node ∈ config.configuration then
      .follower
    else
      .none
  currentTerm := if node ∈ config.configuration then BOOTSTRAP_TERM else 0
  log :=
    if node = config.leader then
      [{
        term := BOOTSTRAP_TERM
        content := .transaction default [.reconfiguration config.configuration]
      }]
    else
      []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := false
  votedFor := none
  leaderKnown := node = config.leader
  votesGranted := ∅

def NodeState.activeConfigurations (config : InitialConfig Node)
    (state : NodeState Node TxId)
    : List (Configuration Node) :=
  CCFRaft.Model.Node.activeConfigurations config state.log state.commitIndex

/--
Active configurations covered by the latest signature, whether committed or not.
Index zero qualifies even before the first signature.
-/
def NodeState.signedActiveConfigurations (config : InitialConfig Node)
    (state : NodeState Node TxId)
    : List (Configuration Node) :=
  (state.activeConfigurations config).filter
    fun configuration => configuration.index <= maxCommittableIndex state.log

def NodeState.activeMembers (config : InitialConfig Node) (state : NodeState Node TxId)
    : Finset Node :=
  configurationMembers (state.activeConfigurations config)

/--
Nodes removed by committed configurations but not retired-committed yet.
Prior membership and absence from the latest committed configuration imply removal.
-/
def NodeState.retirementCompletedNodes (config : InitialConfig Node)
    (state : NodeState Node TxId)
    : Finset Node :=
  let committedLog := state.committedLog
  let committed := configurationHistory config committedLog
  let currentNodes := latestConfigurationMembers committed
  (configurationMembers committed \ currentNodes) \ retiredCommittedNodes committedLog

structure RetirementInfo where
  index : Option Nat
  committableIndex : Option Nat
  phase : MembershipState
deriving DecidableEq, Repr

def NodeState.retirement (config : InitialConfig Node) (node : Node)
    (state : NodeState Node TxId)
    : RetirementInfo :=
  let retirementIndex := retirementIndexInLog config node state.log
  let retirementCommittableIndex :=
    retirementIndex.bind
      fun index =>
        firstLogIndexAfter state.log index EntryContent.isSignature
  let membershipState :=
    match retirementIndex with
    | none => MembershipState.noRetirementObserved
    | some index =>
        if state.retiredCommittedIndex.isSome then
          .retiredCommitted
        else if index <= state.commitIndex then
          .retirementCompleted
        else if retirementCommittableIndex.isSome then
          .retirementSigned
        else
          .retirementOrdered
  {
    index := retirementIndex
    committableIndex := retirementCommittableIndex
    phase := membershipState
  }

abbrev NodeState.isRetiredCommitted (config : InitialConfig Node) (node : Node)
    (state : NodeState Node TxId)
    : Prop :=
  (state.retirement config node).phase = .retiredCommitted

end CCFRaft.Model.Node
