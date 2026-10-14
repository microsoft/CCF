-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model.NodeState

/-!
# Configurations

Cluster initialization, membership history and retirement queries.
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
index and retain their order; CCF installs at most one configuration per transaction.
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
  Local.activeConfigurations config state.log state.commitIndex

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

end CCFRaft.Model.Local
