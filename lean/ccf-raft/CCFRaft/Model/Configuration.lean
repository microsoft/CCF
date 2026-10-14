-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model.Log

/-!
# Configurations

The `InitialConfig` and the membership configurations recorded in a log.
Configurations are log entries, and several can be active while a change is
uncommitted. Retirement records name nodes whose removal is complete.
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

variable {Node TxId : Type}

variable [DecidableEq Node] [DecidableEq TxId]

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
      match entry.content with
      | .retiredCommitted nodes => retired ∪ nodes
      | _ => retired)
    ∅

/-- True when a set of nodes is a strict majority of one configuration. -/
def hasConfigurationMajority (support : Finset Node) (configuration : Configuration Node)
    : Prop :=
  (support ∩ configuration.nodes).card * 2 > configuration.nodes.card

instance (support : Finset Node) (configuration : Configuration Node)
    : Decidable (hasConfigurationMajority support configuration) := by
  unfold hasConfigurationMajority
  infer_instance

end CCFRaft.Model.Local
