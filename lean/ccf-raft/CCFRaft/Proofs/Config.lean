module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model.Node

@[expose] public section

/-!
Proof-only configuration shorthand. The model takes an explicit `InitialConfig`
value; proofs use instance inference to avoid repeating that value in every
supporting lemma.

This file also gives recursive, proof-friendly forms of the model's
configuration and retirement helpers. `Proofs/Ledger.lean` proves that the
model's definitions agree with them. These conveniences do not change the
model or its properties.
-/

attribute [class] CCFRaft.Model.Node.InitialConfig

namespace CCFRaft.Proofs.Config

open Model.Node

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId]

section Initial

variable [config : InitialConfig Node]

abbrev INITIAL_LEADER : Node := config.leader

abbrev INITIAL_CONFIGURATION : Finset Node := config.configuration

abbrev INITIAL_PRE_VOTE_STATUS : Node -> PreVoteStatus := config.preVoteStatus

end Initial

/-- The bootstrap configuration at index 0, which has no log entry. -/
def implicitConfiguration (config : InitialConfig Node) : Configuration Node where
  index := 0
  nodes := config.configuration

/-- Collect the reconfiguration entries of a log with their one-based indices. -/
def configurationsInLogFrom : Nat -> List (Entry Node TxId) -> List (Configuration Node)
  | _, [] => []
  | index, entry :: entries =>
      let remaining := configurationsInLogFrom (index + 1) entries
      (entryConfigurations entry.content).map (fun nodes => { index, nodes }) ++ remaining

/-- All configurations in a log, from reconfiguration entries only. -/
def configurationsInLog (log : List (Entry Node TxId)) : List (Configuration Node) :=
  configurationsInLogFrom 1 log

/-- All configurations of a log, including the bootstrap configuration. -/
def allConfigurations (config : InitialConfig Node) (log : List (Entry Node TxId))
    : List (Configuration Node) :=
  implicitConfiguration config :: configurationsInLog log

/-- The last configuration in a node's log. -/
def latestConfiguration (config : InitialConfig Node) (state : NodeState Node TxId)
    : Configuration Node :=
  (configurationsInLog state.log).foldl (fun _ configuration => configuration)
    (implicitConfiguration config)

/-- The last configuration of a log at or before a commit index. -/
def currentConfigurationAt (config : InitialConfig Node) (log : List (Entry Node TxId))
    (commitIndex : Nat)
    : Configuration Node :=
  (configurationsInLog log).foldl
    (fun current configuration =>
      if configuration.index <= commitIndex then configuration else current)
    (implicitConfiguration config)

/-- The last configuration at or before the node's own commit index. -/
def currentConfiguration (config : InitialConfig Node) (state : NodeState Node TxId)
    : Configuration Node :=
  currentConfigurationAt config state.log state.commitIndex

/-- The current configuration and every later configuration in the node's log. -/
def activeConfigurationsOf (config : InitialConfig Node) (state : NodeState Node TxId)
    : List (Configuration Node) :=
  Model.Node.activeConfigurations config state.log state.commitIndex

/-- Union of the nodes in a node's active configurations. -/
def activeNodeUnion (config : InitialConfig Node) (state : NodeState Node TxId)
    : Finset Node :=
  (activeConfigurationsOf config state).foldl
    (fun nodes configuration => nodes ∪ configuration.nodes) ∅

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
      if entry.content.effects.any (fun effect =>
          match effect with
          | .retiredCommitted nodes => decide (node ∈ nodes)
          | .reconfiguration _ => false) then
        some index
      else
        retiredCommittedIndexFrom node (index + 1) entries

/-- The index of the first retired-committed entry naming a node. -/
def retiredCommittedIndexInLog (node : Node) (log : List (Entry Node TxId))
    : Option Nat :=
  retiredCommittedIndexFrom node 1 log

/-- Nodes named by retired-committed entries at or before a commit index. -/
def retiredCommittedNodesUpToFrom : Nat -> Nat -> List (Entry Node TxId) -> Finset Node
  | _, _, [] => ∅
  | commitIndex, index, entry :: entries =>
      let remaining := retiredCommittedNodesUpToFrom commitIndex (index + 1) entries
      if index <= commitIndex then
        entry.content.effects.foldl (fun retired effect =>
          match effect with
          | .retiredCommitted nodes => retired ∪ nodes
          | .reconfiguration _ => retired) remaining
      else
        remaining

/-- Nodes whose retired-committed records are locally committed. -/
def retiredCommittedNodesUpTo (log : List (Entry Node TxId)) (commitIndex : Nat)
    : Finset Node :=
  retiredCommittedNodesUpToFrom commitIndex 1 log

/-- All nodes already named by any retired-committed log entry. -/
def allRetiredCommittedNodes (log : List (Entry Node TxId)) : Finset Node :=
  retiredCommittedNodesUpToFrom log.length 1 log

/-- Nodes removed by committed configurations but not retired-committed yet. -/
def retirementCompletedNodes (config : InitialConfig Node) (log : List (Entry Node TxId))
    (commitIndex : Nat)
    : Finset Node :=
  let current := currentConfigurationAt config log commitIndex
  let previouslyConfigured :=
    (allConfigurations config log).foldl
      (fun nodes configuration =>
        if configuration.index < current.index then
          nodes ∪ configuration.nodes
        else
          nodes)
      ∅
  ((previouslyConfigured \ current.nodes)
    \ retiredCommittedNodesUpTo log commitIndex).filter
    fun node =>
      (retirementIndexFromConfigurations node false
        (allConfigurations config (log.take commitIndex))).isSome

/-- Nodes which the leader locally knows to have reached an index. -/
def acknowledgingNodes (config : InitialConfig Node) (state : NodeState Node TxId)
    (self : Node) (index : Nat)
    : Finset Node :=
  (activeNodeUnion config state).filter
    fun node =>
      node = self \/ state.matchIndex node >= index

/-- Every active configuration has a majority which reached an index. -/
def hasMajorityAt (config : InitialConfig Node) (state : NodeState Node TxId)
    (self : Node) (index : Nat)
    : Prop :=
  (activeConfigurationsOf config state).all
    fun configuration =>
      decide
        (hasConfigurationMajority (acknowledgingNodes config state self index)
          configuration)

instance (config : InitialConfig Node) (state : NodeState Node TxId) (self : Node)
    (index : Nat)
    : Decidable (hasMajorityAt config state self index) := by
  unfold hasMajorityAt
  infer_instance

/-- Votes form a strict majority in every active configuration. -/
def hasElectionMajority (config : InitialConfig Node) (state : NodeState Node TxId)
    : Prop :=
  (activeConfigurationsOf config state).all
    fun configuration =>
      decide (hasConfigurationMajority state.votesGranted configuration)

instance (config : InitialConfig Node) (state : NodeState Node TxId)
    : Decidable (hasElectionMajority config state) := by
  unfold hasElectionMajority
  infer_instance

/-- Pre-votes form a strict majority in every active configuration. -/
def hasPreVoteMajority (config : InitialConfig Node) (state : NodeState Node TxId)
    : Prop :=
  (activeConfigurationsOf config state).all
    fun configuration =>
      decide (hasConfigurationMajority state.preVotesGranted configuration)

instance (config : InitialConfig Node) (state : NodeState Node TxId)
    : Decidable (hasPreVoteMajority config state) := by
  unfold hasPreVoteMajority
  infer_instance

/--
The accepting branch of `handleAppendEntriesRequest`, after any candidate
step-down: a same-term request that matches the log, starts at or after the
commit index, and either has no term conflict or may roll one back.
-/
def acceptAppendEntriesRequest? (config : InitialConfig Node) (self : Node)
    (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Option (NodeState Node TxId × AppendEntriesResponse) :=
  if request.term = state.currentTerm
      /\ appendEntryMatchesLog state request
      /\ state.commitIndex <= request.prevLogIndex
      /\ Not (hasTermConflict state request /\ !state.isNewFollower) then
    let state := { state with leaderKnown := true }
    let state :=
      if hasTermConflict state request then
        { state with log := state.log.take request.prevLogIndex, isNewFollower := false }
      else
        state
    some (handleAppendEntiresFromLeader config self state request)
  else
    none

/-- The NACK `handleAppendEntriesRequest` sends for a stale or mismatched request. -/
def appendEntriesNack (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : AppendEntriesResponse :=
  if request.term < state.currentTerm \/ termAt state.log request.prevLogIndex = 0 then
    { term := state.currentTerm, success := false, lastLogIndex := state.log.length }
  else
    let lastLogIndex :=
      findHighestPossibleMatch state.log request.prevLogIndex request.prevLogTerm
    { term := termAt state.log lastLogIndex, success := false, lastLogIndex }

/--
The AppendEntries handler of a node that did not step down, as an option: the
NACK or the accepting branch, and `none` when the request is dropped.
-/
def handleAppendEntriesRequest? (config : InitialConfig Node) (self : Node)
    (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Option (NodeState Node TxId × AppendEntriesResponse) :=
  if request.term < state.currentTerm \/ Not (appendEntryMatchesLog state request) then
    some (state, appendEntriesNack state request)
  else
    acceptAppendEntriesRequest? config self state request

/-- The request's entries are already present in the log, compared by term. -/
def alreadyDone (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    : Prop :=
  request.entries = []
  \/ (request.prevLogIndex + request.entries.length <= state.log.length
      /\ ((state.log.drop request.prevLogIndex).take request.entries.length).map
            Entry.term
          = request.entries.map Entry.term)

end CCFRaft.Proofs.Config
