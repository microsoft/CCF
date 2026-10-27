module

public import CCFRaft.Model.NodeState

@[expose] public section

/-!
# Configurations

Ledger-derived membership history and retirement queries.
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

/-- Membership and the one-based index of its configuration transaction. -/
structure Configuration where
  index : Nat
  nodes : Finset NodeID
deriving DecidableEq

/-- Each configuration comes from one transaction in the local log. -/
def configurationHistory (log : List Entry) : List Configuration :=
  (log.zipIdx 1).filterMap
    fun (entry, index) =>
      entry.content.metadata.configuration.map fun nodes => { index, nodes }

/--
The last committed configuration and every pending configuration. Earlier
configurations cease to participate once a later one is committed.
-/
def activeConfigurations (log : List Entry) (commitIndex : Nat) : List Configuration :=
  let history := configurationHistory log
  let committed := history.filter fun configuration => configuration.index <= commitIndex
  history.drop (committed.length - 1)

def configurationMembers (configurations : List Configuration) : Finset NodeID :=
  configurations.foldl (fun nodes configuration => nodes ∪ configuration.nodes) ∅

/-- Members of the last supplied configuration, or none for an empty list. -/
def latestConfigurationMembers (configurations : List Configuration) : Finset NodeID :=
  configurations.getLast?.map Configuration.nodes |>.getD ∅

def latestMembershipIndex (configurations : List Configuration) (node : NodeID) : Nat :=
  configurations.foldl
    (fun highest configuration =>
      if node ∈ configuration.nodes then max highest configuration.index else highest)
    0

/--
The first transition from membership to absence. Absence before a node joins
is not retirement, and later rejoining does not change the first removal.
-/
def retirementIndexInLog (node : NodeID) (log : List Entry) : Option Nat :=
  let history := configurationHistory log
  ((history.zip history.tail).find?
    fun (before, after) => decide (node ∈ before.nodes /\ node ∉ after.nodes)).map
    fun (_, after) => after.index

/--
Nodes named by retirement records in the supplied log or prefix, unless a later
configuration names them again. Pass `log.take commitIndex` to restrict this to
locally committed records. A rejoining node starts unconfirmed, like CCF's fresh
node record with `retired_committed` unset.
-/
def retiredCommittedNodes (log : List Entry) : Finset NodeID :=
  log.foldl
    (fun retired entry =>
      let metadata := entry.content.metadata
      (retired \ metadata.configuration.getD ∅) ∪ metadata.retirementConfirmations)
    ∅

def hasConfigurationMajority (support : Finset NodeID) (configuration : Configuration)
    : Prop :=
  (support ∩ configuration.nodes).card * 2 > configuration.nodes.card

instance (support : Finset NodeID) (configuration : Configuration)
    : Decidable (hasConfigurationMajority support configuration) := by
  unfold hasConfigurationMajority
  infer_instance

abbrev hasQuorum (configurations : List Configuration) (voters : Finset NodeID) : Prop :=
  configurations ≠ []
  /\ configurations.all
      fun configuration =>
        decide (hasConfigurationMajority voters configuration)

def NodeState.activeConfigurations (state : NodeState) : List Configuration :=
  CCFRaft.Model.Node.activeConfigurations state.log state.commitIndex

/--
Active configurations covered by the latest signature, whether committed or not.
-/
def NodeState.signedActiveConfigurations (state : NodeState) : List Configuration :=
  state.activeConfigurations.filter
    fun configuration => configuration.index <= maxCommittableIndex state.log

def NodeState.activeMembers (state : NodeState) : Finset NodeID :=
  configurationMembers state.activeConfigurations

/--
Nodes removed by committed configurations but not retired-committed yet.
Prior membership and absence from the latest committed configuration imply removal.
-/
def NodeState.retirementCompletedNodes (state : NodeState) : Finset NodeID :=
  let committedLog := state.committedLog
  let committed := configurationHistory committedLog
  let currentNodes := latestConfigurationMembers committed
  (configurationMembers committed \ currentNodes) \ retiredCommittedNodes committedLog

structure RetirementInfo where
  index : Option Nat
  committableIndex : Option Nat
  phase : MembershipState
deriving DecidableEq, Repr

def NodeState.retirement (node : NodeID) (state : NodeState) : RetirementInfo :=
  let retirementIndex := retirementIndexInLog node state.log
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

abbrev NodeState.isRetiredCommitted (node : NodeID) (state : NodeState) : Prop :=
  (state.retirement node).phase = .retiredCommitted

end CCFRaft.Model.Node
