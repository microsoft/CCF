module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model
public import CCF.Execution

@[expose] public section

/-!
Each claim quantifies every node and transaction identifier type, every
explicit `InitialConfig` value and every node list. Claims concern valid traces
or individual successful steps of `Model.transitionSystem`. Each has a `Witness`
claim exhibiting a nontrivial execution relevant to the property.
-/

namespace CCFRaft.Properties

abbrev GlobalTrace (Node TxId : Type) := CCF.Execution.Trace (Model.State Node TxId)

open Model.Node

/-- Any two committed logs in a valid trace are prefix-comparable: those of
any two nodes, in any two states of the trace. -/
def CommittedLogsPrefix : Prop :=
  forall (Node TxId : Type) [DecidableEq Node] [DecidableEq TxId] [Inhabited TxId]
          [LinearOrder Node],
  forall (config : InitialConfig Node),
  forall (nodes : List Node) (trace : GlobalTrace Node TxId),
  forall (first second : Model.State Node TxId),
  forall (left right : Node) (leftState rightState : NodeState Node TxId),
    (trace.Valid (Model.transitionSystem config nodes)
      /\ first ∈ trace.states
      /\ second ∈ trace.states
      /\ (left, leftState) ∈ first.nodes
      /\ (right, rightState) ∈ second.nodes)
    -> leftState.committedLog <+: rightState.committedLog
        \/ rightState.committedLog <+: leftState.committedLog

/-- Witness: a valid trace has two states in which two distinct nodes have
nonempty committed logs. -/
def CommittedLogsPrefixWitness : Prop :=
  exists (Node TxId : Type),
  exists (_ : DecidableEq Node) (_ : DecidableEq TxId),
  exists (_ : Inhabited TxId) (_ : LinearOrder Node),
  exists (config : InitialConfig Node),
  exists (nodes : List Node) (trace : GlobalTrace Node TxId),
  exists (first second : Model.State Node TxId),
  exists (left right : Node) (leftState rightState : NodeState Node TxId),
    trace.Valid (Model.transitionSystem config nodes)
    /\ first ∈ trace.states
    /\ second ∈ trace.states
    /\ (left, leftState) ∈ first.nodes
    /\ (right, rightState) ∈ second.nodes
    /\ left ≠ right
    /\ leftState.committedLog ≠ []
    /\ rightState.committedLog ≠ []

/-- A successful network step from a state with unique node IDs preserves each
node's committed prefix. -/
def SingleNodeCommittedLogMonotonic : Prop :=
  forall (Node TxId : Type) [DecidableEq Node] [DecidableEq TxId] [Inhabited TxId]
          [LinearOrder Node],
  forall (config : InitialConfig Node) (nodes : List Node),
  forall (pre post : Model.State Node TxId),
  forall (nodeId : Node) (nodePre nodePost : NodeState Node TxId),
  forall (action : Model.Action Node TxId),
    ((pre.nodes.map Prod.fst).Nodup
      /\ (Model.transitionSystem config nodes).step pre action = some post
      /\ (nodeId, nodePre) ∈ pre.nodes
      /\ (nodeId, nodePost) ∈ post.nodes)
    -> nodePre.committedLog <+: nodePost.committedLog

/-- Witness: a successful step from a state with unique node IDs strictly extends
one node's nonempty committed log. -/
def SingleNodeCommittedLogMonotonicWitness : Prop :=
  exists (Node TxId : Type),
  exists (_ : DecidableEq Node) (_ : DecidableEq TxId),
  exists (_ : Inhabited TxId) (_ : LinearOrder Node),
  exists (config : InitialConfig Node) (nodes : List Node),
  exists (pre post : Model.State Node TxId),
  exists (nodeId : Node) (nodePre nodePost : NodeState Node TxId),
  exists (action : Model.Action Node TxId),
    (pre.nodes.map Prod.fst).Nodup
    /\ (Model.transitionSystem config nodes).step pre action = some post
    /\ (nodeId, nodePre) ∈ pre.nodes
    /\ (nodeId, nodePost) ∈ post.nodes
    /\ nodePre.committedLog ≠ []
    /\ nodePre.committedLog.length < nodePost.committedLog.length

/-- No two distinct nodes lead in the same term. -/
def ElectionSafety : Prop :=
  forall (Node TxId : Type) [DecidableEq Node] [DecidableEq TxId] [Inhabited TxId]
          [LinearOrder Node],
  forall (config : InitialConfig Node),
  forall (nodes : List Node) (trace : GlobalTrace Node TxId)
          (state : Model.State Node TxId),
  forall (left right : Node) (leftState rightState : NodeState Node TxId),
    (trace.Valid (Model.transitionSystem config nodes)
      /\ state ∈ trace.states
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes
      /\ leftState.role = .leader
      /\ rightState.role = .leader
      /\ leftState.currentTerm = rightState.currentTerm)
    -> left = right

/-- Witness: a valid trace has a state in which two nodes are leaders. -/
def ElectionSafetyWitness : Prop :=
  exists (Node TxId : Type),
  exists (_ : DecidableEq Node) (_ : DecidableEq TxId),
  exists (_ : Inhabited TxId) (_ : LinearOrder Node),
  exists (config : InitialConfig Node),
  exists
  (nodes : List Node) (trace : GlobalTrace Node TxId) (state : Model.State Node TxId),
  exists (left right : Node) (leftState rightState : NodeState Node TxId),
    trace.Valid (Model.transitionSystem config nodes)
    /\ state ∈ trace.states
    /\ (left, leftState) ∈ state.nodes
    /\ (right, rightState) ∈ state.nodes
    /\ leftState.role = .leader
    /\ rightState.role = .leader
    /\ left ≠ right

/-- Every positive commit index points to a signature entry. -/
def CommittedFrontierIsSignature : Prop :=
  forall (Node TxId : Type) [DecidableEq Node] [DecidableEq TxId] [Inhabited TxId]
          [LinearOrder Node],
  forall (config : InitialConfig Node),
  forall (nodes : List Node) (trace : GlobalTrace Node TxId)
          (state : Model.State Node TxId),
  forall (node : Node) (nodeState : NodeState Node TxId),
    (trace.Valid (Model.transitionSystem config nodes)
      /\ state ∈ trace.states
      /\ (node, nodeState) ∈ state.nodes
      /\ 0 < nodeState.commitIndex)
    -> isSignatureAt nodeState.log nodeState.commitIndex = true

/-- Witness: a valid trace has a state with a positive commit index. -/
def CommittedFrontierIsSignatureWitness : Prop :=
  exists (Node TxId : Type),
  exists (_ : DecidableEq Node) (_ : DecidableEq TxId),
  exists (_ : Inhabited TxId) (_ : LinearOrder Node),
  exists (config : InitialConfig Node),
  exists
  (nodes : List Node) (trace : GlobalTrace Node TxId) (state : Model.State Node TxId),
  exists (node : Node) (nodeState : NodeState Node TxId),
    trace.Valid (Model.transitionSystem config nodes)
    /\ state ∈ trace.states
    /\ (node, nodeState) ∈ state.nodes
    /\ 0 < nodeState.commitIndex

end CCFRaft.Properties
